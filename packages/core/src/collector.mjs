/**
 * The collector — DES-14, FR-56, FR-62.
 *
 * One core, thin adapters. This is the core: an adapter notices that something
 * happened, builds nothing cryptographic, and hands plaintext here. The record
 * format is therefore adapter-independent, so a verifier never needs to know
 * which collector wrote a pack — and adding a collector cannot introduce an
 * integrity bug.
 *
 * Plaintext goes in; a commitment goes into the record. That ordering is what
 * makes PRIV-02 structural rather than a rule someone has to remember: there is
 * no API here that accepts a payload and puts it in a record.
 *
 * One chain per collector instance, not per run (FR-56). Concurrent runs
 * interleave; heartbeats carry no run at all.
 */

import { randomBytes } from 'node:crypto';
import { chainEntry, genesis, recomputeChain } from './chain.mjs';
import { StoreBusy } from './writelock.mjs';
import { newSalt } from './leaf.mjs';
import { treeRoot } from './merkle.mjs';
import { checkpointText, encodeNote } from './note.mjs';
import { endorse, verifySuccession } from './succession.mjs';
import { signNote } from './signer.mjs';
import { extractRefs } from './content.mjs';
import { SCHEMA_VERSION, SUITE } from './record.mjs';

/** @param {unknown} v @returns {v is Uint8Array} */
const isBytes = v => v instanceof Uint8Array;

/**
 * The collector will not write while it cannot trust its own position.
 *
 * An append that fails leaves the in-memory head and sequence behind what may
 * already be on disk. Continuing from that state reused a record_seq and a
 * stale predecessor, which a verifier reports as SEQ_BROKEN for the rest of the
 * log's life — so a disk-full incident became a permanent accusation of
 * tampering. Refusing to write, loudly, is the honest alternative; the agent
 * keeps running because the adapter is fail-open (SCOPE-16).
 */
export class CollectorDegraded extends Error {
  /** @param {unknown} cause */
  constructor(cause) {
    const why = cause instanceof Error ? cause.message : String(cause);
    super(`collector is degraded after a failed append (${why}); call recover() once the store is writable`);
    this.name = 'CollectorDegraded';
    this.cause = cause;
  }
}

export class Collector {
  /** @type {Map<string, { correlation: string, attempts: number }>} in-memory only */
  #actions = new Map();
  /** @type {unknown} the failure that degraded this collector, or null */
  #degraded = null;
  /** Whether epoch 0 is already in the succession journal. */
  #rootEpochRecorded = false;
  /** @type {boolean} */
  #reconciled = false;

  /**
   * @param {object} o
   * @param {import('./store.mjs').Store} o.store
   * @param {import('./config.mjs').Config} o.config
   * @param {import('./signer.mjs').Signer} o.signer a signing function, never a key — SEC-14
   * @param {string} o.collector the instance identity that scopes the chain
   * @param {string} [o.origin] the log origin; defaults to the signer name
   * @param {() => Date} [o.now] injected so tests are not clock-dependent
   * @param {string} [o.build] the build digest a heartbeat attests — SEC-22
   * @param {(e: { detail: string, span: { from_source_seq: number, to_source_seq: number } })
   *   => void} [o.onUnrecordable] FR-58 — where a failure to record a failure
   *   is surfaced. Out of band, because the place it would otherwise go is the
   *   thing that has filled up.
   */
  constructor({ store, config, signer, collector, origin, now, build, onUnrecordable }) {
    this.store = store;
    this.config = config;
    this.signer = signer;
    this.collector = collector;
    this.origin = origin ?? signer.name;
    this.now = now ?? (() => new Date());
    this.build = build ?? 'sha256:unattested';
    /**
     * FR-58 — where a failure to record a failure is surfaced.
     *
     * Out of band, because the place it would otherwise go is the thing that
     * has filled up. A collector that could not write its gap declaration and
     * said nothing would present a clean history for a lossy run.
     */
    this.onUnrecordable = onUnrecordable ?? null;
    /** Whether reconcileObservations() has already run and declared. */
    this.#reconciled = false;

    // Physical integrity on open, not only on recover(). A process that
    // crashed mid-append leaves a torn line, and resuming on top of it turns a
    // recoverable tail into a broken middle — so the damage is noticed here and
    // the collector starts degraded, with recover() the explicit way forward.
    const detail = store.readChainDetailed();
    if (detail.torn || detail.salts_torn || detail.malformed.length || detail.salts_malformed.length) {
      this.#degraded = new Error(
        'the journals carry an incomplete or unreadable line from a previous run'
        + `${detail.torn ? ' (chain tail torn)' : ''}`
        + `${detail.salts_torn ? ' (salt tail torn)' : ''}`
        + `${detail.malformed.length ? ` (chain line ${detail.malformed.map(m => m.line).join(', ')} unreadable)` : ''}`
        + `${detail.salts_malformed.length ? ` (salt line ${detail.salts_malformed.join(', ')} unreadable)` : ''}`);
    }
    const tip = store.tip();
    this.recordSeq = tip.record_seq;
    this.sourceSeq = tip.source_seq;
    this.head = tip.record_seq === 0 ? genesis() : tip.head;
    this.checkpointSeq = store.lastCheckpointSeq();
    this.rollupSeq = store.lastRollupSeq();

    // The epoch comes off disk, never from memory — FR-11. A collector that
    // remembered its epoch would start back at 0 after a restart and endorse a
    // successor the chain already has, forking the succession.
    //
    // Reading only. The root entry is written on the first write instead, not
    // here: a constructor that claimed the write lock made opening a store an
    // act of writing to it, which broke handover between two instances and
    // would have made a read-only reader mutate what it was reading.
    const chain = store.readSuccession();
    if (chain.length === 0) {
      this.epoch = 0;
      this.#rootEpochRecorded = false;
    } else {
      const root = chain[0];
      if (!root || typeof root.public_key !== 'string') {
        throw new Error('the succession journal has no readable root entry');
      }
      const walk = verifySuccession(Buffer.from(root.public_key, 'base64'), chain);
      const live = walk.epochs[walk.epochs.length - 1];
      if (!walk.ok || !live) {
        throw new Error(
          'the succession journal does not walk: '
          + walk.findings.map(f => `${f.code} ${f.detail}`).join('; '),
        );
      }
      if (live.public_key !== signer.publicKey.toString('base64')) {
        // Signing with a key the chain says is retired would produce
        // checkpoints no verifier could attribute to the live epoch, and the
        // first anyone would hear of it is a verification months later.
        throw new Error(
          `the signer supplied is not the live epoch key: the succession journal's newest entry `
          + `is epoch ${live.epoch}, whose public key is a different one. Pass the current `
          + `epoch's signer, or rotate to this one deliberately.`,
        );
      }
      this.epoch = live.epoch;
      this.#rootEpochRecorded = true;
    }
  }

  /**
   * Record epoch 0 before anything it would have to account for exists.
   *
   * Called from the write paths rather than the constructor, so that opening a
   * store stays a read. It must run before the first checkpoint: a signed note
   * that no succession entry accounts for is exactly the gap a verifier would
   * report as unattributable.
   */
  #ensureRootEpoch() {
    if (this.#rootEpochRecorded) return;
    this.store.appendEpoch({
      epoch: 0,
      public_key: this.signer.publicKey.toString('base64'),
      custody: this.signer.custody,
    });
    this.#rootEpochRecorded = true;
  }

  /**
   * Turn the ratchet — FR-11, SEC-08.
   *
   * The retiring epoch endorses its successor through the signer seam, the
   * endorsement is journalled, and only then does the collector switch. The
   * order matters: endorsing after switching would leave the successor
   * unendorsed if the write failed, and a successor nobody endorsed cannot be
   * attributed to the pinned root.
   *
   * What this does NOT do is destroy the retired private key. Splitstick never
   * holds it (SEC-14), so it cannot. Destruction is the operator's act and
   * their declaration; see SEC-17 and docs/key-custody.md.
   *
   * @param {import('./signer.mjs').Signer} next the incoming epoch's signer
   * @param {{ declare?: boolean }} [opts] `declare` emits the FR-65 custody
   *   record for the new epoch, so that an epoch is never undeclared
   * @returns {Promise<{ epoch: number }>}
   */
  async rotate(next, opts = {}) {
    const degraded = this.#degraded;
    if (degraded) {
      throw new CollectorDegraded(
        'this collector is degraded and will not rotate: '
        + (degraded instanceof Error ? degraded.message : String(degraded)),
      );
    }
    if (next.algorithm !== 'ed25519' || next.publicKey?.length !== 32) {
      throw new TypeError('the incoming epoch signer is not an Ed25519 signer with a 32-byte key');
    }
    if (next.name !== this.signer.name) {
      throw new Error(
        `the incoming signer's origin is ${next.name} but this log's origin is ${this.signer.name}: `
        + 'rotating the origin is starting a different log, not succeeding this one',
      );
    }
    this.#ensureRootEpoch();
    const epoch = this.epoch + 1;
    // endorse() refuses a successor equal to the endorsing key, so a repeated
    // key is caught before anything is written.
    const endorsement = await endorse(this.signer, next.publicKey, epoch);
    this.store.appendEpoch({
      epoch,
      public_key: next.publicKey.toString('base64'),
      custody: next.custody,
      endorsement: endorsement.toString('base64'),
    });
    this.signer = next;
    this.epoch = epoch;
    // After the swap, so the declaration is about the epoch now in force.
    if (opts.declare) this.custody();
    return { epoch };
  }

  /** The log's tree size — the record count, always equal to record_seq. */
  get tree_size() { return this.recordSeq; }

  /** The failure that stopped this collector writing, or null. */
  get degraded() { return this.#degraded; }

  /**
   * Re-read what is on disk and resume, if resuming is safe.
   *
   * Recovery inspects the journals' PHYSICAL integrity before their contents.
   * Reading through readChain() returned the lines it could parse and dropped
   * the torn and malformed indicators beside them, so a real short write was
   * invisible: recovery validated the records before the tear, declared
   * success, and the next append landed immediately after the incomplete bytes.
   * A torn tail — which a verifier treats as the ordinary consequence of a
   * crash — became a broken line in the middle, which it treats as tampering.
   *
   * An incomplete TRAILING line is therefore truncated: it has no newline, so
   * it was never committed, and removing it cannot lose a record. Anything
   * else leaves the collector degraded, because a broken line in the middle is
   * not a crash artifact and writing over it would bury whatever did it.
   * @returns {{ record_seq: number, source_seq: number, repaired_chain_bytes: number, repaired_salts_bytes: number }}
   */
  recover() {
    // Take ownership before inspecting anything, and keep it through the
    // resumption that follows. Recovery reads a position and then writes from
    // it; doing that on a collector another instance owns means two writers
    // assigning sequences from the same place, repair or no repair.
    this.store.lock.claim();
    const before = this.store.readChainDetailed();
    if (before.malformed.length > 0 || before.salts_malformed.length > 0) {
      throw new Error(
        'refusing to resume: a line in the middle of a journal is unreadable '
        + `(chain ${JSON.stringify(before.malformed.map(m => m.line))}, `
        + `salts ${JSON.stringify(before.salts_malformed)}); that is not a crash `
        + 'artifact, and appending over it would bury the evidence of what did it');
    }

    const repaired = (before.torn || before.salts_torn)
      ? this.store.repairTornTail()
      : { chain: 0, salts: 0 };

    const entries = this.store.readChain();
    const check = recomputeChain(entries);
    const structural = check.findings.filter(f => f.code !== 'LEAF_INCONCLUSIVE'
      && !/source_seq/.test(f.detail ?? ''));
    if (structural.length > 0) {
      throw new Error(
        `refusing to resume: the chain on disk is inconsistent (${structural.map(f => f.code).join(', ')}); `
        + 'appending to it would bury the evidence of how it broke');
    }
    const tip = this.store.tip();
    this.recordSeq = tip.record_seq;
    this.head = tip.record_seq === 0 ? genesis() : tip.head;
    // The observation counter is never rewound: an attempt observed during the
    // outage was still observed, and the hole is the report.
    this.sourceSeq = Math.max(this.sourceSeq, tip.source_seq);
    this.#degraded = null;
    return {
      record_seq: this.recordSeq,
      source_seq: this.sourceSeq,
      repaired_chain_bytes: repaired.chain,
      repaired_salts_bytes: repaired.salts,
    };
  }

  /**
   * Consume a source_seq for an observed attempt.
   *
   * Public because the counter advances on every consequential attempt
   * **observed**, written or not. When a write is dropped, the number is spent
   * and the hole is what a verifier sees — an unwritten attempt must leave a
   * mark rather than vanish.
   * @returns {number}
   */
  observe() { return ++this.sourceSeq; }

  /** @returns {string} an opaque random correlation id — DES-13 requires it carry nothing. */
  static newCorrelation() { return randomBytes(12).toString('hex'); }

  /**
   * Correlate an attempt with the logical action it belongs to — FR-62.
   *
   * The caller supplies an identifier for the logical action; it is NOT derived
   * from the payload. Keying on the tool and the argument bytes grouped two
   * independent transfers of the same amount as attempt 1 and attempt 2 of one
   * action — a repeated transaction is not a retry — and because DES-13
   * retains `correlation` after erasure, two records sharing one also told a
   * reader that those actions had byte-identical arguments once the arguments
   * themselves had been shredded. A retained field must carry nothing, and that
   * one carried payload equality.
   *
   * An integration that knows its own retry lineage passes the same key for
   * each attempt. One that does not — OMA expresses none, since a retry there
   * is a new tool call with a new id — asks for a fresh correlation instead and
   * reports one attempt each, which is what it actually observed.
   *
   * The key is held in memory only and never written.
   *
   * @param {string} actionKey an identifier for one logical action, from the source
   * @returns {{ correlation: string, attempt: number }}
   */
  correlate(actionKey) {
    if (typeof actionKey !== 'string' || actionKey === '') {
      throw new TypeError('a logical-action key is required; pass one from the source, or use newCorrelation()');
    }
    const seen = this.#actions.get(actionKey);
    if (seen) { seen.attempts += 1; return { correlation: seen.correlation, attempt: seen.attempts }; }
    const correlation = Collector.newCorrelation();
    this.#actions.set(actionKey, { correlation, attempts: 1 });
    return { correlation, attempt: 1 };
  }

  /**
   * Externalise every payload of one record in a single group, and return the
   * commitments by field name.
   *
   * One file per record, not per payload — a file creation measured 0.3 ms
   * against NFR-01's 1 ms budget, and a record can carry five payloads.
   *
   * @param {Record<string, Uint8Array|undefined>} fields
   * @param {string} [indexField] the field to scan for counterparty references
   * @returns {Record<string, { cid: string, bytes: number }>}
   */
  #commitAll(fields, indexField) {
    /** @type {string[]} */
    const names = [];
    /** @type {{ bytes: Uint8Array, refs?: Set<string> }[]} */
    const payloads = [];
    for (const [name, bytes] of Object.entries(fields)) {
      if (bytes === undefined) continue;
      if (!isBytes(bytes)) {
        throw new TypeError('payloads are handed over as bytes; the collector never records a value');
      }
      names.push(name);
      // FR-55 — only the result is scanned for counterparty references; an
      // argument is what we asked for, a result is what they issued.
      payloads.push(name === indexField ? { bytes, refs: extractRefs(bytes) } : { bytes });
    }
    const commitments = this.store.content.putGroup(payloads);
    /** @type {Record<string, { cid: string, bytes: number }>} */
    const out = {};
    names.forEach((name, i) => { out[name] = /** @type {{cid: string, bytes: number}} */ (commitments[i]); });
    return out;
  }

  /**
   * Validate, chain and write. The sequence advances only once the record is on
   * disk.
   *
   * record_seq must equal tree_size (DES-04 rule 2), so a record that is
   * rejected or fails to write must not consume one. Incrementing in the
   * envelope left a permanent hole after any rejection, and a hole reads as a
   * removed event — the verifier would report tampering forever because of one
   * malformed observation. source_seq is deliberately not treated this way: an
   * observed attempt spends its number whether or not it is written, and the
   * hole is the report.
   * @param {Record<string, unknown>} record
   * @returns {import('./chain.mjs').ChainEntry}
   */
  #write(record) {
    if (this.#degraded !== null) throw new CollectorDegraded(this.#degraded);
    const salt = newSalt();
    const e = chainEntry(record, salt, this.head);   // validates; throws before any mutation
    try {
      this.#ensureRootEpoch();
      this.store.append(e);
    } catch (err) {
      // A lock conflict is not local damage. The lock is claimed before any
      // byte is written, so nothing landed and this collector's position is
      // still exactly what it was — it simply does not own the store. Treating
      // that as degradation would conflate "someone else owns this" with "my
      // own position is untrustworthy", and would need a recover() for a
      // condition recovery cannot address.
      if (err instanceof StoreBusy) throw err;
      // Any other failure may have partially landed, so the position is no
      // longer trustworthy. Stop rather than continue from it.
      this.#degraded = err;
      throw err;
    }
    this.head = e.head;
    this.recordSeq += 1;
    return e;
  }

  /** @param {Partial<Record<string, unknown>>} [extra] */
  #envelope(extra = {}) {
    return {
      v: SCHEMA_VERSION,
      collector: this.collector,
      record_seq: this.recordSeq + 1,
      ts: this.now().toISOString().replace(/\.(\d{3})\d*Z$/, '.$1Z'),
      ...extra,
    };
  }

  /**
   * Record a tool call or an approval — FR-05, FR-06, FR-07, FR-62.
   * @param {object} a
   * @param {string} a.tool
   * @param {boolean} [a.consequential] as the tool declared it
   * @param {string|null} [a.run]
   * @param {Uint8Array} [a.agent]
   * @param {Uint8Array} [a.args]
   * @param {Uint8Array} [a.result]
   * @param {'ok'|'error'|'timeout'|'denied'} [a.outcome]
   * @param {number} [a.attempt]
   * @param {string} [a.correlation]
   * @param {{ decision: 'approve'|'deny', reviewer?: Uint8Array, request?: Uint8Array }|null} [a.approval]
   * @param {'tool_call'|'approval'} [a.kind]
   * @returns {import('./chain.mjs').ChainEntry}
   */
  action(a) {
    if (this.#degraded !== null) throw new CollectorDegraded(this.#degraded);

    // Spend the observation FIRST, before anything that can fail. Externalising
    // the payloads came first, so a storage failure threw with the counter
    // untouched — the adapter caught it, the agent carried on, and the next
    // action took the next consecutive number, leaving a verifier nothing to
    // see. Exposing a consequential action that was observed and never recorded
    // is the one job this counter has.
    const source_seq = this.observe();

    const c = this.#commitAll({
      agent: a.agent,
      args: a.args,
      result: a.result,
      reviewer: a.approval ? a.approval.reviewer : undefined,
      request: a.approval ? a.approval.request : undefined,
    }, 'result');

    const record = this.#envelope({
      run: a.run ?? null,
      source_seq,
      kind: a.kind ?? 'tool_call',
      tool: a.tool,
      consequential: a.consequential ?? true,
      ...(c.agent ? { agent: c.agent } : {}),
      ...(c.args ? { args: c.args } : {}),
      // `ok` is carried alongside the commitment because DES-13 retains it: a
      // boolean outcome identifies nobody, and a verifier needs it after the
      // payload itself has been shredded.
      ...(c.result ? { result: { ...c.result, ok: (a.outcome ?? 'ok') === 'ok' } } : {}),
      approval: a.approval
        ? {
          decision: a.approval.decision,
          ...(c.reviewer ? { reviewer: c.reviewer } : {}),
          ...(c.request ? { request: c.request } : {}),
        }
        : null,
      outcome: a.outcome ?? 'ok',
      attempt: a.attempt ?? 1,
      correlation: a.correlation ?? Collector.newCorrelation(),
    });
    return this.#write(record);
  }

  /**
   * A liveness record — FR-24's resolution. No run, no source_seq: a heartbeat
   * is not an observation, and `null` says so checkably where a repeated value
   * would be indistinguishable from a second observation.
   * @param {{ policy?: string }} [o]
   */
  heartbeat(o = {}) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'heartbeat',
      build: this.build, policy: o.policy ?? 'sha256:unset',
    }));
  }

  /**
   * A declared observation gap — DES-10. Carries the span it lost.
   * @param {{ from_source_seq: number, to_source_seq: number, reason?: string }} o
   */
  gap(o) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'gap',
      from_source_seq: o.from_source_seq, to_source_seq: o.to_source_seq,
      ...(o.reason ? { reason: o.reason } : {}),
    }));
  }

  /**
   * An interval the collector cannot characterise — FR-60. It never carries a
   * span: inventing one would assert what was lost along with the counter.
   * A verifier reports this as inconclusive, never ok.
   * @param {{ from_ts?: string, to_ts?: string, last_checkpoint_source_seq: number }} o
   */
  gapUnknown(o) {
    const ts = this.now().toISOString().replace(/\.(\d{3})\d*Z$/, '.$1Z');
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'gap_unknown',
      from_ts: o.from_ts ?? ts, to_ts: o.to_ts ?? ts,
      last_checkpoint_source_seq: o.last_checkpoint_source_seq,
    }));
  }

  /**
   * A padding leaf — FR-69, off by default. An explicit record kind with its own
   * record_seq, so record_seq == tree_size still holds; dummy leaves without
   * records would break exactly that.
   */
  padding() {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'padding',
      pad: randomBytes(16).toString('hex'),
    }));
  }

  /**
   * A policy change — FR-23, SEC-12. Chained and anchored like anything else,
   * which is what closes the downgrade attack: weakening the policy and then
   * tampering leaves a countersigned record of the weakening.
   * @param {{ previous: string, next: string }} o digests of the effective policies
   */
  policy(o) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'policy',
      previous_policy: o.previous, next_policy: o.next,
    }));
  }

  /**
   * Anchor a periodic summary over many batches — FR-53, FR-22.
   *
   * The roll-up's leaves are the CHECKPOINT NOTES, not the records. A public or
   * rate-limited witness then receives a handful of entries a day rather than
   * thousands, which is the only way a trust-minimised tier is affordable or
   * acceptable use at all: a Bitcoin commitment every 10 seconds is neither.
   *
   * It carries its own origin suffix and lives in its own directory, because a
   * roll-up read as a per-batch checkpoint would look like a checkpoint whose
   * root is not the root of this log — a false TREE_MISMATCH, which is the
   * worst thing a verifier can say.
   *
   * A reader can prove a single batch is under the roll-up by an ordinary
   * RFC 6962 inclusion proof over the same leaves, which is what makes the
   * roll-up a commitment to the history rather than to a number.
   *
   * @returns {Promise<{ rollup_seq: number, covers: number, leaves: Buffer[], note: string }>}
   */
  async rollup() {
    const notes = this.store.readCheckpoints();
    if (notes.length === 0) {
      throw new Error('no checkpoint to roll up: a roll-up over an empty tree commits to nothing');
    }
    const leaves = notes.map(n => Buffer.from(n.note, 'utf8'));
    const text = checkpointText({
      origin: `${this.origin}/rollup`,
      tree_size: leaves.length,
      root: treeRoot(leaves),
      suite: SUITE,
    });
    const note = encodeNote(text, [await signNote(text, this.signer)]);
    const rollup_seq = ++this.rollupSeq;
    this.store.writeRollup(rollup_seq, note);
    return { rollup_seq, covers: leaves.length, leaves, note };
  }

  /**
   * Reconcile the durable observation counter against what was written —
   * FR-60, FR-61. Call once, after opening, before collecting.
   *
   * Three outcomes, and the difference between them is the whole point:
   *
   * - The counter matches what was written: nothing was lost, declare nothing.
   *   A first run is not a loss, and declaring one would put a permanent
   *   unknown-loss interval at the head of every log ever created.
   * - The counter is AHEAD: those observations were spent and never written,
   *   and the span is exact, so FR-26's gap declaration names it.
   * - The counter is absent while records exist: it did not survive, so there
   *   is no exact span to name and FR-60's unknown-loss interval is declared
   *   instead — bounded by the last durable checkpoint and this restart.
   *
   * @returns {{ from_source_seq: number, to_source_seq: number }
   *          | { unknown: true, last_checkpoint_source_seq: number }
   *          | null}
   */
  reconcileObservations() {
    if (this.#reconciled) return null;
    const written = this.store.tip().source_seq;
    const durable = this.store.readObservationCounter();
    const hasRecords = this.store.readChain().length > 0;

    if (durable === null) {
      if (!hasRecords) {
        this.#reconciled = true;
        return null;
      }
      const at = this.store.readObservationCounterAt();
      this.gapUnknown({
        last_checkpoint_source_seq: written,
        ...(at ? { from_ts: at } : {}),
      });
      this.#reconciled = true;
      return { unknown: /** @type {true} */ (true), last_checkpoint_source_seq: written };
    }
    if (durable < written) {
      // The counter can only ever be ahead of or level with what was written.
      // Behind means the file was tampered with or restored from an older copy,
      // and inventing a negative span would be worse than refusing.
      throw new Error(
        `the observation counter is ${durable} but source_seq ${written} is already written: the `
        + 'counter is behind the record, which cannot happen in normal operation. The counter file '
        + 'has been replaced or restored from an older copy.',
      );
    }
    this.#reconciled = true;
    if (durable === written) return null;
    const span = { from_source_seq: written + 1, to_source_seq: durable };
    this.declareGap(span);
    // Continue from after the lost span: reusing those numbers would close the
    // hole, which is exactly what the declaration exists to keep open.
    this.sourceSeq = Math.max(this.sourceSeq, durable);
    return span;
  }

  /**
   * Write a gap declaration, falling back to the reserved slot — FR-58.
   *
   * The ordinary path first. If it fails for want of space, the reserve is
   * released and the declaration retried, because a store that cannot record
   * its own failure reports a clean history for a lossy run. If that fails
   * too, the condition is surfaced out of band and the collector degrades —
   * it does not carry on as though the gap were not there.
   *
   * @param {{ from_source_seq: number, to_source_seq: number, reason?: string }} span
   * @returns {import('./chain.mjs').ChainEntry}
   */
  declareGap(span) {
    try {
      return this.gap(span);
    } catch (first) {
      const freed = this.store.releaseReserve();
      if (freed) {
        // The failed append already degraded this collector, so the retry
        // would be refused before it reached the store and FR-58's whole
        // mechanism would be dead in production. Cleared for exactly one
        // attempt, and restored below whatever happens: the store is still
        // exhausted, and a collector that carried on because its gap
        // declaration succeeded would be claiming the opposite.
        const was = this.#degraded;
        this.#degraded = null;
        try {
          const entry = this.gap(span);
          this.#degraded = new Error(
            'the store is exhausted; the gap declaration was written using the reserved slot '
            + `(FR-58) and nothing further can be recorded: ${
              was instanceof Error ? was.message : String(was)}`,
          );
          return entry;
        } catch (second) {
          this.#degraded = was;
          this.#unrecordable(span, second);
        }
      }
      this.#unrecordable(span, first);
    }
  }

  /**
   * @param {{ from_source_seq: number, to_source_seq: number }} span
   * @param {unknown} cause
   * @returns {never}
   */
  #unrecordable(span, cause) {
    const detail = `the gap declaration for source_seq ${span.from_source_seq}-`
      + `${span.to_source_seq} could not be written even after releasing the reserve: `
      + `${cause instanceof Error ? cause.message : String(cause)}`;
    // Out of band: the place this would otherwise go is the thing that failed.
    if (this.onUnrecordable) this.onUnrecordable({ detail, span });
    this.#degraded = new Error(detail);
    throw new CollectorDegraded(this.#degraded);
  }

  /**
   * Declare how this epoch's signing key is held — FR-65.
   *
   * The declaration goes in the chain so that altering it later breaks the
   * chain, and so a countersignature over the checkpoint above it fixes when it
   * was made. What it establishes is that the operator asserted a class; it
   * does not establish the class, and the record says so in `custody_basis`.
   *
   * @returns {import('./chain.mjs').ChainEntry}
   */
  custody() {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'custody',
      epoch: this.epoch,
      public_key: this.signer.publicKey.toString('base64'),
      custody_class: this.signer.custody,
      custody_basis: 'operator-declared',
    }));
  }

  /**
   * Close the batch: compute the RFC 6962 root over the whole log, sign the
   * note, write it. The root is over every leaf so far, not over this batch —
   * a checkpoint says "this log now has tree_size entries", which is what makes
   * tree_size monotonic and a rollback detectable (DES-05).
   *
   * @returns {Promise<{ checkpoint_seq: number, tree_size: number, root: Buffer, note: string }>}
   */
  async checkpoint() {
    const leaves = this.store.readChain().map(e => e.leaf);
    if (leaves.length === 0) throw new Error('nothing to checkpoint: the log is empty');
    const root = treeRoot(leaves);
    this.#ensureRootEpoch();
    const text = checkpointText({ origin: this.origin, tree_size: leaves.length, root, suite: SUITE });
    const note = encodeNote(text, [await signNote(text, this.signer)]);
    const checkpoint_seq = ++this.checkpointSeq;
    this.store.writeCheckpoint(checkpoint_seq, note);
    // FR-61 — at each batch flush, so an unrecoverable crash loses at most the
    // current window and FR-60's interval is bounded rather than open-ended.
    this.store.writeObservationCounter(this.sourceSeq);
    return { checkpoint_seq, tree_size: leaves.length, root, note };
  }
}
