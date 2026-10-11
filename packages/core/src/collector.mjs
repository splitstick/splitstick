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
import { chainEntry, genesis } from './chain.mjs';
import { newSalt } from './leaf.mjs';
import { treeRoot } from './merkle.mjs';
import { checkpointText, encodeNote } from './note.mjs';
import { signNote } from './signer.mjs';
import { extractRefs } from './content.mjs';
import { SCHEMA_VERSION, SUITE } from './record.mjs';

/** @param {unknown} v @returns {v is Uint8Array} */
const isBytes = v => v instanceof Uint8Array;

export class Collector {
  /** @type {Map<string, { correlation: string, attempts: number }>} in-memory only */
  #actions = new Map();

  /**
   * @param {object} o
   * @param {import('./store.mjs').Store} o.store
   * @param {import('./config.mjs').Config} o.config
   * @param {import('./signer.mjs').Signer} o.signer a signing function, never a key — SEC-14
   * @param {string} o.collector the instance identity that scopes the chain
   * @param {string} [o.origin] the log origin; defaults to the signer name
   * @param {() => Date} [o.now] injected so tests are not clock-dependent
   * @param {string} [o.build] the build digest a heartbeat attests — SEC-22
   */
  constructor({ store, config, signer, collector, origin, now, build }) {
    this.store = store;
    this.config = config;
    this.signer = signer;
    this.collector = collector;
    this.origin = origin ?? signer.name;
    this.now = now ?? (() => new Date());
    this.build = build ?? 'sha256:unattested';

    const tip = store.tip();
    this.recordSeq = tip.record_seq;
    this.sourceSeq = tip.source_seq;
    this.head = tip.record_seq === 0 ? genesis() : tip.head;
    this.checkpointSeq = store.lastCheckpointSeq();
  }

  /** The log's tree size — the record count, always equal to record_seq. */
  get tree_size() { return this.recordSeq; }

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
    const salt = newSalt();
    const e = chainEntry(record, salt, this.head);   // validates; throws before any mutation
    this.store.append(e);
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
    const c = this.#commitAll({
      agent: a.agent,
      args: a.args,
      result: a.result,
      reviewer: a.approval ? a.approval.reviewer : undefined,
      request: a.approval ? a.approval.request : undefined,
    }, 'result');

    const record = this.#envelope({
      run: a.run ?? null,
      source_seq: this.observe(),
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
    const text = checkpointText({ origin: this.origin, tree_size: leaves.length, root, suite: SUITE });
    const note = encodeNote(text, [await signNote(text, this.signer)]);
    const checkpoint_seq = ++this.checkpointSeq;
    this.store.writeCheckpoint(checkpoint_seq, note);
    return { checkpoint_seq, tree_size: leaves.length, root, note };
  }
}
