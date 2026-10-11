/**
 * Submitting checkpoints to witnesses — FR-13, FR-19, FR-20, FR-21, FR-22,
 * SCOPE-15, SCOPE-16, DES-08, DES-15.
 *
 * The checkpoint is written locally first and completely, as an unwitnessed
 * envelope, before any witness is asked anything. Everything in this module is
 * therefore optional at runtime: a configuration with no second party is a
 * supported configuration that establishes less, not an error, and a witness
 * outage widens the unwitnessed window rather than stopping collection. Never
 * block, mark unwitnessed, queue, report the window.
 *
 * Two things here are easy to get wrong and are deliberate:
 *
 * A countersignature that does not verify is DISCARDED, not stored. Storing it
 * would put a proof in the evidence that fails verification later, and the
 * first anyone would hear of it is an auditor's report. But with no acceptance
 * key configured, a countersignature is attached and reported as unverified —
 * the collector is not the verifier, and refusing to keep a proof it cannot
 * check would throw away evidence a reader with the right policy could use.
 * What it must not do is imply it checked.
 *
 * Quorum is counted PER CAPABILITY CLASS. Two time-only witnesses buy
 * redundancy of time, not independence of sequence. One aggregate number would
 * let an operator look well-witnessed while being unable to detect truncation
 * at all, which is the failure DES-20's review named.
 */

import { parseNote, parseCheckpointText, parseVkey, noteKeyId } from './note.mjs';
import { verifyNoteSignature } from './signer.mjs';
import { parseEnvelope, addCountersignature } from './envelope.mjs';
import { consistencyProof } from './merkle.mjs';

/**
 * What a witness can establish. Not a ranking: a TSA's independent clock is
 * not a weaker version of sequence state, it is a different thing.
 *
 * - `sequence` — remembers your heights and refuses a history that does not
 *   extend what it already signed. The only class that reaches truncation.
 * - `time` — an independent clock over the note digest.
 * - `existence` — existed-no-later-than, with no party to trust.
 */
export const CAPABILITY_CLASSES = Object.freeze(['sequence', 'time', 'existence']);

/** Default bound on the unwitnessed queue. */
export const QUEUE_CEILING = 1024;

/** Default per-witness wait. A witness is not on NFR-01's path, but it is on a wall clock. */
export const TIMEOUT_MS = 10_000;

export class AnchorError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'AnchorError'; }
}

/**
 * @typedef {object} WitnessAdapter
 * @property {string} id the issuer identity, which is what a quorum counts
 * @property {'c2sp-note'|'rfc3161'|'opentimestamps'} proof_type
 * @property {string[]} establishes one or more CAPABILITY_CLASSES
 * @property {'anchor'|'rollup'} tier anchor cadence or roll-up cadence
 * @property {(note: string, ctx: { old_size: number, consistency_proof: string[] })
 *   => Promise<import('./envelope.mjs').Countersignature>} submit
 */

export class Anchorer {
  /**
   * @param {object} o
   * @param {import('./store.mjs').Store} o.store
   * @param {WitnessAdapter[]} [o.witnesses]
   * @param {number} [o.quorum]
   * @param {Record<string, Uint8Array>} [o.acceptance] issuer -> raw public key,
   *   for the `c2sp-note` witnesses whose signatures can be checked locally
   * @param {number} [o.timeout_ms]
   * @param {number} [o.queue_ceiling]
   */
  constructor({ store, witnesses = [], quorum = 1, acceptance = {}, timeout_ms = TIMEOUT_MS, queue_ceiling = QUEUE_CEILING }) {
    this.store = store;
    this.quorum = quorum;
    this.acceptance = acceptance;
    this.timeout_ms = timeout_ms;
    this.queue_ceiling = queue_ceiling;
    /** Checkpoints written but not yet witnessed. @type {number[]} */
    this.queue = [];
    /** How many the ceiling has discarded. Reported, never silent. */
    this.dropped = 0;

    const ids = new Set();
    for (const w of witnesses) {
      if (ids.has(w.id)) {
        throw new AnchorError(
          `witness ${w.id} is configured more than once: a quorum made of one party submitting `
          + 'twice is not a quorum',
        );
      }
      ids.add(w.id);
      for (const cls of w.establishes) {
        if (!CAPABILITY_CLASSES.includes(cls)) {
          throw new AnchorError(
            `witness ${w.id} declares capability ${JSON.stringify(cls)}, which is not one of `
            + `${CAPABILITY_CLASSES.join(', ')}. An undeclared capability cannot be reported, and `
            + 'FR-57 requires the verifier to say what the set establishes.',
          );
        }
      }
    }
    this.witnesses = witnesses;
  }

  /** @returns {number[]} a copy, oldest first */
  queued() { return [...this.queue]; }

  /**
   * Submit checkpoint `seq` to the `anchor`-tier witnesses — FR-20.
   * @param {number} seq
   */
  async anchor(seq) { return this.#submit(seq, 'anchor'); }

  /**
   * Submit checkpoint `seq` to the `rollup`-tier witnesses — FR-22, FR-53.
   *
   * Separate because a Bitcoin commitment per 10 seconds is neither affordable
   * nor acceptable use. The hard tier runs at the roll-up cadence.
   * @param {number} seq
   */
  async rollup(seq) { return this.#submit(seq, 'rollup'); }

  /**
   * Submit a ROLL-UP to the `rollup`-tier witnesses — FR-53, FR-22.
   *
   * Separate from `rollup(seq)` above, which submits a per-batch checkpoint to
   * the slow tier. This submits the roll-up artefact itself, which is the thing
   * the hard tier is actually for.
   * @param {number} seq
   */
  async anchorRollup(seq) { return this.#submit(seq, 'rollup', { artefact: 'rollup' }); }

  /**
   * Retry what is queued, HIGHEST FIRST, and drop the rest once one succeeds.
   *
   * Anchoring the highest height makes the lower queued entries not merely
   * redundant but unsubmittable: a stateful witness that has advanced to height
   * 6 refuses height 4 as a regression (FR-43). Retrying oldest-first would
   * therefore have produced a run of 400s that were the queue's own doing, and
   * reported them as witness failures.
   *
   * `superseded` says which were dropped for that reason rather than silently
   * clearing them — an entry that disappears without explanation looks like one
   * that was anchored.
   */
  async flush() {
    /** @type {number[]} */
    const anchored = [];
    /** @type {number[]} */
    const superseded = [];
    /** @type {number[]} */
    const still = [];
    const descending = [...this.queue].sort((a, b) => b - a);
    for (const seq of descending) {
      if (anchored.length > 0) {
        // Something higher is already countersigned, and it covers this one.
        superseded.push(seq);
        continue;
      }
      const r = await this.#submit(seq, 'anchor', { requeue: false });
      if (r.attached.length > 0) anchored.push(seq);
      else still.push(seq);
    }
    this.queue = still.sort((a, b) => a - b);
    return {
      anchored,
      superseded: superseded.sort((a, b) => a - b),
      queued: [...this.queue],
    };
  }

  /**
   * @param {number} seq
   * @param {'anchor'|'rollup'} tier
   * @param {{ requeue?: boolean, artefact?: 'checkpoint'|'rollup' }} [opts]
   */
  async #submit(seq, tier, opts = {}) {
    const artefact = opts.artefact ?? 'checkpoint';
    const raw = artefact === 'rollup'
      ? this.store.readRollupEnvelope(seq)
      : this.store.readCheckpointEnvelope(seq);
    if (raw === null) throw new AnchorError(`no ${artefact} ${seq} in this store`);
    const parsed = parseEnvelope(raw);
    if (!parsed.ok || parsed.note === null) {
      throw new AnchorError(
        `${artefact} ${seq}'s envelope does not parse, so there is nothing safe to submit: `
        + parsed.findings.map(f => f.detail).join('; '),
      );
    }
    const note = parsed.note;
    const due = this.witnesses.filter(w => w.tier === tier);

    // What the witness needs to prove the submission extends what it holds.
    // The highest previously witnessed size is the honest `old_size`: anything
    // larger would be claiming a history the witness has not seen.
    // A roll-up's heights are its own ordinals, not the record log's, so the
    // record-log context would be a lie about what the witness is being asked
    // to extend.
    const ctx = artefact === 'rollup'
      ? { old_size: 0, consistency_proof: [] }
      : this.#consistencyContext(seq, parsed.tree_size);

    /** @type {{ issuer: string, verified: boolean, establishes: string[] }[]} */
    const attached = [];
    /** @type {{ issuer: string, detail: string }[]} */
    const failed = [];
    // `raw` is always envelope JSON: the store synthesises one even for a
    // legacy `.note` file. An earlier version guarded this with
    // `parsed.note === raw`, comparing a note's text to the JSON wrapping it —
    // a condition that could never be true, reading as though it handled a
    // case it never reached.
    let env = /** @type {import('./envelope.mjs').Envelope} */ (JSON.parse(raw));

    for (const w of due) {
      /** @type {import('./envelope.mjs').Countersignature} */
      let cs;
      try {
        cs = await withTimeout(w.submit(note, ctx), this.timeout_ms, w.id);
      } catch (e) {
        failed.push({ issuer: w.id, detail: e instanceof Error ? e.message : String(e) });
        continue;
      }
      if (cs?.issuer !== w.id) {
        // An issuer field is a claim; the adapter's configured identity is what
        // the operator chose to trust.
        failed.push({
          issuer: w.id,
          detail: `the adapter returned a proof issued by ${JSON.stringify(cs?.issuer)}, not ${w.id}`,
        });
        continue;
      }
      const verified = await this.#check(note, cs);
      if (verified === false) {
        failed.push({
          issuer: w.id,
          detail: `the countersignature from ${w.id} does not verify under the key configured for `
            + 'it, so it is discarded rather than stored as evidence that fails later',
        });
        continue;
      }
      try {
        env = addCountersignature(env, cs);
      } catch (e) {
        failed.push({ issuer: w.id, detail: e instanceof Error ? e.message : String(e) });
        continue;
      }
      attached.push({ issuer: w.id, verified: verified === true, establishes: w.establishes });
    }

    if (attached.length > 0) {
      if (artefact === 'rollup') this.store.writeRollupEnvelope(seq, env);
      else this.store.writeCheckpointEnvelope(seq, env);
    }

    // Queue only when a witness was asked and none answered. An empty witness
    // set is SCOPE-15's supported configuration, and queueing for witnesses
    // that do not exist would report an outage that is not happening.
    if (opts.requeue !== false && due.length > 0 && attached.length === 0) this.#enqueue(seq);
    if (attached.length > 0) this.queue = this.queue.filter(q => q !== seq);

    /** @type {Record<string, number>} */
    const quorum = Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, 0]));
    const counted = new Set();
    for (const a of attached) {
      if (counted.has(a.issuer)) continue;      // one issuer, one vote
      counted.add(a.issuer);
      for (const cls of a.establishes) quorum[cls] = (quorum[cls] ?? 0) + 1;
    }
    const quorum_met = Object.fromEntries(
      CAPABILITY_CLASSES.map(c => [c, (quorum[c] ?? 0) >= this.quorum]),
    );

    return { seq, attached, failed, quorum, quorum_met, unwitnessed: attached.length === 0 };
  }

  /**
   * The NEWEST are kept.
   *
   * This was the other way round, on the reasoning that the oldest entries had
   * the widest unwitnessed window. That is backwards: the tree is append-only,
   * so a countersignature at the highest height establishes every record below
   * it. Keeping the oldest meant that after an outage the operator could prove
   * height 3 when height 6 was available — the queue discarded exactly the
   * entries worth retrying.
   * @param {number} seq
   */
  #enqueue(seq) {
    if (this.queue.includes(seq)) return;
    this.queue.push(seq);
    while (this.queue.length > this.queue_ceiling) {
      this.queue.shift();
      this.dropped += 1;
    }
  }

  /**
   * What a stateful witness needs to see that this submission extends what it
   * already holds — FR-43.
   *
   * The proof is computed over the tree the checkpoint being submitted COMMITS
   * TO, not over the log as it is now. Those differ whenever records land
   * between the checkpoint and the anchoring call, which under fail-open is
   * most of the time — and a proof over the current leaves would verify while
   * describing a tree the checkpoint does not, leaving the witness holding a
   * root for a height that was never checkpointed.
   *
   * The highest previously WITNESSED size is the honest `old_size`: a proof
   * from a height the witness has not seen proves consistency with something
   * else, and it refuses one, correctly.
   *
   * @param {number} seq
   * @param {number|null} tree_size what this checkpoint commits to
   * @returns {{ old_size: number, consistency_proof: string[] }}
   */
  #consistencyContext(seq, tree_size) {
    let old_size = 0;
    for (const { seq: s, blob } of this.store.readCheckpoints()) {
      if (s >= seq) continue;
      const p = parseEnvelope(blob);
      if (!p.ok || p.unwitnessed || p.tree_size === null) continue;
      if (p.tree_size > old_size) old_size = p.tree_size;
    }
    if (old_size === 0 || tree_size === null || tree_size <= old_size) {
      return { old_size, consistency_proof: [] };
    }
    // This used to return an empty proof with a comment saying the caller would
    // supply one. No caller did, so a stateful witness refused every submission
    // after the first — and nothing caught it, because the only test that wired
    // the two together anchored exactly one checkpoint. A seam exercised once
    // looks like a seam that works.
    const leaves = this.store.readChain().map(e => e.leaf);
    if (leaves.length < tree_size) {
      // The log no longer reaches the height this checkpoint claims. Submitting
      // without a proof lets the witness refuse and say so, which is a better
      // outcome than this code deciding what happened.
      return { old_size, consistency_proof: [] };
    }
    return {
      old_size,
      consistency_proof: consistencyProof(leaves.slice(0, tree_size), old_size)
        .map(b => b.toString('base64')),
    };
  }

  /**
   * @param {string} note
   * @param {import('./envelope.mjs').Countersignature} cs
   * @returns {Promise<boolean|null>} true verified, false refuted, null not checkable here
   */
  async #check(note, cs) {
    const key = this.acceptance[cs.issuer];
    if (!key) return null;
    if (cs.type !== 'c2sp-note' || typeof cs.line !== 'string') return null;
    try {
      const text = parseNote(note).text;
      const line = parseNote(`${text}\n${cs.line}\n`).signatures.find(s => s.name === cs.issuer);
      if (!line) return false;
      const pub = Buffer.from(key);
      return await verifyNoteSignature(text, line, {
        name: cs.issuer, publicKey: pub, keyId: noteKeyId(cs.issuer, pub),
      });
    } catch {
      return false;
    }
  }
}

/**
 * @template T
 * @param {Promise<T>} p @param {number} ms @param {string} id
 * @returns {Promise<T>}
 */
function withTimeout(p, ms, id) {
  /** @type {NodeJS.Timeout} */
  let t;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise((_, reject) => {
      t = setTimeout(() => reject(new Error(`witness ${id} timed out after ${ms} ms`)), ms);
      t.unref?.();
    }),
  ]);
}

export { parseVkey, parseCheckpointText };
