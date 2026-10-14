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

/** First retry delay, and the cap it grows to — OPS-02. */
export const BACKOFF_BASE_MS = 30_000;
export const BACKOFF_CEILING_MS = 3_600_000;

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
 * @property {boolean} [qualified] LEG-13 — the operator's DECLARATION that this
 *   is a qualified trust service under eIDAS. Carried so a deployment can be
 *   described; nothing in the verifier rests on it, because the Art. 41
 *   presumption is a conclusion the READER draws from their own policy.
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
   * @param {() => number} [o.now] injected so backoff is testable
   * @param {number} [o.unwitnessed_ceiling_ms] FR-68
   * @param {number} [o.backoff_ceiling_ms]
   * @param {(e: { oldest_checkpoint_seq: number, unwitnessed_for_ms: number,
   *   since: string, queued: number }) => void} [o.onCeilingBreached] FR-68 —
   *   raised OUT OF BAND. It must not write a record: an alert about the log's
   *   integrity, written into that log, asks the suspect to carry the complaint.
   */
  constructor({
    store, witnesses = [], quorum = 1, acceptance = {}, timeout_ms = TIMEOUT_MS,
    queue_ceiling = QUEUE_CEILING, now, unwitnessed_ceiling_ms, backoff_ceiling_ms,
    onCeilingBreached,
  }) {
    this.store = store;
    this.quorum = quorum;
    this.acceptance = acceptance;
    this.timeout_ms = timeout_ms;
    this.queue_ceiling = queue_ceiling;
    this.now = now ?? (() => Date.now());
    this.unwitnessed_ceiling_ms = unwitnessed_ceiling_ms ?? null;
    this.backoff_ceiling_ms = backoff_ceiling_ms ?? BACKOFF_CEILING_MS;
    this.onCeilingBreached = onCeilingBreached ?? null;
    /**
     * Breaches observed, kept after they clear. The window happened; a cleared
     * alert must not erase it.
     * @type {{ oldest_checkpoint_seq: number, unwitnessed_for_ms: number,
     *          since: string, queued: number }[]}
     */
    this.breaches = [];
    this.#breached = false;
    /**
     * Checkpoints written but not yet witnessed — NFR-13, read from disk.
     * @type {{ checkpoint_seq: number, since: string, attempts: number }[]}
     */
    this.entries = store.readQueue();
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

  /** @type {boolean} */
  #breached;

  /** @returns {number[]} a copy, oldest first */
  queued() { return this.entries.map(e => e.checkpoint_seq).sort((a, b) => a - b); }

  /**
   * When checkpoint `seq` may next be attempted — OPS-02.
   *
   * Exponential from BACKOFF_BASE_MS and capped, because an unbounded doubling
   * schedules the next attempt past the life of the deployment, and a witness
   * that returns after a long outage should be used rather than waited for.
   * @param {number} seq
   */
  nextAttemptAt(seq) {
    const e = this.entries.find(x => x.checkpoint_seq === seq);
    if (!e) return 0;
    const since = Date.parse(e.since);
    // An entry fresh from anchor() is eligible IMMEDIATELY. Its failure has
    // already been counted — anchor() tried and the witness was down — and the
    // caller choosing to flush is itself the cadence. A first version imposed
    // the base delay on attempts 0, so a witness that came back in two seconds
    // went unused for thirty, which is the opposite of what OPS-02 asks for.
    //
    // The delay applies after a failed RETRY, doubling each time and capped:
    // an unbounded doubling schedules the next attempt past the life of the
    // deployment.
    const delay = e.attempts === 0
      ? 0
      : Math.min(BACKOFF_BASE_MS * 2 ** (e.attempts - 1), this.backoff_ceiling_ms);
    return (Number.isNaN(since) ? this.now() : since) + delay;
  }

  /** FR-68 — is the oldest unwitnessed batch past the ceiling? */
  ceilingBreached() { return this.#breached; }

  /**
   * Check the ceiling and raise the alert at most once per breach.
   *
   * Once per breach, not once per flush: an alert that repeats on every retry
   * is an alert nobody reads, and the retry cadence is not information about
   * the outage.
   */
  #checkCeiling() {
    const ceiling = this.unwitnessed_ceiling_ms;
    if (ceiling === null || this.entries.length === 0) {
      this.#breached = false;
      return;
    }
    const first = this.entries[0];
    if (!first) { this.#breached = false; return; }
    const oldest = this.entries.reduce(
      (m, e) => (Date.parse(e.since) < Date.parse(m.since) ? e : m), first);
    const age = this.now() - Date.parse(oldest.since);
    // An unreadable age counts as OVER, not under. The store refuses such an
    // entry on read, so this should be unreachable — and if it ever is
    // reachable, the safe direction is to raise the alarm rather than to
    // suppress it, which is how the previous version failed.
    const over = !Number.isFinite(age) || age > ceiling;
    if (over && !this.#breached) {
      const event = {
        oldest_checkpoint_seq: oldest.checkpoint_seq,
        unwitnessed_for_ms: age,
        since: oldest.since,
        queued: this.entries.length,
      };
      this.breaches.push(event);
      this.#breached = true;
      // Out of band. Deliberately not a record: see the constructor's note.
      if (this.onCeilingBreached) this.onCeilingBreached(event);
      return;
    }
    if (!over) this.#breached = false;
  }

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
    const waiting = [];
    /** @type {typeof this.entries} */
    const still = [];
    // Whether some HIGHER checkpoint got at least one issuer to sign in this
    // flush. That issuer has now advanced past the lower heights, so they are
    // unsubmittable to it (FR-43); and an issuer still outstanding wants the
    // highest, not a lower one. Tracked separately from `anchored` because a
    // partially witnessed checkpoint still advances a witness while remaining
    // queued — reading `anchored` for this would resubmit heights the witness
    // must refuse and report its refusals as outages.
    let advanced = false;
    const descending = [...this.entries].sort((a, b) => b.checkpoint_seq - a.checkpoint_seq);
    for (const entry of descending) {
      const seq = entry.checkpoint_seq;
      if (advanced) {
        // Something higher is countersigned, and it covers this one.
        superseded.push(seq);
        continue;
      }
      if (this.now() < this.nextAttemptAt(seq)) {
        // OPS-02 — still inside its backoff window. Reported rather than
        // silently retried, so a caller can tell waiting from failing.
        waiting.push(seq);
        still.push(entry);
        continue;
      }
      const r = await this.#submit(seq, 'anchor', { requeue: false });
      if (r.attached.length > 0) advanced = true;
      // Only a SUFFICIENTLY witnessed checkpoint leaves the queue. One answer
      // out of a required two is progress, not completion.
      if (r.sufficient) anchored.push(seq);
      else still.push({ ...entry, attempts: entry.attempts + 1 });
    }
    this.entries = still.sort((a, b) => a.checkpoint_seq - b.checkpoint_seq);
    this.store.writeQueue(this.entries);
    this.#checkCeiling();
    return {
      anchored,
      superseded: superseded.sort((a, b) => a - b),
      waiting: waiting.sort((a, b) => a - b),
      queued: this.queued(),
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

    // What a witness needs to prove the submission extends what IT holds. The
    // height that witness last signed is the honest `old_size`: anything
    // larger claims a history it has not seen.
    // A roll-up's heights are its own ordinals, not the record log's, so the
    // record-log context would be a lie about what the witness is being asked
    // to extend.
    const heights = artefact === 'rollup' ? new Map() : this.#witnessedHeights(seq);

    // Issuers whose countersignature is already on this envelope from an
    // earlier attempt. Asking them again earns a duplicate-issuer refusal,
    // which would read as a witness failure on every retry and would stop the
    // quorum this entry is queued for from ever being reached.
    const already = parsed.issuers;
    const outstanding = due.filter(w => !already.has(w.id));

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

    for (const w of outstanding) {
      const ctx = artefact === 'rollup'
        ? { old_size: 0, consistency_proof: [] }
        : this.#consistencyContext(seq, parsed.tree_size, heights.get(w.id) ?? 0);
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

    // The quorum counts ALL the evidence on the envelope, not just what this
    // attempt added — otherwise a second witness answering on a retry would be
    // counted alone, never reach two, and requeue forever.
    const signed = new Set([...already, ...attached.map(a => a.issuer)]);
    /** @type {Record<string, number>} */
    const quorum = Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, 0]));
    for (const issuer of signed) {                        // one issuer, one vote
      for (const cls of this.#establishes(issuer)) quorum[cls] = (quorum[cls] ?? 0) + 1;
    }
    const quorum_met = Object.fromEntries(
      CAPABILITY_CLASSES.map(c => [c, (quorum[c] ?? 0) >= this.quorum]),
    );
    const target = this.#quorumTarget(due);
    const sufficient = Object.entries(target).every(([c, n]) => (quorum[c] ?? 0) >= n);
    /** @type {string[]} */
    const missing = outstanding.filter(w => !signed.has(w.id)).map(w => w.id);

    // The queue holds checkpoints that are INSUFFICIENTLY witnessed, not only
    // those witnessed by nobody. One answer out of a required two left the
    // entry dequeued and the second witness never retried, so a deployment
    // that asked for two independent sequence witnesses silently kept running
    // on one, permanently, with nothing reporting it. An empty witness set is
    // still SCOPE-15's supported configuration: queueing for witnesses that do
    // not exist would report an outage that is not happening.
    const queued = this.entries.some(e => e.checkpoint_seq === seq);
    if (!sufficient && due.length > 0) {
      if (opts.requeue !== false && !queued) this.#enqueue(seq);
    } else if (queued) {
      this.entries = this.entries.filter(e => e.checkpoint_seq !== seq);
      this.store.writeQueue(this.entries);
    }
    this.#checkCeiling();

    return {
      seq, attached, failed, quorum, quorum_met, sufficient, missing,
      unwitnessed: signed.size === 0,
    };
  }

  /**
   * What class(es) an issuer establishes, per the CONFIGURED witness set.
   *
   * An issuer on the envelope that is not in the configuration counts towards
   * no class: the operator never said what it is good for, and guessing would
   * let an unknown party fill a quorum.
   * @param {string} issuer
   */
  #establishes(issuer) {
    return this.witnesses.find(w => w.id === issuer)?.establishes ?? [];
  }

  /**
   * How many countersignatures each class actually needs here.
   *
   * The configured quorum, BOUNDED by how many witnesses could ever answer for
   * that class. A quorum of two against a single witness is unreachable, and
   * an unreachable target would keep every checkpoint queued and breach the
   * FR-68 ceiling forever rather than ever clearing. `quorum_met` still reports
   * the configured number unmet, and SEC-04 is what flags a set that small.
   *
   * A class no due witness establishes is not a target: it is a thing this
   * witness set does not do, which FR-57 reports.
   * @param {WitnessAdapter[]} due
   */
  #quorumTarget(due) {
    /** @type {Record<string, number>} */
    const target = {};
    for (const cls of CAPABILITY_CLASSES) {
      const n = due.filter(w => w.establishes.includes(cls)).length;
      if (n > 0) target[cls] = Math.min(this.quorum, n);
    }
    return target;
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
    if (this.entries.some(e => e.checkpoint_seq === seq)) return;
    const entry = {
      checkpoint_seq: seq,
      since: new Date(this.now()).toISOString(),
      attempts: 0,
    };
    this.entries.push(entry);
    this.entries.sort((a, b) => a.checkpoint_seq - b.checkpoint_seq);
    let trimmed = false;
    while (this.entries.length > this.queue_ceiling) {
      this.entries.shift();
      this.dropped += 1;
      trimmed = true;
    }
    // THIS entry, not whatever sorted last. Appending `entries.at(-1)` meant
    // that anchoring an older checkpoint appended the newest one a second time
    // and never persisted the new entry at all — the disk held [2,3,3] while
    // memory held [1,2,3], so checkpoint 1 was lost on restart. A batch that
    // never gets witnessed is precisely what NFR-13 exists to prevent.
    if (trimmed || !this.entries.includes(entry)) this.store.writeQueue(this.entries);
    else this.store.appendQueue(entry);
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
  /**
   * The highest tree_size each issuer has already countersigned, below `seq`.
   *
   * PER ISSUER, not per set. This used to take the highest size witnessed by
   * ANYBODY and hand it to every witness as `old_size`. With one witness that
   * is the same number. With two it is wrong for whichever one is behind: a
   * witness returning from an outage would be asked to extend a tree it never
   * signed, refuse, and go on refusing — so the queue could never clear by
   * waiting, which is the only thing the queue does.
   *
   * @param {number} seq
   * @returns {Map<string, number>}
   */
  #witnessedHeights(seq) {
    /** @type {Map<string, number>} */
    const heights = new Map();
    for (const { seq: s, blob } of this.store.readCheckpoints()) {
      if (s >= seq) continue;
      const p = parseEnvelope(blob);
      if (!p.ok || p.unwitnessed || p.tree_size === null) continue;
      for (const issuer of p.issuers) {
        if ((heights.get(issuer) ?? 0) < p.tree_size) heights.set(issuer, p.tree_size);
      }
    }
    return heights;
  }

  /**
   * @param {number} seq
   * @param {number|null} tree_size
   * @param {number} old_size the height THIS issuer last signed
   */
  #consistencyContext(seq, tree_size, old_size) {
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
