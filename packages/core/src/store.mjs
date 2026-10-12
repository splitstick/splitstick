/**
 * The on-disk store — DES-13.
 *
 *   chain/<collector>.jsonl       records, leaves, heads.  NEVER DELETED
 *   salts/<collector>.jsonl       record_seq -> salt.      DELETABLE per record
 *   checkpoints/<collector>/<n>.note   C2SP notes                 [DES-07]
 *   succession/<collector>.jsonl  the epoch chain.         NEVER DELETED
 *   rollups/<collector>/<n>.json  roll-up envelopes        [FR-53]
 *   content/<collector>/      payloads, encrypted.      DELETABLE
 *   keys/<collector>/         per-content keys.         DELETABLE
 *   queue/<collector>.jsonl   unwitnessed batches.     DURABLE  [DES-15, NFR-13]
 *   counter/<collector>.json  the observation counter           [FR-61]
 *   reserve/<collector>.slot  space kept for a gap declaration  [FR-58]
 *
 * The split is the whole point: Article 19 asks for months of logs accessible
 * and Article 17 asks for erasure, and those are only compatible if the two
 * live in different stores. The chain has no retention policy because it holds
 * nothing to retain.
 *
 * Both journals are append-only JSONL. A `record_seq -> salt` map rewritten on
 * every append is O(n²) and would breach NFR-01 within a few thousand records;
 * erasure rewrites the salt file, which is rare and bounded.
 *
 * The two journals are held open. Reopening an append-only file for every
 * record measured at 0.093 ms against 0.008 ms for a write to an open
 * descriptor — an eleven-fold difference on a 1 ms budget, for no benefit.
 * DES-13 already requires one writer per collector, so holding the descriptor
 * takes nothing away.
 */

import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, openSync, writeSync, closeSync, renameSync, unlinkSync, truncateSync } from 'node:fs';
import { randomBytes } from 'node:crypto';


import { join } from 'node:path';
import { ContentStore } from './content.mjs';
import { isTimestamp } from './record.mjs';
import { buildEnvelope, parseEnvelope } from './envelope.mjs';
import { WriteLock } from './writelock.mjs';

export class Store {
  /** @type {number|null} */
  #chainFd = null;
  /** @type {number|null} */
  #saltsFd = null;

  /**
   * @param {string} root
   * @param {string} collector the collector instance identity — FR-56
   */
  constructor(root, collector) {
    this.root = root;
    this.collector = collector;
    for (const d of ['chain', 'salts', 'queue', 'succession', 'counter', 'reserve']) {
      mkdirSync(join(root, d), { recursive: true });
    }
    // Checkpoints are scoped to the collector, like the chain and the salts.
    // A shared directory meant two honest collectors in one store each verified
    // as `fail`, because each was asked to account for the other's signed
    // notes — and the ordinals collided besides.
    this.checkpointDir = join(root, 'checkpoints', collector);
    mkdirSync(this.checkpointDir, { recursive: true });
    // Roll-ups live apart from checkpoints. A roll-up among them would be read
    // as a checkpoint whose root is not the root of this log — a false
    // TREE_MISMATCH, which is the worst possible thing for a verifier to say.
    this.rollupDir = join(root, 'rollups', collector);
    mkdirSync(this.rollupDir, { recursive: true });
    this.chainPath = join(root, 'chain', `${collector}.jsonl`);
    this.saltsPath = join(root, 'salts', `${collector}.jsonl`);
    // Never deleted, like the chain. A retired epoch's public key is what keeps
    // its old signatures verifiable, so erasing the succession journal would
    // destroy the ability to check history rather than the history's content.
    this.successionPath = join(root, 'succession', `${collector}.jsonl`);
    // NFR-13 — durable. An in-memory queue loses exactly the evidence an
    // outage created, and an outage is when a restart is most likely: the two
    // failures compound rather than being independent.
    this.queuePath = join(root, 'queue', `${collector}.jsonl`);
    this.counterPath = join(root, 'counter', `${collector}.json`);
    // FR-58 — space kept back so a gap declaration can be written when
    // everything else has failed. A store that cannot record its own failure
    // reports a clean history for a lossy run, which is the worst outcome
    // available: the log looks complete precisely when it is not.
    //
    // 64 KiB, which is four orders of magnitude more than one declaration
    // needs. The number is generous on purpose: the cost is a file nobody
    // reads, and the thing being bought is the ability to say what went wrong.
    this.reserveBytes = 64 * 1024;
    this.reservePath = join(root, 'reserve', `${collector}.slot`);
    if (!existsSync(this.reservePath)) {
      try {
        writeFileSync(this.reservePath, Buffer.alloc(this.reserveBytes, 0), { mode: 0o600 });
      } catch {
        // Already out of space, or a read-only store. Opening must still
        // succeed: a verifier opens a store it cannot write to, and refusing
        // here would make damage unreadable.
      }
    }
    // One lock per collector, covering the journals AND the content store.
    // Holding it only inside ContentStore.putGroup() left every record that
    // externalises nothing — heartbeat, gap, policy, padding — unprotected, so
    // two writers sharing a collector identity both chained from genesis.
    this.lock = new WriteLock(join(root, '.locks', `${collector}.lock`));
    this.content = new ContentStore(root, collector, this.lock);

  }

  /**
   * Append one chain entry. The record and the chain metadata go to chain/;
   * the salt goes to salts/, because the chain is never deleted and a salt
   * stored there could never be crypto-shredded (FR-36).
   * @param {import('./chain.mjs').ChainEntry} e
   */
  append(e) {
    if (e.salt === null) throw new TypeError('a record is written with its salt; erasure comes later');
    this.lock.claim();
    if (this.#chainFd === null) this.#chainFd = openSync(this.chainPath, 'a', 0o600);
    if (this.#saltsFd === null) this.#saltsFd = openSync(this.saltsPath, 'a', 0o600);

    // The SALT first, then the chain line. Two files cannot be written
    // atomically, so the order decides what a partial failure leaves behind.
    // Chain-first left a committed record whose salt was missing while the
    // collector's own position had not advanced — the next append then reused
    // the sequence, and a verifier called a disk-full incident tampering.
    // Salt-first leaves at worst an orphan salt for a record that was never
    // written, which joins to nothing and says nothing.
    const salt = JSON.stringify({
      record_seq: e.record.record_seq, salt: e.salt.toString('hex'),
    }) + '\n';
    const line = JSON.stringify({
      record: e.record,
      leaf: e.leaf.toString('hex'),
      prev: e.prev.toString('hex'),
      head: e.head.toString('hex'),
    }) + '\n';

    this.#writeAll(this.#saltsFd, salt, this.saltsPath);
    this.#writeAll(this.#chainFd, line, this.chainPath);
  }

  /**
   * Append one epoch to the succession journal — FR-11.
   *
   * Not under the journal descriptors: this is written once per epoch, not once
   * per record, so there is nothing to amortise and an open descriptor would
   * only widen the window in which a crash could tear it.
   * @param {import('./succession.mjs').SuccessionEntry} entry
   */
  appendEpoch(entry) {
    this.lock.claim();
    const fd = openSync(this.successionPath, 'a', 0o600);
    try {
      this.#writeAll(fd, JSON.stringify(entry) + '\n', this.successionPath);
    } finally {
      closeSync(fd);
    }
  }

  /** @returns {import('./succession.mjs').SuccessionEntry[]} */
  readSuccession() { return this.readSuccessionDetailed().entries; }

  /**
   * The newline is the commit marker here as it is for the chain: an entry
   * without one was being written when the process died, and parsing half of
   * it would invent an epoch.
   * @returns {{ entries: import('./succession.mjs').SuccessionEntry[],
   *             torn: boolean, malformed: number[] }}
   */
  readSuccessionDetailed() {
    if (!existsSync(this.successionPath)) return { entries: [], torn: false, malformed: [] };
    const raw = readFileSync(this.successionPath, 'utf8');
    const torn = raw.length > 0 && !raw.endsWith('\n');
    const lines = raw.split('\n');
    if (torn) lines.pop();
    /** @type {import('./succession.mjs').SuccessionEntry[]} */
    const entries = [];
    /** @type {number[]} */
    const malformed = [];
    lines.forEach((line, i) => {
      if (line === '') return;
      try { entries.push(JSON.parse(line)); } catch { malformed.push(i + 1); }
    });
    return { entries, torn, malformed };
  }

  /**
   * Write every byte, or throw. `writeSync` may report a short write, and a
   * truncated JSON line is a torn record — the verifier handles one at the end
   * of a file, but it should not be this code's doing.
   * @param {number} fd @param {string} text @param {string} path
   */
  #writeAll(fd, text, path) {
    const buf = Buffer.from(text, 'utf8');
    let off = 0;
    while (off < buf.length) {
      const n = writeSync(fd, buf, off, buf.length - off);
      if (n <= 0) throw new Error(`short write to ${path}: ${off} of ${buf.length} bytes`);
      off += n;
    }
  }

  /** Release the journal descriptors. Idempotent. */
  close() {
    for (const fd of [this.#chainFd, this.#saltsFd]) if (fd !== null) closeSync(fd);
    this.#chainFd = null;
    this.#saltsFd = null;
    this.content.close();     // releases the shared lock
    this.lock.release();
  }

  /**
   * Read the salt journal, tolerating damage.
   *
   * This used to parse every line eagerly, so one incomplete line threw out of
   * readChainDetailed, out of tip(), and out of the Collector constructor —
   * after a torn salt write the store could not be opened at all and the
   * verifier crashed on it. Since the salt is now the first of the two writes,
   * that was also the likelier half to be torn.
   * @returns {{ salts: Map<number, Buffer>, torn: boolean, malformed: number[] }}
   */
  #readSaltsDetailed() {
    /** @type {Map<number, Buffer>} */
    const salts = new Map();
    /** @type {number[]} */
    const malformed = [];
    let torn = false;
    if (!existsSync(this.saltsPath)) return { salts, torn, malformed };

    const raw = readFileSync(this.saltsPath, 'utf8');
    // The newline is the commit marker. See readChainDetailed.
    torn = raw.length > 0 && !raw.endsWith('\n');
    const body = raw.split('\n').filter(Boolean);
    const committed = torn ? body.slice(0, -1) : body;
    committed.forEach((line, i) => {
      try {
        const { record_seq, salt } = JSON.parse(line);
        if (!Number.isInteger(record_seq) || typeof salt !== 'string') {
          throw new SyntaxError('a salt line is a record_seq and a hex salt');
        }
        salts.set(record_seq, Buffer.from(salt, 'hex'));
      } catch {
        malformed.push(i + 1);
      }
    });
    return { salts, torn, malformed };
  }

  /**
   * Read the chain back, joining each entry to its salt. A record whose salt
   * has been shredded comes back with `salt: null`, which recomputeChain
   * reports as inconclusive rather than as a failure.
   *
   * An unparseable line is NOT thrown. A crash during an append leaves a
   * partial line, which is the ordinary consequence of a crash rather than
   * evidence of anything, and a verifier that exits with a SyntaxError has
   * failed to do its job. `readChainDetailed` returns the damage alongside the
   * entries so the caller can decide; a torn LAST line and a corrupted middle
   * one mean very different things.
   * @returns {import('./chain.mjs').ChainEntry[]}
   */
  readChain() { return this.readChainDetailed().entries; }

  /**
   * @returns {{
   *   entries: import('./chain.mjs').ChainEntry[],
   *   torn: boolean,
   *   malformed: { line: number, reason: string }[],
   *   salts_torn: boolean,
   *   salts_malformed: number[],
   * }}
   */
  readChainDetailed() {
    const sj = this.#readSaltsDetailed();
    if (!existsSync(this.chainPath)) {
      return { entries: [], torn: false, malformed: [], salts_torn: sj.torn, salts_malformed: sj.malformed };
    }
    const salts = sj.salts;
    const raw = readFileSync(this.chainPath, 'utf8');

    /**
     * The newline IS the commit marker, and that is the whole rule.
     *
     * Deciding tornness by whether the last line PARSES was wrong: a write can
     * persist the entire JSON object and fail before its terminator, leaving a
     * complete, valid record with no newline. That was accepted as committed,
     * the journal looked intact, and the next append concatenated onto it —
     * destroying a record that had been reported as written. So a journal that
     * does not end in a newline has an uncommitted trailing write, parseable or
     * not, and that line is not an entry.
     */
    const torn = raw.length > 0 && !raw.endsWith('\n');
    const body = raw.split('\n').filter(Boolean);
    const committed = torn ? body.slice(0, -1) : body;

    /** @type {import('./chain.mjs').ChainEntry[]} */
    const entries = [];
    /** @type {{ line: number, reason: string }[]} */
    const malformed = [];

    committed.forEach((line, i) => {
      try {
        const o = JSON.parse(line);
        if (!o || typeof o !== 'object' || !o.record || !o.leaf || !o.prev || !o.head) {
          throw new SyntaxError('a chain line carries a record, a leaf, a prev and a head');
        }
        entries.push({
          record: o.record,
          salt: salts.get(o.record.record_seq) ?? null,
          leaf: Buffer.from(o.leaf, 'hex'),
          prev: Buffer.from(o.prev, 'hex'),
          head: Buffer.from(o.head, 'hex'),
        });
      } catch (err) {
        // Every line here was terminated, so it was committed: a broken one
        // means the file was edited, not that a write was cut short.
        malformed.push({ line: i + 1, reason: err instanceof Error ? err.message : String(err) });
      }
    });

    return { entries, torn, malformed, salts_torn: sj.torn, salts_malformed: sj.malformed };
  }

  /**
   * Remove an incomplete trailing line from either journal.
   *
   * Only bytes after the last newline are touched, so a committed record is
   * never removed: a line with no terminator was never committed. A broken line
   * anywhere else is left alone — that is not a crash artifact, and repairing
   * it would destroy the evidence of whatever did it.
   * @returns {{ chain: number, salts: number }} bytes removed from each
   */
  repairTornTail() {
    // Repair is a WRITE. Without this a second instance could open a collector,
    // see the torn tail the legitimate writer leaves transiently mid-append,
    // and truncate bytes that writer had just written. The guard belongs here,
    // on the operation, rather than only in the caller that happens to use it.
    this.lock.claim();
    const trim = (/** @type {string} */ path) => {
      if (!existsSync(path)) return 0;
      const raw = readFileSync(path, 'utf8');
      if (raw === '' || raw.endsWith('\n')) return 0;
      const cut = raw.lastIndexOf('\n') + 1;      // 0 when the whole file is one torn line
      const removed = raw.length - cut;
      writeFileSync(path, raw.slice(0, cut), { mode: 0o600 });
      return removed;
    };
    // Reopen on next use: the descriptors point past the bytes just removed.
    for (const fd of [this.#chainFd, this.#saltsFd]) if (fd !== null) closeSync(fd);
    this.#chainFd = null;
    this.#saltsFd = null;
    return { chain: trim(this.chainPath), salts: trim(this.saltsPath) };
  }

  /** @returns {string[]} every collector with a chain in this store */
  collectors() {
    const dir = join(this.root, 'chain');
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter(f => f.endsWith('.jsonl')).map(f => f.replace(/\.jsonl$/, '')).sort();
  }

  /** @returns {{ head: Buffer, record_seq: number, source_seq: number }} */
  tip() {
    const entries = this.readChain();
    const last = entries.at(-1);
    let source = 0;
    for (const e of entries) {
      const s = e.record.source_seq;
      if (typeof s === 'number' && s > source) source = s;
    }
    return {
      head: last ? last.head : Buffer.alloc(32),
      record_seq: last ? Number(last.record.record_seq) : 0,
      source_seq: source,
    };
  }

  /**
   * Crypto-shred one record — FR-36, DES-13. Deletes the leaf salt and every
   * content object the record commits to. The chain line stays, because the
   * chain is never deleted; what is left is a salted commitment to a plaintext
   * nobody can produce.
   * @param {number} record_seq
   */
  shredRecord(record_seq) {
    const entry = this.readChain().find(e => Number(e.record.record_seq) === record_seq);
    if (entry) {
      /** @type {string[]} */
      const cids = [];
      for (const f of ['agent', 'args', 'result']) {
        const c = /** @type {{cid?: string}|undefined} */ (entry.record[f]);
        if (c && typeof c.cid === 'string') cids.push(c.cid);
      }
      const ap = /** @type {Record<string, {cid?: string}>|null} */ (entry.record.approval);
      if (ap) for (const f of ['reviewer', 'request']) {
        if (ap[f] && typeof ap[f].cid === 'string') cids.push(/** @type {string} */ (ap[f].cid));
      }
      // One pass: the payloads of one record share one group file and one
      // rewrite of the key journal.
      this.content.shredAll(cids);
    }
    const left = [...this.#readSaltsDetailed().salts].filter(([seq]) => seq !== record_seq);
    if (this.#saltsFd !== null) { closeSync(this.#saltsFd); this.#saltsFd = null; }
    writeFileSync(this.saltsPath,
      left.map(([record_seq, salt]) => JSON.stringify({ record_seq, salt: salt.toString('hex') })).join('\n')
        + (left.length ? '\n' : ''),
      { mode: 0o600 });
  }

  /** @param {number} seq @param {string} blob */
  writeCheckpoint(seq, blob) {
    // The artefact on disk is a DES-20 envelope, with the note inside it. A
    // bare note has nowhere to carry an RFC 3161 token or a .ots proof, and
    // retrofitting one later would mean rewriting signed files.
    this.writeCheckpointEnvelope(seq, buildEnvelope(blob));
  }

  /** @param {number} seq @returns {string} */
  checkpointPath(seq) { return join(this.checkpointDir, `${seq}.json`); }

  /**
   * Replace a checkpoint envelope atomically — staging file, then rename.
   *
   * Anchoring updates an envelope that already exists, often while a verifier
   * could be reading it. A reader must see the old envelope or the new one and
   * never a prefix of either, because a truncated envelope is indistinguishable
   * from a tampered one.
   * @param {number} seq
   * @param {import('./envelope.mjs').Envelope} env
   */
  writeCheckpointEnvelope(seq, env) {
    const path = this.checkpointPath(seq);
    const tmp = `${path}.${randomBytes(6).toString('hex')}.staging`;
    try {
      writeFileSync(tmp, JSON.stringify(env, null, 1) + '\n', { mode: 0o600 });
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* the staging file may not exist */ }
      throw e;
    }
  }

  /** @param {number} seq @returns {string|null} the envelope JSON, or null */
  readCheckpointEnvelope(seq) {
    return this.readCheckpoints().find(c => c.seq === seq)?.blob ?? null;
  }

  /**
   * Append one queue entry. The newline is the commit marker.
   * @param {{ checkpoint_seq: number, since: string, attempts: number }} entry
   */
  appendQueue(entry) {
    this.lock.claim();
    this.#repairTornLine(this.queuePath);
    const fd = openSync(this.queuePath, 'a', 0o600);
    try {
      this.#writeAll(fd, JSON.stringify(entry) + '\n', this.queuePath);
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Replace the queue wholesale — a drain, or an attempt count changing.
   *
   * Atomic by staging and rename, because a reader must see the old queue or
   * the new one. Rewriting is affordable here in a way it is not for the chain:
   * the queue holds only what is UNWITNESSED, which is bounded by the ceiling
   * (FR-68) rather than by the log's length.
   * @param {{ checkpoint_seq: number, since: string, attempts: number }[]} entries
   */
  writeQueue(entries) {
    this.lock.claim();
    const tmp = `${this.queuePath}.${randomBytes(6).toString('hex')}.staging`;
    try {
      writeFileSync(tmp, entries.map(e => JSON.stringify(e) + '\n').join(''), { mode: 0o600 });
      renameSync(tmp, this.queuePath);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* may not exist */ }
      throw e;
    }
  }

  /**
   * Read the queue, tolerating a torn tail and refusing damage in the middle.
   *
   * The same rule as the succession journal and the witness's retained roots,
   * for the same reason: a torn tail is the ordinary consequence of a crash,
   * and damage in the middle would let one corrupted byte silently drop a
   * queued checkpoint — which is the evidence the queue exists to keep.
   * @returns {{ checkpoint_seq: number, since: string, attempts: number }[]}
   */
  readQueue() {
    if (!existsSync(this.queuePath)) return [];
    const raw = readFileSync(this.queuePath, 'utf8');
    const lines = raw.split('\n');
    if (raw.length > 0 && !raw.endsWith('\n')) lines.pop();
    /** @type {{ checkpoint_seq: number, since: string, attempts: number }[]} */
    const out = [];
    lines.forEach((line, i) => {
      if (line === '') return;
      /** @type {any} */
      let e;
      try {
        e = JSON.parse(line);
      } catch {
        throw new Error(
          `${this.queuePath} line ${i + 1} is unreadable and is not the last line. A torn tail is `
          + 'the ordinary consequence of a crash; damage in the middle is not, and skipping it '
          + 'would silently drop a queued checkpoint.',
        );
      }
      if (!Number.isSafeInteger(e?.checkpoint_seq) || e.checkpoint_seq < 1) {
        throw new Error(
          `${this.queuePath} line ${i + 1} has checkpoint_seq ${JSON.stringify(e?.checkpoint_seq)}, `
          + 'which is not a positive integer. Refused rather than skipped: an entry that '
          + 'disappears from the queue is a batch that never gets witnessed.',
        );
      }
      // `since` is validated, not coerced. It was defaulted to '' when
      // unreadable, so Date.parse gave NaN, the age computed from it was NaN,
      // and FR-68's ceiling never fired — one corrupted byte silenced the
      // unwitnessed-outage alarm permanently and without a sound. Strict
      // RFC 3339, the shape DES-01 requires of every timestamp.
      if (!isTimestamp(e.since)) {
        throw new Error(
          `${this.queuePath} line ${i + 1} has since ${JSON.stringify(e?.since)}, which is not an `
          + 'RFC 3339 timestamp. Refused rather than defaulted: a queue entry whose age cannot be '
          + "computed is one the unwitnessed ceiling can never fire for, and that failure is silent.",
        );
      }
      if (!Number.isSafeInteger(e.attempts) || e.attempts < 0) {
        throw new Error(
          `${this.queuePath} line ${i + 1} has attempts ${JSON.stringify(e?.attempts)}, which is `
          + 'not a non-negative integer. Refused rather than defaulted, for the same reason: a '
          + 'coerced attempt count resets the backoff silently.',
        );
      }
      out.push({ checkpoint_seq: e.checkpoint_seq, since: e.since, attempts: e.attempts });
    });
    return out;
  }

  /**
   * Truncate a torn trailing line. Called before an append, under the lock.
   * @param {string} path
   */
  #repairTornLine(path) {
    if (!existsSync(path)) return;
    const raw = readFileSync(path, 'utf8');
    if (raw.length === 0 || raw.endsWith('\n')) return;
    truncateSync(path, Buffer.byteLength(raw.slice(0, raw.lastIndexOf('\n') + 1), 'utf8'));
  }

  /**
   * Record the observation counter — FR-61.
   *
   * Written at each batch flush, atomically. Observations are spent on
   * ATTEMPTS, written or not (DES-04 rule 2), so after a crash the collector
   * resuming from the last WRITTEN source_seq would reuse the numbers that were
   * spent — the hole would close up and a lossy run would read as a complete
   * one. This file is what makes the loss nameable.
   * @param {number} source_seq
   */
  writeObservationCounter(source_seq) {
    this.lock.claim();
    const tmp = `${this.counterPath}.${randomBytes(6).toString('hex')}.staging`;
    try {
      writeFileSync(tmp, JSON.stringify({
        source_seq, at: new Date().toISOString(),
      }) + '\n', { mode: 0o600 });
      renameSync(tmp, this.counterPath);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* may not exist */ }
      throw e;
    }
  }

  /**
   * @returns {number|null} null when the counter did not survive at all, which
   *   is a different condition from zero and leads to FR-60's unknown-loss
   *   interval rather than to an exact span.
   */
  readObservationCounter() {
    if (!existsSync(this.counterPath)) return null;
    try {
      const d = JSON.parse(readFileSync(this.counterPath, 'utf8'));
      return Number.isSafeInteger(d?.source_seq) && d.source_seq >= 0 ? d.source_seq : null;
    } catch {
      return null;
    }
  }

  /** @returns {string|null} when the counter was last written */
  readObservationCounterAt() {
    if (!existsSync(this.counterPath)) return null;
    try {
      const d = JSON.parse(readFileSync(this.counterPath, 'utf8'));
      return typeof d?.at === 'string' ? d.at : null;
    } catch {
      return null;
    }
  }

  /**
   * Give up the reserved space so a gap declaration can be written — FR-58.
   *
   * Its ABSENCE afterwards is the signal that it was spent, which a reader can
   * see without being told. Releasing it is irreversible by design: a store
   * that quietly re-allocated the slot would be one that had already failed to
   * record something and then hidden that it had.
   * @returns {boolean} whether space was actually freed
   */
  releaseReserve() {
    if (!existsSync(this.reservePath)) return false;
    unlinkSync(this.reservePath);
    return true;
  }

  /** @returns {boolean} FR-58 — is the reserve still intact? */
  reserveIntact() { return existsSync(this.reservePath); }

  /** @param {number} seq @returns {string} */
  rollupPath(seq) { return join(this.rollupDir, `${seq}.json`); }

  /** @param {number} seq @param {import('./envelope.mjs').Envelope} env */
  writeRollupEnvelope(seq, env) {
    const path = this.rollupPath(seq);
    const tmp = `${path}.${randomBytes(6).toString('hex')}.staging`;
    try {
      writeFileSync(tmp, JSON.stringify(env, null, 1) + '\n', { mode: 0o600 });
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* the staging file may not exist */ }
      throw e;
    }
  }

  /** @param {number} seq @param {string} blob a signed note */
  writeRollup(seq, blob) { this.writeRollupEnvelope(seq, buildEnvelope(blob)); }

  /** @returns {{ seq: number, blob: string, note: string }[]} in order */
  readRollups() {
    if (!existsSync(this.rollupDir)) return [];
    /** @type {{ seq: number, blob: string, note: string }[]} */
    const out = [];
    for (const f of readdirSync(this.rollupDir)) {
      const m = /^([0-9]+)\.json$/.exec(f);
      if (m === null) continue;
      const raw = readFileSync(join(this.rollupDir, f), 'utf8');
      out.push({ seq: Number(m[1]), blob: raw, note: parseEnvelope(raw).note ?? '' });
    }
    return out.sort((a, b) => a.seq - b.seq);
  }

  /** @param {number} seq @returns {string|null} */
  readRollupEnvelope(seq) {
    return this.readRollups().find(r => r.seq === seq)?.blob ?? null;
  }

  /** The highest roll-up ordinal written. An ordinal only. */
  lastRollupSeq() {
    return this.readRollups().reduce((max, r) => Math.max(max, r.seq), 0);
  }

  /**
   * This collector's checkpoints, in order.
   *
   * `blob` is always envelope JSON and `note` always the note bytes, whichever
   * format is on disk. An M1 store holds bare `.note` files; those are wrapped
   * on read rather than migrated, because DES-16 says an older format is not
   * retroactively invalid and rewriting signed files to change their shape is
   * the last thing this project should do.
   *
   * When BOTH formats exist for one ordinal, the envelope is authoritative and
   * `legacy_note` carries the bare file beside it, so the verifier can compare
   * them. Two artefacts for one checkpoint that disagree is exactly the "verify
   * one thing and report on another" failure, and silently preferring either
   * would hide it.
   *
   * @returns {{ seq: number, blob: string, note: string, format: 'envelope'|'note',
   *             legacy_note?: string }[]}
   */
  readCheckpoints() {
    if (!existsSync(this.checkpointDir)) return [];
    /** @type {Map<number, string>} */
    const bare = new Map();
    for (const f of readdirSync(this.checkpointDir)) {
      const m = /^([0-9]+)\.note$/.exec(f);
      if (m) bare.set(Number(m[1]), readFileSync(join(this.checkpointDir, f), 'utf8'));
    }
    /** @type {{ seq: number, blob: string, note: string, format: 'envelope'|'note', legacy_note?: string }[]} */
    const out = [];
    for (const f of readdirSync(this.checkpointDir)) {
      const m = /^([0-9]+)\.(note|json)$/.exec(f);
      if (m === null) continue;
      const seq = Number(m[1]);
      const raw = readFileSync(join(this.checkpointDir, f), 'utf8');
      if (m[2] === 'note') {
        // Skipped when an envelope exists for the same ordinal: it is reported
        // through that entry's legacy_note instead of as a second checkpoint.
        if (existsSync(this.checkpointPath(seq))) continue;
        out.push({ seq, blob: JSON.stringify(buildEnvelope(raw)), note: raw, format: 'note' });
        continue;
      }
      // A damaged envelope still has to reach the verifier, which is the thing
      // that knows how to report it. Returning the raw bytes and an empty note
      // lets it emit a finding instead of this code deciding to drop evidence.
      const p = parseEnvelope(raw);
      const legacy = bare.get(seq);
      out.push({
        seq, blob: raw, note: p.note ?? '', format: 'envelope',
        ...(legacy === undefined ? {} : { legacy_note: legacy }),
      });
    }
    return out.sort((a, b) => a.seq - b.seq);
  }

  /**
   * Notes sitting directly in checkpoints/, belonging to no collector. Reported
   * rather than ignored: evidence that cannot be attributed is still evidence,
   * and silently skipping it would hide it from a reader.
   * @returns {string[]}
   */
  unattributedCheckpoints() {
    const dir = join(this.root, 'checkpoints');
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter(f => /\.(note|json)$/.test(f));
  }

  /**
   * The highest checkpoint ordinal written so far. An ordinal only: it is never
   * compared with record_seq or source_seq (DES-04 rule 2).
   * @returns {number}
   */
  lastCheckpointSeq() {
    return this.readCheckpoints().reduce((max, c) => Math.max(max, c.seq), 0);
  }
}
