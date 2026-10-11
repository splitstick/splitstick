/**
 * The on-disk store — DES-13.
 *
 *   chain/<collector>.jsonl       records, leaves, heads.  NEVER DELETED
 *   salts/<collector>.jsonl       record_seq -> salt.      DELETABLE per record
 *   checkpoints/<collector>/<n>.note   C2SP notes                 [DES-07]
 *   content/<collector>/      payloads, encrypted.      DELETABLE
 *   keys/<collector>/         per-content keys.         DELETABLE
 *   queue/                    unwitnessed batches                 [DES-15]
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

import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, openSync, writeSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { ContentStore } from './content.mjs';
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
    for (const d of ['chain', 'salts', 'queue']) {
      mkdirSync(join(root, d), { recursive: true });
    }
    // Checkpoints are scoped to the collector, like the chain and the salts.
    // A shared directory meant two honest collectors in one store each verified
    // as `fail`, because each was asked to account for the other's signed
    // notes — and the ordinals collided besides.
    this.checkpointDir = join(root, 'checkpoints', collector);
    mkdirSync(this.checkpointDir, { recursive: true });
    this.chainPath = join(root, 'chain', `${collector}.jsonl`);
    this.saltsPath = join(root, 'salts', `${collector}.jsonl`);
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
    const lines = raw.split('\n');
    const complete = lines.length > 0 && lines[lines.length - 1] === '';
    const body = lines.filter(Boolean);
    body.forEach((line, i) => {
      try {
        const { record_seq, salt } = JSON.parse(line);
        if (!Number.isInteger(record_seq) || typeof salt !== 'string') {
          throw new SyntaxError('a salt line is a record_seq and a hex salt');
        }
        salts.set(record_seq, Buffer.from(salt, 'hex'));
      } catch {
        if (i === body.length - 1 && !complete) torn = true;
        else malformed.push(i + 1);
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
    const lines = raw.split('\n');
    // A trailing newline means the final record was fully written.
    const complete = lines.length > 0 && lines[lines.length - 1] === '';
    const body = lines.filter(Boolean);

    /** @type {import('./chain.mjs').ChainEntry[]} */
    const entries = [];
    /** @type {{ line: number, reason: string }[]} */
    const malformed = [];
    let torn = false;

    body.forEach((line, i) => {
      const last = i === body.length - 1;
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
        const reason = err instanceof Error ? err.message : String(err);
        // Only the last line, with no trailing newline, is explicable as a
        // crash mid-append. Anywhere else, something edited the file.
        if (last && !complete) torn = true;
        else malformed.push({ line: i + 1, reason });
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
    writeFileSync(join(this.checkpointDir, `${seq}.note`), blob, { mode: 0o600 });
  }

  /** @returns {{ seq: number, blob: string }[]} this collector's checkpoints, in order */
  readCheckpoints() {
    if (!existsSync(this.checkpointDir)) return [];
    return readdirSync(this.checkpointDir)
      .map(f => ({ m: /^([0-9]+)\.note$/.exec(f), f }))
      .filter(x => x.m !== null)
      .map(x => ({
        seq: Number(/** @type {RegExpExecArray} */ (x.m)[1]),
        blob: readFileSync(join(this.checkpointDir, x.f), 'utf8'),
      }))
      .sort((a, b) => a.seq - b.seq);
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
    return readdirSync(dir).filter(f => f.endsWith('.note'));
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
