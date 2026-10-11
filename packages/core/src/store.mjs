/**
 * The on-disk store — DES-13.
 *
 *   chain/<collector>.jsonl   records, leaves, heads.  NEVER DELETED
 *   salts/<collector>.jsonl   record_seq -> salt.      DELETABLE per record
 *   checkpoints/<n>.note      C2SP notes                          [DES-07]
 *   content/<cid>.bin         every payload, encrypted. DELETABLE
 *   content/<cid>.salt        per-content salt.         DELETABLE
 *   content/refs.idx          counterparty references.  DELETABLE [DES-19]
 *   keys/<cid>.key            per-content keys.         DELETABLE
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
    for (const d of ['chain', 'salts', 'checkpoints', 'queue']) {
      mkdirSync(join(root, d), { recursive: true });
    }
    this.chainPath = join(root, 'chain', `${collector}.jsonl`);
    this.saltsPath = join(root, 'salts', `${collector}.jsonl`);
    this.content = new ContentStore(root);

  }

  /**
   * Append one chain entry. The record and the chain metadata go to chain/;
   * the salt goes to salts/, because the chain is never deleted and a salt
   * stored there could never be crypto-shredded (FR-36).
   * @param {import('./chain.mjs').ChainEntry} e
   */
  append(e) {
    if (e.salt === null) throw new TypeError('a record is written with its salt; erasure comes later');
    if (this.#chainFd === null) this.#chainFd = openSync(this.chainPath, 'a', 0o600);
    if (this.#saltsFd === null) this.#saltsFd = openSync(this.saltsPath, 'a', 0o600);
    writeSync(this.#chainFd, JSON.stringify({
      record: e.record,
      leaf: e.leaf.toString('hex'),
      prev: e.prev.toString('hex'),
      head: e.head.toString('hex'),
    }) + '\n');
    writeSync(this.#saltsFd, JSON.stringify({
      record_seq: e.record.record_seq, salt: e.salt.toString('hex'),
    }) + '\n');
  }

  /** Release the journal descriptors. Idempotent. */
  close() {
    for (const fd of [this.#chainFd, this.#saltsFd]) if (fd !== null) closeSync(fd);
    this.#chainFd = null;
    this.#saltsFd = null;
    this.content.close();
  }

  /** @returns {Map<number, Buffer>} */
  #readSalts() {
    /** @type {Map<number, Buffer>} */
    const m = new Map();
    if (!existsSync(this.saltsPath)) return m;
    for (const line of readFileSync(this.saltsPath, 'utf8').split('\n')) {
      if (!line) continue;
      const { record_seq, salt } = JSON.parse(line);
      m.set(record_seq, Buffer.from(salt, 'hex'));
    }
    return m;
  }

  /**
   * Read the chain back, joining each entry to its salt. A record whose salt
   * has been shredded comes back with `salt: null`, which recomputeChain
   * reports as inconclusive rather than as a failure.
   * @returns {import('./chain.mjs').ChainEntry[]}
   */
  readChain() {
    if (!existsSync(this.chainPath)) return [];
    const salts = this.#readSalts();
    return readFileSync(this.chainPath, 'utf8').split('\n').filter(Boolean).map(line => {
      const o = JSON.parse(line);
      return {
        record: o.record,
        salt: salts.get(o.record.record_seq) ?? null,
        leaf: Buffer.from(o.leaf, 'hex'),
        prev: Buffer.from(o.prev, 'hex'),
        head: Buffer.from(o.head, 'hex'),
      };
    });
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
    const left = [...this.#readSalts()].filter(([seq]) => seq !== record_seq);
    if (this.#saltsFd !== null) { closeSync(this.#saltsFd); this.#saltsFd = null; }
    writeFileSync(this.saltsPath,
      left.map(([record_seq, salt]) => JSON.stringify({ record_seq, salt: salt.toString('hex') })).join('\n')
        + (left.length ? '\n' : ''),
      { mode: 0o600 });
  }

  /** @param {number} seq @param {string} blob */
  writeCheckpoint(seq, blob) {
    writeFileSync(join(this.root, 'checkpoints', `${seq}.note`), blob, { mode: 0o600 });
  }

  /**
   * The highest checkpoint ordinal written so far. An ordinal only: it is never
   * compared with record_seq or source_seq (DES-04 rule 2).
   * @returns {number}
   */
  lastCheckpointSeq() {
    const dir = join(this.root, 'checkpoints');
    if (!existsSync(dir)) return 0;
    return readdirSync(dir)
      .map(f => /^([0-9]+)\.note$/.exec(f))
      .reduce((max, m) => (m ? Math.max(max, Number(m[1])) : max), 0);
  }
}
