/**
 * The content store — DES-13, FR-35, FR-36, FR-55, PRIV-02, PRIV-03.
 *
 * No payload enters the chain. Every argument and result is replaced by a
 * salted commitment to the bytes:
 *
 *   cid = SHA-256( 0x05 ‖ content_salt ‖ plaintext )
 *
 * The commitment is over the plaintext, not over an identity assigned to it. An
 * earlier draft of DES-13 said the digest covered the content's *identity*,
 * which an external review correctly called a hole: an identity not derived
 * from the bytes lets an operator swap the payload while the pointer and the
 * chain stay valid. Substitution now changes the cid.
 *
 * The salt is why this does not reintroduce a privacy problem. A bare SHA-256
 * of a short payload is brute-forceable; a salted one is not. Deleting the
 * salt with the ciphertext and the key is what makes the surviving commitment
 * unlinkable — which is the whole of FR-36.
 *
 * Layout (DES-13), scoped to the collector like the chain and the salts, so two
 * collectors can be active in one store root at the same time:
 *   content/<collector>/content.blob   payloads, encrypted, append-only  DELETABLE
 *   content/<collector>/refs.idx      counterparty references            DELETABLE [DES-19]
 *   keys/<collector>/content.jsonl    cid -> key and extent              DELETABLE
 *
 * chain/ holds none of these, which is what makes PRIV-02 literally true
 * rather than true of large payloads only.
 *
 * The content salt is a header in the content file rather than a file of its
 * own. Creating a file costs 0.22 ms on a 1 ms budget (NFR-01), and the salt
 * buys nothing by being separate: FR-36 deletes it in the same step as the
 * ciphertext, and a holder of the ciphertext who lacks the key gains nothing
 * from the salt — if they could decrypt they would already have the plaintext.
 *
 * The encryption key stays in its own directory, and that separation is NOT a
 * performance trade to make later: DES-13 allows content/ to live anywhere
 * including object storage, and a key stored beside its ciphertext would be
 * shipped wherever the ciphertext goes.
 *
 * Two further decisions came out of measuring NFR-01 rather than assuming it.
 *
 * **Nothing on the append path creates a file**, and that is a measurement, not
 * a preference. On the development machine `fs.writeFileSync` creating one new
 * file measured p50 0.19 ms and p99 1.04 ms, while a write to an already-open
 * descriptor measured p50 0.008 ms and p99 0.016 ms. SHA-256 and AES-GCM over a
 * record are 0.03 ms together and were never the problem. A p99 of 1.04 ms for
 * a single file creation means NFR-01's 1 ms budget cannot be met at p99 by any
 * implementation that creates a file per record, however fast its cryptography.
 *
 * So payloads are appended to one encrypted blob and `keys/content.jsonl` maps
 * each cid to its key and its extent. The route taken to get here is recorded
 * because each step was a dead end worth not repeating: one file per payload
 * (0.86 ms of the budget in file creation alone), then one file per record
 * (0.64 ms p50, 3.2 ms p99), then a deferred write queue — which reduces no
 * work at all, only moves it, and turned a 1.4 ms p50 into a multi-second
 * stall. Fewer writes beat later writes.
 *
 * **Erasure stays byte-destructive.** The blob is shared, so FR-36 cannot
 * unlink a payload; it overwrites the extent with zeros in place, which is a
 * positional write of the payload's own length and not a rewrite of the file.
 * The claim therefore stays "the bytes are gone" rather than weakening to "the
 * bytes are unreadable", which is what deleting only the key would have left.
 * Erasing the last surviving payload truncates the blob.
 *
 * **Per-content keys stay per-content** — one shared key would mean erasing a
 * single payload destroyed the batch — and keys/ stays a separate directory,
 * because DES-13 lets content/ live anywhere including object storage and a key
 * stored beside its ciphertext travels wherever the ciphertext goes. One blob
 * per collector is also a better shape for object storage than a million small
 * objects.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, statSync, openSync, writeSync, closeSync, readSync } from 'node:fs';
import { join } from 'node:path';
import { WriteLock } from './writelock.mjs';

/** 0x05 — content commitment. Distinct from 0x00, 0x01, 0x02 and 0x04. */
export const CONTENT_DOMAIN = 0x05;

export const CONTENT_SALT_BYTES = 16;
const KEY_BYTES = 32;      // AES-256
const IV_BYTES = 12;       // GCM nominal
const TAG_BYTES = 16;

export { StoreBusy } from './writelock.mjs';

export class ContentMissing extends Error {
  /** @param {string} cid @param {{ cause?: unknown }} [opts] */
  constructor(cid, opts = {}) {
    super(`content ${cid} is not retrievable: shredded, retained elsewhere, lost, or altered`, opts);
    this.name = 'ContentMissing';
    this.cid = cid;
  }
}

/**
 * @param {Uint8Array} salt
 * @param {Uint8Array} plaintext
 * @returns {string} `sha256:<hex>`
 */
export function contentCid(salt, plaintext) {
  if (salt.length !== CONTENT_SALT_BYTES) {
    throw new RangeError(`a content salt is exactly ${CONTENT_SALT_BYTES} bytes`);
  }
  const h = createHash('sha256')
    .update(Buffer.from([CONTENT_DOMAIN]))
    .update(salt)
    .update(plaintext)
    .digest('hex');
  return `sha256:${h}`;
}

/**
 * Keys whose value is an externally issued identifier. Narrow on purpose: a
 * bare `id` is usually the caller's own, and indexing it would fill the index
 * with identifiers no counterparty could confirm.
 */
const REF_KEY = /(^|_)(ref|reference|txid|tx_id|transaction_id|confirmation|confirmation_ref|receipt|receipt_no|invoice|invoice_no|payment_id|settlement_id)(_id|_no|_ref)?$/i;

/** Free-text form, as in DES-19's `ref=TX-77814`. */
const REF_TEXT = /\bref(?:erence)?[=:]\s*([A-Za-z0-9][A-Za-z0-9_-]{3,63})\b/gi;

/**
 * Extract externally issued identifiers from a tool result — FR-55.
 *
 * Best-effort by design, and the test suite asserts a miss as well as a hit.
 * Reconciliation starts from the counterparty's side (DES-19 mechanism 2), so
 * extraction makes the check a query rather than a grep; it is not itself the
 * guarantee. A reference this misses is still in the plaintext.
 *
 * @param {Uint8Array} result raw result bytes
 * @returns {Set<string>}
 */
export function extractRefs(result) {
  /** @type {Set<string>} */
  const refs = new Set();
  const text = Buffer.isBuffer(result) ? result.toString('utf8') : Buffer.from(result).toString('utf8');

  // Only attempt a parse when the text could be JSON. Letting JSON.parse throw
  // on every plain-text result builds an exception and a stack trace per
  // record, which measured four times the cost of parsing a result that IS
  // JSON — garbage the collector then has to collect, on the one path with a
  // sub-millisecond budget.
  const first = text.trimStart()[0];
  if (first === '{' || first === '[') {
    try {
      walk(JSON.parse(text));
    } catch {
      // Not JSON after all. The free-text pass below still applies.
    }
  }
  /** @param {unknown} v @param {string} [key] */
  function walk(v, key) {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) { for (const x of v) walk(x, key); return; }
    if (typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) walk(x, k);
      return;
    }
    if (typeof v === 'string' && key && REF_KEY.test(key) && v.length >= 2) refs.add(v);
  }

  for (const m of text.matchAll(REF_TEXT)) if (m[1]) refs.add(m[1]);
  return refs;
}

/** @typedef {{ cid: string, bytes: number }} Commitment */
/** @typedef {{ key: Buffer, offset: number, length: number }} Entry */

export class ContentStore {
  /** @type {number|null} */
  #refsFd = null;
  /** @type {number|null} */
  #keysFd = null;
  /** @type {Map<string, Entry>|null} the key journal, read once and kept */
  #keys = null;
  /** @type {number|null} */
  #blobFd = null;
  /** Append offset — the blob's length. */
  #end = 0;

  /**
   * @param {string} root the store root from splitstick.yaml
   * @param {string} [collector] the collector instance this content belongs to
   * @param {import('./writelock.mjs').WriteLock} [lock] the collector's single
   *   write lock, shared with the chain and salt journals. Held inside this
   *   class alone it covered only records that externalise a payload, so a
   *   heartbeat, a gap, a policy change or a padding leaf took no lock at all.
   */
  constructor(root, collector = 'default', lock) {
    this.root = root;
    this.collector = collector;
    this.contentDir = join(root, 'content', collector);
    this.keysDir = join(root, 'keys', collector);
    mkdirSync(this.contentDir, { recursive: true });
    mkdirSync(this.keysDir, { recursive: true });
    this.refsPath = join(this.contentDir, 'refs.idx');
    this.keysPath = join(this.keysDir, 'content.jsonl');
    this.blobPath = join(this.contentDir, 'content.blob');
    this.lock = lock ?? new WriteLock(join(root, '.locks', `${collector}.lock`));
    this.#end = existsSync(this.blobPath) ? statSync(this.blobPath).size : 0;
  }

  /** Claim the collector's single write lock — shared with the journals. */
  #claim() { this.lock.claim(); }

  /** @param {string} cid */
  #base(cid) {
    if (!/^sha256:[0-9a-f]{64}$/.test(cid)) throw new TypeError(`not a cid: ${cid}`);
    return cid.slice('sha256:'.length);
  }

  /**
   * The file a commitment's bytes live in. Exposed because the tamper tests
   * need it, and because a verifier reports the path it could not read.
   * @param {string} cid
   */
  pathFor(cid) { this.#base(cid); return this.blobPath; }

  /** The extent of one commitment inside the blob. For tests. @param {string} cid */
  rangeForTest(cid) {
    const e = /** @type {Entry} */ (this.#readKeys().get(cid));
    return { offset: e.offset, length: e.length };
  }

  /** Whether the key map has been read into memory. For NFR-01's memory test. */
  get keysMaterialisedForTest() { return this.#keys !== null; }

  /**
   * The blob descriptor, opened for reading and positional writing.
   *
   * NOT append mode. Node documents that on Linux a positional write is ignored
   * when the file is opened with O_APPEND — the kernel appends regardless — so
   * 'a+' would have turned erasure's zero-fill into "append zeros and leave the
   * ciphertext in place", silently weakening FR-36 on the platform CI runs on.
   * macOS honours the position, which is exactly why the suite was green
   * locally and would have failed on review.
   * @returns {number}
   */
  #blobHandle() {
    if (this.#blobFd === null) {
      if (!existsSync(this.blobPath)) closeSync(openSync(this.blobPath, 'w', 0o600));
      this.#blobFd = openSync(this.blobPath, 'r+');
    }
    return this.#blobFd;
  }

  /** @returns {Map<string, Entry>} */
  #readKeys() {
    if (this.#keys) return this.#keys;
    /** @type {Map<string, Entry>} */
    const m = new Map();
    if (existsSync(this.keysPath)) {
      for (const line of readFileSync(this.keysPath, 'utf8').split('\n')) {
        if (!line) continue;
        const { cid, key, offset, length } = JSON.parse(line);
        m.set(cid, { key: Buffer.from(key, 'base64'), offset, length });
      }
    }
    this.#keys = m;
    return m;
  }

  /**
   * @param {string} cid @param {Entry} e
   *
   * The journal is the source of truth and it is append-only, so a writer does
   * NOT materialise the key map: a collector that writes a million payloads and
   * reads none would otherwise hold every key in memory for no purpose, which
   * is the shape that breaks NFR-01's million-event target. A reader
   * materialises on demand and sees everything written, because the journal has
   * it all.
   */
  #writeKey(cid, e) {
    if (this.#keysFd === null) this.#keysFd = openSync(this.keysPath, 'a', 0o600);
    writeSync(this.#keysFd, JSON.stringify({
      cid, key: e.key.toString('base64'), offset: e.offset, length: e.length,
    }) + '\n');
    if (this.#keys) this.#keys.set(cid, e);
  }

  /** @param {(cid: string) => boolean} keep */
  #rewriteKeys(keep) {
    const left = [...this.#readKeys()].filter(([cid]) => keep(cid));
    if (this.#keysFd !== null) { closeSync(this.#keysFd); this.#keysFd = null; }
    writeFileSync(this.keysPath,
      left.map(([cid, e]) => JSON.stringify({
        cid, key: e.key.toString('base64'), offset: e.offset, length: e.length,
      })).join('\n') + (left.length ? '\n' : ''),
      { mode: 0o600 });
    this.#keys = new Map(left);
  }

  /**
   * Store a payload and return its commitment. The commitment is all that goes
   * into a record.
   * @param {Uint8Array} plaintext
   * @param {{ refs?: Iterable<string> }} [opts]
   * @returns {Commitment}
   */
  put(plaintext, opts = {}) {
    const [only] = this.putGroup([{ bytes: plaintext, ...(opts.refs ? { refs: opts.refs } : {}) }]);
    return /** @type {Commitment} */ (only);
  }

  /**
   * Store every payload of one record in a single file.
   *
   * @param {{ bytes: Uint8Array, refs?: Iterable<string>, index?: boolean }[]} payloads
   * @returns {Commitment[]} commitments, in the order given
   */
  putGroup(payloads) {
    if (payloads.length === 0) return [];
    this.#claim();
    /** @type {Commitment[]} */
    const out = [];
    /** @type {[string, Entry][]} */
    const entries = [];
    /** @type {Buffer[]} */
    const blobs = [];
    let offset = this.#end;

    for (const p of payloads) {
      const salt = randomBytes(CONTENT_SALT_BYTES);
      const cid = contentCid(salt, p.bytes);
      const key = randomBytes(KEY_BYTES);
      const iv = randomBytes(IV_BYTES);
      const c = createCipheriv('aes-256-gcm', key, iv);
      const blob = Buffer.concat([salt, iv, c.update(p.bytes), c.final(), c.getAuthTag()]);
      blobs.push(blob);
      entries.push([cid, { key, offset, length: blob.length }]);
      offset += blob.length;
      out.push({ cid, bytes: p.bytes.length });
    }

    const joined = Buffer.concat(blobs);
    writeSync(this.#blobHandle(), joined, 0, joined.length, this.#end);
    this.#end += joined.length;
    for (const [cid, e] of entries) this.#writeKey(cid, e);
    for (let i = 0; i < payloads.length; i++) {
      const refs = /** @type {{refs?: Iterable<string>}} */ (payloads[i]).refs;
      if (refs) this.#index(/** @type {Commitment} */ (out[i]).cid, refs);
    }
    return out;
  }

  /** @param {string} cid @returns {Buffer} the stored bytes for one commitment */
  #blob(cid) {
    const e = /** @type {Entry} */ (this.#readKeys().get(cid));
    const buf = Buffer.alloc(e.length);
    readSync(this.#blobHandle(), buf, 0, e.length, e.offset);
    return buf;
  }

  /**
   * Is this payload retrievable?
   *
   * `#end` rather than `existsSync` + `statSync`. Those ran on EVERY call
   * against one unchanging path, and `reproduces()` calls this twice per
   * commitment: at NFR-04's hundred thousand records that is about two hundred
   * thousand pairs of syscalls on the same file, and it measured 20 to 29 per
   * cent of total verification time — second only to the quadratic consistency
   * proof the verifier was doing at the same time.
   *
   * `#end` is the blob's length as this instance knows it: set when the store
   * is opened, advanced on every append, reset by erasure. For a writer it is
   * exact. For a READER it is better than a live `statSync`, which is the part
   * worth saying: the key map is already a point-in-time snapshot taken at
   * first read, so a live file size would pair a cached key journal with a
   * blob that had grown underneath it. Sizing the blob at the same instant the
   * keys were read is the coherent choice, not merely the cheap one.
   * @param {string} cid @returns {boolean}
   */
  has(cid) {
    const e = this.#readKeys().get(cid);
    return e !== undefined && this.#end >= e.offset + e.length;
  }

  /**
   * The content salt a payload was committed under — FR-32, PRIV-06.
   *
   * A content cid is `SHA-256(0x05 ‖ salt ‖ plaintext)`, so a recipient handed
   * the plaintext and the cid cannot check one against the other without the
   * salt. A disclosure pack therefore has to carry it, and this is the only
   * way to read it: it lives in the first bytes of the stored blob, which is
   * private, and the store is where it should stay private.
   *
   * Revealing it for a payload you are ALSO revealing costs nothing — the
   * salt's job is to stop a guess at an undisclosed plaintext being confirmed.
   * Revealing a sibling's would be the whole of PRIV-06's failure, and a
   * caller gets exactly the cid it asks for.
   * @param {string} cid @returns {Buffer}
   */
  contentSalt(cid) {
    if (!this.has(cid)) throw new ContentMissing(cid);
    return Buffer.from(this.#blob(cid).subarray(0, CONTENT_SALT_BYTES));
  }

  /** @param {string} cid @returns {Buffer} */
  get(cid) {
    if (!this.has(cid)) throw new ContentMissing(cid);
    const { key } = /** @type {Entry} */ (this.#readKeys().get(cid));
    const blob = this.#blob(cid);
    const body = blob.subarray(CONTENT_SALT_BYTES);
    const d = createDecipheriv('aes-256-gcm', key, body.subarray(0, IV_BYTES));
    d.setAuthTag(body.subarray(body.length - TAG_BYTES));
    try {
      return Buffer.concat([d.update(body.subarray(IV_BYTES, body.length - TAG_BYTES)), d.final()]);
    } catch (err) {
      // The extent is there but does not authenticate: zeroed by an erasure the
      // key journal no longer records, overwritten, or truncated. A caller gets
      // a typed error naming the cid rather than a bare cipher failure; the
      // verifier distinguishes this from an absence through reproduces().
      throw new ContentMissing(cid, { cause: err });
    }
  }

  /**
   * Does the stored content still reproduce its commitment?
   *
   * Three-valued on purpose (DES-12): true, false, or **null for
   * inconclusive** when the content or its salt is gone. A shredded record
   * must never read as a tamper — with a boolean, lawful erasure and
   * substitution would be the same answer.
   * @param {string} cid
   * @returns {boolean|null}
   */
  reproduces(cid) {
    if (!this.has(cid)) return null;
    const salt = this.#blob(cid).subarray(0, CONTENT_SALT_BYTES);
    try {
      return contentCid(salt, this.get(cid)) === cid;
    } catch {
      return false;   // decryption failed: the bytes were altered
    }
  }

  /**
   * Crypto-shred — FR-36, DES-13. Ciphertext, salt, key and every reference to
   * it. The chain is untouched; the record keeps a commitment to a plaintext
   * nobody can produce.
   * @param {string} cid
   */
  shred(cid) { this.shredAll([cid]); }

  /**
   * Shred several commitments in one pass — FR-36.
   *
   * The key journal is rewritten once per call, not once per cid, so honouring
   * a request that touches ten thousand records is one rewrite rather than ten
   * thousand. Erasure is the operation allowed to be O(n); appending is not.
   * @param {Iterable<string>} cids
   */
  shredAll(cids) {
    this.#claim();
    const keys = this.#readKeys();
    const gone = new Set([...cids].filter(cid => keys.has(cid)));
    if (gone.size === 0) return;

    if (existsSync(this.blobPath)) {
      const fd = this.#blobHandle();
      for (const cid of gone) {
        // Zero the extent in place: a positional write of the payload's own
        // length, not a rewrite of the blob. This is what keeps FR-36's claim
        // "the bytes are gone" rather than "the key is gone".
        const e = /** @type {Entry} */ (keys.get(cid));
        writeSync(fd, Buffer.alloc(e.length), 0, e.length, e.offset);
      }
      const survivors = [...keys].some(([cid]) => !gone.has(cid));
      if (!survivors) {
        closeSync(fd);
        this.#blobFd = null;
        rmSync(this.blobPath, { force: true });
        this.#end = 0;
      }
    }

    this.#rewriteKeys(cid => !gone.has(cid));
    this.#rewriteIndex(e => !gone.has(e.cid));
  }

  /** @param {string} ref @returns {string[]} cids */
  findByRef(ref) {
    return this.#readIndex().filter(e => e.ref === ref).map(e => e.cid);
  }

  /** Replace stored bytes without touching the commitment — FR-35's attack.
   * @param {string} cid @param {Uint8Array} plaintext */
  overwriteForTest(cid, plaintext) {
    const e = /** @type {Entry} */ (this.#readKeys().get(cid));
    const salt = this.#blob(cid).subarray(0, CONTENT_SALT_BYTES);
    const iv = randomBytes(IV_BYTES);
    const c = createCipheriv('aes-256-gcm', e.key, iv);
    const forged = Buffer.concat([salt, iv, c.update(plaintext), c.final(), c.getAuthTag()]);
    // Keep the extent: the point is that the pointer still resolves and the
    // commitment no longer reproduces.
    const padded = Buffer.alloc(e.length);
    forged.copy(padded, 0, 0, Math.min(forged.length, e.length));
    writeSync(this.#blobHandle(), padded, 0, padded.length, e.offset);
  }

  /** @param {string} cid @param {Iterable<string>} refs */
  #index(cid, refs) {
    const lines = [...refs].map(ref => JSON.stringify({ ref, cid }));
    if (!lines.length) return;
    if (this.#refsFd === null) this.#refsFd = openSync(this.refsPath, 'a', 0o600);
    writeSync(this.#refsFd, lines.join('\n') + '\n');
  }

  /** Release the journal descriptors and the write lock. Idempotent. */
  close() {
    for (const fd of [this.#refsFd, this.#keysFd, this.#blobFd]) if (fd !== null) closeSync(fd);
    this.#refsFd = null;
    this.#keysFd = null;
    this.#blobFd = null;
    this.lock.release();
  }

  /** @returns {{ ref: string, cid: string }[]} */
  #readIndex() {
    if (!existsSync(this.refsPath)) return [];
    return readFileSync(this.refsPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  }

  /** @param {(e: { ref: string, cid: string }) => boolean} keep */
  #rewriteIndex(keep) {
    if (this.#refsFd !== null) { closeSync(this.#refsFd); this.#refsFd = null; }
    if (!existsSync(this.refsPath)) return;
    const left = this.#readIndex().filter(keep);
    if (left.length === 0) { rmSync(this.refsPath, { force: true }); return; }
    writeFileSync(this.refsPath, left.map(e => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
  }
}
