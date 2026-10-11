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
 * Layout (DES-13):
 *   content/<cid>.bin    ciphertext, AES-256-GCM        DELETABLE
 *   content/<cid>.salt   per-content salt               DELETABLE
 *   content/refs.idx     counterparty reference index   DELETABLE   [DES-19]
 *   keys/<cid>.key       per-content encryption key     DELETABLE
 *
 * chain/ holds none of these, which is what makes PRIV-02 literally true
 * rather than true of large payloads only.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** 0x05 — content commitment. Distinct from 0x00, 0x01, 0x02 and 0x04. */
export const CONTENT_DOMAIN = 0x05;

export const CONTENT_SALT_BYTES = 16;
const KEY_BYTES = 32;      // AES-256
const IV_BYTES = 12;       // GCM nominal
const TAG_BYTES = 16;

export class ContentMissing extends Error {
  /** @param {string} cid */
  constructor(cid) {
    super(`content ${cid} is not in the store: shredded, retained elsewhere, or lost`);
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
  const text = Buffer.from(result).toString('utf8');

  try {
    walk(JSON.parse(text));
  } catch {
    // Not JSON, or not an object. The free-text pass below still applies.
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

export class ContentStore {
  /** @param {string} root the store root from splitstick.yaml */
  constructor(root) {
    this.root = root;
    this.contentDir = join(root, 'content');
    this.keysDir = join(root, 'keys');
    mkdirSync(this.contentDir, { recursive: true });
    mkdirSync(this.keysDir, { recursive: true });
    this.refsPath = join(this.contentDir, 'refs.idx');
  }

  /** @param {string} cid */
  #base(cid) {
    if (!/^sha256:[0-9a-f]{64}$/.test(cid)) throw new TypeError(`not a cid: ${cid}`);
    return cid.slice('sha256:'.length);
  }

  /** @param {string} cid the ciphertext path, exposed for tamper tests */
  pathFor(cid) { return join(this.contentDir, `${this.#base(cid)}.bin`); }
  /** @param {string} cid */
  saltPathFor(cid) { return join(this.contentDir, `${this.#base(cid)}.salt`); }
  /** @param {string} cid */
  keyPathFor(cid) { return join(this.keysDir, `${this.#base(cid)}.key`); }

  /**
   * Store a payload and return its commitment. The commitment is all that goes
   * into a record.
   * @param {Uint8Array} plaintext
   * @param {{ refs?: Iterable<string> }} [opts]
   * @returns {Commitment}
   */
  put(plaintext, opts = {}) {
    const salt = randomBytes(CONTENT_SALT_BYTES);
    const cid = contentCid(salt, plaintext);
    const key = randomBytes(KEY_BYTES);
    const iv = randomBytes(IV_BYTES);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const body = Buffer.concat([c.update(plaintext), c.final()]);
    writeFileSync(this.pathFor(cid), Buffer.concat([iv, c.getAuthTag(), body]), { mode: 0o600 });
    writeFileSync(this.saltPathFor(cid), salt, { mode: 0o600 });
    writeFileSync(this.keyPathFor(cid), key, { mode: 0o600 });
    if (opts.refs) this.#index(cid, opts.refs);
    return { cid, bytes: plaintext.length };
  }

  /** @param {string} cid @returns {boolean} */
  has(cid) { return existsSync(this.pathFor(cid)) && existsSync(this.keyPathFor(cid)); }

  /** @param {string} cid @returns {Buffer} */
  get(cid) {
    if (!this.has(cid)) throw new ContentMissing(cid);
    const key = readFileSync(this.keyPathFor(cid));
    const blob = readFileSync(this.pathFor(cid));
    const d = createDecipheriv('aes-256-gcm', key, blob.subarray(0, IV_BYTES));
    d.setAuthTag(blob.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
    return Buffer.concat([d.update(blob.subarray(IV_BYTES + TAG_BYTES)), d.final()]);
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
    if (!this.has(cid) || !existsSync(this.saltPathFor(cid))) return null;
    const salt = readFileSync(this.saltPathFor(cid));
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
  shred(cid) {
    for (const p of [this.pathFor(cid), this.saltPathFor(cid), this.keyPathFor(cid)]) {
      rmSync(p, { force: true });
    }
    this.#rewriteIndex(e => e.cid !== cid);
  }

  /** @param {string} ref @returns {string[]} cids */
  findByRef(ref) {
    return this.#readIndex().filter(e => e.ref === ref).map(e => e.cid);
  }

  /** Replace stored bytes without touching the commitment — FR-35's attack.
   * @param {string} cid @param {Uint8Array} plaintext */
  overwriteForTest(cid, plaintext) {
    const key = readFileSync(this.keyPathFor(cid));
    const iv = randomBytes(IV_BYTES);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const body = Buffer.concat([c.update(plaintext), c.final()]);
    writeFileSync(this.pathFor(cid), Buffer.concat([iv, c.getAuthTag(), body]));
  }

  /** @param {string} cid @param {Iterable<string>} refs */
  #index(cid, refs) {
    const lines = [...refs].map(ref => JSON.stringify({ ref, cid }));
    if (lines.length) writeFileSync(this.refsPath, lines.join('\n') + '\n', { flag: 'a', mode: 0o600 });
  }

  /** @returns {{ ref: string, cid: string }[]} */
  #readIndex() {
    if (!existsSync(this.refsPath)) return [];
    return readFileSync(this.refsPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  }

  /** @param {(e: { ref: string, cid: string }) => boolean} keep */
  #rewriteIndex(keep) {
    if (!existsSync(this.refsPath)) return;
    const left = this.#readIndex().filter(keep);
    if (left.length === 0) { rmSync(this.refsPath, { force: true }); return; }
    writeFileSync(this.refsPath, left.map(e => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
  }
}
