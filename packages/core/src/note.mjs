/**
 * The signed note — DES-07's format, needed in M1 because DES-06 makes the note
 * bytes the signing subject.
 *
 * The note already binds origin, tree_size and root together, so signing the
 * note signs all three — and signing the *note itself* rather than a bespoke
 * concatenation is what lets an existing C2SP witness countersign the same
 * bytes. An earlier draft of DES-06 specified a custom preimage; an external
 * review pointed out that no C2SP witness could then have signed it, which
 * would have broken INT-01. There is one signed subject in this system.
 *
 *   <origin>\n<tree_size>\n<base64(root)>\n
 *   \n
 *   — <name> <base64(keyid ‖ signature)>\n   (one line per signature)
 *
 * The operator's clock does not appear in the subject at all. Trustworthy time
 * enters only through a countersignature (DES-20).
 *
 * Only the key-id derivation is checked against an external vector here; a real
 * C2SP witness countersigning a Splitstick checkpoint is FR-46's conformance
 * suite in M3a, and nothing in this module claims it.
 */

import { createHash } from 'node:crypto';

export class NoteError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'NoteError'; }
}

/** Ed25519, per the note format's algorithm registry. */
export const ALG_ED25519 = 1;

/**
 * cosignature/v1 Ed25519 — the algorithm a tlog-witness signs with.
 *
 * Found by running the shipped adapter against transparency-dev/witness for the
 * first time (FR-15). A witness cosignature is NOT a plain note signature:
 *
 *   - its key is declared with algorithm byte 0x04, so its key id hashes 0x04
 *     and not 0x01 — the same key under the two bytes gives different ids, and
 *     ours computed 2f117086 where the wire carried 070e9861
 *   - its blob is 76 bytes, keyId ‖ timestamp ‖ signature, not 68
 *   - it signs `cosignature/v1\ntime <unix>\n<note text>`, not the note text
 *
 * The timestamp is the witness's OWN observation time, signed over the same
 * message as the root. This adapter's comment used to say the protocol gave a
 * witness nowhere to put a time; that was a reading of our own document rather
 * than of theirs. See https://c2sp.org/tlog-cosignature.
 */
export const ALG_ED25519_COSIG_V1 = 4;

/** Bytes in a cosignature/v1 blob: 4 key id, 8 big-endian timestamp, 64 signature. */
const COSIG_V1_LEN = 4 + 8 + 64;
const PLAIN_LEN = 4 + 64;

/**
 * The bytes a cosignature/v1 signature actually covers.
 * @param {bigint|number} timestamp unix seconds, as the witness asserted them
 * @param {string} text the note text
 */
export function cosignatureV1Message(timestamp, text) {
  return `cosignature/v1\ntime ${timestamp}\n${text}`;
}

/**
 * Named, frozen algorithm tuples — DES-16. SS1 is SHA-256, Ed25519, JCS,
 * RFC 6962 and the 0x00-0x05 domain prefixes.
 *
 * There is no algorithm negotiation and no mix-and-match, because negotiation
 * is where downgrade attacks live. SS2 would be a new named tuple published in
 * the spec, and a verifier either knows a suite or refuses the batch.
 */
export const SUITES = Object.freeze(['SS1']);

/** The signature-line marker is an em dash followed by a space. */
const MARKER = '— ';

/**
 * keyid = SHA-256( name ‖ 0x0a ‖ algorithm ‖ public_key )[0:4]
 * @param {string} name
 * @param {Uint8Array} publicKey raw 32-byte Ed25519 key
 * @param {number} [algorithm]
 * @returns {Buffer}
 */
export function noteKeyId(name, publicKey, algorithm = ALG_ED25519) {
  if (publicKey.length !== 32) throw new NoteError('an Ed25519 public key is 32 bytes');
  return createHash('sha256')
    .update(Buffer.from(`${name}\n`))
    .update(Buffer.from([algorithm]))
    .update(publicKey)
    .digest()
    .subarray(0, 4);
}

/**
 * `<name>+<keyid hex>+<base64(algorithm ‖ public_key)>`
 * @param {string} name @param {Uint8Array} publicKey @param {number} [algorithm]
 */
export function formatVkey(name, publicKey, algorithm = ALG_ED25519) {
  if (name.includes('+')) throw new NoteError("a note identity must not contain '+'");
  const id = noteKeyId(name, publicKey, algorithm).toString('hex');
  const body = Buffer.concat([Buffer.from([algorithm]), publicKey]).toString('base64');
  return `${name}+${id}+${body}`;
}

/**
 * @param {string} vkey
 * @returns {{ name: string, algorithm: number, publicKey: Buffer, keyId: Buffer }}
 */
export function parseVkey(vkey) {
  // Split at the FIRST two separators, never the last. Standard base64 contains
  // '+', so popping from the end mangles any key whose encoding happens to
  // include one — which is one key in four and therefore a bug that would have
  // shipped looking like an intermittent failure.
  const i = vkey.indexOf('+');
  const j = vkey.indexOf('+', i + 1);
  if (i < 1 || j < 0) throw new NoteError('a vkey is name+keyid+key');
  const name = vkey.slice(0, i);
  const id = vkey.slice(i + 1, j);
  const body = vkey.slice(j + 1);
  if (!/^[0-9a-f]{8}$/.test(id)) throw new NoteError(`a vkey key id is 8 hex characters, got ${JSON.stringify(id)}`);
  const raw = Buffer.from(body, 'base64');
  if (raw.length !== 33) throw new NoteError('a vkey body is one algorithm byte and a 32-byte key');
  const algorithm = /** @type {number} */ (raw[0]);
  const publicKey = raw.subarray(1);
  const keyId = noteKeyId(name, publicKey, algorithm);
  if (keyId.toString('hex') !== id) {
    throw new NoteError(`vkey key id ${id} does not match its key (${keyId.toString('hex')})`);
  }
  return { name, algorithm, publicKey, keyId };
}

/**
 * @param {{ origin: string, tree_size: number, root: Uint8Array, suite?: string }} cp
 * @returns {string} the note text, which is the signed subject
 */
export function checkpointText({ origin, tree_size, root, suite }) {
  if (typeof origin !== 'string' || origin.length === 0) throw new NoteError('origin is required');
  // An origin carrying a newline could otherwise forge a second line and move
  // the tree size a verifier reads.
  if (/[\n\r]/.test(origin)) throw new NoteError('origin must not contain a newline');
  if (!Number.isInteger(tree_size) || tree_size < 0) {
    throw new NoteError(`tree_size must be a non-negative integer, got ${String(tree_size)}`);
  }
  if (root.length !== 32) throw new NoteError('root is a 32-byte digest');
  let text = `${origin}\n${tree_size}\n${Buffer.from(root).toString('base64')}\n`;
  if (suite !== undefined) {
    if (!SUITES.includes(suite)) {
      throw new NoteError(`unknown algorithm suite ${JSON.stringify(suite)}: a suite is a frozen tuple, not a negotiation (DES-16)`);
    }
    // An extension line, which the note format allows after the third. It rides
    // in the signed subject so the suite a batch was signed under cannot be
    // changed without invalidating the signature.
    text += `suite ${suite}\n`;
  }
  return text;
}

/**
 * @param {string} text
 * @returns {{ origin: string, tree_size: number, root: Buffer, suite: string|null, extra: string[] }}
 */
export function parseCheckpointText(text) {
  if (!text.endsWith('\n')) throw new NoteError('note text must end with a newline');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 3) throw new NoteError('a checkpoint is origin, tree_size and root');
  const [origin, size, rootB64] = /** @type {[string, string, string]} */ (lines);
  if (!/^(0|[1-9][0-9]*)$/.test(size)) throw new NoteError(`tree_size is not a decimal integer: ${size}`);
  const root = Buffer.from(rootB64, 'base64');
  if (root.length !== 32) throw new NoteError('root does not decode to 32 bytes');
  const extra = lines.slice(3);
  // Unknown extension lines are preserved rather than dropped: the signature
  // covers the text as a whole, so a verifier that silently discarded a line
  // could not reproduce the bytes a witness signed.
  const suiteLine = extra.find(l => l.startsWith('suite '));
  return {
    origin, tree_size: Number(size), root,
    suite: suiteLine ? suiteLine.slice('suite '.length) : null,
    extra,
  };
}

/**
 * A signature line. `timestamp` is present only on a cosignature/v1 line, where
 * it is the witness's own signed observation time in unix seconds, and is part
 * of the signed message rather than metadata beside it.
 * @typedef {{ name: string, keyId: Buffer, signature: Buffer, timestamp?: bigint }} NoteSignature
 */

/**
 * @param {string} text
 * @param {NoteSignature[]} signatures
 * @returns {string}
 */
export function encodeNote(text, signatures) {
  if (!text.endsWith('\n')) throw new NoteError('note text must end with a newline');
  if (signatures.length === 0) throw new NoteError('a note carries at least one signature');
  const lines = signatures.map(s => {
    if (/[\n\r ]/.test(s.name)) throw new NoteError('a signature name must not contain whitespace');
    const blob = Buffer.concat([s.keyId, s.signature]).toString('base64');
    return `${MARKER}${s.name} ${blob}\n`;
  });
  return `${text}\n${lines.join('')}`;
}

/**
 * @param {string} blob
 * @returns {{ text: string, signatures: NoteSignature[] }}
 */
export function parseNote(blob) {
  const split = blob.indexOf('\n\n');
  if (split === -1) throw new NoteError('a note is text, a blank line, then signature lines');
  const text = blob.slice(0, split + 1);
  const rest = blob.slice(split + 2);
  if (rest.length === 0 || !rest.endsWith('\n')) throw new NoteError('a note must end with a newline');

  /** @type {NoteSignature[]} */
  const signatures = [];
  for (const line of rest.slice(0, -1).split('\n')) signatures.push(parseSignatureLine(line));
  if (signatures.length === 0) throw new NoteError('a note carries at least one signature');
  return { text, signatures };
}

/**
 * Parse ONE signature line.
 *
 * Separate from parseNote because a caller that wants one line should not have
 * to reconstruct a whole note around it — the tlog adapter did, and a witness
 * cosignature's timestamp was silently lost whenever any OTHER line in the
 * reconstructed note failed to parse. Reading one line should fail for reasons
 * about that line.
 *
 * @param {string} line
 * @returns {NoteSignature}
 */
export function parseSignatureLine(line) {
  {
    if (!line.startsWith(MARKER)) throw new NoteError(`not a signature line: ${JSON.stringify(line)}`);
    const body = line.slice(MARKER.length);
    const sp = body.lastIndexOf(' ');
    if (sp === -1) throw new NoteError('a signature line is a name and a base64 blob');
    const name = body.slice(0, sp);
    const b64 = body.slice(sp + 1);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new NoteError(`signature is not base64: ${b64}`);
    const raw = Buffer.from(b64, 'base64');
    // Two lengths, because a note carries both kinds of line: the log's own
    // plain signature and a witness's timestamped cosignature. This used to
    // accept only 68 and THREW on a real witness cosignature, which the
    // Anchorer caught and reported as "does not verify" — a parse failure
    // wearing a cryptographic verdict's clothes.
    if (raw.length === PLAIN_LEN) {
      return { name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) };
    }
    if (raw.length === COSIG_V1_LEN) {
      return {
        name,
        keyId: raw.subarray(0, 4),
        timestamp: raw.readBigUInt64BE(4),
        signature: raw.subarray(12),
      };
    }
    throw new NoteError(
      `a signature blob is ${PLAIN_LEN} bytes (key id and signature) or ${COSIG_V1_LEN} `
      + `(key id, cosignature/v1 timestamp, signature), got ${raw.length}`);
  }
}
