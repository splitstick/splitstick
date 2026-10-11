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
  const id = noteKeyId(name, publicKey, algorithm).toString('hex');
  const body = Buffer.concat([Buffer.from([algorithm]), publicKey]).toString('base64');
  return `${name}+${id}+${body}`;
}

/**
 * @param {string} vkey
 * @returns {{ name: string, algorithm: number, publicKey: Buffer, keyId: Buffer }}
 */
export function parseVkey(vkey) {
  const parts = vkey.split('+');
  if (parts.length < 3) throw new NoteError('a vkey is name+keyid+key');
  const body = /** @type {string} */ (parts.pop());
  const id = /** @type {string} */ (parts.pop());
  const name = parts.join('+');
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
 * @param {{ origin: string, tree_size: number, root: Uint8Array }} cp
 * @returns {string} the note text, which is the signed subject
 */
export function checkpointText({ origin, tree_size, root }) {
  if (typeof origin !== 'string' || origin.length === 0) throw new NoteError('origin is required');
  // An origin carrying a newline could otherwise forge a second line and move
  // the tree size a verifier reads.
  if (/[\n\r]/.test(origin)) throw new NoteError('origin must not contain a newline');
  if (!Number.isInteger(tree_size) || tree_size < 0) {
    throw new NoteError(`tree_size must be a non-negative integer, got ${String(tree_size)}`);
  }
  if (root.length !== 32) throw new NoteError('root is a 32-byte digest');
  return `${origin}\n${tree_size}\n${Buffer.from(root).toString('base64')}\n`;
}

/**
 * @param {string} text
 * @returns {{ origin: string, tree_size: number, root: Buffer, extra: string[] }}
 */
export function parseCheckpointText(text) {
  if (!text.endsWith('\n')) throw new NoteError('note text must end with a newline');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 3) throw new NoteError('a checkpoint is origin, tree_size and root');
  const [origin, size, rootB64] = /** @type {[string, string, string]} */ (lines);
  if (!/^(0|[1-9][0-9]*)$/.test(size)) throw new NoteError(`tree_size is not a decimal integer: ${size}`);
  const root = Buffer.from(rootB64, 'base64');
  if (root.length !== 32) throw new NoteError('root does not decode to 32 bytes');
  return { origin, tree_size: Number(size), root, extra: lines.slice(3) };
}

/** @typedef {{ name: string, keyId: Buffer, signature: Buffer }} NoteSignature */

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
  for (const line of rest.slice(0, -1).split('\n')) {
    if (!line.startsWith(MARKER)) throw new NoteError(`not a signature line: ${JSON.stringify(line)}`);
    const body = line.slice(MARKER.length);
    const sp = body.lastIndexOf(' ');
    if (sp === -1) throw new NoteError('a signature line is a name and a base64 blob');
    const name = body.slice(0, sp);
    const b64 = body.slice(sp + 1);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new NoteError(`signature is not base64: ${b64}`);
    const raw = Buffer.from(b64, 'base64');
    if (raw.length !== 4 + 64) throw new NoteError('a signature blob is a 4-byte key id and a 64-byte signature');
    signatures.push({ name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  if (signatures.length === 0) throw new NoteError('a note carries at least one signature');
  return { text, signatures };
}
