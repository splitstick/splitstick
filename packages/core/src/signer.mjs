/**
 * The signer seam — DES-06, FR-10, SEC-14.
 *
 * Splitstick must never hold, receive, request or log the operator signing key.
 * The collector therefore takes a *signer interface* — `sign(bytes) → signature`
 * — so a KMS-backed signer and a local one are interchangeable and no code path
 * in core or in the verifier ever sees private material. A file-backed signer
 * exists for development only and lives in its own module (signer-file.mjs), so
 * that a code check can assert which single file touches key material.
 *
 * `sign` is async because a KMS round trip is. Signing happens per checkpoint,
 * not per append, so this is not on NFR-01's path.
 *
 * @typedef {object} Signer
 * @property {string} name the note identity, which is also the log origin
 * @property {'ed25519'} algorithm
 * @property {Buffer} publicKey raw 32 bytes
 * @property {Buffer} keyId the 4-byte note key id
 * @property {'software'|'kms'|'hsm'} custody OPERATOR-DECLARED. See below.
 * @property {(bytes: Uint8Array) => Promise<Buffer>} sign
 * @property {() => Verifier} verifier
 * @property {string} [keyArn] OPTIONAL provenance: the immutable identity of the
 *   key this signer resolved and pinned at construction. A remote signer may be
 *   configured by a mutable name — a KMS alias can be repointed at another key
 *   without the configuration changing — so a signer that resolves such a name
 *   reports the immutable identity it actually signs with, and signs with that
 *   identity rather than re-resolving per call. Absent for a signer whose
 *   configuration already names the key immutably.
 * @property {string} [configuredKeyId] OPTIONAL provenance: what the operator
 *   configured, which may be an alias. Kept beside `keyArn` so a mismatch
 *   between the two is visible rather than silently reconciled.
 *
 * @typedef {object} Verifier
 * @property {string} name
 * @property {Buffer} publicKey
 * @property {Buffer} keyId
 * @property {number} [algorithm] the note algorithm this identity signs with —
 *   ALG_ED25519 (1) for a log's own signature, ALG_ED25519_COSIG_V1 (4) for a
 *   witness cosignature. It selects WHICH BYTES are verified, so it comes from
 *   the reader's acceptance policy and never from the line being checked.
 *   Defaults to ALG_ED25519, which is what every pre-FR-15 caller meant.
 */

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { noteKeyId, cosignatureV1Message, ALG_ED25519, ALG_ED25519_COSIG_V1 } from './note.mjs';

/**
 * A custody class is a *declaration*. An HSM signature and a signature from a
 * PEM file on disk are byte-identical, so nothing here proves custody; FR-65
 * records the declaration in a chained record and FR-70 gives the five checks a
 * provider attestation must pass before a verifier may call custody
 * independently supported. A verifier prints this as operator-declared and
 * refuses to claim forward secrecy for any epoch declared software-keyed.
 */
export const CUSTODY_CLASSES = Object.freeze(['software', 'kms', 'hsm']);

/** @param {Uint8Array} raw 32-byte Ed25519 public key @returns {import('node:crypto').KeyObject} */
export function publicKeyFromRaw(raw) {
  if (raw.length !== 32) throw new RangeError('an Ed25519 public key is 32 bytes');
  // SPKI DER prefix for id-Ed25519.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * Sign note text, producing a signature line entry.
 * @param {string} text the note text — the only signed subject
 * @param {Signer} signer
 * @returns {Promise<import('./note.mjs').NoteSignature>}
 */
export async function signNote(text, signer) {
  const signature = await signer.sign(Buffer.from(text, 'utf8'));
  if (signature.length !== 64) throw new RangeError('an Ed25519 signature is 64 bytes');
  return { name: signer.name, keyId: signer.keyId, signature };
}

/**
 * Verify one signature line against a verifier identity.
 *
 * Returns a boolean: a bad signature is a verdict (DES-12 OPSIG_INVALID), not
 * an exception. The key id is checked first, so a pack signed under a different
 * key for the same origin is rejected rather than silently accepted — FR-63.
 *
 * @param {string} text
 * @param {import('./note.mjs').NoteSignature} sig
 * @param {Verifier} v
 * @returns {Promise<boolean>}
 */
export async function verifyNoteSignature(text, sig, v) {
  if (sig.name !== v.name) return false;
  const algorithm = v.algorithm ?? ALG_ED25519;
  const expect = noteKeyId(v.name, v.publicKey, algorithm);
  if (!expect.equals(sig.keyId)) return false;

  // WHICH BYTES ARE COVERED depends on the algorithm the verifier declares,
  // and the two are not interchangeable. A cosignature/v1 signature covers
  // `cosignature/v1\ntime <unix>\n<text>`; a plain note signature covers the
  // text. Verifying one against the other's message fails, which is how a real
  // witness cosignature read as "does not verify" until FR-15 ran the Go
  // implementation.
  //
  // The algorithm is taken from the verifier -- the READER's acceptance policy
  // -- and never from the line being checked. Letting the line choose would let
  // a witness present a plain signature where the policy expects a timestamped
  // cosignature, which is a downgrade the reader never agreed to.
  if (algorithm === ALG_ED25519_COSIG_V1) {
    if (sig.timestamp === undefined) return false;
    const msg = cosignatureV1Message(sig.timestamp, text);
    return cryptoVerify(null, Buffer.from(msg, 'utf8'), publicKeyFromRaw(v.publicKey), sig.signature);
  }
  if (sig.timestamp !== undefined) return false;
  return cryptoVerify(null, Buffer.from(text, 'utf8'), publicKeyFromRaw(v.publicKey), sig.signature);
}
