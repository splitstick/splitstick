/**
 * File-backed and generated signers — DEVELOPMENT ONLY.
 *
 * DES-06 admits three signer types: kms, hsm and file, and says plainly that
 * file means development. This is the one module in the project that touches
 * private key material, kept separate so SEC-14 can be checked by a code scan
 * rather than by reading every file: core, the collector and the verifier must
 * contain no private-key API at all.
 *
 * A signer created here declares custody 'software', which means a verifier
 * will print the declaration and refuse to claim forward secrecy for anything
 * it signed. That is the correct outcome, not a limitation to work around.
 */

import { generateKeyPairSync, createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { noteKeyId } from './note.mjs';

/** @param {import('node:crypto').KeyObject} pub @returns {Buffer} raw 32 bytes */
const rawPublic = pub => pub.export({ format: 'der', type: 'spki' }).subarray(-32);

/**
 * @param {string} name the note identity and log origin
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {import('node:crypto').KeyObject} publicKey
 * @returns {import('./signer.mjs').Signer}
 */
function wrap(name, privateKey, publicKey) {
  const raw = rawPublic(publicKey);
  const keyId = noteKeyId(name, raw);
  return {
    name,
    algorithm: 'ed25519',
    publicKey: raw,
    keyId,
    custody: 'software',
    async sign(bytes) { return cryptoSign(null, Buffer.from(bytes), privateKey); },
    verifier() { return { name, publicKey: raw, keyId }; },
  };
}

/**
 * A fresh throwaway key. For tests and local development.
 * @param {string} name
 * @returns {Promise<import('./signer.mjs').Signer>}
 */
export async function generateDevSigner(name) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return wrap(name, privateKey, publicKey);
}

/**
 * @param {string} name
 * @param {string} path a PKCS#8 PEM Ed25519 private key
 * @returns {Promise<import('./signer.mjs').Signer>}
 */
export async function fileSigner(name, path) {
  const privateKey = createPrivateKey(readFileSync(path, 'utf8'));
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError(`${path} is not an Ed25519 key`);
  }
  const { createPublicKey } = await import('node:crypto');
  return wrap(name, privateKey, createPublicKey(privateKey));
}
