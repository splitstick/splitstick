/**
 * A witness submission from a SEPARATE PROCESS.
 *
 * In-process concurrency tests cannot reach the failure this guards. The
 * witness serialised requests on a private promise chain, which is correct for
 * one instance and worthless across two: both processes read the same prior
 * root, both validated against it, both signed, and both wrote state.json with
 * an atomic rename. Atomic replacement stops a half-written file; it does not
 * make read-validate-write atomic.
 *
 * Invoked as:
 *   node submit.mjs <dir> <seedFile> <label> <startAtEpochMs>
 *
 * The start time is a barrier: both processes finish every bit of setup and
 * then enter the critical section at the same instant. Without it the first
 * process simply finishes before the second begins and the race never happens
 * — which is how this looked safe.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { StatefulWitness } from '../../src/witness.mjs';
import { checkpointText, encodeNote, noteKeyId } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash, consistencyProof } from '@splitstick/core/merkle';

const [dir, seedFile, label, startAt] = process.argv.slice(2);
const OPERATOR = 'splitstick.dev/host-1';

/** @param {string} pem @param {string} name */
function signerFrom(pem, name) {
  const priv = createPrivateKey(pem);
  const raw = Buffer.from(createPublicKey(priv).export({ format: 'der', type: 'spki' }))
    .subarray(-32);
  const keyId = noteKeyId(name, raw);
  return {
    name,
    algorithm: /** @type {const} */ ('ed25519'),
    publicKey: raw,
    keyId,
    custody: /** @type {const} */ ('software'),
    async sign(/** @type {Uint8Array} */ bytes) { return sign(null, Buffer.from(bytes), priv); },
    verifier() { return { name, publicKey: raw, keyId }; },
  };
}

const seed = JSON.parse(readFileSync(String(seedFile), 'utf8'));
const operator = signerFrom(seed.operator, OPERATOR);
const witnessSigner = signerFrom(seed.witness, 'audit.internal');

const w = new StatefulWitness({ dir: String(dir), signer: witnessSigner });

// Both processes extend the SAME prefix with a DIFFERENT tail, so each
// submission is individually valid and the two histories fork above the
// witnessed height. One of them must lose.
const base = JSON.parse(readFileSync(join(String(dir), 'baseline.json'), 'utf8'));
const prefix = base.prefix.map((/** @type {string} */ h) => Buffer.from(h, 'hex'));
const tail = Array.from({ length: 10 }, (_, i) => leafHash(Buffer.from(`${label}-tail-${i}`)));
const history = [...prefix, ...tail];
const text = checkpointText({
  origin: OPERATOR, tree_size: history.length, root: treeRoot(history), suite: 'SS1',
});
const note = encodeNote(text, [await signNote(text, operator)]);
const proof = consistencyProof(history, prefix.length).map(b => b.toString('base64'));

if (startAt) {
  const t = Number(startAt);
  // A spin, not a timer: the point is to enter the critical section at the
  // same instant, and setTimeout's resolution is coarser than the window.
  while (Date.now() < t) { /* wait */ }
}

try {
  const res = await w.addCheckpoint({ note, old_size: prefix.length, consistency_proof: proof });
  process.stdout.write(JSON.stringify({ label, accepted: true, status: res.status }) + '\n');
} catch (e) {
  process.stdout.write(JSON.stringify({
    label,
    accepted: false,
    status: /** @type {any} */ (e).status ?? null,
    message: e instanceof Error ? e.message : String(e),
  }) + '\n');
}
