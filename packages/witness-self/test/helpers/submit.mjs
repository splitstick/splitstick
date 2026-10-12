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
 *   node submit.mjs <dir> <seedFile> <label> <peerLabel>
 *
 * The barrier is a READINESS HANDSHAKE, not a wall clock. Each process does
 * every bit of setup, drops a `ready-<label>` file, and spins until its peer's
 * file appears — so both enter the critical section together on any machine.
 *
 * The first version used a fixed `Date.now() + 700`. On a loaded runner — which
 * is what CI is — node boot plus ESM loading can exceed that, so the barrier
 * had already expired before either process reached it and the two ran
 * sequentially. The test then passed WITHOUT EXERCISING THE RACE, which is
 * worse than failing: a green result that means nothing.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { StatefulWitness } from '../../src/witness.mjs';
import { checkpointText, encodeNote, noteKeyId } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash, consistencyProof } from '@splitstick/core/merkle';

const [dir, seedFile, label, peer, readyAs] = process.argv.slice(2);
// `readyAs` lets two processes share a HISTORY label (so they compute the same
// root) while still handshaking under distinct names.
const me = readyAs ?? label;
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
// Reported on every path. The caller asserts that the two processes really did
// submit DIFFERENT roots before concluding anything from the acceptance count
// — without it, "both accepted" and "both submitted the same thing" are
// indistinguishable in a CI log.
const root = treeRoot(history).toString('base64');

if (peer) {
  writeFileSync(join(String(dir), `ready-${me}`), '1');
  const deadline = Date.now() + 20_000;
  // A spin, not a timer: the point is to enter the critical section at the
  // same instant, and a timer's resolution is coarser than the window.
  while (!existsSync(join(String(dir), `ready-${peer}`))) {
    if (Date.now() > deadline) {
      process.stdout.write(JSON.stringify({
        label, accepted: false, status: null, message: `peer ${peer} never became ready`,
      }) + '\n');
      // Deliberately without `root`, so a handshake failure is distinguishable
      // in a CI log from a submission the witness refused.
      process.exit(2);
    }
  }
}

try {
  const res = await w.addCheckpoint({ note, old_size: prefix.length, consistency_proof: proof });
  process.stdout.write(JSON.stringify({ label, accepted: true, status: res.status, root }) + '\n');
} catch (e) {
  process.stdout.write(JSON.stringify({
    label,
    accepted: false,
    status: /** @type {any} */ (e).status ?? null,
    message: e instanceof Error ? e.message : String(e),
    root,
  }) + '\n');
}
