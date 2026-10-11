/**
 * A real submission in a separate process, killable mid-transition.
 *
 * Invoked as: node crash.mjs <dir> <seedFile> <label> <size> [killAfterMs]
 *
 * With `killAfterMs` the process SIGKILLs itself after that delay, which lands
 * somewhere inside the submission. It is probabilistic — sometimes before the
 * root append, sometimes between the append and the state write, sometimes
 * after — and that is the point: the invariant has to hold wherever it lands.
 * The deterministic case is covered separately by constructing the exact
 * post-crash file state, since the files ARE the state.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { StatefulWitness } from '../../src/witness.mjs';
import { checkpointText, encodeNote, noteKeyId } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash, consistencyProof } from '@splitstick/core/merkle';

const [dir, seedFile, label, sizeArg, killAfterMs] = process.argv.slice(2);
const OPERATOR = 'splitstick.dev/host-1';

/** @param {string} pem @param {string} name */
function signerFrom(pem, name) {
  const priv = createPrivateKey(pem);
  const raw = Buffer.from(createPublicKey(priv).export({ format: 'der', type: 'spki' })).subarray(-32);
  const keyId = noteKeyId(name, raw);
  return {
    name, algorithm: /** @type {const} */ ('ed25519'), publicKey: raw, keyId,
    custody: /** @type {const} */ ('software'),
    async sign(/** @type {Uint8Array} */ b) { return sign(null, Buffer.from(b), priv); },
    verifier() { return { name, publicKey: raw, keyId }; },
  };
}

const seed = JSON.parse(readFileSync(String(seedFile), 'utf8'));
const operator = signerFrom(seed.operator, OPERATOR);
const witnessSigner = signerFrom(seed.witness, 'audit.internal');

if (killAfterMs) {
  const t = setTimeout(() => process.kill(process.pid, 'SIGKILL'), Number(killAfterMs));
  t.unref();
}

const w = new StatefulWitness({ dir: String(dir), signer: witnessSigner });
const base = JSON.parse(readFileSync(join(String(dir), 'baseline.json'), 'utf8'));
const prefix = base.prefix.map((/** @type {string} */ h) => Buffer.from(h, 'hex'));
const size = Number(sizeArg);
const history = [
  ...prefix,
  ...Array.from({ length: size - prefix.length }, (_, i) => leafHash(Buffer.from(`${label}-${i}`))),
];
const text = checkpointText({
  origin: OPERATOR, tree_size: size, root: treeRoot(history), suite: 'SS1' });
const note = encodeNote(text, [await signNote(text, operator)]);

try {
  const res = await w.addCheckpoint({
    note,
    old_size: prefix.length,
    consistency_proof: consistencyProof(history, prefix.length).map(b => b.toString('base64')),
  });
  process.stdout.write(JSON.stringify({
    label, accepted: true, status: res.status,
    root: treeRoot(history).toString('base64'),
  }) + '\n');
} catch (e) {
  process.stdout.write(JSON.stringify({
    label, accepted: false, status: /** @type {any} */ (e).status ?? null,
    message: e instanceof Error ? e.message : String(e),
    root: treeRoot(history).toString('base64'),
  }) + '\n');
}
