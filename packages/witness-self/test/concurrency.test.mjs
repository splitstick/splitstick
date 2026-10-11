import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, createPublicKey, createPrivateKey, sign } from 'node:crypto';
import { StatefulWitness } from '../src/witness.mjs';
import { checkpointText, encodeNote, noteKeyId } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash } from '@splitstick/core/merkle';

const SUBMIT = fileURLToPath(new URL('./helpers/submit.mjs', import.meta.url));
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

/** A witness directory already holding a countersigned height of 10. */
async function seeded() {
  const dir = mkdtempSync(join(tmpdir(), 'ss-conc-'));
  const op = generateKeyPairSync('ed25519');
  const wit = generateKeyPairSync('ed25519');
  const seedFile = join(dir, 'keys.json');
  writeFileSync(seedFile, JSON.stringify({
    operator: op.privateKey.export({ format: 'pem', type: 'pkcs8' }),
    witness: wit.privateKey.export({ format: 'pem', type: 'pkcs8' }),
  }));
  const operator = signerFrom(JSON.parse(readFileSync(seedFile, 'utf8')).operator, OPERATOR);
  const witnessSigner = signerFrom(
    JSON.parse(readFileSync(seedFile, 'utf8')).witness, 'audit.internal');

  const w = new StatefulWitness({ dir, signer: witnessSigner });
  w.enrol(OPERATOR, operator.publicKey);
  const prefix = Array.from({ length: 10 }, (_, i) => leafHash(Buffer.from(`shared-${i}`)));
  const text = checkpointText({
    origin: OPERATOR, tree_size: 10, root: treeRoot(prefix), suite: 'SS1' });
  await w.addCheckpoint({ note: encodeNote(text, [await signNote(text, operator)]), old_size: 0 });
  writeFileSync(join(dir, 'baseline.json'),
    JSON.stringify({ prefix: prefix.map(b => b.toString('hex')) }));
  return { dir, seedFile };
}

/** @param {string} dir @param {string} seedFile */
function race(dir, seedFile) {
  const startAt = Date.now() + 700;
  return Promise.all(['A', 'B'].map(label => new Promise((resolve) => {
    execFile(process.execPath, [SUBMIT, dir, seedFile, label, String(startAt)],
      { timeout: 30_000 }, (err, stdout, stderr) => {
        const line = String(stdout).trim().split('\n').filter(Boolean).at(-1);
        resolve(line ? JSON.parse(line) : { label, accepted: false, crashed: String(stderr).slice(0, 300) });
      });
  })));
}

/** @param {string} dir */
function rootsAt(dir, size) {
  const p = join(dir, 'roots.jsonl');
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l))
    .filter(r => r.tree_size === size).map(r => r.root);
}

test('two PROCESSES submitting conflicting successors: exactly one wins', async () => {
  // The failure this exists for, which an in-process test cannot reach. With a
  // promise-chain lock and nothing else, BOTH processes were accepted and the
  // witness retained two distinct roots at the same height — it countersigned
  // two conflicting histories, which is the one thing it exists to prevent.
  // Reproduced six times out of six before the fix.
  const { dir, seedFile } = await seeded();
  const results = await race(dir, seedFile);
  const accepted = results.filter(r => r.accepted);
  const refused = results.filter(r => !r.accepted);

  assert.equal(accepted.length, 1,
    `exactly one submission may be accepted: ${JSON.stringify(results)}`);
  assert.equal(refused.length, 1);
  assert.ok(!refused[0].crashed, `the loser must be refused, not crash: ${refused[0].crashed}`);

  const roots = rootsAt(dir, 20);
  assert.equal(new Set(roots).size, 1,
    `the witness must retain ONE root per height, found ${new Set(roots).size}: ${roots}`);
  const state = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'));
  assert.equal(state.seq[OPERATOR].last_size, 20);
  assert.equal(state.seq[OPERATOR].last_root, roots[0],
    'the state and the retained root must agree');
});

test('the loser is told it lost, in protocol terms', async () => {
  const { dir, seedFile } = await seeded();
  const results = await race(dir, seedFile);
  const refused = results.find(r => !r.accepted);
  assert.ok(refused);
  // A contended write and a forked history are different things and the
  // operator's response differs: retry versus stop and investigate. A lock
  // that surfaced as a 409 fork would send them looking for an attacker.
  assert.ok([409, 503].includes(Number(refused.status)),
    `expected a protocol status, got ${JSON.stringify(refused)}`);
});

test('a lock left by a dead process does not wedge the witness', async () => {
  // A witness that needs manual recovery after a crash is a witness an
  // operator will stop running, and then there is no second party at all.
  const { dir, seedFile } = await seeded();
  const lockPath = join(dir, '.lock');
  writeFileSync(lockPath, JSON.stringify({ pid: 999_999, at: new Date().toISOString() }));
  const results = await race(dir, seedFile);
  assert.equal(results.filter(r => r.accepted).length, 1, JSON.stringify(results));
});
