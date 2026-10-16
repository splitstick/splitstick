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

/**
 * Two processes into the critical section together, synchronised by a
 * readiness handshake rather than a wall clock.
 *
 * The fixed `Date.now() + 700` this replaces could expire before either
 * process reached it on a loaded runner, so the two ran sequentially and the
 * test passed without exercising the race at all. A green result that means
 * nothing is worse than a red one.
 * @param {string} dir @param {string} seedFile
 */
function race(dir, seedFile) {
  const peers = { A: 'B', B: 'A' };
  return Promise.all(['A', 'B'].map(label => new Promise((resolve) => {
    execFile(process.execPath, [SUBMIT, dir, seedFile, label, peers[label]],
      { timeout: 40_000 }, (err, stdout, stderr) => {
        const line = String(stdout).trim().split('\n').filter(Boolean).at(-1);
        resolve(line ? JSON.parse(line) : {
          label, accepted: false, crashed: String(stderr).slice(0, 300),
        });
      });
  })));
}

/**
 * One submission, alone, with no handshake.
 *
 * `race` passes a peer label and the child waits for it; omitting the peer
 * makes the child submit immediately. Used to ask whether the witness is
 * USABLE, which is a different question from who won a race.
 * @param {string} dir @param {string} seedFile @param {string} label
 */
function submitAlone(dir, seedFile, label) {
  return new Promise((resolve) => {
    execFile(process.execPath, [SUBMIT, dir, seedFile, label], { timeout: 40_000 },
      (err, stdout, stderr) => {
        const line = String(stdout).trim().split('\n').filter(Boolean).at(-1);
        resolve(line ? JSON.parse(line) : {
          label, accepted: false, crashed: String(stderr).slice(0, 300),
        });
      });
  });
}

/** @param {string} dir */
function rootsAt(dir, size) {
  const p = join(dir, 'roots.jsonl');
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l))
    .filter(r => r.tree_size === size).map(r => r.root);
}

test('two PROCESSES submitting CONFLICTING successors: one root survives', async () => {
  // The failure this exists for, which an in-process test cannot reach. With a
  // promise-chain lock and nothing else, BOTH processes were accepted and the
  // witness retained two distinct roots at the same height — it countersigned
  // two conflicting histories, which is the one thing it exists to prevent.
  // Reproduced six times out of six before the fix.
  const { dir, seedFile } = await seeded();
  const results = await race(dir, seedFile);
  const accepted = results.filter(r => r.accepted);
  const refused = results.filter(r => !r.accepted);

  // THE security invariant, asserted first and on its own terms: whatever the
  // two processes were told, the retained history must hold one root at that
  // height. Everything else below is diagnosis.
  const roots = rootsAt(dir, 20);
  assert.equal(roots.length, 1,
    `the witness must retain ONE root per height, found ${roots.length}: ${JSON.stringify(roots)}`
    + ` — results were ${JSON.stringify(results)}`);
  const state = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'));
  assert.equal(state.seq[OPERATOR].last_size, 20);
  assert.equal(state.seq[OPERATOR].last_root, roots[0],
    'the state and the retained root must agree');

  // And since the two submissions were for DIFFERENT roots, exactly one of
  // them can have been accepted. The failure message carries both roots, so a
  // CI log is enough to tell a genuine dual acceptance from a test artefact.
  assert.equal(new Set(results.map(r => r.root)).size, 2,
    'the fixture must submit two different roots, or this proves nothing');
  assert.equal(accepted.length, 1,
    `two different roots were submitted and ${accepted.length} were accepted: `
    + JSON.stringify(results));
  assert.equal(refused.length, 1);
  assert.ok(!refused[0].crashed, `the loser must be refused, not crash: ${refused[0].crashed}`);
});

test('two PROCESSES submitting the SAME successor: both accepted, and that is correct', async () => {
  // The dual acceptance that is NOT a fault, pinned so it can never be
  // mistaken for one. A resubmission of the same size and root is idempotent
  // by design (DES-08): a retry after a dropped response must not look like an
  // attack. Two processes doing it at once is the same thing twice.
  //
  // Without this test, "both accepted" reads as a security failure in every
  // circumstance, and the distinction that actually matters — whether the
  // retained history forked — is left to whoever is reading the log.
  const { dir, seedFile } = await seeded();
  const peers = { A: 'B', B: 'A' };
  const results = await Promise.all(['A', 'B'].map(label => new Promise((resolve) => {
    // The same label for the history, so both compute the SAME root.
    execFile(process.execPath, [SUBMIT, dir, seedFile, 'same', peers[label], label],
      { timeout: 40_000 }, (_err, stdout) => {
        const line = String(stdout).trim().split('\n').filter(Boolean).at(-1);
        resolve(line ? JSON.parse(line) : { accepted: false });
      });
  })));
  assert.equal(new Set(results.map(r => r.root)).size, 1, 'both submitted the same root');
  // One root retained, however many were accepted. That is the invariant; the
  // acceptance count is not.
  assert.equal(rootsAt(dir, 20).length, 1,
    `one root per height: ${JSON.stringify(rootsAt(dir, 20))}`);
  assert.ok(results.some(r => r.accepted), JSON.stringify(results));
  for (const r of results) {
    assert.ok(r.accepted || [409, 503].includes(Number(r.status)),
      `an identical resubmission must be accepted or merely contended: ${JSON.stringify(r)}`);
  }
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
  //
  // THE PROPERTY IS LIVENESS, and this used to assert a proxy for it that is
  // timing-dependent: that exactly one of two racing processes is accepted.
  // Both processes have to notice the dead lock and break it, and two that
  // break it at the same instant can each then see the OTHER's fresh lock and
  // back off — so `accepted` is legitimately 0, a real client would retry, and
  // the witness is not wedged at all. It failed about once in twenty runs on
  // Node 20, which is often enough to redden an unrelated pull request and
  // rare enough that the evidence was gone before anybody looked.
  //
  // So safety and liveness are asserted separately, on their own terms.
  const { dir, seedFile } = await seeded();
  const lockPath = join(dir, '.lock');
  writeFileSync(lockPath, JSON.stringify({ pid: 999_999, at: new Date().toISOString() }));

  const results = await race(dir, seedFile);
  const accepted = results.filter(r => r.accepted);

  // SAFETY, which is not timing-dependent and must never bend: a stale lock
  // must not let both conflicting successors through. This is the assertion
  // that would catch a lock-breaking bug, and it is strictly stronger than
  // what the old `=== 1` checked.
  assert.ok(accepted.length <= 1,
    `both conflicting successors were accepted after breaking a stale lock: ${JSON.stringify(results)}`);
  const roots = rootsAt(dir, 20);
  assert.equal(new Set(roots).size, Math.min(roots.length, 1),
    `the witness retained two roots at height 20: ${JSON.stringify(roots)}`);

  // Neither process may fail for a reason other than losing the race — a
  // crash, or a handshake that never completed, would make the liveness check
  // below meaningless.
  for (const r of results) {
    assert.equal(r.crashed, undefined, `a submitter crashed: ${JSON.stringify(r)}`);
    assert.ok(r.accepted || r.status === 409 || r.status === 400 || r.message !== undefined,
      `a submitter failed without saying why: ${JSON.stringify(r)}`);
  }

  // LIVENESS, asked directly instead of inferred. If the race left nobody
  // accepted, the question is not who won but whether the witness still
  // works: a stale lock that wedges it would refuse this too, forever.
  if (accepted.length === 0) {
    const retry = await submitAlone(dir, seedFile, 'C');
    assert.equal(retry.accepted, true,
      `the stale lock wedged the witness: a lone submission after the race was also refused — `
      + `${JSON.stringify(retry)}`);
  }
});

test('a stale lock is BROKEN, not merely survived', async () => {
  // The other half of the same requirement, and the one a proxy assertion can
  // hide: the dead process's lock file must not still be sitting there holding
  // the witness shut. A single submission against a stale lock has no race in
  // it at all, so this is deterministic.
  const { dir, seedFile } = await seeded();
  writeFileSync(join(dir, '.lock'),
    JSON.stringify({ pid: 999_999, at: new Date().toISOString() }));

  const r = await submitAlone(dir, seedFile, 'A');
  assert.equal(r.accepted, true, `a stale lock refused a lone submission: ${JSON.stringify(r)}`);
  // And the witness is usable again afterwards, which is what an operator
  // actually needs: the recovery is not single-use.
  const again = await submitAlone(dir, seedFile, 'A');
  assert.ok(again.accepted || again.status === 409,
    `the witness became unusable after recovering from a stale lock: ${JSON.stringify(again)}`);
});
