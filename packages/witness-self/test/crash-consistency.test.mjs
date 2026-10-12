import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  mkdtempSync, readFileSync, writeFileSync, appendFileSync, existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, createPublicKey, createPrivateKey, sign } from 'node:crypto';
import { StatefulWitness, WitnessRefused } from '../src/witness.mjs';
import { checkpointText, encodeNote, noteKeyId } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash, consistencyProof } from '@splitstick/core/merkle';

/**
 * Crash consistency — the P1 from the re-review of ca4f396.
 *
 * A successful submission used to be two operations: append the root to
 * roots.jsonl, then advance state.json. A crash between them left the retained
 * history ahead of the active state, and after restart the witness would accept
 * a DIFFERENT valid successor at the same height — so the retained history
 * ended up holding two conflicting roots at one height even though
 * cross-process locking worked perfectly.
 *
 * The old comment called a retained root without an advanced state harmless.
 * That is only true if recovery reconciles, and it did not.
 */

const CRASH = fileURLToPath(new URL('./helpers/crash.mjs', import.meta.url));
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

async function seeded() {
  const dir = mkdtempSync(join(tmpdir(), 'ss-crash-'));
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
  return { dir, seedFile, operator, witnessSigner, prefix };
}

/** @param {Buffer[]} prefix @param {string} label @param {number} size */
const historyFor = (prefix, label, size) => [
  ...prefix,
  ...Array.from({ length: size - prefix.length }, (_, i) => leafHash(Buffer.from(`${label}-${i}`))),
];

/** @param {string} dir @param {string} seedFile @param {string} label @param {number} size @param {number} [killAfterMs] */
function submitInProcess(dir, seedFile, label, size, killAfterMs) {
  return new Promise((resolve) => {
    const args = [CRASH, dir, seedFile, label, String(size)];
    if (killAfterMs !== undefined) args.push(String(killAfterMs));
    execFile(process.execPath, args, { timeout: 30_000 }, (_err, stdout) => {
      const line = String(stdout).trim().split('\n').filter(Boolean).at(-1);
      resolve(line ? JSON.parse(line) : { killed: true });
    });
  });
}

/** @param {string} dir @param {number} size */
function distinctRootsAt(dir, size) {
  const p = join(dir, 'roots.jsonl');
  if (!existsSync(p)) return [];
  const raw = readFileSync(p, 'utf8');
  // Drop a torn trailing line the way the witness must.
  const lines = raw.split('\n');
  if (raw.length > 0 && !raw.endsWith('\n')) lines.pop();
  const roots = lines.filter(Boolean).flatMap((l) => {
    try { return [JSON.parse(l)]; } catch { return []; }
  }).filter(r => r.tree_size === size).map(r => r.root);
  return [...new Set(roots)];
}

// ── The deterministic case ──────────────────────────────────────────────────

test('a root retained with the state not advanced is reconciled, not ignored', async () => {
  const { dir, seedFile, operator, witnessSigner, prefix } = await seeded();
  const histB = historyFor(prefix, 'B', 20);
  const rootB = treeRoot(histB).toString('base64');

  // The crash, constructed exactly: root B appended, state.json untouched. The
  // files are the whole of the witness's state, so writing them by hand is a
  // faithful reproduction rather than a simulation of one.
  appendFileSync(join(dir, 'roots.jsonl'), JSON.stringify({
    operator: OPERATOR, tree_size: 20, root: rootB, at: '2026-10-11T12:00:00.000Z',
  }) + '\n');

  const after = new StatefulWitness({ dir, signer: witnessSigner });
  // The append happens only after every check has passed, so a retained root is
  // one this witness DID accept. Recovery adopts it rather than pretending it
  // never happened.
  assert.equal(after.state(OPERATOR).last_size, 20);
  assert.equal(after.state(OPERATOR).last_root, rootB);

  const histC = historyFor(prefix, 'C', 20);
  const tC = checkpointText({
    origin: OPERATOR, tree_size: 20, root: treeRoot(histC), suite: 'SS1' });
  const err = await after.addCheckpoint({
    note: encodeNote(tC, [await signNote(tC, operator)]), old_size: 10,
    consistency_proof: consistencyProof(histC, 10).map(b => b.toString('base64')),
  }).then(() => null, (/** @type {any} */ e) => e);

  assert.ok(err instanceof WitnessRefused, 'a conflicting successor must be refused');
  assert.equal(err.status, 409);
  assert.deepEqual(distinctRootsAt(dir, 20), [rootB],
    'the retained history must never hold two roots at one height');
});

test('resubmitting the root that was retained is idempotent, not a fork', async () => {
  // The operator never got their signature, so they retry. After
  // reconciliation the witness holds their root at that height, and the retry
  // must return the signature rather than read as a fork.
  const { dir, seedFile, operator, witnessSigner, prefix } = await seeded();
  const histB = historyFor(prefix, 'B', 20);
  appendFileSync(join(dir, 'roots.jsonl'), JSON.stringify({
    operator: OPERATOR, tree_size: 20, root: treeRoot(histB).toString('base64'),
    at: '2026-10-11T12:00:00.000Z',
  }) + '\n');
  const after = new StatefulWitness({ dir, signer: witnessSigner });
  const tB = checkpointText({
    origin: OPERATOR, tree_size: 20, root: treeRoot(histB), suite: 'SS1' });
  const res = await after.addCheckpoint({
    note: encodeNote(tB, [await signNote(tB, operator)]), old_size: 20,
  });
  assert.equal(res.status, 200);
  assert.deepEqual(distinctRootsAt(dir, 20).length, 1, 'and it is retained once');
});

test('an already-ambiguous history fails CLOSED rather than picking a root', async () => {
  // If two conflicting roots are somehow already on disk — an older build, a
  // restored backup, a filesystem that reordered — the witness cannot tell
  // which it accepted. Continuing to serve from that state is worse than
  // stopping: every signature afterwards rests on a guess.
  const { dir, operator, witnessSigner, prefix } = await seeded();
  for (const label of ['B', 'C']) {
    appendFileSync(join(dir, 'roots.jsonl'), JSON.stringify({
      operator: OPERATOR, tree_size: 20,
      root: treeRoot(historyFor(prefix, label, 20)).toString('base64'),
      at: '2026-10-11T12:00:00.000Z',
    }) + '\n');
  }
  const after = new StatefulWitness({ dir, signer: witnessSigner });
  const hist = historyFor(prefix, 'D', 30);
  const t = checkpointText({
    origin: OPERATOR, tree_size: 30, root: treeRoot(hist), suite: 'SS1' });
  const err = await after.addCheckpoint({
    note: encodeNote(t, [await signNote(t, operator)]), old_size: 20,
    consistency_proof: consistencyProof(hist, 20).map(b => b.toString('base64')),
  }).then(() => null, (/** @type {any} */ e) => e);
  assert.ok(err instanceof WitnessRefused);
  assert.equal(err.status, 409);
  assert.match(err.message, /two different roots|ambiguous/i);
});

test('a torn trailing line is dropped, not parsed, and does not throw', async () => {
  // A crash DURING the append leaves a partial line. roots() used to throw on
  // it, so the witness could not read its own retained history at all and
  // needed a hand edit before it would run again.
  const { dir, witnessSigner } = await seeded();
  const p = join(dir, 'roots.jsonl');
  writeFileSync(p, readFileSync(p, 'utf8') + '{"operator":"splitstick.dev/host-1","tree_siz');
  const after = new StatefulWitness({ dir, signer: witnessSigner });
  assert.equal(after.roots(OPERATOR).length, 1, 'the complete entries are still readable');
  assert.equal(after.state(OPERATOR).last_size, 10);
});

test('a malformed line in the MIDDLE is not a torn tail and fails closed', async () => {
  // A torn tail is the ordinary consequence of a crash. Damage in the middle is
  // not, and quietly skipping it would let somebody delete a retained root by
  // corrupting one byte.
  const { dir, witnessSigner } = await seeded();
  const p = join(dir, 'roots.jsonl');
  writeFileSync(p, '{"operator":"x","tree_siz\n' + readFileSync(p, 'utf8'));
  assert.throws(() => new StatefulWitness({ dir, signer: witnessSigner }),
    /unreadable|middle/i);
});

// ── Real crashes ────────────────────────────────────────────────────────────

test('killing the process mid-transition never produces a forked history', async () => {
  // Genuine SIGKILLs at randomised delays, so the termination lands in
  // different places: before the append, between the append and the state
  // write, after both. Probabilistic by nature — the deterministic case above
  // is what pins the exact window — but it is a real crash, which is the thing
  // the invariant has to survive.
  for (let i = 0; i < 12; i += 1) {
    const { dir, seedFile, witnessSigner, prefix } = await seeded();
    await submitInProcess(dir, seedFile, 'B', 20, 40 + i * 6);

    // Restart and try a CONFLICTING successor at the same height.
    const after = new StatefulWitness({ dir, signer: witnessSigner });
    const histC = historyFor(prefix, 'C', 20);
    const tC = checkpointText({
      origin: OPERATOR, tree_size: 20, root: treeRoot(histC), suite: 'SS1' });
    const operator = signerFrom(JSON.parse(readFileSync(seedFile, 'utf8')).operator, OPERATOR);
    await after.addCheckpoint({
      note: encodeNote(tC, [await signNote(tC, operator)]), old_size: 10,
      consistency_proof: consistencyProof(histC, 10).map(b => b.toString('base64')),
    }).catch(() => {});

    const distinct = distinctRootsAt(dir, 20);
    assert.ok(distinct.length <= 1,
      `run ${i}: the retained history holds ${distinct.length} roots at height 20`);
    // And the active state must never be behind the retained history.
    const kept = after.roots(OPERATOR);
    const highest = kept.reduce((m, r) => Math.max(m, r.tree_size), 0);
    assert.ok(after.state(OPERATOR).last_size >= highest,
      `run ${i}: state ${after.state(OPERATOR).last_size} is behind retained ${highest}`);
  }
});

// ── Repairing the torn tail, not merely tolerating it ───────────────────────

test('a torn tail is REPAIRED before the next append, not appended after', async () => {
  // Tolerating a torn tail on read is not enough. appendFileSync writes after
  // the partial bytes, producing one malformed line that IS newline-terminated
  // — and a terminated malformed line is damage in the middle, which fails
  // closed. So a recoverable crash became permanent corruption through
  // ordinary operation, and the submission that corrupted it was ACCEPTED AND
  // SIGNED first: the operator held a countersignature for a height the
  // witness could no longer read.
  const { dir, seedFile, operator, witnessSigner, prefix } = await seeded();
  const p = join(dir, 'roots.jsonl');
  const intact = readFileSync(p, 'utf8');
  writeFileSync(p, intact + '{"operator":"splitstick.dev/host-1","tree_siz');

  const w = new StatefulWitness({ dir, signer: witnessSigner });
  const hist = historyFor(prefix, 'B', 20);
  const t = checkpointText({
    origin: OPERATOR, tree_size: 20, root: treeRoot(hist), suite: 'SS1' });
  const res = await w.addCheckpoint({
    note: encodeNote(t, [await signNote(t, operator)]), old_size: 10,
    consistency_proof: consistencyProof(hist, 10).map(b => b.toString('base64')),
  });
  assert.equal(res.status, 200);

  // Every line complete, and the partial bytes gone.
  const after = readFileSync(p, 'utf8');
  assert.ok(after.endsWith('\n'));
  assert.ok(!after.includes('"tree_siz{'), 'the partial line must not have been appended after');
  for (const line of after.split('\n').filter(Boolean)) {
    assert.doesNotThrow(() => JSON.parse(line), `line is not complete JSON: ${line.slice(0, 60)}`);
  }

  // And the witness still comes up, with both heights.
  const restarted = new StatefulWitness({ dir, signer: witnessSigner });
  assert.deepEqual(restarted.roots(OPERATOR).map(r => r.tree_size), [10, 20]);
  assert.equal(restarted.state(OPERATOR).last_size, 20);
  assert.equal(restarted.state(OPERATOR).last_root, treeRoot(hist).toString('base64'));
});

test('the repair only removes the torn tail, never a complete entry', async () => {
  const { dir, witnessSigner, operator, prefix } = await seeded();
  const p = join(dir, 'roots.jsonl');
  const before = readFileSync(p, 'utf8').split('\n').filter(Boolean).length;
  writeFileSync(p, readFileSync(p, 'utf8') + 'x');   // one stray byte
  const w = new StatefulWitness({ dir, signer: witnessSigner });
  const hist = historyFor(prefix, 'B', 20);
  const t = checkpointText({
    origin: OPERATOR, tree_size: 20, root: treeRoot(hist), suite: 'SS1' });
  await w.addCheckpoint({
    note: encodeNote(t, [await signNote(t, operator)]), old_size: 10,
    consistency_proof: consistencyProof(hist, 10).map(b => b.toString('base64')),
  });
  assert.equal(readFileSync(p, 'utf8').split('\n').filter(Boolean).length, before + 1,
    'the complete entries survive and exactly one is added');
});

// ── Structurally invalid entries are refused, not skipped ──────────────────

test('a retained entry with the wrong types is refused, not silently skipped', async () => {
  // It parsed as JSON and was then dropped by a type filter in reconciliation,
  // so a retained root at height 20 vanished from the check and a conflicting
  // root at 20 was accepted. Strict about JSON syntax and lax about shape is
  // the worst combination: the lax half is where the bypass lives.
  const { dir, witnessSigner, prefix } = await seeded();
  appendFileSync(join(dir, 'roots.jsonl'), JSON.stringify({
    operator: OPERATOR,
    tree_size: '20',                    // a string, not a number
    root: treeRoot(historyFor(prefix, 'B', 20)).toString('base64'),
    at: '2026-10-11T12:00:00.000Z',
  }) + '\n');
  assert.throws(() => new StatefulWitness({ dir, signer: witnessSigner }),
    /tree_size|unreadable/i);
});

test('every field of a retained entry is validated, not just its presence', async () => {
  const { dir, witnessSigner, prefix } = await seeded();
  const good = {
    operator: OPERATOR, tree_size: 20,
    root: treeRoot(historyFor(prefix, 'B', 20)).toString('base64'),
    at: '2026-10-11T12:00:00.000Z',
  };
  const intact = readFileSync(join(dir, 'roots.jsonl'), 'utf8');
  for (const bad of [
    { ...good, operator: '' },
    { ...good, operator: 42 },
    { ...good, tree_size: 0 },
    { ...good, tree_size: -1 },
    { ...good, tree_size: 1.5 },
    { ...good, root: 'not base64!!' },
    { ...good, root: Buffer.alloc(31).toString('base64') },   // not a SHA-256 root
    { ...good, root: Buffer.alloc(33).toString('base64') },
    { ...good, at: 99 },
    [good],
    'a string',
    null,
  ]) {
    writeFileSync(join(dir, 'roots.jsonl'), intact + JSON.stringify(bad) + '\n');
    assert.throws(() => new StatefulWitness({ dir, signer: witnessSigner }),
      `${JSON.stringify(bad)} should be refused`);
  }
  // And the good one still works, so the validation is not simply refusing.
  writeFileSync(join(dir, 'roots.jsonl'), intact + JSON.stringify(good) + '\n');
  assert.doesNotThrow(() => new StatefulWitness({ dir, signer: witnessSigner }));
});
