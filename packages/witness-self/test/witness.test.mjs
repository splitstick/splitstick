import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { checkpointText, encodeNote, parseNote } from '@splitstick/core/note';
import { signNote, verifyNoteSignature } from '@splitstick/core/signer';
import { treeRoot, consistencyProof, leafHash } from '@splitstick/core/merkle';
import { StatefulWitness, WitnessRefused } from '../src/witness.mjs';

const OPERATOR = 'splitstick.example/treasury-host-1';
const WITNESS = 'audit.internal';

/** `n` distinct leaves, as a real log's would be. */
const leaves = (n) => Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`record-${i}`)));

async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'ss-witness-'));
  const wkey = await generateDevSigner(WITNESS);
  const w = new StatefulWitness({ dir, signer: wkey, now: () => new Date('2026-10-11T12:00:00Z') });
  const opkey = await generateDevSigner(OPERATOR);
  return { dir, w, wkey, opkey };
}

/**
 * A signed note for `size`, as the operator would submit it.
 * @param {import('@splitstick/core/signer').Signer} opkey
 * @param {Buffer[]} all
 * @param {number} size
 * @param {{ root?: Buffer }} [over]
 */
async function submission(opkey, all, size, over = {}) {
  const { root } = over;
  const text = checkpointText({
    origin: OPERATOR, tree_size: size, root: root ?? treeRoot(all.slice(0, size)), suite: 'SS1',
  });
  return encodeNote(text, [await signNote(text, opkey)]);
}

// ── Row 9 — enrolment is a precondition, not a formality ─────────────────────

test('row 9: a submission from an unenrolled operator is refused', async () => {
  const { w, opkey } = await fixture();
  const all = leaves(8);
  await assert.rejects(
    async () => w.addCheckpoint({ note: await submission(opkey, all, 4), old_size: 0 }),
    (/** @type {any} */ e) => e instanceof WitnessRefused && e.status === 403 && /enrol/.test(e.message),
  );
  // Without an identity the witness cannot know whose successor this is, which
  // is also why independence cannot be self-served: enrolment is a
  // relationship, however lightweight.
});

test('enrolling twice with a different key is refused; the same key is idempotent', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  w.enrol(OPERATOR, opkey.publicKey);
  const other = await generateDevSigner(OPERATOR);
  assert.throws(() => w.enrol(OPERATOR, other.publicKey), /already enrolled/);
  // Re-enrolment under a new key would silently reset sequence state, which is
  // the one thing a stateful witness exists to keep.
});

// ── Row 18 — a witness that signs anything is a signature oracle ─────────────

test('row 18: a note signed by a key the witness has not enrolled is refused', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const impostor = await generateDevSigner(OPERATOR);
  const all = leaves(8);
  await assert.rejects(
    async () => w.addCheckpoint({ note: await submission(impostor, all, 4), old_size: 0 }),
    (/** @type {any} */ e) => e instanceof WitnessRefused && e.status === 403,
  );
});

test('a note whose origin is not the enrolled identity is refused', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const elsewhere = await generateDevSigner('splitstick.example/other');
  const text = checkpointText({ origin: 'splitstick.example/other', tree_size: 4, root: treeRoot(leaves(4)), suite: 'SS1' });
  await assert.rejects(
    async () => w.addCheckpoint({ note: encodeNote(text, [await signNote(text, elsewhere)]), old_size: 0 }),
    (/** @type {any} */ e) => e instanceof WitnessRefused,
  );
});

// ── The happy path, and what it establishes ──────────────────────────────────

test('a first submission is accepted and returns the note with the witness line appended', async () => {
  const { w, wkey, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(8);
  const note = await submission(opkey, all, 4);
  const res = await w.addCheckpoint({ note, old_size: 0 });
  assert.equal(res.status, 200);
  const parsed = parseNote(res.note);
  assert.equal(parsed.text, parseNote(note).text, 'the witness must not alter the signed subject');
  assert.equal(parsed.signatures.length, 2);
  const line = parsed.signatures.find(s => s.name === WITNESS);
  assert.ok(line);
  assert.equal(await verifyNoteSignature(parsed.text, line, wkey.verifier()), true);
  assert.deepEqual(w.state(OPERATOR), {
    last_size: 4, last_root: treeRoot(all.slice(0, 4)).toString('base64'),
    received_at: '2026-10-11T12:00:00.000Z',
  });
});

// ── Row 12 — sizes legitimately jump ─────────────────────────────────────────

test('row 12: a size that jumps by more than one is accepted with a consistency proof', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(200);
  await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  // 100 -> 140 -> 200. DES-05 publishes every 10s or 1,024 records, so this is
  // the ordinary case, not an exception. An earlier draft demanded the
  // immediate successor and an external review was right that it contradicted
  // DES-05 — consistency proofs are both correct and what C2SP specifies.
  for (const [from, to] of [[100, 140], [140, 200]]) {
    const res = await w.addCheckpoint({
      note: await submission(opkey, all, to),
      old_size: from,
      consistency_proof: consistencyProof(all.slice(0, to), from).map(b => b.toString('base64')),
    });
    assert.equal(res.status, 200);
  }
  assert.equal(w.state(OPERATOR).last_size, 200);
});

// ── Rows 10, 11, 14 — regression, fork, same height different root ───────────

test('row 10: a tree_size below last_size is 400, a regression', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  await w.addCheckpoint({ note: await submission(opkey, all, 10), old_size: 0 });
  await assert.rejects(
    async () => w.addCheckpoint({ note: await submission(opkey, all, 6), old_size: 10 }),
    (/** @type {any} */ e) => e instanceof WitnessRefused && e.status === 400 && /regress/.test(e.message),
  );
  assert.equal(w.state(OPERATOR).last_size, 10, 'a refused submission must not move the state');
});

test('row 11: a proof that does not verify is 409, and says what the witness remembers', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  await w.addCheckpoint({ note: await submission(opkey, all, 10), old_size: 0 });
  // A forked history: same sizes, different leaves above 5.
  const forked = [...all.slice(0, 5), ...leaves(15).map(l => leafHash(Buffer.concat([l, Buffer.from('x')])))];
  const err = await w.addCheckpoint({
    note: await submission(opkey, forked, 20),
    old_size: 10,
    consistency_proof: consistencyProof(forked, 10).map(b => b.toString('base64')),
  }).then(() => null, e => e);
  assert.ok(err instanceof WitnessRefused);
  assert.equal(err.status, 409);
  assert.equal(err.body.last_size, 10);
  assert.equal(err.body.last_root, treeRoot(all.slice(0, 10)).toString('base64'));
  assert.equal(w.state(OPERATOR).last_size, 10);
});

test('row 11: a growing size with NO proof is refused rather than trusted', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  await w.addCheckpoint({ note: await submission(opkey, all, 10), old_size: 0 });
  await assert.rejects(
    async () => w.addCheckpoint({ note: await submission(opkey, all, 20), old_size: 10 }),
    (/** @type {any} */ e) => e instanceof WitnessRefused && e.status === 409,
  );
});

test('row 11: an old_size that is not what the witness remembers is refused', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  await w.addCheckpoint({ note: await submission(opkey, all, 10), old_size: 0 });
  const err = await w.addCheckpoint({
    note: await submission(opkey, all, 20),
    old_size: 5,
    consistency_proof: consistencyProof(all.slice(0, 20), 5).map(b => b.toString('base64')),
  }).then(() => null, e => e);
  // A proof from a size the witness never saw proves consistency with
  // something else. Accepting it would let an operator choose their own
  // starting point, which is the whole of the sequence guarantee.
  assert.ok(err instanceof WitnessRefused);
  assert.equal(err.status, 409);
});

test('row 14: the same height with a different root is a fork, refused', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  await w.addCheckpoint({ note: await submission(opkey, all, 10), old_size: 0 });
  await assert.rejects(
    async () => w.addCheckpoint({
      note: await submission(opkey, all, 10, { root: Buffer.alloc(32, 9) }), old_size: 10,
    }),
    (/** @type {any} */ e) => e instanceof WitnessRefused && e.status === 409 && /fork/.test(e.message),
  );
});

// ── Row 13 — idempotent retry ────────────────────────────────────────────────

test('row 13: resubmitting the same size and root returns the same signature', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(20);
  const note = await submission(opkey, all, 10);
  const a = await w.addCheckpoint({ note, old_size: 0 });
  const b = await w.addCheckpoint({ note, old_size: 10 });
  assert.equal(b.status, 200);
  // A retry after a dropped response must not look like an attack, and must not
  // produce a second distinct signature over the same subject.
  assert.equal(a.note, b.note);
  assert.equal(w.roots(OPERATOR).length, 1, 'and it is retained once');
});

// ── Row 15 — state updates atomically with the signature ─────────────────────

test('row 15: two concurrent submissions do not interleave', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(300);
  await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  const bump = async (to) => w.addCheckpoint({
    note: await submission(opkey, all, to),
    old_size: 100,
    consistency_proof: consistencyProof(all.slice(0, to), 100).map(b => b.toString('base64')),
  });
  const [a, b] = await Promise.allSettled([bump(200), bump(300)]);
  const ok = [a, b].filter(r => r.status === 'fulfilled');
  const failed = [a, b].filter(r => r.status === 'rejected');
  // Exactly one may win from old_size 100: the loser's proof is from a size the
  // witness no longer remembers. A witness whose state can interleave has no
  // sequence memory at all.
  assert.equal(ok.length, 1);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.status, 409);
  assert.ok([200, 300].includes(w.state(OPERATOR).last_size));
});

// ── Rows 16, 17 — tree heads and key rotation ────────────────────────────────

test('row 16: the witness publishes a signed tree head, and never an earlier one', async () => {
  const { w, wkey, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(200);
  await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  const first = await w.treeHead(OPERATOR);
  await w.addCheckpoint({
    note: await submission(opkey, all, 200), old_size: 100,
    consistency_proof: consistencyProof(all.slice(0, 200), 100).map(b => b.toString('base64')),
  });
  const second = await w.treeHead(OPERATOR);
  const size = (h) => Number(parseNote(h).text.split('\n')[1]);
  assert.equal(size(first), 100);
  assert.equal(size(second), 200);
  // The head is signed by the WITNESS's key under the witness's own origin, so
  // a third party can poll it and a rolled-back head is detected rather than
  // suspected.
  const head = parseNote(second);
  assert.match(head.text.split('\n')[0], new RegExp(WITNESS));
  assert.equal(await verifyNoteSignature(head.text, head.signatures[0], wkey.verifier()), true);
});

test('row 16: a rolled-back witness is detectable by comparing two observed heads', async () => {
  const { w, opkey, dir } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(200);
  await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  const observed = await w.treeHead(OPERATOR);
  // Roll the witness back the way a colluding witness actually would: by
  // editing BOTH its state file and its retained history. The class used to
  // offer a rollbackForTesting() method, which meant the package providing the
  // sequence guarantee also shipped the one call that undoes it.
  //
  // Rolling back state.json alone is no longer enough, and that is the crash
  // reconciliation doing its job: it would adopt the retained root at height
  // 100 and put the state straight back. A witness operator who wants to serve
  // an earlier head has to destroy the evidence as well — which is exactly why
  // FR-50's detection depends on somebody ELSE having retained the head they
  // were served.
  const { readFileSync, writeFileSync } = await import('node:fs');
  const { STATE_FILE } = await import('../src/witness.mjs');
  const statePath = join(dir, STATE_FILE);
  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  state.seq[OPERATOR] = { last_size: 0, last_root: '', received_at: '2026-10-11T12:00:00.000Z' };
  writeFileSync(statePath, JSON.stringify(state));
  writeFileSync(join(dir, 'roots.jsonl'), '');
  const now = await w.treeHead(OPERATOR);
  const { detectRollback } = await import('../src/client.mjs');
  const r = detectRollback(observed, now);
  assert.equal(r.rolledBack, true);
  assert.match(r.detail, /100/);
  assert.equal(detectRollback(observed, observed).rolledBack, false);
});

test('row 17: a countersignature from a retired witness key still verifies', async () => {
  const { w, wkey, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(200);
  const res = await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  const nextKey = await generateDevSigner(WITNESS);
  await w.rotate(nextKey);

  const old = parseNote(res.note).signatures.find(s => s.name === WITNESS);
  assert.equal(await verifyNoteSignature(parseNote(res.note).text, old, wkey.verifier()), true,
    'rotation is not an amnesty for anything signed before it');

  // And the history is signed, so a verifier can attribute both keys.
  const history = await w.keyHistory();
  const parsedHistory = parseNote(history.note);
  assert.equal(parsedHistory.signatures.length, 1);
  assert.equal(history.keys.length, 2);
  assert.equal(history.keys[0].public_key, wkey.publicKey.toString('base64'));
  assert.equal(history.keys[1].public_key, nextKey.publicKey.toString('base64'));
});

test('row 44: every root is retained, in order, and never overwritten', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(300);
  await w.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });
  for (const [from, to] of [[100, 200], [200, 300]]) {
    await w.addCheckpoint({
      note: await submission(opkey, all, to), old_size: from,
      consistency_proof: consistencyProof(all.slice(0, to), from).map(b => b.toString('base64')),
    });
  }
  const kept = w.roots(OPERATOR);
  assert.deepEqual(kept.map(r => r.tree_size), [100, 200, 300]);
  assert.equal(kept[0].root, treeRoot(all.slice(0, 100)).toString('base64'));
});

test('state survives a restart: a witness that forgets is not a witness', async () => {
  const { dir, wkey, opkey } = await fixture();
  const w1 = new StatefulWitness({ dir, signer: wkey });
  w1.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(200);
  await w1.addCheckpoint({ note: await submission(opkey, all, 100), old_size: 0 });

  const w2 = new StatefulWitness({ dir, signer: wkey });
  assert.equal(w2.state(OPERATOR).last_size, 100);
  await assert.rejects(
    async () => w2.addCheckpoint({ note: await submission(opkey, all, 50), old_size: 100 }),
    (/** @type {any} */ e) => e.status === 400,
  );
});

// ── Rows 25, 26 — egress ─────────────────────────────────────────────────────

test('rows 25-26: nothing but the note reaches the witness', async () => {
  const { w, opkey } = await fixture();
  w.enrol(OPERATOR, opkey.publicKey);
  const all = leaves(8);
  const note = await submission(opkey, all, 4);
  await w.addCheckpoint({ note, old_size: 0 });
  // Everything the witness has ever been handed, as bytes.
  const seen = JSON.stringify(w.receivedForTesting);
  for (const secret of ['transfer_funds', '2000000', 'TX-77814', 'salt', 'args', 'result']) {
    assert.ok(!seen.includes(secret), `${secret} must not reach the witness`);
  }
  // Positive control: the check is on the traffic, so it must see the traffic.
  assert.ok(seen.includes(OPERATOR));
});
