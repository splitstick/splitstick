import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { parseEnvelope, addCountersignature } from '@splitstick/core/envelope';
import { leafDigest } from '@splitstick/core/leaf';
import { leafHash } from '@splitstick/core/merkle';
import { buildDisclosure, verifyDisclosure, DiscloseError, PACK_VERSION } from '../src/disclose.mjs';

const ORIGIN = 'splitstick.dev/host-1';

/**
 * Three actions, checkpointed. `countersign` says whether a witness signs it —
 * FR-33 makes that the difference between a pack and a refusal.
 * @param {{ countersign?: boolean, records?: number }} [o]
 */
async function rig(o = {}) {
  const { countersign = true, records = 3 } = o;
  const root = mkdtempSync(join(tmpdir(), 'ss-disc-'));
  const signer = await generateDevSigner(ORIGIN);
  const wk = await generateDevSigner('audit.example');
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  for (let i = 1; i <= records; i += 1) {
    c.action({
      run: 'r-1', tool: 'transfer_funds', consequential: true,
      args: Buffer.from(`{"amount":${i}00}`), result: Buffer.from(`OK c-${i}`),
      outcome: 'ok', attempt: 1, correlation: `c-${i}`,
    });
  }
  const cp = await c.checkpoint();
  if (countersign) await witness(store, cp.checkpoint_seq, wk, new Date(t).toISOString());
  store.close();
  return {
    root, signer, wk,
    vkey: formatVkey(ORIGIN, signer.publicKey),
    policy: {
      witnesses: [{
        id: 'audit.example', public_key: Buffer.from(wk.publicKey).toString('base64'),
      }],
    },
  };
}

/** @param {Store} store @param {number} seq @param {any} key @param {string} at */
async function witness(store, seq, key, at, issuer = 'audit.example') {
  const raw = /** @type {string} */ (store.readCheckpointEnvelope(seq));
  const text = parseNote(/** @type {string} */ (parseEnvelope(raw).note)).text;
  const line = encodeNote(text, [await signNote(text, key)]).trim().split('\n').at(-1);
  store.writeCheckpointEnvelope(seq, addCountersignature(JSON.parse(raw), {
    type: 'c2sp-note', issuer, covers: 'note', line: /** @type {string} */ (line), received_at: at,
  }));
}

/** @param {string} root @param {number} seq */
const pack = (root, seq) => {
  const s = new Store(root, 'host-1');
  try { return buildDisclosure(s, { record_seq: seq }); } finally { s.close(); }
};

// ── FR-32: one event, verified by a recipient holding nothing else ──────────

test('FR-32: a recipient verifies one event without the rest', async () => {
  const { root, vkey, policy } = await rig();
  const p = pack(root, 2);
  const r = await verifyDisclosure(p, { vkey, policy });
  assert.equal(r.verdict, 'ok', JSON.stringify(r.findings));
  assert.deepEqual(r.disclosed, [2]);
  assert.deepEqual(r.witnesses, [{ issuer: 'audit.example', accepted: true, verified: true }]);
  assert.deepEqual(r.findings, []);
});

test('NFR-05, NFR-06: verification touches no network and needs no credential', async () => {
  // Two halves, because neither alone is enough.
  //
  // BEHAVIOURAL: `fetch` is replaced with something that throws, and the
  // environment is emptied so there is no proxy, token or credential to reach
  // even if something tried. A node: module namespace cannot be patched — it is
  // read-only — so this half cannot cover `http.request`, which is why the
  // second half exists.
  //
  // STRUCTURAL: the sources verification reaches are scanned for a network API,
  // with comments and string literals stripped. That is the existing NFR-05
  // instrument in this project, and it is stripped because the scan once failed
  // on the word `fetch` inside a comment saying this verifier does not fetch.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 1);

  const realFetch = globalThis.fetch;
  /** @type {any} */ (globalThis).fetch = () => {
    throw new Error('verification reached the network');
  };
  const savedEnv = { ...process.env };
  for (const k of Object.keys(process.env)) delete process.env[k];
  try {
    const r = await verifyDisclosure(p, { vkey, policy });
    assert.equal(r.verdict, 'ok', JSON.stringify(r.findings));
  } finally {
    globalThis.fetch = realFetch;
    Object.assign(process.env, savedEnv);
  }

  const { readFileSync } = await import('node:fs');
  const { codeOnly } = await import('../../../tools/code-text.mjs');
  for (const rel of ['src/disclose.mjs', 'src/verify.mjs']) {
    const src = codeOnly(readFileSync(new URL(`../${rel}`, import.meta.url).pathname, 'utf8'));
    for (const api of [/\bfetch\s*\(/, /node:https?/, /node:net/, /node:dns/, /XMLHttpRequest/]) {
      assert.ok(!api.test(src), `${rel} reaches for ${api} — verification must be offline`);
    }
  }
});

// ── FR-33: a countersigned root, not a bare local digest ───────────────────

test('FR-33: a pack is REFUSED when the root is unwitnessed', async () => {
  // The whole difference between a proof and a claim. An inclusion proof
  // against a bare local digest establishes only that the operator is
  // consistent with their own arithmetic — and it is refused at build rather
  // than handed over with a caveat, because a caveat is something a recipient
  // has to notice.
  const { root } = await rig({ countersign: false });
  assert.throws(() => pack(root, 2), DiscloseError);
  try {
    pack(root, 2);
    assert.fail('expected a refusal');
  } catch (e) {
    assert.match(String(/** @type {Error} */ (e).message), /none is countersigned/);
    assert.match(String(/** @type {Error} */ (e).message), /FR-33/);
  }
});

test('FR-33: a pack whose proof reaches a root the checkpoint does not commit to fails', async () => {
  // Checking the proof against the pack's OWN root and stopping there would let
  // an operator prove inclusion in a tree nobody countersigned — FR-33 defeated
  // by arithmetic rather than by forgery.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 2);
  const forged = { ...p, proof: { ...p.proof, root: 'ff'.repeat(32) } };
  const r = await verifyDisclosure(forged, { vkey, policy });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH'));
});

test('FR-33: a countersignature from an issuer the recipient does not accept is unverified', async () => {
  // Present, reported, counted for nothing. Presence is not proof — a lesson
  // this project has paid for twice, in the practice-statement command and
  // again in the coverage report.
  const { root, vkey } = await rig();
  const p = pack(root, 2);
  const r = await verifyDisclosure(p, { vkey, policy: { witnesses: [] } });
  assert.equal(r.verdict, 'inconclusive', JSON.stringify(r.findings));
  assert.deepEqual(r.witnesses, [{ issuer: 'audit.example', accepted: false, verified: false }]);
  assert.ok(r.findings.some(f => f.code === 'WITNESS_MISSING' && f.verdict === 'inconclusive'));
  assert.ok(!r.findings.some(f => f.verdict === 'fail'), 'unaccepted is not the same as invalid');
});

test('FR-33: a countersignature that does not verify is a failure, not a shrug', async () => {
  const { root, vkey } = await rig();
  const impostor = await generateDevSigner('audit.example');
  const p = pack(root, 2);
  // The recipient accepts the issuer name but holds a different key for it.
  const r = await verifyDisclosure(p, {
    vkey,
    policy: {
      witnesses: [{
        id: 'audit.example', public_key: Buffer.from(impostor.publicKey).toString('base64'),
      }],
    },
  });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'WITNESS_MISMATCH' && f.verdict === 'fail'));
});

// ── PRIV-06: disclosure minimisation ───────────────────────────────────────

test('PRIV-06: the pack carries exactly one salt — the disclosed record\'s', async () => {
  // A second salt makes a second record's content recomputable by anybody who
  // can guess at it. You cannot un-disclose, so this is checked at BUILD time:
  // a check on the recipient's side would run after the damage.
  const { root } = await rig({ records: 5 });
  for (const seq of [1, 3, 5]) {
    const p = pack(root, seq);
    assert.deepEqual(Object.keys(p.salts), [String(seq)],
      `disclosing ${seq} must carry one salt and no other`);
  }
});

test('PRIV-06: no sibling leaf is reproducible from the pack, and the path is node digests', async () => {
  // The honest statement of what a Merkle proof does and does not reveal.
  //
  // The audit path necessarily contains the HASH of a sibling leaf — that is
  // how an inclusion proof works, and claiming otherwise would be an
  // overclaim. What it does not contain is the sibling's leaf DIGEST, which is
  // the salted commitment to that record, so the sibling's content cannot be
  // reproduced or confirmed: a recipient would need the sibling's salt, which
  // is not in the pack and is the one thing PRIV-06 is about.
  const { root } = await rig({ records: 5 });
  const s = new Store(root, 'host-1');
  const chain = s.readChain();
  s.close();
  const p = pack(root, 2);
  const blob = JSON.stringify(p);

  for (const [i, e] of chain.entries()) {
    const seq = Number(e.record.record_seq);
    if (seq === 2) continue;
    // Neither the sibling's leaf digest nor its salt is anywhere in the pack.
    assert.ok(!blob.includes(Buffer.from(e.leaf).toString('base64')),
      `record ${seq}'s leaf digest is in the pack`);
    assert.ok(!blob.includes(Buffer.from(e.leaf).toString('hex')), `record ${seq}'s leaf in hex`);
    assert.ok(!blob.includes(Buffer.from(/** @type {Buffer} */ (e.salt)).toString('hex')),
      `record ${seq}'s salt is in the pack`);
    // And without the salt, the leaf cannot be recomputed even by somebody who
    // guesses the record exactly — which is what the salt is for.
    const guessed = leafDigest(Buffer.alloc(16), e.record);
    assert.ok(!Buffer.from(guessed).equals(Buffer.from(e.leaf)), 'the salt is load-bearing');
    assert.ok(i >= 0);
  }

  // The path IS sibling leaf hashes and interior node hashes, which is stated
  // rather than denied. A hash of a salted digest reveals neither.
  const path = p.proof.path.map((/** @type {string} */ x) => Buffer.from(x, 'base64'));
  const siblingHash = leafHash(/** @type {Buffer} */ (chain[0]?.leaf));
  assert.ok(path.some((/** @type {Buffer} */ n) => n.equals(siblingHash)),
    'the audit path contains a sibling leaf HASH: that is how a Merkle proof works');
  assert.ok(!path.some((/** @type {Buffer} */ n) => n.equals(/** @type {any} */ (chain[0]?.leaf))),
    'and never a sibling leaf digest, which is the salted commitment itself');
});

test('PRIV-06: only the disclosed record\'s own payloads are carried', async () => {
  const { root } = await rig({ records: 3 });
  const p = pack(root, 2);
  assert.deepEqual(Object.keys(p.content).sort(), ['args', 'result']);
  const blob = JSON.stringify(p);
  assert.ok(blob.includes(Buffer.from('{"amount":200}').toString('base64')), 'its own args');
  for (const other of ['{"amount":100}', '{"amount":300}', 'OK c-1', 'OK c-3']) {
    assert.ok(!blob.includes(Buffer.from(other).toString('base64')),
      `a sibling's payload (${other}) is in the pack`);
  }
});

// ── DES-11's honest flag, and the edges ────────────────────────────────────

test('DES-11: a selective disclosure can never claim completeness', async () => {
  // `complete: false` is set by construction — there is no argument that makes
  // it true — because a recipient must be able to tell a deliberate omission
  // from a missing piece.
  const { root } = await rig({ records: 4 });
  for (const seq of [1, 2, 3, 4]) {
    const p = pack(root, seq);
    assert.equal(p.manifest.covers.complete, false);
    assert.deepEqual(p.manifest.covers, { from_seq: seq, to_seq: seq, complete: false });
    assert.match(p.manifest.note, /not included by design/);
  }
});

test('a record that does not exist is refused, with the range the store holds', async () => {
  const { root } = await rig({ records: 3 });
  for (const seq of [0, -1, 4, 99, 1.5]) {
    assert.throws(() => pack(root, seq), DiscloseError, `seq ${seq}`);
  }
  try {
    pack(root, 9);
    assert.fail('expected a refusal');
  } catch (e) {
    assert.match(String(/** @type {Error} */ (e).message), /it holds 1\.\.3/);
    assert.match(String(/** @type {Error} */ (e).message), /a disclosure of nothing/);
  }
});

test('a SHREDDED record is still disclosable: its inclusion is provable, its content is not', async () => {
  // Erasure must not become a way to make history unprovable. An operator who
  // honoured a deletion request must still be able to prove that the action
  // happened, and the recipient must be told the content is gone rather than
  // left to wonder why it is missing.
  const { root, vkey, policy } = await rig({ records: 3 });
  let s = new Store(root, 'host-1');
  s.shredRecord(2);
  s.close();

  const p = pack(root, 2);
  assert.deepEqual(Object.keys(p.salts), [], 'no salt: it was shredded with the content');
  assert.equal(p.content.args.present, false);
  assert.equal(p.content.result.present, false);
  assert.ok(p.content.args.cid, 'the commitment is still carried');

  // The committed leaf is carried, so inclusion stays PROVABLE. This test
  // asserted only that LEAF_INCONCLUSIVE appeared, which it did — while the
  // pack carried no leaf at all and the proof was never checked. It encoded
  // half the requirement and passed.
  assert.match(p.proof.leaf, /^[0-9a-f]{64}$/, 'the committed leaf digest is carried');

  const r = await verifyDisclosure(p, { vkey, policy });
  // Inconclusive, never fail: erasure is lawful, and reporting it as tampering
  // would make compliance look like an attack.
  assert.equal(r.verdict, 'inconclusive');
  assert.ok(!r.findings.some(f => f.verdict === 'fail'), JSON.stringify(r.findings));
  assert.ok(r.findings.some(f => f.code === 'CONTENT_ABSENT'));
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
  // And the path DID verify: no TREE_MISMATCH. The precise limit is that the
  // leaf cannot be bound to the record shown, not that inclusion failed.
  assert.ok(!r.findings.some(f => f.code === 'TREE_MISMATCH'),
    'inclusion of the committed leaf is still provable after erasure');
  const limit = r.findings.find(f => f.code === 'LEAF_INCONCLUSIVE');
  assert.match(String(limit?.detail), /still\s+provable/);
  assert.match(String(limit?.detail), /binding needs the salt/);

  // A forged leaf is still caught: carrying the leaf is not carrying a licence.
  const forged = await verifyDisclosure(
    { ...p, proof: { ...p.proof, leaf: 'ab'.repeat(32) } }, { vkey, policy });
  assert.equal(forged.verdict, 'fail');
  assert.ok(forged.findings.some(f => f.code === 'TREE_MISMATCH'));

  // And an unshredded sibling is still fully disclosable.
  const other = await verifyDisclosure(pack(root, 1), { vkey, policy });
  assert.equal(other.verdict, 'ok', JSON.stringify(other.findings));
});

test('a later witnessed checkpoint is used when an earlier one is unwitnessed', async () => {
  // The same first-match mistake that discarded real evidence in M4's coverage
  // report: an unwitnessed checkpoint must not mask a witnessed later one whose
  // committed tree reaches the same record.
  const root = mkdtempSync(join(tmpdir(), 'ss-disc-later-'));
  const signer = await generateDevSigner(ORIGIN);
  const wk = await generateDevSigner('audit.example');
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  c.action({
    run: 'r-1', tool: 't', consequential: true, args: Buffer.from('a'),
    result: Buffer.from('b'), outcome: 'ok', attempt: 1, correlation: 'c-1',
  });
  await c.checkpoint();                       // checkpoint 1, unwitnessed
  c.action({
    run: 'r-1', tool: 't', consequential: true, args: Buffer.from('c'),
    result: Buffer.from('d'), outcome: 'ok', attempt: 1, correlation: 'c-2',
  });
  const cp2 = await c.checkpoint();           // checkpoint 2, witnessed
  await witness(store, cp2.checkpoint_seq, wk, new Date(t).toISOString());
  store.close();

  const p = pack(root, 1);
  assert.equal(p.proof.checkpoint_seq, 2, 'the witnessed checkpoint is the one used');
  assert.equal(p.proof.tree_size, 2);
  const r = await verifyDisclosure(p, {
    vkey: formatVkey(ORIGIN, signer.publicKey),
    policy: {
      witnesses: [{ id: 'audit.example', public_key: Buffer.from(wk.publicKey).toString('base64') }],
    },
  });
  assert.equal(r.verdict, 'ok', JSON.stringify(r.findings));
});

test('an unpinned operator identity is inconclusive, and a wrong one fails', async () => {
  const { root, policy } = await rig();
  const p = pack(root, 1);

  const unpinned = await verifyDisclosure(p, { policy });
  assert.equal(unpinned.verdict, 'inconclusive');
  assert.ok(unpinned.findings.some(f => f.code === 'OPSIG_UNCHECKED'));

  const other = await generateDevSigner('splitstick.dev/someone-else');
  const wrong = await verifyDisclosure(p, {
    vkey: formatVkey('splitstick.dev/someone-else', other.publicKey), policy,
  });
  assert.equal(wrong.verdict, 'fail');
  assert.ok(wrong.findings.some(f => f.code === 'IDENTITY_UNPINNED'));
});

test('DES-16: a pack version this verifier does not implement is refused, not partly checked', async () => {
  const { root, vkey, policy } = await rig();
  const p = pack(root, 1);
  for (const version of [PACK_VERSION + 1, 0, 'one', undefined]) {
    const r = await verifyDisclosure({ ...p, manifest: { ...p.manifest, version } },
      { vkey, policy });
    assert.equal(r.verdict, 'fail', `version ${JSON.stringify(version)}`);
    assert.deepEqual(r.findings.map(f => f.code), ['FORMAT_UNSUPPORTED']);
  }
});

test('FR-31: every countersignature is carried, never only a preferred one', async () => {
  // Filtering to one witness would quietly force the recipient to trust whoever
  // we chose, which is what makes DES-09's separate acceptance policy
  // meaningful.
  const { root, wk, vkey } = await rig();
  const second = await generateDevSigner('other-notary.example');
  let s = new Store(root, 'host-1');
  await witness(s, 1, second, '2026-10-12T10:00:10.000Z', 'other-notary.example');
  s.close();

  const p = pack(root, 2);
  assert.equal(p.checkpoint.countersignatures.length, 2);
  // A recipient who accepts only the second one still verifies the same pack,
  // without asking the operator to regenerate anything.
  const r = await verifyDisclosure(p, {
    vkey,
    policy: {
      witnesses: [{
        id: 'other-notary.example', public_key: Buffer.from(second.publicKey).toString('base64'),
      }],
    },
  });
  assert.ok(r.witnesses.some(w => w.issuer === 'other-notary.example' && w.verified));
  assert.ok(r.witnesses.some(w => w.issuer === 'audit.example' && !w.accepted));
  assert.ok(!r.findings.some(f => f.verdict === 'fail'), JSON.stringify(r.findings));
  assert.ok(wk !== undefined);
});

test('a tampered record in the pack fails the inclusion proof', async () => {
  // The recipient recomputes the leaf from the record and the salt rather than
  // taking the operator's word for which leaf this is.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 2);
  const tampered = {
    ...p,
    record: { ...p.record, args: { ...p.record.args, bytes: p.record.args.bytes + 1 } },
  };
  const r = await verifyDisclosure(tampered, { vkey, policy });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH'));
});

// ── The independent review of M5. Four findings, each reproduced first ──────

test('M5 review 1: a substituted payload is CAUGHT, not accepted', async () => {
  // The worst finding in M5. The pack carried the payload bytes and the cid
  // but not the CONTENT SALT, and a content cid is
  // SHA-256(0x05 ‖ salt ‖ plaintext) — so the commitment could not be
  // recomputed and the payload was taken on the operator's word, on the one
  // surface built for an adversarial operator.
  //
  // Worse, verifyDisclosure had a block that LOOKED like a content check: it
  // computed an unsalted digest and compared it to the salted cid, which can
  // never be equal. Substituting `{"amount":200}` with `{"amount":999999999}`
  // produced a verdict of ok with no findings at all.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 2);

  assert.match(p.content.args.salt, /^[0-9a-f]{32}$/, 'the content salt is carried');
  const clean = await verifyDisclosure(p, { vkey, policy });
  assert.equal(clean.verdict, 'ok', JSON.stringify(clean.findings));

  const swapped = {
    ...p,
    content: {
      ...p.content,
      args: {
        ...p.content.args,
        base64: Buffer.from('{"amount":999999999}').toString('base64'),
      },
    },
  };
  const r = await verifyDisclosure(swapped, { vkey, policy });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'CONTENT_MISMATCH' && f.verdict === 'fail'),
    `expected CONTENT_MISMATCH, got ${JSON.stringify(r.findings.map(f => f.code))}`);

  // A substituted SALT is caught too — otherwise an operator could choose a
  // salt that makes any bytes hash to the cid, which is not possible, but a
  // verifier that trusted the salt without recomputing would not know that.
  const resalted = {
    ...p, content: { ...p.content, args: { ...p.content.args, salt: 'ab'.repeat(16) } },
  };
  const r2 = await verifyDisclosure(resalted, { vkey, policy });
  assert.equal(r2.verdict, 'fail');
  assert.ok(r2.findings.some(f => f.code === 'CONTENT_MISMATCH'));

  // And a pack that simply omits the salt cannot claim the payload verified.
  const { salt, ...noSalt } = p.content.args;
  const r3 = await verifyDisclosure({ ...p, content: { ...p.content, args: noSalt } },
    { vkey, policy });
  assert.notEqual(r3.verdict, 'ok');
  assert.ok(r3.findings.some(f => /cannot be verified against its commitment/.test(f.detail)));
});

test('M5 review 2: only the disclosed record\'s content salts are carried', async () => {
  // Adding the salt closed one hole and could have opened a worse one. A
  // sibling's content salt in the pack would let a recipient confirm a guess
  // at a payload that was never disclosed, which is the whole of PRIV-06.
  const { root } = await rig({ records: 5 });
  const s = new Store(root, 'host-1');
  const chain = s.readChain();
  const siblingSalts = chain
    .filter(e => Number(e.record.record_seq) !== 2)
    .flatMap(e => ['args', 'result']
      .map(f => /** @type {any} */ (e.record)[f]?.cid)
      .filter(Boolean)
      .map(cid => s.content.contentSalt(cid).toString('hex')));
  s.close();
  assert.ok(siblingSalts.length >= 8, 'there are siblings to leak');

  const blob = JSON.stringify(pack(root, 2));
  for (const hex of siblingSalts) {
    assert.ok(!blob.includes(hex), 'a sibling content salt is in the pack');
  }
});

test('M5 review 3: a manifest naming a record the pack does not hold is refused', async () => {
  // The salts map is keyed by record_seq, so a manifest naming another record
  // simply found no salt — and the verifier reported `disclosed: [3]` with a
  // verdict of inconclusive while the pack held record 1. A reader is told, in
  // the report's own words, that they are looking at a record they are not.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 1);

  const lying = {
    ...p,
    manifest: { ...p.manifest, disclosed: [3], covers: { from_seq: 3, to_seq: 3, complete: false } },
  };
  const r = await verifyDisclosure(lying, { vkey, policy });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => /the record carried is 1/.test(f.detail)),
    JSON.stringify(r.findings.map(f => f.detail)));

  // And `covers` must name the same record as `disclosed`.
  const inconsistent = {
    ...p, manifest: { ...p.manifest, covers: { from_seq: 1, to_seq: 9, complete: false } },
  };
  const r2 = await verifyDisclosure(inconsistent, { vkey, policy });
  assert.equal(r2.verdict, 'fail');
  assert.ok(r2.findings.some(f => /states the same record in both/.test(f.detail)));
});

test('M5 review 4: content flagged absent while carrying bytes is a contradiction', async () => {
  // Accepting it meant the bytes were silently ignored, so a pack could hand
  // over a payload nothing would ever check — the reverse of finding 1 and
  // reachable even after it was fixed.
  const { root, vkey, policy } = await rig();
  const p = pack(root, 1);
  const sneaky = {
    ...p,
    content: {
      ...p.content,
      args: { cid: p.content.args.cid, present: false, base64: p.content.args.base64 },
    },
  };
  const r = await verifyDisclosure(sneaky, { vkey, policy });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => /cannot both be true/.test(f.detail)));
});
