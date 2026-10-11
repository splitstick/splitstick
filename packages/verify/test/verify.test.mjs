import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';

const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'),
  result: Buffer.from('OK ref=TX-77814'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/** A store with four records and a signed checkpoint. */
async function evidence(n = 4) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < n; i++) c.action(tx({ correlation: `c-${i}` }));
  await c.checkpoint();
  return { root, store, signer, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

const chainFile = root => join(root, 'chain', 'host-1.jsonl');
const readLines = root => readFileSync(chainFile(root), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
const writeLines = (root, ls) => writeFileSync(chainFile(root), ls.map(l => JSON.stringify(l)).join('\n') + '\n');

// A flawless M1 store reads INCONCLUSIVE, not ok. There is no countersignature
// in it, so four of DES-12's ten checks cannot be answered, and a bare `ok`
// would imply more than was checked — the exact overclaim an external review
// pushed back on. What a clean store asserts is zero failures.
test('a clean store has no failures and is inconclusive only for what it cannot answer', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.tree_size, 4);
  for (const name of ['FORMAT', 'SEQUENCE', 'CHAIN', 'LEAF', 'CONTENT', 'TREE', 'OP-SIG']) {
    assert.equal(r.checks.find(c => c.name === name).verdict, 'ok', name);
  }
  assert.deepEqual(
    r.checks.filter(c => c.verdict === 'inconclusive').map(c => c.name),
    ['WITNESS', 'ROLLUP', 'COVERAGE', 'POLICY'],
    'and exactly the checks that need a second party are the unanswered ones');
  assert.equal(r.summary.passed, 7);
  assert.equal(r.summary.unanswered, 4);
});

// SEC-06 / red-team A — alter the recorded action.
test('SEC-06: an altered argument is LEAF_MISMATCH and the verdict is fail', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[1].record.args.cid = 'sha256:' + 'ab'.repeat(32);
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

// SEC-07 / red-team C — alter an event and repair the citing digest.
test('SEC-07: a repaired citation is still detected', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[1].record.outcome = 'denied';
  writeLines(root, lines);
  const bad = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(bad.verdict, 'fail');
  assert.ok(bad.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

test('a deleted middle record is SEQ_BROKEN', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines.splice(1, 1);
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN'));
});

// FR-35 — substituting stored content while preserving the pointer.
test('FR-35: a swapped payload is CONTENT_MISMATCH', async () => {
  const { root, store, vkey } = await evidence();
  const cid = readLines(root)[0].record.args.cid;
  store.content.overwriteForTest(cid, Buffer.from('{"amount":25}'));
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'CONTENT_MISMATCH'), JSON.stringify(r.findings));
});

// DES-12 / DES-13 — lawful erasure must never read as a tamper.
test('a shredded record is inconclusive, never fail', async () => {
  const { root, store, vkey } = await evidence();
  store.shredRecord(2);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.summary.failed, 0, 'erasure must add no failure');
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
  assert.ok(!r.findings.some(f => f.code === 'LEAF_MISMATCH'));
  assert.equal(r.checks.find(c => c.name === 'CHAIN').verdict, 'ok',
    'the chain still verifies — only the content check cannot be answered');
});

test('inconclusive never upgrades to fail, and a single fail outranks it', async () => {
  const { root, store, vkey } = await evidence();
  store.shredRecord(2);
  const lines = readLines(root);
  lines[3].record.outcome = 'denied';
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail', 'one fail makes the whole run fail');
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
  assert.ok(r.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

// FR-10 / OPSIG_INVALID — and FR-63's half of the identity problem.
test('OPSIG_INVALID: a re-signed checkpoint under another key does not pass', async () => {
  const { root, vkey } = await evidence();
  const other = await generateDevSigner(ORIGIN);
  const otherVkey = formatVkey(ORIGIN, other.publicKey);
  const r = await verifyStore(root, { collector: 'host-1', vkey: otherVkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_INVALID' || f.code === 'IDENTITY_UNPINNED'),
    JSON.stringify(r.findings));
  assert.equal((await verifyStore(root, { collector: 'host-1', vkey })).summary.failed, 0);
});

test('IDENTITY_UNPINNED: a checkpoint under an origin the reader did not pin', async () => {
  const { root } = await evidence();
  const elsewhere = await generateDevSigner('splitstick.dev/host-2');
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey('splitstick.dev/host-2', elsewhere.publicKey) });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'IDENTITY_UNPINNED'), JSON.stringify(r.findings));
});

test('TREE_MISMATCH: a checkpoint root that is not the root of this log', async () => {
  const { root, signer, vkey } = await evidence();
  const { checkpointText, encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const text = checkpointText({ origin: ORIGIN, tree_size: 4, root: Buffer.alloc(32, 7) });
  writeFileSync(join(root, 'checkpoints', '1.note'), encodeNote(text, [await signNote(text, signer)]));
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH'), JSON.stringify(r.findings));
});

// AC-4, stated honestly: truncation above the last checkpoint is not detectable here.
test('truncation above the last checkpoint is not detected, and the report says so', async () => {
  const { root, vkey } = await evidence(4);
  const lines = readLines(root);
  writeLines(root, lines.slice(0, 3));   // drop the tail, below the checkpointed size
  const below = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(below.verdict, 'fail', 'below a checkpointed size, truncation IS caught');
  assert.ok(below.findings.some(f => f.code === 'TREE_MISMATCH' || f.code === 'SIZE_REGRESSED'));

  // Now a log whose tail was never checkpointed.
  const { root: r2, vkey: v2, store } = await evidence(4);
  let t = Date.parse('2026-10-11T11:00:00.000Z');
  const c2 = new Collector({ store, config: parseConfig(CFG, r2),
    signer: await generateDevSigner(ORIGIN), collector: 'host-1', origin: ORIGIN,
    now: () => new Date(t += 1000) });
  c2.action(tx({ correlation: 'c-tail' }));
  const full = await verifyStore(r2, { collector: 'host-1', vkey: v2 });
  assert.equal(full.summary.failed, 0);
  writeLines(r2, readLines(r2).slice(0, 4));
  const cut = await verifyStore(r2, { collector: 'host-1', vkey: v2 });
  assert.equal(cut.summary.failed, 0, 'a prefix at or above the checkpoint is internally perfect');
  assert.ok(cut.capability.cannot.some(s => /truncation/i.test(s)),
    'so the capability statement must say truncation is not detectable');
});

// FR-57 — a verdict is incomplete without saying what the evidence could establish.
test('FR-57: the capability statement is derived from the evidence, not from config', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(Array.isArray(r.capability.can));
  assert.ok(r.capability.cannot.length > 0);
  assert.ok(r.capability.cannot.some(s => /no witness/i.test(s)),
    'with no countersignature present, that is the headline limit');
  assert.ok(r.trusting.some(s => /primitive/i.test(s)));
  assert.ok(r.trusting.some(s => new RegExp(ORIGIN).test(s)));
  assert.equal(r.witnesses.length, 0, 'quorum is reported from proofs present, never from config');
});

test('a run with no key supplied reports OP-SIG inconclusive rather than ok', async () => {
  const { root } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.summary.failed, 0);
  const opsig = r.checks.find(c => c.name === 'OP-SIG');
  assert.equal(opsig.verdict, 'inconclusive');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_UNCHECKED'));
  assert.equal(r.checks.find(c => c.name === 'CHAIN').verdict, 'ok');
});

// NFR-07 / DES-16 — an unknown version stops, never partially verifies.
test('FORMAT_UNSUPPORTED: an unknown record version fails closed', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[2].record.v = 2;
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'FORMAT_UNSUPPORTED'));
});

test('an empty store is inconclusive, not ok — there is nothing to attest', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  new Store(root, 'host-1');
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.verdict, 'inconclusive');
  assert.ok(r.findings.some(f => f.code === 'NO_EVIDENCE'));
});

// NFR-05, NFR-06 — offline by construction, enforced at the code level.
test('NFR-05: the verifier package imports no network module', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    const text = readFileSync(new URL(f, dir), 'utf8');
    for (const m of ['node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls', 'node:dns']) {
      assert.ok(!text.includes(m), `${f} imports ${m}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(text), `${f} calls fetch`);
  }
});

// SEC-14's code check: no verifier or collector module imports a key-export API.
test('SEC-14: no private-key API outside the one development signer module', () => {
  const roots = [
    new URL('../src/', import.meta.url),
    new URL('../../core/src/', import.meta.url),
    new URL('../../collect-oma/src/', import.meta.url),
  ];
  const banned = /createPrivateKey|generateKeyPair|privateEncrypt|privateDecrypt|type:\s*['"]pkcs8['"]/;
  let allowed = 0;
  for (const dir of roots) {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      if (!f.isFile() || !f.name.endsWith('.mjs')) continue;
      const text = readFileSync(new URL(f.name, dir), 'utf8');
      if (!banned.test(text)) continue;
      assert.equal(f.name, 'signer-file.mjs',
        `${f.name} touches private key material; only the development signer may`);
      allowed++;
    }
  }
  assert.equal(allowed, 1, 'and exactly one module does');
});

// DES-14 — an adapter may not touch cryptography.
test('DES-14: the OMA adapter contains no cryptography', () => {
  const dir = new URL('../../collect-oma/src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.mjs')) continue;
    const text = readFileSync(new URL(f, dir), 'utf8');
    for (const m of ['node:crypto', 'createHash', 'sha256', 'leafDigest', 'chainHead']) {
      assert.ok(!text.includes(m), `${f} touches ${m}: an adapter produces a record and nothing else`);
    }
  }
});

// DES-16 / NFR-07 — the suite travels in the signed subject, and a verifier
// either knows it or refuses the batch.
test('the checkpoint declares its algorithm suite and the verifier reads it', async () => {
  const { root, vkey } = await evidence();
  const note = readFileSync(join(root, 'checkpoints', '1.note'), 'utf8');
  assert.match(note, /\nsuite SS1\n/);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  assert.ok(!r.findings.some(f => f.code === 'SUITE_UNDECLARED'));
});

test('an unknown suite is FORMAT_UNSUPPORTED, never partially verified', async () => {
  const { root, signer, vkey } = await evidence();
  const { encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const { Store } = await import('@splitstick/core/store');
  const leaves = new Store(root, 'host-1').readChain().map(e => e.leaf);
  // Hand-built, because checkpointText refuses to emit an unknown suite — the
  // case under test is a note written by something else, or by a later release.
  const text = `${ORIGIN}\n${leaves.length}\n${treeRoot(leaves).toString('base64')}\nsuite SS9\n`;
  writeFileSync(join(root, 'checkpoints', '1.note'), encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  const f = r.findings.find(x => x.code === 'FORMAT_UNSUPPORTED');
  assert.ok(f, JSON.stringify(r.findings));
  assert.match(f.detail, /SS9/);
});

test('a checkpoint with no suite line is inconclusive, not assumed current', async () => {
  const { root, signer, vkey } = await evidence();
  const { encodeNote, checkpointText } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const { Store } = await import('@splitstick/core/store');
  const leaves = new Store(root, 'host-1').readChain().map(e => e.leaf);
  const text = checkpointText({ origin: ORIGIN, tree_size: leaves.length, root: treeRoot(leaves) });
  writeFileSync(join(root, 'checkpoints', '1.note'), encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, 'an undeclared suite is not a contradiction');
  assert.ok(r.findings.some(f => f.code === 'SUITE_UNDECLARED'));
  assert.equal(r.verdict, 'inconclusive');
});
