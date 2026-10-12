import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function withRollup({ records = 4, checkpoints = 2, rollup = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'ss-rv-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < checkpoints; i += 1) {
    for (let j = 0; j < records / checkpoints; j += 1) c.action(tx({ correlation: `c-${i}-${j}` }));
    await c.checkpoint();
  }
  const r = rollup ? await c.rollup() : null;
  store.close();
  return { root, signer, store, rollup: r, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

test('ROLLUP passes when a roll-up commits to the checkpoints on disk', async () => {
  const { root, vkey } = await withRollup();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.equal(r.checks.find(c => c.name === 'ROLLUP')?.verdict, 'ok');
  assert.ok(r.capability.can.some(s => /roll-up/i.test(s)), JSON.stringify(r.capability.can));
});

test('a store with no roll-up is inconclusive for ROLLUP, not failed', async () => {
  const { root, vkey } = await withRollup({ rollup: false });
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  assert.equal(r.checks.find(c => c.name === 'ROLLUP')?.verdict, 'inconclusive');
});

test('a roll-up that does not commit to these checkpoints FAILS', async () => {
  const { root, signer, vkey } = await withRollup();
  // Re-sign the roll-up over a tree of one note that is not in this store.
  const s2 = new Store(root, 'host-1');
  const { checkpointText } = await import('@splitstick/core/note');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const text = checkpointText({
    origin: `${ORIGIN}/rollup`, tree_size: 2,
    root: treeRoot([Buffer.from('not a note'), Buffer.from('nor this')]), suite: 'SS1',
  });
  s2.writeRollup(1, encodeNote(text, [await signNote(text, signer)]));
  s2.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH'),
    JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.checks.find(c => c.name === 'ROLLUP')?.verdict, 'fail');
});

test('a roll-up signed by somebody else FAILS', async () => {
  const { root, vkey } = await withRollup();
  const other = await generateDevSigner(ORIGIN);
  const s2 = new Store(root, 'host-1');
  const text = parseNote(String(s2.readRollups()[0].note)).text;
  s2.writeRollup(1, encodeNote(text, [await signNote(text, other)]));
  s2.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_INVALID'));
});

test('a roll-up under a different origin is reported, not silently accepted', async () => {
  const { root, signer, vkey } = await withRollup();
  const s2 = new Store(root, 'host-1');
  const { checkpointText } = await import('@splitstick/core/note');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const notes = s2.readCheckpoints().map(n => Buffer.from(n.note, 'utf8'));
  const text = checkpointText({
    origin: 'splitstick.dev/somewhere-else/rollup', tree_size: notes.length,
    root: treeRoot(notes), suite: 'SS1',
  });
  s2.writeRollup(1, encodeNote(text, [await signNote(text, signer)]));
  s2.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  // Nothing prevents an operator keeping a second log; a reader who pinned an
  // identity has to be told when they are shown another (FR-63).
  assert.ok(r.findings.some(f => f.code === 'IDENTITY_UNPINNED'),
    JSON.stringify(r.findings.map(f => f.code)));
});

test('a malformed roll-up is a finding, not a crash', async () => {
  const { root, vkey } = await withRollup();
  writeFileSync(join(root, 'rollups', 'host-1', '1.json'), '{ not json');
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(r.findings.some(f => f.code === 'FORMAT_UNSUPPORTED'));
});
