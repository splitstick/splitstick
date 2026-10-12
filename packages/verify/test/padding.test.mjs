import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig, ConfigError } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '../src/verify.mjs';

const ORIGIN = 'splitstick.dev/host-1';
const tx = (/** @type {string} */ c) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('a'),
  result: Buffer.from('b'), outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: c,
});

/** @param {string} [pad] a `padding:` block, or nothing */
async function rig(pad = '', root = mkdtempSync(join(tmpdir(), 'ss-pad-'))) {
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig(`version: 1\nstore: ./s\n${pad}`, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  return { root, store, c, signer, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

const chainPath = (/** @type {string} */ root) => join(root, 'chain', 'host-1.jsonl');
const lines = (/** @type {string} */ root) =>
  readFileSync(chainPath(root), 'utf8').trim().split('\n').map(l => JSON.parse(l));
const write = (/** @type {string} */ root, /** @type {any[]} */ ls) =>
  writeFileSync(chainPath(root), `${ls.map(l => JSON.stringify(l)).join('\n')}\n`);

// ── FR-34, FR-69 ────────────────────────────────────────────────────────────

test('FR-69: padding records keep record_seq equal to tree_size', async () => {
  // Dummy leaves WITHOUT records would break the equality, which a review
  // caught in design: two real records plus three dummy leaves would have
  // given tree size 5 against record_seq 2.
  const { root, store, c } = await rig('padding:\n  to_multiple: 8\n');
  c.action(tx('c-1'));
  c.action(tx('c-2'));
  const cp = await c.checkpoint();
  assert.equal(cp.tree_size, 8, 'rounded up to the configured multiple');
  assert.equal(c.recordSeq, cp.tree_size, 'FR-69: record_seq == tree_size, still');
  const kinds = store.readChain().map(e => e.record.kind);
  assert.deepEqual(kinds, ['tool_call', 'tool_call', ...Array(6).fill('padding')]);
  store.close();
});

test('FR-34 rule 1: no two padding records share a leaf', async () => {
  // Identical padding leaves would be a recognisable pattern, and therefore no
  // padding at all — an observer could subtract them.
  const { root, store, c } = await rig('padding:\n  to_multiple: 16\n');
  c.action(tx('c-1'));
  await c.checkpoint();
  const pads = store.readChain().filter(e => e.record.kind === 'padding');
  assert.equal(pads.length, 15);
  assert.equal(new Set(pads.map(e => e.record.pad)).size, 15, 'distinct nonces');
  assert.equal(new Set(pads.map(e => e.leaf.toString('hex'))).size, 15, 'distinct leaves');
  store.close();
});

test('FR-34 rule 2: padding is applied at batch close and cannot be added later', async () => {
  // The structure enforces it rather than a check. Padding records go through
  // the ordinary write path BEFORE the root is computed, so they are part of
  // the tree the checkpoint signs and can never be part of one already signed.
  // There is no code path that adds a leaf to a closed batch, because a closed
  // batch is a signed note and leaves are not stored in it.
  //
  // What an operator CAN do is append to the file afterwards, so that is what
  // is tested: it does not reshape the signed tree, it breaks it.
  const { root, store, c, vkey } = await rig('padding:\n  to_multiple: 4\n');
  c.action(tx('c-1'));
  const cp = await c.checkpoint();
  assert.equal(cp.tree_size, 4);
  store.close();

  const clean = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(clean.summary.failed, 0, 'the padded log verifies');

  // Retroactive padding: copy a padding line and re-append it, so the tree the
  // checkpoint signed is no longer the tree on disk.
  const ls = lines(root);
  const pad = ls.find((/** @type {any} */ l) => l.record.kind === 'padding');
  write(root, [...ls, { ...pad, record: { ...pad.record, record_seq: ls.length + 1 } }]);
  const after = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(after.summary.failed > 0, 'a leaf added after the fact is caught, not absorbed');
  assert.ok(
    after.findings.some(f => f.verdict === 'fail'),
    `expected a failing finding, got ${JSON.stringify(after.findings.map(f => f.code))}`,
  );
});

test('FR-34 rule 4: a real action relabelled as padding fails the leaf check', async () => {
  // Its leaf is already committed over the real record's bytes. A
  // reclassification changes the bytes and so changes the leaf.
  const { root, store, c, vkey } = await rig('padding:\n  to_multiple: 4\n');
  c.action(tx('c-1'));
  c.action(tx('c-2'));
  await c.checkpoint();
  store.close();

  const ls = lines(root);
  const i = ls.findIndex((/** @type {any} */ l) => l.record.kind === 'tool_call');
  // Every action-only field removed, so what is left is schema-valid padding:
  // a leftover `approval` was refused as FORMAT_UNSUPPORTED, which is a finding
  // about a malformed record rather than an altered one, and the test would
  // have passed while proving something weaker than rule 4 claims.
  const { tool, consequential, args, result, outcome, attempt, correlation, approval, agent,
    ...keep } = ls[i].record;
  // WELL-FORMED padding, including `source_seq: null`, which the kind requires.
  // Leaving the action's source_seq in place tripped FORMAT_UNSUPPORTED — a
  // finding about a malformed record rather than about an altered one, so the
  // test passed while proving something weaker than rule 4 claims.
  ls[i] = {
    ...ls[i],
    record: { ...keep, source_seq: null, kind: 'padding', pad: 'a'.repeat(32) },
  };
  write(root, ls);

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(r.summary.failed > 0);
  assert.ok(r.findings.some(f => f.code === 'LEAF_MISMATCH'),
    `expected LEAF_MISMATCH, got ${JSON.stringify(r.findings)}`);
});

test('FR-34 rule 3: a verifier counts real and padding records separately', async () => {
  // Indistinguishable padding would make a disclosed tree size meaningless,
  // which is the whole reason padding is a typed record kind.
  const { root, store, c, vkey } = await rig('padding:\n  to_multiple: 8\n');
  c.heartbeat();
  c.action(tx('c-1'));
  await c.checkpoint();
  store.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.records.tree_size, 8);
  assert.equal(r.records.padding, 6);
  assert.equal(r.records.real, 2);
  assert.deepEqual(r.records.by_kind, { heartbeat: 1, tool_call: 1, padding: 6 });
});

test('PRIV-07: tree size exceeds the action count whenever a run holds heartbeats', async () => {
  // The tree-size leak is a count of ALL records. Describing it as an action
  // count would overstate it, and this is the test that keeps the description
  // honest — asserted with padding OFF, so it is not padding doing the work.
  const { root, store, c, vkey } = await rig();
  for (let i = 0; i < 5; i += 1) c.heartbeat();
  c.action(tx('c-1'));
  c.gap({ from_source_seq: 1, to_source_seq: 2, reason: 'queue_lost_on_disk_full' });
  await c.checkpoint();
  store.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  const actions = r.records.by_kind.tool_call ?? 0;
  assert.equal(actions, 1);
  assert.ok(r.records.tree_size > actions,
    `tree_size ${r.records.tree_size} must exceed the action count ${actions}`);
  assert.equal(r.records.padding, 0, 'and with no padding configured, none is added');
  assert.equal(r.records.real, r.records.tree_size);
});

// ── the configuration itself ────────────────────────────────────────────────

test('FR-34: padding is off by default, and a misconfigured block is refused', async () => {
  const { root, store, c, vkey } = await rig();
  c.action(tx('c-1'));
  const cp = await c.checkpoint();
  assert.equal(cp.tree_size, 1, 'off by default: it inflates every proof');
  store.close();
  assert.equal((await verifyStore(root, { collector: 'host-1', vkey })).records.padding, 0);

  // The key was in the known-key list and never parsed, so `padding:` in a
  // config was accepted and silently ignored — an operator could believe their
  // volume was obscured while nothing padded anything. Same defect as the
  // verifier's `--vkey`, accepted and ignored because the flag is `--key`.
  const dir = mkdtempSync(join(tmpdir(), 'ss-pad-cfg-'));
  const cfg = (/** @type {string} */ body) => parseConfig(`version: 1\nstore: ./s\n${body}`, dir);
  assert.equal(cfg('').padding, null);
  assert.deepEqual(cfg('padding:\n  to_multiple: 16\n').padding, { to_multiple: 16 });
  for (const bad of [
    'padding: 16\n',
    'padding: true\n',
    'padding:\n  to_multiple: 1\n',
    'padding:\n  to_multiple: 0\n',
    'padding:\n  to_multiple: 2.5\n',
    'padding:\n  to_multiple: "8"\n',
    'padding:\n  multiple: 8\n',
  ]) {
    assert.throws(() => cfg(bad), ConfigError, bad);
  }
});

test('a log that is already on the boundary gets no padding block', async () => {
  // Appending a full block at the boundary would make the quantisation visible
  // as a step, which is the pattern it exists to hide.
  const { root, store, c } = await rig('padding:\n  to_multiple: 2\n');
  c.action(tx('c-1'));
  c.action(tx('c-2'));
  const cp = await c.checkpoint();
  assert.equal(cp.tree_size, 2, 'already a multiple of two');
  assert.equal(store.readChain().filter(e => e.record.kind === 'padding').length, 0);
  store.close();
});

test('a padded log verifies end to end, mixed with every other kind', async () => {
  // FR-69's own acceptance: a mixed real-and-padding log verifies. A suite
  // that only asserted refusals would leave the happy path untested, which is
  // how `endorse()` shipped with a dead indirection on its success path.
  const { root, store, c, vkey } = await rig('padding:\n  to_multiple: 8\n');
  c.heartbeat();
  c.action(tx('c-1'));
  c.action(tx('c-2'));
  // The span must MEET the sequence: two actions have consumed 1 and 2, so a
  // declaration begins at 3. M3b's accounting refuses anything else.
  c.gap({ from_source_seq: 3, to_source_seq: 4, reason: 'queue_lost_on_disk_full' });
  const cp = await c.checkpoint();
  store.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings));
  assert.equal(cp.tree_size, 8);
  assert.equal(r.records.real, 4);
  assert.equal(r.records.padding, 4);
});
