import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { parseNote, parseCheckpointText, encodeNote } from '../src/note.mjs';
import { signNote, verifyNoteSignature } from '../src/signer.mjs';
import { parseEnvelope } from '../src/envelope.mjs';
import { Anchorer } from '../src/anchor.mjs';
import { treeRoot, verifyInclusion, inclusionProof } from '../src/merkle.mjs';

const CFG = 'version: 1\nstore: ./s\nanchor_interval: 10s\nrollup_interval: 1h\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'ss-rollup-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c };
}

test('NFR-03: the default anchor interval is 10 seconds and the roll-up is an hour', async () => {
  const { root } = await fresh();
  const cfg = parseConfig('version: 1\nstore: ./s\n', root);
  // The mutability window is how long an edit can go unanchored, so the
  // default is a claim about the product and not a tuning knob's starting point.
  assert.equal(cfg.anchor_interval_ms, 10_000);
  assert.equal(cfg.rollup_interval_ms, 3_600_000);
});

test('FR-53: a roll-up commits to the checkpoints, not to the records again', async () => {
  const { store, signer, c } = await fresh();
  for (let i = 0; i < 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    await c.checkpoint();
  }
  const r = await c.rollup();
  assert.equal(r.rollup_seq, 1);
  assert.equal(r.covers, 3);

  const note = parseNote(r.note);
  const cp = parseCheckpointText(note.text);
  // A distinct origin, so a reader can never mistake a roll-up for a
  // per-batch checkpoint: they commit to different trees and a verifier that
  // conflated them would compare a tree of notes against a tree of records.
  assert.equal(cp.origin, `${ORIGIN}/rollup`);
  assert.equal(cp.tree_size, 3, 'the tree size counts checkpoints');
  assert.equal(await verifyNoteSignature(note.text, note.signatures[0], signer.verifier()), true);
  store.close();
});

test('FR-53: a reader can prove one checkpoint is in the roll-up', async () => {
  const { store, c } = await fresh();
  /** @type {string[]} */
  const notes = [];
  for (let i = 0; i < 5; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    notes.push((await c.checkpoint()).note);
  }
  const r = await c.rollup();
  const leaves = r.leaves;
  assert.equal(leaves.length, 5);
  // The roll-up is only worth anchoring if a single batch can be shown to be
  // under it — otherwise it commits to a number, not to the history.
  const proof = inclusionProof(leaves, 2);
  assert.equal(
    verifyInclusion(leaves[2], 2, 5, proof, parseCheckpointText(parseNote(r.note).text).root),
    true,
  );
  store.close();
});

test('FR-53: a roll-up over nothing is refused rather than signing an empty tree', async () => {
  const { store, c } = await fresh();
  await assert.rejects(() => c.rollup(), /no checkpoint/);
  store.close();
});

test('FR-53: a later roll-up extends the earlier one', async () => {
  const { store, c } = await fresh();
  for (let i = 0; i < 2; i += 1) { c.action(tx({ correlation: `a-${i}` })); await c.checkpoint(); }
  const first = await c.rollup();
  for (let i = 0; i < 3; i += 1) { c.action(tx({ correlation: `b-${i}` })); await c.checkpoint(); }
  const second = await c.rollup();
  assert.equal(second.rollup_seq, 2);
  assert.equal(second.covers, 5);
  // The first roll-up's tree is a prefix of the second's, so the same
  // consistency argument that protects the record log protects the roll-up.
  assert.deepEqual(second.leaves.slice(0, 2), first.leaves);
  store.close();
});

test('FR-53: the roll-up is its own envelope, anchored on the hard tier only', async () => {
  const { store, c } = await fresh();
  c.action(tx());
  await c.checkpoint();
  const r = await c.rollup();

  /** @type {string[]} */
  const seen = [];
  const hard = {
    id: 'bitcoin', proof_type: /** @type {const} */ ('opentimestamps'),
    establishes: ['existence'], tier: /** @type {const} */ ('rollup'),
    async submit(/** @type {string} */ note) {
      seen.push(note);
      return {
        type: /** @type {const} */ ('opentimestamps'), issuer: 'bitcoin',
        covers: /** @type {const} */ ('note_digest'), proof: 'AAAA',
      };
    },
  };
  const a = new Anchorer({ store, witnesses: [hard], quorum: 1 });
  const res = await a.anchorRollup(r.rollup_seq);
  assert.deepEqual(res.attached.map(x => x.issuer), ['bitcoin']);
  // A Bitcoin commitment per 10 seconds is neither affordable nor acceptable
  // use, which is the whole reason this tier exists separately (FR-22, FR-48).
  assert.equal(seen.length, 1);
  assert.equal(seen[0], r.note);
  const env = parseEnvelope(String(store.readRollupEnvelope(r.rollup_seq)));
  assert.equal(env.ok, true);
  assert.deepEqual([...env.issuers], ['bitcoin']);
  store.close();
});

test('FR-53: roll-ups are kept apart from checkpoints on disk', async () => {
  const { store, c } = await fresh();
  c.action(tx());
  await c.checkpoint();
  await c.rollup();
  // A roll-up sitting among the checkpoints would be read as a checkpoint
  // whose root is not the root of this log — a false TREE_MISMATCH, the
  // worst possible outcome for a verifier's credibility.
  assert.deepEqual(store.readCheckpoints().map(x => x.seq), [1]);
  assert.equal(store.readRollups().length, 1);
  store.close();
});
