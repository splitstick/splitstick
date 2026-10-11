import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { Anchorer } from '@splitstick/core/anchor';
import { StatefulWitness } from '../src/witness.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/** A collector and a real stateful witness wired together through an Anchorer. */
async function wired() {
  const root = mkdtempSync(join(tmpdir(), 'ss-seq-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });

  const wdir = mkdtempSync(join(tmpdir(), 'ss-seq-w-'));
  const wkey = await generateDevSigner('audit.internal');
  const witness = new StatefulWitness({ dir: wdir, signer: wkey });
  witness.enrol(ORIGIN, signer.publicKey);

  /** @type {{ old_size: number, proof_length: number }[]} */
  const submissions = [];
  const adapter = {
    id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit(/** @type {string} */ note, /** @type {any} */ ctx) {
      submissions.push({ old_size: ctx.old_size, proof_length: ctx.consistency_proof.length });
      const res = await witness.addCheckpoint({
        note, old_size: ctx.old_size, consistency_proof: ctx.consistency_proof,
      });
      const text = parseNote(res.note).text;
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.internal',
        covers: /** @type {const} */ ('note'),
        line: res.note.trimEnd().split('\n').at(-1),
      };
    },
  };
  const anchorer = new Anchorer({
    store, witnesses: [adapter], quorum: 1, acceptance: { 'audit.internal': wkey.publicKey },
  });
  return { root, store, c, anchorer, witness, submissions, signer };
}

test('successive checkpoints anchor to a real stateful witness', async () => {
  // The gap this test exists for: the Anchorer never computed a consistency
  // proof, so a stateful witness refused everything after the first
  // submission. Nothing caught it because the harness only ever anchored one
  // checkpoint — a seam exercised once looks like a seam that works.
  const { store, c, anchorer, witness, submissions } = await wired();
  /** @type {number[]} */
  const sizes = [];
  for (let batch = 0; batch < 4; batch += 1) {
    for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `c-${batch}-${i}` }));
    const cp = await c.checkpoint();
    const r = await anchorer.anchor(cp.checkpoint_seq);
    assert.deepEqual(r.failed, [], `batch ${batch}: ${JSON.stringify(r.failed)}`);
    assert.equal(r.attached.length, 1, `batch ${batch} did not anchor`);
    assert.equal(r.attached[0].verified, true);
    sizes.push(cp.tree_size);
  }
  assert.deepEqual(sizes, [3, 6, 9, 12]);
  assert.equal(witness.state(ORIGIN).last_size, 12);
  // Sizes jump by three, which is the ordinary case (DES-05 publishes on an
  // interval or a count, never per record), and each submission after the
  // first carried a proof from the height the witness remembered.
  assert.deepEqual(submissions.map(s => s.old_size), [0, 3, 6, 9]);
  assert.ok(submissions.slice(1).every(s => s.proof_length > 0),
    JSON.stringify(submissions));
  assert.deepEqual(witness.roots(ORIGIN).map(r => r.tree_size), [3, 6, 9, 12]);
  store.close();
});

test('the proof is over the log the checkpoint commits to, not the log as it is now', async () => {
  // A proof computed over the CURRENT leaves would be a proof about a tree the
  // checkpoint being submitted does not describe — and it would verify, which
  // is what makes this subtle. The witness would then hold a root for a height
  // that never existed as a checkpoint.
  const { store, c, anchorer, witness } = await wired();
  for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `a-${i}` }));
  const first = await c.checkpoint();
  await anchorer.anchor(first.checkpoint_seq);

  for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `b-${i}` }));
  const second = await c.checkpoint();
  // More records land BEFORE the anchoring call, so "now" is 9 while the
  // checkpoint being anchored commits to 6.
  for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `c-${i}` }));
  const r = await anchorer.anchor(second.checkpoint_seq);
  assert.deepEqual(r.failed, [], JSON.stringify(r.failed));
  assert.equal(witness.state(ORIGIN).last_size, 6, 'the witness holds the checkpointed height');
  store.close();
});

test('a queued checkpoint still anchors with the right proof after a flush', async () => {
  const { store, c, anchorer, witness } = await wired();
  for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `a-${i}` }));
  const first = await c.checkpoint();
  await anchorer.anchor(first.checkpoint_seq);

  // The witness goes away for one checkpoint, then comes back.
  const down = anchorer.witnesses[0];
  const original = down.submit;
  down.submit = async () => { throw new Error('ECONNREFUSED'); };
  for (let i = 0; i < 3; i += 1) c.action(tx({ correlation: `b-${i}` }));
  const second = await c.checkpoint();
  await anchorer.anchor(second.checkpoint_seq);
  assert.deepEqual(anchorer.queued(), [second.checkpoint_seq]);

  down.submit = original;
  const flushed = await anchorer.flush();
  assert.deepEqual(flushed.anchored, [second.checkpoint_seq]);
  assert.equal(witness.state(ORIGIN).last_size, 6);
  store.close();
});
