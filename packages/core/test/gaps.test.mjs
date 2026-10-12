import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { parseNote, encodeNote, parseCheckpointText } from '../src/note.mjs';
import { signNote } from '../src/signer.mjs';
import { Anchorer } from '../src/anchor.mjs';
import { parseEnvelope } from '../src/envelope.mjs';
import { recomputeChain } from '../src/chain.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'ss-gaps-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c };
}

test('FR-26: a gap occupies exactly one record position', async () => {
  const { store, c } = await fresh();
  c.action(tx({ correlation: 'a' }));
  // Three observations lost: the collector spent their source_seq numbers and
  // wrote none of them.
  c.observe(); c.observe(); c.observe();
  const before = c.tree_size;
  c.gap({ from_source_seq: 2, to_source_seq: 4 });
  // One position, whatever the span. record_seq counts WRITES, so a gap
  // spanning a thousand lost observations still advances the tree by one —
  // which is what keeps record_seq == tree_size true (DES-04).
  assert.equal(c.tree_size, before + 1);
  assert.equal(recomputeChain(store.readChain()).ok, true);
  store.close();
});

test('FR-26: the span is exact, and a reversed or empty one is refused', async () => {
  const { store, c } = await fresh();
  c.action(tx({ correlation: 'a' }));
  c.observe(); c.observe();
  assert.throws(() => c.gap({ from_source_seq: 4, to_source_seq: 2 }));
  assert.throws(() => c.gap({ from_source_seq: 0, to_source_seq: 1 }));
  assert.throws(() => c.gap({ from_source_seq: 2, to_source_seq: 2.5 }));
  // And a refused declaration must not consume a record position, or the
  // sequence gets a hole for a record nobody wrote.
  assert.equal(c.tree_size, 1);
  store.close();
});

test('FR-26: a gap is detected from consecutive persisted source_seq, never from record_seq', async () => {
  const { store, c } = await fresh();
  c.action(tx({ correlation: 'a' }));      // source_seq 1
  c.observe(); c.observe();                // 2, 3 lost
  c.action(tx({ correlation: 'b' }));      // source_seq 4
  const persisted = store.readChain().map(e => e.record.source_seq).filter(s => s !== null);
  assert.deepEqual(persisted, [1, 4]);
  // The hole is between 1 and 4 in source_seq. record_seq is 1, 2 — contiguous,
  // as it must be. The two counters count different things and comparing them
  // arithmetically is the error DES-04 rule 2 exists to forbid.
  assert.deepEqual(store.readChain().map(e => e.record.record_seq), [1, 2]);
  store.close();
});

test('FR-27: a gap declaration is submitted for countersignature like any record', async () => {
  const { store, signer, c } = await fresh();
  c.action(tx({ correlation: 'a' }));
  c.observe(); c.observe();
  const gap = c.gap({ from_source_seq: 2, to_source_seq: 3, reason: 'collector restarted' });
  const cp = await c.checkpoint();

  const witnessKey = await generateDevSigner('audit.internal');
  const adapter = {
    id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit(/** @type {string} */ note) {
      const text = parseNote(note).text;
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.internal',
        covers: /** @type {const} */ ('note'),
        line: encodeNote(text, [await signNote(text, witnessKey)]).trim().split('\n').at(-1),
      };
    },
  };
  const a = new Anchorer({
    store, witnesses: [adapter], quorum: 1,
    acceptance: { 'audit.internal': witnessKey.publicKey },
  });
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 1);

  // The gap record is a leaf under the checkpoint the witness countersigned,
  // so its TIME is independently established — which is the whole point of
  // FR-27. A gap whose time is self-asserted can be backdated to cover
  // whatever the operator needs it to cover.
  const env = parseEnvelope(String(store.readCheckpointEnvelope(cp.checkpoint_seq)));
  const size = parseCheckpointText(parseNote(String(env.note)).text).tree_size;
  assert.ok(Number(gap.record.record_seq) <= size,
    'the declaration must be under the countersigned tree, not after it');
  assert.deepEqual([...env.issuers], ['audit.internal']);
  store.close();
});

test('FR-27: a gap written AFTER the last countersigned checkpoint is not yet covered', async () => {
  const { store, c } = await fresh();
  c.action(tx({ correlation: 'a' }));
  const cp = await c.checkpoint();
  c.observe(); c.observe();
  const late = c.gap({ from_source_seq: 2, to_source_seq: 3 });
  // Nothing is wrong here — it is the ordinary fail-open state, and the point
  // is that it must not be reported as though the declaration's time were
  // established. A reader needs to know which side of the anchor it fell on.
  const size = parseCheckpointText(parseNote(String(
    parseEnvelope(String(store.readCheckpointEnvelope(cp.checkpoint_seq))).note)).text).tree_size;
  assert.ok(Number(late.record.record_seq) > size);
  store.close();
});

test('gap_unknown is for when the counter itself was lost, and says so', async () => {
  const { store, c } = await fresh();
  c.action(tx({ correlation: 'a' }));
  const g = c.gapUnknown({ last_checkpoint_source_seq: 1 });
  assert.equal(g.record.kind, 'gap_unknown');
  // No span, because there is no span to name: the observation counter did not
  // survive. Declaring an exact span here would be an invention, and FR-26's
  // whole value is that its span is exact.
  assert.equal(g.record.from_source_seq, undefined);
  assert.equal(g.record.to_source_seq, undefined);
  assert.equal(recomputeChain(store.readChain()).ok, true);
  store.close();
});
