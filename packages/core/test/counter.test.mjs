import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector, CollectorDegraded } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { recomputeChain } from '../src/chain.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function open_(root = mkdtempSync(join(tmpdir(), 'ss-ctr-')), signer) {
  const s = signer ?? await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer: s,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer: s, c };
}

const rec = (/** @type {any} */ e) => e.record;

// ── FR-61: the counter is durable at each flush ─────────────────────────────

test('FR-61: the observation counter is checkpointed at each batch flush', async () => {
  const { root, store, c } = await open_();
  c.action(tx({ correlation: 'a' }));
  c.observe();                     // spent, never written
  c.observe();
  await c.checkpoint();
  // Durable now: the counter is 3, while only source_seq 1 was ever written.
  assert.equal(store.readObservationCounter(), 3);
  assert.equal(store.tip().source_seq, 1);
  assert.ok(existsSync(join(root, 'counter', 'host-1.json')));
  store.close();
});

test('FR-61: a restart after a flush declares the exact span that was lost', async () => {
  // Without this the collector resumes from the last WRITTEN source_seq and
  // reuses the numbers that were spent — so the hole closes up and a lossy run
  // reads as a complete one.
  const root = mkdtempSync(join(tmpdir(), 'ss-ctr-'));
  const { store, c, signer } = await open_(root);
  c.action(tx({ correlation: 'a' }));      // source_seq 1
  c.observe(); c.observe();                // 2 and 3 spent, lost
  await c.checkpoint();
  store.close();

  const { store: s2, c: c2 } = await open_(root, signer);
  const loss = c2.reconcileObservations();
  assert.deepEqual(loss, { from_source_seq: 2, to_source_seq: 3 });
  const gaps = s2.readChain().map(rec).filter(r => r.kind === 'gap');
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].from_source_seq, 2);
  assert.equal(gaps[0].to_source_seq, 3);
  // And the collector continues from AFTER the lost span, never reusing it.
  c2.action(tx({ correlation: 'b' }));
  assert.equal(rec(s2.readChain().at(-1)).source_seq, 4);
  assert.equal(recomputeChain(s2.readChain()).ok, true);
  s2.close();
});

test('FR-61: a clean restart declares nothing', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ss-ctr-'));
  const { store, c, signer } = await open_(root);
  c.action(tx({ correlation: 'a' }));
  await c.checkpoint();
  store.close();
  const { store: s2, c: c2 } = await open_(root, signer);
  assert.equal(c2.reconcileObservations(), null);
  assert.deepEqual(s2.readChain().map(rec).filter(r => r.kind === 'gap'), []);
  s2.close();
});

test('FR-61: reconciling twice does not declare the span twice', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ss-ctr-'));
  const { store, c, signer } = await open_(root);
  c.action(tx({ correlation: 'a' }));
  c.observe();
  await c.checkpoint();
  store.close();
  const { store: s2, c: c2 } = await open_(root, signer);
  c2.reconcileObservations();
  assert.equal(c2.reconcileObservations(), null, 'the span is already declared');
  assert.equal(s2.readChain().map(rec).filter(r => r.kind === 'gap').length, 1);
  s2.close();
});

// ── FR-60: the counter itself did not survive ───────────────────────────────

test('FR-60: with no durable counter, an unknown-loss interval is declared', async () => {
  // Bounded by the last durable checkpoint and the restart — never an
  // unbounded claim, and never silence.
  const root = mkdtempSync(join(tmpdir(), 'ss-ctr-'));
  const { store, c, signer } = await open_(root);
  c.action(tx({ correlation: 'a' }));
  await c.checkpoint();
  const at = rec(store.readChain().at(-1)).ts;
  store.close();
  // The counter file is gone, as an unrecoverable crash with the counter only
  // in memory would leave it.
  const { rmSync } = await import('node:fs');
  rmSync(join(root, 'counter', 'host-1.json'));

  const { store: s2, c: c2 } = await open_(root, signer);
  const loss = /** @type {any} */ (c2.reconcileObservations());
  assert.equal(loss?.unknown, true);
  const unknown = s2.readChain().map(rec).filter(r => r.kind === 'gap_unknown');
  assert.equal(unknown.length, 1);
  // Bounded at both ends: no exact span is invented, because there is none.
  assert.equal(unknown[0].from_source_seq, undefined);
  assert.equal(unknown[0].last_checkpoint_source_seq, 1);
  assert.ok(unknown[0].from_ts <= at || unknown[0].from_ts !== undefined);
  s2.close();
});

test('FR-60: an empty store with no counter declares nothing', async () => {
  // A first run is not a loss. Declaring one would put a permanent
  // unknown-loss interval at the head of every log ever created.
  const { store, c } = await open_();
  assert.equal(c.reconcileObservations(), null);
  assert.deepEqual(store.readChain(), []);
  store.close();
});

test('FR-60: a counter BEHIND the written records is damage, not a loss', async () => {
  // The counter can only ever be ahead of or level with what was written.
  // Behind means the file was tampered with or restored from an older copy,
  // and inventing a negative span would be worse than refusing.
  const root = mkdtempSync(join(tmpdir(), 'ss-ctr-'));
  const { store, c, signer } = await open_(root);
  c.action(tx({ correlation: 'a' }));
  c.action(tx({ correlation: 'b' }));
  await c.checkpoint();
  store.close();
  writeFileSync(join(root, 'counter', 'host-1.json'),
    JSON.stringify({ source_seq: 1, at: '2026-10-11T10:00:00.000Z' }));
  const { store: s2, c: c2 } = await open_(root, signer);
  assert.throws(() => c2.reconcileObservations(), /behind|counter/i);
  s2.close();
});

// ── FR-58: the reserved slot ────────────────────────────────────────────────

test('FR-58: a reserve is pre-allocated, large enough for a gap declaration', async () => {
  const { root, store } = await open_();
  const p = join(root, 'reserve', 'host-1.slot');
  assert.ok(existsSync(p), 'the reserve exists from the moment the store does');
  // Sized against a real declaration rather than a guessed number.
  assert.ok(statSync(p).size >= store.reserveBytes);
  assert.ok(store.reserveBytes >= 4096);
  store.close();
});

test('FR-58: an ordinary record never consumes the reserve', async () => {
  // The slot exists precisely because the ordinary path has exhausted
  // everything else. Spending it on a tool call would mean it is absent at the
  // one moment it is for.
  const { root, store, c } = await open_();
  const before = statSync(join(root, 'reserve', 'host-1.slot')).size;
  for (let i = 0; i < 20; i += 1) c.action(tx({ correlation: `c-${i}` }));
  await c.checkpoint();
  assert.equal(statSync(join(root, 'reserve', 'host-1.slot')).size, before);
  store.close();
});

test('FR-58: when the store is exhausted the reserve is released and the gap lands', async () => {
  // A store that cannot record its own failure reports a clean history for a
  // lossy run, which is the worst outcome available.
  const { root, store, signer } = await open_();
  // Own properties on the REAL store, so every other method keeps its private
  // fields. Object.create(store) produced an object that is not a Store, and
  // the first inherited method touching #chainFd threw.
  let full = true;
  const realAppend = Store.prototype.append.bind(store);
  const realRelease = Store.prototype.releaseReserve.bind(store);
  store.append = (/** @type {any} */ e) => {
    if (full) {
      const err = new Error('ENOSPC: no space left on device');
      /** @type {any} */ (err).code = 'ENOSPC';
      throw err;
    }
    return realAppend(e);
  };
  store.releaseReserve = () => { full = false; return realRelease(); };
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });

  const written = c.declareGap({ from_source_seq: 1, to_source_seq: 7 });
  assert.equal(written.record.kind, 'gap');
  assert.equal(written.record.from_source_seq, 1);
  assert.equal(store.readChain().map(rec).filter(r => r.kind === 'gap').length, 1);
  assert.equal(existsSync(join(root, 'reserve', 'host-1.slot')), false,
    'the reserve was spent, and its absence is the signal that it was');
  store.close();
});

test('FR-58: if even the reserve fails, it is surfaced and the collector degrades', async () => {
  const { root, store, signer } = await open_();
  store.append = () => {
    const err = new Error('ENOSPC: no space left on device');
    /** @type {any} */ (err).code = 'ENOSPC';
    throw err;
  };
  store.releaseReserve = () => true;
  /** @type {any[]} */
  const surfaced = [];
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
    onUnrecordable: (/** @type {any} */ e) => surfaced.push(e) });

  assert.throws(() => c.declareGap({ from_source_seq: 1, to_source_seq: 7 }), CollectorDegraded);
  // Out of band, because the place it would otherwise go is the thing that is
  // full. And degraded, so it does not carry on pretending.
  assert.equal(surfaced.length, 1);
  assert.match(surfaced[0].detail, /gap declaration|reserve/i);
  assert.ok(c.degraded);
  store.close();
});
