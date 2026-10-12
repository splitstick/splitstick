import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { Anchorer } from '../src/anchor.mjs';
import { recomputeChain, chainEntry, genesis } from '../src/chain.mjs';
import { newSalt } from '../src/leaf.mjs';

/**
 * Findings from an independent review of M3b. Every one reproduced before the
 * fix, and every one is the same shape as a finding an external reviewer
 * already raised twice: a bad value COERCED or SKIPPED instead of refused.
 * That these appeared in code written after those reviews is the useful part.
 */

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (o = {}) => ({ run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'),
  result: Buffer.from('y'), outcome: /** @type {const} */ ('ok'), attempt: 1,
  correlation: 'c-1', ...o });
const dead = {
  id: 'w', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
  tier: /** @type {const} */ ('anchor'), async submit() { throw new Error('down'); },
};

async function fresh(root = mkdtempSync(join(tmpdir(), 'ss-rv-')), signer) {
  const s = signer ?? await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  return { root, store, signer: s, c: new Collector({ store,
    config: parseConfig(CFG, root), signer: s, collector: 'host-1', origin: ORIGIN,
    now: () => new Date(t += 1000) }) };
}
const rec = (/** @type {any} */ e) => e.record;

// ── F1: a corrupt `since` silenced the ceiling forever ─────────────────────

test('a queue entry with an unreadable `since` is refused, not coerced', async () => {
  // It was coerced to '' on read, so Date.parse gave NaN, so the age was NaN,
  // so `Number.isFinite(age)` was false and the ceiling NEVER fired. One
  // corrupted byte silenced FR-68's alarm permanently — and silently, which is
  // the only thing worse.
  const { root, store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  const p = join(root, 'queue', 'host-1.jsonl');
  const e = JSON.parse(readFileSync(p, 'utf8').trim());
  for (const since of ['corrupted', '', 42, null, '2026-13-45T00:00:00.000Z']) {
    writeFileSync(p, JSON.stringify({ ...e, since }) + '\n');
    assert.throws(() => new Anchorer({ store, witnesses: [dead], quorum: 1 }),
      /since/i, `since ${JSON.stringify(since)} should be refused`);
  }
  store.close();
});

test('the ceiling fires for a queue that has been waiting, on every version of now', async () => {
  const { store, c } = await fresh();
  let now = Date.parse('2026-10-11T10:00:00Z');
  /** @type {any[]} */
  const alerts = [];
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1, now: () => now,
    unwitnessed_ceiling_ms: 1000, onCeilingBreached: (/** @type {any} */ x) => alerts.push(x) });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  now += 5000;
  await a.flush();
  assert.equal(a.ceilingBreached(), true);
  assert.equal(alerts.length, 1);
  store.close();
});

// ── F2: an out-of-order enqueue persisted the wrong entry ──────────────────

test('enqueueing a LOWER checkpoint persists that checkpoint, not the highest', async () => {
  // It appended `entries.at(-1)` after sorting, so anchoring an older
  // checkpoint appended the newest one again: the disk held [2,3,3] while
  // memory held [1,2,3]. Checkpoint 1 was never persisted — a batch that never
  // gets witnessed, which is the whole of what NFR-13 exists to prevent.
  const { root, store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  for (let i = 0; i < 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    await c.checkpoint();
  }
  await a.anchor(2);
  await a.anchor(3);
  await a.anchor(1);
  const onDisk = readFileSync(join(root, 'queue', 'host-1.jsonl'), 'utf8')
    .trim().split('\n').map(l => JSON.parse(l).checkpoint_seq).sort((x, y) => x - y);
  assert.deepEqual(onDisk, [1, 2, 3], 'the disk must hold what memory holds');
  assert.deepEqual(a.queued(), [1, 2, 3]);

  // And it survives, which is the only reason any of it matters.
  store.close();
  const store2 = new Store(root, 'host-1');
  assert.deepEqual(new Anchorer({ store: store2, witnesses: [dead], quorum: 1 }).queued(),
    [1, 2, 3]);
  store2.close();
});

// ── F3: a legitimate restart threw ─────────────────────────────────────────

test('a counter behind the written records is the NORMAL mid-window state', async () => {
  // It threw "the counter is behind the record", refusing to open. But the
  // counter is written at each FLUSH while source_seq advances on every
  // observation, so being behind is what the ordinary state looks like between
  // flushes — any crash after a reconciliation and before the next checkpoint
  // bricked the store until somebody edited the counter file by hand.
  const root = mkdtempSync(join(tmpdir(), 'ss-rv-'));
  const { store, c, signer } = await fresh(root);
  c.action(tx({ correlation: 'a' }));
  c.observe(); c.observe();
  await c.checkpoint();
  store.close();

  const { store: s2, c: c2 } = await fresh(root, signer);
  assert.deepEqual(c2.reconcileObservations(), { from_source_seq: 2, to_source_seq: 3 });
  c2.action(tx({ correlation: 'b' }));            // source_seq 4, no checkpoint
  s2.close();

  const { store: s3, c: c3 } = await fresh(root, signer);
  assert.doesNotThrow(() => c3.reconcileObservations());
  assert.equal(c3.reconcileObservations(), null, 'nothing new was lost');
  s3.close();
});

// ── F4: the same gap declared twice, accepted by both sides ────────────────

test('a gap already declared is not declared again on the next restart', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ss-rv-'));
  const { store, c, signer } = await fresh(root);
  c.action(tx({ correlation: 'a' }));
  c.observe(); c.observe();
  await c.checkpoint();
  store.close();

  const { store: s2, c: c2 } = await fresh(root, signer);
  c2.reconcileObservations();
  s2.close();
  // A crash with no further writes, then another restart.
  const { store: s3, c: c3 } = await fresh(root, signer);
  assert.equal(c3.reconcileObservations(), null, 'the span is already declared in the chain');
  const gaps = s3.readChain().map(rec).filter(r => r.kind === 'gap');
  assert.equal(gaps.length, 1, `declared ${gaps.length} times`);
  s3.close();
});

test('the verifier refuses a span declared twice', async () => {
  // Both declarations met the sequence because a declaration did not advance
  // the accounted position, so N identical declarations passed. A second
  // declaration of the same span is a contradiction in the operator's own
  // account and must not verify.
  const base = (/** @type {number} */ rs, /** @type {object} */ over) => ({
    v: 1, ts: '2026-10-11T10:00:00.000Z', record_seq: rs, collector: 'host-1', ...over });
  const action = (/** @type {number} */ rs, /** @type {number} */ ss) => base(rs, {
    kind: 'tool_call', run: 'r-1', source_seq: ss, tool: 't', consequential: true,
    args: { cid: `sha256:${'a'.repeat(64)}` }, outcome: 'ok', attempt: 1, correlation: `c-${ss}` });
  const gap = (/** @type {number} */ rs, /** @type {number} */ f, /** @type {number} */ t) =>
    base(rs, { kind: 'gap', run: null, source_seq: null, from_source_seq: f, to_source_seq: t });
  let prev = genesis();
  const chain = [action(1, 1), gap(2, 2, 3), gap(3, 2, 3), action(4, 4)].map(r => {
    const e = chainEntry(r, newSalt(), prev);
    prev = e.head;
    return e;
  });
  const r = recomputeChain(chain);
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN'), JSON.stringify(r.findings));
});

test('two DIFFERENT gaps in a row each account for their own span', async () => {
  // The fix must not refuse consecutive declarations that are genuinely
  // adjacent — a collector that lost two separate windows before writing
  // anything produces exactly this.
  const base = (/** @type {number} */ rs, /** @type {object} */ over) => ({
    v: 1, ts: '2026-10-11T10:00:00.000Z', record_seq: rs, collector: 'host-1', ...over });
  const gap = (/** @type {number} */ rs, /** @type {number} */ f, /** @type {number} */ t) =>
    base(rs, { kind: 'gap', run: null, source_seq: null, from_source_seq: f, to_source_seq: t });
  const action = (/** @type {number} */ rs, /** @type {number} */ ss) => base(rs, {
    kind: 'tool_call', run: 'r-1', source_seq: ss, tool: 't', consequential: true,
    args: { cid: `sha256:${'a'.repeat(64)}` }, outcome: 'ok', attempt: 1, correlation: `c-${ss}` });
  let prev = genesis();
  const chain = [gap(1, 1, 3), gap(2, 4, 6), action(3, 7)].map(r => {
    const e = chainEntry(r, newSalt(), prev);
    prev = e.head;
    return e;
  });
  const r = recomputeChain(chain);
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings));
});

// ── A pre-existing hole found while reviewing M3b ──────────────────────────

test('a timestamp must be a real instant, not merely the right shape', async () => {
  // `2026-13-45T99:99:99.999Z` has every digit in the right place and is not a
  // date. It validated as a record `ts` from M1 onwards, and `Date.parse` gives
  // NaN for it — so anything computing with the value got NaN: FR-39's
  // unwitnessed window, M4's coverage reasoning, any ordering by time.
  const { validateRecord, RecordError, isTimestamp } = await import('../src/record.mjs');
  const heartbeat = (/** @type {string} */ ts) => ({
    v: 1, kind: 'heartbeat', ts, record_seq: 1, source_seq: null, run: null,
    collector: 'host-1', build: `sha256:${'a'.repeat(64)}`, policy: `sha256:${'b'.repeat(64)}`,
  });
  // `Date.parse` is not sufficient on its own: it rejects month thirteen but
  // ROLLS 2026-02-30 over to March 2nd and calls it finite, so a date that
  // never existed would read back as a different date than the one written.
  // The leap second is refused deliberately — RFC 3339 allows :60, but every
  // timestamp here is produced by toISOString, which never emits one.
  for (const bad of [
    '2026-13-45T99:99:99.999Z',
    '2026-02-30T00:00:00.000Z',
    '2026-04-31T00:00:00.000Z',
    '2027-02-29T00:00:00.000Z',
    '0000-00-00T00:00:00.000Z',
    '2026-12-31T23:59:60.000Z',
  ]) {
    assert.equal(isTimestamp(bad), false, bad);
    assert.throws(() => validateRecord(heartbeat(bad)), RecordError, bad);
  }
  // And real ones still pass, including a leap day.
  for (const good of ['2026-10-11T10:00:00.000Z', '2028-02-29T23:59:59.999Z']) {
    assert.equal(isTimestamp(good), true, good);
    assert.doesNotThrow(() => validateRecord(heartbeat(good)), good);
  }
});
