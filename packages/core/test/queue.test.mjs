import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig, ConfigError } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { parseNote, encodeNote } from '../src/note.mjs';
import { signNote } from '../src/signer.mjs';
import { Anchorer } from '../src/anchor.mjs';

const CFG = 'version: 1\nstore: ./s\nunwitnessed_ceiling: 1h\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh(root = mkdtempSync(join(tmpdir(), 'ss-q-'))) {
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c, advance: (/** @type {number} */ ms) => { t += ms; } };
}

const dead = {
  id: 'w', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
  tier: /** @type {const} */ ('anchor'), async submit() { throw new Error('ECONNREFUSED'); },
};

/** @param {string} id */
async function liveWitness(id = 'audit.internal') {
  const key = await generateDevSigner(id);
  return {
    key,
    adapter: {
      id, proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
      tier: /** @type {const} */ ('anchor'),
      async submit(/** @type {string} */ note) {
        const text = parseNote(note).text;
        return {
          type: /** @type {const} */ ('c2sp-note'), issuer: id,
          covers: /** @type {const} */ ('note'),
          line: encodeNote(text, [await signNote(text, key)]).trim().split('\n').at(-1),
        };
      },
    },
  };
}

// ── NFR-12, FR-38 ───────────────────────────────────────────────────────────

test('NFR-12: a whole run completes with every witness unreachable', async () => {
  const { store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  for (let i = 0; i < 5; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    const r = await a.anchor(cp.checkpoint_seq);
    assert.equal(r.unwitnessed, true);
  }
  // Absolute: the collector must never be able to stop an agent run, so a
  // total witness outage is a widened window and nothing else.
  assert.equal(c.tree_size, 5);
  assert.equal(store.readCheckpoints().length, 5);
  store.close();
});

// ── NFR-13: the queue is durable ────────────────────────────────────────────

test('NFR-13: the queue survives a restart', async () => {
  // An in-memory queue loses exactly the evidence an outage created — and an
  // outage is when a restart is most likely. The two failures compound.
  const { root, store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  for (let i = 0; i < 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    await a.anchor((await c.checkpoint()).checkpoint_seq);
  }
  assert.deepEqual(a.queued(), [1, 2, 3]);
  store.close();

  const store2 = new Store(root, 'host-1');
  const a2 = new Anchorer({ store: store2, witnesses: [dead], quorum: 1 });
  assert.deepEqual(a2.queued(), [1, 2, 3], 'the queue is read from disk, not remembered');
  store2.close();
});

test('NFR-13: draining removes an entry durably, not just in memory', async () => {
  const { root, store, c } = await fresh();
  const w = await liveWitness();
  let up = false;
  const flaky = { ...w.adapter, async submit(/** @type {string} */ n) {
    if (!up) throw new Error('down');
    return w.adapter.submit(n);
  } };
  const a = new Anchorer({ store, witnesses: [flaky], quorum: 1,
    acceptance: { 'audit.internal': w.key.publicKey } });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  assert.deepEqual(a.queued(), [1]);
  up = true;
  await a.flush();
  assert.deepEqual(a.queued(), []);
  store.close();

  const store2 = new Store(root, 'host-1');
  const a2 = new Anchorer({ store: store2, witnesses: [flaky], quorum: 1 });
  assert.deepEqual(a2.queued(), [], 'and it stays drained across a restart');
  store2.close();
});

test('NFR-13: a torn queue line is dropped and repaired before the next write', async () => {
  // The same lesson as the witness journal, which took two review rounds
  // there: tolerating a torn tail on read is not enough, because the next
  // append lands after the partial bytes and makes a terminated malformed line.
  const { root, store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  const p = join(root, 'queue', 'host-1.jsonl');
  assert.ok(existsSync(p), 'the queue is a file');
  writeFileSync(p, readFileSync(p, 'utf8') + '{"checkpoint_seq":2,"sin');

  // One store throughout: a second Store on the same collector is refused by
  // the write lock, which is correct and would mask what this test is for.
  const a2 = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  assert.deepEqual(a2.queued(), [1], 'the torn line is dropped on read');
  c.action(tx({ correlation: 'c-2' }));
  await a2.anchor((await c.checkpoint()).checkpoint_seq);
  const after = readFileSync(p, 'utf8');
  assert.ok(after.endsWith('\n'));
  for (const line of after.split('\n').filter(Boolean)) {
    assert.doesNotThrow(() => JSON.parse(line), `incomplete line survived: ${line.slice(0, 40)}`);
  }
  assert.deepEqual(a2.queued(), [1, 2]);
  store.close();
});

test('NFR-13: a malformed line in the middle of the queue is refused, not skipped', async () => {
  const { root, store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  const p = join(root, 'queue', 'host-1.jsonl');
  writeFileSync(p, '{"checkpoint_seq":"not a number"}\n' + readFileSync(p, 'utf8'));
  store.close();
  const store2 = new Store(root, 'host-1');
  // Skipping it would silently drop a queued checkpoint, which is the evidence
  // the queue exists to keep.
  assert.throws(() => new Anchorer({ store: store2, witnesses: [dead], quorum: 1 }),
    /queue|checkpoint_seq/i);
  store2.close();
});

// ── OPS-02: backoff ─────────────────────────────────────────────────────────

test('OPS-02: a failed drain backs off, and the delay grows', async () => {
  const { store, c } = await fresh();
  let now = Date.parse('2026-10-11T10:00:00Z');
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1, now: () => now });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);

  // A fresh entry is eligible at once: anchor() already tried and failed, and
  // the caller choosing to flush is the cadence. Delaying here meant a witness
  // back in two seconds went unused for thirty.
  assert.equal(a.nextAttemptAt(1), now, 'a queued entry is retried without delay first');
  await a.flush();
  const first = a.nextAttemptAt(1);
  assert.ok(first > now, `a failed retry backs off: ${first} vs ${now}`);
  // The clock has to move, or flush only reports `waiting` and the attempt
  // count never rises — which is how the first version concluded it did not grow.
  now = first;
  await a.flush();
  const second = a.nextAttemptAt(1);
  assert.ok(second > first, `and the backoff grows: ${first} -> ${second}`);

  // Bounded, or a long outage schedules the next attempt past the life of the
  // deployment and a returning witness is waited for rather than used.
  for (let i = 0; i < 40; i += 1) {
    now = a.nextAttemptAt(1);
    await a.flush();
  }
  const since = Date.parse(store.readQueue()[0].since);
  assert.ok(a.nextAttemptAt(1) - since <= a.backoff_ceiling_ms,
    'the delay is capped at backoff_ceiling_ms');
  store.close();
});

test('OPS-02: flush skips an entry whose backoff has not elapsed', async () => {
  const { store, c } = await fresh();
  let now = Date.parse('2026-10-11T10:00:00Z');
  const w = await liveWitness();
  let up = false;
  const flaky = { ...w.adapter, async submit(/** @type {string} */ n) {
    if (!up) throw new Error('down');
    return w.adapter.submit(n);
  } };
  const a = new Anchorer({ store, witnesses: [flaky], quorum: 1, now: () => now,
    acceptance: { 'audit.internal': w.key.publicKey } });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  // One failed retry, so there is a backoff window to be inside.
  const failed = await a.flush();
  assert.deepEqual(failed.anchored, []);
  up = true;
  const skipped = await a.flush();
  assert.deepEqual(skipped.anchored, [], 'still inside the backoff window');
  assert.deepEqual(skipped.waiting, [1]);
  now += 60 * 60 * 1000;
  const drained = await a.flush();
  assert.deepEqual(drained.anchored, [1]);
  store.close();
});

// ── FR-68: the ceiling ──────────────────────────────────────────────────────

test('FR-68: past the ceiling an alert is raised OUT OF BAND', async () => {
  const { store, c, advance } = await fresh();
  /** @type {any[]} */
  const alerts = [];
  let now = Date.parse('2026-10-11T10:00:00Z');
  const a = new Anchorer({
    store, witnesses: [dead], quorum: 1, now: () => now,
    unwitnessed_ceiling_ms: 3_600_000,
    onCeilingBreached: (/** @type {any} */ e) => alerts.push(e),
  });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  assert.deepEqual(alerts, [], 'not yet overdue');
  assert.equal(a.ceilingBreached(), false);

  now += 3_600_001;
  await a.flush();
  assert.equal(a.ceilingBreached(), true);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].oldest_checkpoint_seq, 1);
  assert.ok(alerts[0].unwitnessed_for_ms > 3_600_000);
  // Out of band, and not into the log. Writing an alert about the log's
  // integrity into the log would ask the suspect to carry the complaint.
  assert.equal(store.readChain().length, 1, 'no record was written by the alert');
  advance(0);
  store.close();
});

test('FR-68: the alert fires once per breach, not once per flush', async () => {
  const { store, c } = await fresh();
  /** @type {any[]} */
  const alerts = [];
  let now = Date.parse('2026-10-11T10:00:00Z');
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1, now: () => now,
    unwitnessed_ceiling_ms: 1000, onCeilingBreached: () => alerts.push(1) });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  now += 5000;
  for (let i = 0; i < 4; i += 1) await a.flush();
  assert.equal(alerts.length, 1, 'an alert that repeats every retry is an alert nobody reads');
  store.close();
});

test('FR-68: the breach clears when the queue drains, and the window is still reported', async () => {
  const { store, c } = await fresh();
  let now = Date.parse('2026-10-11T10:00:00Z');
  const w = await liveWitness();
  let up = false;
  const flaky = { ...w.adapter, async submit(/** @type {string} */ n) {
    if (!up) throw new Error('down');
    return w.adapter.submit(n);
  } };
  const a = new Anchorer({ store, witnesses: [flaky], quorum: 1, now: () => now,
    unwitnessed_ceiling_ms: 1000, acceptance: { 'audit.internal': w.key.publicKey } });
  c.action(tx());
  await a.anchor((await c.checkpoint()).checkpoint_seq);
  now += 5000;
  await a.flush();
  assert.equal(a.ceilingBreached(), true);
  up = true;
  // Past the backoff the failed retry set, or the flush only reports waiting.
  now = a.nextAttemptAt(1);
  await a.flush();
  assert.equal(a.ceilingBreached(), false);
  // The window happened. A cleared alert must not erase it.
  assert.ok(a.breaches.length >= 1);
  assert.equal(a.breaches[0].oldest_checkpoint_seq, 1);
  store.close();
});

test('FR-68: a ceiling of zero or less is refused at config load', () => {
  // Zero would make every batch instantly overdue, which makes the alert
  // meaningless rather than strict.
  for (const v of ['0s', '0', '-1s']) {
    assert.throws(() => parseConfig(`version: 1\nstore: ./s\nunwitnessed_ceiling: ${v}\n`, '/tmp'),
      ConfigError, v);
  }
  assert.equal(parseConfig('version: 1\nstore: ./s\nunwitnessed_ceiling: 30m\n', '/tmp')
    .unwitnessed_ceiling_ms, 1_800_000);
});
