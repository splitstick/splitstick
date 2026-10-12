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

// ── PR #8 review: the queue, the quorum, and what "anchored" may mean ──────

/**
 * A stateful sequence witness that remembers its height and refuses a history
 * that does not extend what it signed — FR-43. `online` lets a test take it
 * away and give it back.
 * @param {string} id
 */
async function statefulWitness(id) {
  const { generateDevSigner } = await import('../src/signer-file.mjs');
  const { parseNote, encodeNote } = await import('../src/note.mjs');
  const { signNote } = await import('../src/signer.mjs');
  const key = await generateDevSigner(id);
  /** @type {{ old_size: number, size: number }[]} */
  const asked = [];
  const w = {
    id, proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    online: true,
    height: 0,
    asked,
    async submit(/** @type {string} */ note, /** @type {any} */ ctx) {
      if (!w.online) throw new Error('ECONNREFUSED');
      const text = parseNote(note).text;
      const size = Number(text.split('\n')[1]);
      asked.push({ old_size: ctx.old_size, size });
      if (ctx.old_size !== w.height) {
        throw new Error(`409: I am at ${w.height}, you say I am at ${ctx.old_size}`);
      }
      w.height = size;
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: id,
        covers: /** @type {const} */ ('note'),
        line: encodeNote(text, [await signNote(text, key)]).trim().split('\n').at(-1),
      };
    },
  };
  return w;
}

test('a checkpoint short of its quorum stays queued, and recovers after a restart', async () => {
  // One of two required sequence witnesses answers. The entry used to be
  // DEQUEUED on that single answer — quorum was computed afterwards and
  // ignored — so a deployment that asked for two independent sequence
  // witnesses silently ran on one, permanently, with nothing retrying the
  // other and nothing reporting it.
  const { Store } = await import('../src/store.mjs');
  const { Collector } = await import('../src/collector.mjs');
  const { parseConfig } = await import('../src/config.mjs');
  const { generateDevSigner } = await import('../src/signer-file.mjs');
  const { Anchorer } = await import('../src/anchor.mjs');
  const { parseEnvelope } = await import('../src/envelope.mjs');

  const root = mkdtempSync(join(tmpdir(), 'ss-quorum-'));
  const origin = 'splitstick.dev/host-1';
  const signer = await generateDevSigner(origin);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const store = new Store(root, 'host-1');
  const c = new Collector({
    store, signer, collector: 'host-1', origin,
    config: parseConfig('version: 1\nstore: ./s\nunwitnessed_ceiling: 1h\n', root),
    now: () => new Date(t += 1000),
  });
  const A = await statefulWitness('audit-a.internal');
  const B = await statefulWitness('audit-b.internal');
  B.online = false;

  let a = new Anchorer({ store, witnesses: [A, B], quorum: 2, now: () => t });
  for (let i = 1; i <= 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    const r = await a.anchor(cp.checkpoint_seq);
    assert.equal(r.quorum.sequence, 1, 'one witness answered');
    assert.equal(r.sufficient, false, 'one of two required is not sufficient');
    assert.deepEqual(r.missing, ['audit-b.internal'], 'and it says which is missing');
    assert.equal(r.unwitnessed, false, 'but it is not unwitnessed either');
  }
  assert.deepEqual(a.queued(), [1, 2, 3], 'all three are held for the missing witness');

  // NFR-13: the queue is the thing that survives a restart.
  store.close();
  const s2 = new Store(root, 'host-1');
  a = new Anchorer({ store: s2, witnesses: [A, B], quorum: 2, now: () => t });
  assert.deepEqual(a.queued(), [1, 2, 3], 'and it survives the restart');

  B.online = true;
  t += 2 * 3_600_000;                        // past OPS-02's backoff
  const f = await a.flush();
  assert.deepEqual(f.anchored, [3], 'the highest reaches quorum');
  assert.deepEqual(f.superseded, [1, 2], 'the lower ones are covered by it, not silently dropped');
  assert.deepEqual(f.queued, [], 'and the queue clears');

  const env = s2.readCheckpointEnvelope(3);
  assert.notEqual(env, null);
  const issuers = [...parseEnvelope(/** @type {string} */ (env)).issuers].sort();
  assert.deepEqual(issuers, ['audit-a.internal', 'audit-b.internal']);
  s2.close();
});

test('a returning witness is told the height IT signed, not the height the set reached', async () => {
  // The consistency context used the highest size witnessed by ANYBODY. With
  // one witness that is the same number; with two it is wrong for whichever is
  // behind, so a witness coming back from an outage was asked to extend a tree
  // it had never signed, refused, and went on refusing — the queue could never
  // have cleared by waiting, which is the only thing the queue does.
  const { Store } = await import('../src/store.mjs');
  const { Collector } = await import('../src/collector.mjs');
  const { parseConfig } = await import('../src/config.mjs');
  const { generateDevSigner } = await import('../src/signer-file.mjs');
  const { Anchorer } = await import('../src/anchor.mjs');

  const root = mkdtempSync(join(tmpdir(), 'ss-oldsize-'));
  const origin = 'splitstick.dev/host-1';
  const signer = await generateDevSigner(origin);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const store = new Store(root, 'host-1');
  const c = new Collector({
    store, signer, collector: 'host-1', origin,
    config: parseConfig('version: 1\nstore: ./s\nunwitnessed_ceiling: 1h\n', root),
    now: () => new Date(t += 1000),
  });
  const A = await statefulWitness('audit-a.internal');
  const B = await statefulWitness('audit-b.internal');
  B.online = false;
  const a = new Anchorer({ store, witnesses: [A, B], quorum: 2, now: () => t });

  for (let i = 1; i <= 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    await a.anchor(cp.checkpoint_seq);
  }
  assert.equal(A.height, 3, 'A advanced with the log');

  B.online = true;
  B.asked.length = 0;
  t += 2 * 3_600_000;
  await a.flush();

  assert.deepEqual(B.asked, [{ old_size: 0, size: 3 }],
    'B is asked to extend ITS zero, not the set\'s three');
  assert.equal(B.height, 3, 'so it accepts, which is what lets the queue clear');
  store.close();
});

test('a quorum larger than the witness set does not queue forever', async () => {
  // Bounding the target by what could ever answer. Without it a quorum of two
  // against one configured witness would hold every checkpoint in the queue
  // and breach FR-68's ceiling permanently, reporting an outage that is really
  // a configuration the operator chose. SEC-04 is what flags a set that small;
  // `quorum_met` still reports the configured number unmet.
  const { Store } = await import('../src/store.mjs');
  const { Collector } = await import('../src/collector.mjs');
  const { parseConfig } = await import('../src/config.mjs');
  const { generateDevSigner } = await import('../src/signer-file.mjs');
  const { Anchorer } = await import('../src/anchor.mjs');

  const root = mkdtempSync(join(tmpdir(), 'ss-unreach-'));
  const origin = 'splitstick.dev/host-1';
  const signer = await generateDevSigner(origin);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const store = new Store(root, 'host-1');
  const c = new Collector({
    store, signer, collector: 'host-1', origin,
    config: parseConfig('version: 1\nstore: ./s\nunwitnessed_ceiling: 1h\n', root),
    now: () => new Date(t += 1000),
  });
  const A = await statefulWitness('audit-a.internal');
  const a = new Anchorer({ store, witnesses: [A], quorum: 2, now: () => t });
  c.action(tx({ correlation: 'c-1' }));
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);

  assert.equal(r.sufficient, true, 'the only witness there is, is enough to stop queueing');
  assert.equal(r.quorum_met.sequence, false, 'and the configured quorum is still reported unmet');
  assert.deepEqual(a.queued(), []);
  store.close();
});

test('LEG-09: the statement record is append-only, and is not called anchored without a witness', async () => {
  // The command used to DELETE its output directory on every run. Each
  // version's record was therefore the only one that survived, and the chain
  // linking the versions existed solely as text inside the newest record —
  // a log that discarded its own history in order to record its history. It
  // also generated a fresh signing key per run, so even a retained chain would
  // have been unverifiable across versions.
  const { execFileSync } = await import('node:child_process');
  const { Store } = await import('../src/store.mjs');
  const { writeFileSync } = await import('node:fs');

  const dir = mkdtempSync(join(tmpdir(), 'ss-wps-'));
  const statement = join(dir, 'wps.md');
  const out = join(dir, 'store');
  const tool = new URL('../../../tools/anchor-wps.mjs', import.meta.url).pathname;
  const run = () => execFileSync(process.execPath,
    [tool, '--statement', statement, '--out', out], { encoding: 'utf8' });

  writeFileSync(statement, '**Version 1.0**\n\nfirst\n');
  const first = run();
  assert.match(first, /RECORDED \(not anchored\)/,
    'with no witness configured the word anchored is not used');
  assert.match(first, /countersigned nobody/);
  assert.match(first, /outstanding/, 'and it says LEG-09 is not closed by this');
  assert.doesNotMatch(first, /\bANCHORED\b/);

  // Running it again must not append a second record of the same version.
  assert.match(run(), /already the current recorded version/);

  writeFileSync(statement, '**Version 1.1**\n\nsecond\n');
  assert.match(run(), /versions      2 in this chain/);

  const store = new Store(out, 'wps');
  const policies = store.readChain().map(e => e.record).filter(r => r?.kind === 'policy');
  assert.equal(policies.length, 2, 'the first version\'s record is still there');
  // The chain links them: each record names the digest it supersedes, and the
  // predecessor is read from the chain rather than from a file beside it.
  assert.equal(policies[1]?.previous_policy, policies[0]?.next_policy);
  assert.notEqual(policies[0]?.next_policy, policies[1]?.next_policy);
  // One identity across both, which is what makes the second verifiable
  // against the first.
  assert.equal(store.readSuccession().length, 1);
  store.close();
});
