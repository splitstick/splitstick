import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryRunJournal, DurableApprovalLedger, createApprovalRequest } from '@open-multi-agent/core';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { recomputeChain } from '@splitstick/core/chain';
import { SplitstickRunJournal, SplitstickApprovalStore } from '../src/index.mjs';

const CFG = 'version: 1\nstore: ./s\n';

async function wired(opts = {}) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-oma-'));
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const collector = new Collector({
    store, config: parseConfig(CFG, root), signer: await generateDevSigner('splitstick.dev/host-1'),
    collector: 'host-1', origin: 'splitstick.dev/host-1', now: () => new Date(t += 1000),
  });
  const inner = new InMemoryRunJournal();
  const journal = new SplitstickRunJournal({ collector, journal: inner, ...opts });
  return { root, store, collector, inner, journal };
}

/** The full shape OMA's ledger validates — including consequential, which is
 * where DES-01's field comes from rather than being assumed true. */
const toolCallContent = (toolCallId, input, consequential = true) => /** @type {any} */ ({
  kind: 'tool_call', toolName: 'transfer_funds', rawInput: input, input,
  agentName: 'planner', taskId: 'task-1', toolCallId, consequential,
});

/** The record is typed Record<string, unknown>; tests read fields off it freely.
 * @param {Record<string, any>} r @returns {Record<string, any>} */
const fld = r => r;

const ev = (seq, type, rest) => ({ seq, timestampUnixMs: 1760176800000 + seq, runId: 'run-1', attempt: 1, type, ...rest });
const call = (seq, id, name, input) => ev(seq, 'tool/call', { call: { type: 'tool_use', id, name, input } });
const result = (seq, id, text, isError = false) => ev(seq, 'tool/result', {
  toolCallId: id,
  result: { type: 'tool_result', toolUseId: id, content: [{ type: 'text', text }], isError },
});

// INT-04 — additive. The journal is OMA's own interface, implemented, not patched.
test('INT-04: the journal satisfies the unmodified RunJournal contract', async () => {
  const { journal, inner } = await wired();
  for (const m of ['append', 'readFrom', 'close']) assert.equal(typeof journal[m], 'function');
  assert.equal(typeof journal.describe, 'function');

  const events = [ev(1, 'run/start', { mode: 'runAgent' }), call(2, 'tc-1', 'transfer_funds', { amount: 2000000 })];
  await journal.append(events);
  // The inner journal still sees exactly what OMA wrote, byte for byte.
  assert.deepEqual(await journal.readFrom(1), await inner.readFrom(1));
  assert.deepEqual((await inner.readFrom(1)).map(e => e.type), ['run/start', 'tool/call']);
});

// FR-01 — a tool call and its result become one chained record per attempt.
test('FR-01: a call and its result become one record, with the outcome', async () => {
  const { journal, store } = await wired();
  await journal.append([
    ev(1, 'run/start', { mode: 'runAgent' }),
    call(2, 'tc-1', 'transfer_funds', { amount: 2000000, iban: 'DE89370400440532013000' }),
    result(3, 'tc-1', 'OK: transferred EUR 2000000 ref=TX-77814'),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 1, 'one record per attempt, not one per OMA event');
  assert.equal(recs[0].kind, 'tool_call');
  assert.equal(recs[0].tool, 'transfer_funds');
  assert.equal(recs[0].run, 'run-1');
  assert.equal(recs[0].outcome, 'ok');
  assert.equal(recs[0].attempt, 1);
  assert.equal(recs[0].source_seq, 1);
  assert.ok(recs[0].args.cid && recs[0].result.cid);
  assert.equal(recomputeChain(store.readChain()).ok, true);
});

// FR-05, FR-06 — the digested args and result are recoverable from the store.
test('FR-05 and FR-06: the arguments and the result are both committed', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000 }),
    result(2, 'tc-1', 'OK ref=TX-77814'),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.equal(store.content.get(r.args.cid).toString(), JSON.stringify({ amount: 2000000 }));
  assert.match(store.content.get(r.result.cid).toString(), /ref=TX-77814/);
  assert.deepEqual(store.content.findByRef('TX-77814'), [r.result.cid], 'FR-55 through the adapter');
});

// PRIV-02 through the adapter, which is where a leak would actually happen.
test('PRIV-02: nothing OMA handed us appears in the chain', async () => {
  const { journal, root } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000, iban: 'DE89370400440532013000' }),
    result(2, 'tc-1', 'OK: transferred EUR 2000000 ref=TX-77814'),
  ]);
  const text = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8');
  for (const n of ['2000000', 'DE89370400440532013000', 'TX-77814', 'transferred']) {
    assert.ok(!text.includes(n), `chain leaks ${n}`);
  }
  assert.ok(text.includes('transfer_funds'), 'the tool name is retained by design — DES-13');
});

// FR-62 — retries of one logical action.
// FR-62 — OMA expresses no retry lineage: a retry there is a new tool call with
// a new id, indistinguishable from an unrelated call carrying the same
// arguments. So the adapter records what it observed — two attempts of two
// logical actions — rather than inferring a relationship it cannot see. A
// review found the earlier behaviour reporting two independent transfers of the
// same amount as attempt 1 and attempt 2 of one action.
test('FR-62: two calls OMA cannot link are two logical actions', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000 }),
    result(2, 'tc-1', 'upstream timeout', true),
    call(3, 'tc-2', 'transfer_funds', { amount: 2000000 }),
    result(4, 'tc-2', 'OK ref=TX-77814'),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 2);
  assert.deepEqual(recs.map(r => r.outcome), ['error', 'ok']);
  assert.deepEqual(recs.map(r => r.source_seq), [1, 2], 'both attempts are counted');
  assert.deepEqual(recs.map(r => r.attempt), [1, 1], 'neither is an attempt OF the other');
  assert.notEqual(recs[0].correlation, recs[1].correlation);
  assert.notEqual(recs[0].args.cid, recs[1].args.cid, 'and each has its own content salt');
});

test('FR-62: two different actions do not share a correlation', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000 }),
    result(2, 'tc-1', 'OK'),
    call(3, 'tc-2', 'transfer_funds', { amount: 25 }),
    result(4, 'tc-2', 'OK'),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.notEqual(recs[0].correlation, recs[1].correlation);
  assert.deepEqual(recs.map(r => r.attempt), [1, 1]);
});

test('a correlation identifier carries nothing from the payload — DES-13', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000, iban: 'DE89370400440532013000' }),
    result(2, 'tc-1', 'OK ref=TX-77814'),
  ]);
  const c = String(fld(store.readChain()[0].record).correlation);
  assert.match(c, /^[0-9a-f]{24}$/, 'opaque and random, because it survives erasure');
  for (const n of ['2000000', 'DE89', 'tc-1', 'run-1', 'transfer']) assert.ok(!c.includes(n));
});

// FR-62 / fail-open — a call that never returned must still be accountable.
test('an unresolved call is recorded as a timeout at close, never dropped', async () => {
  const { journal, store } = await wired();
  await journal.append([call(1, 'tc-1', 'transfer_funds', { amount: 2000000 })]);
  assert.equal(store.readChain().length, 0, 'nothing is written while the outcome is unknown');
  await journal.close();
  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 1);
  assert.equal(recs[0].outcome, 'timeout');
  assert.equal(recs[0].tool, 'transfer_funds');
  assert.ok(recs[0].args.cid, 'with the arguments we did see');
  assert.ok(!('result' in recs[0]), 'and no result, because there was none');
});

test('run/end also settles anything still outstanding', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 1 }),
    ev(2, 'run/end', { status: { code: 'error' } }),
  ]);
  assert.equal(store.readChain().length, 1);
  assert.equal(fld(store.readChain()[0].record).outcome, 'timeout');
});

// FR-07 — an approval decision through the journal.
test('FR-07: an approval request and decision enter the record', async () => {
  const { journal, store } = await wired();
  const request = createApprovalRequest({
    runId: 'run-1', scope: 'tool_call', boundary: 'tc-1',
    content: toolCallContent('tc-1', { amount: 2000000 }),
    requestedAt: new Date('2026-10-11T10:00:00.000Z'),
  });
  await journal.append([
    ev(1, 'approval/request', { request }),
    ev(2, 'approval/decision', {
      decision: {
        version: 1, requestId: request.id, runId: 'run-1', scope: 'tool_call',
        requestHash: request.requestHash, decision: 'approved',
        reviewer: { id: 'ops@example.com' }, decidedAt: '2026-10-11T10:00:05.000Z',
      },
    }),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 1, 'the decision completes the request, it does not duplicate it');
  assert.equal(recs[0].kind, 'approval');
  assert.equal(recs[0].approval.decision, 'approve');
  assert.equal(recs[0].consequential, true, 'taken from OMA, not assumed');
  assert.ok(recs[0].approval.reviewer.cid, 'the deciding identity is committed, not inlined');
  assert.ok(!JSON.stringify(recs[0]).includes('ops@example.com'));
  assert.equal(store.content.get(recs[0].approval.reviewer.cid).toString(), 'ops@example.com');
  assert.equal(recomputeChain(store.readChain()).ok, true);
});

test('a rejected decision is recorded as deny with outcome denied', async () => {
  const { journal, store } = await wired();
  const request = createApprovalRequest({
    runId: 'run-1', scope: 'tool_call', boundary: 'tc-9',
    content: toolCallContent('tc-9', { amount: 9 }),
    requestedAt: new Date('2026-10-11T10:00:00.000Z'),
  });
  await journal.append([
    ev(1, 'approval/request', { request }),
    ev(2, 'approval/decision', {
      decision: { version: 1, requestId: request.id, runId: 'run-1', scope: 'tool_call',
        requestHash: request.requestHash, decision: 'rejected',
        reviewer: { id: 'ops@example.com' }, decidedAt: '2026-10-11T10:00:05.000Z' },
    }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.equal(fld(r).approval.decision, 'deny');
  assert.equal(r.outcome, 'denied');
});

test('an approval never decided is recorded at close as a timeout', async () => {
  const { journal, store } = await wired();
  const request = createApprovalRequest({
    runId: 'run-1', scope: 'tool_call', boundary: 'tc-1',
    content: toolCallContent('tc-1', {}),
    requestedAt: new Date('2026-10-11T10:00:00.000Z'),
  });
  await journal.append([ev(1, 'approval/request', { request })]);
  await journal.close();
  const r = fld(store.readChain()[0].record);
  assert.equal(r.kind, 'approval');
  assert.equal(r.outcome, 'timeout');
  assert.equal(r.approval, null, 'no decision is recorded, because none was made');
});

// SCOPE-16 / fail-open — the collector may never fail the run it observes.
test('a store failure is surfaced but never fails the append', async () => {
  const { journal, collector, inner } = await wired();
  /** @type {unknown[]} */
  const errors = [];
  journal.onError = e => errors.push(e);
  collector.action = () => { throw new Error('disk full'); };
  await journal.append([call(1, 'tc-1', 'transfer_funds', {}), result(2, 'tc-1', 'OK')]);
  assert.equal(errors.length, 1, 'the failure is reported');
  assert.equal((await inner.readFrom(1)).length, 2, 'and OMA keeps its own journal regardless');
});

test('with no inner journal the adapter is still a valid backend', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-oma-'));
  const store = new Store(root, 'host-1');
  const collector = new Collector({
    store, config: parseConfig(CFG, root), signer: await generateDevSigner('o'),
    collector: 'host-1', origin: 'o' });
  const journal = new SplitstickRunJournal({ collector });
  await journal.append([call(1, 'tc-1', 'x', {}), result(2, 'tc-1', 'OK')]);
  assert.deepEqual(await journal.readFrom(1), [], 'retention is the inner journal\'s job, not ours');
  assert.equal(store.readChain().length, 1);
  assert.equal(journal.describe().kind, 'splitstick');
});

// FR-02 — the approval store, which is a MemoryStore OMA's ledger drives.
test('FR-02: a suspend/approve/resume cycle is recorded through the store', async () => {
  const { collector, store } = await wired();
  const inner = new Map();
  /** A minimal MemoryStore. @type {any} */
  const backing = {
    async get(k) { return inner.has(k) ? { key: k, value: inner.get(k) } : null; },
    async set(k, v) { inner.set(k, v); },
    async compareAndSet(k, expected, v) {
      const cur = inner.has(k) ? inner.get(k) : null;
      if (cur !== expected) return false;
      inner.set(k, v); return true;
    },
    async list() { return [...inner].map(([key, value]) => ({ key, value })); },
    async delete(k) { inner.delete(k); },
    async clear() { inner.clear(); },
  };
  const approvals = new SplitstickApprovalStore({ store: backing, collector });
  const ledger = new DurableApprovalLedger(approvals);
  const request = createApprovalRequest({
    runId: 'run-1', scope: 'tool_call', boundary: 'tc-1',
    content: toolCallContent('tc-1', { amount: 2000000 }),
    requestedAt: new Date('2026-10-11T10:00:00.000Z'),
  });
  await ledger.ensureRequest(request);
  // The ledger's *input* enum is approve|reject; the durable record it writes
  // reads approved|rejected. The adapter must read the record, not the input.
  const decision = await ledger.decide({
    requestId: request.id, requestHash: request.requestHash,
    decision: 'approve', reviewer: { id: 'ops@example.com' },
  });
  assert.equal(decision.decision, 'approved');

  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 1, 'the request and its decision are one record');
  assert.equal(recs[0].kind, 'approval');
  assert.equal(recs[0].approval.decision, 'approve');
  assert.equal(recomputeChain(store.readChain()).ok, true);
  // And the ledger still works: the store is a pass-through with a side effect.
  const row = /** @type {any} */ (await /** @type {any} */ (ledger).get(request.id));
  assert.equal(row.decision.decision, 'approved');
});

// INT-07 — no agent code changes. Verified literally for the adapter surface.
test('INT-07: wiring is construction and configuration only', async () => {
  const { collector } = await wired();
  const j = new SplitstickRunJournal({ collector });
  assert.equal(j.constructor.name, 'SplitstickRunJournal');
  // Nothing was monkey-patched onto the upstream module.
  const oma = await import('@open-multi-agent/core');
  assert.equal(typeof oma.InMemoryRunJournal, 'function');
  const probe = new oma.InMemoryRunJournal();
  await probe.append([ev(1, 'run/start', { mode: 'runAgent' })]);
  assert.equal((await probe.readFrom(1)).length, 1, 'upstream behaviour is untouched');
});

// OMA's ToolResultContent is `string | ToolResultContentPart[]`, and the error
// flag on a ToolResultBlock is `is_error`, not `isError`. The red-team harness
// found both: against a genuine OMA journal the adapter was recording no result
// at all and reporting every failure as ok.
test('FR-06: a string-shaped result is committed, not dropped', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', { amount: 2000000 }),
    ev(2, 'tool/result', {
      toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: 'OK: transferred EUR 2000000 ref=TX-77814' },
    }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.ok(r.result, 'a string result must still be recorded');
  assert.equal(store.content.get(r.result.cid).toString(), 'OK: transferred EUR 2000000 ref=TX-77814');
  assert.equal(r.result.ok, true);
  assert.deepEqual(store.content.findByRef('TX-77814'), [r.result.cid]);
});

test('FR-06: is_error on the result block is read as an error outcome', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', {}),
    ev(2, 'tool/result', {
      toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: 'upstream refused', is_error: true },
    }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.equal(r.outcome, 'error');
  assert.equal(r.result.ok, false);
});

test('FR-06: isError on the ToolCallRecord is honoured too', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', {}),
    ev(2, 'tool/result', {
      toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: 'nope' },
      record: { isError: true },
    }),
  ]);
  assert.equal(fld(store.readChain()[0].record).outcome, 'error');
});

test('FR-06: a result with no text part is still committed rather than lost', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'screenshot', {}),
    ev(2, 'tool/result', {
      toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1',
        content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0K' } }] },
    }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.ok(r.result, 'an image result is a result; dropping it would fail FR-06 silently');
  assert.ok(store.content.get(r.result.cid).toString().includes('iVBORw0K'));
});

/**
 * Review finding P1-1. correlate() was keyed on the tool name and the argument
 * bytes, never retired after success and never scoped to a run, so two
 * independent calls with identical arguments were reported as attempt 1 and
 * attempt 2 of one logical action. A repeated transfer is not a retry.
 *
 * OMA does not express retry lineage at all — a retry there is a new tool call
 * with a new id — so the adapter cannot infer it and no longer tries. Each
 * observed call gets a fresh correlation, and attempt stays 1 unless an
 * integration can actually supply the lineage.
 *
 * There was a privacy consequence too, which the schema makes plain: DES-13
 * retains `correlation` after erasure. Grouping by argument equality meant two
 * retained correlations told a reader those two actions had byte-identical
 * arguments, long after the arguments themselves were shredded.
 */
test('FR-62: two identical successful calls are two logical actions, not a retry', async () => {
  const { journal, store } = await wired();
  await journal.append([call(1, 'tc-1', 'transfer_funds', { amount: 100 }), result(2, 'tc-1', 'OK')]);
  await journal.append([call(3, 'tc-2', 'transfer_funds', { amount: 100 }), result(4, 'tc-2', 'OK')]);

  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 2);
  assert.notEqual(recs[0].correlation, recs[1].correlation,
    'identical arguments are not evidence of a retry');
  assert.deepEqual(recs.map(r => r.attempt), [1, 1]);
  assert.deepEqual(recs.map(r => r.source_seq), [1, 2], 'but both attempts are still counted');
});

test('FR-62: identical calls in different runs stay independent', async () => {
  const { journal, store } = await wired();
  await journal.append([
    ev(1, 'tool/call', { runId: 'run-A', call: { type: 'tool_use', id: 'a', name: 'transfer_funds', input: { amount: 100 } } }),
    ev(2, 'tool/result', { runId: 'run-A', toolCallId: 'a', result: { type: 'tool_result', toolUseId: 'a', content: 'OK' } }),
    ev(3, 'tool/call', { runId: 'run-B', call: { type: 'tool_use', id: 'b', name: 'transfer_funds', input: { amount: 100 } } }),
    ev(4, 'tool/result', { runId: 'run-B', toolCallId: 'b', result: { type: 'tool_result', toolUseId: 'b', content: 'OK' } }),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.deepEqual(recs.map(r => r.run), ['run-A', 'run-B']);
  assert.notEqual(recs[0].correlation, recs[1].correlation);
});

test('a correlation no longer reveals that two actions had the same arguments', async () => {
  const { journal, store } = await wired();
  const same = { amount: 2000000, iban: 'DE89370400440532013000' };
  await journal.append([call(1, 'tc-1', 'transfer_funds', same), result(2, 'tc-1', 'OK')]);
  await journal.append([call(3, 'tc-2', 'transfer_funds', same), result(4, 'tc-2', 'OK')]);
  const [a, b] = store.readChain().map(e => fld(e.record));
  assert.notEqual(a.correlation, b.correlation,
    'correlation is retained after erasure, so equal payloads must not make it equal');
});

/**
 * Review finding P1-2. #settleOutstanding() took no run id, so ending run A
 * wrote a timeout for a call still in flight in run B — and when B's result
 * arrived its pending entry was gone, so the record was written with
 * `tool: 'unknown'`. One in-flight call produced two records, and the one that
 * described the real outcome named the wrong tool.
 */
test('ending one run leaves another run\'s in-flight call alone', async () => {
  const { journal, store } = await wired();
  await journal.append([
    ev(1, 'tool/call', { runId: 'run-B', call: { type: 'tool_use', id: 'tc-B', name: 'transfer_funds', input: { amount: 1 } } }),
    ev(2, 'run/end', { runId: 'run-A', status: { code: 'ok' } }),
  ]);
  assert.equal(store.readChain().length, 0, 'run A ending says nothing about run B');

  await journal.append([
    ev(3, 'tool/result', { runId: 'run-B', toolCallId: 'tc-B', result: { type: 'tool_result', toolUseId: 'tc-B', content: 'OK: done' } }),
  ]);
  const recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 1, 'one call, one record');
  assert.equal(recs[0].tool, 'transfer_funds', 'and it names the tool that actually ran');
  assert.equal(recs[0].outcome, 'ok');
  assert.equal(recs[0].run, 'run-B');
});

test('ending a run settles only its own outstanding calls', async () => {
  const { journal, store } = await wired();
  await journal.append([
    ev(1, 'tool/call', { runId: 'run-A', call: { type: 'tool_use', id: 'a', name: 'transfer_funds', input: {} } }),
    ev(2, 'tool/call', { runId: 'run-B', call: { type: 'tool_use', id: 'b', name: 'refund', input: {} } }),
    ev(3, 'run/end', { runId: 'run-A', status: { code: 'ok' } }),
  ]);
  let recs = store.readChain().map(e => fld(e.record));
  assert.deepEqual(recs.map(r => `${r.run}/${r.tool}/${r.outcome}`), ['run-A/transfer_funds/timeout']);

  await journal.close();
  recs = store.readChain().map(e => fld(e.record));
  assert.equal(recs.length, 2, 'close settles whatever is left');
  assert.equal(recs[1].run, 'run-B');
  assert.equal(recs[1].outcome, 'timeout');
});

test('an approval left undecided is settled by its own run ending', async () => {
  const { journal, store } = await wired();
  const request = createApprovalRequest({
    runId: 'run-A', scope: 'tool_call', boundary: 'tc-1',
    content: toolCallContent('tc-1', { amount: 1 }),
    requestedAt: new Date('2026-10-11T10:00:00.000Z'),
  });
  await journal.append([
    ev(1, 'approval/request', { request }),
    ev(2, 'run/end', { runId: 'run-B', status: { code: 'ok' } }),
  ]);
  assert.equal(store.readChain().length, 0, 'a different run ending must not settle it');
  await journal.append([ev(3, 'run/end', { runId: 'run-A', status: { code: 'ok' } })]);
  assert.equal(fld(store.readChain()[0].record).outcome, 'timeout');
});

/**
 * Review finding P1-4. resultBytes() joined the text parts and returned, so an
 * image or any other non-text part was absent from the commitment. A material
 * part of the observed result was simply not in the evidence.
 */
test('FR-06: a mixed text-and-image result is committed in full', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'render_chart', {}),
    ev(2, 'tool/result', {
      toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: [
        { type: 'text', text: 'chart attached' },
        { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgoAAA' } },
      ] },
    }),
  ]);
  const r = fld(store.readChain()[0].record);
  const committed = store.content.get(r.result.cid).toString();
  assert.match(committed, /chart attached/, 'the text is there');
  assert.match(committed, /iVBORw0KGgoAAA/, 'and so is the image');
});

test('FR-06: an all-text result is still committed as plain text', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'transfer_funds', {}),
    ev(2, 'tool/result', { toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: [
        { type: 'text', text: 'OK: transferred ' }, { type: 'text', text: 'ref=TX-77814' }] } }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.equal(store.content.get(r.result.cid).toString(), 'OK: transferred ref=TX-77814');
  assert.deepEqual(store.content.findByRef('TX-77814'), [r.result.cid]);
});

test('FR-06: an image-only result is committed rather than dropped', async () => {
  const { journal, store } = await wired();
  await journal.append([
    call(1, 'tc-1', 'screenshot', {}),
    ev(2, 'tool/result', { toolCallId: 'tc-1',
      result: { type: 'tool_result', toolUseId: 'tc-1', content: [
        { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0K' } }] } }),
  ]);
  const r = fld(store.readChain()[0].record);
  assert.match(store.content.get(r.result.cid).toString(), /iVBORw0K/);
});
