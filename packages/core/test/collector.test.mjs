import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '../src/collector.mjs';
import { Store } from '../src/store.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { recomputeChain, genesis } from '../src/chain.mjs';
import { RECORD_KINDS } from '../src/record.mjs';
import { treeRoot } from '../src/merkle.mjs';
import { parseNote, parseCheckpointText } from '../src/note.mjs';
import { verifyNoteSignature } from '../src/signer.mjs';

/** The record is typed Record<string, unknown>; tests read fields off it freely.
 * @param {{ record: Record<string, any> }} e @returns {Record<string, any>} */
const rec = e => e.record;

const CFG = 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nanchor_interval: 10s\n';

async function fresh(opts = {}) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-collector-'));
  const config = parseConfig(CFG, root);
  const signer = await generateDevSigner('splitstick.dev/host-1');
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config, signer, collector: 'host-1',
    origin: 'splitstick.dev/host-1', now: () => new Date(t += 1000), ...opts });
  return { root, store, signer, collector: c, advance: ms => { t += ms; } };
}

/** @returns {Parameters<Collector['action']>[0]} */
const tx = (/** @type {Record<string, unknown>} */ over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  agent: Buffer.from('agent:planner@v3'),
  args: Buffer.from('{"amount":2000000,"iban":"DE89370400440532013000"}'),
  result: Buffer.from('OK: transferred EUR 2000000 ref=TX-77814'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-0001', ...over,
});

test('an action is chained, salted and written, and the record holds commitments only', async () => {
  const { collector, store } = await fresh();
  const e = collector.action(tx());
  assert.equal(e.record.record_seq, 1);
  assert.equal(e.record.source_seq, 1);
  assert.equal(e.record.kind, 'tool_call');
  assert.match(rec(e).args.cid, /^sha256:[0-9a-f]{64}$/);
  assert.equal(rec(e).args.bytes, 50);
  assert.equal(e.prev.toString('hex'), genesis().toString('hex'));
  assert.equal(recomputeChain(store.readChain()).ok, true);
});

// PRIV-02 — the scan FR-35 and PRIV-02 both ask for, over everything in chain/.
test('PRIV-02: no payload byte from the fixture appears anywhere in chain/', async () => {
  const { collector, root } = await fresh();
  collector.action(tx());
  collector.action(tx({ attempt: 2, correlation: 'c-0002', result: Buffer.from('DENIED: limit exceeded') }));
  await collector.checkpoint();

  const needles = ['2000000', 'DE89370400440532013000', 'TX-77814', 'planner@v3',
                   'DENIED', 'limit exceeded'];
  const chainDir = join(root, 'chain');
  for (const f of readdirSync(chainDir)) {
    const text = readFileSync(join(chainDir, f), 'utf8');
    for (const n of needles) assert.ok(!text.includes(n), `${f} leaks ${n}`);
  }
  // Including the short inline-sized argument, which is the clause an earlier
  // draft of PRIV-02 would have passed while still leaking.
  const small = collector.action(tx({ correlation: 'c-0003', args: Buffer.from('25') }));
  assert.ok(!readFileSync(join(chainDir, 'host-1.jsonl'), 'utf8').includes('"25"'));
  assert.equal(rec(small).args.bytes, 2);
});

test('the content is still recoverable from the deletable store', async () => {
  const { collector, store } = await fresh();
  const e = collector.action(tx());
  assert.equal(store.content.get(rec(e).result.cid).toString(),
    'OK: transferred EUR 2000000 ref=TX-77814');
  // FR-55 — and the external reference is indexed for reconciliation.
  assert.deepEqual(store.content.findByRef('TX-77814'), [rec(e).result.cid]);
});

// DES-04 rule 2 — record_seq equals tree_size, always.
test('record_seq equals tree_size including heartbeats and padding', async () => {
  const { collector } = await fresh();
  collector.action(tx());
  collector.heartbeat();
  collector.heartbeat();
  collector.padding();
  const last = collector.action(tx({ correlation: 'c-0002' }));
  assert.equal(last.record.record_seq, 5);
  assert.equal(collector.tree_size, 5);
  assert.equal(last.record.source_seq, 2, 'only the two actions consumed a source_seq');
});

test('FR-56: two concurrent runs and a run-less heartbeat form one chain', async () => {
  const { collector, store } = await fresh();
  collector.action(tx({ run: 'r-1', correlation: 'c-1' }));
  collector.action(tx({ run: 'r-2', correlation: 'c-2' }));
  collector.heartbeat();
  collector.action(tx({ run: 'r-1', correlation: 'c-3' }));
  const entries = store.readChain();
  assert.deepEqual(entries.map(e => e.record.run), ['r-1', 'r-2', null, 'r-1']);
  assert.equal(recomputeChain(entries).ok, true);
});

// FR-62 — retries of one logical action, grouped by correlation, not by the counter.
test('FR-62: interleaved retries keep source_seq strictly increasing', async () => {
  const { collector, store } = await fresh();
  collector.action(tx({ correlation: 'c-A', attempt: 1, outcome: 'timeout' }));
  collector.action(tx({ correlation: 'c-B', attempt: 1, outcome: 'error' }));
  collector.action(tx({ correlation: 'c-A', attempt: 2, outcome: 'ok' }));
  collector.action(tx({ correlation: 'c-B', attempt: 2, outcome: 'ok' }));
  const recs = store.readChain().map(e => e.record);
  assert.deepEqual(recs.map(r => r.source_seq), [1, 2, 3, 4]);
  assert.deepEqual(recs.map(r => r.correlation), ['c-A', 'c-B', 'c-A', 'c-B']);
  assert.deepEqual(recs.map(r => r.attempt), [1, 1, 2, 2]);
  assert.equal(recomputeChain(store.readChain()).ok, true);
});

// The counter advances on every attempt OBSERVED, written or not — which is what
// makes an unwritten attempt visible instead of invisible.
test('an observed attempt that was never written leaves a source_seq gap', async () => {
  const { collector, store } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  collector.observe();                       // observed, then dropped
  collector.action(tx({ correlation: 'c-2' }));
  const r = recomputeChain(store.readChain());
  assert.equal(r.ok, false);
  const f = r.findings.find(x => x.code === 'SEQ_BROKEN');
  assert.ok(f, JSON.stringify(r.findings));
  assert.match(f.detail, /1 observed attempt\(s\) were never written/);
});

test('FR-07: an approval decision and its reviewer are recorded, the reviewer as a commitment', async () => {
  const { collector, store } = await fresh();
  const e = collector.action(tx({
    approval: { decision: 'approve', reviewer: Buffer.from('ops@example.com'),
                request: Buffer.from('transfer EUR 2000000?') },
  }));
  assert.equal(rec(e).approval.decision, 'approve');
  assert.match(rec(e).approval.reviewer.cid, /^sha256:/);
  assert.ok(!JSON.stringify(e.record).includes('ops@example.com'));
  assert.equal(store.content.get(rec(e).approval.reviewer.cid).toString(), 'ops@example.com');
});

test('a heartbeat carries no run and no source_seq', async () => {
  const { collector } = await fresh();
  const e = collector.heartbeat();
  assert.equal(e.record.kind, 'heartbeat');
  assert.equal(e.record.run, null);
  assert.equal(e.record.source_seq, null);
  assert.ok(e.record.build, 'a heartbeat carries the build digest it is attesting');
});

test('a gap declaration carries the span it lost; gap_unknown never does', async () => {
  const { collector } = await fresh();
  const g = collector.gap({ from_source_seq: 5, to_source_seq: 9 });
  assert.equal(g.record.from_source_seq, 5);
  const u = collector.gapUnknown({ last_checkpoint_source_seq: 4 });
  assert.equal(u.record.kind, 'gap_unknown');
  assert.ok(u.record.from_ts && u.record.to_ts);
  assert.ok(!('from_source_seq' in u.record), 'FR-60: inventing a span asserts what was lost');
});

// FR-10 — the checkpoint is a signed note over the RFC 6962 root of the whole log.
test('FR-10: a checkpoint signs the note, and the note binds origin, size and root', async () => {
  const { collector, store, signer, root } = await fresh();
  for (let i = 0; i < 5; i++) collector.action(tx({ correlation: `c-${i}` }));
  const cp = await collector.checkpoint();

  assert.equal(cp.checkpoint_seq, 1, 'checkpoint_seq is an ordinal');
  // The artefact on disk is a DES-20 envelope; the note is inside it.
  const blob = JSON.parse(
    readFileSync(join(root, 'checkpoints', 'host-1', '1.json'), 'utf8')).note;
  const note = parseNote(blob);
  const text = parseCheckpointText(note.text);
  assert.equal(text.origin, 'splitstick.dev/host-1');
  assert.equal(text.tree_size, 5, 'tree_size is the record count, not a batch count');
  assert.equal(text.root.toString('hex'),
    treeRoot(store.readChain().map(e => e.leaf)).toString('hex'));
  assert.equal(await verifyNoteSignature(note.text, note.signatures[0], signer.verifier()), true);
});

test('a second checkpoint covers the whole log, not just the new records', async () => {
  const { collector, store } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  const first = await collector.checkpoint();
  collector.action(tx({ correlation: 'c-2' }));
  const second = await collector.checkpoint();
  assert.equal(second.checkpoint_seq, 2);
  assert.equal(second.tree_size, 2);
  assert.notEqual(first.root.toString('hex'), second.root.toString('hex'));
  assert.equal(second.root.toString('hex'),
    treeRoot(store.readChain().map(e => e.leaf)).toString('hex'));
});

test('checkpointing an empty log is refused rather than signing nothing', async () => {
  const { collector } = await fresh();
  await assert.rejects(() => collector.checkpoint(), /nothing to checkpoint/);
});

test('a reopened store continues the chain rather than restarting it', async () => {
  const { root, collector, store, signer } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));
  const head = collector.head.toString('hex');
  // Hand over properly. A second writer on a live store is refused now, which
  // is the point: this used to be the shape that silently overwrote extents.
  store.close();

  const reopened = new Collector({
    store: new Store(root, 'host-1'), config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: 'splitstick.dev/host-1',
  });
  assert.equal(reopened.tree_size, 2);
  assert.equal(reopened.head.toString('hex'), head);
  assert.equal(reopened.sourceSeq, 2);
  const e = reopened.action(tx({ correlation: 'c-3' }));
  assert.equal(e.record.record_seq, 3);
  assert.equal(e.record.source_seq, 3);
  assert.equal(e.prev.toString('hex'), head);
  assert.equal(recomputeChain(new Store(root, 'host-1').readChain()).ok, true);
});

test('the chain file is append-only: an earlier line is never rewritten', async () => {
  const { collector, root } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  const before = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8');
  collector.action(tx({ correlation: 'c-2' }));
  const after = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8');
  assert.ok(after.startsWith(before), 'the existing prefix must be byte-identical');
});

test('salts live outside the chain and are per-record deletable', async () => {
  const { collector, store, root } = await fresh();
  const a = collector.action(tx({ correlation: 'c-1' }));
  const b = collector.action(tx({ correlation: 'c-2' }));
  assert.ok(existsSync(join(root, 'salts', 'host-1.jsonl')));
  const chainText = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8');
  assert.ok(!chainText.includes(a.salt.toString('hex')), 'a salt in the chain could never be shredded');

  store.shredRecord(2);
  const entries = store.readChain();
  assert.equal(entries[1].salt, null);
  const r = recomputeChain(entries);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].code, 'LEAF_INCONCLUSIVE', 'erasure is inconclusive, never a tamper');
  assert.equal(entries[0].salt.toString('hex'), a.salt.toString('hex'), 'and only that record');
  assert.equal(b.record.record_seq, 2);
});

test('the collector never receives key material, only a signing function', async () => {
  const { collector } = await fresh();
  const signer = collector.signer;
  assert.equal(typeof signer.sign, 'function');
  for (const k of Object.keys(signer)) {
    assert.ok(!/private|secret|seed/i.test(k), `signer exposes ${k}`);
  }
  assert.ok(!JSON.stringify(signer).includes('PRIVATE KEY'));
});

// FR-62 — correlation lives in core, not in each adapter: DES-14 forbids an
// adapter touching cryptography, and two adapters numbering attempts
// independently would produce packs that disagree about one logical action.
//
// The key is supplied by the caller and is never derived from the payload. A
// review found the earlier payload-keyed version grouping two independent
// transfers of the same amount as attempts of one action, and leaking payload
// equality through a field DES-13 retains after erasure.
test('FR-62: correlate groups the attempts the source says belong together', async () => {
  const { collector } = await fresh();
  const a = collector.correlate('oma:retry-chain-7');
  const b = collector.correlate('oma:retry-chain-7');
  assert.equal(a.correlation, b.correlation);
  assert.deepEqual([a.attempt, b.attempt], [1, 2]);

  const other = collector.correlate('oma:retry-chain-8');
  assert.notEqual(other.correlation, a.correlation);
  assert.equal(other.attempt, 1);
});

test('FR-62: a correlation key is never derived from the payload', async () => {
  const { collector } = await fresh();
  assert.throws(() => collector.correlate(''), TypeError);
  assert.throws(() => collector.correlate(/** @type {never} */ (undefined)), TypeError);
  // Two actions with identical arguments get unrelated correlations unless the
  // caller says otherwise, which is the whole point.
  const fresh1 = Collector.newCorrelation();
  const fresh2 = Collector.newCorrelation();
  assert.notEqual(fresh1, fresh2);
  assert.match(fresh1, /^[0-9a-f]{24}$/);
});

test('a correlation identifier is opaque and carries nothing — DES-13', async () => {
  const { collector } = await fresh();
  const { correlation } = collector.correlate('oma:tc-1');
  assert.match(correlation, /^[0-9a-f]{24}$/);
  for (const n of ['2000000', 'DE89', 'transfer', 'tc-1']) assert.ok(!correlation.includes(n));
  const { collector: second } = await fresh();
  assert.notEqual(second.correlate('oma:tc-1').correlation, correlation,
    'and the same key in another collector is a different identifier');
});


// DES-13 retains result.ok: a boolean outcome identifies nobody, and a verifier
// needs it once the payload itself has been crypto-shredded.
test('a result commitment carries ok, and it tracks the outcome', async () => {
  const { collector } = await fresh();
  assert.equal(rec(collector.action(tx({ correlation: 'c-1' }))).result.ok, true);
  assert.equal(rec(collector.action(tx({ correlation: 'c-2', outcome: 'error' }))).result.ok, false);
  assert.equal(rec(collector.action(tx({ correlation: 'c-3', outcome: 'timeout' }))).result.ok, false);
});

/**
 * Found in review, and the worst failure mode this product has.
 *
 * #envelope incremented record_seq before the record was validated, so a single
 * rejected record left a permanent hole: record_seq started at 2, and
 * recomputeChain reported SEQ_BROKEN for the rest of that collector's life.
 * Combined with the adapter's fail-open catch, any unexpected shape from
 * upstream turned the whole log into "tampering detected" forever — a verifier
 * crying wolf, which is exactly what DES-12's three verdicts exist to avoid.
 *
 * record_seq must equal tree_size (DES-04 rule 2), so it may only advance when
 * a record is actually written. source_seq is different and is SUPPOSED to be
 * spent: an attempt was observed, and the hole is the report.
 */
test('a rejected record leaves record_seq intact and the chain verifiable', async () => {
  const { collector, store } = await fresh();
  assert.throws(() => collector.action(tx({ correlation: 'c-0', outcome: 'maybe' })), /outcome/);
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));

  const recs = store.readChain().map(e => rec(e));
  assert.deepEqual(recs.map(r => r.record_seq), [1, 2], 'record_seq must equal tree_size');
  assert.equal(collector.tree_size, 2);

  const r = recomputeChain(store.readChain());
  const broken = r.findings.filter(f => /record_seq jumped/.test(f.detail));
  assert.deepEqual(broken, [], 'a rejected record must not look like a removed one');

  // The observed-but-unwritten attempt IS reported, which is correct: it says
  // one attempt was seen and never recorded.
  assert.deepEqual(recs.map(r => r.source_seq), [2, 3]);
  const gap = r.findings.find(f => /source_seq/.test(f.detail));
  assert.ok(gap, 'the spent source_seq is still reported');
  assert.match(gap.detail, /1 observed attempt\(s\) were never written/);
});

test('a rejected record leaves no orphan in the chain or the head', async () => {
  const { collector, store } = await fresh();
  const first = collector.action(tx({ correlation: 'c-1' }));
  assert.throws(() => collector.action(tx({ correlation: 'c-2', outcome: 'nope' })));
  assert.equal(collector.head.toString('hex'), first.head.toString('hex'),
    'the head must not move for a record that was never written');
  const next = collector.action(tx({ correlation: 'c-3' }));
  assert.equal(next.prev.toString('hex'), first.head.toString('hex'));
  assert.equal(recomputeChain(store.readChain()).findings.filter(f => f.code === 'CHAIN_BROKEN').length, 0);
});

// The emitters must satisfy the schema they write to. policy() and gapUnknown()
// had no test and the schema had no requirements, so neither side was checked.
test('every record kind the collector emits validates', async () => {
  const { collector, store } = await fresh();
  const d = (b) => 'sha256:' + b.repeat(32);
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2', kind: 'approval',
    approval: { decision: 'deny', reviewer: Buffer.from('ops@example.com') }, outcome: 'denied' }));
  collector.heartbeat();
  collector.heartbeat({ policy: d('cc') });
  collector.padding();
  collector.gap({ from_source_seq: 3, to_source_seq: 7 });
  collector.gapUnknown({ last_checkpoint_source_seq: 2 });
  collector.policy({ previous: d('aa'), next: d('bb') });
  collector.custody();

  const kinds = store.readChain().map(e => rec(e).kind);
  assert.deepEqual(kinds,
    ['tool_call', 'approval', 'heartbeat', 'heartbeat', 'padding', 'gap', 'gap_unknown',
      'policy', 'custody']);
  assert.deepEqual([...new Set(kinds)].sort(), [...RECORD_KINDS].sort(),
    'and between them they cover the whole enum, so none is unexercised');
  const r = recomputeChain(store.readChain());
  assert.equal(r.ok, true, JSON.stringify(r.findings));
});
