import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector, CollectorDegraded } from '../src/collector.mjs';
import { Store } from '../src/store.mjs';
import { StoreBusy } from '../src/content.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { recomputeChain } from '../src/chain.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const chainPath = (root) => join(root, 'chain', 'host-1.jsonl');
const saltsPath = (root) => join(root, 'salts', 'host-1.jsonl');

async function open(root, id = 'host-1') {
  const store = new Store(root, id);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  return { store, collector: new Collector({
    store, config: parseConfig(CFG, root), signer: await generateDevSigner('o'),
    collector: id, origin: 'o', now: () => new Date(t += 1000) }) };
}

const tx = (over = {}) => ({
  tool: 'transfer_funds', args: Buffer.from('{"amount":2000000}'), correlation: 'c-1', ...over,
});

/**
 * Review finding. recover() read through readChain(), which returns the entries
 * it could parse and drops the torn and malformed indicators beside them. So a
 * genuinely short write — real partial bytes on disk, not a thrown exception —
 * was invisible to recovery: it validated the records before the tear, declared
 * success, and the next append landed immediately after the incomplete bytes.
 * A torn tail, which the verifier treats as the ordinary consequence of a crash,
 * became an invalid line in the middle, which it treats as tampering. Recovery
 * turned a recoverable state into a permanent one.
 */
test('recovery repairs a torn chain tail instead of appending after it', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  let { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  store.close();

  // A real short write: a partial line with no terminating newline.
  appendFileSync(chainPath(root), '{"record":{"v":1,"collector":"host-1","record_seq":2,"lea');

  ({ store, collector } = await open(root));
  assert.ok(collector.degraded, 'a torn journal is noticed when the store is opened');

  const repaired = collector.recover();
  assert.equal(repaired.repaired_chain_bytes > 0, true, 'the uncommitted bytes were removed');
  assert.equal(repaired.record_seq, 1);
  assert.equal(collector.degraded, null);

  collector.action(tx({ correlation: 'c-3' }));
  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.deepEqual(detail.malformed, [], 'no line in the middle is broken');
  assert.equal(detail.torn, false);
  assert.deepEqual(detail.entries.map(e => /** @type {any} */ (e.record).record_seq), [1, 2]);
  assert.equal(recomputeChain(detail.entries).ok, true);
});

/**
 * And the same for the salt journal, which is now the FIRST write and therefore
 * the likelier half to be torn. #readSalts() parsed every line eagerly, so an
 * incomplete one threw out of readChainDetailed, out of tip(), and out of the
 * Collector constructor — after a torn salt write the store could not even be
 * opened, and the verifier crashed on it too. That was a regression introduced
 * by reordering the writes.
 */
test('a torn salt line does not stop the store being read or opened', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  store.close();
  appendFileSync(saltsPath(root), '{"record_seq":2,"sal');

  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.equal(detail.entries.length, 1, 'the committed record is still readable');
  assert.equal(detail.salts_torn, true);

  const reopened = await open(root);
  assert.ok(reopened.collector.degraded, 'and the damage is reported, not thrown');
  const repaired = reopened.collector.recover();
  assert.ok(repaired.repaired_salts_bytes > 0);
  reopened.collector.action(tx({ correlation: 'c-2' }));
  const after = new Store(root, 'host-1').readChainDetailed();
  assert.equal(after.salts_torn, false);
  assert.equal(recomputeChain(after.entries).ok, true, 'and both records verify, salts included');
});

test('recovery refuses a broken line in the middle, which is not a crash artifact', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));
  store.close();

  const lines = readFileSync(chainPath(root), 'utf8').trim().split('\n');
  lines.splice(1, 0, '{"record":{"v":1},"lea');          // a complete, broken line
  writeFileSync(chainPath(root), lines.join('\n') + '\n');

  const reopened = await open(root);
  assert.throws(() => reopened.collector.recover(), /refusing to resume/);
  assert.ok(reopened.collector.degraded, 'and it stays degraded rather than writing on top');
});

test('repair never removes a committed record', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));
  store.close();
  const before = readFileSync(chainPath(root), 'utf8');

  const reopened = await open(root);
  const r = reopened.collector.recover();
  assert.equal(r.repaired_chain_bytes, 0, 'an intact journal needs no repair');
  assert.equal(readFileSync(chainPath(root), 'utf8'), before);
  assert.equal(r.record_seq, 2);
});

/**
 * Review finding. The collector-scoped lock was acquired by
 * ContentStore.putGroup(), so a record that externalises nothing — a heartbeat,
 * a padding leaf, a gap or a policy change — took no lock at all. Two writers
 * sharing a collector identity both wrote record_seq 1 from genesis, and the
 * verifier reported LEAF_MISMATCH, SEQ_BROKEN and CHAIN_BROKEN: two honest
 * collectors, one corrupt log, read as tampering.
 */
test('two writers on one collector are refused, even with no payloads at all', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const first = await open(root, 'host-1');
  first.collector.heartbeat();

  const second = await open(root, 'host-1');
  // Every kind, including the ones that externalise nothing. And it stays
  // StoreBusy on each attempt: a lock conflict is not local damage, so the
  // second writer must not be told to recover() from a condition recovery
  // cannot address.
  assert.throws(() => second.collector.heartbeat(), StoreBusy);
  assert.throws(() => second.collector.padding(), StoreBusy);
  assert.throws(() => second.collector.gap({ from_source_seq: 1, to_source_seq: 2 }), StoreBusy);
  assert.throws(() => second.collector.policy({
    previous: 'sha256:' + 'aa'.repeat(32), next: 'sha256:' + 'bb'.repeat(32) }), StoreBusy);
  assert.throws(() => second.collector.action(tx({ correlation: 'c-x' })), StoreBusy);
  assert.equal(second.collector.degraded, null, 'and it is not degraded, only refused');

  first.collector.padding();
  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.deepEqual(detail.entries.map(e => /** @type {any} */ (e.record).record_seq), [1, 2]);
  assert.equal(recomputeChain(detail.entries).ok, true);
});

test('two writers on different collectors both proceed', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const a = await open(root, 'host-a');
  const b = await open(root, 'host-b');
  for (let i = 0; i < 3; i++) {
    a.collector.heartbeat();
    b.collector.action(tx({ correlation: `b-${i}` }));
  }
  for (const { store } of [a, b]) {
    assert.equal(recomputeChain(store.readChain()).ok, true);
    assert.equal(store.readChain().length, 3);
  }
});

test('the lock is released on close, so a restart takes over', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const first = await open(root, 'host-1');
  first.collector.heartbeat();
  first.store.close();

  const second = await open(root, 'host-1');
  second.collector.heartbeat();
  assert.equal(recomputeChain(second.store.readChain()).ok, true);
  assert.deepEqual(second.store.readChain().map(e => /** @type {any} */ (e.record).record_seq), [1, 2]);
});

test('a degraded collector refuses content-free records too', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.heartbeat();
  const real = store.append.bind(store);
  store.append = () => { throw new Error('EIO'); };
  assert.throws(() => collector.heartbeat(), /EIO/);
  store.append = real;
  assert.throws(() => collector.heartbeat(), CollectorDegraded);
  assert.throws(() => collector.padding(), CollectorDegraded);
});

/**
 * Review finding. A torn tail was recognised only when the JSON failed to
 * parse. But a write can persist the whole object and fail before its trailing
 * newline, leaving a COMPLETE, valid record with no terminator — which was
 * accepted as committed, left the journal unmarked, and allowed the next append
 * to concatenate onto it. The probe lost a record outright: two entries before,
 * one entry and one malformed line after.
 *
 * The newline is the commit marker. A journal that does not end with one has an
 * uncommitted trailing write, whether or not the bytes before it happen to
 * parse — and it is not completed on recovery, because the writer that failed
 * has already reported failure upstream and must not have a record appear
 * anyway.
 */
test('a complete record with no trailing newline is uncommitted, not accepted', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  store.close();

  const committed = readFileSync(chainPath(root), 'utf8');
  const full = committed.trim().replace('"record_seq":1', '"record_seq":2');
  appendFileSync(chainPath(root), full);            // valid JSON, no newline

  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.equal(detail.torn, true, 'a missing terminator is a torn tail');
  assert.equal(detail.entries.length, 1, 'and the unterminated record is not an entry');

  const reopened = await open(root);
  assert.ok(reopened.collector.degraded);
  const r = reopened.collector.recover();
  assert.ok(r.repaired_chain_bytes > 0);
  assert.equal(readFileSync(chainPath(root), 'utf8'), committed, 'exactly the committed bytes remain');

  reopened.collector.action(tx({ correlation: 'c-3' }));
  const after = new Store(root, 'host-1').readChainDetailed();
  assert.deepEqual(after.malformed, [], 'nothing was concatenated');
  assert.deepEqual(after.entries.map(e => /** @type {any} */ (e.record).record_seq), [1, 2]);
  assert.equal(recomputeChain(after.entries).ok, true);
});

test('the same rule applies to the salt journal', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  collector.action(tx({ correlation: 'c-1' }));
  store.close();

  const committed = readFileSync(saltsPath(root), 'utf8');
  appendFileSync(saltsPath(root), committed.trim().replace('"record_seq":1', '"record_seq":2'));

  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.equal(detail.salts_torn, true);
  const reopened = await open(root);
  assert.ok(reopened.collector.degraded);
  assert.ok(reopened.collector.recover().repaired_salts_bytes > 0);
  assert.equal(readFileSync(saltsPath(root), 'utf8'), committed);
});

test('an intact journal is never mistaken for a torn one', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { store, collector } = await open(root);
  for (let i = 0; i < 3; i++) collector.action(tx({ correlation: `c-${i}` }));
  store.close();
  const detail = new Store(root, 'host-1').readChainDetailed();
  assert.equal(detail.torn, false);
  assert.equal(detail.salts_torn, false);
  assert.equal(detail.entries.length, 3);
  const reopened = await open(root);
  assert.equal(reopened.collector.degraded, null);
  assert.equal(reopened.collector.recover().repaired_chain_bytes, 0);
});

test('an empty journal is not torn', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-rec-'));
  const { collector } = await open(root);
  assert.equal(collector.degraded, null);
  collector.action(tx({ correlation: 'c-1' }));
  assert.equal(new Store(root, 'host-1').readChainDetailed().torn, false);
});
