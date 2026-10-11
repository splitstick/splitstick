import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, appendFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector, CollectorDegraded } from '../src/collector.mjs';
import { Store } from '../src/store.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { recomputeChain } from '../src/chain.mjs';

const CFG = 'version: 1\nstore: ./s\n';

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-fail-'));
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const collector = new Collector({
    store, config: parseConfig(CFG, root), signer: await generateDevSigner('o'),
    collector: 'host-1', origin: 'o', now: () => new Date(t += 1000),
  });
  return { root, store, collector };
}

const tx = (over = {}) => ({
  tool: 'transfer_funds', args: Buffer.from('{"amount":2000000}'),
  result: Buffer.from('OK ref=TX-77814'), correlation: 'c-1', ...over,
});

/**
 * Review finding: an observed action could be lost without consuming
 * source_seq.
 *
 * action() externalised the payloads before calling observe(), so a storage
 * failure threw with the counter untouched. The adapter catches and the agent
 * continues — correctly — and the next action then took the next consecutive
 * number, leaving a verifier nothing to see. A consequential action that was
 * observed and not recorded is the single thing this counter exists to expose.
 *
 * Fault-injected through the real ContentStore rather than by calling observe()
 * by hand, because the ordering inside action() is the thing under test.
 */
test('a content-storage failure still spends the observation', async () => {
  const { store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));

  const real = store.content.putGroup.bind(store.content);
  store.content.putGroup = () => { throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' }); };
  assert.throws(() => collector.action(tx({ correlation: 'c-dropped' })), /ENOSPC/);
  store.content.putGroup = real;

  collector.action(tx({ correlation: 'c-3' }));

  const recs = store.readChain().map(e => /** @type {any} */ (e.record));
  assert.deepEqual(recs.map(r => r.source_seq), [1, 3], 'the dropped attempt spent number 2');
  assert.deepEqual(recs.map(r => r.record_seq), [1, 2], 'but no record_seq, because nothing was written');

  const r = recomputeChain(store.readChain());
  const gap = r.findings.find(f => /source_seq/.test(f.detail));
  assert.ok(gap, `the loss must be visible: ${JSON.stringify(r.findings)}`);
  assert.match(gap.detail, /1 observed attempt\(s\) were never written/);
});

test('a rejected record also spends the observation but not the sequence', async () => {
  const { store, collector } = await fresh();
  assert.throws(() => collector.action(tx({ outcome: 'maybe' })), /outcome/);
  collector.action(tx({ correlation: 'c-2' }));
  const recs = store.readChain().map(e => /** @type {any} */ (e.record));
  assert.deepEqual(recs.map(r => r.record_seq), [1]);
  assert.deepEqual(recs.map(r => r.source_seq), [2]);
});

/**
 * Review finding: a partial journal write could leave the live collector
 * inconsistent.
 *
 * append() wrote the chain entry and its salt to separate files. If the second
 * write failed the first was already committed, and #write threw before
 * advancing head and recordSeq — so the next append reused the sequence and the
 * stale predecessor, and recomputeChain reported SEQ_BROKEN from then on. A
 * disk-full incident became a permanent accusation of tampering, which is the
 * same shape of defect as the earlier record_seq bug and the opposite of what
 * a verifier is for.
 *
 * Two changes. The salt is written FIRST, so the chain line is the commit point
 * and the only possible partial state is an orphan salt, which is harmless.
 * And an append that fails marks the collector degraded: it refuses further
 * writes rather than continuing from state it cannot trust, until recover()
 * re-reads what is actually on disk.
 */
test('a failed append degrades the collector instead of corrupting the chain', async () => {
  const { store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  const headBefore = collector.head.toString('hex');

  const real = store.append.bind(store);
  store.append = () => { throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' }); };
  assert.throws(() => collector.action(tx({ correlation: 'c-2' })), /ENOSPC/);
  store.append = real;

  assert.ok(collector.degraded, 'the collector knows it cannot trust its own state');
  assert.equal(collector.head.toString('hex'), headBefore, 'and did not advance');

  // It refuses to keep writing from state it cannot trust.
  assert.throws(() => collector.action(tx({ correlation: 'c-3' })), CollectorDegraded);
  assert.equal(store.readChain().length, 1, 'nothing further was written');
});

test('recover() re-reads what is on disk and resumes cleanly', async () => {
  const { store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));

  const real = store.append.bind(store);
  store.append = () => { throw new Error('EIO'); };
  assert.throws(() => collector.action(tx({ correlation: 'c-3' })));
  store.append = real;

  const resumed = collector.recover();
  assert.equal(resumed.record_seq, 2);
  assert.equal(collector.degraded, null);

  collector.action(tx({ correlation: 'c-4' }));
  const recs = store.readChain().map(e => /** @type {any} */ (e.record));
  assert.deepEqual(recs.map(r => r.record_seq), [1, 2, 3], 'the sequence continues, never repeats');
  const r = recomputeChain(store.readChain());
  assert.deepEqual(r.findings.filter(f => f.code === 'SEQ_BROKEN' && /record_seq/.test(f.detail)), [],
    'a storage failure must not read as a removed event');
  assert.ok(r.findings.some(f => /source_seq/.test(f.detail)), 'the lost attempt is still reported');
});

test('recover() refuses when the chain on disk is itself inconsistent', async () => {
  const { root, store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  const real = store.append.bind(store);
  store.append = () => { throw new Error('EIO'); };
  assert.throws(() => collector.action(tx({ correlation: 'c-2' })));
  store.append = real;

  // Something wrote a duplicate sequence into the file while we were down.
  const path = join(root, 'chain', 'host-1.jsonl');
  appendFileSync(path, readFileSync(path, 'utf8').trim() + '\n');
  assert.throws(() => collector.recover(), /inconsisten/i);
  assert.ok(collector.degraded, 'and it stays degraded rather than resuming on a broken chain');
});

// The benign partial state the new ordering leaves behind, asserted directly.
test('an orphan salt entry is harmless to a verifier', async () => {
  const { root, store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  collector.action(tx({ correlation: 'c-2' }));
  store.close();
  appendFileSync(join(root, 'salts', 'host-1.jsonl'),
    JSON.stringify({ record_seq: 3, salt: 'aa'.repeat(16) }) + '\n');

  const reopened = new Store(root, 'host-1');
  const r = recomputeChain(reopened.readChain());
  assert.equal(r.ok, true, 'a salt for a record that was never written says nothing');
  assert.equal(r.tree_size, 2);
});

test('the salt is written before the chain line, so the chain is the commit point', async () => {
  const { root, store, collector } = await fresh();
  collector.action(tx({ correlation: 'c-1' }));
  store.close();
  const salts = readFileSync(join(root, 'salts', 'host-1.jsonl'), 'utf8').trim().split('\n');
  const chain = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8').trim().split('\n');
  assert.equal(salts.length, 1);
  assert.equal(chain.length, 1);
  assert.equal(recomputeChain(new Store(root, 'host-1').readChain()).ok, true);
});

/**
 * Review observation: ContentStore took a root-wide write lock, so two
 * simultaneously active collectors in one store root could not both write
 * payloads. Scoping the content store to the collector — as the chain, the
 * salts and now the checkpoints already are — removes the contention instead of
 * documenting it as unsupported.
 */
test('two collectors are simultaneously active in one store root', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-fail-'));
  const made = [];
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    made.push({ id, store, collector: new Collector({
      store, config: parseConfig(CFG, root), signer: await generateDevSigner(`o/${id}`),
      collector: id, origin: `o/${id}` }) });
  }
  // Interleaved, both live at once — neither has closed.
  for (let i = 0; i < 3; i++) {
    for (const { id, collector } of made) {
      collector.action(tx({ correlation: `${id}-${i}` }));
    }
  }
  for (const { id, store } of made) {
    const r = recomputeChain(store.readChain());
    assert.equal(r.ok, true, `${id}: ${JSON.stringify(r.findings)}`);
    assert.equal(r.tree_size, 3);
    const recs = store.readChain().map(e => /** @type {any} */ (e.record));
    assert.equal(store.content.get(recs[0].args.cid).toString(), '{"amount":2000000}');
  }
  for (const { store } of made) store.close();
});

test('each collector owns its own content, keys and reference index', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-fail-'));
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    const c = new Collector({ store, config: parseConfig(CFG, root),
      signer: await generateDevSigner(`o/${id}`), collector: id, origin: `o/${id}` });
    c.action(tx({ correlation: 'c-1', result: Buffer.from(`OK ref=TX-${id}`) }));
    store.close();
  }
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    assert.deepEqual(store.content.findByRef(`TX-${id}`).length, 1, `${id} sees its own reference`);
    const other = id === 'host-a' ? 'host-b' : 'host-a';
    assert.deepEqual(store.content.findByRef(`TX-${other}`), [],
      'and not the other collector\'s');
    assert.ok(existsSync(join(root, 'content', id, 'content.blob')));
  }
});
