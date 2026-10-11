import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { genesis, GENESIS_HEX, CHAIN_DOMAIN, chainHead, chainEntry, recomputeChain } from '../src/chain.mjs';
import { leafDigest, newSalt } from '../src/leaf.mjs';
import { action, heartbeat } from './fixtures.mjs';

/** A short collector-scoped log: two runs interleaved, with a heartbeat between. */
function log() {
  const records = [
    action({ record_seq: 1, source_seq: 1, run: 'r-1', correlation: 'c-1' }),
    action({ record_seq: 2, source_seq: 2, run: 'r-2', correlation: 'c-2' }),
    heartbeat({ record_seq: 3 }),
    action({ record_seq: 4, source_seq: 3, run: 'r-1', correlation: 'c-3' }),
  ];
  let prev = genesis();
  return records.map(r => {
    const e = chainEntry(r, newSalt(), prev);
    prev = e.head;
    return e;
  });
}

test('genesis is 32 zero bytes and is not configurable', () => {
  assert.equal(genesis().length, 32);
  assert.equal(genesis().toString('hex'), '00'.repeat(32));
  assert.equal(GENESIS_HEX, '00'.repeat(32));
  // DES-04 rule 3 — writing to a handed-out copy must not move the anchor.
  const borrowed = genesis();
  borrowed[0] = 0xff;
  assert.equal(genesis().toString('hex'), '00'.repeat(32));
  const e = chainEntry(action(), Buffer.alloc(16, 1), genesis());
  assert.equal(recomputeChain([e]).ok, true);
});

test('head = SHA-256(0x02 ‖ prev ‖ leaf), byte-exact', () => {
  assert.equal(CHAIN_DOMAIN, 0x02);
  const salt = Buffer.alloc(16, 3);
  const leaf = leafDigest(salt, action());
  const want = createHash('sha256')
    .update(Buffer.from([0x02])).update(genesis()).update(leaf).digest('hex');
  assert.equal(chainHead(genesis(), leaf).toString('hex'), want);
});

// FR-59 — the ChainEntry wraps the record; it never merges with it.
test('FR-59: the entry holds leaf/prev/head and the record holds none of them', () => {
  const e = chainEntry(action(), newSalt(), genesis());
  for (const f of ['leaf', 'prev', 'head']) assert.ok(e[f], `entry carries ${f}`);
  for (const f of ['leaf', 'prev', 'head', 'salt']) {
    assert.ok(!(f in e.record), `record must not carry ${f}`);
  }
  assert.equal(e.record.record_seq, 1);
});

// FR-56 — one chain per collector, not per run. Concurrent runs interleave.
test('FR-56: two runs and a heartbeat form one contiguous collector-scoped chain', () => {
  const entries = log();
  const r = recomputeChain(entries);
  assert.equal(r.ok, true, JSON.stringify(r.findings));
  assert.deepEqual(entries.map(e => e.record.run), ['r-1', 'r-2', null, 'r-1']);
  assert.equal(r.tree_size, 4);
  assert.equal(r.tree_size, entries.at(-1).record.record_seq, 'record_seq equals tree_size');
});

// SEC-06 / AC-1 / red-team A — alter the recorded action.
test('SEC-06: altering a recorded argument is LEAF_MISMATCH', () => {
  const entries = log();
  entries[1].record.args = { cid: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', bytes: 61 };
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.equal(r.findings[0].code, 'LEAF_MISMATCH');
  assert.equal(r.findings[0].record_seq, 2);
});

test('SEC-06: altering an approval decision is LEAF_MISMATCH', () => {
  const entries = log();
  entries[0].record.approval = { decision: 'approve' };
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.equal(r.findings[0].code, 'LEAF_MISMATCH');
});

test('an altered prev is CHAIN_BROKEN', () => {
  const entries = log();
  entries[2].prev = Buffer.alloc(32, 9);
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'CHAIN_BROKEN'));
});

test('a removed record is SEQ_BROKEN', () => {
  const entries = log();
  entries.splice(1, 1);
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN'), JSON.stringify(r.findings));
});

test('a reordered pair is SEQ_BROKEN', () => {
  const entries = log();
  [entries[1], entries[2]] = [entries[2], entries[1]];
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN'));
});

// SEC-07 / AC-2 / red-team C — alter an event and repair the citing digest.
// Repairing one link is not enough: the chain is recomputed from genesis, so the
// repair propagates and every later head diverges from what was recorded.
test('SEC-07: altering an event and repairing the next prev is still detected', () => {
  const entries = log();
  entries[1].record.args = { cid: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', bytes: 61 };
  entries[1].leaf = leafDigest(entries[1].salt, entries[1].record);   // re-leaf
  entries[1].head = chainHead(entries[1].prev, entries[1].leaf);      // repair own head
  entries[2].prev = entries[1].head;                                  // repair the citation
  const r = recomputeChain(entries);
  assert.equal(r.ok, false, 'the repaired tail must not reconcile');
  assert.ok(r.findings.some(f => f.code === 'CHAIN_BROKEN'));
});

// The honest limit, asserted so it is in the suite rather than only in the prose.
test('a fully rewritten chain is internally perfect — only a pinned head exposes it', () => {
  const original = log();
  const pinned = original.at(-1).head;

  const rewritten = original.map(e => ({ ...e, record: { ...e.record } }));
  rewritten[1].record.args = { cid: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', bytes: 61 };
  let prev = genesis();
  for (const e of rewritten) {
    e.leaf = leafDigest(e.salt, e.record);
    e.prev = prev;
    e.head = chainHead(prev, e.leaf);
    prev = e.head;
  }
  assert.equal(recomputeChain(rewritten).ok, true,
    'DES-04: a consistently rewritten chain verifies from inside — this is why a second party exists');
  assert.notEqual(rewritten.at(-1).head.toString('hex'), pinned.toString('hex'),
    'but its head differs from the one already anchored');
});

// DES-04's third table row, as a test: truncation cannot be detected from inside.
test('a truncated prefix verifies, and the suite says so', () => {
  const entries = log();
  const r = recomputeChain(entries.slice(0, 2));
  assert.equal(r.ok, true, 'a prefix of a valid chain is a valid chain (DES-04)');
  assert.equal(r.tree_size, 2);
});

test('the first entry must cite genesis', () => {
  const entries = log();
  entries[0].prev = Buffer.alloc(32, 1);
  entries[0].head = chainHead(entries[0].prev, entries[0].leaf);
  entries[1].prev = entries[0].head;
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'CHAIN_BROKEN'));
});

// DES-04 rule 2 — the counters are never compared with each other.
test('record_seq and source_seq are never reconciled arithmetically', () => {
  const entries = [];
  let prev = genesis();
  const push = r => { const e = chainEntry(r, newSalt(), prev); prev = e.head; entries.push(e); };
  push(action({ record_seq: 1, source_seq: 1 }));
  for (let i = 2; i <= 101; i++) push(heartbeat({ record_seq: i }));
  push(action({ record_seq: 102, source_seq: 2, correlation: 'c-2' }));
  const r = recomputeChain(entries);
  assert.equal(r.ok, true, 'source_seq 2 against record_seq 102 is not a gap');
  assert.equal(r.tree_size, 102);
});

// FR-62 — an omitted retry shows up as a source_seq gap, independently of record_seq.
test('FR-62: a missing attempt is a source_seq gap, not a chain break', () => {
  const entries = [];
  let prev = genesis();
  const push = r => { const e = chainEntry(r, newSalt(), prev); prev = e.head; entries.push(e); };
  push(action({ record_seq: 1, source_seq: 1, correlation: 'c-1', outcome: 'timeout' }));
  push(action({ record_seq: 2, source_seq: 3, correlation: 'c-1', attempt: 3 }));
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  const f = r.findings.find(x => x.code === 'SEQ_BROKEN');
  assert.ok(f, JSON.stringify(r.findings));
  assert.match(f.detail, /source_seq/);
});

// Found in review: seeding the observation counter with null meant the first
// persisted source_seq was never checked, so an attempt dropped BEFORE the
// first written record was the one hole no verifier could see.
test('an attempt dropped before the first record is still reported', () => {
  const entries = [];
  let prev = genesis();
  const push = r => { const e = chainEntry(r, newSalt(), prev); prev = e.head; entries.push(e); };
  push(action({ record_seq: 1, source_seq: 2, correlation: 'c-1' }));   // 1 was spent, not written
  push(action({ record_seq: 2, source_seq: 3, correlation: 'c-2' }));
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  const f = r.findings.find(x => x.code === 'SEQ_BROKEN');
  assert.ok(f, JSON.stringify(r.findings));
  assert.match(f.detail, /source_seq jumped from 0 to 2/);
});

test('a chain whose first observation is source_seq 1 reports no gap', () => {
  const entries = [];
  let prev = genesis();
  const push = r => { const e = chainEntry(r, newSalt(), prev); prev = e.head; entries.push(e); };
  push(heartbeat({ record_seq: 1 }));
  push(action({ record_seq: 2, source_seq: 1, correlation: 'c-1' }));
  assert.equal(recomputeChain(entries).ok, true, 'a heartbeat first is normal');
});

/**
 * Review finding P2-6. The head check sat in an `else if` after the leaf check,
 * so a record whose salt had been lawfully erased had its chain head checked by
 * nothing. For a record in the middle the break surfaced one position later, as
 * the successor's prev; for the LAST record nothing followed it, so altering
 * the head of a shredded final record was undetectable.
 *
 * The two checks are independent: a leaf needs its salt, a head needs only the
 * prev and the leaf that are already stored. Erasure takes the first away and
 * leaves the second perfectly checkable.
 */
test('the chain head is checked even when the leaf salt is gone', () => {
  const entries = log();
  entries[3].salt = null;                         // lawfully erased
  entries[3].head = Buffer.alloc(32, 0xff);       // and then altered
  const r = recomputeChain(entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'), 'erasure is still inconclusive');
  const broken = r.findings.find(f => f.code === 'CHAIN_BROKEN');
  assert.ok(broken, `the altered head must be caught: ${JSON.stringify(r.findings)}`);
  assert.equal(broken.record_seq, 4, 'and attributed to the record it was altered in');
});

test('an erased record with an intact head is inconclusive and nothing more', () => {
  const entries = log();
  entries[1].salt = null;
  const r = recomputeChain(entries);
  assert.deepEqual(r.findings.map(f => f.code), ['LEAF_INCONCLUSIVE'],
    'lawful erasure must not produce a chain finding');
});

test('an erased record in the middle with an altered head is caught at that record', () => {
  const entries = log();
  entries[1].salt = null;
  entries[1].head = Buffer.alloc(32, 7);
  entries[2].prev = entries[1].head;              // repair the citation too
  const r = recomputeChain(entries);
  const broken = r.findings.filter(f => f.code === 'CHAIN_BROKEN');
  assert.ok(broken.length >= 1);
  assert.equal(broken[0].record_seq, 2, 'the finding belongs to the record that was altered');
});
