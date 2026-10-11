import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ContentStore, ContentMissing, extractRefs } from '../src/content.mjs';
import { Collector } from '../src/collector.mjs';
import { Store } from '../src/store.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';

const fresh = () => new ContentStore(mkdtempSync(join(tmpdir(), 'splitstick-group-')));

/** Every file under a store root, relative-ish, for counting. */
const files = (root) =>
  readdirSync(root, { recursive: true, withFileTypes: true })
    .filter(d => d.isFile())
    .map(d => join(d.parentPath ?? d.path, d.name));

/**
 * Payloads are appended to one encrypted blob — NFR-01.
 *
 * Creating a file measured p50 0.19 ms and p99 1.04 ms on the development
 * machine, against 0.008 ms and 0.016 ms for a write to an open descriptor. A
 * p99 of 1.04 ms for one file creation means the 1 ms budget is unreachable at
 * p99 for any design that creates a file per record, so the append path creates
 * none. Content addressing here is a commitment, not a storage key — every put
 * salts freshly, so two identical payloads never shared a cid and there was no
 * deduplication to lose.
 */
test('a group appends to the blob and returns one commitment per payload', () => {
  const s = fresh();
  const [args, result] = s.putGroup([
    { bytes: Buffer.from('{"amount":2000000}') },
    { bytes: Buffer.from('OK ref=TX-77814'), index: true },
  ]);
  assert.notEqual(args.cid, result.cid);
  assert.equal(args.bytes, 18);
  assert.equal(result.bytes, 15);
  assert.equal(s.pathFor(args.cid), s.pathFor(result.cid), 'both live in the one blob');
  assert.equal(s.pathFor(args.cid), join(s.root, 'content', 'content.blob'));
  // Distinct, non-overlapping extents.
  const a = s.rangeForTest(args.cid);
  const b = s.rangeForTest(result.cid);
  assert.equal(a.offset + a.length, b.offset);
});

test('the append path creates no file at all once the store is warm', () => {
  const s = fresh();
  s.putGroup([{ bytes: Buffer.from('first') }, { bytes: Buffer.from('OK ref=TX-1'), index: true }]);
  const before = files(s.root).length;
  for (let i = 0; i < 50; i++) {
    s.putGroup([
      { bytes: Buffer.from(`args ${i}`) },
      { bytes: Buffer.from(`OK ref=TX-${i}`), index: true },
    ]);
  }
  assert.equal(files(s.root).length, before,
    'a hundred payloads must add no files — that is the whole point of the layout');
});

test('each payload in a group round-trips independently', () => {
  const s = fresh();
  const [a, b, c] = s.putGroup([
    { bytes: Buffer.from('first') },
    { bytes: Buffer.from('the middle one, which is longer') },
    { bytes: Buffer.from('third') },
  ]);
  assert.equal(s.get(a.cid).toString(), 'first');
  assert.equal(s.get(b.cid).toString(), 'the middle one, which is longer');
  assert.equal(s.get(c.cid).toString(), 'third');
  for (const x of [a, b, c]) assert.equal(s.reproduces(x.cid), true);
});

test('each payload in a group has its own key and its own salt', () => {
  const s = fresh();
  const same = Buffer.from('EUR 2000000');
  const [a, b] = s.putGroup([{ bytes: same }, { bytes: same }]);
  assert.notEqual(a.cid, b.cid, 'identical payloads must not share a commitment');
  s.close();
  const blob = readFileSync(s.pathFor(a.cid));
  assert.ok(!blob.includes('EUR 2000000'), 'and the blob holds no plaintext');
});

test('substituting one payload in a group breaks only that commitment', () => {
  const s = fresh();
  const [a, b] = s.putGroup([{ bytes: Buffer.from('{"amount":2000000}') }, { bytes: Buffer.from('OK') }]);
  s.overwriteForTest(a.cid, Buffer.from('{"amount":25}'));
  assert.equal(s.reproduces(a.cid), false);
  assert.equal(s.reproduces(b.cid), true, 'its sibling is untouched');
});

// FR-36 — erasure is per record, and a record is a group, so the file goes.
test('shredding every commitment leaves no blob behind', () => {
  const s = fresh();
  const [a, b] = s.putGroup([{ bytes: Buffer.from('erase') }, { bytes: Buffer.from('me too') }]);
  const path = s.pathFor(a.cid);
  s.shredAll([a.cid, b.cid]);
  assert.equal(existsSync(path), false, 'the last payload gone means the blob goes');
  assert.equal(s.has(a.cid), false);
  assert.throws(() => s.get(b.cid), ContentMissing);
  assert.equal(s.reproduces(a.cid), null, 'gone by design is inconclusive, never a tamper');
});

// And the partial case, which must not take a sibling down with it.
test('shredding one commitment zeroes its bytes and spares the rest', () => {
  const s = fresh();
  const [a, b] = s.putGroup([
    { bytes: Buffer.from('erase this one please') },
    { bytes: Buffer.from('but keep this one') },
  ]);
  const path = s.pathFor(a.cid);
  const dead = s.rangeForTest(a.cid);
  s.shred(a.cid);
  assert.equal(existsSync(path), true, 'the sibling still needs its bytes');
  assert.equal(s.has(a.cid), false);
  assert.equal(s.get(b.cid).toString(), 'but keep this one');
  assert.equal(s.reproduces(b.cid), true);
  // FR-36 claims the bytes are gone, not merely unreadable. Deleting only the
  // key would have left them recoverable from a key backup.
  s.close();
  const blob = readFileSync(path);
  assert.ok(blob.subarray(dead.offset, dead.offset + dead.length).every(byte => byte === 0),
    'the shredded extent must be zeroed in place');
});

test('a single put is a group of one', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('EUR 2000000'));
  assert.equal(s.get(cid).toString(), 'EUR 2000000');
  assert.equal(s.reproduces(cid), true);
});

test('the key journal survives a reopen', () => {
  const s = fresh();
  const [a, b] = s.putGroup([{ bytes: Buffer.from('one') }, { bytes: Buffer.from('two') }]);
  s.close();
  const reopened = new ContentStore(s.root);
  assert.equal(reopened.get(a.cid).toString(), 'one');
  assert.equal(reopened.get(b.cid).toString(), 'two');
});

// The invariant NFR-01 bought, locked in where it can regress.
test('an action creates no content file, whatever payloads it carries', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-group-'));
  const store = new Store(root, 'host-1');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root),
    signer: await generateDevSigner('o'), collector: 'host-1', origin: 'o' });
  // Warm the store first, including refs.idx, which is one file for the whole
  // store and is created the first time a result carries a reference.
  collector.action({ tool: 't', args: Buffer.from('a'),
    result: Buffer.from('OK ref=TX-1'), correlation: 'c-1' });
  const before = files(root).length;
  collector.action({
    tool: 'transfer_funds',
    agent: Buffer.from('agent:planner@v3'),
    args: Buffer.from('{"amount":2000000}'),
    result: Buffer.from('OK ref=TX-77814'),
    approval: { decision: 'approve', reviewer: Buffer.from('ops@example.com'),
                request: Buffer.from('transfer EUR 2000000?') },
    correlation: 'c-2',
  });
  assert.equal(files(root).length, before, 'five payloads, no new file');
});

// NFR-01's million-event target: a collector that writes and never reads must
// not accumulate a key map it has no use for.
test('writing does not materialise the key map, and a later read still sees everything', () => {
  const s = fresh();
  const cids = [];
  for (let i = 0; i < 20; i++) cids.push(s.put(Buffer.from(`payload ${i}`)).cid);
  assert.equal(s.keysMaterialisedForTest, false, 'a write-only store holds no key map');
  assert.equal(s.get(cids[7]).toString(), 'payload 7', 'and a read finds the journal complete');
  assert.equal(s.keysMaterialisedForTest, true);
  for (let i = 0; i < 20; i++) assert.equal(s.get(cids[i]).toString(), `payload ${i}`);
});

test('extractRefs does not need an exception per plain-text result', () => {
  // Behavioural guard for the allocation fix: plain text, text that starts like
  // JSON but is not, and real JSON must all behave.
  /** @type {[string, string[]][]} */
  const cases = [
    ['transfer complete', []],
    ['{not json at all', []],
    ['{"transaction_id":"TX-77814"}', ['TX-77814']],
    ['[{"ref":"TX-1"}]', ['TX-1']],
    ['see ref=TX-77814 for details', ['TX-77814']],
  ];
  for (const [text, expected] of cases) {
    assert.deepEqual([...extractRefs(Buffer.from(text))].sort(), expected, text);
  }
});
