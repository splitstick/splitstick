import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { ContentStore, contentCid, CONTENT_DOMAIN, extractRefs, ContentMissing } from '../src/content.mjs';
import { walkFiles } from './walk.mjs';

const fresh = () => new ContentStore(mkdtempSync(join(tmpdir(), 'splitstick-content-')));

test('cid = SHA-256(0x05 ‖ content_salt ‖ plaintext), byte-exact', () => {
  assert.equal(CONTENT_DOMAIN, 0x05);
  const salt = Buffer.from('0f0e0d0c0b0a09080706050403020100', 'hex');
  const plain = Buffer.from('OK: transferred EUR 2000000 ref=TX-77814');
  const want = createHash('sha256')
    .update(Buffer.from([0x05])).update(salt).update(plain).digest('hex');
  assert.equal(contentCid(salt, plain), `sha256:${want}`);
});

test('the same plaintext under different salts gets different cids', () => {
  const s = fresh();
  const plain = Buffer.from('EUR 2000000');
  assert.notEqual(s.put(plain).cid, s.put(plain).cid);
});

test('a commitment carries the cid and the byte length, and nothing else', () => {
  const s = fresh();
  const c = s.put(Buffer.from('EUR 2000000'));
  assert.deepEqual(Object.keys(c).sort(), ['bytes', 'cid']);
  assert.equal(c.bytes, 11);
  assert.match(c.cid, /^sha256:[0-9a-f]{64}$/);
});

test('round trip: what goes in comes back out', () => {
  const s = fresh();
  const plain = Buffer.from('OK: transferred EUR 2000000');
  const { cid } = s.put(plain);
  assert.equal(s.get(cid).toString(), plain.toString());
});

// FR-35's verification clause — substitution must break reproduction.
test('FR-35: substituting the stored content fails to reproduce the cid', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('EUR 2000000'));
  assert.equal(s.reproduces(cid), true);
  s.overwriteForTest(cid, Buffer.from('EUR 25'));
  assert.equal(s.reproduces(cid), false, 'a swapped payload must not reproduce its commitment');
});

// PRIV-02 — nothing on disk outside the content store holds the plaintext, and the
// ciphertext does not hold it either.
test('PRIV-02: the plaintext appears nowhere in the stored bytes', () => {
  const s = fresh();
  const secret = 'EUR 2000000 to IBAN DE89370400440532013000';
  const { cid } = s.put(Buffer.from(secret));
  s.close();
  for (const path of walkFiles(s.root)) {
    assert.ok(!readFileSync(path).includes(secret), `${path} must not contain the payload`);
  }
  assert.equal(s.get(cid).toString(), secret, 'and it is still recoverable with the key');
});

// FR-36 / PRIV-03 — crypto-shredding. Delete the ciphertext, the salt and the key.
test('FR-36: shredding removes the content, its salt and its key, and nothing else', () => {
  const s = fresh();
  const keep = s.put(Buffer.from('keep me'));
  const drop = s.put(Buffer.from('erase me'));
  s.shred(drop.cid);
  assert.equal(s.has(drop.cid), false);
  assert.throws(() => s.get(drop.cid), ContentMissing);
  assert.equal(s.get(keep.cid).toString(), 'keep me', 'erasure is per record, not per store');
  // Verification of a shredded record is inconclusive, never a failure.
  assert.equal(s.reproduces(drop.cid), null, 'null is inconclusive — the content is gone by design');
});

test('shredding is idempotent and a missing cid is not an error', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('x'));
  s.shred(cid); s.shred(cid);
  s.shred('sha256:' + 'ab'.repeat(32));
});

// FR-55 — counterparty references are extracted and indexed, in the DELETABLE store.
test('FR-55: an external reference is indexed and queryable', () => {
  const s = fresh();
  const plain = Buffer.from('OK: transferred EUR 2000000 ref=TX-77814');
  const { cid } = s.put(plain, { refs: extractRefs(plain) });
  assert.deepEqual(s.findByRef('TX-77814'), [cid]);
  assert.deepEqual(s.findByRef('TX-00000'), []);
});

test('FR-55: references come from a structured result as well as free text', () => {
  const json = Buffer.from(JSON.stringify({
    status: 'settled', transaction_id: 'TX-77814', nested: { confirmation_ref: 'CNF-9' },
    amount: 2000000, note: 'see ref=TX-77814',
  }));
  const refs = extractRefs(json);
  assert.deepEqual([...refs].sort(), ['CNF-9', 'TX-77814']);
});

test('FR-55: extraction is best-effort and says so by finding nothing here', () => {
  assert.deepEqual([...extractRefs(Buffer.from('transfer complete'))], []);
  assert.deepEqual([...extractRefs(Buffer.from('{"amount": 2000000}'))], []);
});

// DES-19 — the index lives in the deletable store and goes with the shredding,
// because a transaction reference can itself be identifying.
test('FR-55: the reference index is crypto-shredded with everything else', () => {
  const s = fresh();
  const plain = Buffer.from('ref=TX-77814');
  const { cid } = s.put(plain, { refs: extractRefs(plain) });
  assert.deepEqual(s.findByRef('TX-77814'), [cid]);
  s.shred(cid);
  assert.deepEqual(s.findByRef('TX-77814'), [], 'the ref must not outlive the content');
  const idx = join(s.root, 'content', 'refs.idx');
  if (existsSync(idx)) {
    assert.ok(!readFileSync(idx).includes('TX-77814'), 'and not linger in the index file');
  }
});

test('the reference index is never written into the chain directory', () => {
  const s = fresh();
  const plain = Buffer.from('ref=TX-77814');
  s.put(plain, { refs: extractRefs(plain) });
  const chain = join(s.root, 'chain');
  if (existsSync(chain)) {
    for (const path of walkFiles(chain)) {
      assert.ok(!readFileSync(path).includes('TX-77814'));
    }
  }
  assert.ok(existsSync(join(s.root, 'content', 'refs.idx')));
});

test('a tampered ciphertext is detected by the cipher, not just by the cid', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('EUR 2000000'));
  const path = s.pathFor(cid);
  const bytes = readFileSync(path);
  bytes[bytes.length - 1] ^= 0xff;
  writeFileSync(path, bytes);
  assert.throws(() => s.get(cid), /unauthenticated|auth/i);
  assert.equal(s.reproduces(cid), false);
});
