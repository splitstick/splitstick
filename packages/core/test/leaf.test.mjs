import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../src/jcs.mjs';
import { newSalt, leafDigest, SALT_BYTES, LEAF_DOMAIN } from '../src/leaf.mjs';
import { nodeHash } from '../src/merkle.mjs';
import { action } from './fixtures.mjs';

test('a salt is 16 CSPRNG bytes and never repeats', () => {
  assert.equal(SALT_BYTES, 16);
  const s = newSalt();
  assert.equal(s.length, 16);
  const seen = new Set(Array.from({ length: 2000 }, () => newSalt().toString('hex')));
  assert.equal(seen.size, 2000, 'salts must not collide');
});

// FR-09's own verification clause: identical content must yield distinct digests.
test('FR-09: identical records with different salts give different leaves', () => {
  const r = action();
  const a = leafDigest(newSalt(), r), b = leafDigest(newSalt(), r);
  assert.notEqual(a.toString('hex'), b.toString('hex'));
});

test('leaf = SHA-256(0x00 ‖ salt ‖ JCS(record)), byte-exact', () => {
  const r = action();
  const salt = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const want = createHash('sha256')
    .update(Buffer.from([0x00])).update(salt).update(canonicalBytes(r)).digest('hex');
  assert.equal(leafDigest(salt, r).toString('hex'), want);
  assert.equal(LEAF_DOMAIN, 0x00);
});

// DES-03: the 0x00 prefix is domain separation against the second-preimage
// attack RFC 6962 exists to prevent, not decoration.
test('a leaf can never be read as an interior node', () => {
  const salt = Buffer.alloc(16, 7);
  const leaf = leafDigest(salt, action());
  const node = nodeHash(salt, canonicalBytes(action()));
  assert.notEqual(leaf.toString('hex'), node.toString('hex'));
});

test('a salt of the wrong length is refused rather than padded', () => {
  for (const bad of [Buffer.alloc(0), Buffer.alloc(15), Buffer.alloc(17), Buffer.alloc(32)]) {
    assert.throws(() => leafDigest(bad, action()), /16/);
  }
});

// SEC-13 — an action record is short and low-entropy. Unsalted, a digest answers
// "was the amount 2,000,000?" by enumeration. Salted, the same dictionary fails —
// and the third case states the limit: the salt is the secret, so a disclosed salt
// restores the attack. That is why salts are deletable (DES-13) and never shipped
// to a witness (DES-03 rule 3).
test('SEC-13: salting defeats a dictionary attack exactly while the salt is secret', () => {
  const amounts = Array.from({ length: 2501 }, (_, i) => i * 1000);
  const secret = 2000000;
  assert.ok(amounts.includes(secret), 'the dictionary must contain the answer');
  const candidate = n => action({ args: { cid: `sha256:${n}`, bytes: 61 } });
  const subject = n => canonicalBytes(candidate(n));

  const unsalted = createHash('sha256').update(subject(secret)).digest('hex');
  assert.equal(
    amounts.find(n => createHash('sha256').update(subject(n)).digest('hex') === unsalted),
    secret, 'the attack must work without a salt, or the test proves nothing');

  const salt = newSalt();
  const salted = leafDigest(salt, candidate(secret));
  assert.equal(
    amounts.find(n => leafDigest(newSalt(), candidate(n)).equals(salted)),
    undefined, 'the same dictionary must not recover a leaf whose salt is unknown');

  assert.equal(
    amounts.find(n => leafDigest(salt, candidate(n)).equals(salted)),
    secret, 'and with the salt disclosed the attack works again — the salt is the secret');
});

// FR-52 at the leaf level: the property test in record.test.mjs proves the canonical
// bytes move; this proves the leaf does.
test('FR-52: mutating any field at any depth moves the leaf', () => {
  const salt = Buffer.alloc(16, 1);
  const base = leafDigest(salt, action()).toString('hex');
  const mutations = [
    action({ tool: 'transfer_fund' }),
    action({ args: { cid: 'sha256:bbbc', bytes: 61 } }),
    action({ args: { cid: 'sha256:bbbb', bytes: 62 } }),
    action({ result: { cid: 'sha256:cccc', bytes: 54, ok: false } }),
    action({ consequential: false }),
    action({ outcome: 'error' }),
    action({ attempt: 2 }),
    action({ correlation: 'c-0002' }),
    action({ source_seq: 2 }),
    action({ ts: '2026-10-11T10:00:00.001Z' }),
  ];
  for (const m of mutations) {
    assert.notEqual(leafDigest(salt, m).toString('hex'), base);
  }
});
