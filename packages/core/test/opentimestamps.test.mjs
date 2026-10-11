import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseOtsProof, describeOtsProof, OtsError, FILE_MAGIC } from '../src/opentimestamps.mjs';

/**
 * A proof builder. These are CONSTRUCTED proofs, not a calendar's: this machine
 * has no network, and a real `.ots` would have to come from one. The parser is
 * therefore proved against the format as documented, not against a live
 * calendar's output, and that difference is worth stating rather than leaving
 * for a reader to find.
 */
const varuint = (/** @type {number} */ n) => {
  const out = [];
  for (;;) {
    if (n < 0x80) { out.push(n); break; }
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  return Buffer.from(out);
};
const varbytes = (/** @type {Buffer} */ b) => Buffer.concat([varuint(b.length), b]);

const BITCOIN = Buffer.from('0588960d73d71901', 'hex');
const PENDING = Buffer.from('83dfe30d2e906c6e', 'hex');

/** @param {Buffer} digest @param {Buffer[]} ops */
const proof = (digest, ops) => Buffer.concat([
  FILE_MAGIC, varuint(1), Buffer.from([0x08]), digest, ...ops,
]);
const sha256Op = Buffer.from([0x08]);
const appendOp = (/** @type {Buffer} */ b) => Buffer.concat([Buffer.from([0xf0]), varbytes(b)]);
const prependOp = (/** @type {Buffer} */ b) => Buffer.concat([Buffer.from([0xf1]), varbytes(b)]);
const bitcoinAt = (/** @type {number} */ h) => Buffer.concat([
  Buffer.from([0x00]), BITCOIN, varbytes(varuint(h)),
]);
const pendingAt = (/** @type {string} */ uri) => Buffer.concat([
  Buffer.from([0x00]), PENDING, varbytes(varbytes(Buffer.from(uri, 'utf8'))),
]);

const DIGEST = createHash('sha256').update('a splitstick checkpoint note').digest();

test('a proof reaching a Bitcoin attestation reports the block height', () => {
  const p = proof(DIGEST, [appendOp(Buffer.from('ab', 'hex')), sha256Op, bitcoinAt(912_345)]);
  const r = parseOtsProof(p, { expectDigest: DIGEST });
  assert.equal(r.algorithm, 'sha256');
  assert.equal(r.digest, DIGEST.toString('hex'));
  assert.equal(r.attestations.length, 1);
  assert.equal(r.attestations[0].chain, 'bitcoin');
  assert.equal(r.attestations[0].height, 912_345);
});

test('the operations are actually applied, so the attested digest is not the file digest', () => {
  const p = proof(DIGEST, [appendOp(Buffer.from('cafe', 'hex')), sha256Op, bitcoinAt(1)]);
  const r = parseOtsProof(p, { expectDigest: DIGEST });
  const expected = createHash('sha256')
    .update(Buffer.concat([DIGEST, Buffer.from('cafe', 'hex')])).digest('hex');
  // A parser that collected attestations without applying the ops would report
  // the same height while committing to the wrong digest — which would look
  // correct in every test that only checks the height.
  assert.equal(r.attestations[0].digest, expected);
  assert.notEqual(r.attestations[0].digest, r.digest);
});

test('prepend and sha256 compose in the order the proof gives them', () => {
  const p = proof(DIGEST, [prependOp(Buffer.from('00ff', 'hex')), sha256Op, bitcoinAt(2)]);
  const r = parseOtsProof(p, { expectDigest: DIGEST });
  assert.equal(r.attestations[0].digest, createHash('sha256')
    .update(Buffer.concat([Buffer.from('00ff', 'hex'), DIGEST])).digest('hex'));
});

test('a fork walks both branches', () => {
  const p = proof(DIGEST, [
    Buffer.from([0xff]),
    appendOp(Buffer.from('01', 'hex')), sha256Op, bitcoinAt(100),
    appendOp(Buffer.from('02', 'hex')), sha256Op, pendingAt('https://alice.btc.calendar.example'),
  ]);
  const r = parseOtsProof(p, { expectDigest: DIGEST });
  assert.equal(r.attestations.length, 2);
  assert.deepEqual(r.attestations.map(a => a.chain).sort(), ['bitcoin', 'pending']);
  assert.equal(r.attestations.find(a => a.chain === 'pending')?.uri,
    'https://alice.btc.calendar.example');
});

test('a proof over a DIFFERENT digest is refused', () => {
  const p = proof(DIGEST, [bitcoinAt(5)]);
  const other = createHash('sha256').update('something else').digest();
  assert.throws(() => parseOtsProof(p, { expectDigest: other }),
    (/** @type {any} */ e) => e instanceof OtsError && /something else/.test(e.message));
  // Without expectDigest a proof about anybody's document parses perfectly,
  // which is why the digest is a required part of asking the question.
  assert.doesNotThrow(() => parseOtsProof(p));
});

test('malformed proofs are refused rather than read past the end', () => {
  for (const bad of [
    Buffer.alloc(0),
    Buffer.from('not a proof'),
    FILE_MAGIC,
    Buffer.concat([FILE_MAGIC, varuint(1)]),
    Buffer.concat([FILE_MAGIC, varuint(1), Buffer.from([0x08]), DIGEST.subarray(0, 10)]),
    Buffer.concat([FILE_MAGIC, varuint(2), Buffer.from([0x08]), DIGEST]),
    proof(DIGEST, [Buffer.from([0x99])]),
    proof(DIGEST, [appendOp(Buffer.from('ab', 'hex')).subarray(0, 2)]),
  ]) {
    assert.throws(() => parseOtsProof(bad, { expectDigest: DIGEST }), OtsError, bad.length.toString());
  }
});

test('a non-SHA-256 file digest is refused, not guessed at', () => {
  const p = Buffer.concat([FILE_MAGIC, varuint(1), Buffer.from([0x02]), Buffer.alloc(20)]);
  assert.throws(() => parseOtsProof(p), (/** @type {any} */ e) => /SHA-256/.test(e.message));
});

// ── describeOtsProof: what is reported, and what is never claimed ────────────

test('a confirmed proof is reported as a commitment, never as confirmed', () => {
  const p = proof(DIGEST, [bitcoinAt(912_345)]);
  const r = describeOtsProof(p, { imprint: DIGEST });
  assert.deepEqual(r.heights, [912_345]);
  // NEVER ok. Walking the proof reaches a block header; confirming that header
  // is in the chain needs a chain source, which NFR-05 forbids.
  assert.equal(r.ok, false);
  assert.equal(r.inconclusive, true);
  assert.match(r.detail, /912345/);
  assert.match(r.detail, /reported, not confirmed/);
  assert.match(r.detail, /no party able to withdraw/);
});

test('a pending proof is pending, not failed', () => {
  const p = proof(DIGEST, [pendingAt('https://a.calendar.example')]);
  const r = describeOtsProof(p, { imprint: DIGEST });
  assert.equal(r.inconclusive, true);
  assert.deepEqual(r.pending, ['https://a.calendar.example']);
  // Treating pending as a failure would make the hard tier look broken for
  // most of its first hour, every time.
  assert.match(r.detail, /not a failure/);
});

test('a proof over other bytes is REFUTED; a mangled one is merely broken', () => {
  const over = describeOtsProof(proof(DIGEST, [bitcoinAt(1)]), {
    imprint: createHash('sha256').update('elsewhere').digest(),
  });
  assert.equal(over.inconclusive, false, 'a proof about another document refutes this one');
  assert.equal(over.malformed, undefined);

  const mangled = describeOtsProof(Buffer.from('rubbish'), { imprint: DIGEST });
  assert.equal(mangled.inconclusive, true);
  assert.equal(mangled.malformed, true);
});

test('a proof reaching no attestation commits to nothing, and says that', () => {
  const r = describeOtsProof(proof(DIGEST, [sha256Op]), { imprint: DIGEST });
  assert.equal(r.inconclusive, true);
  assert.match(r.detail, /commits to nothing/);
});

test('an unknown attestation chain is reported, not treated as Bitcoin', () => {
  const unknown = Buffer.concat([
    Buffer.from([0x00]), Buffer.from('0102030405060708', 'hex'), varbytes(varuint(7)),
  ]);
  const r = describeOtsProof(proof(DIGEST, [unknown]), { imprint: DIGEST });
  assert.deepEqual(r.heights, []);
  assert.match(r.detail, /unknown/);
});
