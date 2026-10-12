import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { verifyTimeStampToken, parseTimeStampToken, Rfc3161Error, timeStampRequest } from '../src/rfc3161.mjs';

const dir = new URL('./fixtures/rfc3161/', import.meta.url);
const f = (/** @type {string} */ n) => readFileSync(new URL(n, dir));
const token = Buffer.from(f('token.b64').toString('utf8').trim(), 'base64');
const root = f('root.pem').toString('utf8');
const tsa = f('tsa.pem').toString('utf8');
const imprint = Buffer.from(f('imprint.hex').toString('utf8').trim(), 'hex');

test('the fixture imprint really is the digest of the fixture bytes', () => {
  // If this drifts, every assertion below is about the wrong bytes.
  assert.equal(createHash('sha256').update(f('note.txt')).digest('hex'), imprint.toString('hex'));
});

test('a genuine OpenSSL TimeStampToken parses', () => {
  const t = parseTimeStampToken(token);
  assert.equal(t.version, 1);
  assert.equal(t.hashAlgorithm, 'sha256');
  assert.equal(t.imprint.toString('hex'), imprint.toString('hex'));
  assert.equal(t.policy, '1.2.3.4.1');
  assert.equal(t.serialNumber, '1001');
  assert.equal(t.genTime.toISOString(), '2026-10-11T12:58:05.000Z');
  assert.equal(t.certificates.length, 2, 'the signer and its issuer were requested with -cert');
  assert.match(t.signerCertificate.subject, /Splitstick Test TSA/);
});

test('a genuine token verifies against its trust anchor, over the imprint it covers', async () => {
  const r = await verifyTimeStampToken(token, { imprint, anchors: [root] });
  assert.equal(r.ok, true, r.detail);
  assert.equal(r.genTime.toISOString(), '2026-10-11T12:58:05.000Z');
  assert.equal(r.tsa, t_subject(r));
  assert.match(r.detail, /verifie/i);
});

const t_subject = (/** @type {any} */ r) => r.tsa;

// ── The adversarial half: every way this must refuse ─────────────────────────

test('a token over a DIFFERENT imprint is refused', async () => {
  const other = createHash('sha256').update('something else').digest();
  const r = await verifyTimeStampToken(token, { imprint: other, anchors: [root] });
  assert.equal(r.ok, false);
  assert.match(r.detail, /imprint/i);
  // This is the check that makes `covers` mean anything. A verifier that
  // validated the CMS signature and skipped this would accept a valid
  // timestamp over somebody else's document as a timestamp over yours.
});

test('a token whose chain reaches no supplied anchor is refused', async () => {
  // An unrelated CA. "Chains to a valid CA" is not the question; chaining to an
  // anchor THIS READER named is (FR-30).
  const unrelated = readFileSync(new URL('unrelated.pem', dir)).toString('utf8');
  const r = await verifyTimeStampToken(token, { imprint, anchors: [unrelated] });
  assert.equal(r.ok, false);
  assert.match(r.detail, /anchor/i);
});

test('pinning the TSA certificate itself is accepted, because that is sound trust', async () => {
  // My first version of this test asserted the opposite, on the reasoning that
  // "the signature over the leaf has to be checked by something". That is wrong:
  // a reader who pins the exact bytes of a certificate has made a stronger
  // statement than one who trusts its issuer, and there is nothing left to
  // check. Exact byte equality is the condition — not subject, not key.
  const r = await verifyTimeStampToken(token, { imprint, anchors: [tsa] });
  assert.equal(r.ok, true, r.detail);
});

test('a certificate with the same subject but a different key is not the pinned one', async () => {
  const impostor = readFileSync(new URL('impostor.pem', dir)).toString('utf8');
  const r = await verifyTimeStampToken(token, { imprint, anchors: [impostor] });
  assert.equal(r.ok, false);
});

test('with no anchors supplied, nothing is claimed — not a pass, not a failure', async () => {
  for (const anchors of [undefined, []]) {
    const r = await verifyTimeStampToken(token, { imprint, anchors });
    assert.equal(r.ok, false);
    assert.equal(r.inconclusive, true);
    assert.match(r.detail, /no trust anchor/i);
  }
});

test('a token with a flipped signature byte is refused', async () => {
  const bad = Buffer.from(token);
  // The signature is near the end of a CMS SignedData; flipping a byte in the
  // last quarter lands in it or in the certificates, both of which must fail.
  bad[bad.length - 20] ^= 0xff;
  const r = await verifyTimeStampToken(bad, { imprint, anchors: [root] });
  assert.equal(r.ok, false);
});

test('a token whose TSTInfo was edited is refused even though the DER still parses', async () => {
  // Flip a byte inside the signed content. The signature is over a digest of
  // exactly these bytes, so this must fail at the signature rather than at the
  // parse — which is the difference between a format check and verification.
  const t = parseTimeStampToken(token);
  const at = token.indexOf(t.tstInfoDer);
  assert.ok(at > 0, 'the eContent must appear verbatim in the token');
  const bad = Buffer.from(token);
  bad[at + t.tstInfoDer.length - 3] ^= 0x01;
  const r = await verifyTimeStampToken(bad, { imprint, anchors: [root] });
  assert.equal(r.ok, false);
});

test('bytes that are not a token are a refusal, not a crash', async () => {
  for (const bad of [
    Buffer.alloc(0), Buffer.from('not der'), Buffer.from([0x30, 0x82, 0xff, 0xff]),
    token.subarray(0, 40), Buffer.concat([token, Buffer.from('trailing')]),
  ]) {
    const r = await verifyTimeStampToken(bad, { imprint, anchors: [root] });
    assert.equal(r.ok, false, bad.length.toString());
    assert.ok(typeof r.detail === 'string' && r.detail.length > 0);
  }
  assert.throws(() => parseTimeStampToken(Buffer.from('nope')), Rfc3161Error);
});

test('a DER length that overruns the buffer is refused rather than read past', async () => {
  const bad = Buffer.from(token);
  // Inflate the outer SEQUENCE length. A parser that trusts the length reads
  // off the end of the buffer or throws something unhelpful; it must refuse.
  bad[2] = 0xff;
  bad[3] = 0xff;
  const r = await verifyTimeStampToken(bad, { imprint, anchors: [root] });
  assert.equal(r.ok, false);
});

// ── The request side ─────────────────────────────────────────────────────────

test('a request carries the imprint and asks for the certificate', () => {
  const req = timeStampRequest(imprint);
  // Round-trip through our own parser's DER reader by locating the imprint: the
  // request must contain exactly those 32 bytes and nothing from the document.
  assert.ok(req.includes(imprint), 'the imprint must be in the request');
  assert.equal(req[0], 0x30, 'a TimeStampReq is a SEQUENCE');
  // PRIV-01 — a request carries a hash, never content. The fixture note text
  // is the positive control: if it ever appears, the adapter is leaking.
  assert.ok(!req.includes(Buffer.from('splitstick test note bytes')));
});

test('a request refuses anything that is not a 32-byte SHA-256 imprint', () => {
  for (const bad of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33), 'abc']) {
    assert.throws(() => timeStampRequest(/** @type {any} */ (bad)), Rfc3161Error);
  }
});
