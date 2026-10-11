import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateAttestation } from '../src/attestation.mjs';
import { verifyTimeStampToken } from '../src/rfc3161.mjs';
import { key, certificate, OID_NON_EXPORTABLE } from './attestation-fixture.mjs';
import { encodeTlv, TAG } from '../src/der.mjs';

/**
 * The trust path, reviewed adversarially.
 *
 * Every assertion here is a refusal that was missing. A product whose claim is
 * "you do not have to trust the operator" cannot have a trust path that accepts
 * a certificate the operator could have obtained for themselves.
 */

const EPOCH = { from: new Date('2026-10-02T00:00:00Z'), to: new Date('2026-10-03T00:00:00Z') };
const TRUE_ = encodeTlv(TAG.BOOLEAN, Buffer.from([0xff]));
const FALSE_ = encodeTlv(TAG.BOOLEAN, Buffer.from([0x00]));

function root(name = 'Provider Root') {
  const k = key();
  return {
    k,
    cert: certificate({
      subject: name, issuer: name, subjectSpki: Buffer.from(k.spki), issuerKey: k.privateKey,
      notBefore: new Date('2020-01-01Z'), notAfter: new Date('2040-01-01Z'), ca: true, serial: 1,
    }),
  };
}

// ── Basic constraints ────────────────────────────────────────────────────────

test('an END-ENTITY certificate cannot act as a CA', () => {
  // The bug this test exists for. Anyone holding ANY certificate from a trusted
  // provider root could sign an attestation over a key of their choosing, and
  // FR-70 reported custody as independently supported. A trust path that
  // accepts a certificate the operator could have obtained for themselves
  // establishes nothing at all.
  const r = root();
  const leafKey = key();
  const endEntity = certificate({
    subject: 'Ordinary Key', issuer: 'Provider Root', subjectSpki: Buffer.from(leafKey.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2020-01-01Z'),
    notAfter: new Date('2040-01-01Z'), ca: false, serial: 2,
  });
  assert.equal(endEntity.ca, false, 'the fixture really is an end entity');

  const victim = key();
  const forged = certificate({
    subject: 'Attested Key', issuer: 'Ordinary Key', subjectSpki: Buffer.from(victim.spki),
    issuerKey: leafKey.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 3,
    extensions: [{ oid: OID_NON_EXPORTABLE, value: TRUE_ }],
  });
  const out = validateAttestation(forged.raw, {
    anchors: [r.cert], intermediates: [endEntity], epochPublicKey: victim.raw, epochSpan: EPOCH,
  });
  assert.equal(out.supported, false);
  assert.equal(out.checks.issuer.ok, false);
  assert.match(out.checks.issuer.detail, /not a certificate authority|basic constraints/i);
});

test('a genuine CA intermediate still works', () => {
  // The refusal must be on CA:FALSE, not on there being an intermediate at all.
  const r = root();
  const midKey = key();
  const mid = certificate({
    subject: 'Provider Intermediate', issuer: 'Provider Root',
    subjectSpki: Buffer.from(midKey.spki), issuerKey: r.k.privateKey,
    notBefore: new Date('2020-01-01Z'), notAfter: new Date('2040-01-01Z'), ca: true, serial: 2,
  });
  const attested = key();
  const leaf = certificate({
    subject: 'Attested Key', issuer: 'Provider Intermediate',
    subjectSpki: Buffer.from(attested.spki), issuerKey: midKey.privateKey,
    notBefore: new Date('2026-10-01Z'), notAfter: new Date('2027-10-01Z'), serial: 3,
    extensions: [{ oid: OID_NON_EXPORTABLE, value: TRUE_ }],
  });
  const out = validateAttestation(leaf.raw, {
    anchors: [r.cert], intermediates: [mid], epochPublicKey: attested.raw, epochSpan: EPOCH,
  });
  assert.equal(out.supported, true, JSON.stringify(out.checks, null, 1));
});

test('an end-entity certificate cannot mint a TSA chain either', async () => {
  // Same helper, same hole: the RFC 3161 path walked the chain with the same
  // issuance test and would have accepted a timestamp signed under any
  // certificate from an accepted anchor.
  const r = root('TSA Root');
  const leafKey = key();
  const endEntity = certificate({
    subject: 'Ordinary Key', issuer: 'TSA Root', subjectSpki: Buffer.from(leafKey.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2020-01-01Z'),
    notAfter: new Date('2040-01-01Z'), ca: false, serial: 2,
  });
  // A real token is not needed: the chain is refused before the signature is
  // reached, and the fixture token's own chain is tested elsewhere.
  const fix = new URL('./fixtures/rfc3161/', import.meta.url);
  const token = Buffer.from(
    readFileSync(new URL('token.b64', fix)).toString('utf8').trim(), 'base64');
  const imprint = Buffer.from(
    readFileSync(new URL('imprint.hex', fix)).toString('utf8').trim(), 'hex');
  const out = await verifyTimeStampToken(token, { imprint, anchors: [endEntity] });
  assert.equal(out.ok, false);
});

// ── Custody properties: the VALUE, not the presence ──────────────────────────

test('an extension asserting non-exportable FALSE is refused', () => {
  // It passed. The check searched the certificate's bytes for the OID and
  // never read what it asserted, so a document explicitly saying "this key is
  // exportable" reported custody as independently supported — laundering the
  // weaker claim into the stronger one, which is the exact thing the code's own
  // comment says it must not do.
  const r = root();
  const k = key();
  const leaf = certificate({
    subject: 'Attested Key', issuer: 'Provider Root', subjectSpki: Buffer.from(k.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 2,
    extensions: [{ oid: OID_NON_EXPORTABLE, value: FALSE_ }],
  });
  const out = validateAttestation(leaf.raw, {
    anchors: [r.cert], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(out.supported, false);
  assert.equal(out.checks.custody_properties.ok, false);
  assert.match(out.checks.custody_properties.detail, /asserts.*false|does not assert/i);
});

test('the OID appearing anywhere in the certificate is not an assertion', () => {
  // The old check was a containment test over the whole DER, so the OID in a
  // subject name, a serial, or an unrelated extension's VALUE would have
  // counted. Here it is inside another extension's value.
  const r = root();
  const k = key();
  const oidBytes = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x04, 0x06]);
  const leaf = certificate({
    subject: 'Attested Key', issuer: 'Provider Root', subjectSpki: Buffer.from(k.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 2,
    extensions: [{ oid: '1.3.6.1.4.1.41482.4.5', value: encodeTlv(TAG.OCTET_STRING, oidBytes) }],
  });
  const out = validateAttestation(leaf.raw, {
    anchors: [r.cert], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(out.checks.custody_properties.ok, false);
});

test('a TRUE assertion in the right extension still passes', () => {
  const r = root();
  const k = key();
  const leaf = certificate({
    subject: 'Attested Key', issuer: 'Provider Root', subjectSpki: Buffer.from(k.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 2,
    extensions: [{ oid: OID_NON_EXPORTABLE, value: TRUE_ }],
  });
  const out = validateAttestation(leaf.raw, {
    anchors: [r.cert], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(out.checks.custody_properties.ok, true, out.checks.custody_properties.detail);
});

// ── RFC 3161: the EKU the spec makes mandatory ───────────────────────────────

test('a certificate without extendedKeyUsage=timeStamping is not a TSA', async () => {
  // RFC 3161 2.3 requires the TSA certificate to carry exactly this EKU, and
  // marks it critical. Without the check, any certificate under an accepted
  // anchor could sign timestamps — which is a weaker statement than "a TSA
  // said so" and was being reported as the stronger one.
  const fix = new URL('./fixtures/rfc3161/', import.meta.url);
  const token = Buffer.from(
    readFileSync(new URL('token.b64', fix)).toString('utf8').trim(), 'base64');
  const imprint = Buffer.from(
    readFileSync(new URL('imprint.hex', fix)).toString('utf8').trim(), 'hex');
  const rootPem = readFileSync(new URL('root.pem', fix)).toString('utf8');
  // The committed fixture DOES carry the EKU, so it must still verify: the new
  // check must not break the genuine token.
  const good = await verifyTimeStampToken(token, { imprint, anchors: [rootPem] });
  assert.equal(good.ok, true, good.detail);

  // And a hand-built signer without it must be refused.
  const r = root('TSA Root');
  const signerKey = key();
  const noEku = certificate({
    subject: 'Not A TSA', issuer: 'TSA Root', subjectSpki: Buffer.from(signerKey.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2020-01-01Z'),
    notAfter: new Date('2040-01-01Z'), serial: 2,
  });
  const { hasTimeStampingEku } = await import('../src/rfc3161.mjs');
  assert.equal(hasTimeStampingEku(noEku), false);
  const withEku = certificate({
    subject: 'A TSA', issuer: 'TSA Root', subjectSpki: Buffer.from(signerKey.spki),
    issuerKey: r.k.privateKey, notBefore: new Date('2020-01-01Z'),
    notAfter: new Date('2040-01-01Z'), serial: 3,
    extensions: [{
      oid: '2.5.29.37',
      value: encodeTlv(TAG.SEQUENCE, encodeTlv(TAG.OID,
        Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]))),
      critical: true,
    }],
  });
  assert.equal(hasTimeStampingEku(withEku), true);
});
