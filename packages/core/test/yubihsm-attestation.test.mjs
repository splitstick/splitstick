import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateAttestation, CUSTODY_PROPERTIES } from '../src/attestation.mjs';
import {
  readBitStringValue, yubihsmOrigin, yubihsmCapabilities, YUBIHSM_ATTESTATION_OID,
} from '../src/trustpath.mjs';
import {
  key, certificate, attestation, yubihsmExtensions, bitStringFor, YUBIHSM_OID,
} from './attestation-fixture.mjs';

/**
 * FR-70 against the VENDOR'S format — the finding a review raised.
 *
 * The previous version had the OIDs wrong (`.5` as Origin, an invented
 * `non_exportable` BOOLEAN at `.6`) and read them with a BOOLEAN decoder. A
 * genuine YubiHSM 2 attestation would have failed custody validation, and the
 * constructed BOOLEAN it did accept established nothing about hardware custody.
 *
 * Yubico's table: `.3` Origin (Bit String), `.4` Domains (Bit String), `.5`
 * Capabilities (Bit String), `.6` Object ID (Integer). There is no
 * non-exportable extension. The property is derived from two facts, and NEITHER
 * ALONE IS SUFFICIENT:
 *
 * - Origin says the key was GENERATED on the device, not imported into it. A
 *   key imported into an HSM was outside one first, and the device's
 *   non-exportability says nothing about where it has already been.
 * - Capabilities do NOT include `exportable-under-wrap`. A key with that
 *   capability can leave under a wrap key, however good the hardware.
 */

const EPOCH = { from: new Date('2026-10-02T00:00:00Z'), to: new Date('2026-10-03T00:00:00Z') };

function provider() {
  const k = key();
  return {
    k,
    cert: certificate({
      subject: 'Yubico Attestation Root', issuer: 'Yubico Attestation Root',
      subjectSpki: Buffer.from(k.spki), issuerKey: k.privateKey,
      notBefore: new Date('2020-01-01Z'), notAfter: new Date('2040-01-01Z'), ca: true, serial: 1,
    }),
  };
}

/** @param {{ origin?: string[], capabilities?: string[] }} shape */
function attested(shape) {
  const root = provider();
  const attestedKey = key();
  const leaf = certificate({
    subject: 'Attested Key', issuer: 'Yubico Attestation Root',
    subjectSpki: Buffer.from(attestedKey.spki), issuerKey: root.k.privateKey,
    notBefore: new Date('2026-10-01Z'), notAfter: new Date('2027-10-01Z'), serial: 2,
    extensions: yubihsmExtensions(shape),
  });
  return { root, attestedKey, leaf };
}

test('the OIDs are the ones Yubico publishes', () => {
  // Written out so a drift from the vendor's table is a test failure rather
  // than a silent acceptance of a document that means something else.
  assert.equal(YUBIHSM_ATTESTATION_OID.origin, '1.3.6.1.4.1.41482.4.3');
  assert.equal(YUBIHSM_ATTESTATION_OID.domains, '1.3.6.1.4.1.41482.4.4');
  assert.equal(YUBIHSM_ATTESTATION_OID.capabilities, '1.3.6.1.4.1.41482.4.5');
  assert.equal(YUBIHSM_ATTESTATION_OID.object_id, '1.3.6.1.4.1.41482.4.6');
  assert.equal(YUBIHSM_ATTESTATION_OID.fips_approved, '1.3.6.1.4.1.41482.4.12');
  // And the property names the policy can require.
  assert.deepEqual([...CUSTODY_PROPERTIES], ['generated_on_device', 'not_exportable']);
});

test('a BIT STRING extension is decoded as the vendor encodes it', () => {
  const { leaf } = attested({ capabilities: ['sign_eddsa', 'exportable_under_wrap'] });
  const caps = readBitStringValue(leaf, YUBIHSM_OID.capabilities);
  assert.ok(caps);
  // Eight content octets, big-endian, exportable-under-wrap at bit 16 — which
  // is exactly the 0x0000000000010000 mask Yubico documents.
  assert.equal(caps.length, 8);
  assert.equal(caps.readBigUInt64BE(0) & 0x10000n, 0x10000n);
  const origin = readBitStringValue(leaf, YUBIHSM_OID.origin);
  assert.equal(origin?.length, 1);
  assert.equal(origin?.[0], 0x01, 'generated is mask 0x01 in the first octet');
});

test('origin and capabilities are reported by name', () => {
  const generated = attested({});
  assert.deepEqual(yubihsmOrigin(generated.leaf),
    { generated: true, imported: false, imported_wrapped: false, present: true, malformed: false });
  assert.equal(yubihsmCapabilities(generated.leaf).exportable_under_wrap, false);

  const imported = attested({ origin: ['imported'] });
  assert.deepEqual(yubihsmOrigin(imported.leaf),
    { generated: false, imported: true, imported_wrapped: false, present: true, malformed: false });

  const wrapped = attested({ origin: ['generated', 'imported_wrapped'] });
  assert.equal(yubihsmOrigin(wrapped.leaf).imported_wrapped, true);
});

// ── The two facts, and that neither alone is enough ─────────────────────────

test('a generated, non-exportable key passes check 5', () => {
  const { root, attestedKey, leaf } = attested({});
  const r = validateAttestation(leaf.raw, {
    anchors: [root.cert], epochPublicKey: attestedKey.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, true, JSON.stringify(r.checks, null, 1));
  assert.equal(r.checks.custody_properties.ok, true);
  assert.match(r.checks.custody_properties.detail, /generated on the device/i);
});

test('a key with exportable-under-wrap is refused', () => {
  // The capability means it can leave under a wrap key, however good the
  // hardware. Non-exportability is the claim; this contradicts it.
  const { root, attestedKey, leaf } = attested({
    capabilities: ['sign_eddsa', 'exportable_under_wrap'],
  });
  const r = validateAttestation(leaf.raw, {
    anchors: [root.cert], epochPublicKey: attestedKey.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /exportable-under-wrap/);
});

test('an IMPORTED key is refused even with no export capability', () => {
  // The distinction the review asked for by name. A key imported into an HSM
  // was outside one first, so the device's non-exportability says nothing about
  // where that key has already been — and forward secrecy rests on the key
  // never having been copyable.
  const { root, attestedKey, leaf } = attested({ origin: ['imported'] });
  const r = validateAttestation(leaf.raw, {
    anchors: [root.cert], epochPublicKey: attestedKey.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /imported/i);
});

test('a key imported under wrap is refused too', () => {
  const { root, attestedKey, leaf } = attested({ origin: ['generated', 'imported_wrapped'] });
  const r = validateAttestation(leaf.raw, {
    anchors: [root.cert], epochPublicKey: attestedKey.raw, epochSpan: EPOCH,
  });
  // `generated` is set as well — Yubico documents 0x11 and 0x12 as the
  // combinations that actually occur — and it still must not pass: the key was
  // wrapped out and brought back, so it existed outside the device.
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /wrap/i);
});

test('an attestation with NO vendor extensions is refused, not assumed good', () => {
  const root = provider();
  const k = key();
  const bare = certificate({
    subject: 'Attested Key', issuer: 'Yubico Attestation Root', subjectSpki: Buffer.from(k.spki),
    issuerKey: root.k.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 2, extensions: [],
  });
  const r = validateAttestation(bare.raw, {
    anchors: [root.cert], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /does not (state|carry)/i);
});

test('a BOOLEAN where a BIT STRING belongs is refused rather than coerced', async () => {
  // The old decoder expected a BOOLEAN. A certificate carrying one at the
  // Origin OID is malformed for this format, and reading it as a yes would be
  // accepting a document that says something else.
  const root = provider();
  const k = key();
  const { encodeTlv, TAG } = await import('../src/der.mjs');
  const wrongType = certificate({
    subject: 'Attested Key', issuer: 'Yubico Attestation Root', subjectSpki: Buffer.from(k.spki),
    issuerKey: root.k.privateKey, notBefore: new Date('2026-10-01Z'),
    notAfter: new Date('2027-10-01Z'), serial: 2,
    extensions: [
      { oid: YUBIHSM_OID.origin, value: encodeTlv(TAG.BOOLEAN, Buffer.from([0xff])) },
      { oid: YUBIHSM_OID.capabilities, value: bitStringFor([], 8) },
    ],
  });
  const r = validateAttestation(wrongType.raw, {
    anchors: [root.cert], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /not a readable BIT STRING/i);
  // Absent and present-but-wrong-type give the same verdict and different
  // diagnostics: an operator with a real device needs to know which it is.
  assert.match(r.checks.custody_properties.detail, /it is not read as a yes/);
});

test('the result still says it has never seen a real provider document', () => {
  // The fixtures are vendor FORMAT, which is a real improvement over a
  // constructed BOOLEAN — and they are still not a real device's attestation.
  // No cloud path issues an Ed25519 attestation and the YubiHSM purchase is
  // held, so the caveat stays on every result.
  const { root, attestedKey, leaf } = attested({});
  const r = validateAttestation(leaf.raw, {
    anchors: [root.cert], epochPublicKey: attestedKey.raw, epochSpan: EPOCH,
  });
  assert.equal(r.provider_untested, true);
  assert.equal(r.establishes_destruction, false);
});
