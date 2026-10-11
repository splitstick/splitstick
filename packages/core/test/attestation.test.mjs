import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateAttestation, ATTESTATION_CHECKS } from '../src/attestation.mjs';
import { key, attestation, OID_NON_EXPORTABLE } from './attestation-fixture.mjs';

const EPOCH = { from: new Date('2026-10-02T00:00:00Z'), to: new Date('2026-10-03T00:00:00Z') };

/** A valid attestation over a fresh epoch key. */
function valid(over = {}) {
  const k = key();
  const a = attestation({ attestedSpki: Buffer.from(k.spki), ...over });
  return { k, a };
}

test('all five checks are named, and a result reports every one', () => {
  // FR-70's value is that the presence of a document establishes nothing. A
  // result that collapsed to a boolean would hide WHICH of the five failed,
  // which is the only thing a reader can act on.
  assert.deepEqual([...ATTESTATION_CHECKS],
    ['issuer', 'signature', 'key_identity', 'epoch_applicability', 'custody_properties']);
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.deepEqual(Object.keys(r.checks).sort(), [...ATTESTATION_CHECKS].sort());
  assert.ok(r.supported);
});

test('a valid attestation reports custody as independently supported', () => {
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, true);
  assert.ok(Object.values(r.checks).every(c => c.ok));
  // And even then, destruction is not established. Non-exportability says a key
  // could not leave the module; it does not say a retired key was deleted.
  assert.equal(r.establishes_destruction, false);
  assert.match(r.detail, /destruction/i);
});

// ── 1. Issuer ────────────────────────────────────────────────────────────────

test('check 1: a document issued by a root the reader never named is refused', () => {
  const { k, a } = valid();
  const stranger = attestation({
    attestedSpki: Buffer.from(key().spki), rootName: 'Some Other CA',
  });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [stranger.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.issuer.ok, false);
  // "Chains to a valid CA" is not the question. The anchor has to be a provider
  // root in THIS reader's acceptance policy.
  assert.match(r.checks.issuer.detail, /anchor/i);
});

test('checks 1 and 2 separate "claims an issuer you accept" from "and the signature holds"', () => {
  // A root with the SAME NAME and a different key. Node's checkIssued is
  // name-based, so the document does claim an issuer this reader accepts — and
  // the claim is false. Reporting issuer ok and signature failed is the
  // informative answer; collapsing them into one boolean would lose which of
  // the two went wrong, and they go wrong for different reasons.
  const { k, a } = valid();
  const sameName = attestation({ attestedSpki: Buffer.from(key().spki) });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [sameName.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.issuer.ok, true);
  assert.equal(r.checks.signature.ok, false);
  assert.match(r.checks.signature.detail, /does NOT verify/);
});

test('check 1: no anchors at all establishes nothing, and is not a failure of the document', () => {
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.inconclusive, true);
  assert.match(r.detail, /no provider root/i);
});

// ── 2. Signature ─────────────────────────────────────────────────────────────

test('check 2: a corrupted signature is refused', () => {
  const k = key();
  const a = attestation({ attestedSpki: Buffer.from(k.spki), corruptSignature: true });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.signature.ok, false);
});

// ── 3. Key identity ──────────────────────────────────────────────────────────

test('check 3: an attestation over ANOTHER key in the same account is refused', () => {
  // The failure this check exists for. A provider will happily attest any key
  // the account holds; the question is whether it attests the key that signed
  // these checkpoints.
  const { a } = valid();
  const elsewhere = key();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: elsewhere.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.key_identity.ok, false);
  assert.match(r.checks.key_identity.detail, /another key|not the key/i);
  // Everything else about the document is fine, which is exactly why this
  // check cannot be folded into the others.
  assert.equal(r.checks.issuer.ok, true);
  assert.equal(r.checks.signature.ok, true);
});

test('check 3: the comparison is on the key, not on the subject name', () => {
  const { a } = valid();
  const impostor = key();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: impostor.raw, epochSpan: EPOCH,
  });
  assert.equal(r.checks.key_identity.ok, false);
});

// ── 4. Epoch applicability ───────────────────────────────────────────────────

test('check 4: an attestation issued AFTER the epoch says nothing about it', () => {
  const k = key();
  const a = attestation({
    attestedSpki: Buffer.from(k.spki),
    notBefore: new Date('2026-11-01T00:00:00Z'),
    notAfter: new Date('2027-11-01T00:00:00Z'),
  });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.epoch_applicability.ok, false);
  assert.match(r.checks.epoch_applicability.detail, /after|does not cover/i);
});

test('check 4: an attestation expiring mid-epoch does not cover the whole epoch', () => {
  const k = key();
  const a = attestation({
    attestedSpki: Buffer.from(k.spki),
    notBefore: new Date('2026-09-01T00:00:00Z'),
    notAfter: new Date('2026-10-02T12:00:00Z'),
  });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  // Partial cover is not cover. Signatures from the uncovered half of the
  // epoch would be reported as independently supported on the strength of a
  // document that had already expired.
  assert.equal(r.checks.epoch_applicability.ok, false);
});

test('check 4: with no epoch span supplied, applicability cannot be judged', () => {
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, { anchors: [a.root], epochPublicKey: k.raw });
  assert.equal(r.supported, false);
  assert.equal(r.checks.epoch_applicability.ok, false);
  assert.match(r.checks.epoch_applicability.detail, /no epoch span/i);
});

// ── 5. Custody properties ────────────────────────────────────────────────────

test('check 5: a document that merely proves a key exists is refused', () => {
  const k = key();
  const a = attestation({ attestedSpki: Buffer.from(k.spki), nonExportable: false });
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.supported, false);
  assert.equal(r.checks.custody_properties.ok, false);
  assert.match(r.checks.custody_properties.detail, /non.exportab/i);
  // A managed key that could be exported is a managed key, not a custody
  // guarantee, and a validator that accepted its existence certificate would
  // launder the weaker claim into the stronger one.
});

test('check 5: the extension is read, not assumed from the issuer', () => {
  const k = key();
  const a = attestation({ attestedSpki: Buffer.from(k.spki), nonExportable: false });
  assert.ok(!a.leaf.raw.includes(Buffer.from(OID_NON_EXPORTABLE.split('.').map(Number).slice(2))),
    'sanity: the fixture really omits the extension');
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
    requireProperties: [],
  });
  // With the requirement explicitly waived the check passes — and the result
  // says the reader waived it, rather than quietly reporting support.
  assert.equal(r.checks.custody_properties.ok, true);
  assert.match(r.checks.custody_properties.detail, /waived|no custody properties were required/i);
});

// ── Malformed input ──────────────────────────────────────────────────────────

test('bytes that are not a certificate are refused, not a crash', () => {
  const { k, a } = valid();
  for (const bad of [Buffer.alloc(0), Buffer.from('nope'), a.leaf.raw.subarray(0, 30)]) {
    const r = validateAttestation(bad, {
      anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
    });
    assert.equal(r.supported, false);
    assert.ok(r.detail.length > 0);
  }
});

test('an attestation never establishes destruction, whatever else it establishes', () => {
  // SEC-17's limit, asserted rather than documented. If this module ever grows
  // a field claiming historical destruction, this is what should fail.
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.equal(r.establishes_destruction, false);
  assert.ok(!JSON.stringify(r).includes('destruction-verified'));
});

test('the fixture is OUR document, and the result says so', () => {
  // docs/m3a-failure-modes.md records that FR-70 ships as a correct procedure
  // for which no genuine instance exists: no cloud path issues an Ed25519
  // attestation. A validator tested only against documents we wrote is worth
  // something — it is not worth what a real one would be, and the result
  // carries that caveat so a reader of the report sees it too.
  const { k, a } = valid();
  const r = validateAttestation(a.leaf.raw, {
    anchors: [a.root], epochPublicKey: k.raw, epochSpan: EPOCH,
  });
  assert.match(r.detail, /attestation/i);
  assert.equal(typeof r.provider_untested, 'boolean');
  assert.equal(r.provider_untested, true);
});
