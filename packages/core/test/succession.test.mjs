import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { generateDevSigner } from '../src/signer-file.mjs';
import {
  SUCCESSION_DOMAIN, endorsementSubject, endorse, verifySuccession, successionReport,
  SuccessionError,
} from '../src/succession.mjs';

const rawPub = (/** @type {any} */ pub) => pub.export({ format: 'der', type: 'spki' }).subarray(-32);

/** An epoch key pair with a raw public key beside it. */
function epochKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicKey, raw: rawPub(publicKey) };
}

/**
 * A valid chain of `n` epochs, 0..n-1, every epoch endorsing its successor.
 * @param {number} n
 * @param {('software'|'kms'|'hsm')[]} [custody]
 */
async function chain(n, custody = []) {
  const keys = Array.from({ length: n }, () => epochKey());
  const entries = [];
  for (let i = 0; i < n; i += 1) {
    const k = keys[i];
    /** @type {any} */
    const e = { epoch: i, public_key: k.raw.toString('base64'), custody: custody[i] ?? 'kms' };
    if (i > 0) {
      e.endorsement = cryptoSign(null, endorsementSubject(k.raw, i), keys[i - 1].privateKey)
        .toString('base64');
    }
    entries.push(e);
  }
  return { keys, entries, root: keys[0].raw };
}

// ── Row 12 — the property FR-11 exists for ────────────────────────────────────

test('row 12: an epoch-N key cannot produce a valid epoch-N-1 signature', async () => {
  const a = await generateDevSigner('log.example/a');
  const b = await generateDevSigner('log.example/b');
  const subject = Buffer.from('checkpoint bytes signed during epoch N-1');
  const byA = await a.sign(subject);

  // A verifies under A. That is the baseline, not the claim.
  const { verify } = await import('node:crypto');
  const { publicKeyFromRaw } = await import('../src/signer.mjs');
  assert.equal(verify(null, subject, publicKeyFromRaw(a.publicKey), byA), true);

  // The claim: epoch N's key cannot produce something that checks out under
  // epoch N-1's public key. Nothing here is a Splitstick property — it is
  // Ed25519 — but FR-11's whole value rests on it, so it is asserted rather
  // than assumed.
  const byB = await b.sign(subject);
  assert.equal(verify(null, subject, publicKeyFromRaw(a.publicKey), byB), false);
  assert.notEqual(byA.toString('hex'), byB.toString('hex'));
});

test('row 12: the endorsement subject binds the successor key AND its epoch number', () => {
  const k = epochKey();
  const atOne = endorsementSubject(k.raw, 1);
  const atTwo = endorsementSubject(k.raw, 2);
  // Without the epoch number in the subject, an endorsement of a key for
  // epoch 1 would be replayable as an endorsement of the same key for epoch 2,
  // which is how a skipped epoch would be made to look contiguous.
  assert.notEqual(atOne.toString('hex'), atTwo.toString('hex'));
  assert.equal(atOne[0], SUCCESSION_DOMAIN);
  assert.equal(atOne.length, 1 + 32 + 8);
  assert.equal(atOne.subarray(1, 33).toString('hex'), k.raw.toString('hex'));
  assert.equal(atOne.readBigUInt64BE(33), 1n);
  // The prefix is what keeps an endorsement from being read as a leaf, a node,
  // a chain head or a content commitment.
  assert.equal(SUCCESSION_DOMAIN, 0x04);
});

// ── Row 13 — a skipped epoch ──────────────────────────────────────────────────

test('row 13: a succession chain that skips an epoch is SUCCESSION_BROKEN', async () => {
  const { entries, root } = await chain(4);
  const gapped = [entries[0], entries[1], entries[3]];
  const r = verifySuccession(root, gapped);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /epoch 2/.test(f.detail)));
});

test('row 13: an epoch whose endorsement is signed by the wrong predecessor is broken', async () => {
  const { keys, entries, root } = await chain(4);
  // Epoch 3 endorsed by epoch 1's key instead of epoch 2's. Every epoch is
  // present and the signature is cryptographically valid — just not by the
  // predecessor, which is the only thing that makes the walk mean anything.
  entries[3].endorsement = cryptoSign(
    null, endorsementSubject(Buffer.from(entries[3].public_key, 'base64'), 3), keys[1].privateKey,
  ).toString('base64');
  const r = verifySuccession(root, entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /epoch 3/.test(f.detail)));
});

test('row 13: a chain not starting at the pinned root is broken, not silently rebased', async () => {
  const { entries } = await chain(3);
  const stranger = epochKey();
  const r = verifySuccession(stranger.raw, entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /pinned root/.test(f.detail)));
  assert.deepEqual(r.epochs, []);
});

// ── Row 14 — self-endorsement and forks ───────────────────────────────────────

test('row 14: an epoch endorsing itself is refused', async () => {
  const { keys, entries, root } = await chain(3);
  // Epoch 2 presents its own key again and endorses it with that same key.
  entries[2].public_key = entries[1].public_key;
  entries[2].endorsement = cryptoSign(
    null, endorsementSubject(Buffer.from(entries[1].public_key, 'base64'), 2), keys[1].privateKey,
  ).toString('base64');
  const r = verifySuccession(root, entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /endorses itself/.test(f.detail)));
});

test('row 14: two entries for the same epoch are refused as a fork', async () => {
  const { keys, entries, root } = await chain(3);
  const other = epochKey();
  const fork = {
    epoch: 2,
    public_key: other.raw.toString('base64'),
    custody: 'kms',
    endorsement: cryptoSign(null, endorsementSubject(other.raw, 2), keys[1].privateKey)
      .toString('base64'),
  };
  // Both endorsements are valid under epoch 1's key. Only a duplicate-epoch
  // check catches this; signature checking alone cannot, which is the point.
  const r = verifySuccession(root, [...entries, fork]);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /two keys/.test(f.detail)));
});

test('row 14: endorsing yourself is refused at the point of emission too', async () => {
  const s = await generateDevSigner('log.example/x');
  await assert.rejects(
    () => endorse(s, s.publicKey, 1),
    (/** @type {any} */ e) => e instanceof SuccessionError && /itself/.test(e.message),
  );
});

test('row 14: epoch 0 cannot be endorsed, and an epoch must follow its endorser', async () => {
  const s = await generateDevSigner('log.example/x');
  const next = epochKey();
  await assert.rejects(() => endorse(s, next.raw, 0),
    (/** @type {any} */ e) => e instanceof SuccessionError && /epoch 0/.test(e.message));
  await assert.rejects(() => endorse(s, next.raw, -1),
    (/** @type {any} */ e) => e instanceof SuccessionError);
  await assert.rejects(() => endorse(s, next.raw, 1.5),
    (/** @type {any} */ e) => e instanceof SuccessionError);
});

test('endorse goes through the signer seam and produces a chain that walks', async () => {
  // The rejection paths above were the only thing exercising endorse(), which
  // left its happy path unproven — and it was broken. A test that only asserts
  // refusals is not a test of the function.
  const zero = await generateDevSigner('log.example/e0');
  const one = epochKey();
  const sig = await endorse(zero, one.raw, 1);
  assert.equal(sig.length, 64);
  const r = verifySuccession(zero.publicKey, [
    { epoch: 0, public_key: zero.publicKey.toString('base64'), custody: 'software' },
    {
      epoch: 1, public_key: one.raw.toString('base64'), custody: 'software',
      endorsement: sig.toString('base64'),
    },
  ]);
  assert.deepEqual(r.findings, []);
  assert.equal(r.ok, true);
  assert.equal(r.epochs.length, 2);
});

test('a signer that returns a short signature is refused at endorsement time', async () => {
  const zero = await generateDevSigner('log.example/e0');
  const one = epochKey();
  const stunted = { ...zero, async sign() { return Buffer.alloc(32); } };
  await assert.rejects(() => endorse(stunted, one.raw, 1),
    (/** @type {any} */ e) => e instanceof SuccessionError && /32 bytes/.test(e.message));
});

// ── Row 15 — an unpinned root claims nothing ──────────────────────────────────

test('row 15: with no pinned root, nothing is claimed — IDENTITY_UNPINNED', async () => {
  const { entries } = await chain(3);
  for (const absent of [undefined, null]) {
    const r = verifySuccession(/** @type {any} */ (absent), entries);
    assert.equal(r.ok, false);
    assert.ok(r.findings.some(f => f.code === 'IDENTITY_UNPINNED'));
    // Nothing is reported as verified: a walk from an unpinned root is not a
    // weaker result, it is no result.
    assert.deepEqual(r.epochs, []);
  }
});

test('an empty chain under a pinned root yields no epochs and no claim', () => {
  const k = epochKey();
  const r = verifySuccession(k.raw, []);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /no epoch/.test(f.detail)));
});

// ── Row 16 — software custody cannot claim forward secrecy ────────────────────

test('row 16: an epoch declared software gets no forward-secrecy claim', async () => {
  const { entries, root } = await chain(3, ['kms', 'software', 'kms']);
  const rep = successionReport(root, entries);
  assert.equal(rep.ok, true);
  const one = rep.epochs.find(e => e.epoch === 1);
  assert.equal(one?.custody, 'software');
  assert.equal(one?.forward_secrecy, 'refused');
  assert.match(String(one?.why), /software/);
  // And the refusal does not spread: a kms epoch beside it is unaffected.
  assert.equal(rep.epochs.find(e => e.epoch === 0)?.forward_secrecy, 'claimed');
});

test('row 16: custody is reported as operator-declared, never as established', async () => {
  const { entries, root } = await chain(2, ['hsm', 'hsm']);
  const rep = successionReport(root, entries);
  for (const e of rep.epochs) {
    assert.equal(e.custody_basis, 'operator-declared');
    // FR-70's attestation path is M3a. Until one is supplied and passes all
    // five checks, no epoch may read as independently supported.
    assert.equal(e.custody_independently_supported, false);
  }
});

test('an unrecognised custody class is refused rather than defaulted', async () => {
  const { entries, root } = await chain(2);
  entries[1].custody = 'secure-enclave';
  const r = verifySuccession(root, entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN' && /custody/.test(f.detail)));
});

test('the current epoch has no forward secrecy, whatever its custody', async () => {
  const { entries, root } = await chain(3, ['hsm', 'hsm', 'hsm']);
  const rep = successionReport(root, entries);
  const last = rep.epochs.at(-1);
  // DES-06: "A key in an HSM that is never rotated has no forward secrecy
  // whatever its custody class." The newest epoch is still signing with the
  // key in question, so there is nothing retired about it.
  assert.equal(last?.epoch, 2);
  assert.equal(last?.retired, false);
  assert.equal(last?.forward_secrecy, 'not-yet');
  assert.equal(rep.epochs.find(e => e.epoch === 0)?.retired, true);
});

test('destruction is reported as operator-declared and never as verified', async () => {
  const { entries, root } = await chain(2, ['hsm', 'hsm']);
  const rep = successionReport(root, entries);
  assert.equal(rep.destruction_basis, 'operator-declared');
  // Nobody can prove they deleted a key (SEC-17). If this report ever grows a
  // field claiming otherwise, this assertion is the thing that should fail.
  assert.ok(!Object.values(rep.epochs[0]).includes('destruction-verified'));
});

// ── Row 17 — a retired key's signatures stay valid ────────────────────────────

test('row 17: a retired epoch signature still verifies years later', async () => {
  const { keys, entries, root } = await chain(4);
  const rep = successionReport(root, entries);
  assert.equal(rep.ok, true);
  const subject = Buffer.from('a checkpoint from epoch 1, long retired');
  const sig = cryptoSign(null, subject, keys[1].privateKey);
  const { verify } = await import('node:crypto');
  const { publicKeyFromRaw } = await import('../src/signer.mjs');
  const one = rep.epochs.find(e => e.epoch === 1);
  assert.equal(one?.retired, true);
  // Rotation is not an amnesty. The public key is retained precisely so this
  // keeps working, and a verifier must not discount it for being old.
  assert.equal(
    verify(null, subject, publicKeyFromRaw(Buffer.from(String(one?.public_key), 'base64')), sig),
    true,
  );
});

test('a valid chain of 64 epochs walks cleanly and attributes every epoch', async () => {
  const { entries, root } = await chain(64);
  const rep = successionReport(root, entries);
  assert.equal(rep.ok, true);
  assert.deepEqual(rep.findings, []);
  assert.equal(rep.epochs.length, 64);
  assert.deepEqual(rep.epochs.map(e => e.epoch), Array.from({ length: 64 }, (_, i) => i));
});

test('a chain presented out of order is walked by epoch, not by file order', async () => {
  const { entries, root } = await chain(5);
  const shuffled = [entries[3], entries[0], entries[4], entries[1], entries[2]];
  const rep = successionReport(root, shuffled);
  assert.equal(rep.ok, true);
  assert.deepEqual(rep.epochs.map(e => e.epoch), [0, 1, 2, 3, 4]);
});

test('a malformed entry is a finding, not a crash', async () => {
  const { entries, root } = await chain(2);
  for (const bad of [
    { epoch: 1 },
    { epoch: 1, public_key: 'not base64 at all!!', custody: 'kms', endorsement: 'x' },
    { epoch: 1, public_key: Buffer.alloc(31).toString('base64'), custody: 'kms', endorsement: 'x' },
    { epoch: '1', public_key: entries[1].public_key, custody: 'kms', endorsement: 'x' },
    { epoch: 1, public_key: entries[1].public_key, custody: 'kms', endorsement: 'AAAA' },
  ]) {
    const r = verifySuccession(root, [entries[0], /** @type {any} */ (bad)]);
    assert.equal(r.ok, false, `${JSON.stringify(bad)} should not verify`);
    assert.ok(r.findings.length > 0);
  }
});

test('the root entry may not carry an endorsement', async () => {
  const { keys, entries, root } = await chain(2);
  // endorsementSubject refuses to build a subject for epoch 0, so the fixture
  // has to assemble the bytes by hand — which is the point: the only way to
  // produce this is deliberately.
  const subject = Buffer.concat([
    Buffer.from([0x04]), Buffer.from(entries[0].public_key, 'base64'), Buffer.alloc(8),
  ]);
  entries[0].endorsement = cryptoSign(null, subject, keys[0].privateKey).toString('base64');
  const r = verifySuccession(root, entries);
  assert.equal(r.ok, false);
  assert.ok(r.findings.some(f => /root/.test(f.detail)));
});
