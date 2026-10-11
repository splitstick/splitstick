import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { signNote, verifyNoteSignature } from '@splitstick/core/signer';
import { checkpointText } from '@splitstick/core/note';
import { treeRoot } from '@splitstick/core/merkle';
import { kmsSigner, KmsSignerError, ED25519_RAW, MAX_RAW_MESSAGE_BYTES } from '../src/index.mjs';

/**
 * Every row of docs/m2-failure-modes.md that can be tested without an AWS
 * account, written before the implementation.
 *
 * The client is faked, which is honest about what this proves: that the adapter
 * sends the right request, refuses the wrong configuration, and surfaces every
 * error rather than swallowing it. It does NOT prove a real KMS signature is
 * verifiable — only a real key can, and that test is in integration.test.mjs
 * and reports itself skipped when credentials are absent.
 */

const KEY = 'arn:aws:kms:eu-west-1:111122223333:key/abcd-1234';
const pair = generateKeyPairSync('ed25519');
const RAW_PUBLIC = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

/** A KMS stand-in that signs with a local key, so the bytes are real Ed25519. */
function fakeKms(over = {}) {
  const calls = [];
  let signs = 0;
  return {
    calls,
    async send(command) {
      calls.push(command);
      const name = command.constructor.name;
      if (name === 'DescribeKeyCommand') {
        if (over.describeError) throw over.describeError;
        return {
          KeyMetadata: {
            KeyId: KEY,
            KeySpec: over.keySpec ?? 'ECC_NIST_EDWARDS25519',
            KeyUsage: over.keyUsage ?? 'SIGN_VERIFY',
            KeyState: over.keyState ?? 'Enabled',
            SigningAlgorithms: over.signingAlgorithms ?? ['ED25519_SHA_512', 'ED25519_PH_SHA_512'],
          },
        };
      }
      if (name === 'GetPublicKeyCommand') {
        if (over.publicKeyError) throw over.publicKeyError;
        return { PublicKey: over.publicKey ?? pair.publicKey.export({ format: 'der', type: 'spki' }) };
      }
      if (name === 'SignCommand') {
        signs += 1;
        // `afterProbe` lets a fake behave correctly for the construction probe
        // and misbehave afterwards, so the sign-time guards are still reachable
        // now that construction proves the key with a real signature.
        const past = over.afterProbe ? signs > 1 : true;
        if (over.signError && past) throw over.signError;
        if (over.signature && past) return { Signature: over.signature };
        return { Signature: nodeSign(null, Buffer.from(command.input.Message), pair.privateKey) };
      }
      throw new Error(`unexpected command ${name}`);
    },
  };
}

const text = () => checkpointText({
  origin: 'splitstick.dev/host-1', tree_size: 3, root: treeRoot([Buffer.from('a')]), suite: 'SS1' });

// ─── row 1: the trap in AWS's own API ────────────────────────────────────────

/**
 * ED25519_PH_SHA_512 is HashEdDSA. A signature made with it cannot be checked
 * by node:crypto or any other Ed25519 verifier, and the failure is silent — the
 * signature is well-formed and simply does not verify. AWS's note that the two
 * "cannot be used interchangeably" is the whole risk, so it is unreachable here.
 */
test('the HashEdDSA algorithm cannot be selected, by any route', async () => {
  const kms = fakeKms();
  await assert.rejects(
    () => kmsSigner({ client: kms, keyId: KEY, name: 'o', algorithm: 'ED25519_PH_SHA_512' }),
    KmsSignerError);
  await assert.rejects(
    () => kmsSigner({ client: kms, keyId: KEY, name: 'o', algorithm: 'ED25519_SHA_256' }),
    KmsSignerError);
  assert.equal(ED25519_RAW.algorithm, 'ED25519_SHA_512');
  assert.equal(ED25519_RAW.messageType, 'RAW');
});

test('every sign request is RAW with the pure-Ed25519 algorithm', async () => {
  const kms = fakeKms();
  const signer = await kmsSigner({ client: kms, keyId: KEY, name: 'o' });
  await signer.sign(Buffer.from('subject'));
  const signCalls = kms.calls.filter(c => c.constructor.name === 'SignCommand');
  assert.equal(signCalls.length, 2, 'the construction probe, then the real subject');
  for (const call of signCalls) {
    assert.equal(call.input.SigningAlgorithm, 'ED25519_SHA_512');
    assert.equal(call.input.MessageType, 'RAW', 'including the probe — no path uses another type');
  }
  assert.equal(Buffer.from(signCalls[1].input.Message).toString(), 'subject');
});

// ─── rows 2, 3, 5, 9: refuse the wrong key or the wrong answer ───────────────

test('a signature that is not 64 bytes is refused, at construction and at sign time', async () => {
  for (const bad of [Buffer.alloc(63), Buffer.alloc(65), Buffer.alloc(0)]) {
    // The construction probe catches it first, which is the better place.
    await assert.rejects(
      () => kmsSigner({ client: fakeKms({ signature: bad }), keyId: KEY, name: 'o' }), /64/);
    // And the guard still holds if a key starts misbehaving later.
    const signer = await kmsSigner({
      client: fakeKms({ signature: bad, afterProbe: true }), keyId: KEY, name: 'o' });
    await assert.rejects(() => signer.sign(Buffer.from('x')), /64/);
  }
});

test('a key of the wrong spec or usage is refused, naming what was found', async () => {
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ keySpec: 'ECC_NIST_P256' }), keyId: KEY, name: 'o' }),
    /ECC_NIST_P256/);
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ keyUsage: 'ENCRYPT_DECRYPT' }), keyId: KEY, name: 'o' }),
    /ENCRYPT_DECRYPT|SIGN_VERIFY/);
});

test('a key that is not usable is refused rather than discovered at sign time', async () => {
  for (const state of ['Disabled', 'PendingDeletion', 'PendingImport', 'Unavailable']) {
    await assert.rejects(
      () => kmsSigner({ client: fakeKms({ keyState: state }), keyId: KEY, name: 'o' }),
      new RegExp(state));
  }
});

test('a key whose advertised algorithms exclude ours is refused', async () => {
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ signingAlgorithms: ['ED25519_PH_SHA_512'] }), keyId: KEY, name: 'o' }),
    /ED25519_SHA_512/);
});

/**
 * Row 9. If the public key fetched is not the one that signs, a verifier pins an
 * identity that can verify nothing — and the failure would appear at
 * verification time, on someone else's machine, long after the fact.
 */
test('the fetched public key is proved to match the signing key', async () => {
  const other = generateKeyPairSync('ed25519');
  await assert.rejects(
    () => kmsSigner({
      client: fakeKms({ publicKey: other.publicKey.export({ format: 'der', type: 'spki' }) }),
      keyId: KEY, name: 'o',
    }),
    /does not verify|mismatch/i);
});

test('a public key that is not Ed25519-shaped is refused', async () => {
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ publicKey: Buffer.alloc(10) }), keyId: KEY, name: 'o' }),
    KmsSignerError);
});

// ─── row 5: the message-size limit ──────────────────────────────────────────

test('a subject beyond the RAW message limit is refused, with the limit named', async () => {
  const signer = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'o' });
  await assert.rejects(
    () => signer.sign(Buffer.alloc(MAX_RAW_MESSAGE_BYTES + 1)),
    new RegExp(String(MAX_RAW_MESSAGE_BYTES)));
  await assert.doesNotReject(() => signer.sign(Buffer.alloc(MAX_RAW_MESSAGE_BYTES)));
});

// ─── rows 6, 7, 8: errors surface, never silently succeed ───────────────────

test('a throttling or network error surfaces rather than returning a bad signature', async () => {
  const throttled = Object.assign(new Error('Rate exceeded'), { name: 'ThrottlingException' });
  // Unavailable from the start: construction fails, so nothing is built on it.
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ signError: throttled }), keyId: KEY, name: 'o' }),
    /Rate exceeded|Throttling/);

  // Throttled later: the error reaches the caller, and checkpointing fails
  // while collection continues (SCOPE-16 — the collector is fail-open).
  const failing = await kmsSigner({
    client: fakeKms({ signError: throttled, afterProbe: true }), keyId: KEY, name: 'o' });
  await assert.rejects(() => failing.sign(Buffer.from('x')), /Rate exceeded|Throttling/);

  // A healthy signer is unaffected: no state is shared between instances.
  const healthy = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'o' });
  assert.equal((await healthy.sign(Buffer.from('x'))).length, 64);
});

test('a missing permission fails at construction, naming the permission', async () => {
  const denied = Object.assign(new Error('User is not authorized to perform: kms:DescribeKey'),
    { name: 'AccessDeniedException' });
  await assert.rejects(
    () => kmsSigner({ client: fakeKms({ describeError: denied }), keyId: KEY, name: 'o' }),
    /kms:DescribeKey|not authorized/);
});

test('no key id, and no name, are usage errors rather than late failures', async () => {
  // Cast: these calls are invalid on purpose, which is what is under test. The
  // typechecker objecting is the type being right, not the test being wrong.
  const bad = /** @type {any} */ (kmsSigner);
  await assert.rejects(() => bad({ client: fakeKms(), name: 'o' }), KmsSignerError);
  await assert.rejects(() => bad({ client: fakeKms(), keyId: KEY }), KmsSignerError);
  await assert.rejects(() => bad({ keyId: KEY, name: 'o' }), KmsSignerError);
  await assert.rejects(() => bad({ client: fakeKms(), keyId: '', name: 'o' }), KmsSignerError);
});

// ─── row 10: concurrency ────────────────────────────────────────────────────

test('one signer serves concurrent checkpoints independently', async () => {
  const signer = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'splitstick.dev/host-1' });
  const subjects = Array.from({ length: 8 }, (_, i) => Buffer.from(`subject-${i}`));
  const sigs = await Promise.all(subjects.map(s => signer.sign(s)));
  assert.equal(new Set(sigs.map(s => s.toString('hex'))).size, 8, 'no two are the same');
  subjects.forEach((s, i) => {
    assert.equal(nodeVerify(null, s, pair.publicKey, sigs[i]), true, `signature ${i}`);
  });
});

// ─── the seam contract ──────────────────────────────────────────────────────

test('it satisfies the core signer interface and declares kms custody', async () => {
  const signer = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'splitstick.dev/host-1' });
  assert.equal(signer.algorithm, 'ed25519');
  assert.equal(signer.custody, 'kms');
  assert.equal(signer.publicKey.length, 32);
  assert.equal(signer.keyId.length, 4);
  assert.equal(typeof signer.sign, 'function');
  assert.equal(typeof signer.verifier, 'function');
});

test('a note signed through KMS verifies under the core verifier', async () => {
  const signer = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'splitstick.dev/host-1' });
  const subject = text();
  const sig = await signNote(subject, signer);
  assert.equal(await verifyNoteSignature(subject, sig, signer.verifier()), true);
  // And a changed subject does not verify, which is the point of signing it.
  assert.equal(await verifyNoteSignature(subject.replace('3', '4'), sig, signer.verifier()), false);
});

test('SEC-14: the signer exposes no key material', async () => {
  const signer = await kmsSigner({ client: fakeKms(), keyId: KEY, name: 'o' });
  for (const k of Object.keys(signer)) assert.ok(!/private|secret|seed/i.test(k), k);
  assert.ok(!JSON.stringify(signer).includes('PRIVATE'));
});
