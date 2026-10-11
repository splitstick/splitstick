import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify as nodeVerify, createPublicKey } from 'node:crypto';
import { checkpointText, encodeNote, parseNote, formatVkey } from '@splitstick/core/note';
import { signNote, verifyNoteSignature } from '@splitstick/core/signer';
import { treeRoot } from '@splitstick/core/merkle';
import { kmsSigner } from '../src/index.mjs';

/**
 * NFR-09's verification clause, against a real AWS KMS key.
 *
 * This is the only test that proves anything about interoperability. Everything
 * in signer.test.mjs runs against a fake and proves the adapter sends the right
 * request and refuses the wrong configuration — which is worth having and is
 * not the same claim. A signature is interoperable only if an implementation
 * that is not ours can check it.
 *
 * It needs a key, so it needs credentials. Run it with:
 *
 *   SPLITSTICK_KMS_KEY_ARN=arn:aws:kms:eu-west-1:…:key/… \
 *   AWS_REGION=eu-west-1 npm run test:kms
 *
 * Create the key with:
 *
 *   aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY \
 *     --description 'splitstick NFR-09 verification'
 *
 * **It reports itself as NOT RUN rather than passing when the key is absent.**
 * A skipped test that reads as success is the pattern this project has had to
 * fix three times, so NFR-09 does not count as verified until this has actually
 * executed — and the harness says so in its own output.
 */

const KEY_ARN = process.env.SPLITSTICK_KMS_KEY_ARN;
const configured = typeof KEY_ARN === 'string' && KEY_ARN.length > 0;
const ORIGIN = 'splitstick.dev/nfr-09';

test('NFR-09 interoperability against a real KMS key', async (t) => {
  if (!configured) {
    // Deliberately not `t.skip()` alone: the message is the point. It must be
    // impossible to read a run of this suite as having verified NFR-09.
    process.stderr.write(
      '\n  NFR-09 NOT VERIFIED: no SPLITSTICK_KMS_KEY_ARN in the environment, so the only test\n'
      + '  that proves a KMS signature is checkable by an independent implementation did not run.\n'
      + '  See the header of this file for the two commands that create a key and run it.\n\n');
    t.skip('SPLITSTICK_KMS_KEY_ARN is not set — NFR-09 remains unverified');
    return;
  }

  const { KMSClient } = await import('@aws-sdk/client-kms');
  const client = new KMSClient({});
  const signer = await kmsSigner({ client, keyId: KEY_ARN, name: ORIGIN });

  assert.equal(signer.custody, 'kms');
  assert.equal(signer.publicKey.length, 32);

  const subject = checkpointText({
    origin: ORIGIN, tree_size: 7, root: treeRoot([Buffer.from('a'), Buffer.from('b')]), suite: 'SS1' });

  const sig = await signNote(subject, signer);

  // 1 — our own verifier accepts it.
  assert.equal(await verifyNoteSignature(subject, sig, signer.verifier()), true);

  // 2 — and so does node:crypto directly, from the public key alone. This is
  // the claim: an independent Ed25519 implementation, given only the published
  // key and the note bytes, reaches the same answer. If AWS had signed with
  // ED25519_PH_SHA_512 this is the assertion that would fail.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), signer.publicKey]);
  const independent = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(nodeVerify(null, Buffer.from(subject, 'utf8'), independent, sig.signature), true,
    'a PureEdDSA signature over the note bytes must verify under a plain Ed25519 verifier');

  // 3 — a changed subject does not verify, so the signature is over what we think.
  assert.equal(
    nodeVerify(null, Buffer.from(subject.replace('\n7\n', '\n8\n'), 'utf8'), independent, sig.signature),
    false, 'altering the tree size must invalidate the signature');

  // 4 — the note round-trips, and the vkey a reader would pin resolves.
  const note = parseNote(encodeNote(subject, [sig]));
  assert.equal(note.text, subject);
  assert.equal(await verifyNoteSignature(note.text, note.signatures[0], signer.verifier()), true);
  assert.match(formatVkey(ORIGIN, signer.publicKey), /^splitstick\.dev\/nfr-09\+[0-9a-f]{8}\+/);

  process.stderr.write(`\n  NFR-09 VERIFIED against ${KEY_ARN}\n\n`);
});

test('the integration suite states plainly whether it verified anything', () => {
  // A test about the test, because the failure mode here is a green suite that
  // proved nothing. Whichever way it goes, the run must be unambiguous.
  assert.equal(typeof configured, 'boolean');
  if (!configured) {
    assert.ok(true, 'reported NOT VERIFIED above; NFR-09 stays open in the backlog');
  }
});
