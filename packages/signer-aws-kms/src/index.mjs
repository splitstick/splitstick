/**
 * AWS KMS signer — FR-10, NFR-09, SEC-14.
 *
 * A separate package, not part of core, because it needs a cloud SDK and
 * `@splitstick/verify` depends on core. NFR-05 and NFR-06 require the verifier
 * to be offline by construction, so a transitive SDK dependency in core would
 * contradict that even if the verifier never called it (DES-14).
 *
 * What this adapter is careful about, in order of how badly it would fail:
 *
 * **The algorithm.** AWS offers two Ed25519 variants. `ED25519_SHA_512` with
 * `MessageType: RAW` is PureEdDSA over the bytes handed to it — what the C2SP
 * note format needs, and what any other Ed25519 verifier can check.
 * `ED25519_PH_SHA_512` is HashEdDSA, and a signature made with it is
 * well-formed and verifiable by nobody else. AWS's documentation says the two
 * "cannot be used interchangeably"; here the wrong one is simply unreachable.
 *
 * **The key.** Spec, usage, state and advertised algorithms are all checked at
 * construction, so a misconfigured key fails where someone is watching rather
 * than at the first checkpoint.
 *
 * **The public key.** It is fetched and then PROVED to belong to the key that
 * signs, by signing a probe and verifying it locally. A mismatch would mean a
 * reader pins an identity that can verify nothing, and the failure would surface
 * on their machine, long after the fact.
 *
 * **The identity validated at construction is the identity that signs.** A KMS
 * alias is mutable — it can be repointed at a different key at any time — so
 * the configured identifier is resolved once to the immutable ARN that
 * DescribeKey returns, and that ARN is what every subsequent request names. The
 * construction probe cannot protect against a repoint, because the repoint
 * happens afterwards. An operator who configured an alias and had it moved
 * would otherwise produce signatures that no longer verify under the identity a
 * reader pinned, which a verifier reports as tampering — by accident, for an
 * operator who did nothing wrong.
 *
 * The private key never exists outside KMS, and nothing here can export it:
 * the module has no key-export API and the seam only ever returns signatures.
 */

import { createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { noteKeyId } from '@splitstick/core/note';

export class KmsSignerError extends Error {
  /** @param {string} m @param {{ cause?: unknown }} [opts] */
  constructor(m, opts = {}) {
    super(m, opts);
    this.name = 'KmsSignerError';
  }
}

/**
 * The only acceptable configuration. PureEdDSA over raw bytes.
 *
 * Frozen and exported so a test can assert it rather than trust a comment.
 */
export const ED25519_RAW = Object.freeze({
  keySpec: 'ECC_NIST_EDWARDS25519',
  algorithm: 'ED25519_SHA_512',
  messageType: 'RAW',
});

/** AWS's limit on a RAW message. The note subject is ~100 bytes; this is headroom. */
export const MAX_RAW_MESSAGE_BYTES = 4096;

const USABLE_STATES = new Set(['Enabled']);

/** @param {Uint8Array} der SPKI DER bytes @returns {Buffer} the raw 32-byte key */
function rawFromSpki(der) {
  const key = createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new KmsSignerError(`the key is ${key.asymmetricKeyType}, not ed25519`);
  }
  return key.export({ format: 'der', type: 'spki' }).subarray(-32);
}

/**
 * @param {object} o
 * @param {any} o.client a KMSClient, or anything with the same `send`
 * @param {string} o.keyId key id, alias or ARN. An alias is resolved once to
 *   the immutable ARN and retained only as configuration metadata.
 * @param {string} o.name the note identity, which is also the log origin
 * @param {string} [o.algorithm] only to be REFUSED if it is not the right one;
 *   it exists so a misconfiguration is an error rather than being ignored
 * @returns {Promise<import('@splitstick/core/signer').Signer>}
 */
export async function kmsSigner({ client, keyId, name, algorithm }) {
  if (!client) throw new KmsSignerError('a KMS client is required');
  if (typeof keyId !== 'string' || !keyId) throw new KmsSignerError('keyId is required');
  if (typeof name !== 'string' || !name) {
    throw new KmsSignerError('name is required: it is the note identity and the log origin');
  }
  if (algorithm !== undefined && algorithm !== ED25519_RAW.algorithm) {
    throw new KmsSignerError(
      `signing algorithm ${algorithm} is not supported. Only ${ED25519_RAW.algorithm} with `
      + `MessageType ${ED25519_RAW.messageType} is PureEdDSA over the signed subject; `
      + 'ED25519_PH_SHA_512 is HashEdDSA and its signatures are verifiable by no other '
      + 'Ed25519 implementation');
  }

  const { DescribeKeyCommand, GetPublicKeyCommand, SignCommand } = await import('@aws-sdk/client-kms');

  // 1 — the key is the right kind, and usable now.
  let meta;
  try {
    ({ KeyMetadata: meta } = await client.send(new DescribeKeyCommand({ KeyId: keyId })));
  } catch (err) {
    throw new KmsSignerError(
      `cannot describe ${keyId}: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
  }
  if (!meta) throw new KmsSignerError(`${keyId} returned no key metadata`);

  // Resolve to something that cannot move under us. An alias is mutable; an ARN
  // and a key id are not. Everything after this point names the resolved value.
  const resolved = meta.Arn ?? meta.KeyId;
  if (typeof resolved !== 'string' || !resolved) {
    throw new KmsSignerError(
      `${keyId} returned neither an ARN nor a key id, so there is no immutable identity to `
      + 'pin. An alias may be repointed at another key at any time, and a signer that keeps '
      + 'using the alias would sign under a key its own public key does not match');
  }
  if (meta.KeySpec !== ED25519_RAW.keySpec) {
    throw new KmsSignerError(
      `${keyId} has key spec ${meta.KeySpec}; SS1 needs ${ED25519_RAW.keySpec}`);
  }
  if (meta.KeyUsage !== 'SIGN_VERIFY') {
    throw new KmsSignerError(`${keyId} has usage ${meta.KeyUsage}; SIGN_VERIFY is required`);
  }
  if (!USABLE_STATES.has(String(meta.KeyState))) {
    throw new KmsSignerError(
      `${keyId} is in state ${meta.KeyState} and cannot sign. A key pending deletion still `
      + 'describes successfully, so this is checked here rather than at the first checkpoint');
  }
  if (Array.isArray(meta.SigningAlgorithms)
      && !meta.SigningAlgorithms.includes(ED25519_RAW.algorithm)) {
    throw new KmsSignerError(
      `${keyId} does not advertise ${ED25519_RAW.algorithm}; it offers `
      + `${meta.SigningAlgorithms.join(', ')}`);
  }

  // 2 — the public key, fetched.
  let publicKey;
  try {
    const { PublicKey } = await client.send(new GetPublicKeyCommand({ KeyId: resolved }));
    if (!PublicKey) throw new KmsSignerError(`${keyId} returned no public key`);
    publicKey = rawFromSpki(PublicKey);
  } catch (err) {
    if (err instanceof KmsSignerError) throw err;
    throw new KmsSignerError(
      `cannot fetch the public key for ${keyId}: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err });
  }

  /** @param {Uint8Array} bytes */
  const rawSign = async (bytes) => {
    if (bytes.length > MAX_RAW_MESSAGE_BYTES) {
      throw new KmsSignerError(
        `a RAW message is at most ${MAX_RAW_MESSAGE_BYTES} bytes and this subject is `
        + `${bytes.length}. It is refused rather than truncated, because a signature over part `
        + 'of a subject is worse than no signature');
    }
    const { Signature } = await client.send(new SignCommand({
      KeyId: resolved,
      Message: Buffer.from(bytes),
      MessageType: ED25519_RAW.messageType,
      SigningAlgorithm: ED25519_RAW.algorithm,
    }));
    const sig = Buffer.from(Signature ?? []);
    if (sig.length !== 64) {
      throw new KmsSignerError(`KMS returned a ${sig.length}-byte signature; Ed25519 is 64`);
    }
    return sig;
  };

  // 3 — prove the fetched key is the one that signs, before anyone depends on
  // it. Otherwise a verifier pins an identity that can verify nothing, and
  // finds out on their own machine long after the fact.
  const probe = randomBytes(32);
  const probeSig = await rawSign(probe);
  const verifies = cryptoVerify(null, probe, createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKey]),
    format: 'der', type: 'spki',
  }), probeSig);
  if (!verifies) {
    throw new KmsSignerError(
      `the public key fetched for ${keyId} does not verify a signature made by it. The identity `
      + 'a reader would pin cannot check this log');
  }

  const keyIdBytes = noteKeyId(name, publicKey);
  return {
    name,
    algorithm: 'ed25519',
    publicKey,
    keyId: keyIdBytes,
    /** The immutable identity that signs. */
    keyArn: resolved,
    /** What the operator configured, which may have been a mutable alias. */
    configuredKeyId: keyId,
    // Operator-declared, like every custody class: an HSM signature and a file
    // signature are byte-identical (DES-06). FR-65 records the declaration and
    // FR-70 is the only route to independent support.
    custody: 'kms',
    sign: rawSign,
    verifier() { return { name, publicKey, keyId: keyIdBytes }; },
  };
}
