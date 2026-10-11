# @splitstick/signer-aws-kms

AWS KMS signer for Splitstick: non-exportable Ed25519 custody behind the core
signer seam.

```js
import { KMSClient } from '@aws-sdk/client-kms';
import { kmsSigner } from '@splitstick/signer-aws-kms';

const signer = await kmsSigner({
  client: new KMSClient({}),
  keyId: 'arn:aws:kms:eu-west-1:…:key/…',
  name: 'splitstick.dev/host-1',   // the note identity, and the log origin
});
```

Create the key with the one spec that works:

```bash
aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY
```

## Why this is a separate package

It needs the AWS SDK, and `@splitstick/verify` depends on `@splitstick/core`.
NFR-05 and NFR-06 require the verifier to be offline by construction — no
network module, no credential, no account — so a transitive SDK dependency in
core would contradict that even if the verifier never called it. Core holds the
`sign(bytes) → signature` seam and nothing that reaches a network.

## The one thing to get right

AWS offers two Ed25519 variants and they are not interchangeable:

| Algorithm | What it is | Usable here |
|---|---|---|
| `ED25519_SHA_512` + `MessageType: RAW` | PureEdDSA over the bytes given | **yes** |
| `ED25519_PH_SHA_512` | HashEdDSA | **no** |

A HashEdDSA signature is well-formed and verifiable by no other Ed25519
implementation — including `node:crypto`, including every independent verifier a
reader might bring. The failure is silent: the signature simply does not verify,
and only on someone else's machine. So the wrong one is unreachable through this
adapter rather than merely discouraged, and a test asserts that.

## What is checked before a signer is returned

Everything that could otherwise fail at the first checkpoint, or worse, at
someone else's verification:

- the key spec is `ECC_NIST_EDWARDS25519`, its usage is `SIGN_VERIFY`, its state
  is `Enabled`, and it advertises `ED25519_SHA_512`
- the public key fetched is **proved** to belong to the key that signs, by
  signing a probe and verifying it locally. Otherwise a reader pins an identity
  that cannot check the log
- a subject beyond KMS's 4096-byte RAW limit is refused, never truncated: a
  signature over part of a subject is worse than no signature

## Custody

`custody: 'kms'`, which is **operator-declared** like every custody class. An
HSM signature and a file-key signature are byte-identical (DES-06), so nothing
in a signature proves where it came from. FR-65 records the declaration in a
chained record; FR-70 is the only route to independently-supported custody, and
`docs/kms-capability-matrix.md` explains why that route currently requires
hardware rather than any cloud KMS.

## Licence

Apache-2.0.
