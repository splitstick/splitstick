# KMS and HSM capability matrix — NFR-09

Verified October 2026 against vendor documentation. **Re-verify before relying on
any row**: provider capabilities move, and the most important row here changed
within the last year.

## Why this document exists

`SS1` pins **Ed25519** (DES-16), and the signer interface enforces it. `NFR-09`
requires operation against "at least one KMS and one HSM" with non-exportable
keys. Before spending anything, the question was whether a managed KMS can sign
our format at all.

## The matrix

| Provider | Ed25519 signing | Protection level | Per-key attestation document | Cost |
|---|---|---|---|---|
| **AWS KMS** | **Yes** — `ECC_NIST_EDWARDS25519`, algorithm `ED25519_SHA_512` with `MessageType: RAW` | KMS HSMs, FIPS-validated | **No** downloadable per-key attestation | $1/key/month + $0.15 per 10,000 sign requests |
| **GCP Cloud KMS** | **Yes** — `EC_SIGN_ED25519`, PureEdDSA, raw input | **SOFTWARE only.** HSM, EXTERNAL and single-tenant HSM do **not** support this algorithm | Cloud HSM attestation exists, but not reachable for Ed25519 because Ed25519 cannot be HSM-protected | — |
| **Azure Key Vault / Managed HSM** | **No** — EC is P-256, P-256K, P-384, P-521 only, plus RSA | — | — | — |
| **YubiHSM 2** | **Yes** — EdDSA, Ed25519 only | Hardware, non-exportable | A `SIGN ATTESTATION CERTIFICATE` command exists; **what it asserts and whether it chains to a Yubico root is unconfirmed** | One-off hardware |

Two details that matter more than they look:

**`MessageType: RAW` with `ED25519_SHA_512` is pure Ed25519 over the bytes you
hand it.** That is exactly what Splitstick needs — the signed subject is the
C2SP note text, signed whole. It interoperates with `node:crypto`'s
`verify(null, …)` and with any other Ed25519 verifier. AWS's other variant,
`ED25519_PH_SHA_512`, is HashEdDSA and would **not** interoperate; it must not
be used. The note in AWS's own documentation that the two "cannot be used
interchangeably" is the whole risk in one sentence.

**Azure cannot sign SS1 even in principle.** Beyond lacking the curve, its sign
operation signs a *hash* — "the service doesn't hash content as part of
signature creation" — and PureEdDSA signs the message, not a digest of it.

## Conclusions

**1. AWS KMS satisfies the KMS half of NFR-09, and costs almost nothing to
prove.** One key at $1/month plus $0.15 per 10,000 signatures. An integration
test is a handful of signatures: cents, not euros. Asymmetric sign operations
are excluded from the free tier, which does not matter at this volume.

Worth recording that this was not true until recently — AWS announced EdDSA
support in November 2025. A design written a year earlier would have concluded
that no managed KMS could sign SS1, and would have been right at the time.

**2. GCP is a trap, and the design should say so.** Ed25519 exists there, so an
operator may reasonably assume Cloud HSM plus Ed25519 works. It does not: the
algorithm is software-protection-level only, which means it cannot support a
custody claim at all. An operator who selects it believing otherwise would get
a `software` custody class and no forward-secrecy claim — correctly, but by
accident rather than by being told.

**3. FR-70 currently has no cloud path for SS1.** This is the significant
finding. FR-70's five checks validate a provider attestation before custody may
be reported as *independently supported*. But:

- the one cloud product that issues a downloadable per-key attestation
  (GCP Cloud HSM) cannot sign Ed25519, and
- the one that can sign Ed25519 under HSM protection (AWS KMS) does not issue a
  per-key attestation document — it offers compliance reports about the service,
  which is a different artefact and not what FR-70 validates.

So for SS1 today, *independently supported* custody requires **hardware**. That
makes YubiHSM 2's attestation capability load-bearing, and it is the one row in
this matrix I could not confirm. Until it is confirmed, FR-70 should be read as
specifying a validation procedure for which no instance has yet been produced.

**4. Azure is a deployment-reach limitation, not a bug.** A regulated buyer
standardised on Azure Key Vault cannot run SS1 at all. That is an input to
whether `SS2` with ECDSA P-256 is ever published (DES-16 makes a suite a frozen
tuple, so this is a deliberate spec act, not a configuration flag) — a decision
for M6/M7 positioning rather than M2.

## What this means for M2

- Test the KMS half against **AWS KMS** with `ECC_NIST_EDWARDS25519`,
  `ED25519_SHA_512`, `MessageType: RAW`. Cost: cents.
- Add a `kms` signer behind the existing `sign(bytes) → signature` seam. Nothing
  else changes: core and the verifier never see key material (SEC-14).
- A conformance test must assert the KMS signature verifies under
  `node:crypto` — different implementation, same bytes. That is the only thing
  that proves interoperability rather than internal consistency.
- Reject `ED25519_PH_SHA_512` explicitly, with a test, because a HashEdDSA
  signature would be silently unverifiable by every other Ed25519 verifier.
- Confirm YubiHSM 2 attestation before NFR-09's HSM half is claimed, and before
  buying anything on the strength of it.

## What the project spends, and what an operator spends

Splitstick never holds, receives, requests or logs a signing key (SEC-14). The
collector takes a signer interface, so the **operator** supplies and pays for
their own KMS or HSM. This project's spend is one-off and exists only to satisfy
NFR-09's verification clause — to prove the implementation works against real
non-exportable custody — and carries no recurring operational cost.

## Sources

- AWS KMS key spec reference — <https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html>
- AWS KMS pricing — <https://aws.amazon.com/kms/pricing/>
- AWS EdDSA announcement — <https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/>
- Google Cloud KMS algorithms — <https://docs.cloud.google.com/kms/docs/algorithms>
- Azure Key Vault key types and algorithms — <https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details>
- YubiHSM 2 command reference — <https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html>
