# M2 failure-mode inventory

Written **before** the code, per the M1 retrospective: eight of M1's defects
were on failure paths nobody had enumerated, and the fix was to enumerate them
first and make each one a test. This is that list for the AWS KMS signer and the
epoch ratchet.

Each row is a test. Rows marked **adversarial** are written before the happy
path.

## The signer seam

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 1 | the configured algorithm is `ED25519_PH_SHA_512` | **refused at construction.** HashEdDSA produces a signature no other Ed25519 verifier can check, so it must never be reachable | ✓ |
| 2 | KMS returns a signature that is not 64 bytes | refused; the seam already asserts this and it must stay asserted for a remote signer | ✓ |
| 3 | the key spec is not `ECC_NIST_EDWARDS25519` | refused at construction, naming the spec found | ✓ |
| 4 | `MessageType` is anything but `RAW` | not configurable; `RAW` is the only correct value for the note subject | ✓ |
| 5 | the note subject exceeds KMS's raw-message limit | refused with the limit named, not truncated | ✓ |
| 6 | the key is disabled, pending deletion, or deleted | the error surfaces; the collector does not treat it as a signing success | ✓ |
| 7 | KMS throttles or the network fails | the error surfaces; checkpointing fails, collection continues (SCOPE-16) | ✓ |
| 8 | credentials are absent or lack `kms:Sign` | fails at construction where possible, with a message naming the permission | ✓ |
| 9 | the public key fetched does not match the key that signs | caught — otherwise a verifier pins an identity that cannot verify anything | ✓ |
| 10 | the same signer is used concurrently for two checkpoints | each signature is independent; no shared mutable state | ✓ |
| 11 | a signature produced by KMS is verified by `node:crypto` | **must pass.** This is the only test that proves interoperability rather than internal consistency | |

## The ratchet (FR-11, SEC-08)

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 12 | epoch N's key is asked to produce an epoch N−1 signature | fails verification under epoch N−1's public key | ✓ |
| 13 | the succession chain skips an epoch | `SUCCESSION_BROKEN` | ✓ |
| 14 | an epoch endorses itself, or two epochs endorse the same successor | refused | ✓ |
| 15 | the succession chain is walked from an untrusted root | nothing is claimed; the root must be pinned | ✓ |
| 16 | an epoch is declared `software` custody | the verifier refuses any forward-secrecy claim for it (SEC-17) | ✓ |
| 17 | a retired epoch's signature is verified years later | still valid. Rotation is not an amnesty for anything signed before it | |

## Architecture consequences found while writing this

**The KMS signer cannot live in `@splitstick/core`.** It needs an AWS SDK, and
core is depended on by `@splitstick/verify`, which NFR-05 and NFR-06 require to
be offline by construction — no network module, no credential, no account. A
transitive AWS SDK dependency would contradict that even if the verifier never
called it. So the signer ships as its own package, and DES-14's layout gains a
`signer-*` row alongside `witness-*`.

**And the existing offline check has a hole.** It scans
`packages/verify/src` only. A network import in `core` would leave the verifier
passing its own offline test while transitively depending on networking. The
check now follows the dependency graph inside this repository, so the guarantee
covers what the verifier actually pulls in rather than only what it contains.
That hole existed before this milestone; adding a signer is simply the change
that would have exploited it.

## What M2 cannot close

**NFR-09's HSM half.** The YubiHSM purchase is on hold until its attestation
capability is confirmed, so "at least one KMS and one HSM" will be half done.
NFR-09 stays open and disclosed rather than quietly passed, as NFR-01 is.

**The interoperability test needs real credentials.** Row 11 is the only test
that proves a KMS signature is checkable by an independent implementation, and
it cannot run without an AWS key. It is written to **fail loudly as skipped**
rather than silently pass, and NFR-09 does not count as verified until it has
actually run — a skipped test that reports success is the pattern this project
has already had to fix three times.

**AC-3 may not close in M2.** The red-team suite's attack C2 names "M2 custody +
M3a countersignature" as what closes it — both halves. Whether AC-3 is gated on
M2 alone or carried into M3a is a decision to take before the gate, not at it.
