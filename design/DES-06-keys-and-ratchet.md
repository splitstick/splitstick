# DES-06 — Key hierarchy, signing and epoch ratchet

**Milestone:** M1 (signing) and M2 (ratchet) · **Covers:** FR-10, FR-11, NFR-09, SEC-08, SEC-14, SEC-17, SEC-24, OPS-04

## Decision

**Ed25519** for all signatures. Fast, small, no parameter choices to get wrong, and natively in
`node:crypto`.

```
subject = the C2SP note bytes          // origin ‖ tree_size ‖ root, per DES-07
sig     = Ed25519-Sign(K_epoch, subject)      // emitted as a signed-note line
```

The note already binds origin, `tree_size` and root together, so signing the note signs all
three — and signing the **note itself** rather than a bespoke concatenation is what lets any
existing C2SP witness countersign it. An earlier draft specified a custom preimage; an external
review pointed out that no C2SP witness could then have signed the same bytes, which would have
broken INT-01. There is one signed subject in this system, not two.

The operator's clock does not appear in the signed subject at all. Trustworthy time enters only
through a countersignature (`DES-20`), which is the honest position: `DES-01`'s `ts` is
self-asserted and nothing should be built on it.

## Which products can actually sign SS1

Verified October 2026 and recorded in
[`docs/kms-capability-matrix.md`](../docs/kms-capability-matrix.md), because the
answer changed recently and will change again.

**AWS KMS can** — `ECC_NIST_EDWARDS25519` with `ED25519_SHA_512` at
`MessageType: RAW`, which is pure Ed25519 over the note bytes and interoperates
with any other Ed25519 verifier. Its `ED25519_PH_SHA_512` variant is HashEdDSA
and must never be used: the signature would be silently unverifiable elsewhere.

**GCP Cloud KMS can, but only at SOFTWARE protection level.** Ed25519 is not
available on Cloud HSM, so selecting GCP for Ed25519 yields a `software` custody
class and no forward-secrecy claim. An operator may reasonably assume otherwise,
so the configuration documentation has to say it.

**Azure Key Vault and Managed HSM cannot** — no Edwards curve, and its sign
operation signs a digest rather than the message, which PureEdDSA does not admit.

### The consequence for FR-70

FR-70 validates a provider attestation before custody may be reported as
independently supported. For SS1 there is currently **no cloud path to it**: the
product that issues per-key attestations (GCP Cloud HSM) cannot sign Ed25519,
and the product that signs Ed25519 under HSM protection (AWS KMS) issues service
compliance reports rather than a per-key attestation document.

So *independently supported* custody presently requires an artefact that only
hardware issues. This is a statement about attestation documents, not about key
protection: AWS KMS keys are generated in and never leave FIPS-validated HSMs,
and the absence of a per-key certificate means only that a third party cannot be
handed one.

YubiHSM 2's attestation is documented — an X.509 certificate over the attested
public key, chaining through a Yubico intermediate to a published root, with
key origin and capabilities in named extensions. What is not demonstrated is
FR-70 conformance against a real certificate. Until it is, FR-70 is a correct
validation procedure for which no instance has been produced, and nothing should
claim otherwise.

**And custody class alone does not determine forward secrecy.** Non-exportability
bounds where a key could have gone. Whether yesterday's record can be re-signed
with today's key depends additionally on the ratchet, on the succession
protocol, and on destruction — which stays operator-declared in every
configuration this design supports. A key in an HSM that is never rotated has no
forward secrecy whatever its custody class.

## Epoch ratchet — FR-11, M2

An **epoch** is a fixed span (default 24 hours). Each epoch has its own key pair. Succession is
a signed chain:

```
epoch n:  K_n signs ( 0x04 ‖ pub(K_(n+1)) ‖ u64be(n+1) )      // endorses its successor
          then pub(K_n) is retained, priv(K_n) is destroyed
```

A verifier walks the succession chain from a trusted root public key, so one pinned key
validates every epoch that followed. Signatures from retired keys stay verifiable forever —
rotation is not an amnesty for anything signed before it.

### The honest limit — SEC-17

Forward security holds **only if the retired private key is genuinely gone**, and key
destruction is not externally verifiable. Nobody can prove they deleted a key.

So this element specifies two modes and the claim differs between them:

| Mode | Claim |
|---|---|
| **Software keys** | Ratchet implemented, succession chain valid. **No forward-security claim.** Suitable for development only. |
| **Non-exportable KMS/HSM** (NFR-09) | Key material never exists outside the module; scheduled deletion is logged by the provider. Forward security claimed, **with the custody precondition stated in the same sentence**. |

**How a verifier knows which mode applied — FR-65.** It cannot tell from the signature: an HSM
signature and a signature from a PEM file on disk are byte-identical. The custody class is
therefore **declared in a chained record** per epoch, countersigned once anchoring exists — which
is why FR-65 sits in M3a rather than M2, a dependency an earlier draft left undeclared and the
ordering validator could not catch, because a validator only checks what you tell it.

**A declaration is a declaration.** It proves the operator asserted a custody class; it does not
prove the key was non-exportable, nor that a retired key was destroyed. The verifier therefore
labels it **operator-declared**, and reports custody as *independently supported* only when a
provider attestation document is supplied alongside — which is the sole path to verified custody
in this design.

A verifier prints the declared class per epoch and refuses to claim forward secrecy for any epoch
declared software-keyed.

### Validating a provider attestation — FR-70

The *presence* of an attestation document establishes nothing. Before custody may be reported as
independently supported, a verifier must check all five:

1. **Issuer** — the document chains to a provider root in the acceptance policy, not merely to
   some valid CA.
2. **Document signature** — valid over the exact bytes presented.
3. **Key identity** — the attested key is the one that signed this epoch's checkpoints, not
   another key in the same account.
4. **Epoch applicability** — the attestation covers the period the epoch spans. An attestation
   issued after the fact says nothing about earlier signatures.
5. **Custody properties** — it actually asserts non-exportability, rather than mere existence of
   a managed key.

And even all five together **do not establish historical destruction**. Non-exportability says a
key could not leave the module; it does not say a retired key was deleted. Destruction remains
operator-declared in every configuration this design supports, and the verifier labels it so.

## Key compromise — SEC-24, M3b

There is no cryptographic recovery from a compromised signing key. Records it produced are
suspect from the compromise onward, and nothing can change that.

What the design provides instead is an **honest discontinuity**:

1. The operator emits a `policy` record declaring the compromise, the last epoch believed sound,
   and the new root public key.
2. The declaration is anchored and countersigned (DES-08), so its *time* is independently
   established — which is the whole point. A silent re-key is indistinguishable from an attack.
3. A verifier that crosses a declared discontinuity reports it prominently and never silently
   bridges it.

## Operator key custody — SEC-14, OPS-04

Splitstick must never hold, receive, request or log the signing key. The collector takes a
*signer interface* — `sign(preimage) → signature` — so a KMS-backed signer and a local one are
interchangeable and no code path ever sees private material.

`OPS-04` documents the separation-of-duties split: engineering holds the signing key, internal
audit holds the witness key (DES-08). Neither function can rewrite history alone, which is the
two-halves-of-a-tally property inside one organisation.

## Consequences

- Per-epoch KMS keys cost roughly $1/month each on major providers, and a 24-hour epoch means
  365 keys a year. Either lengthen the epoch, or use scheduled-deletion key versions within one
  key — the latter is preferred and is the default guidance.
- A verifier needs the full succession chain. It ships inside the evidence pack (DES-11), not
  fetched, so verification stays offline.
