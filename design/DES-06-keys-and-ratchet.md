# DES-06 — Key hierarchy, signing and epoch ratchet

**Milestone:** M1 (signing) and M2 (ratchet) · **Covers:** FR-10, FR-11, NFR-09, SEC-08, SEC-14, SEC-17, SEC-24, OPS-04

## Decision

**Ed25519** for all signatures. Fast, small, no parameter choices to get wrong, and natively in
`node:crypto`.

```
preimage = 0x03 ‖ root ‖ u64be(seq) ‖ ts
sig      = Ed25519-Sign(K_epoch, preimage)
```

The signature covers the root, the sequence number **and** the timestamp together. Signing the
root alone would let a batch be replayed at a different claimed position or time.

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

The precondition appears wherever the claim does, in docs and in `verify` output. A verifier
reports which mode produced a signature, so a reader is never left to assume.

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
