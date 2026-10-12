# DES-20 — Countersignature envelope

**Milestone:** M3a · **Covers:** FR-12, FR-31, INT-02

## Problem

An external review caught a real error in the earlier draft. `DES-07` showed a C2SP signed note
with a TSA signature appearing as one of its signature lines:

```
— operator.treasury 7f3a9c2e MEUCIQD…
— tsa.example       b3b9f297 MEQCIBc…     ← WRONG
```

**A timestamp authority cannot produce a signed-note line.** RFC 3161 defines a
`TimeStampToken`: a CMS `SignedData` structure, DER-encoded, over a `MessageImprint` — its own
format, its own verification path, and nothing to do with the note's. OpenTimestamps is further
away still: a `.ots` proof is not a signature at all, but a chain of commitment operations
terminating in a Bitcoin block header.

Three signers, three incompatible proof formats, over one checkpoint. Pretending they are
interchangeable would have produced an interface that cannot be implemented.

## Decision

The **note is the signed subject**; countersignatures are carried *beside* it in a typed
envelope, not inside it.

```jsonc
// checkpoints/000412.json
{
  "note": "splitstick.example/treasury-host-1\n4812\n3ba3f74c…=\n\n— operator.treasury 7f3a9c2e MEUC…\n",
  "note_digest": "sha256:a1b2…",          // SHA-256 of the exact note bytes above
  "countersignatures": [
    { "type": "c2sp-note",  "issuer": "audit.internal",
      "line": "— audit.internal 5d1e8a3b MEQCIB…" },
    { "type": "rfc3161",    "issuer": "tsa.example",
      "covers": "note_digest",  "token": "<base64 DER TimeStampToken>" },
    { "type": "opentimestamps", "issuer": "bitcoin",
      "covers": "note_digest",  "proof": "<base64 .ots>" }
  ]
}
```

### What each signer actually signs

| Type | Signs | Verified by | Establishes |
|---|---|---|---|
`c2sp-note` | the note bytes, per the signed-note spec | Ed25519 over the note | receipt, ordering, **sequence state** |
`rfc3161` | a `MessageImprint` over `note_digest` | CMS path validation to the TSA's cert chain | **time**, from an independent clock |
`opentimestamps` | a commitment to `note_digest` | attestation path to a Bitcoin block header | the note **existed no later than** the block time, with no party to trust |

**`covers` is explicit on every entry.** Two signers signing different bytes and both appearing
valid is precisely how a confused-deputy bug enters a verifier.

## Consequences the review makes unavoidable

**`DES-06`'s preimage was also wrong.** It specified a custom concatenation
`0x03 ‖ root ‖ u64be(tree_size) ‖ ts`. But if the artifact is a C2SP note, the operator must sign
**the note bytes**, or no existing C2SP witness could ever countersign it and `INT-01` fails.
`DES-06` is corrected: the operator's signature is a signed-note line over the note text. The
custom preimage is removed. One signed subject, not two.

**Capabilities are not uniform, so the verifier must say so.** Only a `c2sp-note` witness
implementing the witness protocol maintains sequence state. A TSA and an OpenTimestamps anchor
establish *time* and nothing about *completeness*. `FR-57` therefore requires the verifier to
print what the observed set can and cannot establish — the review's second finding, and the
cheapest possible answer to it:

```
witnesses   tsa.example (rfc3161, time only)
            bitcoin     (opentimestamps, existed-no-later-than only)
capability  no witness in this set maintains sequence state
            truncation above record_seq 4812 is NOT detectable
            below that height, cross-pack comparison applies (DES-19)
```

**Quorum counts by capability, not by headcount.** `quorum: 2` satisfied by two time-only
witnesses buys redundancy of *time*, not independence of *sequence*. The verifier reports the
quorum per capability class rather than as one number, because a single aggregate figure would
let an operator look well-witnessed while being unable to detect truncation at all.

## What a verifier concludes from a malformed envelope

Three findings belong to the envelope itself rather than to any proof inside it.

- **`ENVELOPE_DIGEST_MISMATCH`** — `note_digest` is not the digest of the note
  beside it. Every countersignature `covers` that digest, so once it is wrong
  they all vouch for bytes that are not present, and nothing in the envelope is
  reported as verified. The digest is never recomputed from the note: the whole
  point of storing it is that the proofs name it.

- **`ENVELOPE_NOTE_MISMATCH`** — the envelope carries a different note than the
  one it was checked against. The condition this catches in practice is an M1
  `.note` file left beside an M3a `.json` envelope for the same ordinal, each
  internally consistent and disagreeing with the other. One checkpoint with two
  stories: a reader must never verify one artefact and report on another, and
  silently preferring either format would hide it.

- **`ENVELOPE_DUPLICATE_ISSUER`** — one issuer appears more than once. Both
  entries are reported, because hiding one would hide a duplicate submission,
  but the issuer counts once towards any quorum. A quorum satisfied by one party
  submitting twice is not a quorum.

## Verification order

Each countersignature is verified independently against the bytes its `covers` field names. An
unknown `type` is **inconclusive** for that entry, never a failure — a pack carrying a proof
format this verifier does not implement is not evidence of tampering (`DES-12`).
