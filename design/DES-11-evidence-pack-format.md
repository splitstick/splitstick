# DES-11 — Evidence pack format

**Milestone:** M3a · **Covers:** FR-31, INT-03

## Decision

A pack is a **self-contained directory or tar**, holding everything needed to verify and nothing
that requires fetching. If verification needs the network, the design has failed.

```
pack/
  manifest.json          version, suite, origin, what this pack claims to cover
  records.jsonl          the disclosed records
  salts.json             cid → salt, only for disclosed records          [DES-03]
  chain.json             heads and prevs across the covered range        [DES-04]
  proofs.json            audit paths: record → batch root → roll-up root [DES-05]
  checkpoints/           DES-07 notes, with EVERY signature line         [FR-31]
  keys/
    operator.pub         pinned root public key
    succession.json      signed epoch key chain                         [DES-06]
    witnesses.json       witness public keys and declared time sources   [SEC-25]
  coverage.json          heartbeats and declared gaps over the range     [DES-10]
```

## FR-31 — every countersignature, never only ours

Packs carry **all** signature lines collected, including from witnesses the project does not
operate and does not endorse. Filtering to a preferred witness would quietly force the recipient
to trust whoever we chose.

This is what makes DES-09's separate acceptance policy meaningful: an auditor who accepts only
eIDAS-qualified authorities can verify the same pack, ignoring every other signature line,
without asking us to regenerate anything.

## INT-03 — documented and versioned so others can implement it

The format is published in `spec/`, versioned under DES-16, with test vectors. The conformance
requirement is specific: **an independent implementation, written from the spec alone, must
validate a reference pack.**

That obligation is deliberate. The TypeScript verifier is a convenience; **the spec is the
guarantee.** If verifying ever requires our code, the whole thesis has inverted — a reader would
be trusting us to tell them whether to trust us.

Packs must therefore be **retained by recipients**, because `DES-19` makes every pack a
permanent constraint on the operator: a countersigned checkpoint in a pack handed over last
quarter contradicts a record truncated below it today.

## Scope of a pack

`manifest.json` states precisely what is claimed, so a pack cannot imply more than it holds:

```jsonc
{
  "version": 1, "suite": "SS1",
  "origin": "splitstick.example/treasury-agent",
  "covers": { "from_seq": 4800, "to_seq": 4812, "complete": false },
  "disclosed": ["cid:9f2c…"],
  "note": "Single-action disclosure. Sibling contents not included by design."
}
```

`complete: false` is the honest flag on a selective disclosure: this proves the included actions
happened, and says nothing about the ones it omits. A full-range pack sets it `true`, and only
then does coverage attestation (DES-10) mean anything about the whole window.
