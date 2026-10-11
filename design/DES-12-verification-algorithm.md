# DES-12 — Verification algorithm

**Milestone:** M1 · **Covers:** FR-29, NFR-04, NFR-05, NFR-06, SEC-03, SEC-04

## Decision

Three verdicts, not two. **Borrowed directly from OMA**, which gets this right and which our own
red team confirmed: a bounded log that evicted its head is not the same as a log that contradicts
itself, and conflating them either cries wolf or hides a tamper.

| Verdict | Meaning |
|---|---|
| `ok` | Every check that could run, ran, and passed. |
| `fail` | The evidence **contradicts itself**. Something was altered. |
| `inconclusive` | A check could not be answered — a missing salt, an unanchored recent batch, a witness key not in the acceptance policy. Absence of evidence, reported as such. |

A single `fail` makes the whole run `fail`. `inconclusive` never upgrades to `fail` and never
downgrades to `ok`.

## Ordered checks

Order matters: a stream that is not a stream should say so before it is interrogated about
content.

```
1. FORMAT        version supported (DES-16); schema valid
2. SEQUENCE      seq starts at 1, increments by 1; gaps only where a `gap` record declares one
3. CHAIN         h_i = H(0x02 ‖ h_(i-1) ‖ leaf_i) from genesis               [DES-04]
4. LEAF          leaf_i = H(0x00 ‖ salt_i ‖ JCS(record_i))                   [DES-02, DES-03]
                 a salt deleted by crypto-shredding yields INCONCLUSIVE for
                 that record, never fail — lawful erasure is not a tamper
5. TREE          each leaf's audit path reproduces its batch root            [DES-05]
6. OP-SIG        batch signature valid under the epoch key; succession chain
                 walks to the pinned root                                    [DES-06]
7. WITNESS       ≥ quorum countersignatures over that root, from issuers the
                 acceptance policy admits                                    [DES-08, DES-09]
8. ROLLUP        batch root included under a countersigned roll-up root      [DES-05]
9. COVERAGE      heartbeat continuity; declared gaps reconciled              [DES-10]
10. POLICY       policy changes chained; report any weakening                [DES-09]
```

`verify --compare <pack>` adds an eleventh check: **CROSS-PACK**, which contradicts a record
truncated below a height already disclosed (`DES-19`).

## Failure codes

Each carries what a reader may conclude, because "verification failed" is useless on its own.

| Code | Conclusion |
|---|---|
`SEQ_BROKEN` | An event was inserted, removed or reordered. |
`CHAIN_BROKEN` | A record or its predecessor was altered. |
`LEAF_MISMATCH` | This record's content is not what was committed. |
`TREE_MISMATCH` | This record is not in the batch it claims. |
`OPSIG_INVALID` | Not signed by the operator identity it claims. |
`WITNESS_SHORT` | Fewer countersignatures than the policy requires. |
`WITNESS_MISMATCH` | **The witness signed a different root. The strongest finding available** — the operator re-signed history but could not forge the countersignature. |
`SUCCESSION_BROKEN` | Epoch key not endorsed by its predecessor. |
`DISCONTINUITY` | A declared key-compromise break was crossed (DES-06). Not a failure; always surfaced. |
`COVERAGE_GAP` | A window with no heartbeat and no declaration. |
`COVERAGE_UNKNOWN` | A `gap_unknown` record is present. **Inconclusive, never `ok`** — the chain may be perfectly intact while the collector cannot say what was observed during the interval. An otherwise flawless run containing one of these is not proof of complete capture, and the coverage report says so. |
`IDENTITY_UNPINNED` | The pack is signed under a key or origin the acceptance policy did not name (`FR-63`). Nothing prevents an operator keeping a second log; this is how a reader who pinned an identity is told they are being shown another. |
`WITNESS_MISSING` | A witness **expected for this checkpoint** — given its tier and cadence — has no proof in the pack (`FR-66`). **Inconclusive, not a finding of deletion.** Absence is consistent with pending under fail-open, a slower roll-up tier, an unavailable witness, or a removed receipt, and nothing in the pack distinguishes them. Demonstrating removal requires an earlier pack that held the proof, which is cross-pack comparison (`DES-19`). |
`TRUNCATED_BELOW_DISCLOSED` | A pack already disclosed holds a countersigned checkpoint above where this record ends. **Truncation, caught without a stateful witness.** |
`LEAF_INCONCLUSIVE` | The leaf salt is absent, so the leaf cannot be reproduced. **Inconclusive** — lawful erasure deletes exactly that (`DES-13`), and a shredded record must never read as a tamper. |
`CONTENT_MISMATCH` | The stored payload does not reproduce the commitment in its record: it was substituted. |
`CONTENT_ABSENT` | A payload is not in the store. **Inconclusive**: shredded by design, retained elsewhere, or lost, and the pack cannot tell those apart. |
`SIZE_REGRESSED` | A checkpoint commits to more records than the log holds — the tail was removed below a size already committed. |
`UNANCHORED` | No checkpoint is present at all, so nothing commits to a tree size. **Inconclusive.** |
`OPSIG_UNCHECKED` | A checkpoint is signed, but no operator identity was pinned, so the signature means nothing to this reader. **Inconclusive.** |
`SUITE_UNDECLARED` | A checkpoint records no algorithm suite, so which primitives signed it is not stated and cannot be recovered years later (`DES-16`). **Inconclusive.** |
`CHECKPOINTS_UNATTRIBUTED` | Notes sit outside any collector's directory and belong to no chain. **Inconclusive** — they were not checked, because a note that cannot be attributed is not evidence about a particular log. |
`NO_EVIDENCE` | No chain was found for the collector named. **Inconclusive.** |
`CONSISTENCY_BROKEN` | Two signed checkpoints are not prefixes of one history, or a later one commits to fewer records than an earlier one. Append-only is checked, not assumed (`DES-04` rule 4). |
`UNANCHORED_TAIL` | Records sit above the highest tree size any checkpoint commits to. **Inconclusive**, and the height is reported: it is what bounds every truncation claim, and what `DES-19`'s cross-pack comparison keys on. |
`TORN_WRITE` | The last line of the chain is incomplete. **Inconclusive** — that is what a crash during an append leaves, and the records before it verify normally. A broken line anywhere else is `MALFORMED_RECORD` and fails, because only the end is explicable by a crash. |
`MULTIPLE_COLLECTORS` | The store holds more than one collector chain and none was named. **Inconclusive**: one was verified and the others were not, which a reader has to be told rather than left to assume. |

## The capability statement — FR-57

A verdict is incomplete without saying what the evidence could establish. An external review
pushed on this: the default witness set cannot reject a truncated history, so a bare `ok` would
imply more than was checked.

Every verdict therefore carries what the observed witnesses can and cannot do:

```
verdict     INCONCLUSIVE  (12 checks passed, 1 could not be answered, 0 failed)
witnesses   tsa.example  (rfc3161, time only)
            bitcoin      (opentimestamps, existed-no-later-than only)
capability  no witness in this set maintains sequence state
            truncation above record_seq 4812 is NOT detectable
            below that height, cross-pack comparison applies (DES-19)
trusting    the primitives; tsa.example's clock; whoever retained the compared pack
```

Derived from the proof types actually present in the envelope (`DES-20`), not from
configuration — a verifier reads evidence, and the operator's config is not evidence. Quorum is
reported **per capability class**, because two time-only witnesses are not two independent
sequence witnesses and one aggregate number would hide that.

## Offline by construction — NFR-05, NFR-06

`verify` opens files and performs arithmetic. It makes **no** network call, reads **no**
credential, and has no notion of an account. Trust anchors arrive as an input file (DES-09), not
from a registry.

Enforced by test: the suite runs in a network-isolated sandbox with an empty environment, and a
code-level check fails the build if the verifier package imports `node:http`, `node:https` or
`node:net`.

## Performance — NFR-04

100,000 events in under 2 seconds. Budget: ~200k SHA-256 operations over ~300 bytes (tens of
milliseconds), ~100 Ed25519 verifications (~5 ms), and JSON parsing, which dominates. Stream the
journal line by line rather than loading it; never hold the whole run in memory.

## What verification does not establish — SEC-03, SEC-04

It assumes the primitives hold, and **at least one countersigning witness is honest**. If every
witness in the quorum colludes with the operator, every check here passes on a fabricated
history. That assumption is stated in the threat model and surfaced in `verify --explain`, which
prints which parties the verdict depends on. A reader should never have to infer whom they are
trusting.
