# M3a failure-mode inventory

Written **before** the code, as M2's was. M1's defects clustered on failure
paths nobody had enumerated; enumerating them first and making each one a test
is the cheapest thing that worked.

M3a is the largest element in the project and the one where the honest answer
is "partly". This list therefore has a second job: to separate what the code
must refuse from what the code cannot know, before any of it is written, so
that neither gets quietly promoted into the other.

Each row is a test. Rows marked **adversarial** are written before the happy path.

## The envelope — DES-20, FR-12, FR-31

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 1 | `note_digest` is not the digest of the note bytes beside it | refused. Everything else in the envelope `covers` that digest, so a wrong one makes every countersignature vouch for bytes nobody has | ✓ |
| 2 | a countersignature's `covers` names something absent, or a field it does not understand | that entry is **inconclusive**, never a pass. Two signers signing different bytes and both looking valid is how a confused deputy enters a verifier | ✓ |
| 3 | a countersignature's `type` is one this verifier does not implement | **inconclusive**, never a failure — an unimplemented proof format is not evidence of tampering (DES-12) | ✓ |
| 4 | the same issuer appears twice | counted once. Otherwise `quorum: 2` is satisfiable by one party submitting twice | ✓ |
| 5 | the note inside the envelope is not the note on disk | refused; a reader must never verify one artefact and report on another | ✓ |
| 6 | the envelope is bytes, not JSON, or JSON that is not an object | a finding, not a crash | ✓ |
| 7 | `countersignatures` is absent or empty | valid and **unwitnessed**. This is the common case and must not read as damage | |
| 8 | an M1 `.note` file sits beside M3a `.json` envelopes | both read; the older format is not retroactively invalid (DES-16) | |

## The stateful witness — FR-17, FR-42, FR-43, FR-44, FR-50, FR-51

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 9 | a submission arrives for an unenrolled operator | refused. Without an identity the witness cannot know whose successor this is, which is why independence cannot be self-served | ✓ |
| 10 | `tree_size` is below `last_size` | `400`, regression — the operator is asking the witness to co-sign a shorter history than it already saw | ✓ |
| 11 | the consistency proof does not verify against `last_root` | `409` with `last_size` and `last_root`, so the operator learns what the witness remembers | ✓ |
| 12 | `tree_size` jumps by more than one | **accepted.** DES-05 publishes every 10s or 1,024 records, so sizes legitimately jump. An earlier draft demanded the immediate successor; a review was right that it contradicted DES-05 | |
| 13 | `tree_size == last_size` and the root matches | idempotent: the same signature, no state change. A retry after a dropped response must not look like an attack | ✓ |
| 14 | `tree_size == last_size` and the root differs | refused — that is a fork at the same height | ✓ |
| 15 | two submissions race | state updates atomically with the signature; one wins, the other sees the new state. A witness whose state can interleave has no sequence memory at all | ✓ |
| 16 | the witness is asked for its tree head after serving a later one | the later head. A witness serving an earlier head than one previously observed is the witness's own misbehaviour, and must be **detected rather than suspected** (FR-50) | ✓ |
| 17 | the witness rotates its key | countersignatures from retired keys stay verifiable indefinitely; the key history is signed (FR-51) | |
| 18 | the submitted note is signed by a key the witness has not enrolled | refused; a witness that signs anything presented to it is a signature oracle | ✓ |

## What the collector does when a witness fails — DES-15, SCOPE-16

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 19 | every witness is unreachable | **collection continues.** Never block, mark unwitnessed, queue. Fail-open is the design, not a concession | ✓ |
| 20 | a witness returns a signature that does not verify | discarded with a finding; a bad countersignature must not be stored as though it were good | ✓ |
| 21 | a witness hangs | bounded by a timeout, and the checkpoint still lands locally | ✓ |
| 22 | a witness returns a valid signature from the *wrong* issuer | discarded. An issuer field is a claim; the key is the fact | ✓ |
| 23 | the queue of unwitnessed checkpoints grows unboundedly | bounded and reported; an unbounded queue is the uncontrolled buffering NFR-01's revision explicitly excluded | ✓ |
| 24 | a queued checkpoint is later witnessed | the envelope is updated in place, atomically; a half-written envelope must never be readable | ✓ |

## Zero content egress — PRIV-01, SEC-15

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 25 | a representative run's witness traffic is captured | **no tool name, argument, result, salt or payload byte appears in it.** Asserted against the fixture strings, not by inspection | ✓ |
| 26 | an adapter is added that would send more than the note | the egress test fails. The check must be on the traffic, not on a reviewer's reading of the adapter | ✓ |

## Acceptance policy and quorum — FR-30, FR-19, FR-57, INT-02

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 27 | the same pack is verified under two different acceptance policies | two different, each internally consistent. The policy is an input, not a hardcoded trust store | ✓ |
| 28 | the acceptance policy is empty | nothing is accepted and the report says the reader trusted nobody — not "no witnesses present" | ✓ |
| 29 | `quorum: 2` is met by two time-only witnesses | quorum for **time** is met and quorum for **sequence** is not, reported separately. One aggregate number would let an operator look well-witnessed while unable to detect truncation at all | ✓ |
| 30 | our own key is absent from the acceptance policy entirely | a pack anchored only to third parties still verifies (INT-02) | ✓ |
| 31 | a countersignature is from a witness the policy does not name | inconclusive for that entry, and it counts towards no quorum | ✓ |

## Truncation and erasure — SEC-09, SEC-10, SEC-26, FR-54

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 32 | the tail is truncated and a stateful witness holds a later root | **detected** — this is AC-4, and the witness's memory is what closes it | ✓ |
| 33 | the tail is truncated and the only witnesses are time-only | **NOT detected**, and the capability statement says so with the height | ✓ |
| 34 | a record is erased and the chain renumbered and re-signed | detected against the witnessed root (AC-5) | ✓ |
| 35 | a pack is truncated below a height already disclosed in another pack | `TRUNCATED_BELOW_DISCLOSED` — the cross-pack comparison, FR-54 | ✓ |
| 36 | two packs disagree about the root at the same height | a fork, reported as such rather than one being preferred | ✓ |

## What M3a cannot close, decided here rather than at the gate

**A TSA and an OpenTimestamps anchor cannot close AC-4 or AC-5.** They are
stateless: they sign a hash and forget you. The shipped default (FR-48) gives
real independent time and closes nothing about completeness. Classes 4 and 5
close only when the operator stands up a stateful witness (FR-17) or an
enumerable log (FR-14) — both free, both requiring a second party. A notary you
supply to yourself is not a notary, and the gate assertions must reflect which
of these is actually configured in the harness rather than which could be.

**FR-70 has no instance to validate against.** The five checks are a correct
procedure for which no attestation document exists on any Ed25519 cloud path
(DES-06). It ships as a validator with a constructed document in its tests and
says so, and NFR-09's HSM half stays open. A procedure tested only against a
document we wrote ourselves is worth something — it is not worth what a real
one would be, and the difference must be written down rather than left for a
reader to discover.

**An OpenTimestamps proof cannot be fully verified offline.** Walking the
attestation path yields a commitment to a Bitcoin block header; confirming that
header needs a chain source, and NFR-05 requires the verifier to be offline by
construction. So the verifier reports the block height the proof commits to and
marks the entry inconclusive pending an out-of-band header check, rather than
either reaching for the network or pretending the commitment is a confirmation.
