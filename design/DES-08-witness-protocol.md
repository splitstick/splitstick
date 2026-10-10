# DES-08 — Witness protocol

**Milestone:** M3a · **Covers:** FR-13, FR-14, FR-15, FR-16, FR-17, FR-19, FR-20, FR-21, FR-22, FR-42, FR-43, FR-44, FR-48, FR-50, FR-51, INT-02, SEC-15, PRIV-01

> The largest element in the project, 18 requirements. It is also the one where 1.0 is honestly
> incomplete, and this document says exactly where.

## Decision

A witness is any party that will sign a DES-07 checkpoint with a key the operator does not hold.
Four adapters, three of them requiring nothing of us.

| Adapter | Req | Provides | Does not provide |
|---|---|---|---|
**RFC 3161 TSA** | FR-16 | signature + independent clock, per batch | retention, enumeration, sequence memory |
**OpenTimestamps** | FR-22 | existed-no-later-than, no party can withdraw it | low latency, enumeration, sequence state |
**Self-hosted** | FR-17 | everything, including sequence enforcement | nothing — but the operator must run it |
**Transparency log** | FR-14, FR-15 | public retention and enumeration | acceptable use at high cadence |

## The gap in 1.0, stated plainly

Attack classes **4 (truncation)** and **5 (erasure)** require a party that *remembers your
sequence*. A TSA is stateless — it signs your hash and forgets you. OpenTimestamps proves a hash
existed before a block but offers no searchable index of your submissions.

So the shipped default (FR-48: TSA + OpenTimestamps roll-up) closes classes 1, 2, 3, 6 and 7 and
gives real independent time evidence — but **does not close 4 and 5.** Those close when the
operator configures either:

- a **stateful witness** (FR-17, self-hosted) → proactive rejection at submission, or
- an **enumerable log** (FR-14) → retrospective discovery of checkpoints the operator published
  but whose local chain no longer admits to.

Both are free. Both require the operator to stand up a second party. **That is not a limitation
of scope, it is the shape of the problem** — a notary you supply to yourself is not a notary.
The README must say which classes the default closes, and M3a's exit criteria must not claim
otherwise.

Until a witness is configured, `DES-19` narrows classes 4 and 5 by other means — cross-pack
comparison and counterparty reconciliation. Neither replaces proactive rejection at submission,
but they turn a cliff into a bounded window.

## Sequence enforcement — FR-42, FR-43 (stateful witnesses only)

```
POST /add-checkpoint  { note, old_size, consistency_proof }
                        → 200  note with the witness signature line appended
                        → 409  { last_size, last_root }   proof does not verify: fork or rollback
                        → 400  tree_size < last_size      regression
```

The witness keeps `(operator_id, last_size, last_root, received_at)` and accepts when **both**
hold: `tree_size >= last_size`, and an RFC 6962 **consistency proof** from `last_size` to
`tree_size` verifies against `last_root`. State is updated atomically with the signature, so a
concurrent submission cannot interleave.

An earlier draft required the tree size to be the *immediate successor*. An external review
pointed out that this contradicts `DES-05`: checkpoints publish every 10 seconds or 1,024
records, so sizes legitimately jump — 100, then 140, then 200. The error was mine and recent: I
changed `DES-05` to a running log and did not propagate it here. Consistency proofs are both the
correct mechanism and what the C2SP witness protocol actually specifies.

**Truncation detection is stronger this way, not weaker.** A truncated or forked tree fails the
consistency proof at *any* size, so the witness refuses without needing to know how many records
should have arrived.

**Enrolment** (FR-42) registers an operator identity and public key. It is a precondition of
sequence state: without an identity the witness cannot know whose successor this is. This is also
why independence cannot be self-served — enrolment is a relationship, however lightweight.

**Gap declarations — FR-26, FR-27.** With consistency proofs the witness cannot deadlock, so a
gap declaration is no longer a protocol escape. It remains necessary one layer down: `DES-04`
requires `record_seq` to increment by exactly one. Note what that means: `record_seq` counts
**writes**, so an action lost before it was written leaves *no hole* — the sequence simply
continues. An earlier draft said otherwise and an external review was right to push on it.

What is lost is the correspondence between what the collector **observed** and what it
**recorded**, which is why `DES-01` carries a second counter. A gap declaration (FR-26) occupies
exactly one record position — preserving `record_seq == tree_size` — and describes the lost span
in `source_seq`. It is chained like any record and countersigned (FR-27) so its time is
independently established.

They sit in this element because they must be countersigned, which needs the witness. `DES-10`
consumes them to distinguish a declared absence from an unexplained one; it does not define them.

## Tree heads and rollback — FR-44, FR-50

The witness retains every root (FR-44) and publishes its own signed tree head (FR-50). An
operator or any third party polls it, so a witness serving an earlier head than one previously
observed is **detected rather than suspected**. This is the check that makes a witness's own
misbehaviour visible.

## Key rotation — FR-51

The witness publishes a signed key history. Countersignatures from retired keys stay verifiable
indefinitely. A rotation is not an amnesty for anything signed before it.

## Quorum — FR-19, INT-02

Quorum counts acceptable **proofs** — note signature lines *and* envelope entries (`DES-20`) —
reported per capability class rather than as one number. `quorum: 2` across parties with no
common interest is the operator's answer to collusion, and the default includes a public anchor
precisely so independence is hard to lose by accident.

**INT-02** requires the verifier to accept countersignatures from witnesses we do not operate —
checked by verifying a pack anchored only to a third-party TSA and OpenTimestamps, with our own
key absent from the acceptance policy entirely.

## What leaves the host — SEC-15, PRIV-01

The note: an origin string, a tree size, a 32-byte root, signatures. **No tool name, no
arguments, no result, no salt.** Verified by capturing all witness traffic during a representative
run and asserting that no fixture content string appears in it.

This is what makes the design deployable in a regulated account, and it is why the witness role
can be handed to an internal audit function that is not permitted to see the data.

## Failure handling

Delegated to DES-15. The short version: never block, mark `unwitnessed`, queue, and report the
widened window as a coverage gap.
