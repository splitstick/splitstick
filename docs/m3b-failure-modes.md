# M3b failure-mode inventory

Written **before** the code, as M2's and M3a's were. Each row is a test; rows
marked **adversarial** are written before the happy path.

M3b is where the project stops adding mechanisms and starts stating what the
mechanisms mean, then checks that losing a party does not lose the evidence. So
this list has an unusual property: a third of it is about documents, and the
test for a document is whether a specific claim appears in a specific place and
whether the code agrees with it. A practice statement that the software
contradicts is worse than no practice statement, because somebody will rely on
it.

## Fail-open, and its ceiling — FR-38, NFR-12, NFR-13, OPS-02, FR-68

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 1 | no witness is reachable for an entire run | the run completes normally. NFR-12 is absolute: the collector must never be able to stop an agent run, and a configuration that could is a bug and not a tuning choice | ✓ |
| 2 | the process restarts with unwitnessed batches queued | they are still queued. An in-memory queue loses exactly the evidence an outage created, and an outage is when a restart is most likely | ✓ |
| 3 | the queue file is torn by a crash mid-append | the torn tail is dropped and repaired before the next append, as the witness's journal is | ✓ |
| 4 | a witness returns after an outage | the queue drains with backoff, newest first, and a success supersedes the lower heights (M3a) | |
| 5 | the queue is drained while another process is draining it | one writer, by the same lock as everything else | ✓ |
| 6 | a witness is unreachable for longer than `unwitnessed_ceiling` | an alert is raised OUT OF BAND — not into the log, which is the thing whose integrity is in question — and the coverage report refuses to issue a completeness claim beyond that point | ✓ |
| 7 | the ceiling is reached and the witness then returns | the alert clears, and the report says the window was unwitnessed rather than pretending it was not | ✓ |
| 8 | the operator sets `unwitnessed_ceiling: 0` or a negative value | refused at config load. A ceiling of zero means every batch is immediately overdue, which would make the alert meaningless rather than strict | ✓ |

## The observation counter — FR-61, FR-60, FR-58

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 9 | the process is killed with observations spent but unwritten | the counter was checkpointed at the last flush, so the loss is bounded by the current window rather than open-ended | ✓ |
| 10 | the counter did not survive at all | an unknown-loss interval is declared, bounded by the last durable checkpoint and the restart — never an unbounded claim, and never silence | ✓ |
| 11 | the store is full when a gap declaration must be written | the reserved slot is used, so the declaration lands. A store that cannot record its own failure is a store that reports a clean history for a lossy run | ✓ |
| 12 | even the reserved slot fails | the condition is surfaced out of band and the collector degrades; it does not pretend the gap does not exist | ✓ |
| 13 | the reserved slot is consumed by ordinary records | refused: the slot exists precisely because the ordinary path has exhausted everything else | ✓ |

## Late countersignatures — FR-39

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 14 | a queued batch is countersigned hours later | the countersignature records the WITNESS's receipt time, not the batch's claimed time. Backdating a late countersignature to the batch would turn the one independent clock in the system into an echo of the operator's | ✓ |
| 15 | a verifier reads a late countersignature | it reports the receipt time and the gap between it and the batch's self-asserted `ts`, because that gap is the unwitnessed window and a reader needs its size | ✓ |
| 16 | a witness claims a receipt time EARLIER than the batch's `ts` | reported. Either the witness's clock is wrong or the operator's is, and the verifier must not quietly prefer one | ✓ |

## Witness key rotation — FR-51

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 17 | a witness rotates its key and an old countersignature is verified | it still verifies, against the retired key in the published signed key history | ✓ |
| 18 | the key history is unsigned, or signed by a key not in it | refused; a key history nobody signed is a list | ✓ |
| 19 | a countersignature is from a key absent from the history | inconclusive for that proof, not a failure: a witness we cannot attribute is a witness this reader does not know | ✓ |

## Compromise recovery — SEC-24

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 20 | an operator declares a key compromise | a `policy` record naming the last epoch believed sound and the new root key, anchored and countersigned so its TIME is independently established | ✓ |
| 21 | a verifier crosses a declared discontinuity | `DISCONTINUITY`, reported prominently, never silently bridged | ✓ |
| 22 | an operator re-keys with no declaration | the succession chain breaks, which is the existing M2 behaviour and the reason a silent re-key is indistinguishable from an attack | ✓ |
| 23 | the discontinuity declaration is itself signed by the compromised key | accepted AND reported as such. It is the only key available at that moment, and a reader needs to know the declaration rests on it | ✓ |

## The practice statement — LEG-01 to LEG-09, LEG-19

Each of these is a claim that must appear in the published document AND must not
be contradicted by the code. The test is therefore two-sided.

| # | The claim | Where it must hold |
|---|---|---|
| 24 | what a countersignature means, versioned | LEG-01 — a document with a version and a change history |
| 25 | the root was received at the stated time, per the witness clock | LEG-02 — and the witness records `received_at` from its own clock |
| 26 | the root is the immediate successor for that operator | LEG-03 — and the witness enforces it by consistency proof |
| 27 | the witness retained the root in its own append-only store | LEG-04 — and `roots.jsonl` is append-only and crash-consistent |
| 28 | it does NOT assert the actions occurred | LEG-05 |
| 29 | it does NOT assert the recorded content is true | LEG-06 |
| 30 | it does NOT assert completeness | LEG-07 — and points at the coverage attestation instead |
| 31 | it does NOT assert lawfulness or authorisation | LEG-08 |
| 32 | the statement is versioned and anchored like any other record | LEG-09 — anchored, not merely published |
| 33 | the witness's time source and the limits of the time assertion | LEG-19 |

**LEG-03 is the one to watch.** The statement asserts "immediate successor", and
M3a deliberately does NOT enforce immediate succession — DES-08 changed to
consistency proofs because checkpoints publish every 10 seconds or 1,024
records, so sizes legitimately jump. Writing "immediate successor" into a legal
document the software contradicts is exactly the failure this inventory is for.
The requirement's wording predates that change and the statement has to say what
the witness actually does: that the submission EXTENDS the history the witness
last held, proved by an RFC 6962 consistency proof.

## Witness store durability — OPS-06

| # | What happens if… | Expected | Adversarial |
|---|---|---|---|
| 34 | the witness loses its store | the corroboration it exists to provide is gone. A documented RPO, a restore procedure, and a drill that meets it | ✓ |
| 35 | a restored witness store is behind the operator's log | the operator's next submission fails the consistency proof against the older root, which is the correct outcome and must be documented so it is not read as tampering | ✓ |

## What M3b cannot close

**OPS-06's drill is a procedure, not a property.** A restore drill that meets an
RPO on one machine says the procedure works, not that any particular deployment
does it. The document says so, and the drill is scripted so it can be run rather
than described.

**LEG-09's anchoring of the statement is only as good as the witness set.** The
statement is anchored like any other record, which means under the default
configuration its time is attested by a TSA and nothing maintains sequence state
over it. That is the same honest limit as everything else and is stated in the
statement itself.
