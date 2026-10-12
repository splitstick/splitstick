# M3b follow-ups

What M3b left open, written at the point of shipping.

## Carried

**NFR-01 and NFR-09's HSM half** are unchanged — both still carried to M7 and
M1 respectively. Nothing in M3b touches the append path or the custody
question.

## Open, and worth deciding before 1.0

**A C2SP witness's receipt time is unsigned, and FR-39 asked for more than the
format allows.** The requirement says the countersignature records the witness's
actual receipt time. For a `splitstick`-type witness there is nowhere inside a
C2SP note to put one, so the value travels beside the signature in the envelope
and the verifier labels it `witness-asserted, unsigned`. That is honest and it
is weaker than it sounds.

Closing it properly means a signed receipt: the witness signs
`(note_digest, received_at)` as a second, small structure carried in the
envelope alongside its note line. That is a protocol addition, so it did not
belong in M3b, and the practice statement states the limit in §1.1 rather than
leaving a reader to infer it. **It should be decided before anybody relies on
the time half of a countersignature.**

**OPS-06 specifies replication and does not implement it.** The drill exercises
restore-from-copy, which is the recovery half. A second witness host, or a
replicating filesystem, is a deployment decision this project cannot make or
check — and if the backup lives on infrastructure the operator controls, the
backup is as compromisable as the witness, which defeats the point of it being a
different party. Stated in `docs/witness-restore-drill.md`.

**A `409` after a restore is indistinguishable from a `409` for a fork, by
status alone.** Both are correct refusals and they mean very different things —
retry from the height in the body, versus stop and investigate. A monitoring
system will page on both. The drill documents the difference; a distinct status
or a machine-readable reason code would be better, and it is a protocol change.

**The practice-statement lint is textual.** It pairs 15 claims with a behaviour
each and catches drift — a reworded requirement, a deleted disclaimer, a
removed behaviour while the promise stays. It cannot prove the behaviours are
correct; the test suites do that. Nor can it catch a claim nobody thought to add
a row for.

## Decided against

**Merging the two witness writes into one atomic transition.** Raised again
here because it would also have simplified the queue. Rejected for the same
reason as in M3a: rewriting the whole retained history on every submission is
the O(n²) shape DES-13 rejects for the salt journal, and at a ten-second cadence
that is 8,640 entries a day.

**Making the compromise declaration a `policy` record, as DES-06 says.** The
per-kind allowlist is exhaustive, so a policy record carrying a last sound epoch
and a new root key would have to make those fields optional — optional on every
ordinary policy change, where they mean nothing. A distinct kind says
required-here and forbidden-there, and it lets the verifier find discontinuities
by kind rather than sniffing for optional fields, which is what makes "never
silently bridged" a checkable property. DES-01 records the deviation.

**Writing the FR-68 alert into the log.** An alert about the log's integrity,
written into that log, asks the suspect to carry the complaint. It goes out of
band through a callback and the collector writes no record for it.

## Defects found while building, each by a test

1. **The FR-58 reserve would have been dead in production.** The failed append
   degrades the collector, so the retry after releasing the reserve was refused
   before it reached the store. The mechanism existed and could never have fired.

2. **M3a built the gap record and never taught the verifier to read it.**
   `recomputeChain` reported `SEQ_BROKEN` for a jump the gap record immediately
   before it *declared* — the honest collector accused of exactly what the
   disclosure exists to disclose.

3. **The OPS-02 backoff blocked the first retry for thirty seconds**, so a
   witness that returned in two went unused for thirty. And its exponent gave
   attempts 0 and 1 the same delay, so it never visibly grew.

4. **`Date.parse("12345")` returns the year 12345**, which would have produced
   an unwitnessed window ten thousand years wide.

5. **An unpublished witness rotation failed the entire verification.** When
   nothing counted towards any quorum the WITNESS check returned `fail`, while
   the per-entry verdict correctly said inconclusive.

6. **The restore drill measured its own recovery point as zero**, because it
   counted retained roots after the restore when both handles pointed at the
   restored directory — and that number is the drill's entire output. It now
   fails if it measures no loss at all, so it cannot pass without exercising a
   stale backup.

## Defects found by the independent review of M3b, each reproduced before it was fixed

Five findings. Four are M3b's; the fifth has been in the record schema since M1.
All five are the same shape as the external findings on M3a — a bad value
tolerated, coerced, or skipped where it should have been refused or repaired.

7. **One corrupt `since` in the queue silenced the FR-68 ceiling forever.** The
   unwitnessed age is `now - since`. An unparseable `since` makes that `NaN`,
   and every comparison against the ceiling is then false — so the mechanism
   whose only job is to stop fail-open becoming indefinite was itself silenced
   indefinitely, by one field, with no warning anywhere. Two changes: an
   unreadable entry is refused by `Store.readQueue` instead of being coerced or
   dropped, and an age that cannot be measured counts as **over** the ceiling,
   because an unmeasurable outage is not a short one.

8. **The queue's append fast path persisted a different queue than the one in
   memory.** Entries are kept ordered by `checkpoint_seq`, so an out-of-order
   enqueue lands mid-array — while `appendQueue` wrote the new entry at the end.
   Memory held `[1,2,3]` and the journal held `[2,3,3]`: a restart could not
   reconcile the two, and the queue is the thing that exists to survive a
   restart. The append is now taken only when the new entry really is last.

9. **A legitimate restart refused to open the store.** A counter behind the
   written records was treated as tampering, but the counter is written at each
   flush while `source_seq` advances at every observation, so behind is what the
   ordinary state between flushes looks like. Any crash after a reconciliation
   and before the next checkpoint bricked the store until somebody edited the
   counter file by hand. The test that asserted the wrong behaviour is rewritten
   to record why. The cost of accepting it: a counter restored from an older
   copy under-declares a loss — the operator misreporting their own loss, which
   the gap mechanism never claimed to prevent, and which cannot be told apart
   from the normal state, so refusing would break the ordinary path to catch
   nothing.

10. **A duplicate gap declaration was accepted by both the collector and the
    verifier, and verified `ok`.** Declaring `2-3` twice passed, because each
    side only ever compared a declaration against the written sequence and never
    against the declarations already made. That is how an operator makes one
    loss look like two, and how the size of a third is hidden inside the
    double-count. Both sides now account against what has already been
    declared: the collector will not propose an accounted span, and the verifier
    will not accept one. Finding 2 above taught the verifier to *read* the
    declaration; reading it was not sufficient.

11. **`2026-13-45T99:99:99.999Z` validated as a timestamp** — month thirteen,
    day forty-five — because every digit was in the right place and the schema
    checked the shape with a regex. Present since M1. Anything computing with
    the value got `NaN`: FR-39's unwitnessed window, M4's coverage reasoning,
    any ordering by time. `Date.parse` is not the fix either: it rejects month
    thirteen but rolls `2026-02-30` over to March 2nd and reports it finite, so
    a date that never existed would read back as a different date than the one
    written. One `isTimestamp` now round-trips through `toISOString` — the
    required format is exactly what `toISOString` emits, so a real instant is
    reproduced character for character and anything normalised away fails — and
    every call site that was testing the regex directly uses it.

**What the five have in common with M3a's external findings.** Every one sits in
state that crosses a restart — the queue, the counter, the declarations, a
stored timestamp — and every one was a place where the code read damaged or
duplicated state and carried on. None was a missing feature; all five were
written, reviewed by me, and passed. The failure is not in noticing that state
must be checked, it is in checking it against the wrong thing: the shape instead
of the value (7, 11), memory instead of disk (8), the written records instead of
what is accounted for (9, 10).
