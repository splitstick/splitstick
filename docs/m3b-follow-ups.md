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

## Defects found by the external review of PR #8

Two findings, both reproduced before being fixed, and both about whether the
evidence is still *sufficient* after the system has been through exactly the
conditions M3b exists to handle.

12. **The practice-statement command destroyed its own history.** `anchor-wps`
    deleted its output directory on every run and generated a fresh signing key
    each time, so each version's record was the only one that survived and the
    link between versions existed solely as text inside the newest record — a
    log discarding its own history in order to record its history. It also
    printed its result as anchored while signed by a throwaway key and
    countersigned by nobody, and LEG-09 was marked done on that basis.

    Now: the store is append-only across runs under one persisted identity, so
    the chain from the first version to the current one *is* the evidence and
    verifies through the ordinary verifier; the predecessor digest is read from
    the chain rather than from a file beside it; re-running on an unchanged
    statement appends nothing, because two records of one version make one
    publication look like two; `--config` submits the checkpoint to a real
    witness set; and the word *anchored* is chosen by reading the envelope for
    a countersignature rather than by the command's intent. §7 of the statement
    now separates the two steps and says which one the project has not taken.

    **LEG-09 is marked `partial`,** not done. The versioning half is held and
    tested. The external-anchoring half needs an operator key this repository
    does not hold and must not, so the project's own published statement is not
    anchored by anybody, and the matrix now says so rather than claiming it.

13. **The queue cleared a checkpoint before its quorum was met.** An entry left
    the durable queue as soon as *any* witness answered; the quorum was computed
    afterwards and not consulted. With two independent sequence witnesses
    required and one offline, the checkpoint was dequeued on the single answer
    and the second witness was never retried — so a deployment that asked for
    two ran on one, permanently, with nothing reporting it.

    The queue now means **insufficiently witnessed**, not unwitnessed. Three
    things were needed and only the first was reported:

    - Entries stay queued until the quorum is met, and the result names which
      issuers are still missing.
    - The quorum counts every countersignature on the envelope, not just the
      ones this attempt added. Counting only the latest attempt would have let
      the second witness answer, be counted alone, never reach two, and requeue
      forever — the fix would have looked like it worked while quietly never
      finishing.
    - `old_size` is now **per issuer**. It was the highest height witnessed by
      anybody, which is the same number with one witness and wrong for whichever
      is behind with two: a witness returning from an outage was asked to extend
      a tree it had never signed, refused, and would go on refusing. The queue
      could never have cleared by waiting, which is the only thing the queue
      does. This was not in the report; it is what made the reported bug
      unfixable on its own.

    The target is bounded by how many witnesses could ever answer for a class,
    so a quorum of two against one configured witness does not hold every
    checkpoint and breach the FR-68 ceiling forever over a configuration the
    operator chose. `quorum_met` still reports the configured number unmet, and
    SEC-04 is what flags a set that small.

**And one found while fixing them.** Reading the previous version's digest from
the chain, I filtered policy records on `r.next` — the field is `next_policy`.
The filter matched nothing, an empty list read as "there is no previous
version", and the command appended a duplicate record of the same version on
every run: precisely the failure the check immediately below it was written to
prevent. A policy record missing that field is now refused rather than treated
as an absent record. Same shape as findings 7 and 11, in code written to fix
findings 7 and 11.

## Defects found by the re-review of PR #8

Both in the command from finding 12 — the fix for a defect, with two defects in
it. Both reproduced before being fixed.

14. **A statement recorded earlier could never be anchored later.** The command
    exited as soon as it saw an unchanged digest, and that check sat *before*
    the witness configuration was read. So the ordinary sequence — record the
    statement now, anchor it when a witness set exists — did not work: the
    second run saw the same digest and went home without contacting anybody.
    Reproduced exactly that way; the run printed "already the current recorded
    version" and made no submission.

    *Already recorded* is not *already anchored*, and only the first is a reason
    to append nothing. The two are now separate: on an unchanged digest the
    command finds the checkpoint the existing record already falls under and
    submits that, appending no second record of the same version.

15. **`ANCHORED` was decided by issuer presence, not by verification.** The
    status was `issuers.length > 0 ? 'ANCHORED' : ...`, read straight off the
    envelope. An envelope can carry a proof this operator could not check — the
    collector attaches an unverified countersignature deliberately, because
    discarding evidence a reader with the right policy could use would be worse
    — so presence was being reported as established time. This was *my* fix for
    finding 12: I replaced "the command asserts it anchored" with "the command
    reads the envelope", which is better and still not verification.

    Three states now, and the verdict is taken from `verifyStore` rather than
    decided here:

    | Reported | What is true |
    |---|---|
    | `RECORDED` | digest and version chain fixed; nothing countersigned them |
    | `COUNTERSIGNED (unverified)` | a proof is present and nothing validated it |
    | `ANCHORED (verified)` | the proof validates against the acceptance policy |

    Using the shipped verifier rather than a check written in the command is
    what makes the timestamp-token, certificate-path and extended-key-usage
    checks apply to this artefact as they do to any other — and it is the
    literal content of LEG-09's "like any other record, with no special path".
    A local check would have been a fifth instance of the recurring instrument
    failure in this project: a check that reads its own description as though
    it were the code.

    `--policy` is a separate flag from `--config` because DES-09 keeps the two
    policy files apart: one says who gets asked, the other whose signature is
    accepted. With no acceptance policy the only honest answer is *unverified*,
    never *anchored*.

**The shape of these two.** Finding 12 was a command that overclaimed. Both of
these are in the correction to it, and both are the same error one step in:
having been told the evidence must survive, I made it survive and then reported
its mere existence as its sufficiency. Presence is not proof, and a record is
not an anchor. That is the third and fourth time in this branch that the defect
was a value checked against the wrong thing.

## Defect found by the second re-review of PR #8

16. **Verified evidence was attributed to the wrong statement version.** The
    command located the checkpoint covering the current version correctly, then
    read `verifyStore`'s witness list — which reports every countersignature in
    the store, across every checkpoint — as though it answered about that
    checkpoint. Reproduced: v1.0 recorded and countersigned, v1.1 recorded
    under a new checkpoint nobody had signed, and v1.1 reported **ANCHORED
    (verified)** on the strength of v1.0's proof. A false assurance about
    exactly the thing anchoring exists to establish, the publication time of
    the newer statement.

    The root cause was in the verifier, not only in the command: every witness
    entry's detail string already began `checkpoint N:`, so the attribution
    existed in the *prose* and not in the *data*, and a caller asking whether a
    particular record was anchored had no field to read. `WitnessEntry` now
    carries `checkpoint_seq` and `tree_size`, stamped once as entries leave the
    envelope loop rather than repeated at each of the eleven push sites — the
    type refuses an entry without them, so a branch added later cannot omit it.

    The rule the command applies: a proof is evidence about a record when the
    tree its checkpoint committed to **reaches** that record. That admits the
    covering checkpoint and any later one, and excludes every earlier one
    however well it verifies. Scoping by exact checkpoint equality would have
    refused real evidence — a checkpoint taken after the statement was recorded
    anchors it too — so both halves are tested. Proofs deliberately not counted
    are reported as `not counted`, with the checkpoints they sit on, rather than
    silently dropped.

**Where this one came from.** Findings 12, 14, 15 and 16 are four defects in one
small command, each found in the fix for the last. The command was the only
place in the project where a human-readable assurance is composed from
evidence, and composing an assurance turns out to be where the assurance can
be made to say more than the evidence supports: a deleted history (12), a step
that could not be taken (14), presence read as proof (15), and now one
subject's evidence read as another's (16). The verifier itself was sound each
time; what was wrong was the question being asked of it.
