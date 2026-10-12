# M4 follow-ups

What M4 left open, written at the point of shipping.

## Carried

**NFR-01** (append overhead) and **NFR-09's HSM half** are unchanged — still
carried to M7 and M1 respectively. Nothing in M4 touches the append path.

**FR-39's signed receipt** is unchanged and still worth deciding before anybody
relies on the time half of a countersignature. M4 makes it slightly more
pressing: FR-40's late-anchor delays are measured against the witness's own
clock, which for a C2SP note is carried beside the signature rather than under
it, so the delay figure rests on the same unsigned value.

## Open, and worth fixing before 1.0

**The test suite leaks a temporary directory per test.** Every fixture is a
`mkdtempSync` under the system temp directory and almost none are removed, so a
few hundred runs of the suite leave tens of thousands of stores behind. This
filled the development machine's disk during M4 — 62,000 directories — and the
failure mode is a build that stops for a reason unrelated to anything being
built. The fix is a shared fixture helper that registers each directory for
removal, which is a mechanical change across a few hundred call sites rather
than a design question.

**`COVERAGE_GAP`'s tolerance is two heartbeat intervals, and that is a
judgement rather than a measurement.** One interval is the expected spacing, so
flagging at one would report ordinary jitter as an outage and teach a reader to
ignore the field; two is a guess at where jitter ends. It should be derived
from observed spacing, or made configurable with the configured value attested
alongside the interval so a reader can see which tolerance produced the claim.

**The coverage report reads the whole chain to answer about a window.** Fine at
M4's scale and not fine indefinitely: it is `O(records)` per report regardless
of how narrow the window is. A date index, or a per-checkpoint summary the
report can seek into, is the obvious answer and neither belongs in M4.

**Nothing cross-checks the heartbeat `counts` against the chain.** DES-10
specifies the field, the collector writes it, and the report does not use it.
It is a second, independently chained statement of how many records of each
kind were written in an interval, so comparing it against what the chain
actually holds would catch a disagreement — modest value, since a chain-breaking
deletion is already caught, but it costs nothing and is currently a field
written for no reader.

## Decided against

**Recording a baseline `policy` record in every store.** It worked, and it cost
a record in every log and shifted the sequence of 76 existing tests. Heartbeats
already commit to the policy in force continuously, which is strictly better
than a baseline event: a reader can say which policy *any* window ran under
rather than reconstructing it from change events.

**Tightening `validateRecord` to demand a well-formed digest for the
heartbeat's `build` and `policy`.** This is the obvious way to close the
`sha256:unset` hole and it breaks something worse: `validateRecord` is also the
read path, so every heartbeat written before the change becomes
`MALFORMED_RECORD`, which the verifier reports as `fail` — a false tampering
signal over evidence that was correct when written, raised by the tool whose
only job is telling those apart. Closed at emission and at interpretation
instead, which are the two ends that do not reclassify old evidence.

**Putting the expected witness set in the envelope for FR-66.** The envelope is
not signed — countersignatures sit beside the note by DES-20 — so an operator
could edit the expectation freely, and it would then look authoritative without
being so. The expectation comes from the effective policy instead, which the
chain commits to.

## Defects found while building, each by a probe or a test

1. **A duplicate `record_seq`.** The pending policy event was flushed in
   `#write`, but `#envelope` is what fixes `record_seq`, so the policy record
   and the record that triggered it were built from the same counter and both
   claimed the same sequence. Both values were valid integers; it was the
   comparison that was against the wrong state.

2. **A practice-statement version read as an effective-policy change.** Both
   use the `policy` record kind and neither said which policy, so the collector
   compared two digests that were not about the same subject.

3. **The baseline policy document was missing exactly when it was needed.** It
   was written only on a change, so the policy a heartbeat attests had no
   document — and that policy is precisely what becomes a later change's
   `previous_policy`. The first downgrade was detectable and not legible.

4. **The integrity check could never have fired.** It read `f.verdict` on a
   `ChainFinding`, which carries no verdict, so the comparison was
   `undefined === 'fail'` for every finding. The typechecker caught it; nothing
   in the behaviour would have.

5. **A verdict with no finding to explain it.** Unwitnessed or late anchoring
   drove the result to `inconclusive` while emitting nothing, so a report could
   conclude `inconclusive` and list no reason.

6. **A second failure-code vocabulary, invented locally.** The spec already
   named `COVERAGE_GAP` and `COVERAGE_UNKNOWN` for M4. A reader should not have
   to know which tool is talking before they can read a code.

7. **The red-team's AC-6 families measured the wrong thing twice.** `G` was
   caught by `SEQ_BROKEN` because only `record_seq` was renumbered, so the
   family read as DETECTED for a reason that had nothing to do with coverage;
   and `G2` removed an action from an honest store, leaving a hole a patched
   collector would never leave, so the declared limit read as closed. Both
   would have credited AC-6 for catching something it does not catch.

8. **`H` tampered with the record's shape rather than its content**, adding a
   field the schema does not declare, so it was caught as
   `FORMAT_UNSUPPORTED` — a finding about a malformed record rather than an
   altered one. The family passed while testing something else.

## And one thing the gate system could not say

AC-6's class is "stop or patch the collector, then claim quiet". The stop is
closed; the patch is not closed by anything in this release, and `SEC-11`,
`FR-25` and `DOC-10` all say so. The gate rule — every assigned attack must be
detected — could therefore only report AC-6 as NOT MET, which reads as a
shortfall rather than as a boundary the project chose and published.

So an attack may now be declared out of scope, and the declaration must name
the requirement that declares it. Such an attack does not count against the
gate and is always printed beside it, so a `HELD` line can never be read as a
fully closed class. Three things keep the marker from becoming an escape hatch:
an undetected attack without a declaration still fails the gate, a class
exercised only by declared limits is reported as closing nothing, and a
declared limit that turns out to be detected is reported as a stale
declaration — because leaving the project claiming a weakness it no longer has
is its own kind of dishonesty.

## Defects found by the independent review of M4

Six findings, each reproduced by a probe before being fixed, and each shown to
fail its regression against the pre-fix code. All 759 tests passed before this
review, so none of the six was covered — which is the review's first result.

Five of the six are in `coverage.mjs`, the module whose own header names it as
the largest surface in the project that composes an assurance out of evidence.
The risk assessment said that was where to look. It was right, and writing that
down did not stop me putting six defects there.

9. **A COMPLETE verdict over a window with no liveness evidence at all.** Three
   countersigned actions, zero heartbeats, no findings, verdict `complete`.
   SEC-11's entire mechanism was absent and nothing said so, because every
   check was written to compare heartbeats against each other and there was
   nothing to compare. The rendering printed "continuity unknown" in prose
   while the verdict said complete — and a reader acts on the verdict. Now
   `COVERAGE_UNKNOWN`: not a gap, because the records present prove the
   collector ran at those instants, and claiming an outage would overstate
   against the operator. What is unestablished is liveness *between* them,
   which is what a heartbeat is for.

10. **A 6.8-year outage invented for time before the log existed.** A window
    opening in 2020 against a chain starting in 2026 produced a `COVERAGE_GAP`
    of 213,962,400,000 ms and a verdict of `incomplete` — a fail-class finding
    accusing the operator of a stop over an interval the report itself says it
    cannot speak to. The same at the other end, where a log that ends is not a
    log that stopped. The report now speaks only to the intersection of the
    window and the chain's span, and the remainder is reported as unknown.

11. **The same record meant different things to different modules.**
    `record.mjs` documents an absent `policy_subject` as read by *neither*
    reader and the collector requires `'effective'`, but the coverage report
    filtered on `!== 'practice-statement'` — so a subject-less policy record
    was counted as an effective-policy change. That is precisely the collision
    `policy_subject` was added to end, reintroduced in the code that consumes
    it. Subject-less records are now reported and counted as neither.

12. **One policy change reported as two.** The capture surface carries
    `anchor_interval_ms` because it is part of what is attested, and it was
    also compared at the top level, so a single change appeared twice — in a
    list an auditor counts.

13. **The coverage CLI leaked a store on every run without `--collector`.** It
    opened a probe to ask which collectors exist, then opened a second store
    for the named one and closed only that. The first regression written for
    this instrumented a `Store` subclass and asserted the subclass paired its
    own opens and closes: true, and silent about the CLI — a check that could
    not see its subject.

14. **FR-40 measured lateness against a hardcoded minute.** The operator
    attests an anchor interval; the report ignored it. An operator anchoring
    every ten minutes by declared policy had nine of those minutes reported as
    lateness, and one anchoring every second had a 59-second delay reported as
    on time. A claim's threshold has to come from the same place the claim
    does, so it is read from the attested policy document — and where no such
    document is held, lateness is not asserted at all rather than asserted
    against a guess.

**What the six have in common.** Four of them — 9, 10, 12, 14 — are the report
saying something the evidence does not support, in both directions: twice too
favourable to the operator (a clean verdict with no liveness evidence, a
generous lateness threshold) and twice too harsh (an invented outage, a doubled
change). The remaining two are a comparison against the wrong thing and a
resource never released. The pattern from M3b holds exactly: the defects are
not in the mechanisms, they are in what gets claimed about them.
