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
