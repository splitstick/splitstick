# DES-10 — Coverage model

**Milestone:** M4 · **Covers:** FR-24, FR-25, FR-26, FR-27, FR-28, FR-40, SEC-11

> The only element here that is not assembled from existing standards. Every comparable tool can
> tell you that what was logged is unaltered; none can tell you that everything was logged.
> **This is the differentiated claim, and the reason it is hard is that proving absence is
> strictly harder than proving presence.**

## Decision

Silence is indistinguishable from "nothing happened" unless the record asserts liveness. So the
collector emits positive evidence that it was alive and which build it was.

### Heartbeat — FR-24, FR-25

```jsonc
{ "v":1, "collector":"treasury-host-1", "run":null, "record_seq":4813, "ts":"…", "kind":"heartbeat",
  "build":"sha256:7f3a…",          // the collector's own artifact digest   FR-25
  "suite":"SS1",
  "policy":"sha256:b2c8…",         // effective capture configuration       FR-64
  "heartbeat_interval":"5s",       // the resolution of this coverage claim
  "counts": { "tool_call": 41, "approval": 3 } }
```

Chained and anchored like any record, every 5 seconds by default, **whether or not a run is
active** (FR-24, FR-56). A window with no heartbeat is as loud as a broken hash.

**Deviation, M4 — `policy` carries the EFFECTIVE policy, not the capture configuration alone.**
The effective policy is a superset of the capture surface — it adds the witness set, the quorum and
the anchor and roll-up intervals — so `FR-64` is unaffected and `FR-23`/`SEC-12` gain something
the design did not have: every heartbeat commits to the policy in force, so a reader can say which
policy *any* window ran under rather than reconstructing it from change events. It also removes the
need for a baseline policy record. An earlier attempt wrote one at `record_seq` 1 of every store;
it worked, cost a record in every log, and shifted the sequence of 76 existing tests.

This is why the chain is collector-scoped (DES-04). A heartbeat stream living inside a run would
prove nothing about the interval between runs — which is precisely when stopping the collector is
invisible, and therefore precisely the window an operator would choose.

**What `build` does and does not do.** An external review was right to push back here, and an
earlier draft of this document overclaimed.

It **does**: bind a window to a traceable artifact, so an honest operator can show which build
ran, a misconfiguration is caught, and the digest resolves to a provenance attestation (`DES-17`)
that ties the artifact to a source commit. Without `DES-17` the field would prove only that
*some* build ran, which is why `SEC-22` had to move into M1.

It **does not**: detect a dishonest patch. A modified collector controls what it reports and can
emit the original digest while suppressing actions. **A self-reported digest is not remote
attestation**, and this release deliberately provides none (`SCOPE-12` rejected TEE claims for
reasons that still hold).

So the honest split, now pinned by `SEC-11`'s tests rather than by prose: **stopping the
collector is detectable** by heartbeat discontinuity; **patching it is not.** `DOC-10` requires
that limit stated wherever coverage is described, including in the report output itself.

### Gap declaration — FR-26, FR-27

When a batch is genuinely lost — disk full, crash mid-write, a witness refusing a stale sequence:

```jsonc
{ "kind":"gap", "from_source_seq":4790, "to_source_seq":4795,
  "reason":"queue_lost_on_disk_full", "declared_at":"…" }
```

One record, one leaf, one `record_seq` — the span lives in `source_seq`, so `record_seq` stays
equal to `tree_size` no matter how many observations were lost. Signed, chained, and submitted
for countersignature. A stateful witness accepts it at the
expected sequence and advances its pointer (DES-08).

**An undeclared absence and a declared one are different objects.** Not just in engineering: where
adverse-inference doctrines apply, unexplained missing evidence invites a conclusion that
documented missing evidence does not. The design converts the first into the second, which is the
most that honesty permits.

### Coverage report — FR-28, FR-40

```
splitstick coverage ./store --from 2027-01-01 --to 2027-03-31
```

Produces the claim that answers an auditor:

```
window          2027-01-01 .. 2027-03-31
actions         18,422 reported by the collector, all chained and anchored
collector       heartbeat continuous 99.98% of the window, one build: sha256:7f3a…
                (a patched collector reporting a valid digest is not detectable
                 without remote attestation, which this release does not provide)
gaps            1 declared  (4790-4795, queue_lost_on_disk_full, countersigned)
                0 undeclared
anchoring       100% of batches witnessed; 3 late (max delay 11 min), reported below
verdict         COMPLETE with 1 declared gap
```

**FR-40** requires late-anchored windows to appear here as gaps. A batch anchored eleven minutes
after the fact had an eleven-minute mutability window, and that is weaker evidence — honestly
weaker, rather than silently absent.

### What the report can conclude — the failure codes

Three codes, in the verifier's shared vocabulary (`spec/failure-codes.json`) rather than a second
set invented for coverage, because a reader should not have to know which tool is talking before
they can read a code:

| Code | Verdict | When |
|---|---|---|
| `COVERAGE_GAP` | fail | a window with no record of any kind and no declaration — nothing attests the collector was running |
| `COVERAGE_UNKNOWN` | inconclusive | a `gap_unknown` is declared, the heartbeat resolution is not established by the records, or the window holds no record at all |
| `UNDATED_RECORD` | inconclusive | a record carries no usable `ts`, so it cannot be placed in a window; excluded from the counts and reported rather than silently dropped |

**Anchoring means VERIFIED anchoring, and the report lives in `@splitstick/verify` because of
it.** Four categories, not three: a record is *anchored* when a covering checkpoint carries a proof
the reader's acceptance policy accepts and that verifies; *countersigned_unverified* when a proof is
present and nothing validated it; *checkpointed_only* when no proof is present; *unanchored* when no
checkpoint covers it. The witness results come from `verifyStore`, never from the envelope's issuer
list — counting issuers meant a countersignature from an unrelated key over different bytes produced
a COMPLETE verdict, which is presence read as proof.

**Every covering checkpoint is considered, not the earliest.** A proof is evidence about a record
when the tree its checkpoint committed to *reaches* that record, so an unwitnessed checkpoint cannot
mask a validly witnessed later one. Lateness is measured from the earliest *verified* receipt, since
an unverified one is an unchecked party's unchecked claim about when.

**Liveness is evidenced by ANY record, not by heartbeats alone.** The first implementation measured
heartbeat-to-heartbeat and reported a two-minute outage over an interval in which three actions had
been written — signed, chained records proving the collector was running. Overstating a stop on the
strength of evidence that says the opposite is the one direction this report must never overstate
in. The heartbeat remains what makes a *quiet* window checkable, which is the whole reason there is
one; both failures are still caught, because a stopped collector writes nothing of either sort.

**The three verdicts.** `incomplete` means something undeclared is missing or damaged.
`inconclusive` means nothing is known to be missing and the evidence cannot support a completeness
claim anyway. `complete` means everything the collector reported is chained, the resolution is
established, liveness is unbroken, and every record falls under a countersigned checkpoint. A
*declared* gap does not downgrade it — that is this document's own example above — because a
disclosed loss is what the project converts an undeclared absence into, and penalising the
disclosure would penalise the honesty it exists to produce.

## What this does not prove — SEC-11's boundary

A collector patched to **drop one specific tool call** while still heartbeating with the original
build digest produces a correct-looking, complete-looking record. Coverage proves a heartbeat was
continuous and reports a digest; it proves nothing about whether the process emitting that digest
was the artifact the digest names.

So "100% captured" means **100% of what the collector reported** — stated that way in the output,
not softened in a footnote.

**Self-reported configuration attestation — FR-64.** The heartbeat attests a digest of the
capture configuration **the collector reports for itself**: upstreams proxied, interfaces bound,
heartbeat and anchor intervals. A change to *that* configuration is therefore recorded and
visible.

**It does not detect a path created outside the collector.** A review was right to push back on
an earlier draft that claimed otherwise. An operator can stand up an entirely separate execution
path; the original collector goes on reporting an unchanged digest and heartbeating normally, and
nothing diverges, because there is nothing inside Splitstick observing the new path. The claim is
provenance of a self-report, not independent observation — and a test pins that limit by
asserting a bypassing path produces **no** signal.

It is still worth having: it makes the *declared* capture surface part of the evidence, so
narrowing it later is a recorded change rather than a quiet one. That is a smaller claim than the
one this document previously made, and it is the true one.

**The heartbeat interval sets the resolution of every claim it supports**, which is why it is in
the config (`FR-41`) and in the attested digest. A sixty-second heartbeat makes a fifty-second
suppression invisible, and a coverage report must never imply finer resolution than its own
interval.

Closing that requires the counterparty to co-sign, which is bilateral receipts (RM-01) in 2.0.
Until then the record rests partly on the operator's word, and the threat model says so under
residual risk. **The one thing this element must never do is imply otherwise** — "100% captured"
means every action the collector saw, and the report says exactly that.
