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
  "policy":"sha256:b2c8…",         // digest of the effective policy        DES-09
  "counts": { "tool_call": 41, "approval": 3 } }
```

Chained and anchored like any record, every 5 seconds by default, **whether or not a run is
active** (FR-24, FR-56). A window with no heartbeat is as loud as a broken hash.

This is why the chain is collector-scoped (DES-04). A heartbeat stream living inside a run would
prove nothing about the interval between runs — which is precisely when stopping the collector is
invisible, and therefore precisely the window an operator would choose.

**`build` is what makes suppression attributable.** A patched collector reports an unrecognised
digest; a stopped one reports nothing. And the digest is only meaningful because DES-17 publishes
a provenance attestation binding it to a source commit — **without DES-17 this field proves that
some build ran**, which is why SEC-22 had to move into M1 rather than sit in M0 where it could
not be done.

### Gap declaration — FR-26, FR-27

When a batch is genuinely lost — disk full, crash mid-write, a witness refusing a stale sequence:

```jsonc
{ "kind":"gap", "from_seq":4790, "to_seq":4795,
  "reason":"queue_lost_on_disk_full", "declared_at":"…" }
```

Signed, chained, and submitted for countersignature. A stateful witness accepts it at the
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
actions         18,422 captured, all chained and anchored
collector       alive 99.98% of the window, one build: sha256:7f3a…
gaps            1 declared  (4790-4795, queue_lost_on_disk_full, countersigned)
                0 undeclared
anchoring       100% of batches witnessed; 3 late (max delay 11 min), reported below
verdict         COMPLETE with 1 declared gap
```

**FR-40** requires late-anchored windows to appear here as gaps. A batch anchored eleven minutes
after the fact had an eleven-minute mutability window, and that is weaker evidence — honestly
weaker, rather than silently absent.

## What this does not prove — SEC-11's boundary

A collector patched to **drop one specific tool call** while still heartbeating with a recognised
build digest produces a correct-looking, complete-looking record. Coverage proves the collector
was running and which build; it cannot prove the build did not lie.

Closing that requires the counterparty to co-sign, which is bilateral receipts (RM-01) in 2.0.
Until then the record rests partly on the operator's word, and the threat model says so under
residual risk. **The one thing this element must never do is imply otherwise** — "100% captured"
means every action the collector saw, and the report says exactly that.
