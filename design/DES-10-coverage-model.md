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

## What this does not prove — SEC-11's boundary

A collector patched to **drop one specific tool call** while still heartbeating with the original
build digest produces a correct-looking, complete-looking record. Coverage proves a heartbeat was
continuous and reports a digest; it proves nothing about whether the process emitting that digest
was the artifact the digest names.

So "100% captured" means **100% of what the collector reported** — stated that way in the output,
not softened in a footnote.

**The cheapest available narrowing — FR-64.** The heartbeat attests a digest of the collector's
effective capture configuration: which upstreams it proxies, which interfaces it binds, and its
heartbeat and anchor intervals. Adding an unobserved path then requires either a recorded
configuration change, which is visible, or a divergence between the attested config and the
observed one, which is also visible. It does not close the bypass gap — only a counterparty
signature does — but it converts "quietly add a second path" into "leave a trace".

**The heartbeat interval sets the resolution of every claim it supports**, which is why it is in
the config (`FR-41`) and in the attested digest. A sixty-second heartbeat makes a fifty-second
suppression invisible, and a coverage report must never imply finer resolution than its own
interval.

Closing that requires the counterparty to co-sign, which is bilateral receipts (RM-01) in 2.0.
Until then the record rests partly on the operator's word, and the threat model says so under
residual risk. **The one thing this element must never do is imply otherwise** — "100% captured"
means every action the collector saw, and the report says exactly that.
