# DES-15 — Failure and availability model

**Milestone:** M3b · **Covers:** FR-38, FR-39, NFR-12, NFR-13, OPS-02, OPS-06, SCOPE-16

## Decision

**The collector can never stop an agent run.** Not configurably, not in a strict mode, not as an
opt-in. This is the single constraint that decides whether anyone installs it: an audit layer
capable of taking down production is an audit layer that eventually does, at which point it is
removed and never reinstalled.

### Fail-open with a marked gap — FR-38

When no witness is reachable:

1. The batch is chained and signed **locally**. Integrity is unaffected; only the countersignature
   is missing.
2. It is marked `unwitnessed` and written to `queue/`.
3. The run proceeds. The agent never learns there was a problem.

### Late countersignature records real time — FR-39

When a witness returns, the queue drains. The witness stamps **its actual receipt time**, not the
batch's claimed time, so the gap between `ts` and `received_at` is visible in the record and
reported by DES-10 as a coverage gap.

A batch anchored eleven minutes late had an eleven-minute mutability window. That is weaker
evidence, and the design's job is to make it *visibly* weaker rather than to hide it. **Honestly
weaker beats silently absent** — the alternative is a record that looks uniformly strong and
isn't.

### SCOPE-16 — no fail-closed option exists

`on_unavailable` accepts exactly one value, `mark_gap`. There is no code path that blocks, and a
pull request adding one will be declined even if it works. The scope guard exists because the
request is reasonable-sounding — *"some customers need strict mode"* — and granting it would
reintroduce the failure mode the design is built to exclude.

Enforced by review and by a config-schema test, not merely by intention.

## Queue durability — NFR-13, OPS-02

| Property | Rule |
|---|---|
Durability | Queue entries are `fsync`ed before the run continues. A `kill -9` loses nothing already acknowledged. |
Ordering | Drained in sequence order, because a stateful witness requires contiguity (DES-08). |
Retry | Exponential backoff, 1 s to 5 min, indefinitely. Never a dead-letter drop: a batch abandoned silently is exactly the evidence gap this project exists to detect. |
Bounded growth | At a configurable ceiling, emit a `gap` declaration (DES-10) rather than grow without limit or discard quietly. |
Reserved slot | Space for one gap declaration is **pre-allocated at startup** (FR-58), so the declaration can be written even when the store is otherwise exhausted. A design that can only report failure while healthy reports nothing when it matters. |

## When nothing can be persisted

An external review noted correctly that durable recording and uninterrupted execution cannot both
hold under disk exhaustion. The design must say which gives way, rather than implying neither
does.

**Execution gives way to nothing; durability gives way.** In order:

1. The queue's reserved slot (FR-58) is used to write a gap declaration. Normally sufficient.
2. If even the reserve cannot be written, the run **still continues** and **records are lost**.
3. The condition is surfaced out of band — non-zero exit status on the collector process, a line
   on stderr, and a metric — because an unreportable failure that is also silent is the worst
   available outcome.
4. On the next successful write, loss evidence is emitted and anchored — and **which kind depends
   on whether the observation counter survived.**

### Two kinds of loss evidence — FR-26, FR-60, FR-61

An external review pointed out that an unrecoverable crash can take the in-memory `source_seq`
with it, leaving the collector unable to know how many actions were observed but never written.
The next successful write must not invent a range.

| | Written when | Contains |
|---|---|---|
| **`gap`** (FR-26) | the counter survived | the exact `source_seq` span |
| **`gap_unknown`** (FR-60) | the counter did not | a bounded time interval and **no span** |

`FR-61` bounds the second case: the observation counter is checkpointed durably at each batch
flush, so a crash loses at most the current window and the unknown interval runs from the last
checkpoint to the first record after restart — not from zero, and not open-ended.

A verifier reports the two differently and never treats an unknown interval as an exact one. This
is the honest version: a system that fabricates a precise span after losing the counter that
would have measured it is asserting something it cannot know.

What must never happen is a claim of durability over that window. The coverage report shows it as
an **undeclared** gap until step 4 converts it to a declared one, and an undeclared gap is exactly
the signal an auditor should treat as adverse.

## Witness store durability — OPS-06

For an operator running their own witness (FR-17): **a witness that loses its roots destroys the
corroboration it exists to provide.** This is the most consequential failure mode in the whole
design, and it is addressed rather than assumed away.

- Replicated storage, with a documented recovery point objective.
- A restore drill that proves the objective, as a release gate — an untested backup is a belief.
- Published tree heads (FR-50) so a restore that silently rolls back is detectable by anyone
  watching.

Mitigated structurally as well as operationally: at `quorum: 2`, losing one witness degrades the
evidence rather than destroying it. The default includes a public anchor for exactly this reason.

## Chaos obligations — NFR-12

Tested, not asserted. The suite runs an agent to completion under: every witness unreachable;
a witness returning 500s; a witness hanging past timeout; disk full on the queue; `kill -9`
mid-batch; and a clock stepped backwards. In every case the run completes and the record states
what happened.
