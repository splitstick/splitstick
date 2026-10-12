# Witness outages: what the queue means, and what recovers on its own

**Covers:** OPS-02, NFR-13, FR-68 · **Related:** FR-38, NFR-12, SEC-04, FR-57,
§4 of the [Witness Practice Statement](witness-practice-statement.md)

A witness outage is an ordinary event, not an incident. Collection never stops
for one (NFR-12 is absolute), the batch is marked unwitnessed, and the evidence
that the outage created is the first thing that would be lost if the queue were
not durable — an outage is exactly when a restart is most likely.

This document says which parts of that recover by themselves, and which need
somebody.

## The queue holds INSUFFICIENTLY witnessed checkpoints

Not *unwitnessed* ones. The distinction matters whenever you configure more
than one witness, and it was a real defect: an entry used to leave the queue as
soon as **any** witness answered, so a deployment that required two independent
sequence witnesses and lost one ran on a single witness permanently, with
nothing retrying the other and nothing reporting it.

A checkpoint leaves the queue when its quorum is met — counting every
countersignature on its envelope, not just the ones the latest attempt added.

## What recovers automatically

| | |
|---|---|
| **A witness that returns** | Yes. `flush()` retries the queue, highest height first, with OPS-02 backoff. |
| **The missing half of a quorum** | Yes. The entry stays queued until the quorum is met, and each attempt asks only the issuers that have not answered. |
| **A witness that was behind** | Yes. Each witness is told the height **it** last signed, so one returning from a long outage is asked to extend its own history rather than a tree it never saw. |
| **Lower heights, once a higher one is witnessed** | They are reported as `superseded`, not retried. A stateful witness that has advanced refuses a lower height (FR-43), so retrying them would manufacture refusals and report them as outages. |
| **The ceiling alert** | Clears when the queue drains. The coverage report still names the window as unwitnessed — the alert clearing does not retroactively witness anything. |
| **A torn queue file** | The tail is dropped and repaired before the next append. |

A `flush()` result names what happened: `anchored`, `superseded`, `waiting`
(still inside its backoff window), and `queued`. A submission result names the
issuers still `missing`. Nothing disappears from the queue without appearing in
one of those.

## What does not recover on its own

**A quorum you cannot reach.** The target for a capability class is the
configured quorum bounded by how many configured witnesses establish that
class — so a quorum of two against one witness is treated as satisfied by that
one, rather than holding every checkpoint forever and breaching the ceiling
over a configuration you chose. `quorum_met` still reports the configured
number as unmet, and SEC-04 flags a single-witness set. **If you meant two,
configure two; nothing here will tell you a second time.**

**A decommissioned witness left in the configuration.** It is counted in the
class target, so if removing it drops a class below the quorum you will see
that class unmet. Remove it from the configuration rather than leaving it to
fail.

**The unwitnessed window itself.** Past `unwitnessed_ceiling` an alert is
raised out of band — through a callback, writing no record, because an alert
about the log's integrity written into that log asks the suspect to carry the
complaint. It fires once per breach, not once per flush. **Nothing in the
software can close a window that has already been unwitnessed**: when the
witness returns, the coverage report states the window rather than pretending
it was not there, and that is the correct outcome.

**A witness that answers but whose proof does not verify.** It is discarded,
not stored, and reported as a failure for that issuer — storing a proof that
fails verification later means the first anyone hears of it is an auditor's
report. It will be re-attempted like any other missing issuer, and it will keep
failing until the key or the acceptance material is fixed.

## What to watch

- **`queued` not shrinking while `waiting` is empty** — attempts are being made
  and failing. Read the per-issuer `failed` details; this is a witness problem
  or a configuration problem, not a backoff problem.
- **A ceiling breach** — the window is past the point where you said fail-open
  stops being acceptable. The log is still complete and still collecting; what
  you have lost is the ability to claim completeness across that window.
- **`quorum_met` false for a class while `sufficient` is true** — you asked for
  more witnesses in that class than you configured. This is a configuration
  statement, not an outage.
- **`missing` naming the same issuer for a long time** — that witness has not
  answered since it was queued. The queue will go on asking; whether it should
  still be in the set is your call.

## What this does not do

It does not replicate a witness. OPS-06 specifies replication and the project
does not implement it: a second witness host, or a replicating filesystem, is a
deployment decision this software cannot make or check. The recovery half is
exercised by [the restore drill](witness-restore-drill.md). And note that if
the backup lives on infrastructure the operator controls, the backup is as
compromisable as the witness — which defeats the point of it being a different
party.
