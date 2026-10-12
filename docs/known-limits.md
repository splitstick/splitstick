# Known limits: what leaks, and what is not covered

**Covers:** DOC-05, DOC-10 · **Related:** SEC-11, FR-25, FR-64, PRIV-07, PRIV-08,
SCOPE-12 · **Checked by:** `packages/core/test/known-limits.test.mjs`

This document is published rather than reviewed. Every attack the red-team
harness still records as **undetected** has to appear here by name, and a test
fails if one does not — so an attack that stops being closed cannot quietly
stop being disclosed either.

## The attacks that are not covered

### A patched collector — AC-6, attack G2

An operator who modifies the collector to suppress individual actions, while
keeping the heartbeat cadence and reporting the published build digest,
produces a record that is correct-looking and complete-looking. The chain
recomputes, the heartbeats are continuous, and the suppressed action is simply
absent: nothing anywhere remembers that it existed.

**This is not detectable by anything in this release**, and the red-team suite
runs it as an attack so the statement is a measured result rather than a
sentence. A self-reported build digest is not remote attestation — the patched
process controls what it reports. Coverage proves a heartbeat was continuous
and reports a digest; it proves nothing about whether the process emitting that
digest was the artifact the digest names. `SCOPE-12` rejects the TEE claims
that would be the alternative, for reasons that still hold.

What the build digest *does* do: binds a window to a traceable artifact, so an
honest operator can show which build ran and a misconfiguration is caught.
That is a smaller claim than it looks, and it is the true one.

### A path created outside the collector — FR-64

An operator can stand up an entirely separate execution path. The original
collector goes on reporting an unchanged capture digest and heartbeating
normally, and nothing diverges, because nothing inside Splitstick observes the
new path. FR-64 is provenance of a self-report, not independent observation.

What it *does* do: makes the declared capture surface part of the evidence, so
narrowing it later is a recorded change rather than a quiet one.

### Erasure with both counters repaired — AC-5, attack F3

Removing a record, renumbering `record_seq` **and** `source_seq`, repairing the
chain and re-signing leaves nothing internally inconsistent. Closed by a
countersignature from a stateful witness, and by reconciliation against a
counterparty's own records (DES-19) — not by cryptography over the operator's
own files.

### Custody and key-exfiltration attacks — AC-3 and AC-4, attacks C2 and D

A software-keyed epoch's private key may have been copied before rotation, so
no forward-secrecy claim is made for it; and an operator holding their own key
can re-sign a rewritten history. Both are closed by a second party, and neither
is closed by files alone.

## What leaks

**Tree size.** An inclusion proof reveals the total number of records, which
counts *everything* — actions, heartbeats, policy events, gap declarations and
padding — so it is not an action count (PRIV-07). FR-69's padding records exist
to blunt the inference and do not remove it.

**Anchor cadence.** Submitting checkpoints to a witness on a schedule leaks
activity volume to that witness (PRIV-08). A witness learns when you were busy.

**Coverage resolution.** The heartbeat interval is in the record and in the
attested policy, so a reader can see how finely the log can speak — and so can
anyone else who sees a heartbeat. A sixty-second interval tells an observer
that a fifty-second suppression would have been invisible.

**Declared capture surface.** The upstreams and interfaces the collector
declares are in the attested policy document, which is stored beside the chain.
That is deliberate — a narrowing has to be visible — and it is information
about the deployment.

## What this project does not try to do

Prevention. The operator is the adversary and runs the machine; the goal is
that interfering with the record is **detectable and attributable**, not that
it is impossible. Where detection depends on a second party, this document and
the verifier both say so rather than implying the files alone are enough.
