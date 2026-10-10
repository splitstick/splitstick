# Threat model

Splitstick records what AI agents did, in a form a third party can check. This document says
who it defends against, what it assumes, what it does not address, and what remains exposed
after everything in 1.0 is built.

**Nothing in this document is verified.** No implementation exists yet. This is the intended
design and the reasoning behind it; every claim becomes a measurement only when the acceptance
suite proves it. Where something is already measured, it says so.

Versioned with the project. Changes are recorded in the history at the end, because a threat
model that can be quietly narrowed after a finding is not a commitment.

## What is being protected

The **record of consequential agent actions** — which tool was invoked, with what arguments,
what it returned, and whether a human approved it — against alteration by the party holding it.

Not the actions themselves. Splitstick does not prevent an agent from doing something; it
makes what happened checkable afterwards. The distinction is deliberate and absolute: there is
no blocking path in the design, and a scope guard (`SCOPE-01`, `SCOPE-16`) forbids adding one.

## The adversary

**The operator.** A party with root on the host, possession of the signing key, write access to
the record, and a motive to change what it says after the fact.

This is an uncomfortable adversary to name, because the operator is usually the customer. It is
also the only one worth defending against here, for a simple reason: every weaker adversary is
already handled. An external attacker without the key cannot forge a signature. A corrupted
disk or a buggy context rewrite produces an inconsistent record that existing verifiers already
catch — we measured that, and OMA's `verifyRun()` detects exactly this class.

What no existing agent-runtime verifier catches is the keyholder. We measured that too: against
a genuine run record, four of six alterations passed the runtime's own verifier, including
changing a EUR 2,000,000 transfer to EUR 25 and deleting it entirely. Reproduce with
`npm test`.

### Goal: detection and attribution, not prevention

A party who controls the machine can always lie. The question is whether lying leaves a trace
someone else can find. Splitstick is **tamper-evident, not tamper-proof**, and no surface may
claim otherwise (`SEC-16`, `SCOPE-02`). That is also the bar the regulation sets: EU AI Act
Article 12 asks for tamper-evident records, not impossible ones.

## Trust assumptions

| Trusted | Not trusted |
|---|---|
| At least one witness in the configured set is honest | The operator |
| The cryptographic primitives (SHA-256, the signature scheme) | The host |
| The verifier's own code, which the reader may compile themselves | The collector binary |
| | Splitstick, the project |

Verification requires only bytes and public keys — no network, no credentials, no account
(`NFR-05`, `NFR-06`). A reader who distrusts everyone, including us, can still check a record.
That is the property the whole design exists to produce.

The shipped default anchors to Rekor, a public transparency log this project does not operate
(`FR-48`). The out-of-box configuration therefore contains no vendor at all.

## Attack classes

Each is closed by a named mechanism and gated by the milestone that implements it. "Local"
means no third party is required; "external" means it cannot be done from inside the record at
all.

| # | Attack | Closed by | Kind | Gate |
|---|---|---|---|---|
| 1 | Alter the recorded action — arguments, result, approval decision | Action-record digests | local | M1 |
| 2 | Alter an event and repair the citing digest | Predecessor chaining, salted leaves | local | M1 |
| 3 | Re-sign rewritten history with the current key | Forward-secure epoch ratchet in non-exportable custody | local + HSM | M2 |
| 4 | Truncate the record's tail | Externally remembered monotonic batch count | **external** | M3a |
| 5 | Erase events and renumber into a clean stream | Same — the count was countersigned before the deletion | **external** | M3a |
| 6 | Stop or patch the collector, then claim a quiet period | Signed heartbeats carrying the collector build digest | external | M4 |
| 7 | Weaken the anchoring policy, then tamper | Witness set and quorum recorded as chain events | external | M4 |

Classes 4 and 5 are the reason this is not a library. **A hash chain over a truncated prefix is
still internally valid** — whoever controls the file controls where it ends, and there is
nothing left to contradict. Detecting truncation requires an independent party that remembers
how many batches it has countersigned.

## Residual risk

What remains exposed after everything in 1.0 is built. Listed because a threat model that only
describes its successes is marketing.

**Omission.** The operator can decline to emit an event at all. A heartbeat gap shows that the
collector *stopped*; the build digest shows which build the collector **claims** to be running.
Neither makes selective suppression attributable: a patched collector that keeps heartbeating
under the original digest and silently drops one tool call leaves a correct-looking record, and
nothing here distinguishes that from a quiet period. The structural fix is bilateral receipts,
where the counterparty co-signs; that is 2.0 (`RM-01`), and until then the record rests partly on
the operator's word.

**Collector integrity.** The collector is open source and runs in the operator's environment, so
it can be patched, and **a patch is not reliably detectable**. A modified collector controls what
it reports and can emit the original digest while suppressing actions; a self-reported digest is
not remote attestation, and this release provides none.

What build provenance (`SEC-22`) does give: a digest that identifies the build the collector
*claims* to be running, traceable to a source commit, so an honest build is verifiable and a
misconfiguration is caught. What it does not give: any assurance that the process emitting the
digest is the artifact the digest names.

So the honest split — **stopping the collector produces a heartbeat gap and is detectable;
patching it to suppress individual calls is neither detectable nor attributable by this
mechanism.** Only remote attestation would change that, and `SCOPE-12` rejects the TEE claims
that would be required, for reasons that still hold.

**Forward secrecy depends on hardware.** The epoch ratchet only holds if the retired key is
genuinely destroyed, and key destruction is not externally verifiable. Without non-exportable
custody in an HSM or KMS, this class reopens (`SEC-17`).

**Full-quorum collusion.** If every configured witness colludes with the operator, external
anchoring provides nothing. Mitigated by configuration rather than by design: run `quorum: 2`
across parties with no common interest. The default includes a public log precisely so this is
hard by accident.

**Witness loss.** A witness that loses its store destroys the corroboration it exists to
provide. Addressed by published tree heads, replication and a stated recovery objective
(`FR-50`, `OPS-06`) — but a witness that vanishes entirely still weakens past records to the
strength of the remaining quorum.

**Metadata leakage.** An inclusion proof necessarily reveals the total count of recorded
actions, and anchor cadence leaks activity volume (`PRIV-07`, `PRIV-08`). You cannot
simultaneously claim "nobody knows how many actions I took" and "you can prove I deleted none."
The count is deliberately public.

**Clock integrity.** A countersignature is only as good as the clock behind it. The witness
derives time from a documented, traceable source and the verifier surfaces that discipline
(`SEC-25`), but a compromised time source undermines every timestamp it issued.

**Key exfiltration before first use.** If the signing key leaks before the first batch, every
record it ever produces is suspect. Out of scope: there is no cryptographic recovery from a
compromised root of trust, only a declared discontinuity after the fact (`SEC-24`).

## Explicitly out of scope

- An action the agent never attempted.
- A compromised model producing bad decisions. Splitstick records faithfully; it does not judge.
- A tool that lies about what it did. The record captures what the tool returned.
- Anything requiring Splitstick to block, gate, filter or approve in-line.

**This list is binding in both directions.** It bounds what the project claims, and it bounds
the bounty programme (`GOV-12`) — exclusions cannot be added after a report arrives. Changes
appear in the history below.

## Reporting a finding

A tamper the suite does not catch is the most valuable contribution to this project. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for how to add an attack class, and the Bounty terms in
the [release notes](splitstick-1.0-release-notes.md) for scope, the 90-day disclosure window,
and the commitment to publish findings **even when no mitigation exists**.

Novelty is judged by an arbiter who is not employed by the project (`GOV-15`). The project is
unfunded, so recognition is attribution and credit rather than cash, stated plainly rather than
implied.

## History

| Rev | Change |
|---|---|
| 1 | Extracted from the release notes into a standalone document, expanded with the residual-risk section and the attack-class-to-milestone mapping. |
