# DES-18 — Witness practice statement structure

**Milestone:** M3b · **Covers:** LEG-01 … LEG-09, LEG-19, OPS-03, OPS-05

## Decision

Certificate authorities publish a Certification Practice Statement because **an attestation whose
meaning is vague is worth nothing, and an unbounded one is a liability nobody should accept.**
A witness needs the equivalent, and it must be deliberately narrow.

For 1.0 this is **self-authored**, not counsel-reviewed — the project is unfunded, and LEG-01's
verification says so. Counsel review is deferred to a funded release. That is stated in the
document itself rather than left for a reader to discover.

## Structure

```
1  Scope and identity         which witness, which origin, which keys
2  What a countersignature asserts          LEG-02, LEG-03, LEG-04
3  What it does not assert                  LEG-05 … LEG-08
4  Time discipline                          LEG-19, SEC-25
5  Key management and rotation              FR-51
6  Retention and recovery objective         OPS-06
7  Limitation of warranty                   (funded release: LEG-10)
8  Version history, and where it is anchored  LEG-09
```

### Section 2 — asserts

- This root was **received** at this time, per the clock described in section 4.
- It is the **immediate successor** of the previous root recorded for this enrolled operator.
- It has been **retained** in the witness's own append-only store.

### Section 3 — does not assert

- That the underlying actions **occurred**.
- That the recorded content is **true**.
- That the operator **captured everything** — coverage attestation (DES-10) addresses that,
  separately and with its own stated limits.
- That any action was **lawful or authorised**.

A witness attests receipt and ordering. It is not an auditor, not a guarantor of the operator's
records, and not a certifier of anyone's compliance.

### Section 4 — time discipline, LEG-19

Names the time source and its bounds, because a countersignature is only as good as the clock
behind it. For an RFC 3161 TSA this cites the TSA's own statement. For a self-hosted witness it is
the operator's to declare. Either way the verifier prints it (DES-07) so a reader never has to
assume NTP.

### Section 8 — versioned and anchored, LEG-09

The statement's own digest is submitted for countersignature like any other root. A practice
statement that can be quietly narrowed after an inconvenient finding is not a commitment, and the
same logic applies here as to the threat model's out-of-scope list.

## OPS-03, OPS-05 — the deployment guides

Two companion documents, because the statement describes *a* witness and most operators will run
their own:

**OPS-03 — running a witness under internal audit.** The two-halves-of-a-tally pattern inside one
organisation: internal audit holds the witness key, engineering holds the signing key, neither can
rewrite history alone. This is ordinary separation of duties, a control these organisations
already operate and already have an owner for — which is why it is an easier sell than it sounds.

**OPS-05 — zero-egress deployment.** How to run with no account, no enrolment with the project,
and no traffic leaving the perimeter. Verified by capturing all egress and finding nothing.

## Consequences

- Self-authored means the liability sections are thin, and the document says plainly that it has
  had no legal review. Overstating the standing of an unreviewed statement would be the exact
  failure this project warns about elsewhere.
- Sections 6 and 7 only bind a witness we operate. For 1.0 we operate none, so they describe the
  reference implementation's expectations of whoever runs it.
