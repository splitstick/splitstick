# Reconciliation against counterparty records

**Covers:** DOC-09 · **Related:** DES-19, SEC-09, SEC-10, AC-4, AC-5, FR-54

This document describes a **procedure an auditor performs**. It is not a
guarantee the software makes, and nothing in Splitstick enforces or verifies it.
It is written down because it is the only thing that reaches a particular class
of tampering, and an operator or auditor who does not know it exists will
conclude that class is simply undetectable.

## The problem it addresses

An operator who erases an action entirely — removes the record, renumbers both
counters, repairs the chain, re-signs the checkpoint — leaves a log that is
internally perfect. There is nothing in it to find, because the thing that would
contradict it is not in it. The same is true of a truncated tail above the last
anchored height.

Cryptography does not reach this. The red-team suite says so explicitly: attacks
C2, D and F3 are UNDETECTED from the files alone, and the reason is not a
weakness in the construction but the shape of the problem. A log is a statement
by one party. A statement by one party cannot be contradicted by itself.

## What reconciliation is

Every consequential action an agent takes touches something outside the log. A
payment appears on a bank statement. An email appears in a recipient's mailbox.
A ticket appears in a tracker. A counterparty has their own record of the same
event, kept for their own reasons, under their own control.

Reconciliation is comparing those two sets:

1. Take a window — a day, a week — and the set of consequential records in the
   log for it.
2. Take the counterparty's record of the same window.
3. For each event in the counterparty's set, find the corresponding record.
4. **An event the counterparty has and the log does not is the finding.**

The asymmetry is the whole method. The operator controls the log and not the
counterparty's records, so an omission shows up as something present on the
other side with nothing to match it.

## Its limits, stated plainly

**It requires access to the counterparty.** An internal auditor can usually get
a bank statement and sometimes a partner's records. A third party reading an
evidence pack after the fact generally cannot get either, which means
reconciliation is available to the operator's own audit function and mostly not
to the people the evidence is for. That is a real limit and not a procedural
inconvenience.

**It is a procedure, with a procedure's failure modes.** It can be done badly,
not at all, or by someone with an interest in the result. Nothing produces a
verifiable artefact from having done it. A reconciliation nobody performed looks
exactly like one that found nothing.

**Its coverage is only as good as the counterparty's completeness.** An action
with no external trace — a read, an internal computation, a tool call that
failed before it reached anything — has no counterparty record to reconcile
against. Reconciliation reaches consequential actions with external effects,
which is a meaningful subset and not the whole log.

**It is retrospective.** It finds an omission after the fact, not at the moment
of writing. A stateful witness (FR-17) refuses a rewritten history at
submission; reconciliation discovers one later. Later is better than never and
worse than refused.

**It does not establish WHEN.** It establishes that an event is missing. The
operator can say the record was lost rather than removed, and nothing in the
reconciliation distinguishes a removal from a gap the collector should have
declared and did not.

## The cheaper mechanism, and how it differs

**Cross-pack comparison** (FR-54, SEC-26) is the mechanical half of the same
idea and the software does implement it. A pack disclosed to a counterparty
contains a countersigned checkpoint at some height. The operator cannot
un-disclose it. If a later pack from the same log ends below that height, or
presents a different root at it, the verifier emits
`TRUNCATED_BELOW_DISCLOSED` or `TREE_MISMATCH` — and that comparison needs no
access to the counterparty's own systems, only to a pack they were already
given.

So the order of preference is:

| Mechanism | Reaches | Needs | Who can do it |
|---|---|---|---|
| Stateful witness (FR-17) | truncation and erasure, at submission | a second party, once | anyone verifying |
| Enumerable log (FR-14) | the same, retrospectively | a second party, once | anyone verifying |
| Cross-pack comparison (FR-54) | truncation below a disclosed height | a pack already handed out | anyone holding two packs |
| Reconciliation (this document) | omission of externally-visible actions | access to the counterparty | the operator's auditor |

Reconciliation is last because it is the most expensive and the least
verifiable. It is in the list because when the first three are unavailable it is
what remains, and because an auditor who knows the first three exist should
configure one rather than resort to this.

## What to tell an auditor

If you are being asked to rely on a Splitstick evidence pack, the verification
report tells you which of the mechanisms above were in play. Read its capability
statement: it names the height below which truncation is detectable, says
whether any witness in the set maintains sequence state, and says plainly when
none does. If it says none does, the honest position is that omission is not
excluded by the evidence, and reconciliation is the procedure that would narrow
it — performed by you, on records the operator does not control.
