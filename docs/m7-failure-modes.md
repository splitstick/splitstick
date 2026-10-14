# M7 failure modes — the launch gate

Enumerated before any code, as in every milestone since M2. `risk` is 1–10, `bdy` says
whether the failure crosses a trust boundary (in/out), `adv` marks the ones an adversary
chooses rather than stumbles into.

M7 is not a feature milestone. Its goal is *every promise that is a claim rather than a
feature*, and it is **mostly about what we must not say**. Sixteen scope guards, four legal
constraints and a claims audit — thirty-seven requirements whose stated verify is, over and
over, "claims audit", "documentation review", "positioning review", "release inventory".

## The central risk: the audit is itself a claim

Every requirement here wants a review turned into a check, because a review is a thing
somebody skips. But a check that passes because its patterns are too narrow is strictly worse
than the review it replaced: the build goes green, the release ships, and nobody looks again.
That is *an instrument reporting a conclusion it had not established* — the defect this
project has shipped at least five times, and M7 is the milestone where it would do the most
damage, because the thing being asserted is "we have not overclaimed".

So every guard in this milestone is written with a companion that **breaks it on purpose**.
Not a sample of them. Each one, individually, against text that violates exactly that guard
and text that must not fire. This is the row-16 lesson from M6's conformance suite — a suite
nothing can fail certifies nothing — applied to the thing certifying our own honesty.

Precedent, all from this project: the LEG-12 splitter cut the eIDAS article reference in half, so the
rule could never fire on the sentence it existed to catch; the OPS-05 static check missed
`await import('node:net')` and `globalThis.fetch(…)`; `C1` counted signatures instead of
checking whose they were; the GOV-09 field check was a denylist of words that had not
anticipated `sponsored`.

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 1 | a guard's pattern matches nothing it should | its companion test fails. Every guard is exercised against a violation and against honest prose | 9 | out | ✓ |
| 2 | a guard fires on honest prose | its companion test fails too. A guard that cries wolf gets switched off, and then it guards nothing | 7 | out | |
| 3 | a new claim surface is added (a package description, a new doc) | it is audited. The surface list is derived, not enumerated by hand | 6 | out | ✓ |
| 4 | the audit is run and passes | that is reported as "no guard fired", never as "no overclaim exists". The audit reads text; it cannot read intent | 8 | out | |

## Already found, before writing anything — M6 said something that was not so

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 5 | the M6 test named "the shipped default configuration names no witness at all" is read | it is WRONG about the artefact it names. It parses a config that omits `witnesses:` and asserts the parser invents none — a true and useful property, under a title claiming something else. The shipped default is `design/default-config.yaml` and it names two | 8 | out | ✓ |
| 6 | the shipped default is used by somebody who did not read the docs | it reaches two public third-party services. That is FR-48 BY DESIGN — a default the project neither operates nor overloads — but nothing discloses the egress, and `defaultWitnessWarning()` discloses only the capability gap | 7 | out | ✓ |
| 7 | M6's inventory row 25 is read against OPS-05 | row 25 overstated it. OPS-05 is "support and verify a deployment with no traffic leaving the perimeter", which a configurable default satisfies; "the default must not egress" was a stronger rule nobody had agreed, and it conflicts with FR-48 | 6 | out | |

## The sixteen scope guards — SCOPE-01 to SCOPE-16, LEG-14 to LEG-16, SEC-16

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 8 | any surface says "tamper-proof" | the audit fails. SCOPE-02 and SEC-16: the claim is tamper-EVIDENT with attribution, and the difference is the whole product | 9 | out | ✓ |
| 9 | a surface says "tamper-proof" inside a sentence refusing the claim | it passes. The refusal is the correct way to use the phrase and the guard must not punish it | 7 | out | |
| 10 | any surface claims EU AI Act conformity | the audit fails (LEG-14). Conformity is assessed by a body, not asserted by a vendor | 9 | out | ✓ |
| 11 | any surface certifies the customer's compliance | the audit fails (LEG-15, SCOPE-03). We produce evidence; a conclusion about their obligations is theirs and their counsel's | 9 | out | ✓ |
| 12 | a statute is cited without a not-legal-advice disclaimer nearby | the audit fails (LEG-16). Nearby means the same section, not a page away — the SEC-17 lesson | 6 | out | |
| 13 | a surface positions this as a replacement for traces, SIEM or dashboards | the audit fails (SCOPE-04). It is an evidence recorder; an observability claim invites an operator to stop keeping the thing they actually need | 5 | out | |
| 14 | a surface publishes an N-of-N attacks-defeated score | the audit fails (SCOPE-14). A self-scored defeat metric is marketing wearing a benchmark's clothes, and the redteam suite's own output says which classes are NOT closed | 8 | out | ✓ |
| 15 | a surface claims a TEE makes suppression impossible | the audit fails (SCOPE-12). A TEE does not make a collector report what it never observed | 8 | out | ✓ |
| 16 | the OSS tree acquires a reviewer UI, SSO, RBAC, multi-tenancy or retention tiers | the release inventory fails (SCOPE-05 to SCOPE-09). These are checked in the TREE, not in prose: a review of what is shipped is a review somebody skips | 6 | out | |
| 17 | a VDF, or a ZK compliance proof, enters the tree or the roadmap | it fails (SCOPE-10, SCOPE-11). SCOPE-11 covers the ROADMAP too, which means the check must read the roadmap | 5 | out | |
| 18 | a blockchain becomes the primary ledger | it fails (SCOPE-13). A public chain is permitted only as the optional hard anchor, which is what the OpenTimestamps tier already is | 6 | out | |
| 19 | any configuration, flag or build makes the collector block a run | it fails (SCOPE-01, SCOPE-16). Fail-open is a design constraint and not a setting, so what is checked is that no enforcement path EXISTS — not that the default is off | 10 | out | ✓ |
| 20 | a future contributor adds `on_unavailable: block` | the config schema refuses it and a test asserts the refusal. SCOPE-16 names config schema review explicitly | 9 | in | ✓ |

## DOC-11 — every assurance claim names its evidence

This is the deepest requirement in the milestone, and its own statement says why: *the design
repeatedly acquired guarantees its own threat model excludes.*

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 21 | an assurance claim is made with no evidence class | the audit fails. Each claim is independent, operator-declared, or none — and the third is a legitimate answer stated plainly | 9 | out | ✓ |
| 22 | a claim rests only on the operator-controlled collector | it is worded as an ASSERTION, never as a verified guarantee. This is the exact shape of PR #8's finding 15, PR #9's P1 and M6's C1: presence counted as proof | 10 | out | ✓ |
| 23 | the register and the prose disagree | the audit fails. A register nothing checks against the text is a second document to keep in step, which is a document that drifts | 7 | out | |
| 24 | a claim is added to the prose and not to the register | the audit fails. Additive drift is the direction a launch gate actually leaks | 8 | out | ✓ |

## Benchmarks behind figures — TRC-04, DOC-04

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 25 | a performance figure is published with no benchmark behind it | the release gate blocks (TRC-04). Every published figure names the benchmark that produces it | 8 | out | ✓ |
| 26 | a figure's benchmark exists but has never produced a qualifying run | it is labelled a TARGET, not a measurement (DOC-04). NFR-01, NFR-02 and NFR-04 are all in this state today | 9 | out | ✓ |
| 27 | a figure from a development machine is reported as met | the harness already refuses this, and the audit must refuse it in the PROSE too. A number in a README has no reference-environment check behind it | 9 | out | ✓ |

## The bounty — GOV-10 to GOV-14, GOV-17, GOV-18, SEC-19 to SEC-21, DOC-08

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 28 | the bounty offer goes live before the terms | DOC-08 fails. The terms are published alongside the offer, not after the first report | 7 | out | |
| 29 | a reporter reads the terms expecting money | they are told plainly that recognition is non-cash while the project is unfunded (GOV-13, GOV-17), with no figure advertised as available | 8 | out | ✓ |
| 30 | an exclusion is added after a report arrives | the terms forbid it and the threat model carries a change log (GOV-12). Scope binds both ways or it binds nobody | 9 | out | ✓ |
| 31 | two reports describe one tamper class | one award, to the first complete report (GOV-10, GOV-14), with timestamps retained | 4 | out | |
| 32 | a finding needs a configuration nobody ships to reproduce | it is out of scope (GOV-11), and the shipped default is documented and PINNED so "the default" is not a moving target | 6 | out | ✓ |
| 33 | a finding has no mitigation | it is published anyway (SEC-21), within 90 days or on fix, whichever is sooner (SEC-20) | 8 | out | |
| 34 | the contributed-attack-class path is referenced in a release gate | GOV-18 fails. It is explicitly a goal and NOT a launch gate, and writing it into a gate would block a release on other people's volunteer work | 3 | out | |

## The carries — what must not be claimed as met

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 35 | NFR-01, NFR-02 or NFR-04 is marked done | it must not be. None has a qualifying run; the development machine reports itself a regression metric, and M7's exit says plainly that neither may be reported as met on a development-machine number | 10 | out | ✓ |
| 36 | NFR-09 is left ambiguous | it must not be. The carry names two options and forbids a third: either a real HSM attestation through FR-70's five checks, or the published text NARROWED to what the KMS half supports. The second is available now and is the honest action | 8 | out | ✓ |
| 37 | FR-15 or LEG-13 is marked done | it must not be. Interop with the Go witness is unverified and the qualified-TSA anchor has not been run; both are recorded as open in M6's follow-ups | 7 | out | ✓ |
