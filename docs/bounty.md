# The tamper bounty

Published alongside the offer, not after the first report — DOC-08. A bounty with no
boundaries is not a commitment, it is an open tab.

**Recognition, not cash, while the project is unfunded.** No figure is advertised as
available, because none is held. Read that first (GOV-13, GOV-17); everything else here is
mechanics.

## Terms

| Term | |
|---|---|
| **One class, one payout** (GOV-10) | The unit is a **tamper class**, not an instance. Twelve variations on truncation are one finding. We would rather recognise a new idea well than the same one repeatedly. |
| **Default configuration** (GOV-11) | The attack must survive the shipped default, pinned below. A tamper that only works once the operator has weakened their own policy is already a recorded chain event, by design. |
| **The threat model is the scope** (GOV-12) | [docs/threat-model.md](threat-model.md) binds the programme in **both** directions. We do not get to add exclusions after a report arrives; the change log at the foot of that document is how you can tell. |
| **Recognition, not cash** (GOV-13, GOV-17) | A novel class earns attribution, credit in the suite and a named finding. A cash award opens only if the project is funded. We would rather say that than advertise money we do not hold. |
| **First reporter wins** (GOV-14) | The first **complete** report takes the award. Receipt timestamps are retained for every report so the order is a fact rather than a recollection. |
| **90 days or on fix** (SEC-20) | Coordinated disclosure after 90 days or on fix, whichever is sooner, tracked per report. |
| **Published even unmitigated** (SEC-21) | We publish the finding either way, including when we have no mitigation. A finding withheld because it is embarrassing is a finding the next operator meets alone. |
| **Nothing is withheld, so nothing is judged** | Every reported finding is published and every reporter credited, whether or not we consider the class novel. We cannot be both the payer and the judge of a security claim and keep the credibility we are paying for — so while recognition is the award, we remove the judgement rather than outsource it. An independent arbiter becomes necessary the day a cash award does. |

## The shipped default, pinned

GOV-11 is only meaningful if "the default" is not a moving target. The configuration an
attack must survive is [`design/default-config.yaml`](../design/default-config.yaml) at:

```
sha256:158276c64667f544d927325b410ac5fa5458298e0a4f58652ebf2592b88f43fd
```

`tools/lint-bounty.mjs` fails the build when the file changes without this digest changing
with it. If the default moves, reports already in flight are judged against the digest
current when they were received — which is why receipt timestamps are retained.

## Intake and triage — SEC-19

| Step | What happens |
|---|---|
| **Intake** | A report arrives as a GitHub security advisory on the repository, or by email to the address in [SECURITY.md](../SECURITY.md). Receipt is acknowledged within five working days, with the received-at timestamp that fixes the first-reporter order. |
| **Completeness** | A report is **complete** when it names the tamper class, the configuration it survives, and a reproduction a reader can run. An incomplete report is not refused — we say what is missing and the clock for first-reporter order keeps the original receipt time. |
| **Triage** | Reproduced against the pinned default. The outcome is one of: a new class, an instance of a class already in the suite, out of scope under the threat model, or not reproducible. Each is recorded with the reasoning, and the reasoning is published with the finding. |
| **Disclosure** | 90 days from receipt, or on fix, whichever is sooner (SEC-20). Published either way (SEC-21). |
| **Recognition** | Attribution in the finding, credit in `redteam/`, and the class named after the reporter if they want it. No cash while unfunded (GOV-13, GOV-17). |
| **Payment** | There is no payment process, because there is no money. If the project is funded, a cash award and an independent arbiter arrive together — the arbiter is not optional once we are the payer. |

### Exercised before launch

SEC-19's verify asks that the process be exercised once before launch, not merely written.
It has been, against this project's own findings rather than a hypothetical: the two P1
findings from the review of PR #11 were taken through intake, completeness, triage and
publication as though they had arrived from outside.

- **Intake and completeness.** Both arrived with a class, a configuration and a reproduction.
- **Triage.** Both reproduced against the shipped default. Classified: a duplicate JSON-RPC id
  erasing an observed invocation, and unanswered calls living only in memory until shutdown.
- **Disclosure.** Published on fix, which was sooner than 90 days, in
  [docs/m6-follow-ups.md](m6-follow-ups.md) — including the part with no mitigation: a
  `SIGKILL` between a request and the next sweep still loses the pending call, and that is
  recorded as an open limitation rather than closed by wording.
- **Recognition.** Both findings are attributed in the commit that fixed them.

What the exercise showed, which is the reason for running one: the hardest step is not
triage, it is **publishing the unmitigated remainder**. Both findings had a residue that no
fix removed, and the temptation was to describe the fix and let the residue go unmentioned.
SEC-21 exists for precisely that temptation.

## Contributed attack classes — GOV-18

Anyone may contribute an attack class to [`redteam/`](../redteam) by pull request, with
attribution, whether or not it is novel and whether or not it currently succeeds. A class
that fails against the shipped default is still worth having: it is a regression canary, and
`npm run redteam:splitstick` reports which gates hold and which do not.

**This path is explicitly a goal and not a launch gate**, and nothing in any release gate
references it. Blocking a release on other people's volunteer work would be a gate we do not
control and they did not agree to. `tools/lint-bounty.mjs` asserts that no release gate
mentions it, because the natural drift is for a good contribution path to become a
requirement somebody has to satisfy.

## Not legal advice

This document and the threat model describe engineering properties and cite statutes for
orientation. Nothing here is legal advice, no conclusion about your obligations is offered,
and nothing certifies your compliance with anything (LEG-15, LEG-16, SCOPE-03).
