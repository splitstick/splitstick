# Non-engineering work

74 of the 187 requirements (40%) complete only when a human who is not writing code
does something. This document groups them into the workstreams they actually represent,
because the raw count badly overstates the effort: ten of them are one document, and
twenty-two are one recurring audit.

Cost and lead-time figures are rough order-of-magnitude estimates for planning, not quotes.
Verify each before budgeting. Nothing here is legal advice.

## Summary

| Workstream | Reqs | Who | Lead time | Rough cost | Feasibility |
|---|---:|---|---|---|---|
| 1. Trademark clearance and filing | 1 | IP attorney | 1 wk search · 4–12 mo registration | €1–3k per jurisdiction | Straightforward |
| 2. Certification mark structure | 1 | IP attorney | 1–2 mo to decide | €2–5k advice | **Structural problem — see below** |
| 3. Witness Practice Statement | 10 | Specialist counsel | 4–8 wks | €5–15k adapting a published CPS | Feasible |
| 4. Limitation of warranty / terms | 1 | Commercial counsel | 2–4 wks | €2–5k | Straightforward |
| 5. US evidence certification template | 1 | US litigation counsel | 2–4 wks | €2–5k | Straightforward |
| 6. EU eIDAS positioning docs | 1 | EU counsel | 2–4 wks | €2–5k | Straightforward |
| 7. eIDAS qualified status | 1 | Accredited CAB + supervisory body | **9–18 months** | **€50–150k + annual** | **Not feasible unfunded** |
| 8. Claims policy and per-release audit | 22 | You | 1 wk to write · recurring | — | Feasible, needs discipline |
| 9. Threat model document | 4 | You | 1 wk | — | Feasible |
| 10. Bounty programme | 9 | You + finance | 2 wks | **€50k/yr exposure** | **Defer the cash — see below** |
| 11. Witness list and mark governance | 4 | You | 1 wk | — | Feasible |
| 12. Contributor governance (DCO, CONTRIBUTING) | 2 | You | 3 days | — | Feasible |
| 13. External arbiter | 1 | Relationship | 1–3 months | Honorarium | **Depends on network** |
| 14. External attack contribution | 1 | Community | **Unschedulable** | — | **Make it a soft gate** |
| 15. Documentation set | 13 | You | 2–3 wks | — | Feasible |
| 16. GDPR erasure review | 1 | DPO / privacy counsel | 2–4 wks | €3–8k | Residual risk remains |
| 17. Commercial SLA | 1 | Commercial counsel | — | €2–5k | Deferred to commercial |

Rough total excluding accreditation: **€20–50k of professional services** and about
**8–12 weeks of your own writing and process work**, spread across the project.

With accreditation: **€70–200k and 9–18 months.**

## The four findings that matter

### GOV-07 as written has a legal conflict

The strategy is "give the code away, control the badge." The badge is `GOV-07`, a
certification mark. But in both the US and the EU, the owner of a certification mark
generally **may not itself supply the goods or services being certified** — in the US that
is a ground for cancellation, and the EU certification mark carries an equivalent
restriction.

So Tally the company cannot sell Tally and also own "Tally" as the certification mark for
conformant witnesses. Options, in descending order of how much they preserve the strategy:

1. **A separate mark held by a neutral entity** — a foundation or association that does not
   trade in the certified service. Cleanest, slowest, and the usual answer for a
   standards programme.
2. **An ordinary trademark plus a contractual conformance programme.** You license use of a
   "conformant" logo under published, non-discriminatory terms. This is what most software
   conformance programmes actually do, and it avoids the certification-mark restriction
   entirely.
3. Drop the mark and rely on the open conformance suite alone — weakest, because anyone can
   then claim conformance without passing.

Option 2 is probably right for 1.0 and costs almost nothing. Decide before filing anything,
because the filing strategy differs.

### LEG-17 is the project's largest non-engineering risk

Qualified trust service provider status requires a conformity assessment by an accredited
body against the relevant ETSI standards, notification to a national supervisory body,
mandatory liability insurance, documented and audited practices, and annual re-assessment.

It is also the thing that makes the commercial moat real: `LEG-12` states plainly that the
eIDAS Art. 41 presumption attaches to qualified providers and to nobody else, which is
exactly why a weekend competitor cannot cross it.

Both facts are true at once. It is a funded-company activity, not a pre-revenue one. The
sequencing that follows: ship 1.0 without it, sell on the open architecture and the
pluggable qualified-TSA slot (`LEG-13`, which lets a customer bring their own qualified
authority and get the presumption without us), and pursue accreditation only once revenue
or investment justifies it.

### The €50,000 bounty cap is an unfunded liability

`GOV-13` commits to EUR 50,000 per year and `GOV-17` to EUR 5,000 per class. A pre-revenue
project cannot underwrite that, and a bounty you cannot pay is worse than no bounty.

Three honest alternatives: lower the figures until funded (EUR 500–1,000 per class, EUR
5,000 annual cap) and raise them publicly later; make recognition non-cash at first
(attribution, credit in the suite, a named finding) and say so plainly; or hold the cash
offer until a funding event and ship 1.0 with the terms published but the programme marked
as opening on a stated date. Any of the three is defensible. Promising money you do not have
is not.

### GOV-18 cannot be scheduled

"At least one external attack class merged before launch" depends on strangers choosing to
contribute. Keep it as a goal, remove it as a launch gate, or launch is hostage to community
uptake you do not control.

## Scheduling consequence

35 of the 74 sit in M7, which is currently estimated at two weeks. That estimate is wrong:
M7 is gated by counsel turnaround and audit discipline, not by effort. Either re-estimate M7
at 4–6 weeks, or pull every counsel-dependent item into M0 and leave M7 as the audit pass
only. The second is better, and `LEG-10` and `LEG-11` are already in M0 for this reason.
