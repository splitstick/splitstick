# M7 follow-ups

What the launch gate left open, and why. Each entry says what would close it.

## The five that are open, and must stay open

M7's exit is explicit: *"NFR-01 has a qualifying acceptance measurement on the reference
environment and NFR-02 has been re-measured against a real provider; neither may be reported
as met on a development-machine number."* Inventory row 35 says the same thing from the other
side. So these are not oversights — reporting them as met is the thing this milestone exists
to prevent.

| | Why it is open | What closes it |
|---|---|---|
| **NFR-01** | the harness has good numbers and **none of them qualifies**. The development machine is short on load average, event count and repeats, and the harness says so in every run | one `bench/append.mjs` run over ≥1e6 events, ≥3 repeats, on a host meeting every constraint in `bench/reference-env.json`, with `--machine` and `--storage` named. It prints QUALIFYING ACCEPTANCE MEASUREMENT only when nothing is short, and that JSON is the evidence |
| **NFR-02** | **reverted from done in M7.** It was marked met against a scripted model at an assumed 400 ms per call. Both assumptions are recorded in the result and neither has met a real provider | re-run the interleaved paired A/B against a real provider and confirm the whole 95% interval still clears 2% at that model latency |
| **NFR-04** | carried since M5; the dev host disqualifies itself on load average alone | one `bench/verify.mjs` run on a qualifying host |
| **LEG-09** | the Witness Practice Statement is versioned and recorded; the **external-anchoring half** needs an operator's own witness set, which this project does not have | `npm run anchor-wps -- --config … --policy …` against a real witness set, which the tool already supports and says so when run with no arguments |
| **LEG-13** | configurable, plumbed and reported — and the verify is a **live** anchor against a qualified trust service, which is procurement rather than engineering | one live anchor; the adapter, the config path and the report are tested, including against a real RFC 3161 token |

**FR-15** is also open, from M6: the tlog adapter is anchored against a local instance across
four checkpoints, and interoperability with transparency-dev's Go binary is unverified. A
client and a server written against one reading of one document agree whether or not the
reading is right.

Every one of these is now *also* enforced by a check rather than a memory:
`tools/lint-figures.mjs` fails the build if a published figure cites an open requirement as
MEASURED.

## Found in M7, fixed in M7

The milestone is about what we must not say, and most of what it found was something already
said.

| What | The shape it had |
|---|---|
| the figures table published **<1 ms at p99** | that is NFR-01's *stretch* target, not its budget — M1 measured, revised the budget to p95 <1 ms and p99 <3 ms, and the table kept the number the project had hoped for. `bench/append.mjs`'s own header said it too, three lines above the code that disagreed |
| NFR-02 was marked **done** | against a scripted model, never a real provider. M7's exit forbids exactly that |
| a restore drill "that **proves** it" | DOC-11 wording: the drill establishes the software recovers; whether *your* store is replicated, and whether you ran it, is operator-declared and no pack can show it |
| Sigstore, Rekor, Trillian and Schneier–Kelsey were credited **nowhere** | DOC-06, in the README and the NOTICE. Attribution is nobody's job until it is a licence problem |
| the two-policy split was documented **nowhere** | DOC-07, and it is the thing the whole independence story rests on: the operator decides who is *asked*, the reader decides who is *accepted*, and conflating them is the commonest way to misread a pack |
| six documents cited statutes with **no disclaimer** | LEG-16. eIDAS, GDPR Art. 17 and 19, the AI Act, FRE 902 |
| the M6 test "the shipped default configuration names no witness at all" | checked the parser's behaviour for an absent key and took its title from a different artefact. The shipped default names two, by FR-48, deliberately |
| the shipped default's **egress** was undisclosed | `defaultWitnessWarning()` disclosed the capability gap and said nothing about reaching two public services |
| M6's inventory row 25 overstated OPS-05 | it read "the default must not egress", which contradicts a delivered requirement. A row that overstates its requirement is how a test comes to assert the wrong thing for a whole milestone |

### And four guards that could not fire, plus two that fired on honest prose

Written up in the commit for the claims audit, because they are the milestone's own central
risk landing on its own tooling. The short version: the strongest form of the integrity
overclaim is phrased in the negative, and the negation exemption meant to protect honest
refusals therefore handed it a pass **for being written the way such a claim is always
written**; the same for the TEE claim; `defeats 12 of 12` walked past a pattern that assumed
the word order; `immutable record kind` in a schema is not `immutable audit log` in marketing
copy. Then the enforcement lint looked for `Object.freeze([…])` where the source says
`new Set([…])`, found nothing, checked nothing, and **reported success**.

That last one is the one to remember. Three of M7's own guards had to be taught to fail when
they cannot locate their subject, because the default behaviour of a guard that cannot find
what it checks is to pass.

## Carried, still not accepted

The test suite leaks a temp directory per test — carried since M5, where roughly 62,000 of
them filled the development disk. Most tests `mkdtempSync` and never remove it. Still offered
as its own small change rather than folded into a milestone, because it touches almost every
test file and would bury whatever diff it travelled with.

## What a claims audit is not

`npm run claims` passing means **no guard fired**. It does not mean no overclaim exists, and
the pass message says so. Patterns over text cannot read intent, cannot see a claim phrased
in words nobody anticipated, and cannot tell whether a figure has a benchmark behind it —
only whether it says it does.

The register, the rejected-designs log and the five open requirements above are what carry
the rest, and they carry it by being read.
