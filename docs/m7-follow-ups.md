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

## Found in the M7 self-review — the audit could not see a real overclaim

The review probed the guards with sentences a marketer would actually write, and with
features in the shape they would actually arrive in. **Twenty out of twenty were missed.**
Every single one.

The twenty sentences are not reproduced here. They live in `REALISTIC` and `REALISTIC_TREE`
in [`test/scope-guards.test.mjs`](../test/scope-guards.test.mjs), which is where a corpus of
forbidden claims belongs: a file the audit exempts by design, so the record is kept without
the record itself tripping the guards. Quoting them into this document fired SEC-16 on the
third attempt, which is a small demonstration that the broadened guards work.

In outline, by guard: three integrity overclaims (SEC-16), two regulatory positioning lines
(LEG-14), two that certify the reader (LEG-15), one observability replacement (SCOPE-04), one
self-scored defeat claim (SCOPE-14), one enclave-as-guarantee (SCOPE-12), one that gates a
tool call (SCOPE-01), one unbenchmarked figure stated as measured (DOC-04) — and eight
feature additions in the shape they would arrive in, from an approval console to a wallet
transaction. Eight for eight on the tree guards.

The cause is the one worth carrying forward, because it is this milestone's own stated risk
landing on this milestone's own tooling. **The companion tests were written from the
patterns.** Each violating example was phrased to match a regex that had just been typed, so
the suite asked *does this pattern fire on text I wrote for it* rather than *does it catch
what somebody would actually write* — the second being the question
`docs/risk-assessment.md` already says a companion has to answer.

The guards passed. The audit was green. And an actual landing page would have shipped.

The correction is an ordering rule, now written into both files: **write the sentence a
marketer would write, then the regex.** The realistic corpus in
`test/scope-guards.test.mjs` is written in that voice, deliberately without looking at the
patterns, and the patterns are fitted to it. Both new companions fail against the pre-fix
guards.

The tree guards were the worse half, and for a structural reason: they are the *release
inventory*, where the question is not what we said but what we shipped — and a reviewer UI
does not announce itself by containing the string "reviewer UI". They now match on two
signals rather than one, identifiers and dependencies, because identifiers alone are
guessable and dependencies alone are evadable: a ZK proof needs a proving library, SSO needs
an OIDC or SAML client, a chain write needs a wallet or an RPC provider.

### And eleven false positives from the fix

Broadening produced the opposite failure immediately, which is the other half of the rule.
The new absolute pattern fired on "Nobody can prove they deleted a key", on "nothing here
changes that", and on the verifier's own "the signature could not be forged" — which is
**true**, and is the product's actual claim. A negative sentence containing an alteration
verb is not an integrity overclaim; a negative sentence saying the *record* cannot be altered
is exactly one, so the object now has to be the record.

`spec/witnesses.json` also tripped it by disclosing that an OpenTimestamps entry is public
and cannot be removed — a true statement about a third party's retention, and an FR-47
obligation.

## Found in the independent review — the exemptions floated free

The self-review fixed the patterns. The independent pass went at the **exemption mechanism**,
and found that an overclaim could wear an unrelated denial and walk through. **Nine of ten
crafted evasions got past the fixed guards.**

| Evasion | Why it passed |
|---|---|
| a positive claim after a negative hook | `No setup required: …`, `Never lose an action again: …`, `Splitstick is not slow, and …` — the denial is real, it is just about something else |
| a positive claim after an honest refusal | `Splitstick is tamper-evident, and your records are …` — `tamper-evident` is in `allows`, in a different clause |
| a claim after the word `rejected` or `Cut` | `Rejected alternatives aside, we ship …` — the rejected-design exemption, borrowed |

Both `negationExempt` and `allows` read the **whole sentence**, with no relationship to the
forbidden phrase. Marketing copy pairs a negative hook with a positive claim as a matter of
course, so in the real world the exemption was nearly always available. The realistic corpus
from the self-review did not catch this because those sentences were realistic in
*vocabulary* and not in *construction* — which is the same lesson one level further in.

**An exemption now has to be attached to the thing it exempts**: the denial must be in the
clause the match sits in. "tamper-evident, not tamper-proof" and "we do not claim an
immutable audit log" keep the denial beside the phrase, which is what makes them honest
rather than merely adjacent to something honest. The clause break is punctuation only —
splitting on `and` broke "considered **and** rejected", where the exemption is the second
half of a fixed phrase about the subject. All ten evasions are now caught, the corpus is kept
permanently, and both companions fail against the pre-fix guards.

### The same shape, three more times

| Where | What the exemption let through |
|---|---|
| `lint-assurance.mjs` | a bare `only` anywhere exempted a guarantee: *"It guarantees completeness, and only takes a second"*. Narrowed to `only under`, `only when`, `proves only` and their kin |
| `lint-assurance.mjs` | a bare `no` exempted *"It ensures **no** tool call escapes the record"* — a guarantee phrased in the negative, which is exactly what SEC-16's `absolute` slot exists for. The one negation form that IS a qualification is the negation of the assurance verb itself: `does not prove`, `cannot establish` |
| `lint-assurance.mjs` | it had **no companion test at all** — probed by hand in M7 and then trusted. `test/assurance.test.mjs` now exists, and it found the second row above |

And a shared-helper bug that had been hiding findings from every lint at once: the sentence
splitter did not break after markdown emphasis, so `…(NFR-09).** The KMS half is…` made a
whole paragraph into one unit and the assurance lint's per-sentence check landed on text it
was not about. Fixing it surfaced two further false positives immediately — both honest limit
statements the check had simply never been able to see.

### Two false positives worth keeping as cases

Tightening produced the opposite failure, which is always the other half:

- `docs/threat-model.md`'s *"EU AI Act Article 12 asks for tamper-evident records, not
  impossible ones"* fired LEG-14. Naming what a statute requires is how you write honestly
  about it, so the guard narrowed to product *positioning* and dropped `Article \d+` and
  `requirements` from its triggers.
- `spec/witnesses.json` fired SEC-16 by disclosing that an OpenTimestamps entry is public and
  cannot be removed. That file is a catalogue of **other people's** terms, and reading a JSON
  value about somebody else's log as a claim about this product is a category error. It is
  exempted from the prose guards and governed instead by `parseWitnessList`, which checks it
  far more precisely: no field expressing preference, every capability class validated, every
  entry required to state its position.

## Found in PR #12 review, fixed in M7

**The HTTP enforcement guard covered only the response leg.** It checked that the agent gets
the upstream's answer before anything is recorded, and said nothing about the way *in*: a
change that recorded before calling the upstream would have put a recording outcome between
the agent and its tool on the outbound path — an availability dependency of exactly the kind
SCOPE-01 forbids — and would have passed the lint. Correct in the implementation today
(`fetchImpl` at line 207, the first `pairing.request` at 228), simply unguarded.

Both halves now exist. The structural guard checks a region that *ends* at the first recording
call, so the test is whether the forward sits inside it — if recording moves earlier the
region shortens and the forward falls out. And a behavioural test captures the invariant **at
the moment of forwarding**: with a recorder that burns 40 ms and then throws, nothing may have
been recorded at the instant the request left. Asserting afterwards would only report the
final order; asserting there names what broke.

Both fail against a source reordered to record first.

### A note on this document's own exemption

`tools/lint-scope.mjs` exempts this file, and only this file among the follow-ups. Explaining
which overclaims the guards missed requires naming the shapes, and three successive
rewordings each made the account worse while still firing. Exempting it is a real reduction
in coverage, taken deliberately: it is one file rather than a class, `m1` through `m6` stay
audited and pass, and nothing here is a product claim — it is an account of what the audit
could not see.

The alternative was to keep the file clean and the record vague. For a milestone about not
saying things that are not so, the vague record was the worse option.

## NFR-04 was not a measurement gap — it was a quadratic verifier

Recorded here because the follow-up said "needs one run on a qualifying host" and that was
wrong. Asked for the number, the benchmark gave **76 s median against a 2 s budget** at
100,000 records — 38× over, which no machine explains. Doubling the records cost ~2.2–2.45×,
so the cost was super-linear and a faster host could not fix it.

Two causes, both found by measurement rather than reading:

**The consistency proof was O(checkpoints · n).** `verify.mjs` generated a proof per
consecutive checkpoint pair, each over a fresh `leaves.slice(0, size)`. Isolated on the real
data its cost quadrupled with every doubling of the log and accounted for most of the run.
The irony is exact: `prefixRoots` was added in M5 to kill this shape for tree ROOTS, it works
(the naive version it replaced is 20× slower at 40k), and the same file kept doing it for
PROOFS one loop further down. The comment above `rootsFor` even predicted the figure.

The proof is now skipped when both signed roots already equal the local prefix roots at their
sizes — an identity, not an optimism: a shorter prefix of one leaf array is a prefix of a
longer prefix of the same array, for every pair, always. Where a root does not match locally
the proof still runs, so `CONSISTENCY_BROKEN` is still reported, and a test pins the fork case
to require **both** that code and `TREE_MISMATCH` rather than either. Those tests pass against
the pre-fix source too, which is the point of them.

**`ContentStore.has()` stat'd the blob on every call.** `existsSync` + `statSync` against one
unchanging path, twice per commitment — about 200,000 pairs of syscalls at 100,000 records,
and 20–29% of total verification time. It now reads `#end`, the length this instance already
tracks. That is not only cheaper but more coherent: the key map is a point-in-time snapshot
taken at first read, so a live file size paired a cached key journal with a blob that had
grown underneath it.

**Result: 76 s → 15.8 s median**, on a host with load average 5.7 that still does not qualify.
Still over the 2 s budget, now by ~8× rather than 38×, and the read floor alone is 1.2 s of it.

**NFR-04 stays open, and its budget is now the open question** rather than its implementation.
Three honest outcomes remain: it passes on a qualifying host; or it lands at a few seconds and
the budget should be revised with the measurement behind it, as M1 revised NFR-01's; or large
logs need a different verification shape — streaming, or not reproducing every payload by
default, since an auditor checking the chain does not need every plaintext.

A small thing worth recording: the first draft of the fix's own comment stated those figures
as fact and **the claims audit refused it**, because they come from a machine the harness
reports as a regression metric. M7's guard caught M7's author on new content, which is the
first evidence it works on something it was not fitted to.
## A flake that cost a pull request, and the evidence that was lost

`a lock left by a dead process does not wedge the witness` failed once on Node 20 in a run of
an unrelated pull request, and passed on re-run with no change — which is what a flake is, by
definition. The evidence was gone by then: the obvious next move is to press re-run, and a
green re-run leaves nothing to read.

Measured rate before the fix: one failure in five isolated runs on Node 20, then none in
twelve, then none in ten at load average 107. Rare, and not load-sensitive in the way M6's
write-lock flake was — so a reproduction could not be relied on to confirm the diagnosis.
It was read out of the code instead.

**The assertion was a timing-dependent proxy for liveness.** The requirement is that a lock
left by a dead process must not wedge the witness. The test asserted that exactly one of two
racing processes is accepted — and both processes have to notice the dead lock and break it,
so two that break it at the same instant can each then see the *other's* fresh lock and back
off. `accepted` is legitimately 0 there, a real client would retry, and the witness is not
wedged at all.

Safety and liveness are now asserted separately, on their own terms:

- **Safety**, which never bends: at most one of two conflicting successors is accepted, and
  the witness retains one root at that height. This is *stronger* than the old `=== 1` — and
  it still catches a real lock-breaking bug, verified by disabling exclusion entirely, where
  four of the file's five tests fail.
- **Liveness**, asked directly rather than inferred: if the race left nobody accepted, a lone
  submission afterwards must succeed. A stale lock that wedged the witness would refuse that
  too, forever.
- And a new deterministic case — a stale lock is **broken**, not merely survived — because a
  single submission against a stale lock has no race in it, and the recovery must not be
  single-use.

37 runs after the fix (25 isolated, 12 at load average 135): zero failures.

**The second half of the problem was that the evidence vanished.** `ci.yml` now tees each
unit run to a file, prints the failing assertions in a collapsed group in the step that
failed, and uploads the log as an artifact kept for thirty days. The summary comes before the
artifact deliberately: what was actually needed was something a reader could see without
downloading anything.

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
