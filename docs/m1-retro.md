# M1 retrospective

M1 shipped: 29 requirements, 13 design elements, attack classes AC-1 and AC-2
closed, 294 tests. It also took **five external review rounds** and produced
roughly **27 defects**, none of them in the cryptographic construction.

This records what worked, what the defects had in common, and what changes for
M3a. It is written to be acted on, not filed.

## What went well

**Test-first against the design document, not against the code.** The
canonicalisation vectors were published before `jcs.mjs` existed, and the record
schema's tests were red before `record.mjs` did. That ordering is why the
record, leaf, chain and tree layers attracted almost no review findings: their
behaviour was specified in a file before it was specified in a function.

**The red-team suite as an acceptance gate rather than a demo.** Two harnesses
run on every change — one against OMA's own `verifyRun()`, one against
`splitstick verify` — and both exit non-zero when *any* observation changes, in
either direction. Three attacks are declared UNDETECTED with the milestone that
closes each. That suite caught the single worst defect of the milestone: the OMA
adapter was recording no tool results at all and reporting every failure as
`ok`, because `ToolResultContent` is `string | Part[]` and the error flag on a
result block is `is_error`, not `isError`. Reading the type declarations did not
find it; running a genuine journal through it did.

**Measuring NFR-01 inside M1 instead of at the end.** It rewrote the storage
layout three times — per-payload files, then per-record files, then one
append-only blob — and the budget was revised on evidence rather than
negotiated. Doing this after M3a would have meant changing the on-disk format
after anchoring depended on it.

**Honest reporting as a deliberate output.** A clean store verifies
INCONCLUSIVE, not `ok`, because four of the verifier's ten checks need a second
party. Three red-team attacks are declared undetected. The threat model names
the operator. None of that was asked for by a reviewer; it came out of the
design review rounds in PR #1 and it held up.

**The validators earned their keep.** Dependency cycles, duplicate ids, config
drift, stale claims and overclaim phrasings were all caught by `npm run backlog`
and `npm run review` rather than by a person.

## What the defects had in common

Of roughly 27 defects, **one** was in the cryptographic construction (an
unpaired-surrogate collision in the canonicaliser, found in my own review). The
rest fall into five groups.

| Group | Count | Examples |
|---|---:|---|
| Failure paths and crash recovery | 8 | shredding was a no-op on Linux; a rejected record broke the chain permanently; a torn line crashed the reader; a complete record with no newline destroyed the next append |
| Concurrency and ownership | 4 | two writers silently overwrote one blob; the lock could be stolen mid-claim; recovery repaired a journal another writer owned |
| Faithfulness of the account | 4 | independent transfers grouped as retries; ending one run settled another's calls; image parts dropped from a committed result |
| Verification completeness and honesty | 5 | the capability block claimed integrity under the word FAIL; the anchored height was never reported; consistency proofs were implemented and never called |
| Measurement validity | 4 | GC attributed without measurement; then measured with a broken instrument; a sequential A/B reported a negative overhead |

Four things are worth naming precisely, because each suggests a different fix.

**1. Tests written alongside code inherit its assumptions.** Two tests actively
*asserted* defects. The retry test asserted that identical arguments make one
logical action — the defect. The fixtures used four-character cids, which is why
nobody noticed the validator accepted them. And FR-52's property test, written
specifically to prove that mutating any field moves the digest, walked past a
real collision because it only mutates values that round-trip through JSON.

**2. Fixes are where the next defects live.** Three later findings were in code
added to fix earlier ones. Putting the salt write first — to make partial
failures benign — made a torn salt line the likely case, and that was the one
path that crashed the `Collector` constructor. Scoping the content lock per
collector left every record that externalises no payload unprotected.

**3. A green suite cannot tell working software from unreachable software.**
`consistencyProof` and `verifyConsistency` were implemented, tested over every
split up to 17, and never called by the verifier. `SUITE` was exported and used
nowhere, so DES-16's per-batch versioning did not exist. Both passed everything.

**4. I reported three measurement claims more confidently than the evidence
supported** — and the pattern repeated after I had named it. GC was asserted
from a correlation; then measured with an observer disconnected before its
asynchronous entries arrived, producing a zero I used to retract the first
claim; and the NFR-02 harness reported a negative overhead as though the
collector made runs faster. The instrument was never the thing I checked.

## What changes for M3a

Five changes, four of them mechanical. Resolutions do not survive a milestone;
checks do.

**1. Failure-mode inventory before implementation.** Each design element gets a
short written list before code: what happens if this write fails midway, if the
process dies here, if two instances do this at once, if the upstream type is the
other member of its union. Each entry becomes a test. The inventory is reviewed
as part of the element, not after it. Eight of M1's defects were on paths nobody
had enumerated.

**2. Adversarial tests first, happy path second.** Inverting M1's order. For
each requirement, at least one test must be one that *would pass if the
requirement were inverted* — the negative case — and fixtures are checked
against the specification rather than against the implementation.

**3. Two-instance and multi-process tests are mandatory** for anything that
writes. M1 added them only after being told, twice. `writelock.test.mjs` already
contends four real OS processes; that is the shape, not the exception.

**4. The verifier's vocabulary is now an artifact.**
[`spec/failure-codes.json`](../spec/failure-codes.json) carries every code with
its verdict class, its conclusion text and the milestone that implements it.

The guarantee is split, because the two halves need different instruments.
`tools/lint-failure-codes.mjs` checks statically that nothing unspecified is
emitted, nothing specified-and-due goes unemitted, every delivered code is named
in the design, and every `code:` site is a literal — that last one is what makes
the scan sound rather than merely plausible. **Coverage is proved separately and
executably** in `packages/verify/test/failure-codes.test.mjs`: a table of
scenarios must cover exactly the delivered codes, and each must make a real
verifier run emit its code with the verdict class the specification promises.

The lint originally claimed coverage too, by searching the test files for each
code's name — and a review pointed out that a comment would satisfy it, which it
did when they tried. That is the measurement-overclaim pattern from §4 above,
reappearing in the very check built to stop the others. Between them the two
instruments found eleven gaps: ten codes specified in no document, one with no
test, one more its own substring bug had been excusing, and a `carries` ordering
rule that was described in a comment and never implemented.

**5. Every budget proves its instrument in the same run.**
`bench/precision.mjs` and `bench/gc.mjs` are modules with tests. A benchmark
reports its clock resolution, verifies the GC recorder against a deliberate
allocation storm, states its resolution alongside its result, and returns
`UNRESOLVED` when the budget falls inside the confidence interval. The reference
environment is machine-readable and **every declared constraint must have an
evaluator or the harness refuses to run**, because `node_major_at_least` was
declared and ignored until a reviewer found it.

### One thing deliberately not changed

The review cycles themselves. Five rounds found thirteen issues that the test
suite, the typechecker and CI all passed over, and the cost of each round was
roughly a day against defects that would otherwise have reached a user as
"Splitstick says my log was tampered with" — which, for this product, is worse
than any outage. The aim for M3a is fewer findings per round because the
mechanisms above catch them first, not fewer rounds.

### A dead end worth recording

I tried a lint for unused exports, reasoning that it would have caught the
unreachable consistency proofs. It reported 34 findings, almost all of them the
legitimate public API of `@splitstick/core` — a library's surface is *supposed*
to be importable by code that does not exist in this repository. Shipping it
with a 34-item allowlist would have been theatre. The failure-code lint is the
right instrument for that defect class because it checks a *specified behaviour*
against its implementation rather than guessing from reachability.
