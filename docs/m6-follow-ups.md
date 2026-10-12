# M6 follow-ups

What M6 left open, and why. Each entry says what would close it, so the next person does
not have to reconstruct the judgement.

## Deliberately not done

### FR-15 — anchor against a real transparency-dev/witness instance

The adapter is written, registered as a witness type, and anchored against a local instance
over HTTP across four successive checkpoints with real consistency proofs. The server in
that test is built from `@splitstick/witness-self`, whose semantics the published
conformance suite checks independently.

**What is missing is interoperability, and it is the part that matters.** A client and a
server written against one reading of one document agree with each other whether or not the
reading is right. M5 produced two verifier bugs of exactly that shape — the vkey's
algorithm byte and the base64 `+` in a three-part split — both from gaps in a specification
this project wrote itself, and both found only when something external was involved.

Closing it: run `transparency-dev/witness` (Go) locally, enrol the operator key, and anchor
against it. The failure to expect is in the request framing — the `old <size>` line, the
proof encoding, and whether a cosignature body carries only the witness's own line.
`packages/witness-tlog/src/index.mjs` states the format it assumes in one place, at the top.

### LEG-13 — live anchor against a qualified TSA

Configurable, plumbed, and reported: the operator can declare a qualified TSA in the witness
set, the reader declares it in their acceptance policy, and the verifier states whether the
Art. 41 presumption attaches — computed from the proof type, so labelling our own witness
qualified carries nothing. All of that is tested, including against a real RFC 3161 token
from the interop fixture.

The stated verify is a **live** anchor against an actual qualified trust service. That needs
a commercial account with a qualified provider, which is a procurement step and not an
engineering one. Same posture as NFR-04: not claimed until run.

### NFR-04 — the offline verification budget

Carried from M5, unchanged. `bench/verify.mjs` exists and reports; the dev host does not
qualify under `bench/reference-env.json` (load average alone disqualifies it), so every run
so far is a regression metric rather than an acceptance result. Needs one run on a
qualifying host.

## Found in M6, fixed in M6

Recorded because the shapes repeat, not for credit.

| What | The shape it had |
|---|---|
| `splitstick-verify` printed nothing and exited 0 when installed | the self-exec guard compared `file://${argv[1]}` against a realpath URL, and npm links a bin as a symlink. A verifier whose silence reads as "nothing wrong" |
| `--upstream "node ./server.mjs"` spawned the whole string as a program name | every documented form was the broken form, which is what executing documentation finds and reviewing it does not |
| an upstream that could not start exited 0 | fail-open reported as success: a recorder that recorded nothing, telling its supervisor it was fine |
| `coverage` and `disclose` exited 2 for both "inconclusive" and "bad flag" | a refusal arriving as a verdict about evidence. 3 is now refusal everywhere |
| `coverage` wrote refusals to stdout | `coverage … > report.txt` on a typo put usage text in the report and nothing on the terminal |
| the LEG-12 lint's sentence splitter cut `Art. 41` in half | the rule could never fire on the exact sentence it existed to catch. A check that cannot fire is worse than no check |
| `qualified` was stamped at 2 of 12 push sites, missing `rfc3161` | the only type the presumption can attach to, so the report's positive branch was unreachable |
| `parseConfig` allowed five witness keys; the builder read seven | an operator could not configure a knob the code uses. Fourth instance of this shape in the project |
| the write-lock contention test asserted "exactly one winner" | a load-sensitive proxy for mutual exclusion. Now asserts no two hold intervals overlap |
| the documented `collect-oma` snippet took a store path | the constructor takes a Collector. Wrong the moment it was written, caught by running it |
| the root pinned OMA 1.21.1 — the middle of three published 1.21.x | "supports 1.21.x" tested at one point. Both ends now run in CI, and both pass |

## Carried, not yet accepted

### The test suite leaks a temp directory per test

Carried from M5 and still true. Roughly 62,000 directories accumulated under the system
temp directory and filled the development disk; they were removed by hand, by prefix, and
the cause is untouched. Most tests `mkdtempSync` and never remove it.

Closing it: a shared helper that registers each directory for removal, and a check that
fails if a test file calls `mkdtempSync` without it. Offered as its own small change rather
than folded into a milestone, because it touches almost every test file and would bury the
diff of whatever it travelled with.

## Not a follow-up, but worth saying once

Every defect in the list above is a defect in **what was claimed**, not in a mechanism. The
Merkle tree, the chain, the signatures and the canonical encoding were all correct
throughout M6. What went wrong was a verifier that said nothing and called it success, a
report whose positive branch could not be reached, a lint that could not fire, an exit code
that turned a typo into a finding, and a manual that described an API nobody had run. The
instrument keeps reporting conclusions it has not established, and that is where the
remaining risk in this project lives.
