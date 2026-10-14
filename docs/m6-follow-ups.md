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

## Found in the M6 self-review, fixed in M6

Each was reproduced with a probe before anything was changed, and each regression was run
against the pre-fix code to confirm it fails there.

| What | The shape it had |
|---|---|
| the stdio proxy rewrote `\r\n` to `\n` | ninety bytes in, eighty-nine out, under a capitalised claim that the bytes forwarded are the bytes received. The guarding test sent only `\n` |
| it also appended a newline to a final message that had none | same claim, same cause: `readline` reports a line without its terminator, so the terminator was reconstructed rather than preserved |
| the committed `args` were `JSON.stringify`'d | `{"amount": 1.50,"big":1e2}` became `{"amount":1.5,"big":100}` under a comment saying they were not re-serialised. Self-consistent, verifiable, and not what the agent sent — and the number of a transfer is where that stops being cosmetic |
| `String(id)` collapsed `1` and `"1"` | JSON-RPC treats them as different ids, so an upstream answering `"1"` to a request made with `1` had its result attributed to a call that never received it. The module refuses to match by proximity because "a guess here invents a tool result"; a coercion invents one just as well, from the untrusted side |
| a `tools/call` with no JSON-RPC id recorded NOTHING | forwarded, executed by any server that dispatches on `method`, and invisible. The one outcome a collector whose premise is "the agent is not trusted to self-report" may not have |
| the tlog adapter labelled every cosignature with its own id | a line signed by someone else travelled into the envelope under the configured identity, so every reader checked it against the wrong key and got a finding whose stated meaning is "the operator rewrote history" — a false tampering signal caused by a misbehaving witness |
| it kept the last of several cosignature lines | nothing makes the last authoritative, and the others were dropped in silence. A witness cosigning under two keys during a rotation is a real case |
| the OPS-05 static check missed `await import('node:net')` | and `globalThis.fetch(…)`. Two of the four ways in, on the guard for the highest-risk row in the milestone, in a repository where `await import('node:crypto')` is ordinary style |
| and then it matched `typeof globalThis.fetch` in a JSDoc type | the overcorrection: a guard that fires on a type reference gets switched off, and then it guards nothing |

### Checked and found sound

Recorded because the investigation was the expensive part, and the next person should not
repeat it.

A recording failure in the proxy looked at first like silent loss: the traffic is forwarded,
the evidence has one fewer record, and the coverage report prints `loss 0 declared`. It is
not silent. `Collector#action` spends the observation counter **before** anything that can
fail, so an observed-and-unwritten attempt leaves a hole in `source_seq` and the verifier
reports `SEQ_BROKEN` — verdict **fail**, with the detail "source_seq jumped from 1 to 5:
3 observed attempt(s) were never written". Where the chain store itself is what failed, the
collector degrades and the log stops rather than continuing from an untrustworthy position,
and the report says `inconclusive` with `COVERAGE_UNKNOWN` rather than claiming
completeness.

The first probe for this replaced `Collector#action` wholesale, which bypassed exactly the
counter-spending under test and produced a false positive. Breaking the content store
instead — the failure the mechanism was built for — showed it working.

## Found by CI, fixed in M6

Two packaging defects that every local gate passed through, because a test runs against a
working tree and a user installs a package.

**`@splitstick/witnesses` imported `@splitstick/witness-tlog` without declaring it.** It
resolved locally because the workspace link was there — put there by hand, during the review
— so nothing noticed. Anybody installing the package would have got a module-not-found at
the first call that reached the new adapter.

**`packages/witness-tlog` was a workspace with no entry in `package-lock.json`.** `npm ci` is
the first step of every CI job and refuses a tree it cannot account for, so the whole matrix
died at step one. Nothing local runs `npm ci`.

Both are now checked by `tools/lint-packaging.mjs`, in `npm run lint` and as its own CI step
so the failure names the package rather than arriving as an npm error. It also checks the
third member of the family, which M6's review found separately: a declared bin that exists,
carries a shebang, and is marked executable — `splitstick-verify` was the only published bin
and it printed nothing and exited 0 when installed. Each of the three rules was verified by
breaking the real thing and watching the lint catch it.

And the write-lock contention test now releases its four processes through a **barrier**
rather than a wall-clock instant chosen before they were spawned. The instant made contention
something the test hoped for: on a loaded runner four node processes can boot further apart
than the lease is long, every one finds a free lock, and the "somebody was refused" assertion
fails for a reason that says nothing about the lock. Startup is now outside the race.

## Carried, not yet accepted

### The test suite leaks a temp directory per test

Carried from M5 and still true. Roughly 62,000 directories accumulated under the system
temp directory and filled the development disk; they were removed by hand, by prefix, and
the cause is untouched. Most tests `mkdtempSync` and never remove it.

Closing it: a shared helper that registers each directory for removal, and a check that
fails if a test file calls `mkdtempSync` without it. Offered as its own small change rather
than folded into a milestone, because it touches almost every test file and would bury the
diff of whatever it travelled with.

## Found in the second (independent) review, fixed in M6

The first self-review covered the pairing core, the stdio transport and the tlog adapter.
This pass went at the four surfaces it had not touched: the HTTP transport, the proxy CLI,
the witness-list parser, and the conformance suite. Each finding was reproduced with a probe
before anything changed, and each regression run against the pre-fix code.

**The conformance suite certified a witness that never signs anything.** `C1` asserted
`sigs.length >= 2` and nothing else, so a "witness" returning the note with the OPERATOR'S
own signature line repeated passed 7 of 7, green, and would have been reported conformant.
That is the third time this project has counted presence as anchoring — PR #8's finding 15,
PR #9's P1, and now the suite a third party certifies against under GOV-05, where the defect
would have travelled into somebody else's implementation. `C1` now requires a signature
under a key id that is not the log's, and the suite's own self-test carries that witness as
a fourth broken implementation, caught by `C1`.

**The agent could redirect the proxy to any host it liked.** `new URL(req.url, upstream)`
reads a request path of `//evil.example/x` as a protocol-relative URL and resolves it to
`http://evil.example/x`, so tool arguments and the agent's headers went wherever the agent
pointed them while the record said the configured upstream. A confused deputy at the one
boundary the proxy exists to police, in a threat model where the operator is the adversary.
The path is now applied to a copy of the upstream URL, and the origin is asserted afterwards
— "assigning pathname cannot change the host" is a fact about the URL specification, not one
this file had checked.

**An unreadable upstream reply killed the collector.** `await upstreamRes.arrayBuffer()`
rejected into the event loop, which terminates the process by default, so an upstream that
truncated a reply took the agent's MCP server down with it. NFR-12 broken by the component
whose first obligation it is, triggerable from the untrusted side. The handler is wrapped
and the response body is now capped the way the request body already was.

Also:

| What | The shape it had |
|---|---|
| a valid call to a down upstream was counted as `unparsed` | `pairing.request()` returns null for a well-formed call and a `?? { what: 'unparsed' }` stood behind it. False about the traffic, and it inflated the count an operator reads to judge how much of it the proxy did not understand |
| `--out /a --out /b` silently wrote to `/b` | the operator named two evidence stores and one was discarded without a word |
| `--listen` with a command upstream was accepted and ignored | nothing was listening on the port the operator believed they had opened. The fourth instance of this shape |
| the witness list accepted `sponsored`, `premium`, `featured`, `vetted`, `best_for` | GOV-09 forbids vetting, ranking **or charging** for inclusion, and the check was a denylist of words that had not anticipated the commercial ones. It is now an allowlist: a new field is a deliberate act |
| the list accepted `establishes: ['everything']` | an unrecognised capability class, unvalidated, where an unknown witness *type* was carefully refused. An operator reading it would choose that witness believing it covered time and sequence |
| the list accepted `establishes: []` and `endpoints: []` | `[]` is neither undefined nor `''`, so it walked past the required-field check — the same "absent reads as permissive" hole that check exists to close, through a different door |
| `C5` reported its status instead of asserting it | its three sibling checks pin theirs, so a witness answering 500 passed a check the others would have failed |
| two tests from the FIRST review passed `collector: c` where the rig returns `collector` | they asserted forwarded bytes, which was still valid, but the recording half of those tests was dead. Found while adding the HTTP tests |

## Found in PR #11 review, fixed in M6

Two P1s, both the same property: every consequential invocation crossing the observation
boundary stays accountable, even when the protocol participant misbehaves or the process
exits unexpectedly.

**Two outstanding calls on one JSON-RPC id erased the first.** `#pending.set(idKey(id), …)`
overwrote, so the first invocation was forwarded, very likely executed, and gone from the
record with no timeout behind it — while the response that arrived was attributed to
whichever call happened to be in the map. Reusing an outstanding id breaks JSON-RPC, but a
proxy that exists because the agent is not trusted to report its own actions cannot answer
misbehaviour by discarding what it saw. Both attempts are now kept, each under a key no
response can produce, and the id is marked ambiguous: a response bearing it answers one of
them and nothing here can say which, so neither is paired and both settle as attempts with
no result, each keeping its own arguments and correlation.

**`expire()` had no caller except shutdown.** A long-running proxy held every unanswered
invocation in memory indefinitely — observed, forwarded, and with no durable record until
the process chose to exit; killed instead, the record never existed. `settle.mjs` now sweeps
on an interval, shared by both transports for the reason the pairing core is shared, and the
bin settles on SIGINT/SIGTERM/SIGHUP before exiting.

### The crash window, bounded rather than closed

A `SIGKILL` between a request and the next sweep still loses the pending call. The window is
now the settle interval rather than the process lifetime, which is the difference between a
bounded loss and an open-ended one, and it matches what FR-61 already does for the
observation counter: flushed at each batch, so an unrecoverable crash loses at most the
current window.

Closing it completely is what the review suggested — record the attempt **before** forwarding
it and append the outcome later. That is two records where DES-01 specifies one, and FR-01's
shape ("the call and its result are one record") is what a verifier and the disclosure format
are both built around. It is a record-format decision with the same weight as the `OUTCOMES`
question below, and it is not one to take during a review. What would make it tractable: an
attempt record whose outcome is amended by a later record referencing its correlation, which
needs a verifier rule for the pair and a disclosure rule for what a single-event pack
contains.

### A record-format gap, left as a decision rather than taken

An id-less `tools/call` is now recorded, and it settles as an attempt with `outcome:
'timeout'` — observed, and no result ever received, which is true. What is imprecise is
*why*: nothing timed out, because nothing was ever going to answer. `OUTCOMES` is
`ok | error | timeout | denied`, a published vocabulary, and adding a value to it makes
records that older verifiers refuse.

So the choice was not made unilaterally at review time. Either an `unanswered` outcome, or a
distinct record kind, with the compatibility question answered deliberately. Until then the
proxy reports the notification out of band and counts it, and the record says the weaker
true thing rather than the stronger false one.

## Not a follow-up, but worth saying once

Every defect in the list above is a defect in **what was claimed**, not in a mechanism. The
Merkle tree, the chain, the signatures and the canonical encoding were all correct
throughout M6. What went wrong was a verifier that said nothing and called it success, a
report whose positive branch could not be reached, a lint that could not fire, an exit code
that turned a typo into a finding, and a manual that described an API nobody had run. The
instrument keeps reporting conclusions it has not established, and that is where the
remaining risk in this project lives.
