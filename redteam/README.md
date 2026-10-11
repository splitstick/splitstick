# Splitstick red team

Reproducible tamper tests against AI agent run records.

Agent runtimes increasingly ship an audit story: a run journal, a verifier, a
claim that the record can be checked after the fact. This repository takes those
claims literally. It generates a **genuine** run record, alters it the way an
interested party would, and re-runs the runtime's **own** verifier.

First target: [OMA](https://github.com/open-multi-agent/open-multi-agent)
(`@open-multi-agent/core`), whose `verifyRun()` is among the few that exist at all.

## Result

A 14-event journal produced by OMA's real runtime. One consequential tool call —
a EUR 2,000,000 transfer. Baseline verifies clean. Then six tampers:

| # | Tamper | `verifyRun()` | Code |
|---|--------|---------------|------|
| A | Edit `tool/result` only — EUR 2,000,000 → EUR 25 | **passes** | — |
| B | Naive edit of a model-visible block | detected | `MISSING_CONTEXT_REPLACE/not-reproducible` |
| C | Same edit, with the citing hash recomputed | **passes** | — |
| D | Truncate the tail | **passes** | — |
| E | Duplicate a sequence number | detected | `SEQ_NOT_MONOTONIC`, `BROKEN_LINK` |
| F | Erase the tool call entirely, then renumber | **passes** | — |

**Four of six alterations verify as clean.** Including the two an audit would
care about most:

```
pristine (truth)   tool/call   {"amount":2000000,"currency":"EUR","to":"ACME-9931"}
                   tool/result "OK: transferred EUR 2000000 to ACME-9931"

A. after tamper    tool/result "OK: transferred EUR 25 to ACME-9931"      -> verifyRun() OK
F. after erasure   tool/call   ABSENT
                   tool/result ABSENT                                      -> verifyRun() OK
```

Attack C takes one additional line, using `canonicalContentHash()` — exported by
OMA so that offline readers can recompute digests, which also makes it available
to whoever is rewriting them.

## Reproduce

Requires Node.js 20+. No API key; the LLM adapter is scripted and makes no
network request.

```bash
npm install
npm test
```

`npm run generate` writes `out/journal.jsonl` through OMA's real orchestrator and
asserts the baseline verifies. `npm run redteam` applies the six tampers above.
`npm run redteam:splitstick` then builds a real Splitstick store from that same
journal and applies eleven tampers to it, asking `splitstick verify` for a
verdict on each.

Every attack declares the outcome currently observed, and both suites **exit
non-zero when an observation changes** — so they are regression canaries in both
directions. If upstream closes a gap, this goes red, which is how you want to
find out.

The two files have different jobs and neither replaces the other.
`redteam.mjs` records what OMA's `verifyRun()` does, and must keep recording it
accurately even as Splitstick closes the same gaps. `splitstick.mjs` is the
acceptance harness for our own milestones: it declares three attacks as
UNDETECTED, with the milestone that closes each, because a suite containing only
its successes is marketing.

```
gate AC-1   HELD   (A1, A2, A3, B, E)
gate AC-2   HELD   (C)

9 of 12 tampers are detected by splitstick verify from files alone.
3 are not, and each names the milestone that closes it: C2, D, F3.
None of those needs new cryptography. Each needs a second party, which is the
shape of the problem.
```

## Is this a vulnerability?

**No, and it should not be reported as one.** It is a scope boundary, and OMA
documents it plainly. From `docs/run-journal.md`:

> **`verifyRun()` detects drift, not tampering.** […] **No hash chain.** No event
> carries a digest of its predecessor […] **No signature.** Nothing in the
> journal is signed.

And from the project README:

> It proves lineage and content, not that the file was never edited.

`docs/self-hosting.md` carries a section titled "What is not provided" listing
multi-tenancy, RBAC, SSO and a database-backed store. Projects that are
overselling do not write that section.

The invariant OMA set out to protect is **"model-visible means logged"** — that
every block the model saw is reproducible from the journal. That is a
*reproducibility* guarantee, and attack B shows it working exactly as designed:
careless edits and accidental corruption are caught. An *audit* guarantee is a
different property against a different adversary — the keyholder — and OMA never
claims it.

This repository exists because the distance between those two properties is easy
to state and hard to feel. A table is more convincing than a caveat.

### One finding that goes slightly beyond the documented boundary

The docs disclose the absence of a chain and a signature. What they do not spell
out is that hash coverage is scoped to **model-visible blocks** recorded in
`llm/request` descriptors. The record of what the tool actually *did* —
`tool/result.result.content` and `tool/result.record.input/output` — carries
lineage but **no content digest at all**.

So attack A requires no hash recomputation. It is a one-field edit of the
authoritative side-effect record, and nothing in the verifier reads it. This
follows logically from the stated invariant: the tool result is only in scope
once it has been assembled into a message the model sees. It does mean the part a
regulator would ask about is the least protected part of the journal.

## The six attacks

- **A — `tool/result` edit.** Change the recorded amount and the tool's
  input/output record. Leave everything else alone.
- **B — naive block edit.** Change the model-visible block but not the
  `contentHash` that cites it. The journal now contradicts itself.
- **C — consistent edit.** Change the block *and* recompute the citing digest.
  Self-consistent, correctly structured, materially false.
- **D — truncation.** Drop everything after the transfer. A monotonic prefix is
  still a valid stream; the run merely looks unfinished.
- **E — duplicate sequence.** Reuse a `seq`. Caught by the sequence check.
- **F — erasure.** Remove the `tool/call`, `tool/result` and assembled
  `user/message`, drop the descriptor citing them, renumber into a contiguous
  stream. The action is gone without a trace.

## What the results imply

The attacks separate cleanly by the defence each one requires, which is more
useful than the headline count:

| Requirement | Fixes | Needs a third party? |
|---|---|---|
| **R1** Digest the *action record* — tool input, output, approval decision — not just the conversation | A | No |
| **R2** Hash-chain each event to its predecessor and sign batches | B, C | No |
| **R3** Anchor a monotonic count externally | D, F | **Yes** |

R3 is the interesting one. A hash chain over a truncated prefix is still
internally valid — there is nothing left to contradict it. **Detecting truncation
and erasure is not possible from inside the record**, no matter how good the
local cryptography, because a party who controls the file controls where it ends.
It requires an independent party that remembers how many batches it has
countersigned.

That is an argument for external anchoring made on evidence rather than on
theory, and it is the reason this repository came before any implementation.

## Scope

- Pinned to `@open-multi-agent/core@1.21.1`. Journal shapes are internal and may
  change; the canary will tell you when they do.
- Covers the JSONL run journal only. The durable-approval ledger binds a request
  to a SHA-256 of the reviewed content and fails closed on mismatch — a stronger
  position, tested separately.
- The fixture is deterministic and offline. Nothing here touches a real provider,
  a real account, or real money.

Contributions adding a runtime are welcome: a generator that produces a genuine
record, and tampers checked by that runtime's own verifier. No synthetic
fixtures — the point is to test what ships.

## License

Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
