# Splitstick

**Agent actions you can prove — including the ones that aren't there.**

A tamper-evident record of what AI agents actually did: chained, signed, independently
countersigned, and verifiable offline by anyone holding the bytes and a public key.

> **Status: M1 built, M3a next.** Local integrity ships: records are canonicalised,
> salted, chained, batched into an RFC 6962 tree and signed, and `splitstick verify`
> reads it all back from files alone. Attack classes AC-1 and AC-2 are closed and the
> suite proves it. Everything that needs a second party — countersignatures,
> truncation detection, coverage attestation — is still ahead, and the verifier says so
> in its own output rather than leaving you to read the roadmap.

## Why this exists

Agent runtimes ship run journals and verifiers. They catch corrupted logs, mis-stitched
resumes and buggy context rewrites — real problems. What they cannot catch is the operator,
who holds the only key and writes the only copy.

We measured that rather than asserting it. Against a genuine run record from a widely used
runtime, with one EUR 2,000,000 transfer in it, most of our alterations passed the runtime's
own verifier — including changing the amount to EUR 25 and deleting the transfer entirely.

[`redteam/`](redteam/) reproduces that in two commands. It is also the acceptance harness:
each milestone flips an attack class from `undetected` to `detected` against *our* verifier,
and the suite exits non-zero whenever an observation changes in either direction.

## Map

| Path | What |
|---|---|
| [`redteam/`](redteam/) | The tamper suite. Reproducible, runs offline, no API key. |
| [`docs/`](docs/) | [Threat model](docs/threat-model.md) · [draft release notes](docs/splitstick-1.0-release-notes.md) — the scope commitment, rev. 8 |
| [`design/`](design/) | One spec per design element — [index and traceability](requirements/DESIGN.md) |
| [`requirements/`](requirements/) | [Backlog](requirements/MATRIX.md), [delivery plan](requirements/PLAN.md) and [design traceability](requirements/DESIGN.md) — gated by attack class. Counts live in the generated matrices, never in prose. |
| [`packages/`](packages/) | Shipped code: [`core`](packages/core) (record, canonical encoding, leaf, chain, tree, signer, store), [`collect-oma`](packages/collect-oma) (OMA journal and approval store), [`verify`](packages/verify) (the verifier and its CLI) |
| [`spec/vectors/`](spec/vectors/) | Conformance vectors — [RFC 8785](spec/vectors/jcs.json), [RFC 6962](spec/vectors/merkle.json), [C2SP note key ids](spec/vectors/note.json) |
| [`bench/`](bench/) | The performance budgets, measured rather than asserted |

## Working on it

```bash
npm install
npm test          # generate a fixture, then both tamper suites
npm run test:unit # the unit and conformance suites
npm run typecheck # JSDoc types over plain ESM, no build step
npm run bench     # the NFR-01 and NFR-02 budgets
npm run backlog   # revalidate requirements, regenerate the matrix and plan
```

Node 20 or later. No build step: plain `.mjs` with JSDoc types checked by `tsc --checkJs`.
One runtime dependency in `core` (`yaml`, pinned exactly) and none in the verifier.

The backlog is data, not prose. `requirements/*.json` is the source of truth; `MATRIX.md`
and `PLAN.md` are generated. The validator rejects any requirement without a release-notes
section behind it and any release-1.0 requirement not assigned to a milestone — a
requirement cannot exist without a promise.

## What M1 closes, and what it does not

Two tamper suites run on every change. The first alters a genuine OMA journal and asks
OMA's own `verifyRun()`; the second builds a real Splitstick store from that same journal
and asks `splitstick verify`.

```
gate AC-1   HELD   (A1, A2, A3, B, E)
gate AC-2   HELD   (C)

9 of 12 tampers are detected by splitstick verify from files alone.
3 are not, and each names the milestone that closes it: C2, D, F3.
```

The three that are not detected are in the suite on purpose:

| | Attack | Why it stands | Closed by |
|---|---|---|---|
| C2 | Edit, repair the chain, **re-sign** the checkpoint | The operator holds the key. Nothing local can refuse this. | M2 non-exportable custody + M3a countersignature |
| D | Truncate the tail and drop the checkpoints above it | A chain over a prefix is internally perfect. | M3a witness + cross-pack comparison |
| F3 | Erase a record, renumber **both** counters, repair and re-sign | The action never appears at all. | M3a + counterparty reconciliation |

None of them needs new cryptography. Each needs a second party, which is the shape of the
problem rather than a gap in the implementation.

This is also why a clean 1.0 store verifies **INCONCLUSIVE** rather than `ok`. Four of the
verifier's ten checks cannot be answered without a countersignature, and `ok` means every
check that could run, ran, and passed. A bare `ok` here would claim more than was checked:

```
verdict     INCONCLUSIVE  (7 checks passed, 4 could not be answered, 0 failed)
capability  ordering and content integrity of every record in this chain
            NOT: truncation above record_seq 4 is NOT detectable from this evidence alone
            NOT: nothing here establishes WHEN any record was written
trusting    the cryptographic primitives (SHA-256, Ed25519)
            the operator for the completeness of what was captured
```

## Measured, not asserted

`npm run bench` prints the budgets with the filesystem's own numbers beside them, because a
percentile without attribution invites widening the budget instead of finding the cause.

- **NFR-02, added agent run latency — met, with the interval to prove it.** Interleaved A/B
  through OMA's real orchestrator, analysed as a paired difference: 0.864 ms added, 95%
  interval [-1.612, 3.340] ms, wholly below the 16.975 ms that 2% of a 400 ms-per-call run
  allows. The interval is wide against the difference and narrow against the budget, which is
  the distinction that matters. A verdict is only `within` when the whole interval clears the
  budget; a budget falling inside it reports `UNRESOLVED`.
- **NFR-01, low-overhead evidence capture — open, pending a qualifying run.** The harness
  declares every run an acceptance measurement or a regression metric against
  `bench/reference-env.json` and names each shortfall, so a laptop number cannot be mistaken
  for acceptance. On the development machine (a regression metric): p50 0.23 ms, p95 0.49 ms,
  p99 1.77 ms against p95 ≤ 1 ms and p99 ≤ 3 ms. The
  requirement was revised at M1 off the back of these measurements: p95 ≤ 1 ms and
  p99 ≤ 3 ms on a defined reference environment, with the original p99 ≤ 1 ms kept as a
  stretch goal. Measured 0.22 ms p50, 0.47 ms p95, 1.75 ms p99. Cryptography costs 0.03 ms
  per record while creating one file costs 0.20 ms, so nothing on the append path creates
  one — measuring this rewrote the storage layout three times. On the tail, the harness now
  measures rather than infers: 71 GC pauses totalling 344 ms, coinciding with **56% of the
  slowest 1%** of samples, with the recorder verified against a deliberate allocation storm
  in the same run. That is correlation, so the honest reading is that garbage collection is
  a material contributor and filesystem latency accounts for much of the rest. Two earlier
  claims here were wrong: the first asserted GC with no measurement, and the second
  retracted it on a measurement that was broken — the observer was disconnected before its
  asynchronous entries arrived. Latency is never bought with durability: a deferred-write
  queue was tried and removed.

## Follow-ups

[`docs/m1-retro.md`](docs/m1-retro.md) is the M1 retrospective: what worked, what
the 27 defects had in common, and the five mechanisms that change for M3a.
[`docs/m1-follow-ups.md`](docs/m1-follow-ups.md) records what M1 left open and
what would close it: NFR-01's acceptance measurement on a qualifying machine,
NFR-02's workload assumptions, and two things to carry into M3a — fuzzing the
canonicaliser, and writing the fault-injection cases before the happy path.

## Resourcing

Unfunded: one person's time, no budget. No hosted witness, no accreditation, no certification
mark, and recognition rather than cash for findings — all stated in the
[release notes](docs/splitstick-1.0-release-notes.md) rather than left to be inferred.

The software is unaffected. Everything in 1.0 is buildable at zero cost and anchors by default
to a public transparency log this project does not operate.

## Licence

Apache-2.0, including the patent grant. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The open components — spec, wire format, test vectors, practice statement, both collectors —
will not be relicensed. A business built on trust cannot afford a licence people expect to
change.
