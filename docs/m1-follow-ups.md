# M1 follow-ups

Work M1 deliberately left open, with the reason. Each item names what would
close it, so none of it depends on remembering a review thread.

## NFR-01 — the acceptance measurement has not been taken

**Status: open.** The requirement is p95 ≤ 1 ms and p99 ≤ 3 ms over at least a
million events across at least three repeats, on the reference environment in
[`bench/reference-env.json`](../bench/reference-env.json), with the original
p99 ≤ 1 ms retained as a stretch target.

Measured on the development machine, which reports itself a **regression
metric** on three counts (load average, event count, repeats):

| | p50 | p95 | p99 |
|---|---|---|---|
| chain only | 0.08 ms | 0.19 ms | 1.40 ms |
| full append path | 0.22 ms | 0.47 ms | 1.75 ms |

To close it:

1. A machine meeting every constraint the reference file declares, idle.
2. `node bench/append.mjs --events 1000000 --repeat 3 --machine '<name>' --storage '<description>'`
   — the harness prints `QUALIFYING ACCEPTANCE MEASUREMENT` only when nothing is
   short, and names each shortfall when something is.
3. The resulting JSON recorded as the requirement's evidence.

**What the qualification check cannot do.** CPU count, memory and load average
do not establish that a machine is dedicated, nor that its storage is comparable
to another's — a large enough shared runner would satisfy all three. That is why
an acceptance run must additionally name its machine and storage: it makes the
claim *attributable* rather than *verifiable*, which is the honest ceiling for a
benchmark describing its own host. A third party who wants to check the number
re-runs it on a host they control.

Candidate further constraints, none of which is implemented: I/O wait ceiling,
storage class asserted rather than described, CPU frequency scaling disabled,
and a filesystem free-space floor, since file creation measurably slows on a
nearly full volume — which this project observed directly when three
interrupted benchmark runs filled a disk.

## NFR-02 — met, with its workload assumption stated

40 paired runs: 0.864 ms added, 95% interval [-1.612, 3.340] ms, wholly below
the 16.975 ms that 2% of a 400 ms-per-call run allows.

Two assumptions travel with that. The model is scripted, which makes the figure
an upper bound — a real call is hundreds of milliseconds and only shrinks the
percentage. And the budget is expressed against an assumed 400 ms per model
call; a materially faster model would tighten it. Worth re-measuring against a
real provider once one is in the loop.

## Ahead of M3a

- **Fuzz the canonicaliser** rather than only driving fixed vectors. The
  unpaired-surrogate collision found in review was a canonicalisation collision
  in the component built to prevent exactly that, and FR-52's own property test
  walked past it because it only mutates values that round-trip through JSON.
  FR-46's conformance suite is the place for this.
- **Write the fault-injection cases first.** Of the findings across M1's reviews,
  almost none were in the cryptographic construction; they were in failure paths
  and concurrency. Two of them could not be reached by injection at all —
  `store.mjs` uses named ESM imports, so `fs` cannot be patched from outside —
  which means some invariants have to be designed to be checkable rather than
  tested after the fact.
