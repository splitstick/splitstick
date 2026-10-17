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

**A correction to step 1, found while trying to take the measurement.** The
qualification check could not be passed on any machine. `max_load_average_1m`
was evaluated against a load average sampled *after* the measured loop, and a
saturated single-threaded benchmark drives its own one-minute average to roughly
1.0 against a limit of 1.0 — so "idle" was impossible to demonstrate, because
the constraint was measuring this benchmark rather than the machine. Two of the
three exclusions the reference file listed in prose, a shared CI runner and a
filesystem near capacity, had no evaluator at all. All three are fixed, and the
harness now prints its verdict as a **preflight**, before the twenty minutes
rather than after. See [m7-follow-ups.md](m7-follow-ups.md#the-gate-that-could-not-be-passed).

To close it:

1. A machine meeting every constraint the reference file declares, idle — which
   the check can now actually recognise.
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

## M6 — ship type declarations with the packages

**Folded into M6's publishing work as an implementation detail, not a separate
requirement.** The release workflow already exists from SEC-22 and SEC-23; this
is a few lines in it.

All three packages currently publish no `types` field and no `.d.ts`, so a
TypeScript consumer importing `@splitstick/core` gets `any` for everything. The
project authors plain `.mjs` with JSDoc checked by `tsc --checkJs` under `strict`
and `noUncheckedIndexedAccess`, deliberately: with no build step the published
artifact IS the source, which matters for a product whose SEC-22 attestation
binds a package digest to the commit a reviewer read. A compile step would
insert a transformation between the two.

Declarations can be emitted without giving that up, and the output carries the
doc comments through — verified before this was written down:

```
tsc -p tsconfig.json --declaration --emitDeclarationOnly --outDir <dir>
→ export function leafDigest(salt: Uint8Array, record: unknown): Buffer;
  export const SALT_BYTES: 16;
```

To close it: emit declarations in the release workflow, add `types` to each
package manifest, include the `.d.ts` files in the published tarballs, and
attest them alongside the tarballs as SEC-22 already does for the rest.

This is ergonomics rather than a promise kept. `DES-11` is explicit that the
spec, not our package, is what an independent implementer works from — which is
why no release-notes line covers it and why it is not a requirement. It makes
the thing third parties are invited to build against pleasant to build against,
and nothing more.

## Ahead of M3a

- **Fuzz the canonicaliser** rather than only driving fixed vectors. The
  unpaired-surrogate collision found in review was a canonicalisation collision
  in the component built to prevent exactly that, and FR-52's own property test
  walked past it because it only mutates values that round-trip through JSON.
  FR-46's conformance suite is the place for this.
- **Guard the failure-code vocabulary at runtime, not only statically.**
  `tools/lint-failure-codes.mjs` checks that every `code:` site is a string
  literal, which is what makes its scan sound — but it exempts `f.code`, where
  the verifier forwards findings produced by `recomputeChain`. That exemption is
  safe today for a specific reason: every forwarding site's origin is itself
  scanned, `chain.mjs` emits only literals, and all five are in the
  specification. It stops being safe the moment a code arrives from somewhere
  the scan does not reach.

  M3a is when that changes, because the verifier gains witness, roll-up and
  coverage codes and more layers to forward them through. The fix is a frozen
  vocabulary in code that every finding is constructed through, so an unknown
  code throws rather than being printed, with the lint asserting that the frozen
  list and `spec/failure-codes.json` agree. A review raised this and correctly
  declined to block the retrospective on it.

- **Write the fault-injection cases first.** Of the findings across M1's reviews,
  almost none were in the cryptographic construction; they were in failure paths
  and concurrency. Two of them could not be reached by injection at all —
  `store.mjs` uses named ESM imports, so `fs` cannot be patched from outside —
  which means some invariants have to be designed to be checkable rather than
  tested after the fact.
