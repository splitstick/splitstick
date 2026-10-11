# DES-17 — Release and provenance pipeline

**Milestone:** M1 · **Covers:** SEC-22, SEC-23, NFR-01, NFR-02, FR-49

## Decision

The release pipeline is part of the security design, not operations housekeeping. **DES-10's
coverage attestation puts the collector's build digest in every heartbeat, and that digest is
only evidence if the build traces to source.** Without this element, coverage attestation proves
that *some* build ran.

## Pipeline

```
tag  →  GitHub Actions
         ├── npm ci && npm test && npm run backlog
         ├── benchmark gate              NFR-01 (<1 ms p99), NFR-02 (<2% latency)   TRC-04
         ├── CLI contract test           FR-49 — every documented invocation, verbatim
         ├── SBOM generate (CycloneDX)   SEC-23
         ├── npm publish --provenance    SEC-22 — Sigstore-backed, free
         └── attach SBOM + attestation to the release
```

### SEC-22 — provenance

`npm publish --provenance` from a GitHub Actions workflow produces a Sigstore attestation binding
the published tarball's digest to the source commit and the workflow that built it. Free,
requires no key of ours, and verifiable by anyone with `npm audit signatures`.

Deliberately chosen over bit-for-bit reproducible builds. Reproducibility is stronger and much
harder; provenance is achievable now and sufficient for the claim actually being made — *this
artifact came from this commit*. Full reproducibility stays a later goal, not a 1.0 promise.

### SEC-23 — signing and SBOM

Every release signed; CycloneDX SBOM published alongside with pinned dependencies. The SBOM
should be short, and a growing one is a design smell: DES-14 commits to writing no cryptographic
primitive, so the dependency list is a standing audit of whether that is still true.

### FR-49 — the CLI contract

The commands in the release notes are a promise people copy and paste:

```
npx @splitstick/collect-oma
npx @splitstick/mcp-proxy  --upstream <url> --out <dir>
npx @splitstick/verify     <dir> --policy <file>
npx @splitstick/coverage   <dir> --from <date> --to <date>
npx @splitstick/disclose   <dir> --event <id> --out <file>
```

A contract test executes **every documented invocation verbatim** and fails if a flag is renamed
or removed. Documentation drift in a CLI is a broken promise, not a typo.

### Benchmark gate — TRC-04

No performance figure is published as fact until its benchmark exists and passes. The gate blocks
a release whose p99 append exceeds 1 ms or whose added run latency exceeds 2%. Measured on a
documented reference machine, with the figures recorded per release so regressions are visible
rather than argued about.

## Consequences

- Releases are tag-triggered and fully automated. A manual `npm publish` from a laptop produces
  no provenance and must be prevented — enforced by `publishConfig` plus a CI-only npm token.
- `publishConfig.access: "public"` on every package: scoped packages default to restricted, and
  a free npm org cannot publish restricted ones.

## The performance budget — NFR-01, revised at M1

M1 measured the append path and the original target — p99 below 1 ms — was not
met: p50 0.278 ms, p95 0.419 ms, p99 2.027 ms. The revision came out of that
measurement rather than around it.

| | Budget | Stretch |
|---|---|---|
| p95 | 1 ms | — |
| p99 | 3 ms | 1 ms |

Three things make this a revision and not a relaxation.

**The budget is a budget, not a finding.** 3 ms is an engineering number, to be
confirmed against representative hardware, sustained workloads and realistic
payload sizes. It is not an industry standard and this document does not pretend
otherwise.

The reference environment is `bench/reference-env.json`: at least four CPUs,
8 GB, a one-minute load average under 1.0, a million events and three repeats.
The thresholds are deliberately loose, because their job is to exclude a busy
laptop and a shared CI runner rather than to require particular hardware. The
harness compares each run against it and prints whether it produced an
**acceptance measurement** or a **regression metric**, naming every shortfall —
so an acceptance claim cannot be made by accident from the wrong machine, which
is how two of this project's performance claims had to be withdrawn.

**The attribution has to be earned, and it took three attempts.** The first
draft asserted the p99 tail was garbage collection — inference from the
filesystem baseline moving with it, never correlated against GC events. The
second measured it and reported zero pauses, so the claim was retracted; that
measurement was also wrong, because `PerformanceObserver` delivers entries
asynchronously and the harness disconnected immediately after a synchronous
loop. The check written to validate the recorder did drain, so it validated the
recorder under conditions the benchmark never met.

The recorder now lives in `bench/gc.mjs` with its own tests, drains before
disconnecting, and runs a deliberate allocation storm through the same path on
every benchmark so that a reported zero is a measurement rather than a lost one.
Measured: 71 pauses totalling 344 ms, coinciding with 56% of the slowest one per
cent of samples. That is a correlation, which supports *garbage collection is a
material contributor to the tail* and not *the tail is garbage collection*;
filesystem write latency accounts for much of the remainder.

The sequence is recorded because the lesson is not about GC. A plausible
mechanism and a correlated signal are not a measurement, and a measurement whose
instrument is unvalidated is not one either.

**Latency is never bought with durability or integrity.** Specifically ruled
out: deferring a critical write without guaranteed recovery, weakening
source-sequence or failure reporting, removing encryption or commitment checks,
and uncontrolled buffering that only improves a benchmark. A deferred-write
queue was tried in M1 and removed, and a reviewer later found two failure paths
in the ordering that replaced it — that is the shape of the risk here. What this
project sells is trustworthy evidence at low overhead, not the fastest audit
logger.

## Every budget proves its instrument and states its resolution

Three performance claims here have been wrong in the same way: a number
reported more confidently than the measurement supported. An attribution with no
measurement behind it; a measurement whose instrument was never validated, which
produced a zero and prompted a retraction that was itself wrong; and a
sequential A/B whose drift produced a negative overhead, printed as a speedup.

So `bench/precision.mjs` and `bench/gc.mjs` are modules with their own tests,
and every budget reports:

- **its instruments, checked in the same run.** Clock resolution against the
  smallest quantity reported, and the GC recorder against a deliberate
  allocation storm. A zero from an instrument that cannot see anything is not a
  measurement.
- **its resolution**, not only its result. `NFR-02` is a paired difference
  because the arms are interleaved, and reports a 95% interval.
- **a verdict that will not overclaim.** `within` requires the whole interval to
  sit below the budget; a budget falling *inside* the interval is reported as
  `UNRESOLVED`, because that run is consistent with passing and with failing.

`NFR-02` is met on that standard, not merely un-contradicted: 40 paired runs put
the added latency at 0.864 ms with a 95% interval of [-1.612, 3.340] ms, wholly
below the 16.975 ms that 2% of a 400 ms-per-call run allows. The interval is wide
relative to the difference and narrow relative to the budget, which is the
distinction that matters — the measurement cannot resolve whether the true cost
is 0.5 ms or 2 ms, and does not need to in order to establish it is under 17 ms.
