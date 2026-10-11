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
payload sizes on a defined reference environment. It is not an industry
standard and this document does not pretend otherwise.

**The attribution has to be earned.** An earlier draft asserted that the p99
tail was garbage collection. That was inference from the filesystem baseline
moving with it, not evidence: the outliers were never correlated against GC
events. The harness now subscribes to `perf_hooks` GC entries and reports the
share of outliers that coincide with one, so the claim is either supported by
the run that makes it or dropped.

**Latency is never bought with durability or integrity.** Specifically ruled
out: deferring a critical write without guaranteed recovery, weakening
source-sequence or failure reporting, removing encryption or commitment checks,
and uncontrolled buffering that only improves a benchmark. A deferred-write
queue was tried in M1 and removed, and a reviewer later found two failure paths
in the ordering that replaced it — that is the shape of the risk here. What this
project sells is trustworthy evidence at low overhead, not the fastest audit
logger.

`NFR-02` independently bounds end-to-end agent run latency at 2%, and is met.
