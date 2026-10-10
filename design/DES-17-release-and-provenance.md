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
