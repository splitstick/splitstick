# Tally

**Agent actions you can prove — including the ones that aren't there.**

A tamper-evident record of what AI agents actually did: chained, signed, independently
countersigned, and verifiable offline by anyone holding the bytes and a public key.

> **Status: pre-build.** No product code exists yet. This repository currently holds the
> evidence that motivated the project, the scope it commits to, and the plan to build it.
> Every figure in the release notes is a target to be met, not a measurement.

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
| [`docs/`](docs/) | [Draft release notes](docs/tally-1.0-release-notes.md) — the scope commitment, rev. 6 |
| [`requirements/`](requirements/) | [Backlog](requirements/MATRIX.md) and [delivery plan](requirements/PLAN.md) — 187 requirements, 174 in 1.0, gated by attack class |
| [`packages/`](packages/) | Shipped code. Empty until M1. |
| [`spec/`](spec/) | Wire format and conformance vectors. Empty until M6. |

## Working on it

```bash
npm install
npm test        # generate a fixture, run the tamper suite
npm run backlog # revalidate requirements and regenerate the matrix and plan
```

The backlog is data, not prose. `requirements/*.json` is the source of truth; `MATRIX.md`
and `PLAN.md` are generated. The validator rejects any requirement without a release-notes
section behind it and any release-1.0 requirement not assigned to a milestone — a
requirement cannot exist without a promise.

## Licence

Apache-2.0, including the patent grant. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The open components — spec, wire format, test vectors, practice statement, both collectors —
will not be relicensed. A business built on trust cannot afford a licence people expect to
change.
