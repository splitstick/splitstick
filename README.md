# Splitstick

**Agent actions you can prove — including the ones that aren't there.**

A tamper-evident record of what AI agents actually did: chained, signed, independently
countersigned, and verifiable offline by anyone holding the bytes and a public key.

> **Status: 0.9.0 — a public technical preview.** All nine milestones are built and all
> seven attack-class categories are implemented and exercised against our own verifier,
> with **one attack deliberately left unclosed: G2**, which no mechanism in this release
> detects and which the suite reports as `NOT CLOSED` on every run. The 1.0 requirement
> backlog is complete — 193 of 193 — and the release gate would pass a `v1.0.0` tag.
>
> It is 0.9.0 anyway, because every requirement has evidence behind it and none of that
> evidence has yet met an operator who did not write it. The things a `1.0.0` would imply
> and this release has not earned are listed in
> [the 0.9.0 notes](docs/splitstick-0.9.0-release-notes.md), which lead with them: no live
> qualified timestamp, no witness operated by somebody else, performance figures from one
> laptop. The verifier says the same in its own output, including a `trusting` list naming
> every assumption it could not discharge.
>
> What a preview means in practice: the packages install from their own tarballs
> into a project with no workspace (`npm run smoke` proves it on every release),
> and nobody outside this project has yet operated it. If you are the first, the
> things most likely to bite are a witness configuration this author never tried
> and an onboarding step that only works because of something in this repository.

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
| [`docs/`](docs/) | [0.9.0 release notes](docs/splitstick-0.9.0-release-notes.md) — **start here**, it leads with what is not established · [1.0 notes](docs/splitstick-1.0-release-notes.md) — the full claim set and the figures table · [threat model](docs/threat-model.md) · [self-hosted witness](docs/self-hosted-witness.md) — OPS-03, the deployment guide · [witness outages](docs/witness-outages.md) · [restore drill](docs/witness-restore-drill.md) · [evidence](docs/evidence/) — committed results a claim can be checked against |
| [`design/`](design/) | One spec per design element — [index and traceability](requirements/DESIGN.md) |
| [`requirements/`](requirements/) | [Backlog](requirements/MATRIX.md), [delivery plan](requirements/PLAN.md) and [design traceability](requirements/DESIGN.md) — gated by attack class. Counts live in the generated matrices, never in prose. |
| [`packages/`](packages/) | Shipped code, 11 packages: [`core`](packages/core) (record, canonical encoding, leaf, chain, tree, signer, store), [`collect-oma`](packages/collect-oma) (OMA journal and approval store), [`verify`](packages/verify) (the verifier and its CLI), [`mcp-proxy`](packages/mcp-proxy) (capture at the MCP seam), [`witnesses`](packages/witnesses) (the witness-set builder), and one package per witness type — [`witness-tlog`](packages/witness-tlog) (transparency-dev/witness), [`witness-tsa`](packages/witness-tsa) (RFC 3161), [`witness-ots`](packages/witness-ots), [`witness-rekor`](packages/witness-rekor), [`witness-self`](packages/witness-self) (the operator-hosted stateful witness), plus [`signer-aws-kms`](packages/signer-aws-kms) |
| [`spec/vectors/`](spec/vectors/) | Conformance vectors — [RFC 8785](spec/vectors/jcs.json), [RFC 6962](spec/vectors/merkle.json), [C2SP note key ids](spec/vectors/note.json) |
| [`bench/`](bench/) | The performance budgets, measured rather than asserted, with [committed results](bench/results/) the release notes cite by field |

## Getting started

Five entry points. Everything below is executed verbatim by the CLI contract test
(`test/cli-contract.test.mjs`), so a flag that is renamed, dropped or invented here is a
failing test rather than a manual that lies.

**Record.** `collect-oma` is a library, not a command: it is the journal and approval-store
backend you hand to `@open-multi-agent/core` (tested against 1.21.x). Every action the agent
takes is appended, salted and chained as it happens.

```js
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { SplitstickRunJournal } from '@splitstick/collect-oma';

const store = new Store('./evidence', 'host-1');
const collector = new Collector({
  store, config: parseConfig('version: 1\nstore: ./evidence\n', '.'),
  signer: await generateDevSigner('splitstick.dev/host-1'),
  collector: 'host-1', origin: 'splitstick.dev/host-1',
});
// `journal` is OMA's own, passed through: retention stays its job.
const journal = new SplitstickRunJournal({ collector });
```

For an agent you do not control the source of, sit in front of its MCP server instead and
record the tool calls as they cross the wire:

```bash
splitstick-mcp-proxy --upstream "node ./my-mcp-server.mjs" --out ./evidence
```

**Verify.** Offline — it opens files and does arithmetic. `--policy` is your acceptance
policy, not ours: whose countersignature you accept and what each one establishes. Two
readers with different policies get different, internally consistent answers from the same
evidence, which is the point (FR-30). `$SPLITSTICK_KEY` is the operator identity you pin,
printed by the collector when it starts.

```bash
splitstick-verify ./evidence --collector host-1 --key "$SPLITSTICK_KEY" --policy ./policy.json
```

**Coverage.** What fraction of a window is anchored, and to what. The window is explicit
because a coverage number without one is a claim about nothing.

```bash
splitstick-coverage ./evidence --from 2026-10-01 --to 2026-10-31 --collector host-1 --policy ./policy.json
```

**Disclose.** One event, and nothing else — not the run, not the neighbouring records. The
pack carries the inclusion proof and the signed root, so the recipient learns that this
event is in the tree without learning what else is. This needs a checkpoint some witness
has countersigned: an inclusion proof against a root only you signed establishes that you
are consistent with your own arithmetic, so FR-33 refuses to build the pack rather than
hand it over with a caveat somebody has to notice.

```bash
splitstick-disclose ./evidence --event 3 --collector host-1 --out ./disclosure.json
```

The recipient verifies it with no store, no network and no credential:

```bash
splitstick-disclose --verify ./disclosure.json --key "$SPLITSTICK_KEY" --policy ./policy.json
```

Working from a clone rather than an install, each command is also an npm script:
`npm run verify -- ./evidence --collector host-1`, and likewise `coverage`, `disclose` and
`mcp-proxy`.

**Exit codes**, because a pipeline reads these and an auditor reads the report. `0`, `1` and
`2` are always a *verdict* about evidence, and `3` is always a *refusal* of the invocation —
never a verdict. Nothing you typed wrong can come back as a finding about your evidence.

| | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| `verify` | ok | inconclusive | fail | refused | |
| `coverage` | complete | incomplete | inconclusive | refused | |
| `disclose --verify` | ok | fail | inconclusive | refused | |
| `mcp-proxy` | — | | | refused | upstream would not start |

## Working on it

```bash
npm install
npm test          # generate a fixture, then both tamper suites
npm run test:unit # the unit and conformance suites
npm run typecheck # JSDoc types over plain ESM, no build step
npm run bench     # the NFR-01 and NFR-02 budgets
npm run backlog   # revalidate requirements, regenerate the matrix and plan
npm run smoke     # pack the tarballs, install them into a clean project, run every bin
```

Node 20 or later. No build step: plain `.mjs` with JSDoc types checked by `tsc --checkJs`.
One runtime dependency in `core` (`yaml`, pinned exactly) and none in the verifier.

The backlog is data, not prose. `requirements/*.json` is the source of truth; `MATRIX.md`
and `PLAN.md` are generated. The validator rejects any requirement without a release-notes
section behind it and any release-1.0 requirement not assigned to a milestone — a
requirement cannot exist without a promise.

## What is closed, and what still stands

Two tamper suites run on every change. The first alters a genuine OMA journal and asks
OMA's own `verifyRun()`; the second builds a real Splitstick store from that same journal
and asks `splitstick verify`.

```
13 of 17 tampers are detected from files alone.
4 are not: C2, D, F3, G2.
With a stateful witness configured and its retained heights in the reader's hands,
16 of 17 are detected. Still open even then: G2.

gate AC-1   HELD from files alone        (A1, A2, A3, B, E)
gate AC-2   HELD from files alone        (C)
gate AC-3   HELD with a witness          (C2, C3)
gate AC-4   HELD with a witness          (D, D2)
gate AC-5   HELD with a witness          (F, F2, F3)
gate AC-6   HELD from files alone        (G)
            NOT CLOSED: G2
gate AC-7   HELD from files alone        (H, H2)
```

**The gap between those two numbers is the whole argument.** Three of the four tampers a
file-only reader misses — re-signing rewritten history, truncating the tail, erasing a
record and renumbering — are closed by a second party and by nothing else. None of them
needs new cryptography. A notary you supply to yourself is not a notary.

**One attack is not closed by anything in this release, and is in the suite on purpose:**

| | Attack | Why it stands |
|---|---|---|
| G2 | Patch the collector to suppress one action, keeping the cadence and the build digest | The heartbeats continue, the digest is the published one, the chain recomputes, and the action is simply absent. A self-reported digest is not remote attestation: the patched process controls what it reports. Coverage proves the heartbeat was continuous; it proves nothing about whether the process emitting that digest was the artifact the digest names. |

SEC-11, FR-25 and DOC-10 state that limit, and SCOPE-12 rejects remote attestation as the
fix. G2 is run as an attack so the limit is a measured result rather than a sentence in a
document — and it is why the verifier's `trusting` list says, unconditionally, that you are
trusting the operator for the **completeness** of what was captured. No witness discharges
that: a witness attests to the sequence and time of what it was *shown*, never to an action
the collector never observed.

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
Every figure below is committed as a result file the release notes cite by field, and a
claims guard refuses a published number that is not the measured one.

- **NFR-01, append overhead — met.** 1e6 events × 3 repeats: p95 **0.76 ms** and p99
  **2.61 ms** against budgets of 1 ms and 3 ms, taken on the **worst repeat** rather than
  the median, because an auditor runs it once. The p99 stretch target of 1 ms is not met,
  which the requirement states is a pass. Attribution rather than correlation: an
  open-descriptor write has a p99 of 0.04 ms while creating one file is p99 2.30 ms, so the
  append path creates none — measuring this rewrote the storage layout three times. GC is
  measured, not inferred, with the recorder verified against a deliberate allocation storm
  in the same run. Three host conditions are disclosed with the figure and the result
  reports `unconditional: false`: this is a laptop, and it says so.
- **NFR-02, added agent run latency — met against a real provider.** 24 interleaved pairs
  through OMA's real orchestrator to a real model, 96 live calls: added latency is at most
  **0.29%** of the measured 2,725 ms run, against a 2% budget. The denominator is measured,
  not assumed — an earlier version modelled it at 400 ms per call, and that assumption is
  why the requirement was reverted once. The figure is the interval's **upper bound**; the
  point estimate sits below this host's noise floor and would read as a speedup.
- **NFR-04, offline verification — met.** 100,000 events verified in **14.2 s** worst-run
  against a 30 s budget. The budget was revised from 2 s against a measurement: 1.2 s of it
  is the floor reading the journals imposes and JCS canonicalisation is ~1.9 s more, so the
  original figure was unreachable. Verification is offline and one-shot, and the revision is
  recorded in the requirement with the number that prompted it.

Two of those three budgets were revised off the back of measurement rather than reported as
missed, and both revisions carry the figure that forced them. A third thing was retracted
outright: a claim that overhead grows with run duration, which a better instrument showed
was noise.

## What is not proven

[`docs/splitstick-0.9.0-release-notes.md`](docs/splitstick-0.9.0-release-notes.md) leads with
this, and it is the part to read if you are evaluating rather than browsing.

- **No live qualified timestamp.** An operator can configure a qualified TSA, credential
  included, and the verifier reports the eIDAS presumption from their declaration about it.
  Nobody here has bought an account and anchored against one. A complete requirement count
  is not evidence that qualified timestamping has been demonstrated in a live deployment.
- **No witness this project does not operate.** The practice statement is anchored against a
  real transparency-dev/witness instance — an independent *implementation*, which we run.
  That is mechanism parity and a cosignature our own witness code did not produce; it is not
  independent custody.
- **Interoperability against one other implementation.** The tlog adapter talks to
  transparency-dev's Go witness, and that cost four defects to establish. It is one external
  reading of one document, not a conformance programme.
- **G2 stands**, as above.

## Resourcing

Unfunded: one person's time, no budget. No hosted witness, no accreditation, no certification
mark, and recognition rather than cash for findings — all stated in the
[release notes](docs/splitstick-1.0-release-notes.md) rather than left to be inferred.

The software is unaffected. Everything in this release is buildable and runnable at zero
cost. The shipped default anchors to a free RFC 3161 timestamp authority for time plus an
OpenTimestamps roll-up on a slow interval — **not** to a public transparency log. FR-48 keeps
a transparency log such as Rekor opt-in on purpose: a 10-second anchoring cadence against a
public good is not acceptable use, and choosing a witness without reading its terms is how a
project becomes a bad citizen of somebody else's infrastructure.

## Credit — DOC-06

Splitstick did not invent a protocol. The full attribution, with what each piece of upstream
work actually contributes, is in [NOTICE](NOTICE); the short version:

- **[open-multi-agent](https://github.com/open-multi-agent/open-multi-agent)** built the run-journal
  primitive and then documented exactly where it stopped, in a section titled "What it does not
  prove." Projects that oversell do not write that section.
- **[C2SP](https://c2sp.org)** designed the signed-note, `tlog-checkpoint` and `tlog-witness`
  formats this project adopts rather than reinvents — which is what lets somebody else implement
  a witness without asking us anything.
- **[Sigstore](https://www.sigstore.dev)** and **[Rekor](https://github.com/sigstore/rekor)**
  demonstrated that public, independently-witnessed append-only logs are operable at scale, and
  run the infrastructure the opt-in Rekor adapter submits to.
- **[Trillian](https://github.com/google/trillian)** and
  **[transparency-dev/witness](https://github.com/transparency-dev/witness)** are the log
  implementation the ecosystem was built on and the stateful witness whose refusal to cosign a
  shortened history is the only mechanism that closes the attack this project exists for.
- **Schneier and Kelsey**, *Secure Audit Logs to Support Computer Forensics* (1999) — the
  forward-secure hash-chained log, and the discipline of naming the custody assumption instead
  of hiding it.
- **RFC 8785**, **RFC 6962**, **RFC 3161** and
  **[OpenTimestamps](https://opentimestamps.org)** for the canonical encoding, the tree and its
  proofs, the timestamp token, and the free public anchor no company can withdraw.

## Not legal advice

**Not legal advice.** eIDAS is named above only to say where an engineering property stops:
the Article 41 presumption attaches through a **qualified** trust service and never through a
witness this project operates, and nothing in this release establishes it. Statutes are cited
here and in [the threat model](docs/threat-model.md) for orientation — to say which
engineering property is relevant to which regime, and where it ends. Nothing here is legal
advice, no conclusion about your obligations is offered, and nothing certifies anything about
your deployment. Consult your counsel.

## Licence

Apache-2.0, including the patent grant. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The open components — spec, wire format, test vectors, practice statement, both collectors —
will not be relicensed. A business built on trust cannot afford a licence people expect to
change.
