# DES-14 — Collector architecture

**Milestone:** M1 · **Covers:** FR-01, FR-02, FR-03, FR-04, FR-46, FR-47, INT-04, INT-05, INT-06, INT-07

## Decision

One core, thin adapters. The core owns everything an auditor depends on; an adapter only knows
how to notice that something happened.

```
@splitstick/core          record schema, JCS, leaf, chain, tree, signer iface, store, queue
   ├── @splitstick/collect-oma    RunJournal + approval-store impls        FR-01, FR-02
   ├── @splitstick/mcp-proxy      stdio + HTTP interception                FR-03, FR-04
   ├── @splitstick/verify         the verifier (depends on core, nothing else)
   ├── @splitstick/signer-*       AWS KMS, PKCS#11 adapters                FR-10, NFR-09
   └── @splitstick/witness-*      TSA, OpenTimestamps, self-hosted, Rekor adapters
```

A signer adapter is a separate package for the same reason a witness adapter is,
and one more: it needs a cloud SDK, and `@splitstick/verify` depends on core.
NFR-05 and NFR-06 require the verifier to be offline by construction, so a
transitive SDK dependency in core would contradict that even if the verifier
never called it. Core holds the `sign(bytes) → signature` seam and nothing that
reaches a network.

**An adapter may not touch cryptography.** It produces a DES-01 action record and hands it to
core. This is what makes the record format adapter-independent, so a verifier never needs to know
which collector wrote a pack — and it means adding a collector cannot introduce an integrity bug.

## The two capture boundaries

| | Where it sits | Sees |
|---|---|---|
**OMA** (FR-01, FR-02) | in-process, implementing OMA's own interfaces | tool calls, results, approval decisions, as OMA emits them |
**MCP proxy** (FR-03, FR-04) | between the agent and its MCP servers | every tool call and result crossing the protocol |

They overlap deliberately. The OMA backend is deeper — it sees approvals the protocol never
carries. The proxy is broader — it works for any runtime, including ones with no journal at all,
which is what stops the project depending on a single upstream.

The proxy is also where **bilateral receipts** become possible in 2.0 (RM-01): it is the one
boundary where both parties to an action are present. That is why it is in 1.0 rather than later,
even though the OMA backend alone would ship sooner.

## INT-04 — additive, never a fork

The OMA integration is a dependency plus a config line. No patch, no vendored copy, no upstream
pull request, and nothing that breaks when OMA releases. Verified by installing against
unmodified upstream at the supported version.

## INT-07 — no agent code changes

Both adapters integrate by dependency and configuration only. Verified literally: the test
asserts the agent's source files are **byte-identical** before and after integration.

## INT-06 — reuse, do not reimplement

Stated as a design constraint so it is auditable: JCS from RFC 8785, the tree from RFC 6962,
checkpoints from C2SP, signatures from `node:crypto`, timestamps from RFC 3161, anchoring from
existing public services. **This project writes no cryptographic primitive and operates no
transparency log.** A dependency review at each release checks that this is still true.

## FR-46, FR-47 — conformance and the witness list

The conformance suite (FR-46) runs against any witness implementation, including competitors', so
an implementer can self-check without asking permission. The witness list (FR-47) is a data file
in which each entry records its **acceptable-use terms, rate limits and whether it retains
entries publicly** — because the Rekor episode showed that choosing a witness without reading its
terms is how a project becomes a bad citizen of someone else's infrastructure.
