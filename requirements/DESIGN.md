# Design traceability matrix

Design elements are decisions with a specification: a format, an algorithm, a protocol, a schema. Requirements trace to them many-to-one. A requirement with no design element must be explicitly classified instead, so the absence is deliberate rather than an oversight. The chain is: release-notes promise -> requirement -> design element -> test.

**Generated — do not edit by hand.** Source of truth is `requirements/design.json`.
Regenerate with `npm run backlog`.

## Totals

| | Count |
|---|---:|
| Design elements | 20 |
| Release-1.0 requirements traced to a design element | 132 |
| Classified non-design | 61 |
| **Total 1.0** | **193** |

### Non-design classifications

| Kind | Count | Meaning |
|---|---:|---|
| policy | 33 | a stated rule and a recurring audit, with nothing to build |
| document | 17 | prose that must exist and be accurate |
| process | 7 | a repeatable procedure, often enforced in CI |
| audit | 4 | a check performed against the project itself |

## Design elements

### [DES-01 — Action record schema](../design/DES-01-action-record-schema.md)

**Milestone:** M1 · **Requirements covered:** 5

Which fields constitute an action record, their types, and what is deliberately excluded (no prompt, no conversation, no model output).

| Requirement | | Status |
|---|---|---|
| `FR-05` | Digest tool identity and arguments | ✅ |
| `FR-06` | Digest tool result | ✅ |
| `FR-07` | Digest approval decisions | ✅ |
| `FR-59` | Action record and chain entry are separate structures | ✅ |
| `FR-62` | Retries, timeouts and errors in the schema | ✅ |

### [DES-02 — Canonical encoding](../design/DES-02-canonical-encoding.md)

**Milestone:** M1 · **Requirements covered:** 2

Deterministic serialisation: recursive key ordering, array order preserved, number and null handling, and the rule that every field at every depth contributes to the digest.

| Requirement | | Status |
|---|---|---|
| `FR-52` | Canonicalisation completeness | ✅ |
| `SEC-07` | Resist consistent rewrite | ✅ |

### [DES-03 — Leaf and salt construction](../design/DES-03-leaf-and-salt.md)

**Milestone:** M1 · **Requirements covered:** 2

Salt length and source, leaf = H(salt || canonical), and where salts are stored so a disclosure can carry one without revealing others.

| Requirement | | Status |
|---|---|---|
| `FR-09` | Per-leaf salting | ✅ |
| `SEC-13` | Digest pre-image resistance in practice | ✅ |

### [DES-04 — Chain construction](../design/DES-04-chain-construction.md)

**Milestone:** M1 · **Requirements covered:** 5

h_i = H(h_(i-1) || leaf_i), the genesis value, sequence semantics, and what a verifier may conclude from a break.

| Requirement | | Status |
|---|---|---|
| `FR-08` | Predecessor chaining | ✅ |
| `SEC-06` | Resist action alteration | ✅ |
| `SEC-09` | Resist truncation | ☐ |
| `SEC-10` | Resist erasure and renumbering | ☐ |
| `FR-56` | Collector instance identity | ✅ |

### [DES-05 — Batching and Merkle tree](../design/DES-05-batching-and-merkle.md)

**Milestone:** M1 · **Requirements covered:** 6

Batch boundaries, tree shape, odd-leaf handling, and root computation — the construction that lets one action be disclosed without the rest.

| Requirement | | Status |
|---|---|---|
| `FR-32` | splitstick disclose | ☐ |
| `FR-33` | Inclusion proof binds to countersigned root | ☐ |
| `FR-34` | Optional batch padding | ☐ |
| `FR-53` | Roll-up anchoring | ☐ |
| `PRIV-06` | Disclosure minimisation | ☐ |
| `FR-69` | Padding is a record kind | ☐ |

### [DES-06 — Key hierarchy, signing and epoch ratchet](../design/DES-06-keys-and-ratchet.md)

**Milestone:** M1 · **Requirements covered:** 10

What an epoch is, how the signing key evolves, how the predecessor is destroyed, the KMS and HSM integration surface, and recovery after compromise.

| Requirement | | Status |
|---|---|---|
| `FR-10` | Batch signing with operator key | ✅ |
| `FR-11` | Forward-secure epoch ratchet | ☐ |
| `NFR-09` | HSM/KMS support | ☐ |
| `SEC-08` | Resist re-signing history | ☐ |
| `SEC-14` | Operator key never leaves operator | ✅ |
| `SEC-17` | State the forward-secrecy precondition | ☐ |
| `SEC-24` | Key compromise recovery | ☐ |
| `OPS-04` | Separation-of-duties guidance | ☐ |
| `FR-65` | Operator-declared key custody | ☐ |
| `FR-70` | Validate a provider custody attestation | ☐ |

### [DES-07 — Checkpoint format](../design/DES-07-checkpoint-format.md)

**Milestone:** M3a · **Requirements covered:** 4

The C2SP tlog-witness conformant checkpoint, its signed preimage, and how the operator identity and sequence appear in it.

| Requirement | | Status |
|---|---|---|
| `FR-12` | C2SP checkpoint emission | ☐ |
| `FR-45` | Witness stamps its own clock | ☐ |
| `INT-01` | C2SP conformance | ☐ |
| `SEC-25` | Witness time source | ☐ |

### [DES-08 — Witness protocol](../design/DES-08-witness-protocol.md)

**Milestone:** M3a · **Requirements covered:** 20

Submission and response, enrolment, per-operator sequence enforcement, countersignature contents, tree-head publication, key rotation, and every failure mode.

| Requirement | | Status |
|---|---|---|
| `FR-13` | Configurable witness set | ☐ |
| `FR-14` | Rekor witness adapter | ☐ |
| `FR-16` | RFC 3161 TSA adapter | ☐ |
| `FR-17` | Operator-hosted witness adapter | ☐ |
| `FR-19` | Configurable quorum | ☐ |
| `FR-20` | Configurable anchor cadence | ☐ |
| `FR-21` | Soft anchor tier | ☐ |
| `FR-22` | Hard anchor tier | ☐ |
| `FR-42` | Operator enrolment | ☐ |
| `FR-43` | Witness verifies consistency, not increments | ☐ |
| `FR-44` | Witness retains roots | ☐ |
| `FR-50` | Witness publishes signed tree heads | ☐ |
| `FR-51` | Witness key rotation | ☐ |
| `FR-15` | transparency-dev/witness adapter | ☐ |
| `FR-48` | Shipped default witness configuration | ☐ |
| `INT-02` | Verify third-party countersignatures | ☐ |
| `SEC-15` | Witness sees roots only | ☐ |
| `PRIV-01` | Zero content egress | ☐ |
| `FR-26` | Gap declarations with an exact span | ☐ |
| `FR-27` | Countersigned gap declarations | ☐ |

### [DES-09 — Policy files](../design/DES-09-policy-files.md)

**Milestone:** M1 · **Requirements covered:** 6

Two separate schemas: the collector's witness set, and the verifier's acceptance policy. Plus how a policy change is recorded as a chain event.

| Requirement | | Status |
|---|---|---|
| `FR-41` | Configuration file | ✅ |
| `FR-30` | Acceptance policy as input | ☐ |
| `FR-23` | Policy changes as chain events | ☐ |
| `SEC-12` | Resist policy downgrade | ☐ |
| `SCOPE-15` | Hard anchor must be disableable | ☐ |
| `NFR-03` | Default mutability window | ☐ |

### [DES-10 — Coverage model](../design/DES-10-coverage-model.md)

**Milestone:** M4 · **Requirements covered:** 7

Heartbeat cadence and contents, the build digest, gap declaration semantics, and precisely what the claim "100% captured between T1 and T2" asserts.

| Requirement | | Status |
|---|---|---|
| `FR-24` | Signed heartbeats | ☐ |
| `FR-25` | Build digest in heartbeat | ☐ |
| `FR-28` | splitstick coverage | ☐ |
| `FR-40` | Late anchors reported as gaps | ☐ |
| `SEC-11` | Resist collector stoppage | ☐ |
| `DOC-10` | Document the collector-patch limit | ☐ |
| `FR-64` | Collector self-reported configuration attestation | ☐ |

### [DES-11 — Evidence pack format](../design/DES-11-evidence-pack-format.md)

**Milestone:** M3a · **Requirements covered:** 2

The artifact an auditor receives: records, salts, inclusion paths, every countersignature collected, and the public keys needed to check them.

| Requirement | | Status |
|---|---|---|
| `FR-31` | Evidence pack carries all countersignatures | ☐ |
| `INT-03` | Documented evidence pack format | ☐ |

### [DES-12 — Verification algorithm](../design/DES-12-verification-algorithm.md)

**Milestone:** M1 · **Requirements covered:** 9

The ordered checks, the verdict taxonomy including an inconclusive outcome, and what each distinct failure permits a reader to conclude.

| Requirement | | Status |
|---|---|---|
| `FR-29` | splitstick verify | ✅ |
| `NFR-04` | Verification throughput | ☐ |
| `NFR-05` | No network at verification | ☐ |
| `NFR-06` | No credentials at verification | ☐ |
| `SEC-03` | No trust in operator or vendor | ☐ |
| `SEC-04` | One honest witness assumption | ☐ |
| `FR-57` | Verifier states witness-set capabilities | ☐ |
| `FR-63` | Pinned operator identity | ☐ |
| `FR-66` | Compare expected witnesses against proofs present | ☐ |

### [DES-13 — Storage and erasure](../design/DES-13-storage-and-erasure.md)

**Milestone:** M1 · **Requirements covered:** 8

The content store, pointer scheme, crypto-shredding procedure, and how retention is configured without touching the cryptography.

| Requirement | | Status |
|---|---|---|
| `FR-35` | Payloads are content-addressed and externalised | ✅ |
| `FR-36` | Crypto-shredding | ☐ |
| `FR-37` | Retention policy on storage | ☐ |
| `PRIV-02` | No content in the chain | ✅ |
| `PRIV-03` | Erasure via crypto-shredding | ☐ |
| `PRIV-04` | Chain survives erasure | ☐ |
| `PRIV-05` | Minimal retained artefacts | ☐ |
| `PRIV-09` | Operator-controlled retention | ☐ |

### [DES-14 — Collector architecture](../design/DES-14-collector-architecture.md)

**Milestone:** M1 · **Requirements covered:** 10

The shared capture core, the OMA backend, the MCP proxy, and where the capture boundary sits in each.

| Requirement | | Status |
|---|---|---|
| `FR-01` | OMA journal backend | ✅ |
| `FR-02` | OMA approval-store backend | ✅ |
| `FR-03` | MCP proxy collector (stdio) | ☐ |
| `FR-04` | MCP proxy collector (HTTP) | ☐ |
| `INT-04` | Additive OMA integration | ✅ |
| `INT-05` | Framework-agnostic capture | ☐ |
| `INT-07` | No agent code changes | ✅ |
| `FR-46` | Conformance test suite | ☐ |
| `FR-47` | Witness list as data | ☐ |
| `INT-06` | Reuse rather than reimplement | ☐ |

### [DES-15 — Failure and availability model](../design/DES-15-failure-and-availability.md)

**Milestone:** M3b · **Requirements covered:** 11

Fail-open behaviour, the durable queue, retry and backoff, late countersignature handling, and the guarantee that the collector can never block a run.

| Requirement | | Status |
|---|---|---|
| `FR-38` | Fail-open with marked batch | ☐ |
| `FR-39` | Late countersignature records real time | ☐ |
| `NFR-12` | Never degrade availability | ☐ |
| `NFR-13` | Durable local queue | ☐ |
| `OPS-02` | Queue drain and retry | ☐ |
| `OPS-06` | Witness store durability | ☐ |
| `SCOPE-16` | No fail-closed option | ☐ |
| `FR-58` | Reserved slot for gap declarations | ☐ |
| `FR-60` | Unknown-loss intervals | ☐ |
| `FR-61` | Observation counter durability | ☐ |
| `FR-68` | Unwitnessed outage ceiling | ☐ |

### [DES-16 — Format versioning and algorithm agility](../design/DES-16-format-versioning.md)

**Milestone:** M1 · **Requirements covered:** 4

Version negotiation in the record and pack, and the migration path when a hash or signature algorithm must change.

| Requirement | | Status |
|---|---|---|
| `NFR-07` | Long-term verifiability | ✅ |
| `NFR-08` | Node.js 20+ | ☐ |
| `NFR-10` | OMA version compatibility | ☐ |
| `NFR-11` | MCP transport coverage | ☐ |

### [DES-17 — Release and provenance pipeline](../design/DES-17-release-and-provenance.md)

**Milestone:** M1 · **Requirements covered:** 5

Build reproducibility, provenance attestation, release signing, SBOM generation, and how a heartbeat's build digest is traced back to source.

| Requirement | | Status |
|---|---|---|
| `SEC-22` | Build provenance attestation | ✅ |
| `SEC-23` | Signed releases and SBOM | ✅ |
| `NFR-01` | Low-overhead evidence capture | ☐ |
| `NFR-02` | Run latency budget | ✅ |
| `FR-49` | Documented CLI contract | ☐ |

### [DES-18 — Witness practice statement structure](../design/DES-18-practice-statement-structure.md)

**Milestone:** M3b · **Requirements covered:** 12

What the countersignature asserts and disclaims, how the statement is versioned and anchored, and how the time discipline is declared.

| Requirement | | Status |
|---|---|---|
| `LEG-01` | Publish a Witness Practice Statement | ☐ |
| `LEG-02` | WPS asserts receipt time | ☐ |
| `LEG-03` | WPS asserts successor ordering | ☐ |
| `LEG-04` | WPS asserts retention | ☐ |
| `LEG-05` | WPS disclaims occurrence | ☐ |
| `LEG-06` | WPS disclaims truthfulness | ☐ |
| `LEG-07` | WPS disclaims completeness | ☐ |
| `LEG-08` | WPS disclaims lawfulness | ☐ |
| `LEG-09` | WPS versioned and anchored | ☐ |
| `LEG-19` | WPS states the time discipline | ☐ |
| `OPS-03` | Self-hosted witness deployment guide | ☐ |
| `OPS-05` | Zero-egress mode | ☐ |

### [DES-19 — Detection without a stateful witness](../design/DES-19-detection-without-a-witness.md)

**Milestone:** M1 · **Requirements covered:** 4

Two mechanisms that narrow attack classes 4 and 5 when no stateful witness is configured: cross-pack comparison, which turns every disclosure into a permanent constraint; and counterparty reconciliation, which is the only free answer to omission.

| Requirement | | Status |
|---|---|---|
| `FR-54` | Cross-pack consistency verification | ☐ |
| `FR-55` | Counterparty reference capture | ✅ |
| `SEC-26` | Resist truncation below a disclosed height | ☐ |
| `DOC-09` | Reconciliation guidance | ☐ |

### [DES-20 — Countersignature envelope](../design/DES-20-countersignature-envelope.md)

**Milestone:** M3a · **Requirements covered:** 3

How proofs in three incompatible formats — C2SP note signature lines, DER RFC 3161 timestamp tokens, and OpenTimestamps proofs — are carried over one checkpoint and verified, since a TSA cannot sign a signed note and an OTS proof is not a signature at all.

| Requirement | | Status |
|---|---|---|
| `FR-12` | C2SP checkpoint emission | ☐ |
| `FR-31` | Evidence pack carries all countersignatures | ☐ |
| `INT-02` | Verify third-party countersignatures | ☐ |

## Requirements with no design element

Deliberate, not an oversight. Each is a rule, a document, a procedure or a check.

### policy — 33

- `SCOPE-01` No blocking or gating
- `SCOPE-02` No tamper-proof claim
- `SCOPE-03` No compliance certification
- `SCOPE-04` Not an observability platform
- `SCOPE-05` No reviewer UI in OSS
- `SCOPE-06` No SSO in OSS
- `SCOPE-07` No RBAC in OSS
- `SCOPE-08` No multi-tenancy in OSS
- `SCOPE-09` No retention tiers in OSS
- `SCOPE-10` No verifiable delay function
- `SCOPE-11` No ZK compliance proofs
- `SCOPE-12` No TEE suppression claim
- `SCOPE-13` No blockchain as ledger
- `SCOPE-14` No self-scored defeat metric
- `SEC-16` Bounded integrity claim
- `SEC-20` Coordinated disclosure window
- `SEC-21` Publish unmitigated findings
- `GOV-04` Non-relicensing commitment
- `GOV-05` Third-party witnesses permitted
- `GOV-09` No gatekeeping of the witness list
- `GOV-10` Bounty: one class, one payout
- `GOV-11` Bounty: default configuration only
- `GOV-12` Bounty: scope binding both ways
- `GOV-13` Bounty: recognition, not cash
- `GOV-14` Bounty: first reporter wins
- `GOV-15` Bounty: no adjudication while unfunded
- `GOV-17` Bounty: cash deferred until funded
- `LEG-14` No conformity claims
- `LEG-15` No certification of the customer
- `LEG-16` Not-legal-advice disclaimer
- `LEG-12` eIDAS presumption only via qualified TSA
- `LEG-13` Qualified TSA configurable
- `LEG-18` Trademark clearance

### document — 17

- `DOC-01` Public red-team suite
- `DOC-02` Threat model document
- `DOC-03` Considered-and-rejected rationale
- `DOC-04` Label targets as targets
- `DOC-05` Publish honest limits
- `DOC-06` Upstream attribution
- `DOC-07` Document the two-policy split
- `DOC-08` Publish bounty terms
- `SEC-01` Published threat model
- `SEC-02` Detection, not prevention
- `SEC-05` Documented exclusions
- `PRIV-07` Disclose the tree-size leak
- `PRIV-08` Disclose the cadence leak
- `GOV-16` Published review history
- `GOV-19` State the resourcing honestly
- `GOV-03` Open component set
- `DOC-11` Every assurance claim names its evidence

### process — 7

- `GOV-01` Apache-2.0 with patent grant
- `GOV-02` DCO on contributions
- `GOV-06` Open conformance suite
- `GOV-08` Witness list by pull request
- `GOV-18` Accept third-party attack classes
- `SEC-19` Bounty intake and triage
- `TRC-03` Red-team canary in CI

### audit — 4

- `TRC-01` Every requirement traces to a promise
- `TRC-02` Every requirement has a verification method
- `TRC-04` Benchmark before claiming
- `TRC-05` Claims audit per release

