# Delivery plan — Splitstick 1.0

193 release-1.0 requirements sequenced into 9 milestones, gated by the attack-class
table in [the release notes](../docs/splitstick-1.0-release-notes.md).

**Generated — do not edit by hand.** Source of truth is `requirements/milestones.json`.
Regenerate with `npm run plan`.

The rule: **no milestone is complete until its attack classes fail closed against our own
verifier.** Not a code review, not a demo — the red-team suite, with that class's expectation
flipped from `undetected` to `detected`.

Every milestone runs the complete red-team suite, not only its own classes. A gate closed earlier that reopens fails the build.

## Attack-class gates

| Gate | Class | Closed by | Red-team |
|---|---|---|---|
| `AC-1` | Alter the recorded action — arguments, result, approval decision | M1 Local integrity | A (local) |
| `AC-2` | Alter an event and repair the citing digest | M1 Local integrity | C (B must not regress) (local) |
| `AC-3` | Re-sign rewritten history with the current key | M3a Anchoring and sequencing | ratchet suite (local + HSM) |
| `AC-4` | Truncate the record's tail | M3a Anchoring and sequencing | D (external) |
| `AC-5` | Erase events and renumber into a clean stream | M3a Anchoring and sequencing | E, F (external) |
| `AC-6` | Stop or patch the collector, then claim quiet | M4 Coverage attestation | G (new) (external) |
| `AC-7` | Weaken the anchoring policy, then tamper | M4 Coverage attestation | H (new) (external) |

## Sequence

| Milestone | Gate | Reqs | Weeks | Goal |
|---|---|---:|---|---|
| **M0** Foundations and long-lead | — | 15 | 1-2, parallel to M1 | Start everything whose clock runs outside engineering, and turn the red-team suite into the acceptance harness. |
| **M1** Local integrity | AC-1, AC-2 | 29 | 3-4 | Close the two attack classes that need no third party, and measure the performance budget before the design hardens. |
| **M2** Key custody | — | 5 | 2 | Make yesterday's record unforgeable with today's key, and state the precondition honestly. |
| **M3a** Anchoring and sequencing | AC-3, AC-4, AC-5 | 38 | 5-7 | The first second party. Close truncation and erasure, which no amount of local cryptography can reach. |
| **M3b** Practice statement and resilience | — | 22 | 3-4 | Say exactly what the countersignature means, and make sure losing a witness does not lose the evidence. |
| **M4** Coverage attestation | AC-6, AC-7 | 11 | 3-4 | The differentiated claim: prove the record is complete, not merely unaltered. |
| **M5** Disclosure and erasure | — | 17 | 3-4 | No new attack class. This is the milestone that makes the product buyable by a regulated, multi-customer organisation. |
| **M6** Reach and conformance | — | 19 | 4-6 | Stop depending on one upstream project, and make the format genuinely somebody else's to implement. |
| **M7** Launch gate | — | 37 | 2 | Every promise that is a claim rather than a feature. This milestone is mostly about what we must not say. |
| | | **193** | | |

## Milestones

### M0 — Foundations and long-lead

Start everything whose clock runs outside engineering, and turn the red-team suite into the acceptance harness.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 15 (GOV×7  TRC×3  SEC×3  LEG×1  DOC×1)
- **Effort:** weeks 1-2, parallel to M1
- **Exit criteria:** Trademark search returned and recorded. Counsel engagement deferred to a funded release. Threat model published. CI runs the canary, the DCO check and all three validators. Harness inverted so each attack class can assert DETECTED against our own verifier. Bounty adjudication removed rather than outsourced, so no arbiter is required.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ✅ `GOV-01` | **Apache-2.0 with patent grant** — Licence all open components under Apache-2.0. | LICENSE present; headers applied |
| ✅ `GOV-02` | **DCO on contributions** — Require Signed-off-by on all contributions. | CI check enforces the trailer |
| ✅ `GOV-03` | **Open component set** — Keep the spec, wire format, test vectors, practice statement, both collectors AND the witness implementation open. The witness is in the open set because the self-hosting story is load-bearing: the operator must supply the second party, and cannot do so from a binary they are not permitted to read. | Repository inventory lists every component above under the open licence, witness included |
| ✅ `GOV-04` | **Non-relicensing commitment** — Publish a commitment never to relicense the open components. | Commitment published in the repository |
| ✅ `GOV-16` | **Published review history** — Maintain a public record of what was added, cut and rewritten across revisions. | Section present and updated per revision |
| ✅ `GOV-15` | **Bounty: no adjudication while unfunded** — Publish every reported finding and credit every reporter, whether or not the project considers the class novel. With nothing withheld there is nothing to adjudicate, so no arbiter is required. An independent arbiter becomes necessary only if a cash award is ever introduced. | Terms published stating that all findings are published and all reporters credited, with no novelty test |
| ✅ `LEG-18` | **Trademark clearance** — Complete a free knockout search on the public registers and on npm, GitHub and domains before the name is relied on. Registration is deferred to a funded release. | Search record committed to the repository |
| ✅ `DOC-02` | **Threat model document** — Publish the threat model as a maintained document. | Document present, versioned |
| ✅ `TRC-01` | **Every requirement traces to a promise** — Each requirement names the release-notes section that promises it; orphans are rejected. | Validator fails on a missing source |
| ✅ `TRC-02` | **Every requirement has a verification method** — Each requirement names how it will be verified. | Validator fails on a missing verify field |
| ✅ `TRC-03` | **Red-team canary in CI** — The tamper suite runs in CI and fails the build when an observation changes. | CI job present and failing on drift |
| ✅ `SEC-01` | **Published threat model** — Publish a threat model naming the operator as the adversary. | Document exists and is referenced from the README |
| ✅ `SEC-02` | **Detection, not prevention** — The stated security goal is detection and attribution, not prevention. | Claims review against documentation and marketing |
| ✅ `SEC-05` | **Documented exclusions** — Publish what is out of scope: actions never attempted, a compromised model, a lying tool, full quorum collusion, a key exfiltrated before first use. | Document review |
| ✅ `GOV-19` | **State the resourcing honestly** — Publish that the project is unfunded and what that means: no hosted witness, no accreditation, no certification mark, and recognition rather than cash. Stated plainly rather than implied by omission. | Section present in the release notes and the README |

### M1 — Local integrity

Close the two attack classes that need no third party, and measure the performance budget before the design hardens.

- **Gate:** `AC-1` — Alter the recorded action — arguments, result, approval decision; `AC-2` — Alter an event and repair the citing digest
- **Requirements:** 29 (FR×16  SEC×6  NFR×3  INT×2  PRIV×1  DOC×1)
- **Effort:** weeks 3-4
- **Exit criteria:** Red-team A and C both DETECTED by splitstick verify; baseline still passes. p99 append overhead measured under 1 ms and run latency under 2% — measured, not assumed. Chain files contain no plaintext. First package published with a provenance attestation and an SBOM, so the build digest M4 relies on can be traced to its source.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ✅ `FR-01` | **OMA journal backend** — Provide a RunJournal implementation for @open-multi-agent/core, installable as a dependency and enabled by configuration alone. | Integration test: journal written through OMA orchestrator |
| ✅ `FR-02` | **OMA approval-store backend** — Provide an approval-store implementation for OMA so approval requests and decisions enter the same record. | Integration test: suspend/approve/resume cycle recorded |
| ✅ `FR-05` | **Digest tool identity and arguments** — Record and digest the tool name and its invocation arguments. | Red-team attack A fails closed |
| ✅ `FR-06` | **Digest tool result** — Record and digest the tool result content. | Red-team attack A fails closed |
| ✅ `FR-07` | **Digest approval decisions** — Record and digest approval decisions, including the deciding identity as supplied. | Unit test: decision tamper detected |
| ✅ `FR-08` | **Predecessor chaining** — Every event carries a cryptographic digest of its predecessor. | Red-team attacks B, C, F fail closed |
| ✅ `FR-09` | **Per-leaf salting** — Every leaf is salted with a per-leaf random nonce before hashing. | Unit test: identical content yields distinct digests |
| ✅ `FR-10` | **Batch signing with operator key** — Sign each batch root with the operator-supplied key. | Signature verifies under operator public key |
| ✅ `FR-29` | **splitstick verify** — Verify chain integrity, batch signatures and witness countersignatures from files alone. | All red-team classes fail closed; baseline passes |
| ✅ `FR-35` | **Payloads are content-addressed and externalised** — No payload enters the chain. Every argument and result is replaced by a salted content digest, cid = H(0x05 \|\| content_salt \|\| plaintext), and the plaintext is stored encrypted in the deletable store. Substituting a payload while preserving its pointer is therefore impossible, and deleting the salt, key and ciphertext leaves an unlinkable commitment. | Payload-substitution test: replacing stored content without changing the cid fails verification. Automated scan asserts no payload bytes appear anywhere in the chain |
| ✅ `FR-41` | **Configuration file** — Support splitstick.yaml with store, signer, anchor_interval, rollup_interval, heartbeat_interval, on_unavailable, witnesses, quorum and unwitnessed_ceiling keys. | The documented example config is loaded in test and each key asserted to take effect; heartbeat_interval is present because it sets the resolution of every coverage claim |
| ☐ `NFR-01` | **Low-overhead evidence capture** — Splitstick must add no more than 1 ms per event at p95 and 3 ms per event at p99 on a defined reference environment, measured over at least one million representative events across multiple benchmark runs. Measurements must include content commitment, encryption and local persistence, exclude deferred checkpoint and witness operations, and report sustained throughput and memory behaviour. The engineering stretch target remains p99 below 1 ms. Durability and integrity are never traded for latency: no deferring a critical write without guaranteed recovery, no weakening source-sequence or failure reporting, no removing encryption or commitment checks, and no uncontrolled buffering to improve a benchmark. | Benchmark harness on the reference environment defined in bench/reference-env.json: p95 and p99 over at least 1e6 events, at least three repeats, reporting p50/p95/p99/p99.9, throughput, memory and GC activity. The harness declares each run an acceptance measurement or a regression metric and names every shortfall, and it verifies its own instruments — clock resolution and the GC recorder — in the same run. A run that meets p95 but not the p99 stretch target is a pass against the budget and is reported as such. |
| ✅ `NFR-02` | **Run latency budget** — Added end-to-end agent run latency below 2%. | Interleaved A/B through the real OMA orchestrator, analysed as a paired difference because the arms alternate run by run. The verdict requires the whole 95% interval to sit below the budget; a budget falling inside the interval is reported as UNRESOLVED rather than as a pass. The harness records its environment and checks its clock resolution. |
| ✅ `SEC-06` | **Resist action alteration** — Altering recorded arguments, result or approval decision must be detectable. | Red-team class A |
| ✅ `SEC-07` | **Resist consistent rewrite** — Altering an event and repairing its citing digest must be detectable. | Red-team class C |
| ✅ `SEC-13` | **Digest pre-image resistance in practice** — Salting must prevent brute-force recovery of low-entropy action records from their digests. | Dictionary attack against salted digests fails |
| ✅ `SEC-14` | **Operator key never leaves operator** — Splitstick must never hold, receive, request or log the operator signing key. | Automated egress capture during a representative run asserts no private key material leaves the host; plus a code check that no verifier or collector module imports a key-export API |
| ✅ `PRIV-02` | **No content in the chain** — The chain contains no payload bytes at all — not merely no oversized ones. Records in the chain carry metadata and salted content digests; every argument and result lives in the deletable store, so there is nothing in the chain that erasure cannot reach. | Automated scan of chain files for any payload string from the fixture finds nothing, including short inline-sized arguments |
| ✅ `INT-04` | **Additive OMA integration** — Integrate with OMA without a fork, patch or upstream pull request. | Install against unmodified upstream at the supported version |
| ✅ `DOC-01` | **Public red-team suite** — Maintain a public tamper suite reproducible in two commands. | Clean-clone run succeeds |
| ✅ `NFR-07` | **Long-term verifiability** — Evidence remains verifiable years later; algorithms and formats are versioned to allow it. | Format version negotiation test; documented algorithm migration path |
| ✅ `INT-07` | **No agent code changes** — Both collectors integrate by dependency and configuration only; no change to the customer's agent code is required. | Byte-identical agent source before and after integration, for both collectors |
| ✅ `SEC-22` | **Build provenance attestation** — Publish a provenance attestation for every released collector artifact, binding the digest to its source commit and build, so the digest in a heartbeat can be independently traced. | Attestation verifies against the published artifact and source revision |
| ✅ `SEC-23` | **Signed releases and SBOM** — Sign every release and publish an SBOM with pinned dependencies. | Signature and SBOM present and verified in CI for each release |
| ✅ `FR-52` | **Canonicalisation completeness** — The canonical encoding must cover every field of the action record at every nesting depth. A test must prove that mutating any single field, at any depth, changes the leaf digest. | Property test mutating each field in turn, including nested argument keys; every mutation must change the digest |
| ✅ `FR-55` | **Counterparty reference capture** — Extract externally issued identifiers from a tool result and index them for reconciliation. The index lives in the deletable content store, never in the chain, because a transaction reference can itself be identifying. | A result containing an external reference is indexed and queryable; the index is removed by crypto-shredding |
| ✅ `FR-56` | **Collector instance identity** — Each collector instance has a stable identity that scopes its chain and its log origin. Records carry the run they belong to as a field; the chain itself is collector-scoped, so concurrent runs interleave in one log and heartbeats need no run at all. | Two concurrent runs produce one contiguous chain with correct run tags; a heartbeat emitted with no run active is chained and anchored |
| ✅ `FR-59` | **Action record and chain entry are separate structures** — The canonicalised, hashed ActionRecord is immutable and contains no chain metadata. prev, leaf and head live in a ChainEntry wrapper that is never canonicalised, so the digest of a record can never depend on a value derived from it. Conformance vectors publish the exact bytes hashed. | Conformance vectors: given a fixed ActionRecord, the canonical bytes, leaf and head are byte-exact. A test asserts no chain field appears inside the canonicalised subject |
| ✅ `FR-62` | **Retries, timeouts and errors in the schema** — The record schema represents a failed, timed-out or retried tool call explicitly: an outcome enum, an attempt number, and a correlation id grouping attempts of one logical action. source_seq advances once per observed ATTEMPT, not per logical action, because a timed-out attempt may already have caused an external side effect and must stay independently accountable. Correlation, not the counter, is what groups attempts. The correlation identifier is opaque and randomly generated, never derived from a payload, user or session, because it is retained after erasure. | Interleaved retries across two correlations keep source_seq strictly increasing; an omitted retry is detected as a source_seq gap; coverage reports attempt count and logical-action count separately |

### M2 — Key custody

Make yesterday's record unforgeable with today's key, and state the precondition honestly.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 5 (SEC×2  FR×1  NFR×1  OPS×1)
- **Effort:** weeks 2
- **Exit criteria:** An epoch-N key cannot produce a valid epoch-N-1 signature. The succession chain walks from a pinned root and a skipped or self-endorsing epoch is refused. The non-exportable custody precondition appears wherever the forward-secrecy claim does, and the verifier refuses the claim outright for any epoch declared software-keyed. M2 closes no attack class on its own: AC-3 needs the countersignature and is carried to M3a.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ✅ `FR-11` | **Forward-secure epoch ratchet** — Evolve the signing key per epoch and destroy the predecessor so prior entries cannot be re-signed with the current key. | Test: epoch N key cannot produce a valid epoch N-1 signature; the succession chain walks from a pinned root across 64 epochs, and a skipped epoch, a wrong-predecessor endorsement, a self-endorsement, a fork and an unpinned root are each refused |
| ☐ `NFR-09` | **HSM/KMS support** — Operate with a KMS or HSM offering non-exportable keys. | Integration test against at least one KMS and one HSM. The KMS half runs via npm run test:kms against a real ECC_NIST_EDWARDS25519 key and asserts the signature verifies under an independent Ed25519 implementation, not only under ours; it reports NOT VERIFIED and skips when no key is configured, so a green suite never reads as having verified it. |
| ✅ `SEC-08` | **Resist re-signing history** — Re-signing rewritten history with the current key must be detectable under non-exportable custody. | Epoch-ordering test: a checkpoint re-signed by a later epoch than a later checkpoint emits OPSIG_EPOCH_REGRESSED. A WHOLESALE re-sign is NOT caught locally and the report says so — that half is AC-3, carried to M3a |
| ✅ `SEC-17` | **State the forward-secrecy precondition** — Any forward-secrecy claim must state its non-exportable key custody precondition in the same place. | Executable, not a documentation review: tools/lint-claims.mjs fails the build on any paragraph claiming forward secrecy without its precondition in the same paragraph, and the verifier report attaches both declarations to the claim |
| ✅ `OPS-04` | **Separation-of-duties guidance** — Document the key-custody split between engineering and internal audit. | Guide published at docs/key-custody.md, stating the engineering/internal-audit key split, that nothing enforces it, and that one person holding both keys makes the split absent rather than weaker |

### M3a — Anchoring and sequencing

The first second party. Close truncation and erasure, which no amount of local cryptography can reach.

- **Gate:** `AC-3` — Re-sign rewritten history with the current key; `AC-4` — Truncate the record's tail; `AC-5` — Erase events and renumber into a clean stream
- **Requirements:** 38 (FR×25  SEC×7  INT×2  NFR×1  PRIV×1  SCOPE×1  DOC×1)
- **Effort:** weeks 5-7
- **Exit criteria:** Red-team C2, D, E and F all DETECTED. A run with no configuration at all anchors to a public log the project does not operate. A rolled-back witness is detected. An auditor supplying their own acceptance policy verifies the same pack. Egress captured against real witness traffic, confirming no content leaves the host. AC-3 closes here rather than in M2, because a re-signed history is contradicted by a countersignature over the original root and by nothing local.
- **Carried in for closure:** `NFR-09`

> **Carried from M2 — `NFR-09` HSM/KMS support**
>
> Carried into M3a from M2 and NOT closed here. The KMS half is built and covered (packages/signer-aws-kms) and needs only the operator's key to run. The HSM half is blocked by evidence rather than effort and nothing in M3a changed that: of the products that sign Ed25519, AWS KMS issues no per-key attestation and GCP offers the algorithm at software protection level only, so independently-supported custody still requires hardware, and the YubiHSM 2 purchase is held. FR-70's validator now exists and is correct, but it has only ever been run against documents this project constructed — every result carries provider_untested: true to say so. See docs/kms-capability-matrix.md and docs/m3a-failure-modes.md.
>
> *Closes when:* A hardware signer behind the same sign(bytes) seam, with an integration test proving its signature verifies under an independent Ed25519 implementation, and FR-70's five checks exercised against a REAL provider attestation rather than a constructed one. M7 is the right home because the launch gate is where every published claim has to have evidence behind it, and 'operate with a KMS or HSM' is a published claim.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ✅ `FR-12` | **C2SP checkpoint emission** — Emit checkpoints in C2SP tlog-witness conformant format. | Checkpoint is a C2SP note inside a DES-20 envelope; packages/core/test/c2sp-conformance.test.mjs asserts the wire format against the spec as written |
| ✅ `FR-13` | **Configurable witness set** — Submit roots to a configurable list of witnesses rather than a single endpoint. | witnessesFromConfig builds the set from config.witnesses; an unknown type is refused rather than skipped |
| ✅ `FR-14` | **Rekor witness adapter** — Support Rekor as a witness type. | Rekor adapter with fetch injected; declares existence and NOT sequence, and refuses a public instance on the per-batch tier (FR-47) |
| ✅ `FR-19` | **Configurable quorum** — Accept a K-of-N quorum setting governing how many countersignatures a batch requires. | Quorum counted PER CAPABILITY CLASS and reported as three numbers, never one |
| ✅ `FR-20` | **Configurable anchor cadence** — Accept an anchor_interval setting that determines the mutability window. | anchor_interval default asserted at 10s; the anchor tier submits at that cadence |
| ✅ `FR-21` | **Soft anchor tier** — Provide a fast anchor tier, default every 10 seconds. | Soft tier runs at anchor cadence; the rollup tier is not asked on every checkpoint |
| ✅ `FR-42` | **Operator enrolment** — Operator identity is the operator public key together with the log origin, and it is the same notion whether the witness is hosted or self-hosted. Only the provisioning differs: with a self-hosted witness it is local configuration and no account exists anywhere, which is what the zero-egress promise means; with a hosted witness it is a registration. | Enrolment required before any submission; re-enrolling under a different key refused because it would reset the sequence state |
| ✅ `FR-43` | **Witness verifies consistency, not increments** — The witness accepts a checkpoint whose tree_size is greater than or equal to the last it recorded for that operator AND whose Merkle consistency proof from the previous size verifies. It does not require tree_size to increase by one: a checkpoint published every 10 seconds or 1,024 records legitimately jumps. Witness state is updated atomically with the signature. | Sequence enforced by RFC 6962 consistency proof, not by successor: sizes legitimately jump, and a forked tree fails the proof at any size. Enforced under an exclusive cross-process lock, so two witness processes cannot each accept a different successor |
| ✅ `FR-44` | **Witness retains roots** — The witness keeps submitted roots in its own append-only store. | Every root retained in order and never overwritten. Crash-consistent: a torn tail is dropped on read AND repaired under the lock before the next append, damage in a terminated line refuses to start, every retained entry is validated by shape rather than skipped, and a root retained without the state having advanced is reconciled on load and inside the critical section |
| ✅ `FR-45` | **Witness stamps its own clock** — The countersignature carries the witness's own time, not the operator's. | The witness records its own received_at, and an RFC 3161 token's genTime is the TSA's clock; neither is the operator's |
| ✅ `NFR-03` | **Default mutability window** — Default anchor interval of 10 seconds. | Default anchor interval asserted at 10s from the canonical config |
| ✅ `SEC-03` | **No trust in operator or vendor** — Verification must not require trusting the operator, host, collector binary, or Splitstick. | The report enumerates what the reader is trusting; the operator appears only for completeness, identity and custody. The verifier source is asserted to import no config loader at all, and the trust path refuses any certificate the operator could have obtained for themselves |
| ✅ `SEC-04` | **One honest witness assumption** — Security holds if at least one witness in the configured set is honest; the assumption is documented. | The assumption is stated in DES-08 alongside its uncomfortable half — a set sharing an interest is one witness wearing several hats — and a single-witness set is flagged by describeWitnessSet |
| ✅ `SEC-09` | **Resist truncation** — Truncating the record's tail must be detectable. | Truncation DETECTED when a sequence witness holds a later root; with time-only witnesses it is not, and the capability statement says so with the height |
| ✅ `SEC-10` | **Resist erasure and renumbering** — Erasing events and renumbering into a clean stream must be detectable. | Erasure and renumbering detected against the witnessed root; red-team F, F2 and F3 all DETECTED in the witnessed configuration |
| ✅ `SEC-15` | **Witness sees roots only** — Witnesses receive salted roots and nothing else. | Asserted on the bytes that actually left the host, with a positive control so a check that sees nothing cannot pass |
| ✅ `INT-01` | **C2SP conformance** — Conform to the C2SP tlog-witness checkpoint specification. | Twelve conformance assertions against the C2SP spec as written, spelled out rather than expressed through our own helpers — including that what is signed is the body INCLUDING its trailing newline and NOT the blank-line separator |
| ✅ `INT-02` | **Verify third-party countersignatures** — The verifier accepts countersignatures from witnesses we do not operate. | A pack anchored only to third parties verifies with our key absent from the acceptance policy entirely |
| ✅ `FR-48` | **Shipped default witness configuration** — Ship a default the project neither operates nor overloads: an RFC 3161 timestamp authority for the per-batch countersignature and clock, plus a trust-minimised roll-up anchor on a slow interval. A transparency log such as Rekor is opt-in — for operators self-hosting one, or whose volume suits a public instance — and never the shipped default, because a 10-second cadence against a public good is not acceptable use. | The canonical default-config.yaml is read by the test, so the shipped default cannot drift from what is asserted; defaultWitnessWarning() states that it does NOT close classes 4 and 5 |
| ✅ `FR-50` | **Witness publishes signed tree heads** — The witness publishes its own signed tree head so an operator or third party can detect a rolled-back or equivocating witness. | The witness publishes its own signed tree head; detectRollback compares two observed heads and says which contradicts which |
| ✅ `SEC-25` | **Witness time source** — The witness clock derives from a documented, traceable time source, and the verifier surfaces the witness's declared time discipline. | Every witness type declares its time discipline, including that OpenTimestamps is not a clock at all and a TSA's clock is disciplined as its practice statement says and no better |
| ✅ `PRIV-01` | **Zero content egress** — No content bytes leave the operator's host under any configuration. | Zero content egress asserted against the fixture strings on the captured traffic of every adapter, not by inspection |
| ✅ `FR-30` | **Acceptance policy as input** — The verifier takes a caller-supplied acceptance policy naming trusted witness keys and quorum. | The same pack verified under two acceptance policies gives two different, internally consistent answers; an empty policy says the reader trusted nobody |
| ✅ `FR-31` | **Evidence pack carries all countersignatures** — Packs include every countersignature collected, not only Splitstick's. | Every countersignature is carried in the envelope with an explicit `covers`, and the type-to-subject pairing is enforced rather than documented |
| ✅ `FR-22` | **Hard anchor tier** — Provide an optional slow, trust-minimised anchor tier that no company can withdraw. | OpenTimestamps proof parsing with the operations APPLIED, not merely collected; reported as a commitment to a block, never as confirmed |
| ✅ `SCOPE-15` | **Hard anchor must be disableable** — The trust-minimised roll-up anchor must be switchable off in one setting, and switching it off must be recorded in the chain like any other policy change. It is on by default because it is the only free public anchor with no acceptable-use objection; it must never be mandatory, because some regulated buyers forbid public-chain anchoring outright. | An empty witness set anchors nothing, queues nothing and reports establishing nothing — a supported configuration, not an error |
| ✅ `FR-53` | **Roll-up anchoring** — Anchor a periodic summary checkpoint covering many batches, separately from the per-batch soft anchor, so a public or rate-limited witness receives a handful of entries per day rather than thousands. | A roll-up commits to the CHECKPOINT NOTES; a single batch is provable under it by an ordinary inclusion proof, and successive roll-ups are prefixes of each other |
| ✅ `FR-16` | **RFC 3161 TSA adapter** — Support an RFC 3161 timestamp authority as a witness type. | Verified against a GENUINE LibreSSL-produced TimeStampToken committed as a fixture; the signer must carry extendedKeyUsage=id-kp-timeStamping as its sole purpose (RFC 3161 2.3), and the chain must reach an anchor the reader supplied through certificate authorities only |
| ✅ `FR-17` | **Operator-hosted witness adapter** — Support an operator's own internal witness endpoint. | Operator-hosted stateful witness: enrolment, consistency-proof sequence enforcement, retained roots, signed tree heads, key history. The critical state transition is held under an exclusive CROSS-PROCESS lock covering enrolment, and is crash-consistent: recovery reconciles the retained history with the active state before validating anything |
| ✅ `FR-54` | **Cross-pack consistency verification** — Given two or more evidence packs, detect a record inconsistent with a checkpoint already countersigned in an earlier pack — so a record truncated below a height previously disclosed is contradicted offline, with no live service. | A pack disclosed earlier holding a countersigned height above where this record ends emits TRUNCATED_BELOW_DISCLOSED; a differing root at the same height is reported as a fork with neither preferred |
| ✅ `SEC-26` | **Resist truncation below a disclosed height** — A record truncated below a sequence already disclosed in a countersigned pack must be detectable by comparing the two, without any stateful witness. | TRUNCATED_BELOW_DISCLOSED emitted from a height a counterparty already holds |
| ✅ `DOC-09` | **Reconciliation guidance** — Document reconciliation against counterparty records as a detection method for erasure and omission, with its limits stated: it requires access to the counterparty and it is a procedure an auditor performs, not a guarantee the software makes. | docs/reconciliation.md states the procedure and five limits: it needs access to the counterparty, it is a procedure with a procedure's failure modes, its coverage is bounded by the counterparty's completeness, it is retrospective, and it does not establish WHEN |
| ✅ `FR-57` | **Verifier states witness-set capabilities** — The verifier prints what the configured or observed witness set can and cannot establish — in particular whether any witness maintains operator sequence state, and therefore whether truncation above the last disclosed height is detectable at all. | The capability statement is derived from the proofs actually present, not from configuration, and prints quorum per class |
| ✅ `FR-26` | **Gap declarations with an exact span** — When the observation counter survived the failure, record a signed declaration naming the exact source_seq span that was observed but never written. It occupies one record position. Observation gaps are detected from consecutive persisted source_seq values, never by comparing source_seq with record_seq, which count different things. | A gap occupies one record position whatever its span; a reversed, zero-bounded or non-integer span is refused and consumes no position. The verifier now READS the declaration: it accounts for exactly the span it names, must meet the sequence where it left off, does not carry forward, and a span wider or narrower than the jump is itself reported. A span already accounted for by an earlier declaration is refused at both ends — the collector will not propose it and the verifier will not accept it |
| ✅ `FR-27` | **Countersigned gap declarations** — Gap declarations are themselves submitted for countersignature. | The declaration falls under a countersigned checkpoint, which is what establishes WHEN it was declared; the fail-open case where it falls after the last anchor is asserted separately |
| ✅ `FR-63` | **Pinned operator identity** — The acceptance policy names the operator identity the reader expects, and the verifier reports any pack presented under a different key or origin rather than silently accepting it. Nothing prevents an operator maintaining a second log; the guarantee is that a reader who pinned an identity is told when they are shown another. | A pack under another origin emits IDENTITY_UNPINNED; the right origin with the wrong key is also reported; pinning nothing reads as pinning nothing rather than as a pass |
| ✅ `FR-65` | **Operator-declared key custody** — The key custody class — non-exportable KMS or HSM, versus a software key — is declared in a chained record per epoch, because an HSM signature and a file-key signature are byte-identical and a verifier cannot otherwise tell them apart. The declaration proves the operator declared it, not that the key was non-exportable or later destroyed. Custody is reported as operator-declared unless a provider attestation document is supplied alongside, which is the only path to independently supported custody. | A `custody` record kind, chained; custody_basis admits only 'operator-declared' and the validator refuses 'independently-supported' outright |
| ✅ `FR-70` | **Validate a provider custody attestation** — Before reporting custody as independently supported, validate the attestation: issuer chains to a provider root named in the acceptance policy, document signature valid over the bytes presented, attested key is the one that signed this epoch, attestation period covers the epoch, and the document actually asserts non-exportability. Even all five together do not establish historical key destruction, which remains operator-declared. | All five checks reported separately, each with a test that breaks only it. Check 5 reads YubiHSM 2's own Origin and Capabilities BIT STRINGs at the OIDs Yubico publishes, and requires BOTH that the key was generated on the device (not imported, not imported under wrap) and that it lacks exportable-under-wrap. Fixtures are vendor FORMAT; no real provider document has ever been put through it, and every result carries provider_untested: true |

### M3b — Practice statement and resilience

Say exactly what the countersignature means, and make sure losing a witness does not lose the evidence.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 22 (LEG×10  FR×7  NFR×2  OPS×2  SEC×1)
- **Effort:** weeks 3-4
- **Exit criteria:** Practice statement published, versioned and itself anchored, naming its time discipline. An agent run completes normally with every witness unreachable. Restore drill meets the stated recovery point objective. Countersignatures from a retired witness key still verify. Operator key compromise recoverable as a declared, countersigned discontinuity.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ✅ `FR-38` | **Fail-open with marked batch** — When no witness is reachable, chain and sign locally, mark the batch unwitnessed, and queue it. | A total witness outage leaves the run complete and the batch marked unwitnessed and queued; asserted over five checkpoints with every witness unreachable |
| ✅ `FR-39` | **Late countersignature records real time** — A retroactive countersignature records the witness's actual receipt time, not the batch's claimed time. | The witness's own receipt time is carried in the envelope and reported with its BASIS — 'witness-asserted, unsigned' for a C2SP note, which has nowhere inside it to carry a time, versus signed for an RFC 3161 genTime. The gap to the batch's self-asserted ts is reported as the unwitnessed window; a receipt time earlier than the batch is reported and not preferred; an absent one is never assumed to be the batch time |
| ✅ `NFR-12` | **Never degrade availability** — The collector must never be able to stop or block an agent run. | Absolute: a whole run completes with every witness unreachable, and no configuration can make the collector block |
| ✅ `NFR-13` | **Durable local queue** — Unwitnessed batches survive process restart and are re-submitted. | The queue is a journal, read from disk on open; a drain is durable across restart; a torn tail is dropped AND repaired before the next append; damage in the middle is refused rather than skipped |
| ✅ `LEG-01` | **Publish a Witness Practice Statement** — Publish a versioned practice statement defining exactly what a countersignature means. | Published at docs/witness-practice-statement.md, versioned with a change history, and every claim matched against the code by tools/lint-practice-statement.mjs |
| ✅ `LEG-02` | **WPS asserts receipt time** — The countersignature asserts the root was received at the stated time per the witness clock. | §1.1 asserts receipt at the stated time by the witness's own clock, AND states the limit: for a C2SP note the time travels beside the signature rather than under it, reported as 'witness-asserted, unsigned' |
| ✅ `LEG-03` | **WPS asserts successor ordering** — The countersignature asserts the root EXTENDS the history the witness last held for that operator, proved by an RFC 6962 consistency proof. Not 'immediate successor': DES-05 publishes every 10 seconds or 1,024 records, so heights legitimately jump, and DES-08 moved to consistency proofs for exactly that reason. The earlier wording predated that change. | §1.2 asserts the submitted root EXTENDS the history the witness last held, proved by an RFC 6962 consistency proof — not 'immediate successor', which M3a deliberately does not enforce because DES-05 publishes every 10s or 1,024 records and heights legitimately jump |
| ✅ `LEG-04` | **WPS asserts retention** — The countersignature asserts the witness retained the root in its own append-only store. | §1.3 asserts retention in the witness's own append-only store, paired with the roots journal |
| ✅ `LEG-05` | **WPS disclaims occurrence** — The statement disclaims any assertion that the underlying actions occurred. | §2.1 disclaims that the actions occurred, and the lint asserts no source claims otherwise |
| ✅ `LEG-06` | **WPS disclaims truthfulness** — The statement disclaims any assertion that recorded content is true. | §2.2 disclaims that recorded content is true, and the lint asserts no source claims otherwise |
| ✅ `LEG-07` | **WPS disclaims completeness** — The statement disclaims completeness and points to coverage attestation instead. | §2.3 disclaims completeness and points at the coverage attestation (DES-10, M4) instead |
| ✅ `LEG-08` | **WPS disclaims lawfulness** — The statement disclaims any assertion that an action was lawful or authorised. | §2.4 disclaims lawfulness and authorisation, and the lint asserts no source claims otherwise |
| ☐ `LEG-09` | **WPS versioned and anchored** — The practice statement is itself versioned and anchored like any other record. | §7 — the statement is versioned AND anchored like any other record, by the same mechanism and with no special path. `npm run anchor-wps` appends a chained `policy` record naming the digest and the version it supersedes, never removing an earlier one, verifiable through the ordinary verifier; re-running on an unchanged statement appends nothing. Recording and anchoring are separate steps and separate runs: a statement recorded before any witness existed is anchored later against the checkpoint it already falls under. Three reported states, taken from verifyStore rather than decided by the command — RECORDED, COUNTERSIGNED (unverified), ANCHORED (verified) — so issuer presence can never be reported as established time. The verdict is SCOPED to the version reported: a proof counts only when the tree its checkpoint committed to reaches that version's record, so an earlier version's countersignature never anchors a later statement, and proofs not counted are named rather than dropped. OUTSTANDING: the project's own published statement is not yet anchored by any witness, because this repository holds no operator key |
| ✅ `OPS-02` | **Queue drain and retry** — Drain and re-submit queued unwitnessed batches with backoff once a witness returns. | Drain with exponential backoff, capped, highest height first; a fresh entry is eligible immediately because anchor() already tried, and the delay applies after a failed retry; `waiting` is reported separately from `anchored` so a caller can tell waiting from failing. The queue holds INSUFFICIENTLY witnessed checkpoints, not merely unwitnessed ones: an entry stays until its quorum is met, counting the countersignatures already on the envelope, and each attempt asks only the issuers that have not answered. docs/witness-outages.md states for an operator which parts recover automatically and which do not |
| ✅ `FR-51` | **Witness key rotation** — Rotate witness keys while keeping historical countersignatures verifiable, by publishing a signed key history. | A retired witness key still verifies, against a published key history that is VALIDATED first: the note must exist, verify under a key that is itself in the list, and sign a digest that covers the list as presented. A key absent from a valid history is inconclusive, not a failure |
| ✅ `OPS-06` | **Witness store durability** — The witness store is replicated and recoverable, with a documented recovery point objective, because a witness that loses its roots destroys the corroboration it exists to provide. | A runnable drill (`npm run drill:restore`) rather than a described procedure: it takes a backup, advances past it, destroys the live store, restores, and asserts the restored witness refuses both a conflicting submission AND the operator's honest next one — then recovers by resubmitting from the height the witness reports. It exits non-zero if it measures no loss, so it cannot pass without exercising a stale backup |
| ✅ `LEG-19` | **WPS states the time discipline** — The practice statement names the witness's time source and the limits of the time assertion. | §4 names each witness type's time source and the limits of the time assertion, including that OpenTimestamps is not a clock at all and that none of them establishes when an action OCCURRED — only when a root was received, and only from above |
| ✅ `SEC-24` | **Key compromise recovery** — Document and support recovery from operator key compromise: a declared, countersigned discontinuity rather than a silent re-key. | A `discontinuity` record kind naming the last sound epoch, the new root key and a required reason; reported prominently as DISCONTINUITY, never bridged — no affirmative signing claim spans it and the report says the reader must re-pin out of band. The declaration is signed by the key it disowns and the report says so |
| ✅ `FR-58` | **Reserved slot for gap declarations** — Pre-allocate storage sufficient to write a gap declaration, so the declaration can be written even when the store is otherwise exhausted. If even that fails, the condition is surfaced out of band and the next successful write declares the lost window. | A 64 KiB reserve written when the store is created, never touched by ordinary records, released only to write a gap declaration; its absence afterwards is the signal it was spent. If even that fails the condition is surfaced out of band and the collector degrades |
| ✅ `FR-60` | **Unknown-loss intervals** — When the observation counter did not survive — an unrecoverable crash with the counter only in memory — declare an unknown-loss interval bounded by the last durable checkpoint and the first record after restart. Never fabricate an exact span. The two kinds of loss evidence are distinct record kinds and a verifier reports them differently. | An unknown-loss interval bounded by the last durable checkpoint and the restart, declared when the counter did not survive; a first run declares nothing, because a first run is not a loss |
| ✅ `FR-61` | **Observation counter durability** — Checkpoint the observation counter durably at each batch flush, so an unrecoverable crash loses at most the current window and the unknown-loss interval is bounded rather than open-ended. | The counter is written atomically at each batch flush and reconciled against the chain on open; level means no loss, ahead means an exact span to declare, absent means FR-60's interval. A counter BEHIND the accounted position is the ordinary mid-window state and declares nothing: the counter advances at each flush while source_seq advances at every observation, so behind is what the state between flushes looks like |
| ✅ `FR-68` | **Unwitnessed outage ceiling** — Fail-open must not become indefinite. An unwitnessed_ceiling sets the point at which the collector raises an alert out of band, and beyond which the coverage report refuses to issue a completeness claim spanning the outage, stating the unwitnessed window instead. | Past the ceiling an alert is raised OUT OF BAND through a callback that writes no record, once per breach rather than once per flush; the breach clears on drain and `breaches` keeps the window; a ceiling of zero or less is refused at config load |

### M4 — Coverage attestation

The differentiated claim: prove the record is complete, not merely unaltered.

- **Gate:** `AC-6` — Stop or patch the collector, then claim quiet; `AC-7` — Weaken the anchoring policy, then tamper
- **Requirements:** 11 (FR×7  SEC×2  DOC×2)
- **Effort:** weeks 3-4
- **Exit criteria:** Killing the collector produces a detectable gap. Patching it reports an unrecognised build digest. Downgrading the witness policy appears as a countersigned chain event. A declared gap lets the sequence recover without a silent reset.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-23` | **Policy changes as chain events** — Record any change to the witness set or quorum as a timestamped event inside the chain. | Red-team: policy downgrade is visible in the record |
| ☐ `FR-24` | **Signed heartbeats** — Emit signed heartbeats into the collector-scoped chain at a configured interval, independently of whether any run is active, because the dangerous window is precisely when none is. | Stopping the collector produces a detectable gap, including during an interval with no agent run |
| ☐ `FR-25` | **Build digest in heartbeat** — Each heartbeat carries the collector build digest, binding a run to a traceable artifact for configuration assurance and non-repudiation by an honest operator. It is not an attestation of the running process and does not detect a dishonest patch. | Digest present and resolvable to a published provenance attestation; test asserts no claim of patch detection appears in output |
| ☐ `FR-28` | **splitstick coverage** — Produce a coverage report over a date range stating the proportion of actions the collector reported that were captured, chained and anchored, plus heartbeat continuity — never a claim about actions the collector did not report. Attempts and logical actions are counted separately, since one action may span several attempts. | Report wording asserted by test; injected gaps appear exactly; attempt and logical-action counts are both present and differ under retry; a suppressed action does not appear and the report does not imply completeness |
| ☐ `FR-40` | **Late anchors reported as gaps** — Windows anchored late are reported as coverage gaps. | Coverage report flags the widened window |
| ☐ `SEC-11` | **Resist collector stoppage** — Stopping the collector and claiming a quiet period must be detectable, by heartbeat discontinuity. Patching the collector is NOT covered: a modified build can report the original digest, and a self-reported digest is not remote attestation. | Kill the collector mid-window; the coverage report shows an undeclared gap. A separate test asserts a collector reporting a forged digest is NOT flagged, so the limit is pinned by a test rather than by prose |
| ☐ `SEC-12` | **Resist policy downgrade** — Weakening the anchoring policy before tampering must be visible in the record. | Test weakens the witness set, then asserts a countersigned policy event appears in the chain before the next batch |
| ☐ `DOC-05` | **Publish honest limits** — Publish the known information leaks and the attacks not covered. | Documentation review |
| ☐ `DOC-10` | **Document the collector-patch limit** — State plainly, wherever coverage attestation is described, that a collector patched to report a valid digest while suppressing actions is not detectable without remote attestation, which this release does not provide. | Statement present in the threat model, the coverage report output, and DES-10; claims audit checks no surface implies otherwise |
| ☐ `FR-64` | **Collector self-reported configuration attestation** — Each heartbeat carries a digest of the capture configuration the collector reports for itself — upstreams proxied, interfaces bound, heartbeat and anchor intervals — so a change to THAT configuration is recorded and visible. It does not detect an execution path created outside the collector: such a path leaves the collector reporting an unchanged digest and nothing diverges. This is provenance of a self-report, not independent observation. | Changing a declared upstream alters the attested digest and emits a policy record; a test asserts that a path bypassing the collector entirely produces NO signal, so the limit is pinned by a test rather than by prose |
| ☐ `FR-66` | **Compare expected witnesses against proofs present** — Each checkpoint records which witnesses were expected for it, given their tier and cadence, and the verifier compares that against the proofs in the pack. A proof that is expected and absent is reported as missing and inconclusive — it may be pending under fail-open, the witness may have been unavailable, or the receipt may have been removed, and the verifier cannot tell which from absence alone. Demonstrating removal requires an earlier pack that contained it, which is cross-pack comparison. | Remove a proof: WITNESS_MISSING is reported as inconclusive, never as deletion. A witness on a slower tier with no proof yet is reported as not-yet-expected. A pack pair where one holds the proof and the later one does not yields removal |

### M5 — Disclosure and erasure

No new attack class. This is the milestone that makes the product buyable by a regulated, multi-customer organisation.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 17 (PRIV×7  FR×6  NFR×3  INT×1)
- **Effort:** weeks 3-4
- **Exit criteria:** Verification passes after content and key deletion. A single-event disclosure verifies in isolation against a countersigned root. A 100,000-event run verifies in under 2 seconds with no network and no credentials. Both metadata leaks documented.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-32` | **splitstick disclose** — Emit a Merkle inclusion proof for a single named event. | Recipient verifies one event without the rest |
| ☐ `FR-33` | **Inclusion proof binds to countersigned root** — Inclusion proofs verify against a countersigned root, not a bare local digest. | Proof rejected when root is unwitnessed |
| ☐ `FR-34` | **Optional batch padding** — Provide optional padding of batches with dummy leaves to obscure activity volume. Padding is applied only at batch close and never retroactively; dummy leaves are explicitly typed so a verifier holding the pack can count them; and a real action can never be reclassified as padding, because its leaf is already committed. | Retroactive padding is rejected; a verifier reports real and dummy leaf counts separately; reclassifying a committed action fails the leaf check |
| ☐ `FR-36` | **Crypto-shredding** — Deleting content and its key leaves the chain verifiable and the commitment permanently unlinkable. | Verify passes after content+key deletion |
| ☐ `FR-37` | **Retention policy on storage** — Retention and erasure are configurable at the storage layer, independent of the cryptography. | Retention config honoured; chain unaffected |
| ☐ `NFR-04` | **Verification throughput** — Verify a 100,000-event run in under 2 seconds, offline. | Benchmark on a documented reference machine |
| ☐ `NFR-05` | **No network at verification** — Verification completes with networking disabled. | Test executed in a network-isolated sandbox |
| ☐ `NFR-06` | **No credentials at verification** — Verification requires no account, token or credential. | Test with an empty environment |
| ☐ `PRIV-03` | **Erasure via crypto-shredding** — Support a documented erasure procedure satisfying a data-subject deletion request, over payloads, content salts, leaf salts, the reference index, the agent label and any approval reviewer. The claim is scoped to that enumerated set, not to all personal information everywhere. | Procedure executed; the enumerated set is unrecoverable; an independent privacy assessment of the residue is deferred to a funded release and recorded as such |
| ☐ `PRIV-04` | **Chain survives erasure** — The chain still verifies after content deletion. | Verify passes post-deletion |
| ☐ `PRIV-05` | **Minimal retained artefacts** — After erasure the chain retains only the version-1 permanent set: v, collector, run, record_seq, source_seq, ts, kind, consequential, tool, outcome, attempt, correlation, approval.decision, result.ok, args.bytes, result.bytes, a padding record pad nonce, gap spans, unknown-loss intervals, and salted digests, leaf digests and chain heads. Every other field is erasable: payloads, the agent label, the approval reviewer, the reviewed request, content salts, leaf salts and the reference index. The byte lengths and the correlation relationship are documented residual leaks with no mitigation in 1.0. | Automated scan after crypto-shredding asserts the residue matches the enumerated permanent set exactly, field for field, across every record kind including padding; the list is derived from the version-1 schema so a schema change fails the test rather than silently passing |
| ☐ `PRIV-06` | **Disclosure minimisation** — A disclosure reveals the named event and nothing else about other events' contents. | Test asserts a disclosure pack contains exactly one salt and that no sibling leaf is reproducible from the pack |
| ☐ `PRIV-07` | **Disclose the tree-size leak** — Document that an inclusion proof reveals the log tree size, and that tree size is the count of ALL records — actions, heartbeats, policy events, gap declarations and padding — not a count of agent actions. The action count is therefore not directly disclosed, which is a weaker leak than an earlier draft claimed. | Documentation review; a test asserts tree size exceeds the action count in any run containing heartbeats |
| ☐ `PRIV-08` | **Disclose the cadence leak** — Document that anchor cadence leaks activity volume. | Documentation review |
| ☐ `PRIV-09` | **Operator-controlled retention** — Retention is a setting on operator-controlled storage, not a vendor policy. | Configuration test |
| ☐ `INT-03` | **Documented evidence pack format** — Publish and version the evidence pack format so third parties can write verifiers. | Spec published; independent verifier implementation validates a pack |
| ☐ `FR-69` | **Padding is a record kind** — A padding leaf is an explicit record kind in the version-1 enum, with its own record_seq, source_seq null, no tool or payload fields, and a random nonce so no two padding records share a leaf. Padding leaves without records would break record_seq equals tree_size. | Two real records plus three padding records yield tree_size 5 and record_seq 5; a verifier counts real and padding records separately; a mixed real-and-padding log verifies end to end |

### M6 — Reach and conformance

Stop depending on one upstream project, and make the format genuinely somebody else's to implement.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 19 (FR×6  GOV×4  NFR×3  INT×2  OPS×2  LEG×2)
- **Effort:** weeks 4-6
- **Exit criteria:** End-to-end capture against two non-OMA runtimes over both MCP transports. A third-party witness passes the published conformance suite. A fully self-hosted deployment verified at zero egress, with no account and no enrolment with us. The conformance suite fuzzes the canonicaliser rather than only driving fixed vectors, because a fixed-vector suite is exactly what missed the surrogate collision in M1.
- **Carried in for closure:** `FR-52`

> **Carried from M1 — `FR-52` Canonicalisation completeness**
>
> M1 proved canonicalisation completeness with a property test that mutates every field at every depth, and an independent review still found a collision it could not reach: two records differing only by an unpaired surrogate produced identical canonical bytes and identical leaves. The test only mutates values that round-trip through JSON, so no amount of running it would ever have found that.
>
> *Closes when:* FR-46's conformance suite fuzzes the canonicaliser rather than only driving fixed vectors: unpaired surrogates, numbers at the representable boundary, deeply nested structures, keys that collide after Unicode normalisation. The property asserted is that distinct inputs never share canonical bytes.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-03` | **MCP proxy collector (stdio)** — Intercept agent-to-MCP-server traffic over stdio and record every tool call and result. | E2E test against a reference MCP server over stdio |
| ☐ `FR-04` | **MCP proxy collector (HTTP)** — Same capture over HTTP transport. | E2E test against a reference MCP server over HTTP |
| ☐ `FR-15` | **transparency-dev/witness adapter** — Support transparency-dev/witness as a witness type. | Anchor against a local instance |
| ☐ `FR-46` | **Conformance test suite** — Publish an executable conformance suite any witness implementation can run against itself. | Suite runs green against the reference witness |
| ☐ `FR-47` | **Witness list as data** — Maintain the list of known conformant witnesses as a machine-readable file, each entry carrying its acceptable-use terms, rate limits, and whether it retains entries publicly, so an operator chooses on informed grounds rather than by default. | File parses; the collector consumes it; every entry states its acceptable-use position |
| ☐ `NFR-08` | **Node.js 20+** — Run on Node.js 20 and later. | CI matrix across supported majors |
| ☐ `NFR-10` | **OMA version compatibility** — Support @open-multi-agent/core 1.21.x. | CI pinned against the supported range |
| ☐ `NFR-11` | **MCP transport coverage** — Support MCP over stdio and HTTP. | E2E per transport |
| ☐ `GOV-05` | **Third-party witnesses permitted** — Anyone, including competitors and hyperscalers, may run a conformant witness. | No technical or licence barrier; third-party witness interoperates |
| ☐ `GOV-06` | **Open conformance suite** — Publish the conformance suite so implementations can self-check. | Suite in the repository under the open licence |
| ☐ `GOV-08` | **Witness list by pull request** — Accept witness-list entries by pull request. | Contribution path documented and exercised |
| ☐ `GOV-09` | **No gatekeeping of the witness list** — Do not vet, rank, or charge for inclusion in the witness list. | Policy published; list contains entries not controlled by us |
| ☐ `INT-05` | **Framework-agnostic capture** — Capture works for any stack speaking MCP, including runtimes with no journal. | E2E against two non-OMA agent runtimes |
| ☐ `INT-06` | **Reuse rather than reimplement** — Build on Sigstore, Rekor, Trillian and C2SP rather than reimplementing their roles. | Dependency review; no bespoke transparency log |
| ☐ `OPS-03` | **Self-hosted witness deployment guide** — Document running the witness under internal audit with keys in their custody. | Guide published; followed end to end in a clean environment |
| ☐ `OPS-05` | **Zero-egress mode** — Support and verify a deployment with no account, no enrolment with us, and no traffic leaving the perimeter. | Egress capture in a fully self-hosted deployment |
| ☐ `LEG-13` | **Qualified TSA configurable** — A qualified TSA can be configured in the witness set by the operator. | Live anchor against a qualified TSA |
| ☐ `LEG-12` | **eIDAS presumption only via qualified TSA** — Document that the Art. 41 presumption attaches only when anchored to a qualified TSA, and not via Splitstick's own witness. | Documentation review; no contrary claim anywhere |
| ☐ `FR-49` | **Documented CLI contract** — Provide the entry points and flags printed in Getting started: collect-oma, mcp-proxy (--upstream, --out), verify (--policy), coverage (--from, --to) and disclose (--event, --out). | CLI contract test executes every documented invocation verbatim |

### M7 — Launch gate

Every promise that is a claim rather than a feature. This milestone is mostly about what we must not say.

- **Gate:** none on its own — see the exit criteria
- **Requirements:** 37 (SCOPE×15  GOV×7  DOC×6  SEC×4  LEG×3  TRC×2)
- **Effort:** weeks 2
- **Exit criteria:** Claims audit clean across all sixteen scope guards. Every published figure has a passing benchmark behind it. Bounty terms published, stating plainly that recognition is non-cash while the project is unfunded. No surface anywhere claims conformity, certification, or tamper-proofing. NFR-01 has a qualifying acceptance measurement on the reference environment and NFR-02 has been re-measured against a real provider; neither may be reported as met on a development-machine number.
- **Carried in for closure:** `NFR-01`, `NFR-02`, `NFR-09`

> **Carried from M1 — `NFR-01` Low-overhead evidence capture**
>
> M1 measured the append path and revised the budget to p95 under 1 ms and p99 under 3 ms, but no run has qualified: the development machine reports itself a regression metric on load average, event count and repeats. The numbers recorded against it are measurements, not acceptance.
>
> *Closes when:* One run of bench/append.mjs over at least 1e6 events and at least three repeats, on a machine meeting every constraint in bench/reference-env.json, with --machine and --storage named. The harness prints QUALIFYING ACCEPTANCE MEASUREMENT only when nothing is short; that JSON becomes the requirement evidence.

> **Carried from M1 — `NFR-02` Run latency budget**
>
> The 2 percent budget is established against a scripted model and an assumed 400 ms per model call. Both assumptions are recorded in the result, and neither has been tested against a real provider.
>
> *Closes when:* Re-measure the interleaved paired A/B against a real provider once one is in the loop, and confirm the 95 percent interval still clears the budget at that model latency.

> **Carried from M2 — `NFR-09` HSM/KMS support**
>
> Re-carried from M3a. The KMS half is delivered and awaits a key; the HSM half is blocked on hardware whose attestation capability is unconfirmed. Deciding it at the launch gate is the honest place: that is where a published claim must have evidence.
>
> *Closes when:* Either a real HSM attestation through FR-70's five checks, or the claim narrowed in the published text to what the KMS half actually supports. One of those two, explicitly, and not a third option where the claim stands unevidenced.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `GOV-10` | **Bounty: one class, one payout** — Pay once per tamper class, not per instance. | Terms published; applied in triage |
| ☐ `GOV-11` | **Bounty: default configuration only** — Findings must survive the shipped default configuration. | Terms published; default config documented and pinned |
| ☐ `GOV-12` | **Bounty: scope binding both ways** — The published threat model binds the programme; exclusions cannot be added after a report. | Terms published; change log on the threat model |
| ☐ `GOV-13` | **Bounty: recognition, not cash** — Recognise a novel tamper class with attribution, credit in the suite and a named finding. The project is unfunded; no cash is promised. | Terms published stating plainly that recognition is non-cash while unfunded |
| ☐ `GOV-14` | **Bounty: first reporter wins** — Award the first complete report. | Terms published; timestamps retained |
| ☐ `SEC-19` | **Bounty intake and triage** — Operate an intake, triage and payment process for the tamper bounty. | Process documented and exercised once before launch |
| ☐ `SEC-20` | **Coordinated disclosure window** — Disclose within 90 days or on fix, whichever is sooner. | Policy published; tracked per report |
| ☐ `SEC-21` | **Publish unmitigated findings** — Publish findings even when no mitigation exists. | Policy published; audited at each disclosure |
| ☐ `DOC-03` | **Considered-and-rejected rationale** — Publish rejected designs with reasons. | Section present; updated as decisions are made |
| ☐ `DOC-04` | **Label targets as targets** — Any unverified figure is labelled a target, not a measurement, until benchmarked. | Documentation review before each release |
| ☐ `DOC-06` | **Upstream attribution** — Credit OMA, Sigstore, Rekor, Trillian, C2SP and Schneier–Kelsey. | Attribution present in README and NOTICE |
| ☐ `DOC-07` | **Document the two-policy split** — Document that the witness list governs who is asked and the acceptance policy governs who is accepted. | Documentation review; worked example for both |
| ☐ `DOC-08` | **Publish bounty terms** — Publish the full bounty terms alongside the offer. | Terms published before the offer goes live |
| ☐ `LEG-14` | **No conformity claims** — No product surface or marketing claims EU AI Act conformity. | Claims audit across docs, site and UI |
| ☐ `LEG-15` | **No certification of the customer** — Never certify the customer's compliance. | Claims audit |
| ☐ `LEG-16` | **Not-legal-advice disclaimer** — Carry a not-legal-advice disclaimer wherever statutes are cited. | Documentation review |
| ☐ `SEC-16` | **Bounded integrity claim** — Never claim tamper-proof; claim tamper-evident with attribution. | Claims review |
| ☐ `SCOPE-01` | **No blocking or gating** — MUST NOT block, gate or filter agent actions. | Code review; no enforcement path exists |
| ☐ `SCOPE-02` | **No tamper-proof claim** — MUST NOT describe the product as tamper-proof. | Claims audit across all surfaces |
| ☐ `SCOPE-03` | **No compliance certification** — MUST NOT issue or imply a compliance certificate. | Claims audit |
| ☐ `SCOPE-04` | **Not an observability platform** — MUST NOT position as a replacement for traces, SIEM or dashboards. | Positioning review |
| ☐ `SCOPE-05` | **No reviewer UI in OSS** — MUST NOT include a reviewer surface in the open-source release. | Release inventory |
| ☐ `SCOPE-06` | **No SSO in OSS** — MUST NOT include SSO in the open-source release. | Release inventory |
| ☐ `SCOPE-07` | **No RBAC in OSS** — MUST NOT include RBAC in the open-source release. | Release inventory |
| ☐ `SCOPE-08` | **No multi-tenancy in OSS** — MUST NOT include multi-tenancy in the open-source release. | Release inventory |
| ☐ `SCOPE-09` | **No retention tiers in OSS** — MUST NOT include retention tiers in the open-source release. | Release inventory |
| ☐ `SCOPE-10` | **No verifiable delay function** — MUST NOT ship a VDF. | Dependency and code review |
| ☐ `SCOPE-11` | **No ZK compliance proofs** — MUST NOT ship zero-knowledge compliance proofs, and MUST NOT place them on the roadmap. | Roadmap and code review |
| ☐ `SCOPE-12` | **No TEE suppression claim** — MUST NOT claim a TEE makes event suppression impossible. | Claims audit |
| ☐ `SCOPE-13` | **No blockchain as ledger** — MUST NOT use a blockchain as the primary ledger; a public chain may serve only as the optional hard anchor. | Architecture review |
| ☐ `SCOPE-14` | **No self-scored defeat metric** — MUST NOT publish an N-of-N attacks-defeated score. | Marketing and documentation audit |
| ☐ `TRC-04` | **Benchmark before claiming** — No performance figure is published as fact until its benchmark exists and passes. | Release gate blocks on missing benchmark |
| ☐ `TRC-05` | **Claims audit per release** — Run a claims audit against the scope guards before each release. | Checklist completed and signed off per release |
| ☐ `SCOPE-16` | **No fail-closed option** — MUST NOT provide any configuration, flag or build that makes the collector block an agent run. Fail-open is a design constraint, not a setting. | Config schema review; no enforcement path exists; rejected as a feature request by policy |
| ☐ `GOV-17` | **Bounty: cash deferred until funded** — State publicly that a cash award opens only if the project is funded, rather than promising money that is not held. | Terms published with the condition stated; no figure advertised as available |
| ☐ `GOV-18` | **Accept third-party attack classes** — Accept contributed attack classes by pull request, with attribution. A goal, explicitly not a launch gate. | Contribution path documented; not referenced in any release gate |
| ☐ `DOC-11` | **Every assurance claim names its evidence** — Each assurance claim in the specifications and the release notes names the evidence that supports it, classified as independent, operator-declared, or none. A claim resting only on the operator-controlled collector is worded as an assertion, never as a verified guarantee. This rule exists because the design repeatedly acquired guarantees its own threat model excludes. | Claims audit per release checks each assurance claim against the register; npm run review flags a curated set of overclaim phrasings |

## Deferred


**2.0 — 5**

- `SEC-18` Remote build attestation (experimental)
- `RM-01` Bilateral receipts
- `RM-02` HTTP egress collector
- `RM-03` Shell collector
- `RM-04` Database-write collector

**commercial — 12**

- `FR-18` Splitstick hosted witness adapter
- `LEG-10` Limitation of warranty
- `LEG-11` FRE 902(13)/(14) technical shape
- `LEG-17` Pursue qualified status
- `GOV-07` Certification mark on passing
- `OPS-01` Witness SLA
- `RM-05` Reviewer surface
- `RM-06` SSO
- `RM-07` RBAC
- `RM-08` Multi-tenancy
- `RM-09` Retention tiers
- `RM-10` Evidence export

---

*193 requirements in 1.0 across 9 milestones; 210 total in the backlog.*
