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
| `AC-3` | Re-sign rewritten history with the current key | M2 Key custody | ratchet suite (local + HSM) |
| `AC-4` | Truncate the record's tail | M3a Anchoring and sequencing | D (external) |
| `AC-5` | Erase events and renumber into a clean stream | M3a Anchoring and sequencing | E, F (external) |
| `AC-6` | Stop or patch the collector, then claim quiet | M4 Coverage attestation | G (new) (external) |
| `AC-7` | Weaken the anchoring policy, then tamper | M4 Coverage attestation | H (new) (external) |

## Sequence

| Milestone | Gate | Reqs | Weeks | Goal |
|---|---|---:|---|---|
| **M0** Foundations and long-lead | — | 15 | 1-2, parallel to M1 | Start everything whose clock runs outside engineering, and turn the red-team suite into the acceptance harness. |
| **M1** Local integrity | AC-1, AC-2 | 29 | 3-4 | Close the two attack classes that need no third party, and measure the performance budget before the design hardens. |
| **M2** Key custody | AC-3 | 5 | 2 | Make yesterday's record unforgeable with today's key, and state the precondition honestly. |
| **M3a** Anchoring and sequencing | AC-4, AC-5 | 38 | 5-7 | The first second party. Close truncation and erasure, which no amount of local cryptography can reach. |
| **M3b** Practice statement and resilience | — | 22 | 3-4 | Say exactly what the countersignature means, and make sure losing a witness does not lose the evidence. |
| **M4** Coverage attestation | AC-6, AC-7 | 11 | 3-4 | The differentiated claim: prove the record is complete, not merely unaltered. |
| **M5** Disclosure and erasure | — | 17 | 3-4 | No new attack class. This is the milestone that makes the product buyable by a regulated, multi-customer organisation. |
| **M6** Reach and conformance | — | 19 | 4-6 | Stop depending on one upstream project, and make the format genuinely somebody else's to implement. |
| **M7** Launch gate | — | 37 | 2 | Every promise that is a claim rather than a feature. This milestone is mostly about what we must not say. |
| | | **193** | | |

## Milestones

### M0 — Foundations and long-lead

Start everything whose clock runs outside engineering, and turn the red-team suite into the acceptance harness.

- **Gate:** none — unlocks adoption rather than closing an attack class
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
| ☐ `FR-01` | **OMA journal backend** — Provide a RunJournal implementation for @open-multi-agent/core, installable as a dependency and enabled by configuration alone. | Integration test: journal written through OMA orchestrator |
| ☐ `FR-02` | **OMA approval-store backend** — Provide an approval-store implementation for OMA so approval requests and decisions enter the same record. | Integration test: suspend/approve/resume cycle recorded |
| ☐ `FR-05` | **Digest tool identity and arguments** — Record and digest the tool name and its invocation arguments. | Red-team attack A fails closed |
| ☐ `FR-06` | **Digest tool result** — Record and digest the tool result content. | Red-team attack A fails closed |
| ☐ `FR-07` | **Digest approval decisions** — Record and digest approval decisions, including the deciding identity as supplied. | Unit test: decision tamper detected |
| ☐ `FR-08` | **Predecessor chaining** — Every event carries a cryptographic digest of its predecessor. | Red-team attacks B, C, F fail closed |
| ☐ `FR-09` | **Per-leaf salting** — Every leaf is salted with a per-leaf random nonce before hashing. | Unit test: identical content yields distinct digests |
| ☐ `FR-10` | **Batch signing with operator key** — Sign each batch root with the operator-supplied key. | Signature verifies under operator public key |
| ☐ `FR-29` | **splitstick verify** — Verify chain integrity, batch signatures and witness countersignatures from files alone. | All red-team classes fail closed; baseline passes |
| ☐ `FR-35` | **Payloads are content-addressed and externalised** — No payload enters the chain. Every argument and result is replaced by a salted content digest, cid = H(0x05 \|\| content_salt \|\| plaintext), and the plaintext is stored encrypted in the deletable store. Substituting a payload while preserving its pointer is therefore impossible, and deleting the salt, key and ciphertext leaves an unlinkable commitment. | Payload-substitution test: replacing stored content without changing the cid fails verification. Automated scan asserts no payload bytes appear anywhere in the chain |
| ☐ `FR-41` | **Configuration file** — Support splitstick.yaml with store, signer, anchor_interval, rollup_interval, heartbeat_interval, on_unavailable, witnesses, quorum and unwitnessed_ceiling keys. | The documented example config is loaded in test and each key asserted to take effect; heartbeat_interval is present because it sets the resolution of every coverage claim |
| ☐ `NFR-01` | **Append overhead** — p99 append overhead below 1 ms per event. | Benchmark harness, p99 over 1e6 events |
| ☐ `NFR-02` | **Run latency budget** — Added end-to-end agent run latency below 2%. | A/B benchmark with and without the collector |
| ☐ `SEC-06` | **Resist action alteration** — Altering recorded arguments, result or approval decision must be detectable. | Red-team class A |
| ☐ `SEC-07` | **Resist consistent rewrite** — Altering an event and repairing its citing digest must be detectable. | Red-team class C |
| ☐ `SEC-13` | **Digest pre-image resistance in practice** — Salting must prevent brute-force recovery of low-entropy action records from their digests. | Dictionary attack against salted digests fails |
| ☐ `SEC-14` | **Operator key never leaves operator** — Splitstick must never hold, receive, request or log the operator signing key. | Automated egress capture during a representative run asserts no private key material leaves the host; plus a code check that no verifier or collector module imports a key-export API |
| ☐ `PRIV-02` | **No content in the chain** — The chain contains no payload bytes at all — not merely no oversized ones. Records in the chain carry metadata and salted content digests; every argument and result lives in the deletable store, so there is nothing in the chain that erasure cannot reach. | Automated scan of chain files for any payload string from the fixture finds nothing, including short inline-sized arguments |
| ☐ `INT-04` | **Additive OMA integration** — Integrate with OMA without a fork, patch or upstream pull request. | Install against unmodified upstream at the supported version |
| ✅ `DOC-01` | **Public red-team suite** — Maintain a public tamper suite reproducible in two commands. | Clean-clone run succeeds |
| ☐ `NFR-07` | **Long-term verifiability** — Evidence remains verifiable years later; algorithms and formats are versioned to allow it. | Format version negotiation test; documented algorithm migration path |
| ☐ `INT-07` | **No agent code changes** — Both collectors integrate by dependency and configuration only; no change to the customer's agent code is required. | Byte-identical agent source before and after integration, for both collectors |
| ☐ `SEC-22` | **Build provenance attestation** — Publish a provenance attestation for every released collector artifact, binding the digest to its source commit and build, so the digest in a heartbeat can be independently traced. | Attestation verifies against the published artifact and source revision |
| ☐ `SEC-23` | **Signed releases and SBOM** — Sign every release and publish an SBOM with pinned dependencies. | Signature and SBOM present and verified in CI for each release |
| ☐ `FR-52` | **Canonicalisation completeness** — The canonical encoding must cover every field of the action record at every nesting depth. A test must prove that mutating any single field, at any depth, changes the leaf digest. | Property test mutating each field in turn, including nested argument keys; every mutation must change the digest |
| ☐ `FR-55` | **Counterparty reference capture** — Extract externally issued identifiers from a tool result and index them for reconciliation. The index lives in the deletable content store, never in the chain, because a transaction reference can itself be identifying. | A result containing an external reference is indexed and queryable; the index is removed by crypto-shredding |
| ☐ `FR-56` | **Collector instance identity** — Each collector instance has a stable identity that scopes its chain and its log origin. Records carry the run they belong to as a field; the chain itself is collector-scoped, so concurrent runs interleave in one log and heartbeats need no run at all. | Two concurrent runs produce one contiguous chain with correct run tags; a heartbeat emitted with no run active is chained and anchored |
| ☐ `FR-59` | **Action record and chain entry are separate structures** — The canonicalised, hashed ActionRecord is immutable and contains no chain metadata. prev, leaf and head live in a ChainEntry wrapper that is never canonicalised, so the digest of a record can never depend on a value derived from it. Conformance vectors publish the exact bytes hashed. | Conformance vectors: given a fixed ActionRecord, the canonical bytes, leaf and head are byte-exact. A test asserts no chain field appears inside the canonicalised subject |
| ☐ `FR-62` | **Retries, timeouts and errors in the schema** — The record schema represents a failed, timed-out or retried tool call explicitly: an outcome enum, an attempt number, and a correlation id grouping attempts of one logical action. source_seq advances once per observed ATTEMPT, not per logical action, because a timed-out attempt may already have caused an external side effect and must stay independently accountable. Correlation, not the counter, is what groups attempts. The correlation identifier is opaque and randomly generated, never derived from a payload, user or session, because it is retained after erasure. | Interleaved retries across two correlations keep source_seq strictly increasing; an omitted retry is detected as a source_seq gap; coverage reports attempt count and logical-action count separately |

### M2 — Key custody

Make yesterday's record unforgeable with today's key, and state the precondition honestly.

- **Gate:** `AC-3` — Re-sign rewritten history with the current key
- **Requirements:** 5 (SEC×2  FR×1  NFR×1  OPS×1)
- **Effort:** weeks 2
- **Exit criteria:** An epoch-N key cannot produce a valid epoch-N-1 signature against a real HSM or KMS. The non-exportable custody precondition appears wherever the forward-secrecy claim does.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-11` | **Forward-secure epoch ratchet** — Evolve the signing key per epoch and destroy the predecessor so prior entries cannot be re-signed with the current key. | Test: epoch N key cannot produce a valid epoch N-1 signature |
| ☐ `NFR-09` | **HSM/KMS support** — Operate with a KMS or HSM offering non-exportable keys. | Integration test against at least one KMS and one HSM |
| ☐ `SEC-08` | **Resist re-signing history** — Re-signing rewritten history with the current key must be detectable under non-exportable custody. | Epoch ratchet test with HSM |
| ☐ `SEC-17` | **State the forward-secrecy precondition** — Any forward-secrecy claim must state its non-exportable key custody precondition in the same place. | Documentation review |
| ☐ `OPS-04` | **Separation-of-duties guidance** — Document the key-custody split between engineering and internal audit. | Guide published and reviewed |

### M3a — Anchoring and sequencing

The first second party. Close truncation and erasure, which no amount of local cryptography can reach.

- **Gate:** `AC-4` — Truncate the record's tail; `AC-5` — Erase events and renumber into a clean stream
- **Requirements:** 38 (FR×25  SEC×7  INT×2  NFR×1  PRIV×1  SCOPE×1  DOC×1)
- **Effort:** weeks 5-7
- **Exit criteria:** Red-team D, E and F all DETECTED. A run with no configuration at all anchors to a public log the project does not operate. A rolled-back witness is detected. An auditor supplying their own acceptance policy verifies the same pack. Egress captured against real witness traffic, confirming no content leaves the host.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-12` | **C2SP checkpoint emission** — Emit checkpoints in C2SP tlog-witness conformant format. | Conformance suite; third-party witness accepts checkpoint |
| ☐ `FR-13` | **Configurable witness set** — Submit roots to a configurable list of witnesses rather than a single endpoint. | Config test with 3 witnesses |
| ☐ `FR-14` | **Rekor witness adapter** — Support Rekor as a witness type. | Live anchor against Rekor; inclusion proof retrieved |
| ☐ `FR-19` | **Configurable quorum** — Accept a K-of-N quorum setting governing how many countersignatures a batch requires. | Verifier rejects a batch below quorum |
| ☐ `FR-20` | **Configurable anchor cadence** — Accept an anchor_interval setting that determines the mutability window. | Observed anchor spacing matches configuration |
| ☐ `FR-21` | **Soft anchor tier** — Provide a fast anchor tier, default every 10 seconds. | Timing test |
| ☐ `FR-42` | **Operator enrolment** — Operator identity is the operator public key together with the log origin, and it is the same notion whether the witness is hosted or self-hosted. Only the provisioning differs: with a self-hosted witness it is local configuration and no account exists anywhere, which is what the zero-egress promise means; with a hosted witness it is a registration. | Zero-egress deployment completes with no account and no outbound registration; a hosted deployment registers the same key and origin and the verifier treats both identically |
| ☐ `FR-43` | **Witness verifies consistency, not increments** — The witness accepts a checkpoint whose tree_size is greater than or equal to the last it recorded for that operator AND whose Merkle consistency proof from the previous size verifies. It does not require tree_size to increase by one: a checkpoint published every 10 seconds or 1,024 records legitimately jumps. Witness state is updated atomically with the signature. | 100 records then a checkpoint, then 40 more then a checkpoint at 140: accepted. A truncated or forked tree at any size: rejected, because consistency fails |
| ☐ `FR-44` | **Witness retains roots** — The witness keeps submitted roots in its own append-only store. | Root retrievable from the witness independently |
| ☐ `FR-45` | **Witness stamps its own clock** — The countersignature carries the witness's own time, not the operator's. | Operator-supplied time cannot influence the countersignature |
| ☐ `NFR-03` | **Default mutability window** — Default anchor interval of 10 seconds. | Default config inspection plus timing test |
| ☐ `SEC-03` | **No trust in operator or vendor** — Verification must not require trusting the operator, host, collector binary, or Splitstick. | Verification from bytes and public keys only |
| ☐ `SEC-04` | **One honest witness assumption** — Security holds if at least one witness in the configured set is honest; the assumption is documented. | Documented; quorum semantics tested |
| ☐ `SEC-09` | **Resist truncation** — Truncating the record's tail must be detectable. | Red-team class D |
| ☐ `SEC-10` | **Resist erasure and renumbering** — Erasing events and renumbering into a clean stream must be detectable. | Red-team class F |
| ☐ `SEC-15` | **Witness sees roots only** — Witnesses receive salted roots and nothing else. | Wire capture of all witness traffic |
| ☐ `INT-01` | **C2SP conformance** — Conform to the C2SP tlog-witness checkpoint specification. | Conformance suite against the published spec |
| ☐ `INT-02` | **Verify third-party countersignatures** — The verifier accepts countersignatures from witnesses we do not operate. | Verify a pack anchored only to Rekor and a third-party TSA |
| ☐ `FR-48` | **Shipped default witness configuration** — Ship a default the project neither operates nor overloads: an RFC 3161 timestamp authority for the per-batch countersignature and clock, plus a trust-minimised roll-up anchor on a slow interval. A transparency log such as Rekor is opt-in — for operators self-hosting one, or whose volume suits a public instance — and never the shipped default, because a 10-second cadence against a public good is not acceptable use. | Default config asserted in test; a day of operation produces no more than the configured roll-up count against any public service |
| ☐ `FR-50` | **Witness publishes signed tree heads** — The witness publishes its own signed tree head so an operator or third party can detect a rolled-back or equivocating witness. | Rollback simulation: a witness serving an earlier head is detected |
| ☐ `SEC-25` | **Witness time source** — The witness clock derives from a documented, traceable time source, and the verifier surfaces the witness's declared time discipline. | Time source documented; drift monitored and alerted |
| ☐ `PRIV-01` | **Zero content egress** — No content bytes leave the operator's host under any configuration. | Full egress capture during a representative run |
| ☐ `FR-30` | **Acceptance policy as input** — The verifier takes a caller-supplied acceptance policy naming trusted witness keys and quorum. | Same pack verifies under two different policies |
| ☐ `FR-31` | **Evidence pack carries all countersignatures** — Packs include every countersignature collected, not only Splitstick's. | Automated pack assertion: after anchoring to three witnesses, the pack contains three signature lines and verification succeeds under a policy naming only the third |
| ☐ `FR-22` | **Hard anchor tier** — Provide an optional slow, trust-minimised anchor tier that no company can withdraw. | Anchor obtained; off unless explicitly enabled |
| ☐ `SCOPE-15` | **Hard anchor must be disableable** — The trust-minimised roll-up anchor must be switchable off in one setting, and switching it off must be recorded in the chain like any other policy change. It is on by default because it is the only free public anchor with no acceptable-use objection; it must never be mandatory, because some regulated buyers forbid public-chain anchoring outright. | One setting disables it; the change appears as a chain event |
| ☐ `FR-53` | **Roll-up anchoring** — Anchor a periodic summary checkpoint covering many batches, separately from the per-batch soft anchor, so a public or rate-limited witness receives a handful of entries per day rather than thousands. | A day of 10-second batches produces one roll-up entry per configured interval, and the roll-up proves inclusion of every batch beneath it |
| ☐ `FR-16` | **RFC 3161 TSA adapter** — Support an RFC 3161 timestamp authority as a witness type. | Timestamp token obtained and verified |
| ☐ `FR-17` | **Operator-hosted witness adapter** — Support an operator's own internal witness endpoint. | Self-hosted witness round trip |
| ☐ `FR-54` | **Cross-pack consistency verification** — Given two or more evidence packs, detect a record inconsistent with a checkpoint already countersigned in an earlier pack — so a record truncated below a height previously disclosed is contradicted offline, with no live service. | Disclose at seq 5000, truncate to 4799, compare the two packs: the earlier countersigned checkpoint contradicts the later record |
| ☐ `SEC-26` | **Resist truncation below a disclosed height** — A record truncated below a sequence already disclosed in a countersigned pack must be detectable by comparing the two, without any stateful witness. | Red-team class I: truncate below a disclosed height; cross-pack comparison fails closed |
| ☐ `DOC-09` | **Reconciliation guidance** — Document reconciliation against counterparty records as a detection method for erasure and omission, with its limits stated: it requires access to the counterparty and it is a procedure an auditor performs, not a guarantee the software makes. | Guidance published; the limits appear wherever the method is claimed |
| ☐ `FR-57` | **Verifier states witness-set capabilities** — The verifier prints what the configured or observed witness set can and cannot establish — in particular whether any witness maintains operator sequence state, and therefore whether truncation above the last disclosed height is detectable at all. | Test asserts a stateless witness set yields an explicit "truncation not detectable above <height>" line, and a stateful one does not |
| ☐ `FR-26` | **Gap declarations with an exact span** — When the observation counter survived the failure, record a signed declaration naming the exact source_seq span that was observed but never written. It occupies one record position. Observation gaps are detected from consecutive persisted source_seq values, never by comparing source_seq with record_seq, which count different things. | Induce a write failure for 6 observed actions with the counter intact: one gap record names source_seq 4790-4795, and a mixed stream of actions, heartbeats and policy records shows no false gap |
| ☐ `FR-27` | **Countersigned gap declarations** — Gap declarations are themselves submitted for countersignature. | Declaration carries a witness signature |
| ☐ `FR-63` | **Pinned operator identity** — The acceptance policy names the operator identity the reader expects, and the verifier reports any pack presented under a different key or origin rather than silently accepting it. Nothing prevents an operator maintaining a second log; the guarantee is that a reader who pinned an identity is told when they are shown another. | A pack under an unpinned key yields IDENTITY_UNPINNED; a pack under the pinned key verifies; the limit is documented as detection rather than prevention |
| ☐ `FR-65` | **Operator-declared key custody** — The key custody class — non-exportable KMS or HSM, versus a software key — is declared in a chained record per epoch, because an HSM signature and a file-key signature are byte-identical and a verifier cannot otherwise tell them apart. The declaration proves the operator declared it, not that the key was non-exportable or later destroyed. Custody is reported as operator-declared unless a provider attestation document is supplied alongside, which is the only path to independently supported custody. | A verifier prints the declared class per epoch, labels it operator-declared, and refuses to claim forward secrecy for an epoch declared software-keyed; a supplied provider attestation is reported as independently supported |
| ☐ `FR-70` | **Validate a provider custody attestation** — Before reporting custody as independently supported, validate the attestation: issuer chains to a provider root named in the acceptance policy, document signature valid over the bytes presented, attested key is the one that signed this epoch, attestation period covers the epoch, and the document actually asserts non-exportability. Even all five together do not establish historical key destruction, which remains operator-declared. | Five negative tests, one per check, each rejecting the attestation; a valid attestation yields independently-supported custody; destruction is still reported as operator-declared |

### M3b — Practice statement and resilience

Say exactly what the countersignature means, and make sure losing a witness does not lose the evidence.

- **Gate:** none — unlocks adoption rather than closing an attack class
- **Requirements:** 22 (LEG×10  FR×7  NFR×2  OPS×2  SEC×1)
- **Effort:** weeks 3-4
- **Exit criteria:** Practice statement published, versioned and itself anchored, naming its time discipline. An agent run completes normally with every witness unreachable. Restore drill meets the stated recovery point objective. Countersignatures from a retired witness key still verify. Operator key compromise recoverable as a declared, countersigned discontinuity.

| | ID | Requirement | Verified by |
|---|---|---|---|
| ☐ `FR-38` | **Fail-open with marked batch** — When no witness is reachable, chain and sign locally, mark the batch unwitnessed, and queue it. | Agent completes with all witnesses unreachable |
| ☐ `FR-39` | **Late countersignature records real time** — A retroactive countersignature records the witness's actual receipt time, not the batch's claimed time. | Test asserts the witness receipt time differs from the batch timestamp and both appear in the record |
| ☐ `NFR-12` | **Never degrade availability** — The collector must never be able to stop or block an agent run. | Chaos test: witness outage, disk full, slow witness |
| ☐ `NFR-13` | **Durable local queue** — Unwitnessed batches survive process restart and are re-submitted. | Kill -9 during outage, then recovery |
| ☐ `LEG-01` | **Publish a Witness Practice Statement** — Publish a versioned practice statement defining exactly what a countersignature means. | Self-authored practice statement published in the repository and versioned |
| ☐ `LEG-02` | **WPS asserts receipt time** — The countersignature asserts the root was received at the stated time per the witness clock. | Statement text review against implementation |
| ☐ `LEG-03` | **WPS asserts successor ordering** — The countersignature asserts the root is the immediate successor of the previous one for that operator. | Statement matches FR-43 behaviour |
| ☐ `LEG-04` | **WPS asserts retention** — The countersignature asserts the witness retained the root in its own append-only store. | Statement matches FR-44 behaviour |
| ☐ `LEG-05` | **WPS disclaims occurrence** — The statement disclaims any assertion that the underlying actions occurred. | Text review |
| ☐ `LEG-06` | **WPS disclaims truthfulness** — The statement disclaims any assertion that recorded content is true. | Text review |
| ☐ `LEG-07` | **WPS disclaims completeness** — The statement disclaims completeness and points to coverage attestation instead. | Text review |
| ☐ `LEG-08` | **WPS disclaims lawfulness** — The statement disclaims any assertion that an action was lawful or authorised. | Text review |
| ☐ `LEG-09` | **WPS versioned and anchored** — The practice statement is itself versioned and anchored like any other record. | Statement root present in the witness log; counsel review deferred to a funded release |
| ☐ `OPS-02` | **Queue drain and retry** — Drain and re-submit queued unwitnessed batches with backoff once a witness returns. | Outage and recovery test |
| ☐ `FR-51` | **Witness key rotation** — Rotate witness keys while keeping historical countersignatures verifiable, by publishing a signed key history. | Countersignatures from a retired key still verify after rotation |
| ☐ `OPS-06` | **Witness store durability** — The witness store is replicated and recoverable, with a documented recovery point objective, because a witness that loses its roots destroys the corroboration it exists to provide. | Restore drill from backup; RPO measured against the stated objective |
| ☐ `LEG-19` | **WPS states the time discipline** — The practice statement names the witness's time source and the limits of the time assertion. | Statement text reviewed against SEC-25 implementation |
| ☐ `SEC-24` | **Key compromise recovery** — Document and support recovery from operator key compromise: a declared, countersigned discontinuity rather than a silent re-key. | Compromise drill: discontinuity is recorded, countersigned and visible to the verifier |
| ☐ `FR-58` | **Reserved slot for gap declarations** — Pre-allocate storage sufficient to write a gap declaration, so the declaration can be written even when the store is otherwise exhausted. If even that fails, the condition is surfaced out of band and the next successful write declares the lost window. | Disk-exhaustion test: the agent completes, a gap declaration is written from the reserve, and the lost window appears in the coverage report |
| ☐ `FR-60` | **Unknown-loss intervals** — When the observation counter did not survive — an unrecoverable crash with the counter only in memory — declare an unknown-loss interval bounded by the last durable checkpoint and the first record after restart. Never fabricate an exact span. The two kinds of loss evidence are distinct record kinds and a verifier reports them differently. | Disk exhaustion followed by kill -9 and restart: an unknown-loss interval is written with no span, and no exact gap is invented. A verifier distinguishes it from a declared span |
| ☐ `FR-61` | **Observation counter durability** — Checkpoint the observation counter durably at each batch flush, so an unrecoverable crash loses at most the current window and the unknown-loss interval is bounded rather than open-ended. | Kill -9 mid-window: the restart reads the last checkpointed source_seq and the declared unknown interval starts there, not at zero |
| ☐ `FR-68` | **Unwitnessed outage ceiling** — Fail-open must not become indefinite. An unwitnessed_ceiling sets the point at which the collector raises an alert out of band, and beyond which the coverage report refuses to issue a completeness claim spanning the outage, stating the unwitnessed window instead. | Exceed the ceiling: an alert is raised and the coverage report declines a completeness claim for that window rather than reporting it as covered |

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

- **Gate:** none — unlocks adoption rather than closing an attack class
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

- **Gate:** none — unlocks adoption rather than closing an attack class
- **Requirements:** 19 (FR×6  GOV×4  NFR×3  INT×2  OPS×2  LEG×2)
- **Effort:** weeks 4-6
- **Exit criteria:** End-to-end capture against two non-OMA runtimes over both MCP transports. A third-party witness passes the published conformance suite. A fully self-hosted deployment verified at zero egress, with no account and no enrolment with us.

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

- **Gate:** none — unlocks adoption rather than closing an attack class
- **Requirements:** 37 (SCOPE×15  GOV×7  DOC×6  SEC×4  LEG×3  TRC×2)
- **Effort:** weeks 2
- **Exit criteria:** Claims audit clean across all sixteen scope guards. Every published figure has a passing benchmark behind it. Bounty terms published, stating plainly that recognition is non-cash while the project is unfunded. No surface anywhere claims conformity, certification, or tamper-proofing.

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
