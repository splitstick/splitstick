# Requirements traceability matrix

Derived line by line from [docs/splitstick-1.0-release-notes.md (rev. 5)](../docs/splitstick-1.0-release-notes.md).

Every requirement traces to a promise made in the release notes. 'source' names the section. Nothing here is invented: if the notes do not promise it, it is not a requirement.

**Generated — do not edit by hand.** Source of truth is `requirements/*.json`.
Regenerate with `npm run requirements`.

## Totals

| Category | Count |
|---|---:|
| Functional | 56 |
| Security | 26 |
| Legal & regulatory | 19 |
| Governance, licensing & community | 19 |
| Scope guards (negative) | 16 |
| Non-functional | 13 |
| Roadmap (post-1.0) | 10 |
| Privacy & data protection | 9 |
| Documentation & transparency | 9 |
| Interoperability & standards | 7 |
| Operational | 6 |
| Traceability & process | 5 |
| **Total** | **195** |

### By release

| Release | Count |
|---|---:|
| 1.0 | 178 |
| 2.0 | 5 |
| commercial | 12 |
| **Total** | **195** |

## Matrix

### Functional — 56

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `FR-01` | **OMA journal backend** — Provide a RunJournal implementation for @open-multi-agent/core, installable as a dependency and enabled by configuration alone. | Capture — two collectors | Integration test: journal written through OMA orchestrator | 1.0 | M1 | ☐ |
| `FR-02` | **OMA approval-store backend** — Provide an approval-store implementation for OMA so approval requests and decisions enter the same record. | Capture — two collectors | Integration test: suspend/approve/resume cycle recorded | 1.0 | M1 | ☐ |
| `FR-03` | **MCP proxy collector (stdio)** — Intercept agent-to-MCP-server traffic over stdio and record every tool call and result. | Capture — two collectors | E2E test against a reference MCP server over stdio | 1.0 | M6 | ☐ |
| `FR-04` | **MCP proxy collector (HTTP)** — Same capture over HTTP transport. | Getting started — tested against MCP servers over stdio and HTTP | E2E test against a reference MCP server over HTTP | 1.0 | M6 | ☐ |
| `FR-05` | **Digest tool identity and arguments** — Record and digest the tool name and its invocation arguments. | Capture — action record | Red-team attack A fails closed | 1.0 | M1 | ☐ |
| `FR-06` | **Digest tool result** — Record and digest the tool result content. | Capture — action record | Red-team attack A fails closed | 1.0 | M1 | ☐ |
| `FR-07` | **Digest approval decisions** — Record and digest approval decisions, including the deciding identity as supplied. | Capture — action record | Unit test: decision tamper detected | 1.0 | M1 | ☐ |
| `FR-08` | **Predecessor chaining** — Every event carries a cryptographic digest of its predecessor. | Integrity — chained, salted, ratcheted | Red-team attacks B, C, F fail closed | 1.0 | M1 | ☐ |
| `FR-09` | **Per-leaf salting** — Every leaf is salted with a per-leaf random nonce before hashing. | Integrity — salted leaves | Unit test: identical content yields distinct digests | 1.0 | M1 | ☐ |
| `FR-10` | **Batch signing with operator key** — Sign each batch root with the operator-supplied key. | Integrity — batches are signed with your key | Signature verifies under operator public key | 1.0 | M1 | ☐ |
| `FR-11` | **Forward-secure epoch ratchet** — Evolve the signing key per epoch and destroy the predecessor so prior entries cannot be re-signed with the current key. | Integrity — forward-secure epoch ratchet | Test: epoch N key cannot produce a valid epoch N-1 signature | 1.0 | M2 | ☐ |
| `FR-12` | **C2SP checkpoint emission** — Emit checkpoints in C2SP tlog-witness conformant format. | Independence — C2SP tlog-witness conformant | Conformance suite; third-party witness accepts checkpoint | 1.0 | M3a | ☐ |
| `FR-13` | **Configurable witness set** — Submit roots to a configurable list of witnesses rather than a single endpoint. | Independence — to a witness set | Config test with 3 witnesses | 1.0 | M3a | ☐ |
| `FR-14` | **Rekor witness adapter** — Support Rekor as a witness type. | Independence — Rekor | Live anchor against Rekor; inclusion proof retrieved | 1.0 | M3a | ☐ |
| `FR-15` | **transparency-dev/witness adapter** — Support transparency-dev/witness as a witness type. | Independence — transparency-dev/witness | Anchor against a local instance | 1.0 | M6 | ☐ |
| `FR-16` | **RFC 3161 TSA adapter** — Support an RFC 3161 timestamp authority as a witness type. | Independence — an RFC 3161 TSA | Timestamp token obtained and verified | 1.0 | M3a | ☐ |
| `FR-17` | **Operator-hosted witness adapter** — Support an operator's own internal witness endpoint. | Independence — your own internal authority | Self-hosted witness round trip | 1.0 | M3a | ☐ |
| `FR-18` | **Splitstick hosted witness adapter** — Support the Splitstick hosted witness. | Independence — or Splitstick's | Hosted witness round trip | commercial | — | ☐ |
| `FR-19` | **Configurable quorum** — Accept a K-of-N quorum setting governing how many countersignatures a batch requires. | Independence — set quorum: 2 | Verifier rejects a batch below quorum | 1.0 | M3a | ☐ |
| `FR-20` | **Configurable anchor cadence** — Accept an anchor_interval setting that determines the mutability window. | Independence — cadence is yours to set | Observed anchor spacing matches configuration | 1.0 | M3a | ☐ |
| `FR-21` | **Soft anchor tier** — Provide a fast anchor tier, default every 10 seconds. | Independence — soft anchor | Timing test | 1.0 | M3a | ☐ |
| `FR-22` | **Hard anchor tier** — Provide an optional slow, trust-minimised anchor tier that no company can withdraw. | Independence — hard anchor | Anchor obtained; off unless explicitly enabled | 1.0 | M3a | ☐ |
| `FR-23` | **Policy changes as chain events** — Record any change to the witness set or quorum as a timestamped event inside the chain. | Independence — written into the chain | Red-team: policy downgrade is visible in the record | 1.0 | M4 | ☐ |
| `FR-24` | **Signed heartbeats** — Emit signed heartbeats into the collector-scoped chain at a configured interval, independently of whether any run is active, because the dangerous window is precisely when none is. | Coverage attestation — signed heartbeats | Stopping the collector produces a detectable gap, including during an interval with no agent run | 1.0 | M4 | ☐ |
| `FR-25` | **Build digest in heartbeat** — Each heartbeat carries the collector's build digest. | Coverage attestation — build digest | Patched binary reports an unrecognised digest | 1.0 | M4 | ☐ |
| `FR-26` | **Signed gap declarations** — Allow the operator to record an explicit, signed declaration of a genuinely lost batch so the sequence can recover. | Coverage attestation — signed gap declarations | Sequence resumes after a declared gap without a silent reset | 1.0 | M4 | ☐ |
| `FR-27` | **Countersigned gap declarations** — Gap declarations are themselves submitted for countersignature. | Coverage attestation — signed, countersigned statement of absence | Declaration carries a witness signature | 1.0 | M4 | ☐ |
| `FR-28` | **splitstick coverage** — Produce a coverage report over a date range stating the percentage of tool calls captured and proving collector liveness throughout. | Coverage attestation — splitstick coverage | Report output matches injected gaps exactly | 1.0 | M4 | ☐ |
| `FR-29` | **splitstick verify** — Verify chain integrity, batch signatures and witness countersignatures from files alone. | Proof — offline verification | All red-team classes fail closed; baseline passes | 1.0 | M1 | ☐ |
| `FR-30` | **Acceptance policy as input** — The verifier takes a caller-supplied acceptance policy naming trusted witness keys and quorum. | Proof — an input, not a hardcoded trust store | Same pack verifies under two different policies | 1.0 | M3a | ☐ |
| `FR-31` | **Evidence pack carries all countersignatures** — Packs include every countersignature collected, not only Splitstick's. | Proof — never only ours | Automated pack assertion: after anchoring to three witnesses, the pack contains three signature lines and verification succeeds under a policy naming only the third | 1.0 | M3a | ☐ |
| `FR-32` | **splitstick disclose** — Emit a Merkle inclusion proof for a single named event. | Disclosure — splitstick disclose | Recipient verifies one event without the rest | 1.0 | M5 | ☐ |
| `FR-33` | **Inclusion proof binds to countersigned root** — Inclusion proofs verify against a countersigned root, not a bare local digest. | Disclosure — against a countersigned root | Proof rejected when root is unwitnessed | 1.0 | M5 | ☐ |
| `FR-34` | **Optional batch padding** — Provide optional padding of batches to obscure activity volume. | Disclosure — optional batch padding | Anchor volume decoupled from event volume when enabled | 1.0 | M5 | ☐ |
| `FR-35` | **Content externalised from the chain** — The chain stores salted commitments and pointers only; content lives in operator-controlled mutable storage. | Erasure — no content is ever in the chain | Automated scan of chain files for any content string from the fixture finds nothing (shares PRIV-02 harness) | 1.0 | M1 | ☐ |
| `FR-36` | **Crypto-shredding** — Deleting content and its key leaves the chain verifiable and the commitment permanently unlinkable. | Erasure — crypto-shredding | Verify passes after content+key deletion | 1.0 | M5 | ☐ |
| `FR-37` | **Retention policy on storage** — Retention and erasure are configurable at the storage layer, independent of the cryptography. | Erasure — policy settings on your storage | Retention config honoured; chain unaffected | 1.0 | M5 | ☐ |
| `FR-38` | **Fail-open with marked batch** — When no witness is reachable, chain and sign locally, mark the batch unwitnessed, and queue it. | Operations — fails open, loudly | Agent completes with all witnesses unreachable | 1.0 | M3b | ☐ |
| `FR-39` | **Late countersignature records real time** — A retroactive countersignature records the witness's actual receipt time, not the batch's claimed time. | Operations — the witness's real time | Test asserts the witness receipt time differs from the batch timestamp and both appear in the record | 1.0 | M3b | ☐ |
| `FR-40` | **Late anchors reported as gaps** — Windows anchored late are reported as coverage gaps. | Operations — reported as a coverage gap | Coverage report flags the widened window | 1.0 | M4 | ☐ |
| `FR-41` | **Configuration file** — Support splitstick.yaml with witnesses, quorum, on_unavailable and anchor_interval keys. | Getting started — splitstick.yaml | The documented example config is loaded in test and each key asserted to take effect | 1.0 | M1 | ☐ |
| `FR-42` | **Operator enrolment** — Register an operator identity and public key with a witness so per-operator sequence state can be kept. | Witness Practice Statement — this enrolled operator | Enrolment then successive anchors tracked | 1.0 | M3a | ☐ |
| `FR-43` | **Witness enforces monotonic sequence** — The witness verifies that each submitted root is the immediate successor of the last recorded for that operator. | Witness Practice Statement — immediate successor | Truncation and erasure both detected | 1.0 | M3a | ☐ |
| `FR-44` | **Witness retains roots** — The witness keeps submitted roots in its own append-only store. | Witness Practice Statement — has retained it | Root retrievable from the witness independently | 1.0 | M3a | ☐ |
| `FR-45` | **Witness stamps its own clock** — The countersignature carries the witness's own time, not the operator's. | Witness Practice Statement — at this time, per its clock | Operator-supplied time cannot influence the countersignature | 1.0 | M3a | ☐ |
| `FR-46` | **Conformance test suite** — Publish an executable conformance suite any witness implementation can run against itself. | Licence and governance — conformance suite is open | Suite runs green against the reference witness | 1.0 | M6 | ☐ |
| `FR-47` | **Witness list as data** — Maintain the list of known conformant witnesses as a machine-readable file, each entry carrying its acceptable-use terms, rate limits, and whether it retains entries publicly, so an operator chooses on informed grounds rather than by default. | Licence and governance — a plain file in the repository | File parses; the collector consumes it; every entry states its acceptable-use position | 1.0 | M6 | ☐ |
| `FR-48` | **Shipped default witness configuration** — Ship a default the project neither operates nor overloads: an RFC 3161 timestamp authority for the per-batch countersignature and clock, plus a trust-minimised roll-up anchor on a slow interval. A transparency log such as Rekor is opt-in — for operators self-hosting one, or whose volume suits a public instance — and never the shipped default, because a 10-second cadence against a public good is not acceptable use. | Independence — the shipped default anchors to a log we do not run | Default config asserted in test; a day of operation produces no more than the configured roll-up count against any public service | 1.0 | M3a | ☐ |
| `FR-49` | **Documented CLI contract** — Provide the entry points and flags printed in Getting started: collect-oma, mcp-proxy (--upstream, --out), verify (--policy), coverage (--from, --to) and disclose (--event, --out). | Getting started — the published commands | CLI contract test executes every documented invocation verbatim | 1.0 | M6 | ☐ |
| `FR-50` | **Witness publishes signed tree heads** — The witness publishes its own signed tree head so an operator or third party can detect a rolled-back or equivocating witness. | Durability — losing a witness must not lose the evidence | Rollback simulation: a witness serving an earlier head is detected | 1.0 | M3a | ☐ |
| `FR-51` | **Witness key rotation** — Rotate witness keys while keeping historical countersignatures verifiable, by publishing a signed key history. | Durability — key rotation | Countersignatures from a retired key still verify after rotation | 1.0 | M3b | ☐ |
| `FR-52` | **Canonicalisation completeness** — The canonical encoding must cover every field of the action record at every nesting depth. A test must prove that mutating any single field, at any depth, changes the leaf digest. | Capture — action record: tool name, arguments, result, approval decision | Property test mutating each field in turn, including nested argument keys; every mutation must change the digest | 1.0 | M1 | ☐ |
| `FR-53` | **Roll-up anchoring** — Anchor a periodic summary checkpoint covering many batches, separately from the per-batch soft anchor, so a public or rate-limited witness receives a handful of entries per day rather than thousands. | Independence — tiered anchoring | A day of 10-second batches produces one roll-up entry per configured interval, and the roll-up proves inclusion of every batch beneath it | 1.0 | M3a | ☐ |
| `FR-54` | **Cross-pack consistency verification** — Given two or more evidence packs, detect a record inconsistent with a checkpoint already countersigned in an earlier pack — so a record truncated below a height previously disclosed is contradicted offline, with no live service. | Proof — offline verification; Durability | Disclose at seq 5000, truncate to 4799, compare the two packs: the earlier countersigned checkpoint contradicts the later record | 1.0 | M3a | ☐ |
| `FR-55` | **Counterparty reference capture** — Extract externally issued identifiers from a tool result and index them for reconciliation. The index lives in the deletable content store, never in the chain, because a transaction reference can itself be identifying. | Capture — action record | A result containing an external reference is indexed and queryable; the index is removed by crypto-shredding | 1.0 | M1 | ☐ |
| `FR-56` | **Collector instance identity** — Each collector instance has a stable identity that scopes its chain and its log origin. Records carry the run they belong to as a field; the chain itself is collector-scoped, so concurrent runs interleave in one log and heartbeats need no run at all. | Capture — action record; Coverage attestation | Two concurrent runs produce one contiguous chain with correct run tags; a heartbeat emitted with no run active is chained and anchored | 1.0 | M1 | ☐ |

### Non-functional — 13

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `NFR-01` | **Append overhead** — p99 append overhead below 1 ms per event. | Numbers we are signing up to | Benchmark harness, p99 over 1e6 events | 1.0 | M1 | ☐ |
| `NFR-02` | **Run latency budget** — Added end-to-end agent run latency below 2%. | Numbers we are signing up to | A/B benchmark with and without the collector | 1.0 | M1 | ☐ |
| `NFR-03` | **Default mutability window** — Default anchor interval of 10 seconds. | Numbers we are signing up to | Default config inspection plus timing test | 1.0 | M3a | ☐ |
| `NFR-04` | **Verification throughput** — Verify a 100,000-event run in under 2 seconds, offline. | Numbers we are signing up to | Benchmark on a documented reference machine | 1.0 | M5 | ☐ |
| `NFR-05` | **No network at verification** — Verification completes with networking disabled. | Proof — no network | Test executed in a network-isolated sandbox | 1.0 | M5 | ☐ |
| `NFR-06` | **No credentials at verification** — Verification requires no account, token or credential. | Proof — no credentials, no account | Test with an empty environment | 1.0 | M5 | ☐ |
| `NFR-07` | **Long-term verifiability** — Evidence remains verifiable years later; algorithms and formats are versioned to allow it. | Proof — will still work in 2031 | Format version negotiation test; documented algorithm migration path | 1.0 | M1 | ☐ |
| `NFR-08` | **Node.js 20+** — Run on Node.js 20 and later. | Getting started — requires Node.js 20+ | CI matrix across supported majors | 1.0 | M6 | ☐ |
| `NFR-09` | **HSM/KMS support** — Operate with a KMS or HSM offering non-exportable keys. | Getting started — a KMS or HSM | Integration test against at least one KMS and one HSM | 1.0 | M2 | ☐ |
| `NFR-10` | **OMA version compatibility** — Support @open-multi-agent/core 1.21.x. | Getting started — tested against 1.21.x | CI pinned against the supported range | 1.0 | M6 | ☐ |
| `NFR-11` | **MCP transport coverage** — Support MCP over stdio and HTTP. | Getting started — stdio and HTTP | E2E per transport | 1.0 | M6 | ☐ |
| `NFR-12` | **Never degrade availability** — The collector must never be able to stop or block an agent run. | Operations — no audit layer that can take down production | Chaos test: witness outage, disk full, slow witness | 1.0 | M3b | ☐ |
| `NFR-13` | **Durable local queue** — Unwitnessed batches survive process restart and are re-submitted. | Operations — marked unwitnessed, and queued | Kill -9 during outage, then recovery | 1.0 | M3b | ☐ |

### Security — 26

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `SEC-01` | **Published threat model** — Publish a threat model naming the operator as the adversary. | Threat model | Document exists and is referenced from the README | 1.0 | M0 | ✅ |
| `SEC-02` | **Detection, not prevention** — The stated security goal is detection and attribution, not prevention. | Threat model — goal | Claims review against documentation and marketing | 1.0 | M0 | ✅ |
| `SEC-03` | **No trust in operator or vendor** — Verification must not require trusting the operator, host, collector binary, or Splitstick. | Threat model — trust | Verification from bytes and public keys only | 1.0 | M3a | ☐ |
| `SEC-04` | **One honest witness assumption** — Security holds if at least one witness in the configured set is honest; the assumption is documented. | Threat model — trust | Documented; quorum semantics tested | 1.0 | M3a | ☐ |
| `SEC-05` | **Documented exclusions** — Publish what is out of scope: actions never attempted, a compromised model, a lying tool, full quorum collusion, a key exfiltrated before first use. | Threat model — out of scope | Document review | 1.0 | M0 | ✅ |
| `SEC-06` | **Resist action alteration** — Altering recorded arguments, result or approval decision must be detectable. | Attack class table, row 1 | Red-team class A | 1.0 | M1 | ☐ |
| `SEC-07` | **Resist consistent rewrite** — Altering an event and repairing its citing digest must be detectable. | Attack class table, row 2 | Red-team class C | 1.0 | M1 | ☐ |
| `SEC-08` | **Resist re-signing history** — Re-signing rewritten history with the current key must be detectable under non-exportable custody. | Attack class table, row 3 | Epoch ratchet test with HSM | 1.0 | M2 | ☐ |
| `SEC-09` | **Resist truncation** — Truncating the record's tail must be detectable. | Attack class table, row 4 | Red-team class D | 1.0 | M3a | ☐ |
| `SEC-10` | **Resist erasure and renumbering** — Erasing events and renumbering into a clean stream must be detectable. | Attack class table, row 5 | Red-team class F | 1.0 | M3a | ☐ |
| `SEC-11` | **Resist collector suppression** — Stopping or patching the collector and claiming a quiet period must be detectable and attributable. | Attack class table, row 6 | Kill and patch tests against coverage report | 1.0 | M4 | ☐ |
| `SEC-12` | **Resist policy downgrade** — Weakening the anchoring policy before tampering must be visible in the record. | Attack class table, row 7 | Test weakens the witness set, then asserts a countersigned policy event appears in the chain before the next batch | 1.0 | M4 | ☐ |
| `SEC-13` | **Digest pre-image resistance in practice** — Salting must prevent brute-force recovery of low-entropy action records from their digests. | Integrity — otherwise simply brute-forced | Dictionary attack against salted digests fails | 1.0 | M1 | ☐ |
| `SEC-14` | **Operator key never leaves operator** — Splitstick must never hold, receive, request or log the operator signing key. | Integrity — Splitstick never holds it, sees it, or asks for it | Automated egress capture during a representative run asserts no private key material leaves the host; plus a code check that no verifier or collector module imports a key-export API | 1.0 | M1 | ☐ |
| `SEC-15` | **Witness sees roots only** — Witnesses receive salted roots and nothing else. | Independence — salted roots only | Wire capture of all witness traffic | 1.0 | M3a | ☐ |
| `SEC-16` | **Bounded integrity claim** — Never claim tamper-proof; claim tamper-evident with attribution. | Scope — not tamper-proof | Claims review | 1.0 | M7 | ☐ |
| `SEC-17` | **State the forward-secrecy precondition** — Any forward-secrecy claim must state its non-exportable key custody precondition in the same place. | Integrity — this holds only under non-exportable key custody | Documentation review | 1.0 | M2 | ☐ |
| `SEC-18` | **Remote build attestation (experimental)** — Remote attestation of the collector build may ship as experimental; it must not be presented as preventing suppression. | Considered and rejected — stays experimental | Feature flagged experimental; claims review | 2.0 | — | ☐ |
| `SEC-19` | **Bounty intake and triage** — Operate an intake, triage and payment process for the tamper bounty. | Bounty terms | Process documented and exercised once before launch | 1.0 | M7 | ☐ |
| `SEC-20` | **Coordinated disclosure window** — Disclose within 90 days or on fix, whichever is sooner. | Bounty terms — first reporter, 90 days | Policy published; tracked per report | 1.0 | M7 | ☐ |
| `SEC-21` | **Publish unmitigated findings** — Publish findings even when no mitigation exists. | Bounty terms — including when we have no mitigation | Policy published; audited at each disclosure | 1.0 | M7 | ☐ |
| `SEC-22` | **Build provenance attestation** — Publish a provenance attestation for every released collector artifact, binding the digest to its source commit and build, so the digest in a heartbeat can be independently traced. | Provenance — a build digest you can check | Attestation verifies against the published artifact and source revision | 1.0 | M1 | ☐ |
| `SEC-23` | **Signed releases and SBOM** — Sign every release and publish an SBOM with pinned dependencies. | Provenance — signed releases and an SBOM | Signature and SBOM present and verified in CI for each release | 1.0 | M1 | ☐ |
| `SEC-24` | **Key compromise recovery** — Document and support recovery from operator key compromise: a declared, countersigned discontinuity rather than a silent re-key. | Durability — key compromise | Compromise drill: discontinuity is recorded, countersigned and visible to the verifier | 1.0 | M3b | ☐ |
| `SEC-25` | **Witness time source** — The witness clock derives from a documented, traceable time source, and the verifier surfaces the witness's declared time discipline. | Durability — the clock the witness stamps with | Time source documented; drift monitored and alerted | 1.0 | M3a | ☐ |
| `SEC-26` | **Resist truncation below a disclosed height** — A record truncated below a sequence already disclosed in a countersigned pack must be detectable by comparing the two, without any stateful witness. | Attack class table, rows 4 and 5 | Red-team class I: truncate below a disclosed height; cross-pack comparison fails closed | 1.0 | M3a | ☐ |

### Privacy & data protection — 9

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `PRIV-01` | **Zero content egress** — No content bytes leave the operator's host under any configuration. | Numbers — 0 bytes of content leaving your host | Full egress capture during a representative run | 1.0 | M3a | ☐ |
| `PRIV-02` | **No content in the chain** — The chain contains no plaintext content. | Erasure — no content is ever in the chain | Automated scan of chain files for plaintext | 1.0 | M1 | ☐ |
| `PRIV-03` | **Erasure via crypto-shredding** — Support a documented erasure procedure satisfying a data-subject deletion request. | Erasure — GDPR-compatible | Procedure documented and exercised; independent privacy review deferred to a funded release | 1.0 | M5 | ☐ |
| `PRIV-04` | **Chain survives erasure** — The chain still verifies after content deletion. | Erasure — the chain still verifies | Verify passes post-deletion | 1.0 | M5 | ☐ |
| `PRIV-05` | **Minimal retained artefacts** — After erasure, only a salted hash and timestamp remain. | Erasure — what survives is a salted hash and a timestamp | Automated scan after crypto-shredding asserts only salted hashes and timestamps remain | 1.0 | M5 | ☐ |
| `PRIV-06` | **Disclosure minimisation** — A disclosure reveals the named event and nothing else about other events' contents. | Disclosure — without seeing anything else | Test asserts a disclosure pack contains exactly one salt and that no sibling leaf is reproducible from the pack | 1.0 | M5 | ☐ |
| `PRIV-07` | **Disclose the tree-size leak** — Document that an inclusion proof reveals the total count of recorded actions. | Disclosure — the honest limit | Documentation review | 1.0 | M5 | ☐ |
| `PRIV-08` | **Disclose the cadence leak** — Document that anchor cadence leaks activity volume. | Disclosure — anchor cadence likewise leaks | Documentation review | 1.0 | M5 | ☐ |
| `PRIV-09` | **Operator-controlled retention** — Retention is a setting on operator-controlled storage, not a vendor policy. | Erasure — policy settings on your storage | Configuration test | 1.0 | M5 | ☐ |

### Legal & regulatory — 19

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `LEG-01` | **Publish a Witness Practice Statement** — Publish a versioned practice statement defining exactly what a countersignature means. | Witness Practice Statement | Self-authored practice statement published in the repository and versioned | 1.0 | M3b | ☐ |
| `LEG-02` | **WPS asserts receipt time** — The countersignature asserts the root was received at the stated time per the witness clock. | WPS — a countersignature asserts | Statement text review against implementation | 1.0 | M3b | ☐ |
| `LEG-03` | **WPS asserts successor ordering** — The countersignature asserts the root is the immediate successor of the previous one for that operator. | WPS — a countersignature asserts | Statement matches FR-43 behaviour | 1.0 | M3b | ☐ |
| `LEG-04` | **WPS asserts retention** — The countersignature asserts the witness retained the root in its own append-only store. | WPS — a countersignature asserts | Statement matches FR-44 behaviour | 1.0 | M3b | ☐ |
| `LEG-05` | **WPS disclaims occurrence** — The statement disclaims any assertion that the underlying actions occurred. | WPS — asserts nothing about | Text review | 1.0 | M3b | ☐ |
| `LEG-06` | **WPS disclaims truthfulness** — The statement disclaims any assertion that recorded content is true. | WPS — asserts nothing about | Text review | 1.0 | M3b | ☐ |
| `LEG-07` | **WPS disclaims completeness** — The statement disclaims completeness and points to coverage attestation instead. | WPS — asserts nothing about | Text review | 1.0 | M3b | ☐ |
| `LEG-08` | **WPS disclaims lawfulness** — The statement disclaims any assertion that an action was lawful or authorised. | WPS — asserts nothing about | Text review | 1.0 | M3b | ☐ |
| `LEG-09` | **WPS versioned and anchored** — The practice statement is itself versioned and anchored like any other record. | WPS — versioned and anchored like everything else | Statement root present in the witness log; counsel review deferred to a funded release | 1.0 | M3b | ☐ |
| `LEG-10` | **Limitation of warranty** — Publish an explicit limitation of warranty for the witness service. | WPS — warranties are limited accordingly | Terms published and reviewed by counsel | commercial | — | ☐ |
| `LEG-11` | **FRE 902(13)/(14) technical shape** — Produce records whose integrity and generation process can be certified by a qualified person, matching the shape those rules contemplate. | Legal posture | Counsel review; certification template produced | commercial | — | ☐ |
| `LEG-12` | **eIDAS presumption only via qualified TSA** — Document that the Art. 41 presumption attaches only when anchored to a qualified TSA, and not via Splitstick's own witness. | Legal posture | Documentation review; no contrary claim anywhere | 1.0 | M6 | ☐ |
| `LEG-13` | **Qualified TSA configurable** — A qualified TSA can be configured in the witness set by the operator. | Legal posture — the architecture is pluggable precisely so you can | Live anchor against a qualified TSA | 1.0 | M6 | ☐ |
| `LEG-14` | **No conformity claims** — No product surface or marketing claims EU AI Act conformity. | Legal posture — nothing claims conformity | Claims audit across docs, site and UI | 1.0 | M7 | ☐ |
| `LEG-15` | **No certification of the customer** — Never certify the customer's compliance. | Legal posture — Splitstick does not certify you | Claims audit | 1.0 | M7 | ☐ |
| `LEG-16` | **Not-legal-advice disclaimer** — Carry a not-legal-advice disclaimer wherever statutes are cited. | Legal posture; footer | Documentation review | 1.0 | M7 | ☐ |
| `LEG-17` | **Pursue qualified status** — Pursue accreditation for the hosted witness so the eIDAS presumption can attach. | What comes after 1.0 — qualified status | Accreditation process initiated and tracked | commercial | — | ☐ |
| `LEG-18` | **Trademark clearance** — Complete a free knockout search on the public registers and on npm, GitHub and domains before the name is relied on. Registration is deferred to a funded release. | Draft banner — placeholder pending a trademark search | Search record committed to the repository | 1.0 | M0 | ✅ |
| `LEG-19` | **WPS states the time discipline** — The practice statement names the witness's time source and the limits of the time assertion. | Witness Practice Statement — per its clock | Statement text reviewed against SEC-25 implementation | 1.0 | M3b | ☐ |

### Governance, licensing & community — 19

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `GOV-01` | **Apache-2.0 with patent grant** — Licence all open components under Apache-2.0. | Licence and governance | LICENSE present; headers applied | 1.0 | M0 | ✅ |
| `GOV-02` | **DCO on contributions** — Require Signed-off-by on all contributions. | Licence and governance — contributions under DCO | CI check enforces the trailer | 1.0 | M0 | ✅ |
| `GOV-03` | **Open component set** — Keep the spec, wire format, test vectors, practice statement and both collectors open. | Licence and governance | Repository inventory | 1.0 | M0 | ✅ |
| `GOV-04` | **Non-relicensing commitment** — Publish a commitment never to relicense the open components. | Licence and governance — we commit publicly | Commitment published in the repository | 1.0 | M0 | ✅ |
| `GOV-05` | **Third-party witnesses permitted** — Anyone, including competitors and hyperscalers, may run a conformant witness. | Licence and governance | No technical or licence barrier; third-party witness interoperates | 1.0 | M6 | ☐ |
| `GOV-06` | **Open conformance suite** — Publish the conformance suite so implementations can self-check. | Licence and governance | Suite in the repository under the open licence | 1.0 | M6 | ☐ |
| `GOV-07` | **Certification mark on passing** — Hold a certification mark and grant it on a passing conformance run. | Licence and governance — control the badge | Mark registered; grant procedure documented | commercial | — | ☐ |
| `GOV-08` | **Witness list by pull request** — Accept witness-list entries by pull request. | Licence and governance — arrive by pull request | Contribution path documented and exercised | 1.0 | M6 | ☐ |
| `GOV-09` | **No gatekeeping of the witness list** — Do not vet, rank, or charge for inclusion in the witness list. | Licence and governance — open data, not a gate | Policy published; list contains entries not controlled by us | 1.0 | M6 | ☐ |
| `GOV-10` | **Bounty: one class, one payout** — Pay once per tamper class, not per instance. | Bounty terms | Terms published; applied in triage | 1.0 | M7 | ☐ |
| `GOV-11` | **Bounty: default configuration only** — Findings must survive the shipped default configuration. | Bounty terms | Terms published; default config documented and pinned | 1.0 | M7 | ☐ |
| `GOV-12` | **Bounty: scope binding both ways** — The published threat model binds the programme; exclusions cannot be added after a report. | Bounty terms | Terms published; change log on the threat model | 1.0 | M7 | ☐ |
| `GOV-13` | **Bounty: recognition, not cash** — Recognise a novel tamper class with attribution, credit in the suite and a named finding. The project is unfunded; no cash is promised. | Bounty terms; Resourcing | Terms published stating plainly that recognition is non-cash while unfunded | 1.0 | M7 | ☐ |
| `GOV-14` | **Bounty: first reporter wins** — Award the first complete report. | Bounty terms | Terms published; timestamps retained | 1.0 | M7 | ☐ |
| `GOV-15` | **Bounty: no adjudication while unfunded** — Publish every reported finding and credit every reporter, whether or not the project considers the class novel. With nothing withheld there is nothing to adjudicate, so no arbiter is required. An independent arbiter becomes necessary only if a cash award is ever introduced. | Bounty terms; Resourcing | Terms published stating that all findings are published and all reporters credited, with no novelty test | 1.0 | M0 | ✅ |
| `GOV-16` | **Published review history** — Maintain a public record of what was added, cut and rewritten across revisions. | Review history | Section present and updated per revision | 1.0 | M0 | ✅ |
| `GOV-17` | **Bounty: cash deferred until funded** — State publicly that a cash award opens only if the project is funded, rather than promising money that is not held. | Resourcing | Terms published with the condition stated; no figure advertised as available | 1.0 | M7 | ☐ |
| `GOV-18` | **Accept third-party attack classes** — Accept contributed attack classes by pull request, with attribution. A goal, explicitly not a launch gate. | Attack class section — the suite is open, contributions are invited | Contribution path documented; not referenced in any release gate | 1.0 | M7 | ☐ |
| `GOV-19` | **State the resourcing honestly** — Publish that the project is unfunded and what that means: no hosted witness, no accreditation, no certification mark, and recognition rather than cash. Stated plainly rather than implied by omission. | Resourcing | Section present in the release notes and the README | 1.0 | M0 | ✅ |

### Operational — 6

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `OPS-01` | **Witness SLA** — Offer an independent non-hyperscaler countersignature with a service level agreement. | What comes after 1.0 — commercial plane | SLA published; uptime measured | commercial | — | ☐ |
| `OPS-02` | **Queue drain and retry** — Drain and re-submit queued unwitnessed batches with backoff once a witness returns. | Operations — queued | Outage and recovery test | 1.0 | M3b | ☐ |
| `OPS-03` | **Self-hosted witness deployment guide** — Document running the witness under internal audit with keys in their custody. | Deployment — two parties, one company | Guide published; followed end to end in a clean environment | 1.0 | M6 | ☐ |
| `OPS-04` | **Separation-of-duties guidance** — Document the key-custody split between engineering and internal audit. | Deployment — separation of duties | Guide published and reviewed | 1.0 | M2 | ☐ |
| `OPS-05` | **Zero-egress mode** — Support and verify a deployment with no account, no enrolment with us, and no traffic leaving the perimeter. | Deployment — no traffic leaving your perimeter | Egress capture in a fully self-hosted deployment | 1.0 | M6 | ☐ |
| `OPS-06` | **Witness store durability** — The witness store is replicated and recoverable, with a documented recovery point objective, because a witness that loses its roots destroys the corroboration it exists to provide. | Durability — losing a witness must not lose the evidence | Restore drill from backup; RPO measured against the stated objective | 1.0 | M3b | ☐ |

### Interoperability & standards — 7

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `INT-01` | **C2SP conformance** — Conform to the C2SP tlog-witness checkpoint specification. | Independence — C2SP tlog-witness conformant | Conformance suite against the published spec | 1.0 | M3a | ☐ |
| `INT-02` | **Verify third-party countersignatures** — The verifier accepts countersignatures from witnesses we do not operate. | Proof — a verifier with a different policy | Verify a pack anchored only to Rekor and a third-party TSA | 1.0 | M3a | ☐ |
| `INT-03` | **Documented evidence pack format** — Publish and version the evidence pack format so third parties can write verifiers. | Proof; Licence and governance — wire format open | Spec published; independent verifier implementation validates a pack | 1.0 | M5 | ☐ |
| `INT-04` | **Additive OMA integration** — Integrate with OMA without a fork, patch or upstream pull request. | Capture — not a fork | Install against unmodified upstream at the supported version | 1.0 | M1 | ☐ |
| `INT-05` | **Framework-agnostic capture** — Capture works for any stack speaking MCP, including runtimes with no journal. | Capture — including runtimes that ship no journal at all | E2E against two non-OMA agent runtimes | 1.0 | M6 | ☐ |
| `INT-06` | **Reuse rather than reimplement** — Build on Sigstore, Rekor, Trillian and C2SP rather than reimplementing their roles. | Credit; Independence — we did not invent a protocol | Dependency review; no bespoke transparency log | 1.0 | M6 | ☐ |
| `INT-07` | **No agent code changes** — Both collectors integrate by dependency and configuration only; no change to the customer's agent code is required. | Why — without asking you to change your agent code | Byte-identical agent source before and after integration, for both collectors | 1.0 | M1 | ☐ |

### Scope guards (negative) — 16

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `SCOPE-01` | **No blocking or gating** — MUST NOT block, gate or filter agent actions. | Scope — not a policy engine | Code review; no enforcement path exists | 1.0 | M7 | ☐ |
| `SCOPE-02` | **No tamper-proof claim** — MUST NOT describe the product as tamper-proof. | Scope — not tamper-proof | Claims audit across all surfaces | 1.0 | M7 | ☐ |
| `SCOPE-03` | **No compliance certification** — MUST NOT issue or imply a compliance certificate. | Scope — not a compliance certificate | Claims audit | 1.0 | M7 | ☐ |
| `SCOPE-04` | **Not an observability platform** — MUST NOT position as a replacement for traces, SIEM or dashboards. | Scope — not an observability platform | Positioning review | 1.0 | M7 | ☐ |
| `SCOPE-05` | **No reviewer UI in OSS** — MUST NOT include a reviewer surface in the open-source release. | Scope — belongs to the operated control plane | Release inventory | 1.0 | M7 | ☐ |
| `SCOPE-06` | **No SSO in OSS** — MUST NOT include SSO in the open-source release. | Scope | Release inventory | 1.0 | M7 | ☐ |
| `SCOPE-07` | **No RBAC in OSS** — MUST NOT include RBAC in the open-source release. | Scope | Release inventory | 1.0 | M7 | ☐ |
| `SCOPE-08` | **No multi-tenancy in OSS** — MUST NOT include multi-tenancy in the open-source release. | Scope | Release inventory | 1.0 | M7 | ☐ |
| `SCOPE-09` | **No retention tiers in OSS** — MUST NOT include retention tiers in the open-source release. | Scope | Release inventory | 1.0 | M7 | ☐ |
| `SCOPE-10` | **No verifiable delay function** — MUST NOT ship a VDF. | Considered and rejected | Dependency and code review | 1.0 | M7 | ☐ |
| `SCOPE-11` | **No ZK compliance proofs** — MUST NOT ship zero-knowledge compliance proofs, and MUST NOT place them on the roadmap. | Considered and rejected | Roadmap and code review | 1.0 | M7 | ☐ |
| `SCOPE-12` | **No TEE suppression claim** — MUST NOT claim a TEE makes event suppression impossible. | Considered and rejected | Claims audit | 1.0 | M7 | ☐ |
| `SCOPE-13` | **No blockchain as ledger** — MUST NOT use a blockchain as the primary ledger; a public chain may serve only as the optional hard anchor. | Considered and rejected | Architecture review | 1.0 | M7 | ☐ |
| `SCOPE-14` | **No self-scored defeat metric** — MUST NOT publish an N-of-N attacks-defeated score. | Attack class section — we deliberately publish no score | Marketing and documentation audit | 1.0 | M7 | ☐ |
| `SCOPE-15` | **Hard anchor must be disableable** — The trust-minimised roll-up anchor must be switchable off in one setting, and switching it off must be recorded in the chain like any other policy change. It is on by default because it is the only free public anchor with no acceptable-use objection; it must never be mandatory, because some regulated buyers forbid public-chain anchoring outright. | Independence — optional and off by default | One setting disables it; the change appears as a chain event | 1.0 | M3a | ☐ |
| `SCOPE-16` | **No fail-closed option** — MUST NOT provide any configuration, flag or build that makes the collector block an agent run. Fail-open is a design constraint, not a setting. | Operations — a design constraint, not a setting | Config schema review; no enforcement path exists; rejected as a feature request by policy | 1.0 | M7 | ☐ |

### Documentation & transparency — 9

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `DOC-01` | **Public red-team suite** — Maintain a public tamper suite reproducible in two commands. | Why — the suite is public and runs in two commands | Clean-clone run succeeds | 1.0 | M1 | ✅ |
| `DOC-02` | **Threat model document** — Publish the threat model as a maintained document. | Threat model | Document present, versioned | 1.0 | M0 | ✅ |
| `DOC-03` | **Considered-and-rejected rationale** — Publish rejected designs with reasons. | Considered and rejected | Section present; updated as decisions are made | 1.0 | M7 | ☐ |
| `DOC-04` | **Label targets as targets** — Any unverified figure is labelled a target, not a measurement, until benchmarked. | Draft banner; footer | Documentation review before each release | 1.0 | M7 | ☐ |
| `DOC-05` | **Publish honest limits** — Publish the known information leaks and the attacks not covered. | Disclosure — the honest limit; Threat model — out of scope | Documentation review | 1.0 | M4 | ☐ |
| `DOC-06` | **Upstream attribution** — Credit OMA, Sigstore, Rekor, Trillian, C2SP and Schneier–Kelsey. | Credit | Attribution present in README and NOTICE | 1.0 | M7 | ☐ |
| `DOC-07` | **Document the two-policy split** — Document that the witness list governs who is asked and the acceptance policy governs who is accepted. | Getting started — separate files on purpose | Documentation review; worked example for both | 1.0 | M7 | ☐ |
| `DOC-08` | **Publish bounty terms** — Publish the full bounty terms alongside the offer. | Bounty terms | Terms published before the offer goes live | 1.0 | M7 | ☐ |
| `DOC-09` | **Reconciliation guidance** — Document reconciliation against counterparty records as a detection method for erasure and omission, with its limits stated: it requires access to the counterparty and it is a procedure an auditor performs, not a guarantee the software makes. | Durability; Threat model — residual risk | Guidance published; the limits appear wherever the method is claimed | 1.0 | M3a | ☐ |

### Roadmap (post-1.0) — 10

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `RM-01` | **Bilateral receipts** — Have the counterparty co-sign a receipt so a record exists outside the operator. | What comes after 1.0 | Reference counterparty implementation co-signs via the MCP proxy | 2.0 | — | ☐ |
| `RM-02` | **HTTP egress collector** — Capture consequential actions taken over outbound HTTP. | What comes after 1.0 — more collectors | E2E capture of an outbound call | 2.0 | — | ☐ |
| `RM-03` | **Shell collector** — Capture consequential shell actions. | What comes after 1.0 — more collectors | E2E capture of a shell invocation | 2.0 | — | ☐ |
| `RM-04` | **Database-write collector** — Capture consequential database writes. | What comes after 1.0 — more collectors | E2E capture of a write | 2.0 | — | ☐ |
| `RM-05` | **Reviewer surface** — Provide the approval review surface OMA leaves unbuilt. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |
| `RM-06` | **SSO** — Provide SSO in the operated plane. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |
| `RM-07` | **RBAC** — Provide RBAC in the operated plane. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |
| `RM-08` | **Multi-tenancy** — Provide tenant isolation in the operated plane. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |
| `RM-09` | **Retention tiers** — Provide retention tiers in the operated plane. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |
| `RM-10` | **Evidence export** — Provide regulator-ready evidence export in the operated plane. | What comes after 1.0 — operated plane | Commercial release acceptance | commercial | — | ☐ |

### Traceability & process — 5

| ID | Requirement | Traces to | Verified by | Rel | M | Status |
|---|---|---|---|---|---|---|
| `TRC-01` | **Every requirement traces to a promise** — Each requirement names the release-notes section that promises it; orphans are rejected. | Backlog construction rule | Validator fails on a missing source | 1.0 | M0 | ✅ |
| `TRC-02` | **Every requirement has a verification method** — Each requirement names how it will be verified. | Backlog construction rule | Validator fails on a missing verify field | 1.0 | M0 | ✅ |
| `TRC-03` | **Red-team canary in CI** — The tamper suite runs in CI and fails the build when an observation changes. | redteam — regression canary | CI job present and failing on drift | 1.0 | M0 | ✅ |
| `TRC-04` | **Benchmark before claiming** — No performance figure is published as fact until its benchmark exists and passes. | Numbers we are signing up to; footer | Release gate blocks on missing benchmark | 1.0 | M7 | ☐ |
| `TRC-05` | **Claims audit per release** — Run a claims audit against the scope guards before each release. | Scope; Considered and rejected | Checklist completed and signed off per release | 1.0 | M7 | ☐ |

---

*195 requirements. Status column is maintained by hand as work lands.*
