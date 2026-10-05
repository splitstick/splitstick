# Tally 1.0 — draft release notes

`v1.0.0` · Apache-2.0 · rev. 4

**Agent actions you can prove — including the ones that aren't there.**

> **Draft, written before any build work.** These notes exist to fix the scope of 1.0 while it is
> still cheap to change. Every figure is a *commitment we would have to meet*, not a measurement.
> This revision survived an adversarial review that cut four features and rewrote two claims — see
> [Review history](#review-history). The name is a placeholder pending a trademark search, which
> matters here because the mark is the control point, not the licence.

---

## Why

A tally stick was split down the middle. Each party kept a half, and only the matching halves proved
the transaction. Neither side could rewrite its own notches, because its own notches were never the
evidence — the *pair* was. That is a twelfth-century answer to a problem agent runtimes have
reintroduced.

Agent frameworks now ship run journals and verifiers. They are real, and they catch real problems:
corrupted logs, mis-stitched resumes, buggy context rewrites. What they cannot catch is the operator,
because the operator holds the only key and writes the only copy.

We measured this rather than asserting it. Against a genuine run record from a widely used runtime,
with one EUR 2,000,000 transfer in it, most of our alterations passed the runtime's own verifier —
including changing the amount to EUR 25 and deleting the transfer entirely. The suite is public and
runs in two commands, so you need not take our word for the finding either.

Tally closes that gap without asking you to change your agent code, hand over a key, or send us your
data.

## Threat model

Stated first, because every claim below is meaningless without it, and because the adversary we care
about is an uncomfortable one to name.

| | |
|---|---|
| **Adversary** | **The operator.** A party with root on the host, possession of the signing key, write access to the record, and a motive to change what it says after the fact. Everyone else — the external attacker, the buggy library, the corrupted disk — is a strictly easier case already handled by existing verifiers. |
| **Goal** | Not prevention. **Detection and attribution.** A party who controls the machine can always lie; the question is whether lying leaves a trace someone else can find. |
| **Trust** | No trust in the operator, the host, the collector binary, or Tally. Verification requires only bytes and public keys. We assume at least one witness in the configured set is honest. |
| **Out of scope** | An action the agent never attempted. A compromised model. A tool that lies about what it did. Collusion across every witness in the quorum. A key exfiltrated before first use. |

## What Tally adds, by attack class

| Attack class | Mechanism that closes it | Local or external? |
|---|---|---|
| Alter the recorded action — arguments, result, approval decision | Action-record digests (the conversation is not the action) | Local |
| Alter an event and repair the citing digest | Per-event predecessor chaining; salted leaves | Local |
| Re-sign rewritten history with the current key | Forward-secure epoch ratchet in non-exportable key custody | Local + HSM |
| Truncate the record's tail | Externally remembered monotonic batch count | External |
| Erase events and renumber into a clean stream | Same — the count was countersigned before the deletion | External |
| Stop or patch the collector, then claim quiet | Signed heartbeats carrying the collector build digest | External |
| Weaken the anchoring policy, then tamper | Witness set and quorum recorded as chain events | External |

Truncation and erasure are **mathematically impossible to detect from inside the record**: whoever
controls the file controls where it ends, and a chain over a truncated prefix is still internally
valid. Those rows are why Tally is not merely a library.

We deliberately publish no "*N* of *N* attacks defeated" score. We wrote the attacks, so passing them
proves little. Instead the suite is open, contributions are invited, and we pay **EUR 5,000 per novel
tamper class** that survives a default Tally configuration. A number someone else can move is worth
more than one we award ourselves.

## What ships in 1.0

### Capture — two collectors

- **`@tally/collect-oma`** — a drop-in journal and approval-store backend for OMA, via documented
  interfaces. **Not a fork**: no patch, no pull request, nothing upstream has to accept.
- **`@tally/mcp-proxy`** — sits between any agent and its MCP servers. Works with anything that
  speaks MCP, including runtimes that ship no journal at all.
- Both digest the **action record** — tool name, arguments, result, approval decision — not only the
  conversation the model saw. Our red team found this gap in a shipped verifier, and it was in
  nobody's documentation.

### Integrity — chained, salted, ratcheted

- Every event carries a digest of its predecessor. In-place edits, dropped events and renumbered
  tails all break the chain.
- Every leaf is **salted with a per-leaf random nonce**. Without this, a digest of a short,
  predictable action record is simply brute-forced, and inclusion proofs leak their siblings.
- **Forward-secure epoch ratchet.** The signing key evolves per epoch and the predecessor is
  destroyed, so yesterday's entries cannot be re-signed with today's key. *This holds only under
  non-exportable key custody* — an HSM or KMS with attested rotation. Key destruction is not
  externally verifiable, so we state the precondition rather than the stronger claim.
- Batches are signed with **your** key. Tally never holds it, sees it, or asks for it.

### Independence — tiered, pluggable anchoring

- **C2SP `tlog-witness` conformant** checkpoints. We did not invent a protocol; we adopted the one
  Sigstore and the Go checksum database already depend on.
- **Soft anchor**, default every 10 seconds, to a witness *set* — Rekor,
  `transparency-dev/witness`, an RFC 3161 TSA, your own internal authority, or Tally's. Cadence is
  the mutability window and it is yours to set.
- **The shipped default is `[tally, rekor]`, not Tally alone.** Rekor is free, public and not ours,
  so the out-of-box configuration demonstrates independence rather than asserting it — and if this
  company ceases to exist, every record still verifies.
- **Hard anchor**, optional and *off by default*: a slow, trust-minimised backstop that no company
  can withdraw. Off by default because its confirmation latency cannot serve a ten-second window,
  and because many regulated buyers hold blanket policies against it.
- Set `quorum: 2` for records meant to be adverse to you. The active set and quorum are written into
  the chain, so weakening them is a timestamped event rather than a silent config edit.
- Witnesses receive **salted roots only**. No prompts, no arguments, no customer data leaves your
  host, ever.

### Deployment — two parties, one company

The two halves of a tally never had to be two *companies*. Most regulated buyers will not take an
external dependency for their audit trail, and they do not need to.

- Run the witness yourself, under **internal audit**, with the key in their custody. Engineering
  holds the signing key. Neither function can rewrite history alone.
- That is ordinary **separation of duties** — a control such organisations already operate, already
  document, and already have an owner for.
- So **Tally runs without trusting us at all**: no account, no enrolment, no traffic leaving your
  perimeter. Our hosted witness is one option among several, and declining it costs you nothing in
  the open-source release.

### The new part — coverage attestation

Every other tool in this space can tell you that what was logged is unaltered. None can tell you
that **everything was logged** — and silence is indistinguishable from "nothing happened."

- Collectors emit **signed heartbeats** into the same chain, so a window without one is as loud as a
  broken hash.
- Each heartbeat carries the collector's **build digest**. A patched collector reports an
  unrecognised build; a stopped one reports nothing. Either way it is attributable.
- **Signed gap declarations.** When a batch is genuinely lost, the operator records an explicit,
  signed, countersigned statement of absence. Strict sequence contiguity without this is a
  denial-of-service on yourself: one lost batch and the stream never recovers.
- An unexplained absence and a declared one are different objects — in engineering and, where
  adverse-inference doctrines apply, in litigation. Tally converts the first into the second.
- `tally coverage` produces the claim that answers an auditor: *"100% of tool calls captured between
  T1 and T2, with proof the collector was alive for every second of it."*

### Disclosure — prove one action, reveal one action

- An auditor investigating one transaction should not receive your entire log — and if the log spans
  customers, you cannot lawfully hand it over.
- `tally disclose <event>` emits a **Merkle inclusion proof** against a countersigned root. The
  recipient verifies that this action is in the record, at that position, at that time, without
  seeing anything else.
- Salted leaves mean the sibling hashes in the proof reveal nothing about their contents.
- **The honest limit:** a proof necessarily discloses the tree size, so the *number* of recorded
  actions becomes known. We consider this unavoidable rather than unfortunate — you cannot
  simultaneously claim "nobody knows how many actions I took" and "you can prove I deleted none."
  Anchor cadence likewise leaks activity volume; optional batch padding is available where that
  matters.

### Erasure — append-only, and still GDPR-compatible

A permanent tamper-evident log of agent actions appears to collide head-on with the right to
erasure. It is the first objection a data-protection officer raises, and it is usually fatal. Tally
is built so the collision does not occur.

- **No content is ever in the chain.** The chain holds salted commitments and pointers. Content
  lives in ordinary mutable storage that you control and can delete.
- Erasure is **crypto-shredding**: delete the content and its key. The data subject's information is
  genuinely gone; the chain still verifies; the commitment becomes permanently unlinkable to any
  plaintext.
- What survives is a salted hash and a timestamp — which is what makes the integrity of the
  remaining record provable, and which is defensible to retain where the content itself is not.
- Retention and erasure are therefore **policy settings on your storage**, not properties of the
  cryptography. That separation is deliberate.

### Proof — offline verification

- `tally verify` needs **no network, no credentials, no account** — only bytes and public keys. It
  will still work in 2031.
- The acceptance policy is an **input, not a hardcoded trust store**. An auditor who accepts only
  qualified trust service providers supplies their own list and verifies the same pack.
- Evidence packs carry **every** countersignature collected, never only ours, so a verifier with a
  different policy can find one it trusts.

### Operations — fails open, loudly

- If a witness is unreachable, **the agent does not stop.** The batch is chained and signed locally,
  marked `unwitnessed`, and queued.
- A late countersignature records the witness's *real* time, so the widened window appears in the
  record and is reported as a coverage gap. Honestly weaker beats silently absent.
- No audit layer that can take down production will ever be installed. A design constraint, not a
  setting.

## Witness Practice Statement

Certificate authorities publish a Certification Practice Statement because an attestation whose
meaning is vague is an attestation worth nothing — and an unbounded one is a liability nobody should
accept. Tally's witness ships with the equivalent, and it is deliberately narrow.

**A countersignature asserts**

- This root was **received** by this witness at this time, per its clock.
- It is the **immediate successor** of the previous root recorded for this enrolled operator.
- The witness has **retained** it in its own append-only store.

**It asserts nothing about**

- Whether the underlying actions **actually occurred**.
- Whether the recorded content is **true**.
- Whether the operator **captured everything** — that is what coverage attestation addresses,
  separately.
- Whether any action was **lawful or authorised**.

The witness attests receipt and ordering. It is not an auditor, not a guarantor of your records, and
not a certifier of your compliance. Warranties are limited accordingly and stated in full in the
published practice statement, which is versioned and anchored like everything else.

## Legal posture

Earlier drafts of these notes said Tally makes a record "admissible." That was wrong, and counsel
would have caught it. **Admissibility is a judicial determination, not a product feature.** No
software can confer it, and claiming otherwise is the kind of overstatement that costs a trust vendor
its credibility exactly once.

What is accurate, and still valuable:

- Tally produces records whose integrity and process of generation can be certified by a qualified
  person — the technical shape contemplated by **US FRE 902(13) and 902(14)** for self-authenticating
  electronic records and hash-identified copies.
- Where a batch is anchored to a **qualified** timestamp authority, the **eIDAS Art. 41 presumption**
  of date, time and data integrity attaches. Anchoring to our own witness, or to any non-qualified
  one, does *not* attach it. If that presumption is what you need, configure a qualified TSA in your
  witness set — the architecture is pluggable precisely so you can.
- The practical effect is **burden shifting**. Without this, a challenge to your record is answered
  by your assurances. With it, the challenger must explain an independently countersigned,
  monotonic, hash-chained sequence. That is a materially different conversation, and it is the honest
  version of the value proposition.

Tally does not certify you. Nothing in this release claims EU AI Act conformity, and these notes are
not legal advice.

## Scope

**What 1.0 is**

- **A recorder and a verifier.** It produces evidence about what agents did.
- **Additive.** Nothing is forked; nothing upstream must accept a patch.
- **Self-contained to verify.** Bytes plus public keys, forever.
- **Blind.** Salted roots leave your host; content never does.
- **Erasure-compatible.** Append-only integrity over deletable content.
- **Usable without us.** Self-host the witness: no account, no enrolment, no egress.

**What 1.0 deliberately is not**

- **Not a policy engine.** Tally records; it does not block, gate or filter. Guardrails are a
  different product with a different failure mode.
- **Not tamper-*proof*.** Tamper-*evident*. An operator who controls the host can still lie — not
  without leaving an attributable trace. That is the bar the regulation sets and the only one anyone
  can honestly claim.
- **Not a compliance certificate.** We produce evidence; we do not certify you.
- **Not an observability platform.** It will not replace your traces, SIEM or dashboards.
- **No reviewer UI, SSO, RBAC, multi-tenancy or retention tiers** in the open-source release. Those
  belong to the operated control plane.

## Considered and rejected

Four features were cut in review. They are listed because the reasons are more informative than the
features would have been, and because a security product that publishes only its additions is hiding
half its design.

| Rejected | Why |
|---|---|
| **Verifiable delay function** | Proposed as an offline lower bound on elapsed time. It bounds *sequential computation*, not wall-clock: an adversary with faster hardware shrinks the bound, and the parameters cannot be set safely across heterogeneous hosts. External anchoring is strictly stronger and already present. Cut. |
| **Zero-knowledge compliance proofs** | Proposed as "prove every high-value action was approved, without disclosing the log." A ZK proof establishes correct computation over *claimed* inputs; it says nothing about whether the inputs are true. An operator generating a proof over their own unanchored data proves only that they can run a circuit. The only meaningful version operates over already-anchored roots, at which point the root is doing the work. Cut, and not placed on the roadmap. |
| **Collector sealed in a TEE** | Proposed to make the collector unpatchable by its own operator. Enclave technologies have a sustained record of practical breaks, and presenting one as an assurance boundary adds attack surface while inviting justified scepticism. **Remote attestation of the collector build** remains interesting and stays experimental; the claim that a TEE makes suppression impossible does not ship. |
| **A blockchain as the ledger** | Never seriously considered, stated for the avoidance of doubt. The requirement is an append-only log with inclusion proofs and independent witnessing, which transparency logs provide without consensus, tokens or throughput limits. A public chain appears in exactly one optional role — the slow hard anchor — and is off by default. |

## Numbers we are signing up to

| | |
|---|---|
| **<1 ms** | p99 append overhead per event |
| **<2%** | added end-to-end run latency |
| **10 s** | default mutability window |
| **<2 s** | to verify a 100,000-event run, offline |
| **0 bytes** | of content leaving your host |
| **EUR 5,000** | per novel tamper class found against us |

## Getting started

```yaml
# tally.yaml — the witness surface. Defaults shown; every line is yours to change.
witnesses:
  - { id: tally, url: "https://witness.tally.dev", key: "<shipped pubkey>" }
  - { id: rekor, type: rekor }
#  - { id: corp,  url: "https://tsa.audit.internal", key: "..." }   # your own
#  - { id: qtsp,  type: rfc3161, url: "https://qts.provider.eu" }   # qualified
quorum: 1
on_unavailable: mark_gap
anchor_interval: 10s
```

```bash
# Existing OMA runtime — one dependency, one config change
npm i @tally/collect-oma

# Any other stack — put the proxy in front of your MCP servers
npx @tally/mcp-proxy --upstream http://localhost:8931 --out ./tally

# Verify, with no network and no credentials
npx @tally/verify ./tally --policy ./acceptance.json
npx @tally/coverage ./tally --from 2027-01-01 --to 2027-03-31

# Hand an auditor one action, and nothing else
npx @tally/disclose ./tally --event 8f2c91 --out invoice-4471.pack
```

Requires Node.js 20+ and a KMS or HSM offering non-exportable keys for the forward-secure ratchet.
Tested against `@open-multi-agent/core` 1.21.x and MCP servers over stdio and HTTP.

Note that `witnesses` decides who is *asked* to countersign, while the verifier's `--policy` decides
whose signature is *accepted*. They are separate files on purpose: if only the first were
configurable, the openness would be decorative, because every verification would still terminate at
our key.

## Licence and governance

**Apache-2.0**, including the patent grant. Contributions under DCO. The spec, wire format, test
vectors, practice statement and both collectors are open, and **we commit publicly to never
relicensing them** — a business built on trust cannot afford a licence people expect to change.

Anyone may run a witness against this format, including our competitors and the hyperscalers. The
conformance suite is open so implementations can self-check; the certification mark is held and
granted on passing. Give the code away, control the badge.

**The witness list is open data, not a gate.** Known conformant witnesses live in a plain file in the
repository and arrive by pull request. We do not vet, rank, or charge for inclusion. Deciding who is
*allowed* to be a witness would be precisely the kind of hard power that makes a standards community
distrust whoever holds it — and distrust is the one thing this product cannot afford. The conformance
suite is open so anyone can self-check, and the certification mark, which we do hold, carries the
quality signal instead. Soft power only, and only where a passing test earns it.

## What comes after 1.0

**Bilateral receipts.** 1.0 retains one structural weakness, and the threat model names it: you are
the only signer, so an action never emitted is an action with no record. The fix is for the
*counterparty* to co-sign — the bank, the internal API, the MCP server attesting "I received this
instruction from agent A at this time." The MCP proxy is deliberately placed at the one boundary
where both parties are present. That is 2.0, and it is where this stops resting on the operator's
word at all.

**More collectors**, ranked by where agents actually take consequential actions: HTTP egress, shell,
and database writes.

**Qualified status.** Pursuing accreditation for the hosted witness, because the eIDAS presumption
attaches to qualified providers and to nobody else. This is a moat you buy rather than build, and a
weekend competitor cannot clear it.

Separately, the operated plane — reviewer surface, SSO, RBAC, multi-tenancy, retention, evidence
export, and an independent non-hyperscaler countersignature with an SLA — is a commercial product and
is not part of this release.

## Review history

These notes were drafted, enriched, attacked, and revised before any code existed. The record of that
is published rather than discarded, on the same principle as everything else here.

| Rev | | |
|---|---|---|
| 1 | DRAFTED | Collectors, action-record digests, chaining, C2SP anchoring, coverage attestation, offline verification, fail-open. |
| 2 | ADDED | Forward-secure ratchet; selective disclosure; spoliation-grade gap records; burden-shifting framing; trust-minimised hard anchor; threat model; practice statement. |
| 3 | CUT | Verifiable delay function; zero-knowledge compliance proofs; TEE-as-guarantee; the "*N* of *N* attacks defeated" metric. |
| 3 | REWROTE | "Admissible" → burden shifting with the statutes named. Forward secrecy now states its HSM precondition. Hashes salted after a brute-force objection. Strict sequence contiguity softened with signed gap declarations. |
| 3 | ADDED | Crypto-shredding for erasure compatibility, after the GDPR Art. 17 objection; adversarial bounty in place of the self-scored metric; hard anchor defaulted off. |
| 4 | CHANGED | Default witness set is now `[tally, rekor]` rather than Tally alone, so the shipped configuration is independent of us on day one. |
| 4 | ADDED | Self-hosted witness under internal audit as a named deployment pattern; witness list published as open data, with inclusion ungated. |

## Credit

> "It proves lineage and content, not that the file was never edited."
> — open-multi-agent/open-multi-agent, README

Tally exists because OMA built the right primitive and then documented exactly where it stopped. Its
`verifyRun()` catches drift, which is what it was built to catch, and its docs say so in a section
titled "What it does not prove." Projects that oversell do not write that section.

OMA's constraint is principled rather than an oversight: external anchoring is incompatible with "no
telemetry, no hosted control plane, your keys." It cannot close this gap without becoming a different
project. We are the layer that can, and we are a plugin rather than a fork precisely so that stays
true. **OMA gives you a record you can inspect. Tally gives you one that holds up when you are the
party being questioned.**

Built on Sigstore, Rekor, Trillian and the C2SP specifications, and on Schneier and Kelsey's 1999
work on forward-secure audit logs — none of which we wrote, all of which we depend on.

---

*Draft release notes for an unbuilt product, written to lock scope before implementation begins.
Figures are targets to be met and verified, not results. The red-team findings referenced throughout
are real and reproducible against `@open-multi-agent/core@1.21.1`; everything described as shipping
in Tally 1.0 is not yet built. Statutory references are included to make the product's posture
precise and are not legal advice.*
