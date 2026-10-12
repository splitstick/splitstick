# Witness Practice Statement

**Version 1.0** · 2026-10-12 · **Covers:** LEG-01 to LEG-09, LEG-19, SEC-25

This document says exactly what a Splitstick countersignature means. It is
written to be read by somebody deciding whether to rely on one — an auditor, a
counterparty, a court — and it is deliberately short on what we assert and long
on what we do not.

Every claim here is checked against the code by
`tools/lint-practice-statement.mjs`, which fails the build if an assertion in
this document has no corresponding behaviour or if a disclaimer is contradicted.
A practice statement the software does not implement is worse than no practice
statement, because somebody will rely on it.

---

## 1. What a countersignature asserts

A countersignature from a Splitstick witness asserts **three things and no
others**.

### 1.1 Receipt at the stated time — LEG-02

The witness received the submitted root at the time it records, **according to
its own clock**. See §4 for what that clock is and is not.

**The limit, stated here rather than in a footnote.** A C2SP signed note has
nowhere inside it to carry a time. For a `splitstick`-type witness the receipt
time therefore travels *beside* the signature in the envelope, not under it: it
is the witness's word, unsigned. A verifier reports this as
`witness-asserted, unsigned`, and you should read it as exactly as good as that
witness's word. An RFC 3161 timestamp token is different — its `genTime` is
inside the signature, and the verifier says so.

### 1.2 Extension of the history it already held — LEG-03

The witness asserts that the submitted root **extends the history it last held
for that operator**, proved by an RFC 6962 consistency proof from the height the
witness remembers to the height being submitted.

**This is not the same as "immediate successor", and the difference matters.**
An earlier draft of the requirement said immediate successor. Splitstick
deliberately does not enforce that: checkpoints publish every ten seconds or
every 1,024 records, so heights legitimately jump — 100, then 140, then 200. A
consistency proof is both the correct mechanism and what the C2SP witness
protocol specifies. We have corrected the requirement rather than write a
promise here that the software does not keep.

What this does assert: the operator cannot show the witness a history that
forks below the height the witness already signed, because the proof fails at
*any* size. What it does not assert: that no checkpoint was skipped in between.

### 1.3 Retention in the witness's own store — LEG-04

The witness asserts it retained the submitted root in its own append-only
store, which the operator does not control.

Retention is what makes the countersignature worth anything after the fact: a
proof inside the operator's own envelope is evidence only until the operator
deletes the envelope. See §5 for the durability commitment and §6 for the limit.

---

## 2. What a countersignature does NOT assert

Each of these is a disclaimer, and each is here because somebody could
reasonably have assumed otherwise.

### 2.1 It does not assert the actions occurred — LEG-05

A countersignature says a root was received. It says nothing about whether the
actions the underlying records describe actually happened. An agent that
recorded a payment it never made produces a log that countersigns perfectly.

### 2.2 It does not assert the content is true — LEG-06

The records commit to content by salted digest. Neither the witness nor the
verifier reads that content, and neither is in a position to say it is accurate.
A record saying "transferred EUR 25" when EUR 2,000,000 moved is a true record
of a false statement, and the countersignature covers the former.

### 2.3 It does not assert completeness — LEG-07

A countersignature covers the records that were *submitted*. It asserts nothing
about actions the collector never observed, or observed and never wrote.

Completeness is a separate question with its own separate mechanism: the
coverage attestation (DES-10, M4), which reasons about heartbeat continuity and
declared gaps. Until that ships, the honest position is that completeness is
**not** established by anything in this document, and a verifier's capability
statement says so.

### 2.4 It does not assert lawfulness or authorisation — LEG-08

Nothing here says an action was lawful, authorised, within policy, or
appropriate. The `approval` record kind records that somebody approved
something; it does not establish that they were entitled to.

### 2.5 It does not assert the operator's time

`DES-01`'s `ts` field is self-asserted by the operator and nothing
countersignes it. Where a verifier reports a time, it reports the *witness's*,
and the gap between the two — which is the window in which the log was
unwitnessed.

---

## 3. What the OPERATOR asserts, which is a different thing

Two properties in a verification report are the operator's declarations, not the
witness's assertions, and the report labels them `operator-declared`:

- **Key custody.** An HSM signature and a signature from a key file on disk are
  byte-identical. The custody class per epoch is what the operator declared. Only
  a provider attestation passing FR-70's five checks raises it above that, and
  no cloud path to such a document currently exists for Ed25519.
- **Key destruction.** Nobody can prove they deleted a key. The forward-secrecy
  claim rests on this declaration, and the verifier states both the claim and the
  declaration in the same sentence.

---

## 4. Time discipline — LEG-19, SEC-25

The witness's time source, and the limits of the time assertion.

| Witness type | Where the time comes from | What it is worth |
|---|---|---|
| `splitstick` (operator-hosted) | the witness host's system clock, recorded as `received_at` | as good as the party running that host, which is the point of it being a different party. **Unsigned** — see §1.1 |
| `rfc3161` | the TSA's own clock, disciplined as its published practice statement says and **no better** | a qualified TSA under eIDAS states its traceability to UTC(k); a free public one may state nothing, and the operator chose which. The `genTime` is inside the signature |
| `opentimestamps` | a Bitcoin block header | **not a clock at all.** Block timestamps are loosely bounded by consensus rules, so this establishes "existed no later than", which is weaker than a timestamp and much harder to forge |
| `rekor` | the log's own signed entry timestamp | as good as that log's operator says |

**The limits of the time assertion, plainly.** None of these establishes when an
action *occurred*. They establish when a *root was received*, which bounds when
the records under it were written — and only from above. A record can be written
long after the action it describes, and nothing here detects that.

---

## 5. Durability and recovery — OPS-06

A witness that loses its roots destroys the corroboration it exists to provide.

**Recovery point objective: one submission.** The witness commits a retained
root before advancing its sequence state, so the most that can be lost in an
unclean shutdown is the receipt of a submission the operator never got a
signature for — and that submission is idempotent on retry.

**Recovery procedure.** `docs/witness-restore-drill.md` is a scripted drill
rather than a described one, so it can be run. It restores a witness store from
a copy, replays a conflicting submission, and asserts the restored witness
refuses it.

**The limit.** A drill that meets an RPO on one machine says the procedure
works. It does not say any particular deployment performs it, and nothing in
the software can check that it does.

---

## 6. The assumption this all rests on — SEC-04

**Security holds if at least one witness in the configured set is honest.** Not
a majority, and not a specific one: a single honest witness that retained a root
the operator later contradicts is enough to produce the contradiction.

The uncomfortable half, in the same place: **a set whose members share an
interest is one witness wearing several hats.** Two witnesses run by the same
team, in the same account, under the same legal entity satisfy "at least one
honest" once, not twice. No quorum number fixes that, because quorum counts
parties and the assumption is about interests.

**And a witness nobody polls is not a witness.** Rollback detection needs
somebody other than the operator to have retained an earlier tree head.

---

## 7. Versioning and anchoring — LEG-09

This statement is versioned, and each version is **anchored like any other
record** — by the same mechanism, with no special path: its digest goes into a
`policy` record in a Splitstick log, chained to the digest of the version it
supersedes, and the checkpoint over it is submitted to a witness set. So the
claim "this is what version 1.0 said" is checkable rather than asserted.

`npm run anchor-wps` writes the record. Each run appends; no version's record
is ever removed, so the chain from the first version to the current one is
itself the evidence, and it verifies through the ordinary verifier.

**Two steps, and only one of them is ours.** Recording the digest establishes
the version chain. It establishes nothing about *when*, because that takes a
second party. `npm run anchor-wps -- --config <witnesses> --policy <acceptance>`
submits the checkpoint to a configured witness set. The two steps need not be
one run: a statement recorded before any witness set existed is anchored later
against the checkpoint it already falls under, with no second record of the
same version.

**Three states, because countersigned is not verified.** A proof sitting on an
envelope is not a proof anybody checked, and the difference is the whole of
what a countersignature is worth:

| Reported | What is true |
|---|---|
| `RECORDED` | the digest and the version chain are fixed; nothing countersigned them |
| `COUNTERSIGNED (unverified)` | a proof is present and nothing here validated it — no acceptance policy was supplied, or it does not accept that issuer |
| `ANCHORED (verified)` | the proof validates against the acceptance policy, over the note it names |

The verdict is taken from the ordinary verifier, not decided by the command, so
the timestamp-token, certificate-path and extended-key-usage checks that apply
to any other evidence apply to this statement too. Which signatures count is
the reader's acceptance policy (DES-09), a separate file from the one naming
who gets asked: a verification that terminated at the key of the party who
requested the signature would establish nothing.

**What this means for the copy you are reading.** This repository holds no
operator key and must not, so the artefact its own command produces is signed
by a local development key and countersigned by nobody: it fixes the digest and
the version chain, not the publication time. **Until the project anchors its
published statement with a real witness set, that half of LEG-09 is
outstanding**, and `docs/m3b-follow-ups.md` records it as such. An operator
anchoring their own statement, with their own signer and witnesses, gets the
time assertion; the project does not get it by writing this paragraph.

**The limit, even then.** Anchoring is only as good as the witness set that
anchored it. Under the shipped default (FR-48: a TSA plus an OpenTimestamps
roll-up) the statement's *time* is attested and nothing maintains sequence
state over it — the same honest limit as everything else here.

### Change history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-10-12 | First published. LEG-03 states extension-by-consistency-proof rather than immediate succession, correcting a requirement whose wording predated DES-08's change to consistency proofs. §1.1 states that a `splitstick` witness's receipt time is unsigned. |
