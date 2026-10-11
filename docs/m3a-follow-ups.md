# M3a follow-ups

What M3a left open, and where each one lands. Written at the point of shipping
rather than reconstructed later, because the value of this file is that it was
written while the reasons were still true.

## Carried, with a milestone

**NFR-09's HSM half → M7.** Carried into M3a from M2 and not closed here. The
KMS half is built, covered, and needs only the operator's key to run. The HSM
half is blocked by evidence rather than effort and nothing in M3a changed that:
of the products that sign Ed25519, AWS KMS issues no per-key attestation and GCP
offers the algorithm at software protection level only, so independently
supported custody still requires hardware and the YubiHSM 2 purchase is held.

FR-70's validator now exists and is correct. It has only ever been run against
documents this project constructed, and every result it returns carries
`provider_untested: true` so a reader of a report sees that rather than having
to find DES-06. M7 is the right home because the launch gate is where a
published claim must have evidence behind it, and "operate with a KMS or HSM" is
a published claim. It closes either with a real attestation through the five
checks, or by narrowing the published text to what the KMS half supports —
explicitly one of those two, and not a third option where the claim stands
unevidenced.

**NFR-01 → still open from M1.** Unchanged by M3a. The revised budget (p95 ≤ 1
ms, p99 ≤ 3 ms on the reference environment over ≥1e6 events across multiple
runs) awaits a qualifying run. Nothing in M3a is on the append path: witness
submission happens per checkpoint, and the checkpoint is written locally and
completely before any witness is asked anything.

## Not blocking, worth doing

**An `.ots` fixture from a real calendar.** The OpenTimestamps parser is tested
against proofs this project constructs from the format as documented. That
proves the parser against the specification; it does not prove it against what
a calendar actually returns, and the two have been known to differ in framing.
One real proof, committed as a fixture the way the RFC 3161 token is, would
close the gap. It needs a network, which is why it is not here.

**A real Rekor response fixture, for the same reason.** The adapter searches the
response for a signed note line rather than reading a fixed path, precisely
because the shape varies by version and entry type — which is a sensible
response to not having a real one to look at, and a poor substitute for having
one.

**The witness protocol has no transport.** `@splitstick/witness-self` is a
complete stateful witness with no HTTP in front of it: the operator supplies the
transport. That is deliberate — it is their host, their TLS, their
authentication — but it means the one adapter that closes classes 4 and 5 takes
more work to deploy than the two that do not. A reference server, clearly marked
as a reference, would change the economics of doing the right thing. DES-08's
own argument is that the barrier is the point; this is the counter-argument, and
it should be decided rather than left.

**`chainTo` and `findIssuer` do not check revocation.** Neither the RFC 3161
path nor the attestation path consults a CRL or OCSP, because both would need a
network and NFR-05 forbids it. A revoked TSA certificate therefore verifies.
This is a real limit of offline verification rather than an oversight, and it
belongs in the practice statement (M3b) where a reader can weigh it.

**Keccak-256 in OpenTimestamps proofs is refused, not implemented.** `node:crypto`
has no Keccak, and guessing is worse than refusing. A proof using it reports as
unimplemented. No calendar in the default set uses it; a proof from elsewhere
might.

## Found by reviewing my own work before shipping

**The Anchorer never computed a consistency proof.** `#consistencyContext`
returned an empty one with a comment saying the caller would supply it. No
caller did, so a stateful witness — the adapter that closes classes 4 and 5 —
refused every submission after the first with a 409. Nothing caught it because
the only place that wired the Anchorer to a real witness anchored exactly one
checkpoint, and a seam exercised once looks like a seam that works.

The fix also had a subtlety worth recording: the proof must be over the tree the
checkpoint **commits to**, not over the log as it is now. Those differ whenever
records land between the checkpoint and the anchoring call, which under
fail-open is most of the time — and a proof over the current leaves would
*verify* while describing a tree the checkpoint does not, leaving the witness
holding a root for a height that was never checkpointed. There is a test for
exactly that, and the red-team harness now anchors every checkpoint rather than
the first.

## Decided against

**Fetching block headers to confirm an OpenTimestamps attestation.** It would
turn a reported commitment into a confirmed one, and it would cost the offline
guarantee that makes the verifier worth trusting. The commitment plus an
out-of-band header check is strictly more honest than a verifier that reaches
for the network, and a verifier that *optionally* reached for it would be worse
still — a reader could not tell from the output which mode produced it.

**A single `@splitstick/witnesses` package containing the adapters themselves.**
It would be more convenient and it would put an HTTP client in the verifier's
dependency closure the first time anyone imported the wrong thing. The split
across `witness-tsa`, `witness-ots`, `witness-rekor`, `witness-self` and a
`witnesses` builder that depends on all four is the awkward arrangement that
keeps NFR-05 structurally true rather than true by discipline.

**Making `gate_evidence` default to `witnessed`.** It would have saved a line in
`milestones.json` and it would have let a future milestone claim a gate on
evidence it had not asked for. The field defaults to `local` and a test asserts
that it does.
