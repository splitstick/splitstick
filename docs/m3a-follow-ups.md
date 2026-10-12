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

## Found by an independent review after shipping, and fixed

Eleven findings. Three were vulnerabilities in the trust path, which for a
product whose claim is "you do not have to trust the operator" is the worst
place to have them.

**An end-entity certificate could act as a CA.** Neither the RFC 3161 path nor
the attestation path checked basic constraints, so an ordinary certificate from
a trusted provider root could mint an attestation over any key, or a TSA chain —
and FR-70 reported the result as independently supported. An operator holds such
certificates. Both paths now share one implementation
(`packages/core/src/trustpath.mjs`); two copies of a trust walk is how one gets
fixed and the other does not.

**FR-70's check 5 read the extension's presence, not its value.** A document
explicitly asserting `non_exportable = FALSE` passed, reporting custody as
independently supported — laundering the weaker claim into the stronger one,
which the code's own comment said it must not do. The containment test it used
would also have been satisfied by the OID appearing in a subject name or inside
another extension's value.

**No `extendedKeyUsage = timeStamping` check.** RFC 3161 §2.3 requires it of a
TSA certificate. Without it, any certificate under an accepted anchor could sign
timestamps: "somebody with a certificate from this CA said so" was being
reported as "a timestamp authority said so".

Then four that would have produced false or misleading reports:

**A duplicated witness retry failed the whole verification.**
`ENVELOPE_DUPLICATE_ISSUER` was emitted as `fail`, so a retry that landed twice
— which the stateful witness itself treats as idempotent — read as tampering.
The verdict is now sourced from one table that the lint holds against
`spec/failure-codes.json`, because it was being decided at the call site in two
places: hard-coded `fail` for envelope findings, and derived from the code's
NAME suffix for chain findings. The second was right only by luck —
`TORN_WRITE` is specified inconclusive and does not end in `_INCONCLUSIVE`.

**The retry queue kept the least valuable entries.** On overflow it discarded
the newest, reasoning that the oldest had the widest unwitnessed window. That is
backwards: the tree is append-only, so a countersignature at the highest height
establishes every record below it. It now keeps the newest, flushes
highest-first, and reports the lower entries as `superseded` — because a witness
that has advanced refuses them as regressions, and retrying them oldest-first
produced failures that were the queue's own doing.

**Refuted versus malformed was decided by matching an error message.**
Rewording it would silently have downgraded a proof that contradicts a
checkpoint to one that merely could not be read. It is a property on the error
now.

**The verifier carried a second Ed25519 implementation.** `checkNoteLine` had
its own SPKI assembly and verify call rather than using core's, duplicating a
security-critical path for no reason once the function became async.

And four pieces of code that read as decisions and were not: a condition that
could never be true, a ternary whose branches were identical, a predicate forced
constant by `&& false`, and `rollbackForTesting()` — a method on the production
witness that rewound the only guarantee it provides. The test now edits the
state file, which is what a dishonest operator would have to do.

**The lesson that needed a structural fix.** Four separate instruments here have
read their own documentation as code: the failure-code lint, the claims lint, the
NFR-05 offline scan, and the review regression test written during this very
review. It had been learned three times and written down twice.
`tools/code-text.mjs` is now the one shared helper, and its second variant —
which also strips string literals — is documented as the wrong instrument for
asking whether a ternary's branches differ, because it made
`endsWith('_INCONCLUSIVE') ? 'inconclusive' : 'fail'` look identical.

## Found by external review of PR #7, and fixed

Two P1 findings, both confirmed by running them.

**The YubiHSM attestation OIDs were wrong, and the decoder expected the wrong
type.** The code had `.5` as Origin and an invented `non_exportable` BOOLEAN at
`.6`. Yubico's published table says `.3` is Origin, `.4` Domains, `.5`
Capabilities, `.6` Object ID — and there is **no non-exportable extension at
all**. A genuine YubiHSM 2 attestation would have failed custody validation,
while the constructed BOOLEAN that did pass established nothing.

The property is now derived from the two facts the device actually states, and
neither alone is sufficient: Origin must say the key was **generated on the
device** rather than imported into it — a key imported into an HSM was outside
one first, so the device's non-exportability says nothing about where that key
has already been — and Capabilities must **not** include
`exportable-under-wrap`, which lets a key leave under a wrap key however good
the hardware. A key imported under wrap is refused even though Yubico documents
`generated` as also set in that case (masks 0x11 and 0x12), because it was
wrapped out and brought back.

Bit indexing follows Yubico's own reference parser: Origin is the first content
octet read LSB-first, Capabilities is eight content octets read as a big-endian
uint64, which is how the documented masks (`0x01`, `0x0000000000010000`) line
up. It is **not** X.690's MSB-first numbering, and guessing that would have been
the same class of error as the OIDs.

Fixtures are now vendor FORMAT rather than a constructed BOOLEAN. That is a
real improvement and still not a real device: `provider_untested: true` stays on
every result, and NFR-09's HSM half stays carried to M7.

**The stateful witness lock was process-local.** Submissions were serialised on
a private promise chain and state written with an atomic rename. That is correct
for one instance and worthless across two: both processes read the same prior
root, both validated against it, both signed, and the witness retained **two
distinct roots at the same height**. It countersigned two conflicting histories,
which is the one thing it exists to prevent.

It reproduced six times out of six once the two processes were made to enter the
critical section at the same wall-clock instant. Without that barrier the first
simply finished before the second began — which is how it looked safe, and why
an in-process test could never have found it. Atomic replacement stops a
half-written file; it does not make read-validate-write atomic, and that
sequence is the whole protocol.

The critical section now runs under the same exclusive cross-process
`WriteLock` the collector uses, covering enrolment as well as checkpoint
transitions, with the same crash behaviour: a lock naming a dead process is
taken over rather than left to wedge the witness. Contention surfaces as **503**
and a genuine fork as **409**, because an operator's response differs — retry
versus stop and investigate — and reporting contention as a fork would send them
hunting for an attacker who is not there.

## Found by the re-review of ca4f396, and fixed

**A crash could leave the retained history inconsistent with the active state.**
A submission commits in two writes — append the root to `roots.jsonl`, then
advance `state.json`. A crash between them left the history ahead of the state,
and after restart the witness accepted a different valid successor at the same
height. The retained history then held two conflicting roots at one height,
with cross-process locking working perfectly.

The old comment here called a retained root with an unadvanced state harmless.
That is true only if recovery reconciles, and it did not. Reproduced exactly as
the reviewer described.

The two writes are deliberately NOT merged into one. Keeping the full root
history inside the atomically-rewritten state file would rewrite every retained
root on every submission — the O(n²) shape DES-13 rejects for the salt journal,
and at a ten-second cadence that is 8,640 entries a day. So the order is
load-bearing and recovery closes the window: append only after every check has
passed, so a retained root is one the witness DID accept; reconcile on load and
again inside the critical section, so a root above the active state is adopted
rather than ignored; and fail CLOSED on two different roots at one height,
because a witness that cannot tell which it accepted would rest every later
signature on a guess.

Checking that turned up an adjacent one the reviewer did not name: a crash
*during* the append leaves a partial line, and `roots()` parsed every line
eagerly, so it **threw** — the witness could not read its own retained history
and needed a hand edit before it would run. The newline is now the commit
marker, as it is for the collector's journals, and damage in the MIDDLE refuses
to start rather than being skipped, because one corrupted byte would otherwise
delete a retained root.

The fault-injection test has two halves, and they are different kinds of
evidence. The deterministic one constructs the exact post-crash file state —
faithful, because the files are the whole of the witness's state — and pins the
window precisely. The other SIGKILLs a real submission at twelve randomised
delays and asserts the invariant after every restart; that is a real crash and
probabilistic about where it lands.

One side effect worth recording: the rollback-detection test had to change,
because rolling `state.json` back alone no longer works — reconciliation puts it
straight back from the retained root. A witness operator who wants to serve an
earlier head now has to destroy the evidence too, which is precisely why FR-50's
detection depends on somebody else having retained the head they were served.

## Found by the re-review of e88a70b, and fixed

**A torn tail was tolerated on read and never repaired.** `appendFileSync`
writes after the partial bytes, so the next submission produced one malformed
line that WAS newline-terminated — damage in the middle, which fails closed. A
recoverable crash therefore became permanent corruption through ordinary
operation.

It is worse than it reads, and the reviewer was generous about it: the
submission that corrupted the journal was **accepted and signed first**. The
operator walked away holding a countersignature for a height the witness could
no longer read. The repair now happens under the exclusive lock, before
reconciliation and before the append, truncating to the last newline — which
removes only the incomplete line, because a complete entry always ends in one.

**Structurally invalid entries were silently skipped.** `#reconcile` filtered on
types and dropped anything that did not match, so a retained root whose
`tree_size` was the string `"20"` vanished from the check and a conflicting root
at height 20 was accepted. Strict about JSON syntax and lax about shape was the
worst combination available: the lax half is where the bypass lived.

Validation moved into the reader, where every complete line is checked as
strictly as it is parsed — operator non-empty, `tree_size` a positive safe
integer, `root` exactly 32 base64-encoded bytes, `at` present — and a line that
fails refuses to start rather than disappearing. `#reconcile` no longer filters
anything, because there is nothing left for it to skip.

## The dual-acceptance question, answered

Asked to resolve a CI failure about the witness accepting two submissions. I
could not reproduce it: every CI job passes on Node 20, 22 and 24, ten
consecutive runs of the witness suites and five more under eight-way CPU
contention, all green. So the answer here is the conclusive explanation, plus
the two things examining the question did turn up.

**When dual acceptance is correct.** A resubmission of the same tree_size and
the same root is idempotent by design (DES-08): a retry after a dropped
response must not look like an attack. Two processes doing that at once are
doing the same harmless thing twice, and both are accepted. There is now a test
pinning exactly that, because without it "both accepted" reads as a security
failure in every circumstance and the distinction that matters is left to
whoever is reading the log.

**When it is a fault.** Two different roots at the same height. The invariant is
therefore not the acceptance count — it is that the retained history holds **one
root per height** and the active state is never behind it. The conflicting-
successor test now asserts that FIRST and on its own terms, with the acceptance
count as secondary diagnosis, and it asserts that the two processes really did
submit different roots before concluding anything from the count. A CI log is
now enough to tell a genuine dual acceptance from a test artefact.

**The test could have been passing vacuously.** The barrier was a fixed
`Date.now() + 700`. On a loaded runner — which is what CI is — node boot plus
ESM loading can exceed that, so the barrier had already expired before either
process reached it and the two ran sequentially. The test then passed WITHOUT
EXERCISING THE RACE, which is worse than failing: a green result that means
nothing. It is a readiness handshake now — each process drops a file and spins
for its peer — so the race happens on any machine at any load.

Proved rather than asserted: with the cross-process lock disabled, the test
reports two distinct roots at height 20 on Node 20, 22 AND 24. The instrument
sees the fault it exists to see, on every version CI runs.

**And the assertion I added to make a failure self-diagnosing was itself
wrong.** It read a `root` field the submission helper never emitted — I had
added that field to the other helper — so it failed closed rather than passing
vacuously, which is the right direction for a mistake of that kind to fall.

Node 24's default test reporter is not TAP, so greps for `^not ok` or `# fail`
show nothing there regardless of the result. Everything above is keyed on exit
codes.

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
