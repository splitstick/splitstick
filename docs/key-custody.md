# Key custody and separation of duties

**Covers:** OPS-04 · **Related:** SEC-14, SEC-17, FR-11, NFR-09, DES-06, DES-08

This is operational guidance, not a feature. Nothing in the software enforces
any of it, and the software cannot: the operator controls the host. What the
design does is make a particular split *worth something*, so that an operator
who adopts it can be contradicted by evidence rather than only disbelieved.

## The property the split buys

Splitstick's claim is not that the operator is honest. It is that an operator
who rewrites history leaves evidence that contradicts them. Inside one
organisation, that needs two functions that cannot both be captured by the same
person:

| Function | Holds | Can therefore |
|---|---|---|
| **Engineering** | the signing key (DES-06) | append records, sign checkpoints, rotate epochs |
| **Internal audit** | the witness key (DES-08) | countersign a checkpoint, maintain sequence state |

Neither can rewrite history alone. Engineering can re-sign a rewritten log, but
the countersignature over the original root still exists and still says
something else. Audit can refuse to countersign, which is visible as an
unanchored tail, but cannot forge records. This is the two-halves-of-a-tally
property: a split tally stick is only evidence because the two halves are not in
the same hands.

**If one person holds both keys, the split buys nothing.** It is not weakened —
it is absent, and a reader should treat the log as self-attested. This is worth
saying plainly because the configuration looks identical either way.

## What to do

1. **Separate the key holders.** The engineering signing key and the internal
   audit witness key are held by different people, under different credentials,
   in different accounts. Same account with different IAM roles is a weaker
   arrangement than it looks: whoever administers the account holds both.

2. **Use non-exportable custody for the signing key.** A KMS or HSM key that
   cannot be exported bounds where the key could have gone. See
   [kms-capability-matrix.md](kms-capability-matrix.md) for which products can
   actually sign SS1 — fewer than you would expect, and Ed25519 is the
   constraint.

3. **Rotate on a schedule and record the succession.** `collector.rotate(next)`
   endorses the successor with the retiring key and journals it, so a verifier
   that pinned the root key years ago still attributes every epoch (FR-11).

4. **Destroy the retired private key.** This is the step nobody can verify, and
   the one the forward-secrecy claim rests on. Schedule deletion through the
   provider so there is at least a provider-side record, and understand what
   that record is and is not — see below.

5. **Pin the root public key out of band.** A reader who takes the root from
   the same store they are verifying has pinned nothing. Publish it where the
   operator cannot quietly change it: a signed release, a registrar, a
   counterparty's records.

6. **Do not let the collector hold anything.** Splitstick must never hold,
   receive, request or log the signing key (SEC-14). It takes a signer
   interface. If an operational procedure involves putting a key where
   Splitstick can read it, the procedure is wrong, not the interface.

## What this does not establish

**Custody is a declaration.** An HSM signature and a signature from a key file
on disk are byte-identical. The custody class per epoch is what the operator
declared, and the verifier reports it labelled `operator-declared`. Only a
provider attestation passing FR-70's five checks raises an epoch above that,
and no cloud path to one currently exists for Ed25519 (DES-06).

**Destruction is a declaration too, and a weaker one.** Nobody can prove they
deleted a key. A provider's scheduled-deletion record says the provider was
asked and reports having complied; it is not a proof, it is the provider's
assertion, and it is the operator who holds the provider relationship. The
verifier therefore reports destruction as `operator-declared` in every
configuration this design supports, and the forward-secrecy claim in its output
carries both declarations in the same sentence as the claim (SEC-17).

**A rotation schedule is not forward secrecy.** A key in an HSM that is never
rotated has no forward secrecy whatever its custody class, and the newest epoch
never has it — it is still signing with the key in question. The verifier's
report says `not-yet` for the live epoch rather than claiming it.

## The honest summary for a reader of the log

If you are reading evidence rather than writing it, the custody section of a
verification report tells you what the operator *says* about their keys. Treat
it as you would any other statement by the party whose conduct is in question:
useful, checkable against their other statements, and not self-proving. The
parts of the report that do not depend on their word are the chain, the tree,
the inclusion proofs, and any countersignature — and those are the parts to
rely on.
