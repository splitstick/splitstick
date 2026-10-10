# DES-19 — Detection without a stateful witness

**Milestone:** M1 (capture) and M3a (comparison) · **Covers:** FR-54, FR-55, SEC-26, DOC-09

## Problem

`DES-08` states the gap honestly: the shipped default closes attack classes 1, 2, 3, 6 and 7, but
not 4 (truncation) and 5 (erasure). Those need a party that remembers your sequence, and a
stateless TSA signs your hash and forgets you.

An operator who has not yet stood up a witness therefore has no defence against truncation at
all. This element narrows that — not to zero, but from a cliff to a bounded window — using
nothing the operator has to provision.

## Mechanism 1 — every disclosure is a permanent constraint (FR-54, SEC-26)

You disclose a pack covering seq 1–5000 whose checkpoint `C5000` is countersigned by a TSA at
time T. The recipient keeps it. Later you present a record ending at 4799.

That is a contradiction, detectable **offline from the old pack alone**: a countersigned
checkpoint asserts tree size 5000 at a time before your record claims the log ended. No live
service, no enumeration, no query.

```
splitstick verify ./store --compare ./packs/2027-q1.pack
  → FAIL  TRUNCATED_BELOW_DISCLOSED
          pack 2027-q1 holds a countersigned checkpoint at size 5000 (T=2027-01-31)
          the record under test ends at 4799
```

**This is not new cryptography.** It is split-view detection, exactly what Certificate
Transparency's gossip protocols do — the packs are the gossip. Consistent with `DES-14`'s
commitment to adopt rather than invent.

What makes it self-reinforcing: **using the system creates the memory.** The only way to avoid
accumulating constraints is to never prove anything to anyone, and proving things is the point.

### Limits, stated

- Protects everything **below the highest sequence ever disclosed**. The tail since the last
  disclosure is unprotected — a bounded window, the same shape as the anchor-cadence window
  already documented in `DES-05`.
- Requires the recipient to retain the pack and to actually compare. The software makes
  comparison a single flag; it cannot make anyone run it.
- A mild perverse incentive: an operator who understands this discloses less. Self-limiting
  rather than exploitable — an operator who stops producing evidence is its own signal.
- **Origin substitution.** Comparison keys on log identity, so presenting a record under a *new*
  origin would sidestep it. Closed by keying on the **operator key** as well: a new origin signed
  by the same key is reported as `ORIGIN_CHANGED` and compared anyway, and a new key requires a
  declared discontinuity (DES-06) which a verifier always surfaces. An operator can start a fresh
  log; they cannot do it quietly.

## Mechanism 2 — counterparty reconciliation (FR-55, DOC-09)

Not cryptography at all. It is how financial audit has always worked, and it catches the one
thing a stateful witness does not.

The record already captures `ref=TX-77814` in its result. The bank holds `TX-77814`. An auditor
samples transactions **from the counterparty's side** and checks each appears in the record.
Missing ones are erasure — or omission, an action never recorded at all, which is `DES-10`'s
stated residual risk and otherwise has no free answer.

`FR-55` makes this practical by extracting external identifiers and indexing them, so
reconciliation is a query rather than a grep.

### The privacy consequence, handled rather than noted

A transaction reference can itself be identifying. So:

```
splitstick/
  content/refs.idx      ref → cid.   DELETABLE, crypto-shredded with everything else
  chain/                             never contains a reference
```

The index lives in the deletable content store (`DES-13`), never in the chain. Erasure removes
it along with the content, and the chain still verifies. Indexing makes an identifier *findable*,
not newly *present* — it was already in `result` — but findable is enough of a change to warrant
putting it on the deletable side.

### Limits, stated — DOC-09

- Requires access to the counterparty's records. Internal audit has it; a regulator can compel
  it; a casual reader cannot.
- It is **a procedure an auditor performs, not a guarantee the software makes.** The guidance must
  say so wherever the method is claimed, because the temptation is to present it as a feature.

## What this changes in the claim

Before: *the default closes 5 of 7 classes; 4 and 5 need a witness you must provision.*

After: *the default closes 5 of 7 cryptographically; 4 and 5 are detectable by cross-pack
comparison and counterparty reconciliation, with stated limits; a stateful witness remains the
only way to reject a gap at submission rather than discover it afterwards.*

Proactive rejection is still strictly better, and `DES-08` still recommends standing up a
witness. But not having one yet is no longer a cliff — which matters for an unfunded release
whose first users will all start without one.
