# Two policies, and why they are not one — DOC-07

There are two lists of witnesses in this system and they belong to different people. Running
them together is the single most common way to misread what a pack establishes.

| | Who writes it | What it decides | Where it lives |
|---|---|---|---|
| **The witness list** | the **operator** | who is **asked** | `splitstick.yaml`, as the `witnesses:` set — and `spec/witnesses.json` is the catalogue they choose from |
| **The acceptance policy** | the **reader** | who is **accepted** | a file the reader passes to `--policy` at verification time |

The operator decides who signs. The reader decides whose signature counts. **Neither can do
the other's job**, and that is the point rather than an inconvenience:

- An operator who could also decide who is accepted would be marking their own homework. The
  whole value of a countersignature is that it comes from somebody the operator does not
  control, and it would be worth nothing if the operator also chose whether to believe it.
- A reader who could decide who is asked would be dictating the operator's infrastructure,
  and a verifier that shipped a hardcoded trust store would make independence impossible to
  demonstrate (FR-30, INT-02). Two readers with different trust must be able to reach
  different, internally consistent conclusions from one pack.

So a pack carries **every** countersignature that was collected, never only the ones we would
accept, because a reader with a different policy must be able to find one they trust.

## Worked example — the operator's side

The operator anchors to a free public TSA, their own internal witness, and the roll-up
calendar. This is who gets **asked**:

```yaml
version: 1
store: ./evidence
witnesses:
  - { id: tsa.example,     type: rfc3161,        url: "https://tsa.example/tsr" }
  - { id: audit.internal,  type: splitstick }            # theirs, run by internal audit
  - { id: ots,             type: opentimestamps, tier: rollup }
quorum: 2
```

`quorum: 2` means a batch is not considered anchored until two of those three have
countersigned. The active set and the quorum are **written into the chain**, so weakening
them later is a timestamped event rather than a silent config edit.

## Worked example — the reader's side

Three readers receive the same pack and reach three different, internally consistent
verdicts. Nothing about the evidence changed.

**A regulator who accepts only a qualified trust service:**

```json
{
  "quorum": 1,
  "witnesses": [
    { "id": "qtsa.example", "establishes": ["time"], "qualified": true,
      "anchors": ["-----BEGIN CERTIFICATE-----…"] }
  ]
}
```

This pack has no `qtsa.example` countersignature, so the report says `WITNESS_MISSING` and
names it. The other three countersignatures are still **in** the pack and still **printed**,
marked as not accepted by this reader's policy — reported, counted towards no quorum, and
available to somebody else.

**The operator's own internal auditor, who accepts the internal witness:**

```json
{
  "quorum": 1,
  "witnesses": [
    { "id": "audit.internal", "public_key": "…", "establishes": ["sequence"] }
  ]
}
```

Verdict `inconclusive`, with zero failures: the countersignature verifies and establishes
**sequence**, so nothing here establishes **time**. That is the honest answer and not a
shortfall — a witness inside one perimeter buys independence of sequence, not of clock.

**A counterparty who accepts the public TSA and the calendar:**

```json
{
  "quorum": 2,
  "witnesses": [
    { "id": "tsa.example", "establishes": ["time"], "anchors": ["…"] },
    { "id": "ots", "establishes": ["existence"] }
  ]
}
```

Two accepted witnesses, quorum met for time and existence, nothing accepted for sequence.
Again a different verdict from the same bytes.

## What goes wrong when they are conflated

- **Reading the witness list as an endorsement.** It is not. Nobody vets, ranks or charges
  for inclusion in `spec/witnesses.json`, the parser refuses any field expressing preference,
  and every entry states its own acceptable use and rate limits so an operator chooses on
  informed grounds (FR-47, GOV-09). Being *askable* is not being *trustworthy*.
- **Reading "a witness countersigned it" as "the evidence is verified".** Presence is not
  verification. This project has shipped that confusion three times — a coverage report that
  said `ANCHORED` because an issuer's name was present, a verifier that counted a
  countersignature it had not checked, and a conformance suite that certified a witness which
  never signed anything. The acceptance policy is where a reader's key for that issuer lives;
  without one, the report says *present and unverified*, never *verified*.
- **Shipping a default acceptance policy.** There is none, deliberately. A verifier run with
  no `--policy` reports that nothing was accepted and that nothing is therefore established
  about who saw what — rather than quietly accepting whoever turns up.

## Not legal advice

This page describes engineering properties. Nothing here is legal advice and nothing
certifies anybody's compliance with anything (LEG-15, LEG-16, SCOPE-03).
