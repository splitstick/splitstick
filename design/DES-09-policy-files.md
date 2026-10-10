# DES-09 — Policy files

**Milestone:** M1 · **Covers:** FR-41, FR-30, FR-23, NFR-03, SEC-12, SCOPE-15

## Decision

**Two files, deliberately separate.** One says who gets *asked* to countersign; the other says
whose signature is *accepted*. Collapsing them into one would make the openness decorative,
because every verification would terminate at the project's own key.

### `splitstick.yaml` — the collector's, authored by the operator

```yaml
version: 1
store: ./splitstick            # DES-13
signer:
  type: kms                    # kms | hsm | file (file = development only)
  key: projects/…/cryptoKeys/splitstick
  epoch: 24h                   # DES-06
anchor_interval: 10s           # the mutability window — NFR-03
rollup_interval: 1h            # DES-05 tier two
on_unavailable: mark_gap       # the ONLY value. See SCOPE-16.
witnesses:
  - { id: tsa,   type: rfc3161,        url: "https://<free-public-tsa>" }
  - { id: ots,   type: opentimestamps, tier: rollup }
# - { id: audit, type: splitstick,     url: "https://witness.audit.internal", key: "…" }
# - { id: rekor, type: rekor,          tier: rollup }   # opt-in; see FR-47 on acceptable use
quorum: 1
```

`on_unavailable` accepts exactly one value. It is a key rather than a hardcoded behaviour only so
the file documents itself — **there is no fail-closed setting, by design** (SCOPE-16). A
configuration that can stop an agent run is a configuration that will, at 3 a.m.

### `acceptance.json` — the verifier's, authored by whoever is checking

```json
{
  "version": 1,
  "accept": [
    { "id": "qtsp", "type": "rfc3161", "key": "<base64 spki>" },
    { "id": "ots",  "type": "opentimestamps" }
  ],
  "quorum": 1,
  "require_rollup": false
}
```

An auditor who accepts only eIDAS-qualified authorities supplies this and verifies the same pack.
Evidence packs carry **every** countersignature collected (FR-31), never only the default, so a
verifier with a different policy can always find one it trusts.

## Policy changes are chain events — FR-23, SEC-12

Any change to `witnesses`, `quorum`, `anchor_interval` or `rollup_interval` emits a `policy`
record carrying the digest of the previous effective policy and of the new one. It is chained and
anchored like anything else.

This closes the downgrade attack: weakening the policy and *then* tampering leaves a timestamped,
countersigned record of the weakening. Detectable, attributable, and impossible to do quietly.

## SCOPE-15 — the roll-up anchor must be disableable

The trust-minimised roll-up (`ots`) is on by default, because it is the only free public anchor
with no acceptable-use objection. Removing it is one line — and that removal is itself a `policy`
record. It can never be mandatory: public-chain anchoring is forbidden outright at some regulated
buyers.

## Consequences

- Two schemas to version, both under DES-16.
- The commented-out lines ship in the default file. An operator should be able to see their
  options without reading documentation first.
