# DES-16 — Format versioning and algorithm agility

**Milestone:** M1 · **Covers:** NFR-07, NFR-08, NFR-10, NFR-11

## Decision

Versioning is an M1 decision because **it cannot be retrofitted**. A record written in 2027
without a version field is a record that can never be migrated safely, and NFR-07 promises
verifiability years later.

Three independently versioned things:

| | Field | Changes when |
|---|---|---|
Record schema | `v` in each record (DES-01) | a field is added, removed or reinterpreted |
Algorithm suite | `suite` in each batch | a hash or signature algorithm changes |
Pack format | `version` in the manifest (DES-11) | the pack layout changes |

### Suites, not negotiated algorithms

```jsonc
"suite": "SS1"    // SHA-256 · Ed25519 · JCS · RFC6962 · domain prefixes 0x00-0x04
```

A suite is a **named, frozen tuple**. There is no algorithm negotiation and no mix-and-match,
because negotiation is where downgrade attacks live. `SS2` would be a new named tuple, published
in the spec, and a verifier either knows a suite or refuses the batch.

## Migration path

When SHA-256 or Ed25519 must be retired:

1. `SS2` is published with the new primitives.
2. The operator emits a `policy` record declaring the suite change (DES-09), anchored and
   countersigned, so the transition has an independently established time.
3. New batches use `SS2`. **Old batches are never re-signed** — re-signing history under a new
   key is indistinguishable from the attack this project exists to detect.
4. A verifier validates each batch under its own recorded suite, and reports a batch whose suite
   is deprecated as `inconclusive` with an explanation, never silently `ok`.

That last rule is the important one. The temptation, years out, will be to "upgrade" old
evidence. Old evidence is only worth what it was worth when it was witnessed.

## Unknown versions fail closed

A verifier meeting an unrecognised `v`, `suite` or pack `version` reports `FORMAT_UNSUPPORTED`
and stops. It never skips the record, never guesses, and never partially verifies. Forward
compatibility by ignoring unknown fields is appropriate for configuration; it is not appropriate
for evidence.

## Platform support — NFR-08, NFR-10, NFR-11

| | Supported |
|---|---|
Node.js | 20 and later, tested across supported majors in CI |
`@open-multi-agent/core` | 1.21.x, pinned and tested |
MCP transports | stdio and HTTP |

The OMA range is narrow on purpose. Journal shapes there are internal and may change, and the
red-team canary is what tells us when they do.
