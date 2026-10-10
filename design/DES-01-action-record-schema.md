# DES-01 — Action record schema

**Milestone:** M1 · **Covers:** FR-05, FR-06, FR-07

## Decision

The unit of evidence is an **action record**: one consequential thing an agent did.
It is not a conversation turn, not a span, and not a log line.

**Two structures, never one — FR-59.** The `ActionRecord` below is the canonicalised, hashed subject. It
carries no chain metadata, because a digest that depends on a value derived from itself is
circular — an external review caught exactly that in an earlier draft, where `head` lived in the
record while `DES-02` said every field contributes.

```jsonc
// ActionRecord — canonicalised by DES-02, hashed by DES-03. Immutable.
{
  "v": 1,                                  // DES-16 format version
  "collector": "treasury-host-1",          // scopes the chain and the log origin  FR-56
  "run": "bf10bc73-2c1b-442c-b3b2-c044678e03b6",   // null on a heartbeat
  "record_seq": 4812,                      // position in the COLLECTOR's log, from 1
  "source_seq": 4817,                      // observed consequential actions, incl. ones never written
  "ts": "2026-10-10T10:40:36.907Z",        // collector clock, RFC 3339, always UTC, ms precision
  "kind": "tool_call",                     // tool_call | approval | heartbeat | gap | policy
  "tool": "transfer_funds",               // a function name, not a person — retained
  "agent":  { "cid": "sha256:1a0d…" },     // a label that could identify — erasable
  "args":   { "cid": "sha256:9f2c…", "bytes": 61 },     // salted digest, FR-35
  "result": { "cid": "sha256:4b71…", "bytes": 54, "ok": true },
  "approval": null,                        // see below
  "consequential": true                    // as declared by the tool, never inferred
}
```

```jsonc
// ChainEntry — the storage wrapper. NEVER canonicalised, never hashed as a unit.
{ "record": { /* the ActionRecord above, verbatim */ },
  "leaf": "507c3f35…",      // H(0x00 ‖ salt ‖ JCS(record))        DES-03
  "prev": "e818cb6b…",      // predecessor head
  "head": "fe3c7f5e…" }     // H(0x02 ‖ prev ‖ leaf)               DES-04
```

**The leaf salt is not in the ChainEntry.** It lives in `salts/<collector>.json` keyed by
`record_seq` (`DES-03`), because the chain is never deleted and a salt persisted inside it could
never be crypto-shredded — an external review caught exactly that in an earlier draft. This is a
*different* salt from the per-content `content_salt` used to derive each `cid` (`FR-35`); both are
deletable, and both must be, for different reasons.

**No payload is in either structure.** Arguments and results are salted content digests
(`FR-35`); the plaintext lives encrypted in the deletable store (`DES-13`). This is what makes
`PRIV-02` literally true rather than true of large payloads only — and it is what lets erasure
reach *everything*, including a short inline argument that an earlier draft would have written
into a chain that is never deleted.

### Field rules

| Field | Rule |
|---|---|
| `v` | Integer. Bumped only by DES-16's migration process. |
| `collector` | Stable per instance. The chain is scoped to it, not to a run. |
| `run` | Which run this record belongs to, or `null` for a heartbeat. A field, not a partition. |
| `record_seq` | Position in the collector's log, from 1, no gaps except a declared `gap`. Equals the log's `tree_size` at that point. |
| `ts` | Collector clock. **Self-asserted and worth nothing on its own** — the trustworthy time comes from the witness in DES-07. Recorded anyway so drift is visible. |
| `kind` | Closed enum. An unknown `kind` makes a record unverifiable, not ignorable. |
| `args`, `result` | Arbitrary JSON, canonicalised by DES-02. Size-capped; over the cap, content moves to the store (DES-13) and the field holds a pointer. |
| `approval` | `null`, or `{ "decision": "approve"\|"deny", "reviewer": "<as supplied>", "request_hash": "<hex>" }`. |
| `consequential` | Taken from the tool's own declaration. Never inferred from names or arguments. |

### What is deliberately absent

No prompt, no system prompt, no conversation history, no model output, no reasoning. Those are
the agent runtime's concern and OMA's `verifyRun()` already covers what the model saw. Including
them would enlarge the record, the privacy surface and the erasure problem for no evidentiary
gain — an auditor asks what the agent *did*.

### `approval.reviewer` is not authenticated

The collector records the identity the application supplied, exactly as OMA does. Splitstick
cannot verify that a human with that name decided anything. The field means "the application
asserted this reviewer", and DES-18's practice statement says so. Authenticated approval is a
control-plane feature, not a 1.0 claim.

## Consequences

- The capture boundary (DES-14) must produce this shape from both collectors, so the record format
  is adapter-independent and a verifier never needs to know which collector wrote it.
- A new `kind` is a format version bump, not an additive change, because a verifier must refuse
  what it cannot interpret.

## Verifies

FR-05 and FR-06 by a round-trip test through both collectors; FR-07 by a suspend/approve/resume
cycle whose decision appears as an `approval` record.
