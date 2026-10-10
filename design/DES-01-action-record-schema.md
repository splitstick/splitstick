# DES-01 — Action record schema

**Milestone:** M1 · **Covers:** FR-05, FR-06, FR-07

## Decision

The unit of evidence is an **action record**: one consequential thing an agent did.
It is not a conversation turn, not a span, and not a log line.

```jsonc
{
  "v": 1,                                  // DES-16 format version
  "run": "bf10bc73-2c1b-442c-b3b2-c044678e03b6",
  "seq": 4812,                             // monotonic within a run, from 1
  "ts": "2026-10-10T10:40:36.907Z",        // collector clock, RFC 3339, always UTC, ms precision
  "kind": "tool_call",                     // tool_call | approval | heartbeat | gap | policy
  "agent": "treasury-agent",
  "tool": "transfer_funds",
  "args": { "amount": 2000000, "currency": "EUR", "to": "ACME-9931" },
  "result": { "ok": true, "content": "OK: transferred EUR 2000000 …" },
  "approval": null,                        // see below
  "consequential": true                    // as declared by the tool, never inferred
}
```

### Field rules

| Field | Rule |
|---|---|
| `v` | Integer. Bumped only by DES-16's migration process. |
| `run`, `seq` | Together uniquely identify a record. `seq` has no gaps except a `gap` record. |
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
