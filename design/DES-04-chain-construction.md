# DES-04 — Chain construction

**Milestone:** M1 · **Covers:** FR-08, SEC-06, SEC-09, SEC-10

## Decision

```
h_0 = 0x00 * 32                                  // genesis
h_i = SHA-256( 0x02 ‖ h_(i-1) ‖ leaf_i )          // 0x02 = chain domain
```

Each record stores `prev` (the predecessor digest) and `head` (its own). A verifier recomputes
the whole chain from genesis.

## What a break proves, and what it does not

| Observation | Conclusion |
|---|---|
`head_i` ≠ recomputed | Record *i* or its predecessor was altered. |
`prev_i` ≠ `head_(i-1)` | An event was inserted, removed or reordered at *i*. |
Chain intact to *n*, nothing after | **Nothing.** A truncated prefix is a valid chain. |

That last row is the whole reason this project needs a second party. **Truncation cannot be
detected from inside the record** — whoever controls the file controls where it ends, and a chain
over a prefix is internally perfect. DES-07 and DES-08 close it by putting the batch count
somewhere the operator does not control.

So SEC-09 and SEC-10 trace to this element for their *mechanism* but are only satisfied once
DES-08 ships. The design states this explicitly rather than letting the chain appear to close
them.

## Rules

1. `seq` starts at 1 per run and increments by exactly 1. The only legitimate discontinuity is a
   `gap` record (DES-10), which is itself chained.
2. A chain is per run. Cross-run ordering comes from the batch sequence at the witness, not from
   the chain.
3. The genesis value is fixed and not configurable. A configurable genesis is a way to fork a
   chain quietly.
4. The chain is append-only in use, but the **file** is not immutable — nothing here assumes
   write protection. Append-only is an invariant the verifier checks, not a property of the
   medium.

## Consequences

- Recomputation is O(n) over the run. DES-12's 100,000-events-in-under-2-seconds budget
  (NFR-04) is a SHA-256 throughput question: ~100k hashes over ~300 bytes each is a few tens of
  milliseconds, so the budget is dominated by parsing, not hashing.
- The chain gives ordering and content integrity. It gives **no** time evidence whatsoever. All
  trustworthy time comes from DES-07.
