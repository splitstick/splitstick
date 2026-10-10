# DES-05 — Batching and Merkle tree

**Milestone:** M1 · **Covers:** FR-32, FR-33, FR-34, FR-53, PRIV-06

## Decision

**Adopt RFC 6962 §2 (Certificate Transparency) for the tree.** Same reason as JCS: the
hard parts are already specified and independently implemented.

```
MTH({})        = SHA-256()
MTH({d0})      = SHA-256(0x00 ‖ d0)              // leaf — matches DES-03
MTH(D[n])      = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))
                 where k is the largest power of two < n
```

RFC 6962 gets right the two things hand-rolled trees get wrong: **odd leaf counts** (it does not
duplicate the last leaf, which is the bug that enabled CVE-2012-2459 in Bitcoin) and **domain
separation** between leaf and interior nodes.

## The log is append-only and running

The Merkle tree is over **every leaf in the collector's log so far**, not over an isolated batch.
A checkpoint says "this log now has `tree_size` entries and this is its root" — exactly the CT
model, and the reason `tree_size` is monotonic and a rollback is detectable.

A "batch" is therefore only a **publication cadence**: the set of records added since the last
checkpoint. Both tiers below publish checkpoints of the same log at different frequencies to
different witnesses, so there is one tree, not two.

## Publication boundaries

A checkpoint is published on whichever comes first:

| Trigger | Default | Requirement |
|---|---|---|
| Elapsed time | `anchor_interval`, 10 s | NFR-03 |
| Record count | 1,024 | — |
| Explicit flush | on shutdown | DES-15 |

The elapsed-time trigger is the **mutability window**: records in an open batch are not yet
anchored and are freely rewritable. The default is 10 seconds and the operator sets it. This is
stated plainly in the notes rather than hidden.

## Two tiers — FR-53

| Tier | Interval | Submitted to |
|---|---|---|
| **Frequent checkpoint** | 10 s | per-batch witness (TSA) |
| **Roll-up checkpoint** | 1 h | trust-minimised anchor, or a transparency log |

The roll-up is a checkpoint of the same running log at a lower frequency, so one roll-up entry
covers every record beneath it. This exists because a public good is not free infrastructure: at a 10-second
cadence a single agent produces 8,640 entries a day, and the Rekor maintainers' guidance on
exactly this workload was to anchor a summary instead. The roll-up is that summary.

An inclusion proof for one record is a single audit path to a root; which checkpoint that root belongs to determines which witnesses countersigned it.

## Disclosure — FR-32, FR-33, PRIV-06

`splitstick disclose` emits the record, its salt, the audit path to the batch root, the audit
path to the roll-up root, and every countersignature over both. The recipient recomputes and
matches.

**What is revealed, exactly:** the disclosed record; the sibling *digests* along both paths; and
the **tree sizes**, hence the total number of recorded actions.

**What is not:** the content of any sibling, because their salts are never disclosed (DES-03).

The tree-size leak is unavoidable, not an oversight. An inclusion proof is a statement about a
position in a tree of known size; concealing the size would mean you could no longer prove
nothing was deleted. You cannot simultaneously claim *"nobody knows how many actions I took"*
and *"you can prove I deleted none."* The count is deliberately public.

**FR-34** offers optional batch padding with dummy leaves where activity volume itself is
sensitive. Off by default, because it inflates every proof and most operators do not need it.

## Consequences

- Proof size is O(log n) twice over — around 20 sibling digests for a million records, so under
  a kilobyte. Disclosure is cheap.
- The two-tier scheme means a verifier must handle a record whose batch is anchored but whose
  roll-up is not yet. That window is reported as **inconclusive for the roll-up leg**, with the
  batch leg still verified.
