# DES-13 — Storage and erasure

**Milestone:** M1 · **Covers:** FR-35, FR-36, FR-37, PRIV-02, PRIV-03, PRIV-04, PRIV-05, PRIV-09

## Decision

**Content never enters the chain.** Two stores with different lifetimes:

```
splitstick/
  chain/<run>.jsonl        append-only; records, leaves, heads, salts.  NEVER DELETED
  batches/<seq>.json       roots, signatures, countersignatures
  content/<cid>.bin        large or sensitive payloads.  DELETABLE
  keys/<cid>.key           per-content encryption keys.  DELETABLE
  queue/                   unwitnessed batches awaiting a witness (DES-15)
```

A record field over the inline cap holds a pointer instead:

```jsonc
"result": { "ref": "cid:9f2c…", "bytes": 48213, "enc": "aes-256-gcm" }
```

The pointer — and therefore the digest — covers the content *identity*, not its bytes. The
chain commits to what the content was without containing it.

## Erasure is crypto-shredding — FR-36, PRIV-03

To honour a deletion request:

1. Delete `content/<cid>.bin`.
2. Delete `keys/<cid>.key`.
3. Leave the chain untouched.

Afterwards: the data subject's information is unrecoverable; the chain still verifies; the record
retains a salted commitment to a plaintext nobody can produce. The commitment becomes
**permanently unlinkable**.

Verification of a shredded record yields `ok` for chain, tree, signature and countersignature,
and `inconclusive` for content reproduction — correctly, since the content is gone by design
rather than by tampering. **DES-12's three-verdict taxonomy is what makes GDPR compatibility
expressible at all**; with a binary pass/fail, erasure would look identical to a tamper.

## The residual risk, stated

A salted SHA-256 of personal data is probably not personal data once the salt and plaintext are
destroyed, since re-identification requires both. "Probably" is doing real work in that sentence:
regulators' positions on hashed and pseudonymised data vary, and this design has had no
independent privacy review — `PRIV-03`'s verification says so, and the review is deferred to a
funded release. The architecture makes the argument as strong as it can be made; it does not
settle it.

## Retention — FR-37, PRIV-09

Retention is a policy on `content/` and `keys/`, expressed in `splitstick.yaml`, and is
**entirely independent of the cryptography**. The chain has no retention policy because it holds
nothing to retain. That separation is the whole point: Article 19 asks for six months of logs
accessible, and Article 17 asks for erasure, and these are only compatible if the two live in
different stores.

## Rules

1. `chain/` is append-only and never deleted. It is small — a few hundred bytes per action.
2. `content/` is operator-controlled, deletable, and may live anywhere, including object storage.
3. PRIV-02 is enforced by test: a scan of `chain/` for any string from the fixture's content must
   find nothing.
