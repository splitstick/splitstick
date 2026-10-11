# DES-13 — Storage and erasure

**Milestone:** M1 · **Covers:** FR-35, FR-36, FR-37, PRIV-02, PRIV-03, PRIV-04, PRIV-05, PRIV-09

## Decision

**Content never enters the chain.** Two stores with different lifetimes:

```
splitstick/
  chain/<collector>.jsonl  append-only; records, leaves, heads.  NEVER DELETED
  salts/<collector>.jsonl  record_seq -> salt.  DELETABLE per record            [DES-03]
  checkpoints/<n>.note     C2SP notes with every signature line                 [DES-07]
  content/<cid>.bin        every payload, encrypted.  DELETABLE
  content/<cid>.salt       per-content salt.  DELETABLE
  keys/<cid>.key           per-content encryption keys.  DELETABLE
  content/refs.idx         counterparty reference index.  DELETABLE          [DES-19]
  queue/                   unwitnessed batches awaiting a witness (DES-15)
```

**Every** payload is externalised, not just oversized ones, and the pointer is a commitment to
the bytes:

```
cid = SHA-256( 0x05 ‖ content_salt ‖ plaintext )
```

```jsonc
"result": { "cid": "sha256:9f2c…", "bytes": 48213, "ok": true }
```

An external review found the earlier wording — "the digest covers the content *identity*, not its
bytes" — to be a real hole: an identity not derived from the content lets an operator substitute
the payload while the pointer and the chain stay valid. The `cid` is now a salted hash **of the
plaintext**, so substitution changes it and the leaf no longer reproduces.

The salt is why this does not reintroduce a privacy problem. A bare `SHA-256` of a short payload
is brute-forceable; a salted one is not, and deleting `content_salt` with the ciphertext and key
is what makes the surviving commitment unlinkable.

## Erasure is crypto-shredding — FR-36, PRIV-03

To honour a deletion request:

1. Delete `content/<cid>.bin` and `content/<cid>.salt`.
2. Delete `keys/<cid>.key`.
3. Delete the record's entry from `salts/`.
4. Leave the chain untouched.

Step 3 is what makes the commitment unlinkable, and it is why **salts must not live in the
chain**: the chain is never deleted, so a salt stored there could never be shredded and the
erasure claim would be unsatisfiable. An earlier draft of this document made exactly that
mistake.

Afterwards: the enumerated set is unrecoverable; the chain still verifies; the record retains a
salted commitment to a plaintext nobody can produce.

**What permanently remains**, stated rather than waved at — an external review was right that a
blanket claim was doing too much work:

| Retained forever | Erasable |
|---|---|
| `v`, `collector`, `run`, `record_seq`, `source_seq`, `ts`, `kind`, `consequential` | every payload |
| `tool` — a function name, not a person | the `agent` label |
| `approval.decision` — approve or deny identifies nobody | `approval.reviewer` |
| `outcome`, `attempt` — an enum and a small integer | |
| `pad` — a padding record's random nonce | |
| `correlation` — **required to be an opaque random identifier**, never derived from a payload, a user or a session | |
| `result.ok` — a boolean outcome | `approval.request` |
| `args.bytes`, `result.bytes` — payload lengths | content salts, leaf salts |
| salted content digests, leaf digests, chain heads | the reference index |
| gap spans and unknown-loss intervals | |

This table is the whole inventory, not a sample. An external review found an earlier version
omitting `approval.decision`, `approval.request_hash`, `result.ok` and the byte lengths — and a
partial inventory is worse than none, because it reads as exhaustive.

**`correlation` is retained, so it must carry nothing.** It survives erasure and links the
attempts of one action, which means it also reveals that those records belong together. That
relationship is the point and cannot be erased without breaking retry accounting. So the
identifier itself is required to be opaque and randomly generated — never a request id, a user
id, a session id, or anything derived from a payload. A reviewer noted it could otherwise carry
identifying information, and a retained field that carries anything is a retained disclosure.

**The byte lengths are a deliberate, documented leak.** `args.bytes` and `result.bytes` survive
erasure and reveal payload size, which narrows a guess about content. They are retained because a
verifier needs them to detect a truncated content store, and the trade is stated here rather than
discovered later.

**There is no mitigation for this in 1.0, and `FR-34` is not one.** Batch padding adds dummy
leaves to obscure *how many* records exist; it does nothing about `args.bytes`, which reveals how
large one payload was. A reviewer caught an earlier draft citing it as the remedy. Concealing
individual lengths would need the content itself padded before encryption, which is not in this
release. The leak is documented and unmitigated — which is the honest pair of words.

The `agent` label and any reviewer are stored as salted content digests precisely because either
could name a person. `tool` is retained because `transfer_funds` identifies a function. Whether
that residue is non-personal under a given regime is a question for the privacy assessment
`PRIV-03` defers to a funded release, not something this document should settle by assertion.

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

1. `chain/` is append-only and never deleted, and contains **no salts and no content**. It is
   small — a few hundred bytes per action.
   The salt file is append-only JSONL for the same reason the chain is: a `record_seq -> salt`
   map rewritten on every append is O(n²) and would breach NFR-01's 1 ms p99 within a few
   thousand records. Erasure rewrites it, which is rare and bounded; appending must not.
2. `content/` is operator-controlled, deletable, and may live anywhere, including object storage.
3. PRIV-02 is enforced by test: a scan of `chain/` for any string from the fixture's content must
   find nothing.
