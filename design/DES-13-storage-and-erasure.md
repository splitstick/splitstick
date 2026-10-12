# DES-13 — Storage and erasure

**Milestone:** M1 · **Covers:** FR-35, FR-36, FR-37, PRIV-02, PRIV-03, PRIV-04, PRIV-05, PRIV-09

## Decision

**Content never enters the chain.** Two stores with different lifetimes:

```
splitstick/
  chain/<collector>.jsonl  append-only; records, leaves, heads.  NEVER DELETED
  salts/<collector>.jsonl  record_seq -> salt.  DELETABLE per record            [DES-03]
  checkpoints/<collector>/<n>.note  C2SP notes, scoped like the chain          [DES-07]
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

### The residue scan — PRIV-05, PRIV-03

The table above is a claim, and `packages/core/src/residue.mjs` is what stops it from becoming a
description of a previous version of the schema. Four codes, in the verifier's shared vocabulary
rather than a second one:

| Code | Verdict | When |
|---|---|---|
| `RESIDUE_UNCLASSIFIED_FIELD` | fail | the schema permits a field the inventory does not classify, so the scan cannot say whether it survives — and an unclassified field would survive by default |
| `RESIDUE_UNEXPECTED_FIELD` | fail | a field, or a sub-key of a commitment, is present and is not retained by this table |
| `RESIDUE_SALT_RETAINED` | fail | a shredded record's leaf salt is still held, so the commitment is still linkable |
| `RESIDUE_CONTENT_RETAINED` | fail | a shredded record's payload is still retrievable — the key journal still holds its entry, or the blob still reaches the bytes |

All four are `fail`, because each is a privacy claim broken rather than a weaker one.

**The first code is the one that matters.** A scan that only checked the residue would pass
forever while the schema grew underneath it, so the classification is checked against `ALLOWED`:
extending the record format forces a decision about whether the new field survives a deletion
request. The scan found one on its first run — `agent.bytes` was retained, and this table, which a
review established as the whole inventory rather than a sample, does not list it. Nothing reads
it, and a label's length is more identifying per byte than a payload's, because an address or a
name is short and its length narrows a guess at a person. **The collector no longer writes it**;
`args.bytes` and `result.bytes` remain, for the reason stated above.

Tightened at emission only. `validateRecord` still accepts `bytes` on any commitment, because it
is also the read path: refusing it there would turn every record already written into
`MALFORMED_RECORD`, which the verifier reports as `fail` — a false tampering signal over evidence
that was correct when it was written.

### Retention — FR-37, PRIV-09

`retention: 30d` in the config, applied by `Store.applyRetention`, which crypto-shreds every
record older than the window and **never touches the chain**. That independence is the
requirement: a retention setting that changed what the chain committed to would make the
cryptography and the policy inseparable, and the chain is the thing that must survive every lawful
deletion. A test asserts the leaves and heads are byte-identical across a sweep.

Nothing is written into the chain about a sweep. A retention sweep is not an agent action, and
recording one there would mean the chain grew every time the operator deleted something. A record
whose `ts` cannot be read is **not** swept — guessing would mean deleting evidence on the strength
of a field we just refused to read — and the sweep returns it instead.

The key was in the config's known-key list and never parsed, so `retention: 30d` was accepted and
silently meant *keep forever*. That is the third instance of this shape in the project, after
`padding` and the verifier's `--vkey`.

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
   It is **one append-only encrypted blob** plus a `cid -> key, offset, length` journal, not a file
   per payload. Creating a file measured p50 0.19 ms and p99 1.04 ms against NFR-01's 1 ms budget,
   while a write to an open descriptor measured 0.008 ms — so a file per record cannot meet the
   budget at p99 no matter how fast the cryptography is. Erasure overwrites the extent with zeros
   in place, which keeps FR-36's claim at *the bytes are gone* rather than weakening it to *the key
   is gone*; erasing the last surviving payload removes the blob.
3. **The salt is written before the chain line.** Two files cannot be written atomically, so the
   order decides what a partial failure leaves. Chain-first left a committed record whose salt was
   missing while the collector's own position had not advanced, and the next append then reused the
   sequence — a verifier reported a disk-full incident as tampering, permanently. Salt-first leaves
   at worst an orphan salt for a record that was never written, which joins to nothing.
   An append that fails marks the collector **degraded**: it refuses further writes rather than
   continuing from a position it cannot trust, until `recover()` re-reads the chain and finds it
   consistent. The agent keeps running throughout, because the adapter is fail-open (SCOPE-16).
4. **One writer per collector, enforced.** With a file per payload two writers could not collide. With
   one blob they both cache the append offset and the second silently overwrites the first, so the
   store takes an advisory lock on its first write and a second writer is refused. Readers take no
   lock and are never refused: a verifier must be able to open a live store, and cannot damage it.
   The lock is **per collector**, not per root — content, keys and the reference index are all
   scoped to the collector, like the chain and the salts — so two collectors may be active in one
   store root simultaneously. A root-wide lock was safe but made that impossible, which contradicted
   the multi-collector reads the verifier already supports.
3. PRIV-02 is enforced by test: a scan of `chain/` for any string from the fixture's content must
   find nothing.
