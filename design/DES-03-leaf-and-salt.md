# DES-03 — Leaf and salt construction

**Milestone:** M1 · **Covers:** FR-09, SEC-13

## Decision

```
salt_i = CSPRNG(16 bytes)
leaf_i = SHA-256( 0x00 ‖ salt_i ‖ JCS(record_i) )
```

### Why each part

**16 bytes of salt**, from `crypto.randomBytes`. Per leaf, never derived from the record, never
reused. An action record is short and low-entropy — a transfer has perhaps three unknowns — so an
unsalted digest answers *"was the amount 2,000,000?"* in one guess. The salt turns a
2⁴⁸-ish search into a 2¹²⁸ one.

**The `0x00` prefix is domain separation**, and it is not decoration. DES-05 prefixes interior
Merkle nodes with `0x01`. Without distinct prefixes, a leaf and a node can be confused, which is
the textbook second-preimage attack on Merkle trees that RFC 6962 exists to prevent.

**Salts are stored beside the record, not in it.** The record is what gets canonicalised; the
salt is metadata in the store (DES-13). This matters for DES-05's disclosure: revealing one
record means revealing one salt, and the sibling leaves stay opaque because their salts are
never handed over.

## Rules

1. One salt per record. Regenerating a record regenerates its salt and therefore its leaf.
2. A salt is never reconstructible from anything else. Losing a salt makes that record
   unverifiable — reported as **inconclusive**, not as a failure (DES-12).
3. Salts are never transmitted to a witness. The witness sees roots only.
4. Crypto-shredding (DES-13) deletes content and its key; the salt may be deleted with it, which
   is what makes the remaining commitment permanently unlinkable.

## Consequences

- An evidence pack is larger than a bare log: each disclosed record carries 16 bytes of salt.
  Irrelevant in practice.
- Salt loss degrades gracefully to inconclusive. The verdict taxonomy in DES-12 must therefore
  distinguish "cannot answer" from "contradicted" — a distinction OMA's `verifyRun()` gets right
  and which is worth copying.
