# Disclosure pack, version 1

**Covers:** INT-03, FR-32, FR-33, PRIV-06 · **Design:** DES-11 · **Versioning:**
DES-16 · **Checked by:** `packages/verify/test/pack-conformance.test.mjs`

A disclosure pack proves that **one named event** is in a log whose root a second
party countersigned. It is a single JSON document, self-contained: verifying it
requires no network, no credential, no access to the operator's store, and no
code from this project.

**The spec is the guarantee; the implementation is a convenience.** If verifying
ever requires our verifier, the thesis has inverted — a reader would be trusting
us to tell them whether to trust us. So this document is written to be
implemented from, and the conformance test asserts that what the implementation
emits matches what is written here, field for field.

## What a pack claims, and what it does not

It claims: this record was in the tree whose root is named, that root was signed
by the operator identity named, and that root was countersigned by the parties
whose signature lines are included.

It does **not** claim anything about any other record. `covers.complete` is
`false` on every single-event disclosure and is set by construction — there is
no argument to the builder that makes it true. A recipient must be able to tell
a deliberate omission from a missing piece, which is the only reason the field
exists.

## Structure

```jsonc
{
  "manifest": {
    "version": 1,                         // this document's version — DES-16
    "suite": "SS1",                       // or null when the note omits it
    "origin": "splitstick.example/host-1",// the log origin, from the checkpoint
    "collector": "host-1",                // which collector's chain — FR-56
    "covers": { "from_seq": 2, "to_seq": 2, "complete": false },
    "disclosed": [2],                     // the record_seq values in this pack
    "note": "Single-action disclosure. …"
  },
  "record": { /* the ActionRecord, exactly as it is in the chain */ },
  "salts":  { "2": "<32 hex chars>" },    // the DISCLOSED record's leaf salt only
  "proof": {
    "index": 1,                           // 0-based leaf index in the tree
    "tree_size": 3,                       // the size the checkpoint commits to
    "path": ["<base64 node digest>", …],  // RFC 6962 audit path
    "root": "<64 hex chars>",             // the root the path must reach
    "checkpoint_seq": 1,                  // which checkpoint, for the operator
    "leaf": "<64 hex chars>"              // ONLY when the salt is gone — below
  },
  "checkpoint": { /* a DES-20 envelope: the note plus EVERY countersignature */ },
  "content": {
    "args":   { "cid": "sha256:…", "present": true, "base64": "…", "salt": "<32 hex chars>" },
    "result": { "cid": "sha256:…", "present": false }
  }
}
```

### `salts` — exactly one entry, or none

One entry, keyed by the disclosed `record_seq`, holding that record's 16-byte
leaf salt as 32 hex characters. **A second entry would make a second record's
content recomputable** by anybody who can guess at it, and you cannot
un-disclose: this is checked when the pack is built, not when it is read.

The object is **empty** when the record has been crypto-shredded, and
`proof.leaf` is then present instead: the committed leaf digest, as 64 hex
characters. That is what keeps a shredded record's inclusion **provable** —
erasure must not become a way to make history unprovable — and it is precise
about the limit. A recipient can prove that leaf is in the countersigned tree;
they cannot prove the leaf is the record shown, because that binding needs the
salt and the salt was destroyed with the content. A verifier must report both
halves, because an inconclusive that did not distinguish them would read as the
proof having failed.

`proof.leaf` is present **only** when the salt is absent. A pack carrying both
would let a recipient check the cheap one and skip recomputing the leaf from
the record, which is the step that binds the two together.

### `proof` — RFC 6962, over the tree the checkpoint committed to

The leaf is `SHA-256(0x00 ‖ leaf_digest)` where `leaf_digest` is computed from
the record and its salt as DES-03 specifies. The audit path and the verification
algorithm are RFC 6962 §2.1.1 unchanged.

`tree_size` is the size the **checkpoint** commits to, which may be smaller than
the log is now. A proof built against a taller tree would not verify against the
root the witness signed.

**What the path reveals, stated rather than denied.** The audit path contains the
*hash* of a sibling leaf — that is how an inclusion proof works. It does not
contain a sibling's `leaf_digest`, which is the salted commitment itself, so a
sibling's content can be neither reproduced nor confirmed: that would need the
sibling's salt, which is not in the pack.

### The note and the identity formats, for an implementer

An independent implementation needs these stated, not inferred. The first
version of this document omitted them and the project's own
written-from-the-spec verifier got the identity wrong on its first run — which
is the gap INT-03 exists to find.

**The note** (DES-07, after C2SP `tlog-checkpoint`) is text, a blank line, then
signature lines:

```
<origin>\n<tree_size>\n<base64 32-byte root>\n[<extension lines>\n]
\n
— <name> <base64(key_id ‖ signature)>\n
…
```

The signed bytes are the text **including its trailing newline** and **excluding**
the blank line and everything after it. The marker is an em dash and one space,
`U+2014 U+0020`. `key_id` is 4 bytes; the Ed25519 signature is the remaining 64.

**An identity** (`vkey`) is `<name>+<key_id hex>+<base64(algorithm ‖ public_key)>`.
Algorithm `0x01` is Ed25519 and the public key is the 32 bytes after it. Two
traps, both of which this project's own spec-only verifier fell into:

- **The third part is not a bare public key.** It carries the algorithm byte
  first; the key is the 32 bytes after it, and the whole blob is 33.
- **Split at the first two `+`, never on every one.** Standard base64 contains
  `+`, so splitting on all of them shards the key material — roughly one key in
  four, which fails intermittently and looks like anything but a parsing bug.

**`key_id`** is the first 4 bytes of `SHA-256(name ‖ 0x0A ‖ algorithm ‖ public_key)`.

### `checkpoint` — every countersignature, never a preferred one

A DES-20 envelope carrying the note and **all** signature lines collected,
including from witnesses this project does not operate and does not endorse
(FR-31). Filtering to one would force the recipient to trust whoever we chose,
and it is what makes a separate acceptance policy meaningful: a reader who
accepts only one authority verifies the same pack, ignoring the rest, without
asking the operator to regenerate anything.

### `content` — this record's payloads, with the salts that make them checkable

Keyed by where the commitment sits on the record: `agent`, `args`, `result`,
`approval.reviewer`, `approval.request`.

| Field | |
|---|---|
| `cid` | the commitment the record holds, `sha256:` and 64 hex characters |
| `present` | whether the bytes are carried |
| `base64` | the plaintext, when `present` |
| `salt` | the **content salt**, 32 hex characters, when `present` |

**`salt` is not optional when `present` is true, and a pack without it proves
nothing about the payload.** A content cid is
`SHA-256(0x05 ‖ salt ‖ plaintext)`, so a recipient handed the plaintext and the
cid and no salt cannot check one against the other. The first version of this
format omitted it: substituting the payload entirely produced a verdict of `ok`
with no findings, because the implementation's "content check" compared an
unsalted digest against the salted cid — a comparison that can never be true.

Revealing this salt costs nothing. Its job is to stop a guess at an
**undisclosed** plaintext being confirmed, and this plaintext is being
disclosed. A **sibling's** content salt must never appear: that would let a
recipient confirm a guess at a payload nobody disclosed, which is the whole of
PRIV-06.

`present: false` means the payload was erased; the commitment is still carried,
so the recipient can tell *erased* from *not included*. `present: false`
**with** `base64` is a contradiction and must be refused: accepting it means the
bytes are silently ignored, so a pack could hand over a payload nothing would
ever check.

### The manifest must agree with the record

`manifest.disclosed[0]`, `manifest.covers.from_seq`, `manifest.covers.to_seq`
and `record.record_seq` are all the same number for a single-event pack. A
verifier checks this **before** anything else, or it ends up reasoning about two
records at once: the salts map is keyed by `record_seq`, so a manifest naming a
record the pack does not hold simply finds no salt, and a report that trusted
the manifest would tell the reader they are looking at a record they are not.

## How to verify, in order

1. **Refuse an unknown `manifest.version`.** Do not partially verify a format
   you cannot read.
2. **Parse the checkpoint note** and read its `origin`, `tree_size` and `root`.
3. **Require a countersignature** (FR-33). A root nothing countersigned
   establishes only that the operator is consistent with their own arithmetic.
   A pack without one is refused, not accepted with a caveat.
4. **Check each countersignature** against your acceptance policy. One from an
   issuer you do not name is *present and unverified* — never verified, and
   never a failure either.
5. **Check the operator signature** over the note against the identity you
   pinned. Pinning nothing is reported as pinning nothing, not as a pass.
6. **Check the manifest against the record.** `disclosed[0]`, both `covers`
   bounds and `record.record_seq` are one number.
7. **Recompute the leaf** from `record` and its salt. Do not take the pack's
   word for which leaf this is. Where the salt is absent, use `proof.leaf` and
   report that the leaf-to-record binding is unchecked.
8. **Recompute each present payload's commitment** as
   `SHA-256(0x05 ‖ salt ‖ plaintext)` and compare it to `cid`. Refuse a payload
   flagged absent that carries bytes anyway.
9. **Verify the audit path** reaches `proof.root`, then check that
   `proof.root` is the root **the checkpoint commits to**. Stopping after the
   first half would let an operator prove inclusion in a tree nobody
   countersigned.
10. **Report absent content as absent**, not as a failure. Erasure is lawful.

## Verdicts

`ok`, `fail`, `inconclusive`. A single `fail` makes the verdict `fail`;
`inconclusive` never becomes `ok` and never becomes `fail`. The codes are the
verifier's shared vocabulary in `spec/failure-codes.json` — a reader should not
have to know which tool is talking before they can read a code.

## Versioning

Breaking changes raise `manifest.version`. A verifier that implements version
*n* refuses *n+1* with the version it cannot read. Additive, ignorable fields do
not raise it.
