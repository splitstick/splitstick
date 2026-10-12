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
    "checkpoint_seq": 1                   // which checkpoint, for the operator
  },
  "checkpoint": { /* a DES-20 envelope: the note plus EVERY countersignature */ },
  "content": {
    "args":   { "cid": "sha256:…", "present": true, "base64": "…" },
    "result": { "cid": "sha256:…", "present": false }
  }
}
```

### `salts` — exactly one entry, or none

One entry, keyed by the disclosed `record_seq`, holding that record's 16-byte
leaf salt as 32 hex characters. **A second entry would make a second record's
content recomputable** by anybody who can guess at it, and you cannot
un-disclose: this is checked when the pack is built, not when it is read.

The object is **empty** when the record has been crypto-shredded. Its inclusion
is still provable, and its content is not reproducible — erasure must not become
a way to make history unprovable.

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

### `content` — this record's payloads only

Keyed by where the commitment sits on the record: `agent`, `args`, `result`,
`approval.reviewer`, `approval.request`. `present: false` means the payload was
erased; the commitment is still carried, so the recipient can tell *erased* from
*not included*.

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
6. **Recompute the leaf** from `record` and its salt. Do not take the pack's
   word for which leaf this is.
7. **Verify the audit path** reaches `proof.root`, then check that
   `proof.root` is the root **the checkpoint commits to**. Stopping after the
   first half would let an operator prove inclusion in a tree nobody
   countersigned.
8. **Report absent content as absent**, not as a failure. Erasure is lawful.

## Verdicts

`ok`, `fail`, `inconclusive`. A single `fail` makes the verdict `fail`;
`inconclusive` never becomes `ok` and never becomes `fail`. The codes are the
verifier's shared vocabulary in `spec/failure-codes.json` — a reader should not
have to know which tool is talking before they can read a code.

## Versioning

Breaking changes raise `manifest.version`. A verifier that implements version
*n* refuses *n+1* with the version it cannot read. Additive, ignorable fields do
not raise it.
