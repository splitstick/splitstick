# M5 follow-ups

What M5 left open, written at the point of shipping.

## Not met, and said so — NFR-04

**Verification of a 100,000-event run in under two seconds is NOT established.**
Sixteen of M5's seventeen requirements are done; this one is not, and the matrix
says so rather than claiming it.

Two reasons, and they are different in kind.

**The measurement has nowhere to run.** `bench/reference-env.json` puts the
load-average ceiling at 1.0 and calls a number from anywhere else a regression
metric, not an acceptance result — a discipline this project adopted after
performance claims from unqualified runs had to be withdrawn. The development
host sat at load average 13 while M5 was built. Nothing measured there settles
anything, in either direction, and widening the budget to fit a loaded laptop is
the exact failure that discipline exists to prevent.

**What was measured is an algorithmic defect, and it is fixed.** The verifier
called `treeRoot(leaves.slice(0, cp.tree_size))` once per checkpoint —
O(checkpoints · n). That was the single largest cost in verification: 585 ms of
a 2.3 s run over 8,000 records, which extrapolates to roughly 59 seconds at the
size NFR-04 names. `merkle.prefixRoots` now computes every requested prefix in
one left-to-right pass, proven equal to `treeRoot` for **every** prefix size
rather than for a sample, because the forest fold is exactly where an off-by-one
would live.

**What remains, and is the next thing to measure.** JCS canonicalisation costs
about 19 µs a record, and `leafDigest` about 30 µs including it. At 100,000
records that is roughly three seconds before any tree or signature work — over
the budget on its own. So NFR-04 probably needs the canonicaliser optimised, not
only the tree walk, and that should be established on the reference host before
anybody decides how much work it is. The honest options, in order of preference:
make canonicalisation faster; or revise the requirement with a measured number
and a stated reason. Not: quietly leave the requirement claiming something no
run supports.

## Open, and worth deciding before 1.0

**`PRIV-03` defers an independent privacy assessment of the residue, and that is
still deferred.** The residue scan proves the enumerated set is what remains; it
cannot establish that the residue is non-personal under any particular regime.
`tool` is retained because `transfer_funds` identifies a function, and
`correlation` is retained and required to be opaque — whether that is enough is
a question for a privacy assessment and not for this codebase to settle by
assertion.

**The byte-length leak is unmitigated and will stay that way in 1.0.**
`args.bytes` and `result.bytes` survive erasure and narrow a guess at content.
A verifier needs them to detect a truncated content store. Concealing them would
need the content padded before encryption, which is not in this release. M5
narrowed the leak — label lengths are no longer retained at all — and did not
remove it.

**Padding quantises the chain's height, which costs a full block per action at
the boundary.** With `to_multiple: 8` and one action per batch, the collector
writes eight records per action. That is the documented cost of obscuring
volume, and whether a cheaper scheme exists — quantising a rolling window rather
than the absolute height — is worth thinking about before an operator turns it on
in anger.

**`INT-03`'s conformance is in-repo, which is the strongest thing available
here and not the thing the requirement ultimately wants.** A second
implementation written from the spec alone is a real check — it found two gaps
in the document on its first run — but it is not a *third party*, and only a
third party can supply that. The spec is published and versioned so one can.

## Decided against

**Tightening `validateRecord` to refuse `bytes` on a label commitment.** It is
also the read path, so refusing it there would turn every record already written
into `MALFORMED_RECORD` — a false tampering signal over evidence that was correct
when written. Closed at emission and at interpretation instead, which is the same
split M4 arrived at for the heartbeat fields and for the same reason.

**A `RESIDUE_ERASABLE_RETAINED` failure code.** It existed for about an hour.
Correcting the classification — `approval.reviewer` and `approval.request` are
commitments whose *values* are erasable, not sub-keys that disappear — left it
unreachable, and a code nothing can emit is what the failure-code lint exists to
prevent.

**Writing a retention sweep into the chain.** A sweep is not an agent action,
and recording one there would mean the chain grew every time the operator
deleted something.

## Defects found while building, each by running the thing

1. **The residue scan looked for files that never existed.** It checked
   `content/<cid>.bin` and `keys/<cid>.key` — DES-13's illustrative filenames —
   while the content store groups payloads into one blob with a key journal
   beside it. Every content check passed vacuously. A scan written against a
   document rather than against the code reports a clean residue for a store it
   has not looked at.

2. **The first erasure classification reported a correctly shredded record as
   retaining data.** `approval.reviewer` and `approval.request` were listed as
   erasable sub-keys; they are commitments whose values are erasable. The
   salted digest remains in the chain, which is never deleted, and shredding
   makes it unlinkable.

3. **`agent.bytes` was retained and DES-13's inventory does not list it.** Found
   by the residue scan on its first real run. An external review had established
   that table as the whole inventory rather than a sample, so either the table
   was wrong or the field should not be there. It should not: nothing reads it,
   and a label's length is more identifying per byte than a payload's, because an
   address or a name is short and its length narrows a guess at a person.

4. **`padding` and `retention` were both in the config's known-key list and
   never parsed.** `padding: { to_multiple: 16 }` was accepted and silently
   meant *off*; `retention: 30d` was accepted and silently meant *keep forever*.
   An operator could believe their volume was obscured, or their data expiring,
   while nothing happened. Second and third instances of the shape after the
   verifier's `--vkey`, which was accepted and ignored because the flag is
   `--key`.

5. **`leafDigest(salt, record)` takes the salt first**, and the disclosure
   builder called it the other way round. Caught by reading the signature rather
   than by a test, because the test would have reported a leaf mismatch — a
   finding about the record rather than about the call.

6. **The spec-only verifier found two gaps in the spec**, which is exactly what
   it is for. A `vkey`'s third part carries an algorithm byte before the public
   key; and base64 contains `+`, so an identity must be split at the first two
   separators and never with `split('+')`, which shards the key material for
   roughly one key in four and fails intermittently in a way that looks like
   anything but a parsing bug. The project had learned the second one already —
   `parseVkey`'s comment says "one key in four" — and the document did not say
   it, so the independent implementation walked straight into it.

7. **A test's complexity bound was wrong in the direction of failing the
   improvement it measured.** The one-pass construction performs at most *n*
   merges in total, not *n log n*; the first bound overestimated by a factor of
   twelve and the assertion failed against a function that was five times
   faster.
