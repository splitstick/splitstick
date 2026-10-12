# M5 failure-mode inventory

Written **before** the code, as M1's through M4's were. Each row is a test; rows
marked **adv** are written before the happy path. The **risk** column names the
shape from [the risk assessment](risk-assessment.md), and **bdy** names the
trust boundary the row guards.

M5 is the milestone where evidence **leaves the operator**. Everything before it
was about what a log can establish to someone holding the whole store; a
disclosure pack goes to a counterparty who holds one event and must be able to
verify it without being shown anything else. So M5's boundary fails in two
directions at once, and the rows below are deliberately split between them:

- **Too much crosses** — a disclosure reveals a sibling's content, a salt it
  should not carry, or an action count it should not imply. This is a privacy
  failure and it is permanent: you cannot un-disclose.
- **Too little crosses** — a proof is refused, or verified against something
  weaker than it should be, so an honest operator cannot prove a true thing.
  A disclosure that proves nothing is a disclosure nobody can rely on.

And erasure is the same boundary read backwards: after a deletion request, what
**remains** must be exactly the enumerated permanent set, and the chain must
still verify. Too much remaining is a privacy failure; too little and the
evidence is destroyed.

## The disclosure pack — FR-32, FR-33, PRIV-06

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 1 | a single event is disclosed | the recipient verifies that one event against a countersigned root, holding nothing else | 2 | out | |
| 2 | the pack carries a salt for a record it does not disclose | refused at build. One disclosed record, one salt — a second salt is a second record's content made recomputable | 2 | out | ✓ |
| 3 | a recipient tries to recompute a sibling leaf from the pack | impossible: the audit path carries node digests, never sibling leaves, and a leaf without its salt is not recomputable | 2 | out | ✓ |
| 4 | the proof is offered against a root nothing countersigned | REFUSED, not reported as weaker. FR-33 is the whole difference between a proof and a claim: a bare local digest is the operator's own word | 1 | out | ✓ |
| 5 | the root is countersigned but by nobody the recipient accepts | reported as present-and-unverified, never as verified. Presence is not proof — twice now | 2 | in | ✓ |
| 6 | a pack is built for a record_seq that does not exist | refused with the range the store actually holds | 1 | out | ✓ |
| 7 | a pack is built for a SHREDDED record | the inclusion proof still verifies and the content is absent, stated as such. Shredding must not make a record undisclosable, or erasure becomes a way to make history unprovable | 7 | out | ✓ |
| 8 | the pack claims to cover more than it holds | `complete: false` is set by construction for a selective disclosure, and a test asserts no pack can claim completeness it does not have | 2 | out | ✓ |
| 9 | the recipient has only the pack and no network | verification completes. If it needs the network the design has failed | — | out | ✓ |
| 10 | the disclosed record's leaf does not match its salt and content | refused at build, before anything is handed over | 1 | out | ✓ |

## Padding — FR-34, FR-69

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 11 | padding is requested at batch close | dummy leaves are appended as `padding` records, each with its own `record_seq` and a random nonce, so `record_seq` still equals `tree_size` | 4 | — | |
| 12 | padding is applied RETROACTIVELY to a closed batch | refused. A leaf already committed cannot be reinterpreted, and the attempt must fail at the leaf check rather than be silently accepted | 1 | in | ✓ |
| 13 | a real action is relabelled as padding | fails the leaf check: its leaf is already committed over the real record's bytes | 1 | in | ✓ |
| 14 | a verifier reads a padded log | real and padding records are counted SEPARATELY and reported separately. One number would let padding inflate an apparent action count | 2 | out | ✓ |
| 15 | two padding records are written | their leaves differ, because each nonce is random. Identical padding leaves would be a recognisable pattern and so no padding at all | 1 | — | ✓ |
| 16 | padding is disabled | nothing changes about correctness; the volume leak is simply not blunted, and the report says the cadence leak remains | — | out | |

## Erasure — FR-36, FR-37, PRIV-03, PRIV-04, PRIV-05, PRIV-09

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 17 | content and its key are deleted | the chain still verifies, and the commitment is permanently unlinkable | 7 | in | |
| 18 | a shredded record is verified | `inconclusive` for that record's content, never `fail`. Erasure is a lawful act, not tampering, and reporting it as tampering would make compliance look like an attack | 7 | in | ✓ |
| 19 | the residue is scanned after shredding | it matches the enumerated permanent set EXACTLY, field for field, across every record kind including padding | 2 | in | ✓ |
| 20 | a new field is added to the version-1 schema | the residue scan FAILS rather than passing silently. The permanent set is derived from the schema, so a field nobody classified is a field nobody decided about | 5 | in | ✓ |
| 21 | an erasable field is left behind by the shredder | the scan names it. PRIV-05's claim is the enumerated set and nothing broader | 2 | in | ✓ |
| 22 | retention is configured at the storage layer | honoured there, with the cryptography untouched — the two are independent by FR-37 | 4 | — | |
| 23 | retention is set to something unparseable | refused at config load | 1 | in | ✓ |
| 24 | the operator deletes a leaf salt but not the content | the leaf is unverifiable and reported inconclusive; the content is still there and still disclosable by digest | 7 | in | ✓ |

## Verification as a closed system — NFR-04, NFR-05, NFR-06

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 25 | verification runs with networking disabled | it completes. Asserted by a test that makes any network call throw, not by inspection | 3 | in | ✓ |
| 26 | verification runs with an empty environment | it completes: no account, no token, no credential | — | in | ✓ |
| 27 | a 100,000-event run is verified | under two seconds on the documented reference machine, measured rather than asserted | — | — | |
| 28 | the verifier is handed a pack from a future format version | refused with the version it cannot read, never partially verified | 1 | in | ✓ |

## The published format — INT-03, PRIV-07, PRIV-08

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 29 | a third party implements from the spec alone | a reference pack validates. The spec is the guarantee; our verifier agreeing with itself proves nothing | 3 | out | ✓ |
| 30 | the spec and the emitted pack disagree | a test fails. A published format nothing checks is a format that drifts | 3 | out | ✓ |
| 31 | a run contains heartbeats | tree size exceeds the action count, and a test asserts it — so the tree-size leak cannot be described as an action count | 2 | out | ✓ |
| 32 | the pack format version changes | it is versioned under DES-16 and the old version is still readable or explicitly refused, never silently misread | 1 | in | ✓ |
