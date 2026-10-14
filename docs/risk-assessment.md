# Assessing security and correctness risk while writing code

**Applies to:** every change from M4 onward · **Derived from:** the 16 defects
found by review in M3a and M3b, plus M1's and M2's

Code review asks *is this code good*. This asks two different questions, and
they are the ones that have actually caught things in this project:

- **Correctness risk** — under what input or sequence does this produce a wrong
  answer rather than an error?
- **Security risk** — what does this let a dishonest operator claim that the
  evidence does not support?

The second is the one that matters here, because **the operator is the
adversary**. A bug that crashes is a bug; a bug that makes the log look more
complete than it is, is the product failing at its only job.

## The seven shapes, each from a real defect

Before writing a unit, ask which of these it could be. Every finding in this
project so far has been one of them.

### 1. A bad value coerced or skipped instead of refused

The single most common shape. `tree_size: "20"` silently skipped; `since`
unparseable so the age became `NaN` and every ceiling comparison went false;
`2026-13-45T99:99:99.999Z` accepted because the regex matched; `Date.parse`
rolling `2026-02-30` to March 2nd and reporting it finite.

**Ask:** for each field read from disk or from a counterparty, what happens if
it is the wrong type, out of range, or absent? If the answer is anything other
than *refuse and say so*, that is the defect.

### 2. An assurance composed to say more than the evidence supports

Four defects in one 200-line command: it deleted the history it was recording;
it could not perform the step it documented; it read issuer *presence* as
proof; and it read one subject's evidence as another's.

**Ask:** what exactly does this output assert, and is every word of it
established by something checked? Prefer deriving the verdict from the
verifier over computing it locally — a second implementation of a check is a
second thing that can be wrong, and it will be the one that is wrong.

### 3. A check that reads its own documentation as code

Four separate instruments made this; `tools/code-text.mjs` exists because of
it. A comment saying "this verifier does not fetch" failed the no-fetch scan.

**Ask:** does this check scan text that includes prose? Use `code()` or
`codeOnly()`.

### 4. State checked against the wrong thing

Memory instead of disk (the queue persisted `[2,3,3]` while holding `[1,2,3]`).
The written records instead of what is accounted for (a duplicate gap
declaration accepted twice). The set's height instead of the issuer's own (a
returning witness asked to extend a tree it never signed).

**Ask:** this comparison — are both sides the same kind of thing, measured from
the same place, about the same subject?

### 5. A seam exercised once looks like a seam that works

The Anchorer never computed a consistency proof, so a stateful witness refused
everything after the first submission; the only test that wired them together
anchored exactly one checkpoint. The FR-58 reserve could never have fired in
production.

**Ask:** does any test drive this path twice, and in the state it is in after
the first time?

### 6. A test asserting only refusals is not a test of the function

`endorse()` had a dead indirection that threw on its happy path. Every test
asserted a rejection, so every test passed.

**Ask:** does something assert the success path end to end, and check the value
it produced rather than that it did not throw?

### 7. Fail-open and fail-closed, inverted

SCOPE-16 says fail-open, never fail-closed. But a counter behind the records was
treated as damage and refused to open the store — fail-closed where the state
was ordinary. And two roots at one height must fail closed.

**Ask:** is this an availability decision or an integrity decision? Availability
fails open and reports; integrity fails closed and refuses.

## Trust boundaries, and the two directions a boundary fails

A trust boundary is any point where data changes hands or changes status: a
pack handed to a counterparty, a countersignature arriving from a witness, a
file read back from disk after a restart, a digest crossing from "present" to
"established". Every finding in sections 1, 2 and 4 above sits on one.

**Name the boundary before writing the code that crosses it**, and for each,
answer both questions — because a boundary fails in two opposite directions and
the second one is the one that gets missed:

| | Too much crosses | Too little crosses |
|---|---|---|
| **Outbound** (a pack, a report) | a disclosure reveals a sibling's content; a report asserts more than the evidence supports | a report discards valid evidence and reports the operator as worse than they are |
| **Inbound** (a proof, a file, a flag) | an unverified proof is counted as verified; a damaged field is coerced into a usable one | a valid proof is refused because it arrived on a later checkpoint than expected |

The PR #9 review found exactly one of each, in the same function: a
countersignature's *presence* counted as anchoring (too much crossing inbound),
and a validly witnessed later checkpoint ignored (too little crossing). Both had
passed a self-review that was explicitly looking for the first kind.

**FIXING A BOUNDARY CHECK MOVES THE BOUNDARY.** Learned twice in one day, on
one function. The disclosure pack's payload was unverifiable, so the content
salt was added and the bytes checked against the cid — which made a new question
reachable: *where does the cid come from?* It came from the unauthenticated part
of the pack, so replacing bytes, salt and cid together passed. Each fix moved
the trust boundary one step inward and left the next step unexamined.

So after adding a check at a boundary, ask the same question of its inputs:
**what authenticates the thing I just compared against?** Keep asking until the
answer is something a signature covers. In that case the answer was the record,
whose leaf is bound to a countersigned root; everything between the bytes and
that root had to be checked, not just the first hop.

**Three rules that follow:**

1. **Status changes are earned, never assumed.** `present` → `verified`,
   `claimed` → `established`, `declared` → `attested`. Each arrow needs a
   check, and the check belongs to whichever module already owns it. If
   deriving the answer means importing the verifier, import the verifier —
   that is what M4 ended up doing, after writing a second one.
2. **A boundary's own direction is data.** What a pack *omits* is part of its
   contract (`complete: false`), and a recipient must be able to tell a
   deliberate omission from a missing piece.
3. **The spec is the boundary, not the implementation.** Where a third party
   writes against a format (INT-03), the format is what must be correct; our
   verifier agreeing with itself proves nothing.

## M4 carries one risk the earlier milestones did not

M4's requirements demand tests that assert the system does **not** signal
something: SEC-11 (a forged build digest is not flagged), FR-64 (a path
bypassing the collector produces no signal), FR-25 (no claim of patch detection
appears in output).

**A test asserting the absence of a signal passes trivially when the signal was
never possible.** A test that proves "a bypassing path is not detected" also
passes against a collector with no attestation at all, against an empty
function, and against a typo in the fixture.

**So every non-detection test must prove the mechanism is live in the same
test.** Assert that the declared change DOES produce the record, and the
undeclared one does not, in one test over one store. Otherwise it is shape 5
wearing a different hat: a seam asserted to be silent that was never connected.

## And the limits must be in the output, not only the prose

DOC-10 requires the collector-patch limit stated wherever coverage is
described — including in the report itself. A limit documented in a design file
is a limit the person reading the report does not see. The report is the surface
an auditor acts on, so that is where it has to be, and a test has to assert it
is there.
