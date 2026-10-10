# Name knockout search

Record for `LEG-18`. Run 10 October 2026. A free knockout search, not a legal opinion —
no attorney involved, no register searched exhaustively.

## Result: "Tally" should not be used

### Registered marks in the same field

**Tally Solutions Pvt. Ltd.** (Bangalore, founded 1986) holds `Tally`, `Tally9`,
`Tally.ERP 9`, `Tally.NET`, `Tally.Server9` and `TallyPrime` as registered or claimed
trademarks for accounting and ERP **software**. That is the same broad field as this project —
software sold to businesses — and the company is long established with products in many
markets.

**Tally.so** is a widely used form-builder SaaS operating under the same word.

### Namespaces already taken

| Namespace | Status |
|---|---|
| npm `tally` | **taken** |
| npm `@tally` scope | free (0 packages) but the bare name is not |
| `github.com/tally` | **taken** |
| `github.com/tallyhq` | **taken** |
| `github.com/tally-dev` | **taken** |

### It is also a weak mark on its own terms

Setting the conflicts aside, "tally" is an ordinary English word and directly descriptive of
what the product does — tallying, keeping count. Descriptive marks are harder to register,
easier to oppose and weaker to enforce. The metaphor that makes the name a good *explanation*
is exactly what makes it a poor *trademark*.

## Recommendation

Rename before anything is published. At the time of writing that is nine commits in a private
repository: a directory move, a find-and-replace, and a GitHub rename. After a public launch it
costs the audience instead.

The tally-stick metaphor is worth keeping in the documentation — it explains the two-party
design in one sentence. It does not have to be the name.

## What a stronger name looks like

Coined or arbitrary words make the strongest marks; descriptive ones the weakest. Candidates
drawn from the same world, each of which needs its own search before use:

- **Splitstick** — the mechanism in one word. A distinctive compound, unlikely to collide.
- **Chirograph** — a medieval document written twice on one sheet, then cut apart along an
  indented line so the halves had to match to prove authenticity. Historically exact for a
  two-party tamper-evident record. Distinctive and obscure, therefore strong; long to type.
- **Stockfoil** — the two halves of a tally stick were the *stock* (creditor's half, the origin
  of "stockholder") and the *foil*. A coined compound, very strong as a mark, needs explaining.
- A pure coinage with no dictionary meaning at all is stronger than any of the above.

Selection criteria, in order: no conflicting mark in software classes; free on npm, GitHub and
as a domain; not descriptive of logging or auditing; short and pronounceable.

## Next step

Choose a name, repeat this search against it, and record the result here before the first
public commit. Registration itself stays deferred to a funded release.
