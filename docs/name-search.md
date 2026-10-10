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

## "Splitstick" — searched 10 October 2026: clear

Same method, same caveats. **Result: passes the knockout.**

### No conflicting mark found in software

No trademark registration found for `Splitstick` or `Split Stick` as a brand, in software or
otherwise. The existing uses are all in unrelated classes and all descriptive within their own
field, which makes them weak marks and unlikely to reach software:

| Existing use | Field | Class |
|---|---|---|
| Wolverine Snow Products "Split Sticks" — collapsible splitboard poles | sporting goods | ~28 |
| Rhino "Split" stick — a beeswax skin balm | cosmetics | ~3 |
| Generic woodworking and logging usage | — | — |

Nothing in class 9 (software) or class 42 (SaaS).

### Namespaces are free

| Namespace | Status |
|---|---|
| npm `splitstick`, `split-stick`, `@splitstick/*` | **free** — zero search hits |
| PyPI `splitstick`, `split-stick` | **free** |
| `github.com/splitstick`, `/split-stick`, `/splitstickhq` | **free** |
| `splitstick.dev`, `splitstick.io` | no nameservers — likely unregistered |
| `splitstick.org` | **registered** (parked at Namecheap) |
| `splitstick.com` | **inconclusive** — the query timed out here; check at a registrar |

One dormant repository exists at `benvoemel-a11y/SplitStick`: zero stars, no description, no
bearing on an organisation name.

### It is a stronger mark than "Tally" on the merits

Descriptiveness is judged against the goods and services. "Tally" describes what an audit tool
does. **"Splitstick" describes nothing about software** — it is arbitrary in class 9, which is
the category of mark that registers most easily and enforces best. It only becomes descriptive
if you start selling actual split sticks.

It also carries the explanation: the tally stick was split so that neither half alone was the
evidence. That is the architecture in one word.

### Before relying on it

1. Confirm `.com` and `.dev` availability at a registrar — the DNS check here was inconclusive.
2. Claim the free things now: npm scope `@splitstick`, the GitHub organisation, one domain.
3. File in classes 9 and 42 when there is budget. Deferred, not abandoned.

**Verdict: adopt it.** No conflict found in the relevant classes, every namespace that matters
is free, and it is a materially stronger mark than the name it replaces.

## Next step

Choose a name, repeat this search against it, and record the result here before the first
public commit. Registration itself stays deferred to a funded release.
