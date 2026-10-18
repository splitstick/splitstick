# Brand

Two assets, both SVG, both monochrome where they can be.

| File | What it is |
|------|------------|
| `mark.svg` | The mark, 64×64 viewBox, `currentColor`. Legible at 32px. |
| `social.svg` | The social preview, 1280×640. |
| `social.png` | `social.svg` rasterised, which is the format GitHub accepts. |

## The mark

A tally stick split lengthwise. Two halves, three pairs of notches, the notches
meeting across the split — one party holds each half and neither half means
anything alone. That is the mechanism the project is named after
(`docs/name-search.md`), so the mark is the mechanism rather than a metaphor
about it: no shields, no locks, no chains.

It is drawn in `currentColor` so it inherits whatever it is placed on. Three
earlier drafts are not here and the reasons are worth keeping: eight even
blocks read as a spreadsheet, notches cut into the outer edges read as square
brackets, and rounded corners turned the halves into six pills.

## Regenerating `social.png`

GitHub's social preview field takes PNG or JPG, not SVG, so the PNG is
committed alongside its source. It is rendered by a browser engine because the
card is set in the system UI font and a rasteriser without that font produces a
different image:

```sh
{ printf '<style>html,body{margin:0;padding:0;background:#0d1117}svg{display:block}</style>\n'; cat brand/social.svg; } > /tmp/social.html
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1280,640 --screenshot=brand/social.png file:///tmp/social.html
```

On Linux the same command with `chromium --headless=new`. Do not use
`qlmanage`: it renders into a square thumbnail and scales the viewBox to it, so
the card comes out enlarged and clipped on the right.

There is no check that the PNG matches the SVG. A byte comparison would depend
on the renderer's font version and would fail on a machine that is not wrong,
so it is not written — regenerate the PNG whenever the SVG changes.

## The words on the card are audited

The three lines of text are claims, and a claim set in 88px type reaches more
readers than any document here. `brand/*.svg` is therefore a claim surface:
every scope guard in `tools/scope-guards.mjs` reads it, as do the SEC-17 and
LEG-12 rules in `tools/lint-claims.mjs`. Markup and authoring comments are
stripped first; `aria-label` is read, because it is what a screen-reader user
is given. `test/scope-guards.test.mjs` breaks it on purpose.

## Repository metadata

GitHub's description and topics are set in the repository settings, which no
lint in this tree can reach. They are claims all the same — the description is
the line that appears under the repository name in search results — so the
exact text is kept here, where the claims audit reads it, and pasted from here
rather than composed in the settings box.

**Description** (one line):

> A tamper-evident record of what AI agents actually did — including the actions that aren't there. Hash-chained, signed, independently countersigned, verifiable offline by anyone holding the bytes and a public key.

**Topics**:

```
tamper-evident  transparency-log  merkle-tree  rfc6962  rfc8785
rfc3161  checkpoint  witness  cosignature  ed25519
timestamping  audit-trail  provenance  ai-agents  agent-accountability
```

Three topics were considered and dropped, and the reasons are the same ones the
scope guards encode:

| Dropped | Why |
|---------|-----|
| `eu-ai-act` | LEG-14: no surface claims EU AI Act conformity. A topic is a surface, and a regulation's name sitting beside a product name is read as a claim about it whether or not a sentence makes one. Conformity is assessed by a body. |
| `append-only` | SCOPE-02: the data structure is append-only; the operator's disk is not. A topic cannot carry the precondition, and the premise of this project is that storage is the thing you cannot trust. |
| `non-repudiation` | It names a legal conclusion this release does not reach. The records are tamper-evident, and what follows from that is for a court and not for a keyword. |

*The regulation is named above only to explain a topic that is not used. Nothing
here is a statement about what any statute requires, and it is not legal advice.*
