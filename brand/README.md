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
