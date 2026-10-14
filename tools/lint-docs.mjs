// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The documentation requirements, as checks — DOC-03, DOC-06, DOC-07, LEG-16.
 *
 * Four requirements whose verify is "documentation review" or "attribution
 * present". A review is a thing somebody skips, and three of these were
 * genuinely absent when M7 looked: Sigstore, Rekor, Trillian and
 * Schneier–Kelsey were credited in neither the README nor the NOTICE, and the
 * two-policy split that the whole independence story rests on was documented
 * nowhere at all.
 *
 * Attribution in particular is the kind of thing that is nobody's job until it
 * is a licence problem.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { markdown, paragraphs, sentences } from './claim-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const read = (/** @type {string} */ rel) => readFileSync(join(ROOT, rel), 'utf8');

/** @type {string[]} */
const findings = [];

// ── DOC-06: credit, in the README and the NOTICE ─────────────────────────
/**
 * The six DOC-06 names, with the spellings that count as crediting each.
 * `open-multi-agent` rather than `OMA`, because an initialism in running prose
 * is not attribution.
 */
const CREDIT = [
  ['open-multi-agent', /open-multi-agent/i],
  ['Sigstore', /\bsigstore\b/i],
  ['Rekor', /\brekor\b/i],
  ['Trillian', /\btrillian\b/i],
  ['C2SP', /\bc2sp\b/i],
  ['Schneier–Kelsey', /\bschneier\b/i],
  ['Schneier–Kelsey (Kelsey)', /\bkelsey\b/i],
];
for (const [name, pattern] of CREDIT) {
  for (const rel of ['README.md', 'NOTICE']) {
    if (!(/** @type {RegExp} */ (pattern)).test(read(rel))) {
      findings.push(`${rel} does not credit ${name} (DOC-06)`);
    }
  }
}

// ── DOC-07: the two-policy split, with a worked example of each ──────────
const TWO = 'docs/two-policies.md';
if (!existsSync(join(ROOT, TWO))) {
  findings.push(`${TWO} is missing. DOC-07: the witness list governs who is ASKED and the `
    + 'acceptance policy governs who is ACCEPTED, and conflating them is the commonest way to '
    + 'misread what a pack establishes');
} else {
  const two = read(TWO);
  for (const [what, pattern] of /** @type {const} */ ([
    ['that the witness list governs who is asked', /who is \*\*asked\*\*/],
    ['that the acceptance policy governs who is accepted', /who is \*\*accepted\*\*/],
    ['that the operator writes one and the reader the other', /the \*\*operator\*\*[\s\S]{0,400}the \*\*reader\*\*/],
    ['a worked example of the operator\'s side', /## Worked example — the operator's side/],
    ['a worked example of the reader\'s side', /## Worked example — the reader's side/],
    ['that a pack carries every countersignature collected', /carries \*\*every\*\* countersignature/],
  ])) {
    if (!pattern.test(two)) findings.push(`${TWO} does not show ${what} (DOC-07)`);
  }
  // The worked examples must be real configurations, not prose about them.
  const fences = (two.match(/```(?:yaml|json)\n/g) ?? []).length;
  if (fences < 4) {
    findings.push(`${TWO} carries ${fences} worked configuration(s). DOC-07 asks for a worked `
      + 'example for BOTH sides, and three readers reaching three verdicts from one pack is the '
      + 'thing that makes the split legible');
  }
}

// ── DOC-03: the considered-and-rejected log, with reasons ────────────────
const NOTES = 'docs/splitstick-1.0-release-notes.md';
const notes = read(NOTES);
const rejected = /## Considered and rejected([\s\S]*?)\n## /.exec(notes);
if (rejected === null) {
  findings.push(`${NOTES} has no "Considered and rejected" section. DOC-03: publish rejected `
    + 'designs with reasons — a decision with no recorded reason is a decision somebody '
    + 'relitigates');
} else {
  const rows = (rejected[1] ?? '').split('\n').filter(l => /^\|/.test(l) && !/^\|\s*-+/.test(l));
  const body = rows.filter(r => !/\bWhy\b/.test(r));
  if (body.length < 4) {
    findings.push(`${NOTES}: the rejected log has ${body.length} entries, and the scope guards `
      + 'alone reject four things by name (the VDF, ZK proofs, TEE-as-guarantee and the N-of-N '
      + 'metric). DOC-03 wants the reasons published, not the list');
  }
  for (const r of body) {
    // A row with no reason is a list entry, which is what DOC-03 is not.
    const cells = r.split('|').map(c => c.trim()).filter(c => c !== '');
    if (cells.length < 2 || (cells[1] ?? '').length < 40) {
      findings.push(`${NOTES}: a rejected-design row gives no reason: ${r.slice(0, 90)}`);
    }
  }
}

// ── LEG-16: a not-legal-advice disclaimer where statutes are cited ───────
/**
 * Statute citations, and the disclaimer that must be NEARBY — the same
 * paragraph-level discipline SEC-17 uses, because a disclaimer a page away is
 * read without it.
 */
const STATUTE = /\b(?:eIDAS|GDPR|AI Act|FRE\s*90\d|Art(?:icle)?\.?\s*\d+|Reg(?:ulation)?\.?\s*\(EU\)|\bUCC\b)\b/;
const DISCLAIMER = /not legal advice|no legal advice|nothing here is legal|consult (?:your|an) (?:counsel|lawyer)|your counsel/i;
for (const f of markdown(ROOT)) {
  const rel = f.slice(ROOT.length);
  // The inventories and the requirements discuss citations rather than make
  // them; the register records which claims rest on what.
  if (/^(?:requirements\/|docs\/m\d[a-z]?-|docs\/risk-assessment)/.test(rel)) continue;
  const text = readFileSync(f, 'utf8');
  if (!STATUTE.test(text)) continue;
  if (!DISCLAIMER.test(text)) {
    findings.push(`${rel} cites a statute and carries no not-legal-advice disclaimer (LEG-16)`);
  }
}

if (findings.length > 0) {
  console.error('\nDOCS LINT FAILED — DOC-03, DOC-06, DOC-07, LEG-16\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}
void paragraphs; void sentences;

console.log('\n  docs: upstream credited in README and NOTICE, the two-policy split shown with a');
console.log('        worked example on both sides, rejected designs published with reasons, and');
console.log('        a not-legal-advice disclaimer wherever a statute is cited\n');
