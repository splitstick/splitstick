// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The bounty programme, as checks — GOV-10 to GOV-14, GOV-17, GOV-18,
 * SEC-19 to SEC-21, DOC-08.
 *
 * Eleven requirements that are documents. The test for a document is whether a
 * specific commitment is in a specific place, and — where the document makes a
 * promise about something mechanical — whether the mechanism agrees with it.
 * That is the shape tools/lint-practice-statement.mjs already proved out for
 * the Witness Practice Statement.
 *
 * Three of these are mechanical rather than textual, and they are the ones
 * worth having:
 *
 *   GOV-11  the shipped default an attack must survive is PINNED by digest, so
 *           "the default" is not a moving target. The digest in the terms must
 *           match the file, or a report in flight is being judged against a
 *           configuration that changed under it.
 *   GOV-17  no figure is advertised as available. A currency amount anywhere
 *           in the terms fails, because the one thing this programme must not
 *           do is imply money it does not hold.
 *   GOV-18  the contribution path is NOT referenced by a release gate. The
 *           natural drift is for a good contribution path to become something
 *           somebody has to satisfy, and blocking a release on other people's
 *           volunteer work is a gate we do not control and they did not agree
 *           to.
 */

import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const read = (/** @type {string} */ rel) => readFileSync(join(ROOT, rel), 'utf8');

/** @type {string[]} */
const findings = [];

// ── the terms exist, and are published alongside the offer (DOC-08) ───────
for (const rel of ['docs/bounty.md', 'SECURITY.md']) {
  if (!existsSync(join(ROOT, rel))) {
    findings.push(`${rel} is missing. DOC-08: the full terms are published ALONGSIDE the offer, `
      + 'not after the first report');
  }
}
if (findings.length > 0) {
  console.error('\nBOUNTY LINT FAILED\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  process.exit(1);
}

const terms = read('docs/bounty.md');
const security = read('SECURITY.md');

/** Each requirement, and the commitment that must be in the terms. */
const REQUIRED = [
  ['GOV-10', /one class, one payout/i, 'the unit is a tamper class, not an instance'],
  ['GOV-11', /pinned/i, 'the attack must survive the shipped default, and the default is pinned'],
  ['GOV-12', /binds? the programme in \*\*both\*\* directions|binding in both directions/i,
    'the threat model binds both ways; exclusions are not added after a report'],
  ['GOV-13', /recognition, not cash/i, 'recognition is non-cash while the project is unfunded'],
  ['GOV-14', /first \*\*complete\*\* report|first reporter wins/i, 'the first complete report wins'],
  ['GOV-14', /timestamps? (?:are )?retained|receipt timestamps/i,
    'receipt timestamps are retained, so the order is a fact rather than a recollection'],
  ['GOV-17', /only if the project is funded/i, 'a cash award opens only if the project is funded'],
  ['GOV-18', /not a launch gate/i, 'the contribution path is a goal, explicitly not a gate'],
  ['SEC-19', /## Intake and triage/i, 'an intake, triage and disclosure process is documented'],
  ['SEC-19', /Exercised before launch/i, 'and exercised once before launch, not merely written'],
  ['SEC-20', /90 days.{0,40}or on fix|on fix, whichever is sooner/i, 'the 90-day window'],
  ['SEC-21', /even unmitigated|including when we have no mitigation|no mitigation/i,
    'findings are published even with no mitigation'],
  ['LEG-16', /Nothing here is legal advice|not legal advice/i,
    'a not-legal-advice disclaimer where statutes are cited'],
];

for (const [id, pattern, what] of REQUIRED) {
  if (!(/** @type {RegExp} */ (pattern)).test(terms)) {
    findings.push(`docs/bounty.md does not state ${what} (${id})`);
  }
}

// SECURITY.md is where a reporter actually arrives.
for (const [id, pattern, what] of /** @type {const} */ ([
  ['SEC-20', /90 days/i, 'the disclosure window'],
  ['SEC-21', /no mitigation/i, 'that findings are published unmitigated'],
  ['GOV-13', /[Rr]ecognition, not cash/, 'that recognition is non-cash'],
])) {
  if (!pattern.test(security)) findings.push(`SECURITY.md does not state ${what} (${id})`);
}

// ── GOV-11: the pin matches the file ─────────────────────────────────────
const pinned = /sha256:([0-9a-f]{64})/.exec(terms);
if (pinned === null) {
  findings.push('docs/bounty.md pins no digest for the shipped default. GOV-11 is only '
    + 'meaningful if "the default" is not a moving target');
} else {
  const actual = createHash('sha256').update(readFileSync(join(ROOT, 'design/default-config.yaml')))
    .digest('hex');
  if (actual !== pinned[1]) {
    findings.push(`the shipped default has changed and the pin has not: design/default-config.yaml `
      + `is sha256:${actual} and the terms pin sha256:${pinned[1]}. A report in flight is being `
      + 'judged against a configuration that moved under it. Update the pin deliberately, and '
      + 'remember that reports already received are judged against the digest current when they '
      + 'arrived');
  }
}

// ── GOV-17: no figure advertised as available ────────────────────────────
const MONEY = /(?:[$£€]\s?\d|\b\d+[\d,.]*\s*(?:USD|EUR|GBP|dollars?|euros?|pounds?)\b|\bup to \$)/i;
if (MONEY.test(terms) || MONEY.test(security)) {
  findings.push('a currency amount appears in the bounty terms. GOV-17: state that a cash award '
    + 'opens only if the project is funded, and advertise no figure as available — the one thing '
    + 'this programme must not do is imply money it does not hold');
}

// ── GOV-18: no release gate references the contribution path ─────────────
for (const rel of ['.github/workflows/ci.yml', '.github/workflows/release.yml']) {
  if (!existsSync(join(ROOT, rel))) continue;
  const wf = read(rel);
  if (/contributed attack class|GOV-18|redteam\/contrib/i.test(wf)) {
    findings.push(`${rel} references the contributed-attack-class path. GOV-18 is explicitly a `
      + 'goal and NOT a launch gate: a release must not block on other people\'s volunteer work');
  }
}

if (findings.length > 0) {
  console.error('\nBOUNTY LINT FAILED — GOV-10..18, SEC-19..21, DOC-08\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log('\n  bounty: terms published alongside the offer, the shipped default pinned by');
console.log('          digest, no figure advertised, and no release gate depends on the');
console.log('          contribution path (GOV-10..18, SEC-19..21, DOC-08)\n');
