// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Every published figure names its benchmark and its evidence class —
 * TRC-04, DOC-04.
 *
 * TRC-04's verify is "release gate blocks on missing benchmark". DOC-04's is
 * "any unverified figure is labelled a target, not a measurement, until
 * benchmarked". Both are about the same table: the one in the release notes
 * where the project states what it is signing up to.
 *
 * WHY THIS GUARD EXISTS AT ALL. That table published **<1 ms at p99** as the
 * headline append figure. NFR-01's budget is p95 under 1 ms and p99 under
 * 3 ms; p99 under 1 ms is the STRETCH target the requirement names. M1
 * measured, revised the budget, and the table kept the number the project had
 * hoped for — as did `bench/append.mjs`'s own header comment, three lines
 * above code using the corrected values. Nothing was lying; a number simply
 * outlived the measurement that revised it, in two places, for several
 * milestones. That is what this check is for.
 *
 * It checks three things, and deliberately not a fourth:
 *
 *   1. every row of the figures table carries an evidence class
 *   2. a figure claimed as MEASURED names a benchmark path that EXISTS
 *   3. no requirement whose status is open is cited by a MEASURED row
 *
 * What it does not do is run the benchmarks or read their results. A guard
 * that tried would be asserting that a number is correct, which only a
 * qualifying run on the reference environment can do — and saying so is the
 * point of the TARGET label.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const NOTES = join(ROOT, 'docs/splitstick-1.0-release-notes.md');
const HEADING = '## Numbers we are signing up to';

/** The evidence classes a row may declare. */
const CLASSES = ['MEASURED', 'TARGET'];

/** @type {string[]} */
const findings = [];

const notes = readFileSync(NOTES, 'utf8');
const start = notes.indexOf(HEADING);
if (start === -1) {
  findings.push(`docs/splitstick-1.0-release-notes.md no longer has a "${HEADING}" section, so `
    + 'the figures TRC-04 gates on cannot be found. If the section moved, update this guard '
    + 'deliberately rather than letting it pass over nothing');
} else {
  const section = notes.slice(start, notes.indexOf('\n## ', start + 1));
  const rows = section.split('\n')
    .filter(l => /^\|/.test(l) && !/^\|\s*-+/.test(l))
    .filter(l => !/\bEvidence\b.*\bBenchmark\b/.test(l));

  if (rows.length === 0) {
    findings.push('the figures table has no rows, which is not a table of figures');
  }

  // Requirement statuses, so a MEASURED row cannot cite an open requirement.
  /** @type {Map<string, string>} */
  const status = new Map();
  for (const f of readdirSync(join(ROOT, 'requirements'))) {
    if (!/^part\d+\.json$/.test(f)) continue;
    const parsed = JSON.parse(readFileSync(join(ROOT, 'requirements', f), 'utf8'));
    const items = Array.isArray(parsed) ? parsed
      : (parsed.requirements ?? parsed.items
        ?? Object.values(parsed).flat().filter(x => x && typeof x === 'object'));
    for (const r of /** @type {any[]} */ (items)) {
      if (r?.id) status.set(r.id, r.status ?? 'open');
    }
  }

  for (const row of rows) {
    const cells = row.split('|').map(c => c.trim());
    const text = row.replace(/\s+/g, ' ');
    const declared = CLASSES.filter(c => row.includes(c));

    // A row that is explicitly not a measurement says so and is left alone.
    if (/\bn\/a\b|\bnot a measurement\b/.test(row)) continue;

    if (declared.length === 0) {
      findings.push(`a figure row carries no evidence class (${CLASSES.join(' or ')}): ${text.slice(0, 120)}`);
      continue;
    }
    if (declared.length > 1) {
      findings.push(`a figure row declares ${declared.join(' and ')} at once: ${text.slice(0, 120)}`);
      continue;
    }

    // Benchmarks named in the row, as paths.
    const paths = [...row.matchAll(/`([a-z0-9_./-]+\.(?:mjs|json))`/gi)].map(m => String(m[1]));

    if (declared[0] === 'MEASURED') {
      if (paths.length === 0) {
        findings.push('a MEASURED figure names no benchmark. TRC-04: no performance figure is '
          + `published as fact until its benchmark exists and passes — ${text.slice(0, 120)}`);
      }
      for (const rel of paths) {
        if (!existsSync(join(ROOT, rel))) {
          findings.push(`a MEASURED figure cites ${rel}, which does not exist`);
        }
      }
      for (const id of [...row.matchAll(/\b([A-Z]{3,5}-\d{2})\b/g)].map(m => String(m[1]))) {
        if (status.get(id) === 'open') {
          findings.push(`a figure is published as MEASURED while ${id} is still open. M7's exit `
            + 'says plainly that neither NFR-01 nor NFR-02 may be reported as met on a '
            + `development-machine number — ${text.slice(0, 110)}`);
        }
      }
    } else if (paths.length === 0 && !/—\s*\|?\s*$/.test(row)) {
      // A TARGET still names the benchmark that would settle it; otherwise
      // nobody knows what would.
      findings.push('a TARGET figure names no benchmark, so nothing says what would settle it: '
        + text.slice(0, 120));
    }
    void cells;
  }
}

if (findings.length > 0) {
  console.error('\nFIGURES LINT FAILED — TRC-04, DOC-04\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log('\n  figures: every published figure carries an evidence class and names its');
console.log('           benchmark; no MEASURED figure cites an open requirement (TRC-04, DOC-04)\n');
