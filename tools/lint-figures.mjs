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
 * It checks five things:
 *
 *   1. every row of the figures table carries an evidence class
 *   2. a figure claimed as MEASURED names a benchmark path that EXISTS
 *   3. no requirement whose status is open is cited by a MEASURED row
 *   4. no row cites a requirement id this guard could not find at all —
 *      absent is not satisfied, and that is how the third check used to be
 *      evaded without anyone trying: ids outside the files it read returned
 *      undefined, which is not equal to 'open', so the row passed
 *   5. a MEASURED figure for a requirement whose acceptance rests on
 *      ATTRIBUTION rather than on a reference environment must cite the run's
 *      own result JSON, and that file must say it was an acceptance
 *      measurement, name its machine and storage, and meet the event and
 *      repeat counts the requirement asks for
 *
 * The fifth check is the companion to a deliberate relaxation. NFR-01's
 * "defined reference environment" clause was dropped, because no such host was
 * available and a requirement cannot be closed against evidence nobody can
 * produce. What replaced it is attribution: the conditions come WITH the
 * figure. A relaxation whose companion guard is optional is just a deletion,
 * so this check reads the evidence file rather than the prose around it — a
 * sentence can be written to sound attributed, a result file either carries the
 * host or does not.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const REPO = new URL('..', import.meta.url).pathname;

/**
 * Paths are injectable so this guard can be tested against fixtures. It had no
 * test at all while it was the only thing standing between an open requirement
 * and a MEASURED claim, and it is now also the companion to a deliberate
 * relaxation of NFR-01 — which makes "it has never been exercised" the wrong
 * state for it to be in.
 *
 * An unrecognised flag is refused rather than ignored: a misspelled flag on a
 * claims guard is a claims guard that did not run.
 * @param {string} name
 */
const flag = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
};
const KNOWN = new Set(['notes', 'requirements', 'root']);
for (const a of process.argv.slice(2).filter(x => x.startsWith('--'))) {
  if (!KNOWN.has(a.slice(2))) {
    console.error(`\n  ${a} is not a flag this reads. Refused rather than ignored: a misspelled `
      + 'flag on a claims guard would be a claims guard that did not run.\n');
    process.exit(2);
  }
}

/** Where benchmark result files and requirement files are resolved from. */
const ROOT = flag('root') ?? REPO;
const NOTES = flag('notes') ?? join(ROOT, 'docs/splitstick-1.0-release-notes.md');
const REQS = flag('requirements') ?? join(ROOT, 'requirements');
const HEADING = '## Numbers we are signing up to';

if (!existsSync(NOTES)) {
  console.error(`\n  ${NOTES} does not exist, so there are no figures to check. Refused rather `
    + 'than reported as clean: a guard that found no subject has not approved it.\n');
  process.exit(2);
}

/** The evidence classes a row may declare. */
const CLASSES = ['MEASURED', 'TARGET'];

/** @type {string[]} */
const findings = [];

const notes = readFileSync(NOTES, 'utf8');
const start = notes.indexOf(HEADING);
if (start === -1) {
  findings.push(`${NOTES} no longer has a "${HEADING}" section, so `
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
  //
  // backlog.json AND every partN.json, because there is no part1.json and this
  // loader used to read only the partN pattern. 47 requirements, FR-15 among
  // them, were invisible to it — and an invisible id returns undefined from the
  // map below, which is not equal to 'open', so a MEASURED row citing one
  // passed. tools/lint-release.mjs had the identical defect.
  /** @type {Map<string, string>} */
  const status = new Map();
  /** @param {any} parsed */
  const itemsOf = (parsed) => Array.isArray(parsed) ? parsed
    : (parsed.requirements ?? parsed.items
      ?? Object.values(parsed).flat().filter(x => x && typeof x === 'object'));
  for (const f of readdirSync(REQS)) {
    if (!/^(backlog|part\d+)\.json$/.test(f)) continue;
    for (const r of itemsOf(JSON.parse(readFileSync(join(REQS, f), 'utf8')))) {
      if (r?.id) status.set(r.id, r.status ?? 'open');
    }
  }
  const resolvedPath = join(REQS, 'backlog.resolved.json');
  /** @type {string[]} */
  let declaredIds = [];
  if (!existsSync(resolvedPath)) {
    // Generated and gitignored, so absent on a fresh clone. Announced rather
    // than skipped quietly: without it this guard cannot tell that it read
    // every requirement file, and cannot recognise an id whose whole family
    // went unread.
    console.error(`  note: ${resolvedPath} is absent, so this guard could not cross-check that `
      + 'it read every requirement file. Run `npm run requirements` first for that check.');
  }
  if (existsSync(resolvedPath)) {
    declaredIds = itemsOf(JSON.parse(readFileSync(resolvedPath, 'utf8')))
      .map((/** @type {any} */ r) => r?.id).filter(Boolean);
    const missed = declaredIds.filter((/** @type {string} */ id) => !status.has(id));
    if (missed.length > 0) {
      findings.push('this guard did not read ' + missed.join(', ') + ', which the resolved '
        + 'backlog declares. A status it cannot see reads as not-open, so it cannot be trusted '
        + 'to refuse a MEASURED row citing one');
    }
  }

  /**
   * Requirements whose acceptance rests on attribution rather than on a
   * reference environment, with what their evidence file must show. Each entry
   * is the price of the relaxation that let the requirement close.
   *
   * `budgets` is the part that was missing, and the omission was exactly the
   * failure this project keeps finding: the checks established that evidence
   * EXISTED and was QUALIFIED -- right kind, named machine, enough events and
   * repeats, disclosures present -- and never asked whether the number in it
   * passed. Evidence reporting `"worst": 45000` against a 30,000 ms budget with
   * `"within_budget": false` satisfied every check and let the figures table go
   * on calling NFR-04 MEASURED. Evidence being present is not evidence
   * establishing the claimed result.
   *
   * The limits live HERE rather than being read from the evidence. Comparing a
   * measurement against a budget the same file declares is not a check: a file
   * stating `"budget_ms": 999999` next to a 900-second measurement would pass.
   * So the limit is held by the guard, the evidence's own declared budget must
   * EQUAL it, and the harness's own pass/fail flag must agree with the
   * recomputation -- three statements that have to line up rather than one that
   * is taken on trust.
   *
   * NFR-01's p99 STRETCH target of 1 ms is deliberately not checked: the
   * requirement states that meeting p95 while missing the stretch is a pass
   * against the budget.
   */
  const ATTRIBUTED = {
    'NFR-01': {
      kind: 'acceptance measurement', events: 1_000_000, repeats: 3,
      budgets: [
        { label: 'p95 on the worst repeat', limit: 1, unit: 'ms',
          declaredAt: 'budget.p95_ms', measuredAt: 'arms.full.worst_p95_ms',
          verdictAt: 'verdict.p95', passes: 'within' },
        { label: 'p99 on the worst repeat', limit: 3, unit: 'ms',
          declaredAt: 'budget.p99_ms', measuredAt: 'arms.full.worst_p99_ms',
          verdictAt: 'verdict.p99', passes: 'within' },
      ],
    },
    // NFR-02's budget is a PERCENTAGE, so the limit is checked in percent and
    // the measured figure is the UPPER BOUND of the interval -- the requirement
    // is met only if the whole interval is below 2%, not if the point estimate
    // is. Its verdict field is the DIRECT one: the paired wall-clock difference
    // on the same runs reports UNRESOLVED, and checking that one would refuse
    // a requirement its own evidence establishes.
    'NFR-02': {
      kind: 'acceptance', events: 24, repeats: 1,
      // Storage is not a variable this benchmark's result depends on: it
      // measures time inside a journal wrapper, not file creation.
      attests: ['machine'],
      // bench/run-latency.mjs has no reference-environment gate, so it has no
      // shortfalls to disclose. Requiring the array would be requiring it to
      // publish an empty one, and an empty list claims "nothing was short" --
      // a statement about a check that was never run. The machine is still
      // required, because that is what attribution means.
      disclosures_required: false,
      budgets: [
        { label: 'added run latency, whole interval', limit: 2, unit: '%',
          declaredAt: 'budget_percent', measuredAt: 'added_direct_percent_ci_high',
          verdictAt: 'verdict_direct', passes: 'WITHIN BUDGET' },
      ],
    },
    'NFR-04': {
      kind: 'acceptance', events: 100_000, repeats: 3,
      budgets: [
        { label: 'elapsed on the worst run', limit: 30_000, unit: 'ms',
          declaredAt: 'budget_ms', measuredAt: 'verify_ms.worst',
          verdictAt: 'within_budget', passes: true },
      ],
    },
  };

  /** @param {any} o @param {string} path */
  const at = (o, path) => path.split('.').reduce((v, k) => (v === undefined || v === null ? v : v[k]), o);

  /**
   * Which strings in a row are requirement references, derived from the ids
   * actually loaded rather than guessed at.
   *
   * This used to be /\b([A-Z]{3,5}-\d{2})\b/ — three to five letters. FR and RM
   * are two, so 79 of 210 requirement ids could not match it, including every
   * FR, the largest family in the backlog, and FR-15, which is open. The
   * headline check this guard advertises — no MEASURED figure cites an open
   * requirement — could not fire for 38% of the backlog, and the status lookup
   * behind it was never reached for any of them.
   *
   * The prefixes come from the resolved backlog where there is one, and from
   * the ids this guard loaded otherwise. Deriving them from the loaded ids
   * ALONE would be self-defeating for the case that matters: an id whose whole
   * family went unread could not be recognised as an id, so the absent-is-not-
   * satisfied check would never reach it. The resolved merge is the full
   * declared set, which is what makes an unread id detectable.
   *
   * Taking them from the backlog either way means the pattern cannot drift from
   * it again, and a string that looks id-shaped but belongs to no declared
   * family — AES-256, FRE-902 — is not mistaken for a requirement.
   */
  const prefixes = new Set(
    [...declaredIds, ...status.keys()].map(id => id.split('-')[0]));
  if (prefixes.size === 0) {
    findings.push('no requirement ids were loaded, so nothing can be checked against their '
      + 'status. Refused rather than passed: a guard with no subject has not approved anything');
  }
  /** @param {string} row */
  const idsIn = (row) => [...row.matchAll(/\b([A-Z]{2,6})-(\d{1,3})\b/g)]
    .filter(m => prefixes.has(String(m[1])))
    .map(m => `${m[1]}-${m[2]}`);

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
      for (const id of idsIn(row)) {
        if (!status.has(id)) {
          findings.push(`a MEASURED figure cites ${id}, which this guard could not find in any `
            + 'requirement file. An id it cannot resolve is not a satisfied one, so the row is '
            + `refused rather than passed — ${text.slice(0, 110)}`);
          continue;
        }
        if (status.get(id) === 'open') {
          findings.push(`a figure is published as MEASURED while ${id} is still open. M7's exit `
            + 'says plainly that neither NFR-01 nor NFR-02 may be reported as met on a '
            + `development-machine number — ${text.slice(0, 110)}`);
          continue;
        }
        const want = /** @type {any} */ (ATTRIBUTED)[id];
        if (!want) continue;

        // The companion to dropping the reference-environment clause: this
        // figure must point at the run that produced it, and that run must
        // carry the host it was taken on.
        const results = paths.filter(x => /^bench\/results\/.*\.json$/.test(x));
        if (results.length === 0) {
          findings.push(`${id} closed on attribution rather than on a reference environment, so a `
            + 'MEASURED figure for it must cite its run result under `bench/results/*.json`. This '
            + `row cites none, so the conditions behind the number are unpublished — ${text.slice(0, 110)}`);
          continue;
        }
        for (const rel of results) {
          const full = join(ROOT, rel);
          if (!existsSync(full)) { findings.push(`${id} cites ${rel}, which does not exist`); continue; }
          /** @type {any} */
          let r;
          try { r = JSON.parse(readFileSync(full, 'utf8')); }
          catch (e) { findings.push(`${id}'s evidence ${rel} is not valid JSON: ${e}`); continue; }
          if (r.kind !== want.kind) {
            findings.push(`${id}'s evidence ${rel} reports kind ${JSON.stringify(r.kind)}, not `
              + `${JSON.stringify(want.kind)}. A regression metric may not back a MEASURED figure`);
          }
          for (const k of want.attests ?? ['machine', 'storage']) {
            if (typeof r[k] !== 'string' || r[k].trim() === '') {
              findings.push(`${id}'s evidence ${rel} does not name its ${k}, which is the whole of `
                + 'what replaced the reference-environment requirement');
            }
          }
          if (Number(r.events) < want.events) {
            findings.push(`${id}'s evidence ${rel} reports ${r.events} events, fewer than the `
              + `${want.events} the requirement asks for`);
          }
          if (Number(r.repeats) < want.repeats) {
            findings.push(`${id}'s evidence ${rel} reports ${r.repeats} repeat(s), fewer than `
              + `${want.repeats}`);
          }
          if (want.disclosures_required !== false && !Array.isArray(r.host_disclosures)) {
            findings.push(`${id}'s evidence ${rel} carries no host_disclosures array. An empty `
              + 'array is a claim that nothing was short; a missing one is silence');
          }

          // And the point of the whole file: did the number PASS?
          for (const b of want.budgets) {
            const declared = at(r, b.declaredAt);
            if (declared !== b.limit) {
              findings.push(`${id}'s evidence ${rel} declares ${b.declaredAt} = `
                + `${JSON.stringify(declared)}, but ${id}'s budget for ${b.label} is `
                + `${b.limit} ${b.unit}. A measurement checked against a budget its own file `
                + 'supplies is not checked; the budget is held by this guard');
              continue;
            }
            const measured = at(r, b.measuredAt);
            if (typeof measured !== 'number' || !Number.isFinite(measured)) {
              findings.push(`${id}'s evidence ${rel} has no finite ${b.measuredAt}, so its `
                + `${b.label} cannot be checked against the ${b.limit} ${b.unit} budget. An `
                + 'unreadable measurement is not a passing one');
              continue;
            }
            if (measured > b.limit) {
              findings.push(`${id} is published as MEASURED, but its evidence ${rel} reports `
                + `${b.label} of ${measured} ${b.unit} against a budget of ${b.limit} ${b.unit} `
                + '— the cited evidence reports a MISS. Evidence being present is not evidence '
                + 'establishing the claimed result');
            }
            const verdict = at(r, b.verdictAt);
            if (verdict !== b.passes) {
              findings.push(`${id}'s evidence ${rel} reports ${b.verdictAt} = `
                + `${JSON.stringify(verdict)} rather than ${JSON.stringify(b.passes)}, so the `
                + `harness itself did not call ${b.label} a pass`);
            }
          }
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
