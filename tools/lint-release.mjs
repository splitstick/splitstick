// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * A publish may not claim a release whose requirements are still open —
 * TRC-04, TRC-05.
 *
 * The release workflow ran the tests, both tamper suites, the traceability
 * check and the specification review, under a comment saying "nothing is
 * published that has not passed the gates. A release is the one moment where
 * skipping them is most tempting and least defensible." It did not run the
 * claims audit, and it had no opinion about whether the version being tagged
 * was a version the project had actually finished.
 *
 * ── THE FIRST VERSION OF THIS GATE FAILED OPEN ───────────────────────────
 *
 * It took a single argument and treated anything it could not parse as "this
 * version claims no release", which exited 0. The workflow also publishes on a
 * manual `workflow_dispatch` with `dry_run: false`, where `github.ref_name` is
 * whatever ref was selected — `main`, typically. So the gate passed `main`,
 * passed an empty string, passed `release-1.0`, and the publish step ran.
 *
 * A gate that treats an unrecognised input as permission is the fail-open
 * shape this project refuses everywhere else, and it was built into the one
 * tool whose entire job is to refuse. Found by review, reproduced in one
 * command.
 *
 * So there are now two modes and they are not the same code path:
 *
 *   --report                 what a human runs before deciding. Prints the
 *                            state of every release and exits 0. Claims
 *                            nothing about eligibility.
 *   --gate <ref> …           what the workflow runs. Every input must be
 *                            recognised, and ANYTHING UNRECOGNISED IS A
 *                            REFUSAL.
 *
 * In gate mode, publishing requires all of:
 *
 *   - a dry run, which publishes nothing and is always allowed; or
 *   - a ref that is a TAG, because a branch is not a release; and
 *   - a strict, fully anchored version tag — `v1.2.3` or `v1.2.3-rc.1`, not
 *     `v1.2.3garbage`, which the first version accepted by matching a prefix;
 *     and
 *   - a version that every publishable workspace package already carries,
 *     because a tag that disagrees with the manifests publishes something
 *     other than what it names; and
 *   - no open requirement in the release that version claims.
 *
 * A PRERELEASE OF A 1.x STILL CLAIMS 1.0. `1.0.0-rc.1` on a registry reads as
 * 1.0 to anyone scanning, and the honest way to publish while requirements are
 * open already exists: a 0.x version, which claims nothing and passes.
 *
 * Usage:
 *   node tools/lint-release.mjs --report
 *   node tools/lint-release.mjs --gate <ref> --ref-type <tag|branch> --dry-run <true|false>
 *   node tools/lint-release.mjs --requirements <dir>   (fixtures, for tests)
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;

// ── arguments, read strictly ─────────────────────────────────────────────
const argv = process.argv.slice(2);
/** @param {string} name */
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? undefined : argv[i + 1];
};
const wants = (/** @type {string} */ name) => argv.includes(`--${name}`);

const KNOWN = new Set(['report', 'gate', 'ref-type', 'dry-run', 'requirements', 'packages']);
for (const a of argv.filter(x => x.startsWith('--'))) {
  if (!KNOWN.has(a.slice(2))) {
    console.error(`\n  ${a} is not a flag this reads. Refused rather than ignored: a misspelled `
      + 'flag on a release gate would be a release gate that did not run.\n');
    process.exit(2);
  }
}

/**
 * Requirements, from the repository or from a fixture directory.
 *
 * `backlog.json` AND every `partN.json`, which is what requirements/build.mjs
 * merges to produce the matrix. This gate used to read only the partN files,
 * and there is no part1.json — so 47 requirements, FR-15 among them, were
 * invisible to it. It reported "1.0: 142/147 done" and five open while the real
 * figure was 193 and six, and FR-15 was listed as open in the follow-ups and in
 * MATRIX.md the whole time. A release gate that reads a subset and reports a
 * total is worse than no gate, because the total looks authoritative.
 *
 * So the read is cross-checked against backlog.resolved.json, the generated
 * merge of the same inputs, and any disagreement in either direction refuses.
 * That catches both an input file this function forgot and a stale generated
 * file, without either one being able to pass quietly.
 */
function requirements(dir = join(ROOT, 'requirements')) {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    console.error(`\n  ${dir} is not a directory of requirement files.\n`);
    process.exit(2);
  }
  /** @type {{ id: string, title: string, release: string, status?: string, verify?: string }[]} */
  const all = [];
  let files = 0;
  /** @param {any} parsed */
  const itemsOf = (parsed) => Array.isArray(parsed) ? parsed
    : (parsed.requirements ?? parsed.items
      ?? Object.values(parsed).flat().filter(x => x && typeof x === 'object'));
  for (const f of readdirSync(dir)) {
    if (!/^(backlog|part\d+)\.json$/.test(f)) continue;
    files += 1;
    for (const r of /** @type {any[]} */ (itemsOf(JSON.parse(readFileSync(join(dir, f), 'utf8'))))) {
      if (r?.id) all.push(r);
    }
  }
  if (files === 0) {
    // A gate that found no requirements must not conclude that none are open.
    console.error(`\n  ${dir} holds no backlog.json or partN.json requirement files, so this gate `
      + 'read nothing. That is refused rather than reported as clean: an empty read is not an '
      + 'empty backlog.\n');
    process.exit(2);
  }

  // Cross-check against the generated merge, when the fixture or repo has one.
  // backlog.resolved.json is generated and gitignored, so it is absent on a
  // fresh clone until `npm run requirements` runs. That must not be a SILENT
  // skip: a guard that checked nothing has to say so, or the next reader will
  // believe it ran.
  const resolved = join(dir, 'backlog.resolved.json');
  if (!existsSync(resolved)) {
    console.error(`  note: ${resolved} is absent, so this gate could not cross-check that it `
      + 'read every requirement file. Run `npm run requirements` first for that check.');
  }
  if (existsSync(resolved)) {
    const expected = new Set(itemsOf(JSON.parse(readFileSync(resolved, 'utf8')))
      .map((/** @type {any} */ r) => r?.id).filter(Boolean));
    const seen = new Set(all.map(r => r.id));
    const missed = [...expected].filter(id => !seen.has(id));
    const extra = [...seen].filter(id => !expected.has(id));
    if (missed.length > 0 || extra.length > 0) {
      console.error('\n  this gate\'s view of the backlog disagrees with '
        + 'requirements/backlog.resolved.json, so one of them is wrong and neither may be '
        + 'treated as the total.'
        + (missed.length ? `\n  not read by this gate: ${missed.join(', ')}` : '')
        + (extra.length ? `\n  read by this gate but not in the resolved merge: ${extra.join(', ')}`
          : '')
        + '\n  run `npm run requirements` to regenerate the merge, or add the file this '
        + 'function is not reading.\n');
      process.exit(2);
    }
  }
  return all;
}

const reqDir = flag('requirements');
const all = requirements(reqDir === undefined ? undefined : reqDir);
const releases = [...new Set(all.map(r => String(r.release)))].sort();
/** @param {string} rel */
const openIn = (rel) => all.filter(r => String(r.release) === rel && r.status !== 'done');

/**
 * Publishable workspace package versions, by name.
 *
 * The directory is injectable for the same reason the requirements are: the
 * companion tests have to exercise the state where 1.0 IS complete, and they
 * cannot do that against a repository whose packages all say 0.1.0 and whose
 * requirements are open. Testing a gate only against today's state is how the
 * first version of these tests came to fail on the first legitimately
 * releasable build.
 * @param {string} [dir]
 */
function packageVersions(dir = join(ROOT, 'packages')) {
  /** @type {Map<string, string>} */
  const out = new Map();
  if (!existsSync(dir)) return out;
  for (const d of readdirSync(dir)) {
    const man = join(dir, d, 'package.json');
    if (!existsSync(man)) continue;
    const m = JSON.parse(readFileSync(man, 'utf8'));
    if (m.private === true) continue;
    out.set(String(m.name), String(m.version));
  }
  return out;
}

/** A strict, fully anchored release tag. */
const TAG = /^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/;

/** @param {string[]} lines */
const refuse = (lines) => {
  console.error('\nRELEASE GATE FAILED\n');
  for (const l of lines) console.error(`  ${l}`);
  console.error('');
  process.exit(1);
};

function report() {
  for (const rel of releases) {
    const group = all.filter(r => String(r.release) === rel);
    const out = openIn(rel);
    console.log(`\n  ${rel}: ${group.length - out.length}/${group.length} done`);
    for (const r of out) console.log(`       OPEN  ${r.id.padEnd(8)} ${String(r.title).trim()}`);
  }
  const versions = [...new Set(packageVersions(flag('packages')).values())];
  console.log(`\n  package version(s): ${versions.join(', ') || '(none)'}`);
  console.log('\n  This is a report, not an eligibility decision. The gate the workflow runs is');
  console.log('  `--gate <tag> --ref-type tag --dry-run false`.\n');
}

// ── report mode ──────────────────────────────────────────────────────────
if (wants('report') || argv.length === 0 || (reqDir !== undefined && !wants('gate'))) {
  report();
  process.exit(0);
}

// ── gate mode ────────────────────────────────────────────────────────────
const ref = flag('gate');
const refType = flag('ref-type');
const dryRun = flag('dry-run');

if (dryRun !== 'true' && dryRun !== 'false') {
  refuse([`--dry-run must be exactly true or false; got ${JSON.stringify(dryRun ?? null)}.`,
    'A gate cannot guess whether a run publishes.']);
}
if (dryRun === 'true') {
  console.log('\n  release: dry run — nothing is published, so eligibility is not gated.');
  console.log('           The state of every release, for the record:');
  report();
  process.exit(0);
}

// From here on, this run publishes.
if (refType !== 'tag') {
  refuse([`publishing requires a tag; --ref-type is ${JSON.stringify(refType ?? null)}.`,
    'A manual run on a branch reaches the publish step through `dry_run: false`, and a branch',
    'is not a release. Tag the commit and run the workflow on the tag.']);
}

const m = ref === undefined ? null : TAG.exec(ref);
if (m === null) {
  refuse([`${JSON.stringify(ref ?? null)} is not a release tag.`,
    'Publishing requires a strict `vMAJOR.MINOR.PATCH` with an optional prerelease suffix —',
    '`v1.2.3` or `v1.2.3-rc.1`. An unrecognised ref is REFUSED and never treated as a version',
    'that claims nothing: that is how the first version of this gate let `main` through.']);
}

const version = `${m[1]}.${m[2]}.${m[3]}${m[4] === undefined ? '' : `-${m[4]}`}`;
const major = Number(m[1]);

// The tag must agree with what is actually being published.
const versions = packageVersions(flag('packages'));
const disagree = [...versions].filter(([, v]) => v !== version);
if (versions.size === 0) {
  refuse(['no publishable workspace package was found, so the tag could not be checked against',
    'anything. Refused rather than passed: a gate that reads nothing must not report clean.']);
}
if (disagree.length > 0) {
  refuse([`tag ${ref} names version ${version} and these packages do not carry it:`,
    ...disagree.map(([n, v]) => `  ${n} is ${v}`),
    'A tag that disagrees with the manifests publishes something other than what it names.']);
}

// 0.x claims no requirement release. That is the honest way to publish while
// anything is open, and the gate must not stand in its way.
if (major === 0) {
  console.log(`\n  release: ${ref} publishes ${version}, a pre-1.0 version that claims no`);
  console.log('           requirement release — the honest option while anything is open.\n');
  process.exit(0);
}

const claimed = `${major}.0`;
if (!releases.includes(claimed)) {
  refuse([`${ref} claims release ${claimed}, and no requirement declares that release.`,
    'Refused rather than passed: a version claiming a release nobody has specified is a',
    'claim with no backlog behind it.']);
}

const outstanding = openIn(claimed);
if (outstanding.length > 0) {
  refuse([`${ref} claims release ${claimed}, and ${outstanding.length} requirement(s) are open:`,
    '',
    ...outstanding.flatMap(r => [
      `  ${r.id}  ${String(r.title).trim()}`,
      `      verify: ${String(r.verify ?? '').trim().slice(0, 150)}`,
      '',
    ]),
    `A ${claimed} tag says "this is ${claimed}" more loudly than any README can qualify, and a`,
    'prerelease of it says the same thing. Close them, narrow the requirements deliberately, or',
    'publish a 0.x version — which claims nothing and passes.']);
}

console.log(`\n  release: ${ref} publishes ${version}, claims ${claimed}, and every ${claimed}`);
console.log('           requirement is done.\n');
