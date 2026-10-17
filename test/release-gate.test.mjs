// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The release gate, broken on purpose — TRC-04, TRC-05.
 *
 * AGAINST FIXTURES, NOT AGAINST TODAY'S REPOSITORY. The first version of this
 * file asserted `open.length > 0` on the real backlog and expected NFR-01 in
 * the report. Both are true today and both become false the moment the project
 * is genuinely releasable — and the release workflow runs the unit suite before
 * publishing, so the first legitimately releasable 1.0 build would have been
 * rejected by the release gate's own tests. A gate has to work when the project
 * is unfinished AND when it is ready.
 *
 * So the requirement set and the package manifests are both injectable, and
 * every case below supplies its own.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const GATE = join(ROOT, 'tools/lint-release.mjs');

/** @returns {Promise<{ code: number, out: string, err: string }>} */
const run = (/** @type {string[]} */ args) => new Promise((resolve) => {
  execFile(process.execPath, [GATE, ...args], (e, out, err) => resolve({
    code: e && typeof e.code === 'number' ? e.code : 0, out, err,
  }));
});

/**
 * A fixture world: a requirements directory and a packages directory.
 *
 * `file` says which requirement file the fixture writes, because WHICH file is
 * exactly what the gate got wrong. These fixtures all wrote part1.json, which
 * the repository does not have — so the suite passed while the gate was blind
 * to requirements/backlog.json and the 47 requirements in it.
 *
 * @param {{ reqs?: any[], versions?: Record<string, string>, file?: string,
 *           resolved?: any[] }} o
 */
function world(o) {
  const dir = mkdtempSync(join(tmpdir(), 'ss-rel-'));
  const reqs = join(dir, 'requirements');
  const pkgs = join(dir, 'packages');
  mkdirSync(reqs);
  mkdirSync(pkgs);
  if (o.reqs !== undefined) {
    writeFileSync(join(reqs, o.file ?? 'part1.json'), JSON.stringify({ requirements: o.reqs }));
  }
  if (o.resolved !== undefined) {
    writeFileSync(join(reqs, 'backlog.resolved.json'),
      JSON.stringify({ count: o.resolved.length, requirements: o.resolved }));
  }
  for (const [name, version] of Object.entries(o.versions ?? { a: '1.0.0' })) {
    mkdirSync(join(pkgs, name));
    writeFileSync(join(pkgs, name, 'package.json'),
      JSON.stringify({ name: `@splitstick/${name}`, version }));
  }
  return {
    dir,
    args: ['--requirements', reqs, '--packages', pkgs],
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const req = (/** @type {string} */ id, /** @type {string} */ release, /** @type {string} */ status) =>
  ({ id, title: `${id} title`, release, status, verify: `${id} verify` });

const publish = (/** @type {string} */ tag) => ['--gate', tag, '--ref-type', 'tag', '--dry-run', 'false'];

test('TRC-04: a COMPLETE requirement set lets its release publish', async () => {
  // The case the old suite could not express, and the one that matters most:
  // when the work is done, the gate must get out of the way.
  const w = world({
    reqs: [req('NFR-01', '1.0', 'done'), req('LEG-09', '1.0', 'done')],
    versions: { core: '1.0.0', verify: '1.0.0' },
  });
  try {
    const r = await run([...publish('v1.0.0'), ...w.args]);
    assert.equal(r.code, 0, `a releasable 1.0 was blocked:\n${r.err}`);
    assert.match(r.out, /every 1\.0\s+requirement is done/);
  } finally { w.cleanup(); }
});

test('TRC-04: an INCOMPLETE requirement set refuses its release, and names what is open', async () => {
  const w = world({
    reqs: [req('NFR-01', '1.0', 'done'), req('LEG-09', '1.0', 'open')],
    versions: { core: '1.0.0' },
  });
  try {
    const r = await run([...publish('v1.0.0'), ...w.args]);
    assert.equal(r.code, 1);
    assert.match(r.err, /LEG-09/);
    assert.match(r.err, /LEG-09 verify/, 'the refusal does not say what would close it');
    assert.doesNotMatch(r.err, /NFR-01/, 'a done requirement was reported as open');
    assert.match(r.err, /publish a 0\.x version/, 'the refusal offers no honest alternative');
  } finally { w.cleanup(); }
});

test('TRC-04: a prerelease of a 1.x claims 1.0 too', async () => {
  // `1.0.0-rc.1` on a registry reads as 1.0 to anyone scanning, and the honest
  // pre-1.0 path already exists.
  const w = world({
    reqs: [req('NFR-01', '1.0', 'open')],
    versions: { core: '1.0.0-rc.1' },
  });
  try {
    const r = await run([...publish('v1.0.0-rc.1'), ...w.args]);
    assert.equal(r.code, 1, 'a 1.0 prerelease published with 1.0 open');
    assert.match(r.err, /claims release 1\.0/);
  } finally { w.cleanup(); }
});

test('TRC-04: a 0.x tag claims nothing and publishes while everything is open', async () => {
  // The gate must not block the honest version, or the pressure becomes to
  // bypass the gate rather than to version accurately.
  const w = world({
    reqs: [req('NFR-01', '1.0', 'open'), req('LEG-09', '1.0', 'open')],
    versions: { core: '0.1.0' },
  });
  try {
    const r = await run([...publish('v0.1.0'), ...w.args]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /claims no\s+requirement release/);
  } finally { w.cleanup(); }
});

test('TRC-04: a MISSING requirement set is refused, never treated as complete', async () => {
  // An empty read is not an empty backlog. A gate that found no requirements
  // and concluded nothing was open would pass every release.
  const w = world({ reqs: undefined, versions: { core: '1.0.0' } });
  try {
    const r = await run([...publish('v1.0.0'), ...w.args]);
    assert.equal(r.code, 2, 'an empty requirements directory was treated as clean');
    assert.match(r.err, /an empty read is not an empty backlog/);
  } finally { w.cleanup(); }
});

test('TRC-04: a release nobody has specified is refused', async () => {
  // A v2.0.0 tag with no 2.0 requirements is a claim with no backlog behind it.
  const w = world({ reqs: [req('NFR-01', '1.0', 'done')], versions: { core: '2.0.0' } });
  try {
    const r = await run([...publish('v2.0.0'), ...w.args]);
    assert.equal(r.code, 1);
    assert.match(r.err, /no requirement declares that release/);
  } finally { w.cleanup(); }
});

test('P1: a manual run on a branch cannot publish', async () => {
  // The bypass. The workflow publishes on `workflow_dispatch` with
  // `dry_run: false`, where `github.ref_name` is whatever ref was selected —
  // `main`, typically. The first version of this gate took only the ref name
  // and treated anything unparseable as "claims nothing", so `main`, an empty
  // string and `release-1.0` all exited 0 and the publish step ran.
  const w = world({ reqs: [req('NFR-01', '1.0', 'done')], versions: { core: '1.0.0' } });
  try {
    for (const ref of ['main', '', 'release-1.0', 'v1.0.0']) {
      const r = await run(['--gate', ref, '--ref-type', 'branch', '--dry-run', 'false', ...w.args]);
      assert.equal(r.code, 1, `a branch ref ${JSON.stringify(ref)} was allowed to publish`);
      assert.match(r.err, /publishing requires a tag/);
    }
  } finally { w.cleanup(); }
});

test('P1: an unrecognised ref is refused, not read as claiming nothing', async () => {
  const w = world({ reqs: [req('NFR-01', '1.0', 'done')], versions: { core: '1.0.0' } });
  try {
    for (const ref of ['main', '', 'release-1.0', '1.0.0', 'v1.0', 'v1.0.0.0']) {
      const r = await run([...publish(ref), ...w.args]);
      assert.equal(r.code, 1, `${JSON.stringify(ref)} was accepted as a version`);
      assert.match(r.err, /is not a release tag/);
    }
  } finally { w.cleanup(); }
});

test('P2: a version-like prefix is not a version', async () => {
  // `v1.2.3garbage` matched the old unanchored parser and was read as 1.2.3.
  const w = world({ reqs: [req('X-01', '1.0', 'done')], versions: { core: '1.2.3' } });
  try {
    for (const ref of ['v1.2.3garbage', 'v1.2.3 ', 'vv1.2.3', 'v1.2.3+meta!']) {
      const r = await run([...publish(ref), ...w.args]);
      assert.equal(r.code, 1, `${JSON.stringify(ref)} was accepted`);
    }
  } finally { w.cleanup(); }
});

test('TRC-04: a tag the manifests do not carry is refused', async () => {
  // A tag that disagrees with the manifests publishes something other than
  // what it names.
  const w = world({
    reqs: [req('NFR-01', '1.0', 'done')],
    versions: { core: '1.0.0', verify: '0.9.0' },
  });
  try {
    const r = await run([...publish('v1.0.0'), ...w.args]);
    assert.equal(r.code, 1);
    assert.match(r.err, /@splitstick\/verify is 0\.9\.0/);
  } finally { w.cleanup(); }
});

test('a dry run publishes nothing and is always allowed', async () => {
  const w = world({ reqs: [req('NFR-01', '1.0', 'open')], versions: { core: '1.0.0' } });
  try {
    const r = await run(['--gate', 'main', '--ref-type', 'branch', '--dry-run', 'true', ...w.args]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /dry run — nothing is published/);
    // And it still reports the state, so a dry run is informative.
    assert.match(r.out, /OPEN {2}NFR-01/);
  } finally { w.cleanup(); }
});

test('--dry-run must be explicit: a gate cannot guess whether a run publishes', async () => {
  const w = world({ reqs: [req('NFR-01', '1.0', 'done')], versions: { core: '1.0.0' } });
  try {
    for (const bad of [[], ['--dry-run', 'yes'], ['--dry-run', '']]) {
      const r = await run(['--gate', 'v1.0.0', '--ref-type', 'tag', ...bad, ...w.args]);
      assert.equal(r.code, 1, `--dry-run ${JSON.stringify(bad)} was accepted`);
      assert.match(r.err, /must be exactly true or false/);
    }
  } finally { w.cleanup(); }
});

test('a misspelled flag is refused rather than ignored', async () => {
  // A misspelled flag on a release gate is a release gate that did not run.
  const r = await run(['--gaet', 'v1.0.0']);
  assert.equal(r.code, 2);
  assert.match(r.err, /is not a flag this reads/);
});

test('--report describes the real backlog without deciding eligibility', async () => {
  // The human-facing mode, against the real repository — the one place today's
  // state is the subject rather than an accident.
  const r = await run(['--report']);
  assert.equal(r.code, 0);
  assert.match(r.out, /1\.0: \d+\/\d+ done/);
  assert.match(r.out, /This is a report, not an eligibility decision/);
});

test('TRC-05: the release workflow runs the claims audit and gates the publish', async () => {
  const wf = readFileSync(join(ROOT, '.github/workflows/release.yml'), 'utf8');
  for (const step of ['npm run lint', 'npm run claims', 'tools/lint-release.mjs']) {
    assert.ok(wf.includes(step), `release.yml does not run ${step}`);
  }
  // Every input explicit, so no path reaches publish with the gate guessing.
  for (const f of ['--gate', '--ref-type', '--dry-run']) {
    assert.ok(wf.includes(f), `release.yml does not pass ${f} to the gate`);
  }
  assert.match(wf, /github\.ref_type/, 'the gate is not told whether the ref is a tag');

  // Every gate CI runs, the release runs too.
  const ci = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const gates = [...ci.matchAll(/run: (npm run [a-z:]+)/g)].map(m => String(m[1]));
  const missing = [...new Set(gates)].filter(g => !wf.includes(g) && !/bench|generate/.test(g));
  assert.deepEqual(missing, [], `gates CI runs that a release does not: ${missing.join(', ')}`);
});

/**
 * The gate read `part\\d+\\.json` and nothing else, and the repository has no
 * part1.json — so requirements/backlog.json, 47 requirements including FR-15,
 * were invisible to it. It reported "1.0: 142/147 done" and five open while the
 * truth was 193 and six. A gate that reads a subset and reports a total is
 * worse than no gate, because the total looks authoritative.
 *
 * Every fixture above writes part1.json, which is why the suite never saw this.
 * These three read the layout the repository actually has.
 */
test('requirements in backlog.json are read, not only partN.json', async () => {
  const w = world({ file: 'backlog.json', reqs: [req('FR-01', '1.0', 'open')] });
  try {
    const r = await run([...w.args, ...publish('v1.0.0')]);
    assert.equal(r.code, 1, 'an open requirement in backlog.json must block the release');
    assert.match(r.out + r.err, /FR-01/);
  } finally { w.cleanup(); }
});

test('a backlog the gate cannot fully see is refused, not totalled', async () => {
  // The resolved merge names a requirement this gate did not read. Neither
  // number may stand as the total.
  const w = world({
    file: 'backlog.json',
    reqs: [req('FR-01', '1.0', 'done')],
    resolved: [req('FR-01', '1.0', 'done'), req('FR-15', '1.0', 'open')],
  });
  try {
    const r = await run([...w.args, ...publish('v1.0.0')]);
    assert.equal(r.code, 2, 'a partial read must refuse rather than report a total');
    assert.match(r.out + r.err, /not read by this gate: FR-15/);
  } finally { w.cleanup(); }
});

test('the real repository backlog is read in full, FR-15 included', async () => {
  // Against the repository itself, not a fixture. The defect was a mismatch
  // between the fixture layout and the real one, so a fixture cannot catch it.
  const r = await run(['--report']);
  assert.equal(r.code, 0);
  const resolved = JSON.parse(
    readFileSync(new URL('../requirements/backlog.resolved.json', import.meta.url), 'utf8'));
  const open10 = resolved.requirements
    .filter((/** @type {any} */ x) => String(x.release) === '1.0' && x.status !== 'done')
    .map((/** @type {any} */ x) => x.id);
  assert.ok(open10.length > 0, 'this check needs at least one open 1.0 requirement to be meaningful');
  for (const id of open10) {
    assert.match(r.out, new RegExp(`OPEN\\s+${id}\\b`),
      `${id} is open in the resolved backlog and the gate did not report it`);
  }
  assert.match(r.out, /1\.0: \d+\/\d+ done/);
});
