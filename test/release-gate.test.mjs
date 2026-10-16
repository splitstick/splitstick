// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The release gate, broken on purpose — TRC-04, TRC-05.
 *
 * M7's rule applies to this guard as much as to the others: it ships with a
 * companion that breaks it, because the guards M7 trusted without one are
 * where the review found the holes.
 *
 * What this one protects is narrow and worth stating: every individual surface
 * in this project can be scrupulously honest about an open requirement — the
 * figures table labels three performance numbers TARGET, the follow-ups
 * document lists all five open requirements, the assurance register classes
 * every claim — and a `1.0.0` on npm would still say "this is 1.0" more loudly
 * than any of it. A version is a claim, and it is the one claim the claims
 * audit cannot read, because it is not in any document.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
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

/** Requirements, read the way the gate reads them. */
function requirements() {
  /** @type {any[]} */
  const all = [];
  for (const f of readdirSync(join(ROOT, 'requirements'))) {
    if (!/^part\d+\.json$/.test(f)) continue;
    const parsed = JSON.parse(readFileSync(join(ROOT, 'requirements', f), 'utf8'));
    const items = Array.isArray(parsed) ? parsed
      : (parsed.requirements ?? parsed.items
        ?? Object.values(parsed).flat().filter(x => x && typeof x === 'object'));
    for (const r of /** @type {any[]} */ (items)) if (r?.id) all.push(r);
  }
  return all;
}

test('TRC-04: a 1.0 tag is refused while any 1.0 requirement is open', async () => {
  const open = requirements().filter(r => r.release === '1.0' && r.status !== 'done');
  assert.ok(open.length > 0,
    'every 1.0 requirement is done, so this test no longer exercises the refusal. If that is '
    + 'genuinely true, the project is releasable and this assertion should be inverted '
    + 'deliberately rather than deleted');

  const r = await run(['v1.0.0']);
  assert.equal(r.code, 1, 'a 1.0.0 tag was allowed with open requirements');
  // It must NAME them. A gate that refuses without saying what is missing gets
  // overridden rather than satisfied.
  for (const req of open) {
    assert.match(r.err, new RegExp(req.id), `the refusal does not name ${req.id}`);
  }
  assert.match(r.err, /publish a\s+pre-1\.0 version/,
    'the refusal does not say what the honest alternative is');
});

test('TRC-04: a pre-1.0 tag claims nothing and is allowed', async () => {
  // The gate must not block the honest way to publish while work is open. If
  // it did, the pressure would be to bypass the gate rather than to version
  // accurately.
  for (const v of ['v0.1.0', '0.2.3', 'v0.9.99']) {
    const r = await run([v]);
    assert.equal(r.code, 0, `${v} was blocked`);
  }
});

test('TRC-04: a 2.0 tag is judged against 2.0, not 1.0', async () => {
  // The release a version claims is derived from the version, so a future
  // major does not inherit this major's state.
  const r = await run(['v2.0.0']);
  const open2 = requirements().filter(x => x.release === '2.0' && x.status !== 'done');
  assert.equal(r.code, open2.length > 0 ? 1 : 0);
  if (open2.length > 0) {
    assert.match(r.err, /claims release 2\.0/);
    // And it must not be refused for 1.0's reasons.
    assert.ok(!/NFR-01/.test(r.err), 'a 2.0 tag was judged against 1.0 requirements');
  }
});

test('TRC-04: with no version it reports rather than refuses', async () => {
  // A human deciding whether to cut a release is the main reader. A tool that
  // only ever exits non-zero is one they run once.
  const r = await run([]);
  assert.equal(r.code, 0);
  assert.match(r.out, /1\.0: \d+\/\d+ done/);
  assert.match(r.out, /OPEN {2}NFR-01/);
});

test('TRC-05: the release workflow runs the claims audit and this gate', async () => {
  // The finding this change exists for: the release workflow ran the tests,
  // the tamper suites, the traceability check and the specification review,
  // under a comment saying nothing is published that has not passed the gates
  // — and did not run the claims audit. It was enforced on every push and pull
  // request, and not on the tag that actually publishes.
  const wf = readFileSync(join(ROOT, '.github/workflows/release.yml'), 'utf8');
  for (const step of ['npm run lint', 'npm run claims', 'tools/lint-release.mjs']) {
    assert.ok(wf.includes(step), `release.yml does not run ${step}`);
  }
  // And the gate reads the tag rather than a hardcoded version.
  assert.match(wf, /lint-release\.mjs" ?"\$\{\{ github\.ref_name \}\}"|lint-release\.mjs "\$\{\{ github\.ref_name \}\}"/);

  // Every gate CI runs, the release runs too. A release is the one moment
  // where skipping a gate is most tempting and least defensible, which is what
  // the workflow's own comment says.
  const ci = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const gates = [...ci.matchAll(/run: (npm run [a-z:]+)/g)].map(m => String(m[1]));
  const missing = [...new Set(gates)].filter(g => !wf.includes(g)
    // CI-only by nature: the benchmarks report rather than gate, and the
    // generated-file check compares against a working tree.
    && !/bench|generate/.test(g));
  assert.deepEqual(missing, [], `gates CI runs that a release does not: ${missing.join(', ')}`);
});
