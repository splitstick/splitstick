// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * A tag may not claim a release whose requirements are still open —
 * TRC-04, TRC-05.
 *
 * The release workflow ran the tests, the tamper suites, the traceability
 * check and the specification review, under a comment saying "nothing is
 * published that has not passed the gates. A release is the one moment where
 * skipping them is most tempting and least defensible." It did not run the
 * claims audit, and it had no opinion at all about whether the version being
 * tagged was a version the project had actually finished.
 *
 * So `v1.0.0` could have been published with five 1.0 requirements open —
 * including the two M7's own exit criteria name, and three published
 * performance figures that the documentation correctly labels TARGET. Every
 * individual surface was honest. The TAG would not have been: a 1.0.0 on npm
 * says "this is 1.0" more loudly than any README can qualify.
 *
 * Usage: node tools/lint-release.mjs <version>
 *
 * In the workflow the version comes from the tag. Run with no argument it
 * reports the state and exits 0, which is what makes it useful to a human
 * deciding whether to cut one.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;

/** @type {{ id: string, title: string, release: string, status?: string, verify?: string }[]} */
const all = [];
for (const f of readdirSync(join(ROOT, 'requirements'))) {
  if (!/^part\d+\.json$/.test(f)) continue;
  const parsed = JSON.parse(readFileSync(join(ROOT, 'requirements', f), 'utf8'));
  const items = Array.isArray(parsed) ? parsed
    : (parsed.requirements ?? parsed.items
      ?? Object.values(parsed).flat().filter(x => x && typeof x === 'object'));
  for (const r of /** @type {any[]} */ (items)) if (r?.id) all.push(r);
}

/** The requirement release a package version is claiming. `1.x` claims 1.0. */
const claimedBy = (/** @type {string} */ version) => {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (m === null) return null;
  const major = Number(m[1]);
  // 0.x claims nothing: a pre-1.0 version is the honest way to publish while
  // requirements are open, and this guard must not stand in the way of that.
  if (major === 0) return null;
  return `${major}.0`;
};

const version = process.argv[2];
const release = version === undefined ? null : claimedBy(version);

/** @param {string} rel */
const openIn = (rel) => all.filter(r => r.release === rel && r.status !== 'done');

if (release === null) {
  // Reporting mode. No argument, or a 0.x version: say where things stand.
  for (const rel of ['1.0', '2.0']) {
    const group = all.filter(r => r.release === rel);
    if (group.length === 0) continue;
    const out = openIn(rel);
    console.log(`\n  ${rel}: ${group.length - out.length}/${group.length} done`);
    for (const r of out) console.log(`       OPEN  ${r.id.padEnd(8)} ${r.title.trim()}`);
  }
  if (version !== undefined) {
    console.log(`\n  ${version} is a pre-1.0 version and claims no requirement release, which is`);
    console.log('  the honest way to publish while anything is open.\n');
  } else {
    console.log('\n  Pass a version to check whether a tag may claim it.\n');
  }
  process.exit(0);
}

const outstanding = openIn(release);
if (outstanding.length > 0) {
  console.error(`\nRELEASE GATE FAILED — ${version} claims release ${release}\n`);
  console.error(`  ${outstanding.length} requirement(s) in ${release} are not done:\n`);
  for (const r of outstanding) {
    console.error(`  ${r.id}  ${r.title.trim()}`);
    console.error(`      verify: ${(r.verify ?? '').trim().slice(0, 150)}\n`);
  }
  console.error(`  A ${release} tag says "this is ${release}" more loudly than any README can`);
  console.error('  qualify. Close them, narrow the requirements deliberately, or publish a');
  console.error('  pre-1.0 version — which claims nothing and is the honest option while');
  console.error('  anything is open.\n');
  process.exit(1);
}

console.log(`\n  release: ${version} claims ${release}, and every ${release} requirement is done\n`);
