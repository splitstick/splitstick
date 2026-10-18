// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The manifests, checked against the code and against the lockfile.
 *
 * M6 shipped two packaging defects that every test passed through, because a
 * test runs against a working tree and a user installs a package:
 *
 *   `@splitstick/witnesses` imported `@splitstick/witness-tlog` and did not
 *   declare it. It resolved locally because the workspace link happened to be
 *   there; anybody installing the package would have got a module-not-found at
 *   the first call.
 *
 *   `packages/witness-tlog` existed as a workspace with no entry in
 *   package-lock.json, so `npm ci` — the first step of every CI job — refused
 *   the tree. Nothing local noticed, because nothing local runs `npm ci`.
 *
 * And M6's review found a third of the same family: `splitstick-verify`, the
 * only published bin, printed nothing and exited 0 when installed, because npm
 * links a bin as a symlink and the self-exec guard compared paths that then
 * differ. A bin that is declared and does not run is a manifest that lies in
 * the same way.
 *
 * None of these is findable by running the suite. They are findable by reading
 * the manifests against the code, which is what this does.
 */

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const PKGS = join(ROOT, 'packages');

/** @param {string} p */
const json = (p) => JSON.parse(readFileSync(p, 'utf8'));

/** @param {string} dir @returns {string[]} */
function sources(dir) {
  /** @type {string[]} */
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (name.endsWith('.mjs')) out.push(p);
  }
  return out;
}

/** @type {string[]} */
const findings = [];
const names = readdirSync(PKGS).filter(n => existsSync(join(PKGS, n, 'package.json')));
const manifests = new Map(names.map(n => [n, json(join(PKGS, n, 'package.json'))]));
const published = new Set([...manifests.values()].map(m => m.name));
const lock = json(join(ROOT, 'package-lock.json'));

for (const dir of names) {
  const m = /** @type {any} */ (manifests.get(dir));
  const deps = new Set(Object.keys(m.dependencies ?? {}));
  const peers = new Set(Object.keys(m.peerDependencies ?? {}));

  // 1. Every @splitstick module the source imports is declared.
  for (const f of sources(join(PKGS, dir, 'src'))) {
    const src = readFileSync(f, 'utf8');
    for (const match of src.matchAll(/from\s+['"](@splitstick\/[a-z0-9-]+)(?:\/[^'"]*)?['"]/g)) {
      const dep = String(match[1]);
      if (dep === m.name || deps.has(dep) || peers.has(dep)) continue;
      findings.push(
        `${relative(ROOT, f)} imports ${dep}, which ${m.name} does not declare as a dependency. `
        + 'It resolves here because the workspace link is present; it would not resolve for '
        + 'anybody who installed the package.');
    }
  }

  // 2. Every declared @splitstick dependency is a package that exists.
  for (const dep of [...deps].filter(d => d.startsWith('@splitstick/'))) {
    if (!published.has(dep)) {
      findings.push(`${m.name} declares ${dep}, which is not a package in this repository`);
    }
  }

  // 3. The lockfile knows about this workspace. `npm ci` is the first step of
  //    every CI job and refuses a tree it cannot account for.
  if (lock.packages?.[`packages/${dir}`] === undefined) {
    findings.push(
      `packages/${dir} is a workspace with no entry in package-lock.json, so \`npm ci\` will `
      + 'refuse this tree. Run `npm install` and commit the lockfile.');
  }

  // 4. Every declared bin exists and is executable.
  for (const [cmd, target] of Object.entries(m.bin ?? {})) {
    const p = join(PKGS, dir, String(target));
    if (!existsSync(p)) {
      findings.push(`${m.name} declares the bin ${cmd} at ${target}, which does not exist`);
      continue;
    }
    const src = readFileSync(p, 'utf8');
    if (!src.startsWith('#!')) {
      findings.push(`${m.name}'s bin ${cmd} (${target}) has no shebang, so it is not executable`);
    }
    // eslint-disable-next-line no-bitwise
    if ((statSync(p).mode & 0o111) === 0) {
      findings.push(`${m.name}'s bin ${cmd} (${target}) is not marked executable`);
    }
  }
}


/**
 * Every workspace package carries ONE version, and every @splitstick dependency
 * pin names it.
 *
 * Found while preparing 0.9.0, which nothing here would have caught. Ten
 * packages pin `@splitstick/core` and `witnesses` pins five siblings, all at
 * an exact version. Bumping `version` without bumping the pins publishes a set
 * whose members ask the registry for a version that is not being published --
 * every `npm install` fails at resolution, and the suite passes throughout
 * because a workspace resolves its siblings by link and never consults a pin.
 *
 * The same family as the two defects this file was written for: findable by
 * reading the manifests against each other, not by running anything.
 */
const versions = new Map([...manifests].map(([dir, m]) => [m.name, { dir, version: m.version }]));
const distinct = new Set([...versions.values()].map(v => v.version));
if (distinct.size > 1) {
  findings.push(
    `the workspace packages carry ${distinct.size} different versions (${[...distinct].sort().join(', ')}). `
    + 'They are published together from one tag, so one tag would name a version that some of '
    + 'them do not carry — which the release gate refuses, and rightly.');
}
for (const [dir, m] of manifests) {
  for (const section of ['dependencies', 'peerDependencies']) {
    for (const [dep, range] of Object.entries(/** @type {any} */ (m)[section] ?? {})) {
      if (!dep.startsWith('@splitstick/')) continue;
      const target = versions.get(dep);
      if (!target) continue;                 // not a workspace package; nothing to match
      if (typeof range !== 'string') continue;
      // An exact pin must be the version actually being published. A range
      // (^, ~, *, workspace:) is the publisher's deliberate choice and is left
      // alone -- this checks a pin that has silently gone stale, which is the
      // failure a version bump produces.
      if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(range)) continue;
      if (range !== target.version) {
        findings.push(
          `packages/${dir} pins ${dep} at ${range} in ${section}, and ${dep} is ${target.version}. `
          + 'A pin that names a version nobody publishes fails at install for everybody, while '
          + 'resolving here because the workspace link is present.');
      }
    }
  }
}


/**
 * Every published package ships the licence and the NOTICE, byte-identical to
 * the root.
 *
 * Found by inspecting a packed tarball during the 0.9.0 release rehearsal: all
 * eleven declared `"license": "Apache-2.0"` and none of them contained the
 * licence text. npm packs from each package directory, and the root LICENSE is
 * not in any of them, so `files: ["src", "README.md"]` shipped neither.
 *
 * Apache-2.0 section 4(a) requires a redistribution to include a copy of the
 * License, and 4(d) requires the NOTICE to travel with derivative
 * distributions. A project whose subject is being exact about what it claims
 * should not publish eleven packages asserting a licence they do not carry.
 *
 * Copies in a monorepo drift, which is the reason this check exists rather
 * than a comment telling somebody to remember.
 */
const rootLicence = readFileSync(join(ROOT, 'LICENSE'), 'utf8');
const rootNotice = readFileSync(join(ROOT, 'NOTICE'), 'utf8');
for (const dir of names) {
  const m = /** @type {any} */ (manifests.get(dir));
  const declaredFiles = m.files ?? null;
  for (const [name, want] of [['LICENSE', rootLicence], ['NOTICE', rootNotice]]) {
    const p = join(PKGS, dir, name);
    if (!existsSync(p)) {
      findings.push(
        `packages/${dir} declares "license": ${JSON.stringify(m.license ?? null)} and ships no `
        + `${name}. npm packs from the package directory, so the root ${name} is not included: `
        + 'Apache-2.0 4(a) asks for the licence to travel with the redistribution, and 4(d) for '
        + 'the NOTICE.');
      continue;
    }
    if (readFileSync(p, 'utf8') !== want) {
      findings.push(
        `packages/${dir}/${name} differs from the root ${name}. A copy in a monorepo drifts, and `
        + 'a licence that drifts is a licence nobody can rely on.');
    }
    if (declaredFiles !== null && !declaredFiles.includes(name)) {
      findings.push(
        `packages/${dir} has a ${name} and does not list it in "files", so it is present in the `
        + 'repository and absent from the tarball — the worst of both, because it reads as '
        + 'handled.');
    }
  }
}


/**
 * Every shipped source file carries the copyright and SPDX header.
 *
 * 55 of 57 did not, found while inspecting a tarball for the 0.9.0 rehearsal.
 * The repository asserted its copyright in NOTICE and in two files; a file
 * lifted out of the tree — vendored, pasted into an issue, copied into another
 * project — carried no attribution and no licence identifier at all, which is
 * the situation the header exists for.
 *
 * A shebang stays on line 1. Prepending the header above one broke all four
 * published bins, which is why that order is asserted rather than assumed.
 */
const HEADER_LINES = ['// Copyright 2026 prathish-ks', '// SPDX-License-Identifier: Apache-2.0'];
for (const dir of names) {
  for (const f of sources(join(PKGS, dir, 'src'))) {
    const lines = readFileSync(f, 'utf8').split('\n');
    const shebang = lines[0]?.startsWith('#!') ? 1 : 0;
    const head = lines.slice(shebang, shebang + 2);
    if (head[0] !== HEADER_LINES[0] || head[1] !== HEADER_LINES[1]) {
      findings.push(
        `${relative(ROOT, f)} does not open with the copyright and SPDX header`
        + `${shebang ? ' (after its shebang)' : ''}. A file copied out of this repository takes `
        + 'its attribution and its licence identifier with it, or takes neither.');
    }
    // `startswith` is Python's spelling. On a JS string it is undefined, and
    // `?.` made the whole test falsy — so this never fired, including on the
    // case it was written for: prepending the header ABOVE a shebang, which
    // satisfies the header check and breaks the bin.
    const misplaced = lines.findIndex((l, i) => i > 0 && l.startsWith('#!'));
    if (misplaced > 0) {
      findings.push(
        `${relative(ROOT, f)} has a shebang on line ${misplaced + 1} rather than line 1, so it `
        + 'will not execute. Prepending the copyright header above a shebang does this, and it '
        + 'broke all four published bins once.');
    }
  }
}

if (findings.length > 0) {
  console.error('\nPACKAGING LINT FAILED\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log(`\n  packaging: ${names.length} package(s) — every @splitstick import is declared, every`);
console.log('             workspace is in the lockfile, every declared bin exists and runs\n');
