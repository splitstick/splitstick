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

if (findings.length > 0) {
  console.error('\nPACKAGING LINT FAILED\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log(`\n  packaging: ${names.length} package(s) — every @splitstick import is declared, every`);
console.log('             workspace is in the lockfile, every declared bin exists and runs\n');
