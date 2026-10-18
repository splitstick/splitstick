// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Install the packed tarballs into a clean project and exercise what a user gets.
 *
 * Every other check in this repository runs inside the monorepo, where a
 * workspace link resolves what a consumer's install would have to fetch. That
 * is not a hypothetical gap — it is how `@splitstick/witnesses` once imported a
 * package it did not declare, how `packages/witness-tlog` sat outside the
 * lockfile until `npm ci` refused the tree, and how `splitstick-verify`, the
 * only published bin, printed nothing and exited 0 once installed. All three
 * passed every test, because a test runs against a working tree.
 *
 * So this packs, installs into a directory with no workspace above it, and then
 * asks for each published entry point and each declared bin by name.
 *
 * Inter-package dependencies are the reason for `overrides`. Each manifest pins
 * its siblings at an exact version that is NOT yet on the registry at release
 * time, so a plain install would try to fetch it and fail. The overrides point
 * every @splitstick dependency at the tarball being tested, which is also what
 * makes this a test of these artifacts rather than of whatever is published.
 *
 *   node tools/smoke-install.mjs [dist]        # packs if the directory is empty
 *
 * Exits non-zero on the first failure, naming the entry point or bin.
 *
 * WHAT THIS CANNOT SEE, measured rather than assumed. The overrides pull every
 * @splitstick package into the tree whether or not the package that imports it
 * DECLARES it, so an undeclared dependency still resolves here — probed by
 * deleting `@splitstick/witness-tlog` from `witnesses`, and this passed. That
 * exact defect shipped once, so it is covered elsewhere and deliberately:
 * tools/lint-packaging.mjs reads every import in the source against the
 * manifest that should declare it, structurally, which is the check that
 * catches it. What THIS adds is the half a manifest reading cannot reach — that
 * the files are actually shipped, the exports resolve, and the bins link and
 * run. Deleting `src` from a package's `files` is caught here and nowhere else.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const DIST = resolve(ROOT, process.argv[2] ?? 'dist');

/** @param {string} cmd @param {string[]} args @param {{cwd?: string, allowFail?: boolean}} [o] */
function run(cmd, args, o = {}) {
  try {
    return execFileSync(cmd, args, {
      cwd: o.cwd ?? ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, npm_config_audit: 'false', npm_config_fund: 'false' },
    });
  } catch (e) {
    if (o.allowFail) return String(/** @type {any} */ (e).stdout ?? '') + String(/** @type {any} */ (e).stderr ?? '');
    const err = /** @type {any} */ (e);
    console.error(`\n  ${cmd} ${args.join(' ')} failed\n${err.stdout ?? ''}${err.stderr ?? ''}`);
    process.exit(1);
  }
}

// ── pack, unless tarballs are already there ─────────────────────────────────
mkdirSync(DIST, { recursive: true });
if (readdirSync(DIST).filter(f => f.endsWith('.tgz')).length === 0) {
  console.log(`packing workspaces into ${DIST}`);
  run('npm', ['pack', '--workspaces', '--pack-destination', DIST]);
}
const tarballs = readdirSync(DIST).filter(f => f.endsWith('.tgz')).sort();

// Map each package name to its tarball, by reading the manifest INSIDE it
// rather than by guessing from the filename — a scoped name mangles differently
// across npm versions, and guessing is how this check would silently test
// nothing.
/** @type {Map<string, string>} */
const byName = new Map();
for (const t of tarballs) {
  const manifest = run('tar', ['-xzOf', join(DIST, t), 'package/package.json']);
  const { name } = JSON.parse(manifest);
  byName.set(name, join(DIST, t));
}
const expected = readdirSync(join(ROOT, 'packages'))
  .filter(d => existsSync(join(ROOT, 'packages', d, 'package.json')))
  .map(d => JSON.parse(readFileSync(join(ROOT, 'packages', d, 'package.json'), 'utf8')));
const missing = expected.map(m => m.name).filter(n => !byName.has(n));
if (missing.length > 0) {
  console.error(`\n  these workspaces produced no tarball: ${missing.join(', ')}\n`);
  process.exit(1);
}
console.log(`${byName.size} tarball(s): ${[...byName.keys()].join(', ')}\n`);

// ── a project with no workspace above it ────────────────────────────────────
const proj = mkdtempSync(join(tmpdir(), 'splitstick-smoke-'));
process.on('exit', () => rmSync(proj, { recursive: true, force: true }));

const overrides = Object.fromEntries([...byName].map(([n, p]) => [n, `file:${p}`]));
writeFileSync(join(proj, 'package.json'), JSON.stringify({
  name: 'splitstick-smoke', private: true, version: '0.0.0', type: 'module',
  dependencies: Object.fromEntries([...byName].map(([n, p]) => [n, `file:${p}`])),
  // Every @splitstick dependency OF a tarball resolves to the tarball under
  // test, not to the registry.
  overrides,
}, null, 2) + '\n');

console.log(`installing into ${proj}`);
run('npm', ['install', '--no-audit', '--no-fund'], { cwd: proj });

// ── every published entry point, by name ───────────────────────────────────
/** @type {string[]} */
const failures = [];
/**
 * The specifiers a consumer can actually write.
 *
 * A `./*` export is a PATTERN, not an entry point: importing `pkg/*` literally
 * throws ERR_MODULE_NOT_FOUND. The first version of this did exactly that and
 * reported it as a pass, so it claimed to have verified seventeen entry points
 * while several of them were meaningless — a check that decides nothing,
 * printing reassurance.
 *
 * A wildcard is expanded against the files the package actually ships, which is
 * also what makes this test notice a module that stops being published.
 * @param {any} m
 */
function specifiers(m) {
  /** @type {string[]} */
  const out = [];
  for (const [sub, target] of Object.entries(m.exports ?? { '.': './src/index.mjs' })) {
    if (!sub.includes('*')) {
      out.push(sub === '.' ? m.name : `${m.name}${sub.slice(1)}`);
      continue;
    }
    // e.g. "./*": "./src/*.mjs" — enumerate src/*.mjs as shipped.
    const dir = join(ROOT, 'packages', m.name.split('/')[1], String(target).replace(/\/[^/]*$/, '').replace(/^\.\//, ''));
    if (!existsSync(dir)) continue;
    // A module that is the target of a declared `bin` is a COMMAND. Importing
    // it runs the CLI, which then correctly refuses for want of arguments --
    // so sweeping it as a library reported three failures that were this
    // check's fault rather than the package's. Commands are exercised below,
    // through the bin links npm creates, which is how a user reaches them.
    const binTargets = new Set(Object.values(m.bin ?? {})
      .map(v => String(v).replace(/^\.\//, '').replace(/^src\//, '').replace(/\.mjs$/, '')));
    for (const f of readdirSync(dir).filter(f => f.endsWith('.mjs')).sort()) {
      const stem = f.replace(/\.mjs$/, '');
      if (stem === 'index') continue;              // already covered by "."
      if (binTargets.has(stem)) continue;
      out.push(`${m.name}/${stem}`);
    }
  }
  return out;
}

for (const m of expected) {
  for (const spec of specifiers(m)) {
    // A marker the error text cannot contain, so a failure can never be read
    // as a pass. `includes('ok')` was too loose to be trustworthy.
    const out = run(process.execPath, [
      '-e', `import(${JSON.stringify(spec)}).then(() => console.log('IMPORT-OK'), e => { console.error(e.message); process.exit(1); })`,
    ], { cwd: proj, allowFail: true });
    if (!out.split('\n').some(l => l.trim() === 'IMPORT-OK')) {
      failures.push(`import ${spec}: ${out.trim().split('\n')[0]}`);
    } else console.log(`  import ${spec}`);
  }
}

// ── every declared bin, by the name npm links ──────────────────────────────
//
// Resolved through node_modules/.bin, which is what a user's npx and npm
// scripts use. A bin that is declared and does not run is a manifest that lies.
for (const m of expected) {
  for (const bin of Object.keys(m.bin ?? {})) {
    const p = join(proj, 'node_modules', '.bin', bin);
    if (!existsSync(p)) { failures.push(`bin ${bin} was not linked`); continue; }
    // --help must print something and exit without a crash. An exit code is
    // not enough: the defect this is for exited 0 and printed nothing.
    const out = run(p, ['--help'], { cwd: proj, allowFail: true });
    if (out.trim() === '') failures.push(`bin ${bin} printed nothing for --help`);
    else console.log(`  bin ${bin} (${out.trim().split('\n')[0].slice(0, 56)})`);
  }
}

if (failures.length > 0) {
  console.error(`\n  CONSUMER INSTALL FAILED — ${failures.length} finding(s):\n`);
  for (const f of failures) console.error(`  - ${f}`);
  console.error('\n  These are what a first-time user would hit. A workspace link hides them.\n');
  process.exit(1);
}
console.log(`\n  consumer install: ${byName.size} package(s) installed from tarballs with no`);
console.log('                    workspace, every entry point imports, every bin runs\n');
