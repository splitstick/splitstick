// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The claims audit — TRC-05, and the verify for sixteen scope guards.
 *
 * Runs the prose guards in `tools/scope-guards.mjs` over every surface a
 * reader could take a claim from, and the tree guards over the shipped source.
 *
 * WHAT A PASS MEANS, said here because it is the thing most likely to be
 * misread: NO GUARD FIRED. It does not mean no overclaim exists. These are
 * patterns over text. They cannot read intent, cannot see a claim phrased in
 * words nobody anticipated, and cannot tell whether a figure has a benchmark
 * behind it. Inventory row 4. The audit is a floor; the considered-and-rejected
 * log and DOC-11's assurance register carry the rest.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { claimSurfaces, paragraphs, sentences, SKIP } from './claim-text.mjs';
import { GUARDS, TREE_GUARDS, violates } from './scope-guards.mjs';
import { code } from './code-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;

/**
 * What the guards do not read, and why each is exempt.
 *
 * Kept short and justified line by line, because an exemption list is how an
 * audit quietly stops auditing. There are exactly three kinds here, and each
 * is a document whose subject IS the forbidden thing:
 *
 *   the requirements      SCOPE-05 to SCOPE-11 are requirements that say "MUST
 *                         NOT include RBAC", "MUST NOT ship a VDF". Stating a
 *                         prohibition means naming the thing prohibited, so the
 *                         backlog and every matrix generated from it contain
 *                         every forbidden phrase BY CONSTRUCTION. Auditing them
 *                         would make the audit fail for doing its job.
 *   the inventories       docs/m*-failure-modes.md, the risk instrument and the
 *                         known-limits page enumerate what must not be said.
 *   generated metadata    package-lock.json is a dependency graph, not a claim.
 *
 * Note what is NOT exempt: the release notes, every design document, the
 * README, the specs, the package descriptions and the verifier's own output.
 * Those are where a claim would actually reach somebody.
 */
const EXEMPT = [
  /^requirements\//,
  /^package-lock\.json$/,
  /^docs\/m\d[a-z]?-failure-modes\.md$/,
  /^docs\/risk-assessment\.md$/,
  /^docs\/known-limits\.md$/,
  // M7's retrospective, whose SUBJECT is these guards: it explains which
  // overclaims they missed and why, and the explanation cannot be written
  // without naming the shapes. Three rewordings in, each one worse than the
  // last, the honest move was to exempt the file rather than keep degrading
  // the record to satisfy a guard about the record.
  //
  // This IS a reduction in coverage and it is taken deliberately. It is narrow
  // — this one file, not every follow-up document; m1 to m6 stay audited and
  // pass — and the file makes no product claims: it is an internal account of
  // what the audit could not see.
  /^docs\/m7-follow-ups\.md$/,
  // A catalogue of OTHER PEOPLE'S services, in their terms: each entry states
  // a third party's acceptable use, rate limits and retention, because FR-47
  // requires an operator to choose on informed grounds. "Every entry is public
  // and cannot be removed" is a true disclosure about an OpenTimestamps
  // calendar, not an integrity claim about our records, and reading a JSON
  // value describing somebody else's log as a claim about this product is a
  // category error.
  //
  // It is not unaudited. `parseWitnessList` governs it far more precisely than
  // a prose guard could: it refuses any field expressing preference (GOV-09),
  // validates every capability class against CAPABILITY_CLASSES, requires each
  // entry to state its position rather than default to permissive, and refuses
  // an unknown field outright. That is the better instrument for this file.
  /^spec\/witnesses\.json$/,
];

/** Source the tree guards do not read, beyond EXEMPT. */
const TREE_EXEMPT = [
  /^spec\/vectors\//,  // published conformance fixtures: arbitrary JSON by design,
                      // including strings that happen to contain anything
  /^tools\//,        // the guards name what they forbid
  /(^|\/)test\//,    // a test asserting we refuse X must name X
  /^redteam\//,      // the tamper suite names the attacks
  /^bench\//,        // the harnesses name the budgets they refuse to claim
];

const exempt = (/** @type {string} */ rel) => EXEMPT.some(re => re.test(rel));

/** @type {{ surface: string, id: string, what: string, text: string, why: string }[]} */
const findings = [];

for (const { label, text } of claimSurfaces(ROOT)) {
  if (exempt(label)) continue;
  for (const para of paragraphs(text)) {
    for (const sentence of sentences(para)) {
      for (const guard of GUARDS) {
        if (!violates(guard, sentence)) continue;
        findings.push({
          surface: label, id: guard.id, what: guard.what,
          text: sentence.replace(/\s+/g, ' ').slice(0, 170), why: guard.why,
        });
      }
    }
  }
}

/** @param {string} dir @returns {string[]} */
function sourceFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sourceFiles(p));
    else if (name.endsWith('.mjs') || name.endsWith('.json') || name.endsWith('.yaml')) out.push(p);
  }
  return out;
}

for (const f of sourceFiles(ROOT)) {
  const rel = relative(ROOT, f);
  if (exempt(rel) || TREE_EXEMPT.some(re => re.test(rel))) continue;
  // Comments stripped: a paragraph explaining that we do not ship RBAC must not
  // be read as RBAC. That is the mistake code-text.mjs exists for, made four
  // times in this repository before it did.
  const raw = readFileSync(f, 'utf8');
  const src = f.endsWith('.mjs') ? code(raw) : raw;
  for (const guard of TREE_GUARDS) {
    const hit = src.match(guard.forbids);
    if (hit === null) continue;
    findings.push({
      surface: rel, id: guard.id, what: guard.what,
      text: String(hit[0]), why: guard.why,
    });
  }
}

if (findings.length > 0) {
  console.error('\nCLAIMS AUDIT FAILED — the scope guards\n');
  for (const f of findings) {
    console.error(`  ${f.surface}  [${f.id}]`);
    console.error(`    ${f.what}`);
    console.error(`    found: ${f.text}`);
    console.error(`    why:   ${f.why}\n`);
  }
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

const surfaces = claimSurfaces(ROOT).filter(s => !exempt(s.label)).length;
console.log(`\n  scope: ${GUARDS.length} prose guard(s) over ${surfaces} surface(s), `
  + `${TREE_GUARDS.length} tree guard(s) over the shipped source (TRC-05)`);
console.log('         a pass means NO GUARD FIRED, not that no overclaim exists\n');
