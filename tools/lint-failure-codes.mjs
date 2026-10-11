// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The verifier may only say things the specification admits.
 *
 * M1 shipped ten failure codes that appeared in output and in no document —
 * invented while implementing and never added to the design's vocabulary. A
 * code is a verdict about someone's evidence; one that nothing documents is a
 * conclusion a reader cannot look up.
 *
 * It also shipped the opposite: `consistencyProof` and `verifyConsistency` were
 * implemented in merkle.mjs, tested over every split up to 17, and never called
 * by the verifier, so a later checkpoint that did not extend an earlier one went
 * unnoticed. A green suite cannot distinguish a capability that works from one
 * that is never reached.
 *
 * So spec/failure-codes.json is the source of truth, and this enforces:
 *
 *   1. every code the verifier emits is specified there
 *   2. every code whose milestone has been delivered IS emitted
 *   3. every delivered code is exercised by at least one test
 *   4. every delivered code is named in the design, so the prose stays honest
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const spec = JSON.parse(readFileSync('spec/failure-codes.json', 'utf8'));
const delivered = new Set(spec.delivered_milestones);

/** @param {string} dir @param {(f: string) => boolean} keep */
function walk(dir, keep) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path, keep));
    else if (keep(path)) out.push(path);
  }
  return out;
}

const read = (/** @type {string[]} */ files) => files.map(f => readFileSync(f, 'utf8')).join('\n');

/**
 * Whole-word containment. A substring test would let UNANCHORED_TAIL satisfy a
 * search for UNANCHORED, which it did on the first run of this lint — the check
 * reported nine gaps and silently excused a tenth.
 * @param {string} haystack @param {string} code
 */
const names = (haystack, code) => new RegExp(`\\b${code}\\b`).test(haystack);

const srcFiles = walk('packages', f => f.endsWith('.mjs') && f.includes('/src/'));
const testFiles = walk('packages', f => f.endsWith('.test.mjs'));
const designText = read(walk('design', f => f.endsWith('.md')));
const srcText = read(srcFiles);
const testText = read(testFiles);

/** Codes a module emits: `code: 'X'`. @param {string} text */
const emitted = (text) =>
  new Set([...text.matchAll(/code:\s*'([A-Z_]+)'/g)].map(m => /** @type {string} */ (m[1])));

const emittedCodes = emitted(srcText);
const specified = new Map(spec.codes.map((/** @type {any} */ c) => [c.code, c]));

/** @type {string[]} */
const errs = [];

// 1 — nothing undocumented reaches a reader.
for (const code of emittedCodes) {
  if (!specified.has(code)) {
    errs.push(`${code} is emitted by the verifier and specified in no document. `
      + 'Add it to spec/failure-codes.json with what a reader may conclude from it.');
  }
}

for (const [code, entry] of specified) {
  if (!delivered.has(entry.milestone)) {
    // Not yet due. But if it is already emitted, the file is stale.
    if (emittedCodes.has(code)) {
      errs.push(`${code} is emitted but spec/failure-codes.json schedules it for ${entry.milestone}; `
        + 'move it to a delivered milestone.');
    }
    continue;
  }
  // 2 — a delivered code that nothing emits is a specified behaviour with no
  // implementation, which is how the consistency proof went unused.
  if (!emittedCodes.has(code)) {
    errs.push(`${code} is specified for ${entry.milestone} (delivered) and the verifier never emits it.`);
  }
  // 3 — and one nothing tests is a behaviour nobody has seen happen.
  if (!names(testText, code)) {
    errs.push(`${code} is specified for ${entry.milestone} (delivered) and no test exercises it.`);
  }
  // 4 — the design prose is the thing a reader actually reads.
  if (!names(designText, code)) {
    errs.push(`${code} is specified for ${entry.milestone} (delivered) and named in no design element.`);
  }
  if (!['fail', 'inconclusive'].includes(entry.verdict)) {
    errs.push(`${code} has verdict ${JSON.stringify(entry.verdict)}; only fail and inconclusive exist.`);
  }
  if (!entry.conclusion || entry.conclusion.length < 20) {
    errs.push(`${code} has no conclusion text. "Verification failed" is useless on its own.`);
  }
}

if (errs.length) {
  process.stderr.write('\nFAILURE-CODE LINT FAILED\n\n');
  for (const e of errs) process.stderr.write(`  ${e}\n`);
  process.stderr.write(`\n  ${errs.length} finding(s).\n\n`);
  process.exit(1);
}

const due = [...specified.values()].filter((/** @type {any} */ c) => delivered.has(c.milestone));
const later = specified.size - due.length;
process.stdout.write(`\n  failure codes: ${due.length} delivered, all emitted, tested and documented;`
  + ` ${later} scheduled for later milestones\n\n`);
