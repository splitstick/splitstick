// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * DOC-11's guard, broken on purpose.
 *
 * `tools/lint-assurance.mjs` shipped in M7 with four rules and no companion of
 * its own — it was probed by hand and then trusted. The review found the same
 * escape hatch the scope guards had: a bare `only` anywhere in the sentence
 * exempted a guarantee, so "It guarantees completeness, and only takes a
 * second" passed. That is the second instrument in this milestone to let an
 * exemption float free of the thing it exempts, which is why it now has a
 * test instead of a memory of being probed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { clauseAt } from '../tools/claim-text.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = readFileSync(join(ROOT, 'tools/lint-assurance.mjs'), 'utf8');

/** Read a pattern out of the lint, so the test cannot drift from what runs. */
const pattern = (/** @type {string} */ name) => {
  const m = new RegExp(`const ${name} = (/[^\\n]*/i);`).exec(SRC);
  assert.ok(m, `${name} is no longer a single-line regex in lint-assurance.mjs, so this test `
    + 'is reading something else. Update it deliberately rather than deleting it');
  // eslint-disable-next-line no-eval
  return /** @type {RegExp} */ (eval(String(m[1])));
};

const OVERCLAIM = pattern('OVERCLAIM');
const QUALIFIED = pattern('QUALIFIED');

/** The lint's rule 3, as the lint applies it. */
const overclaims = (/** @type {string} */ s) => {
  const hit = OVERCLAIM.exec(s);
  return hit !== null && !QUALIFIED.test(clauseAt(s, hit.index));
};

test('DOC-11: a guarantee with no limit attached is caught', () => {
  for (const s of [
    'Splitstick guarantees every action is recorded.',
    'The collector proves nothing was omitted.',
    'Coverage is verified end to end.',
    'It ensures no tool call escapes the record.',
    'Suppression is impossible once the collector is running.',
  ]) {
    assert.ok(overclaims(s), `not caught: ${s}`);
  }
});

test('DOC-11: an unrelated "only" does not rescue a guarantee', () => {
  // The review finding. `\bonly\b` is an adverb about anything, and it was
  // exempting guarantees that qualified nothing.
  for (const s of [
    'It guarantees completeness, and only takes a second.',
    'The collector guarantees nothing is missed — only configure it once.',
    'Splitstick proves the record is whole; only the operator can erase it.',
  ]) {
    assert.ok(overclaims(s), `an unrelated "only" shielded: ${s}`);
  }
});

test('DOC-11: a claim that names its limit in the same clause survives', () => {
  // The half that keeps the guard alive. Each of these is the project doing
  // exactly what DOC-11 asks.
  for (const s of [
    'Coverage is guaranteed only under non-exportable key custody.',
    'Without this, the field would prove only that some build ran.',
    'Every count is of what the collector reported.',
    'A self-reported digest is not remote attestation, and this release provides none.',
    'The receipt time is witness-asserted and unsigned.',
    'Key destruction is not externally verifiable, so we state the precondition.',
  ]) {
    assert.equal(overclaims(s), false, `wrongly caught: ${s}`);
  }
});

test('DOC-11: the register itself is well formed and classified', () => {
  // The register is the thing the lint checks the prose against, so a register
  // that had quietly lost its classes would make every check vacuous.
  const reg = JSON.parse(readFileSync(join(ROOT, 'spec/assurance-register.json'), 'utf8'));
  assert.equal(reg.version, 1);
  assert.ok(reg.claims.length >= 14, `only ${reg.claims.length} claims registered`);
  const classes = ['independent', 'operator-declared', 'none'];
  for (const c of reg.claims) {
    assert.ok(classes.includes(c.class), `${c.id}: class ${c.class}`);
    assert.ok(String(c.why).length > 40, `${c.id}: the reason is too short to be a reason`);
    assert.ok(String(c.evidence).length > 10, `${c.id}: names no evidence`);
  }
  // DOC-11 exists because claims drift towards the stronger class. If every
  // claim were `independent` the register would be decoration.
  const declared = reg.claims.filter((/** @type {any} */ c) => c.class !== 'independent');
  assert.ok(declared.length >= 5,
    `only ${declared.length} claims are operator-declared or unestablished, which is fewer than `
    + 'this threat model implies — the coverage claim, the build digest, key custody, key '
    + 'destruction, the witness receipt time and the eIDAS presumption are all in that category');
});
