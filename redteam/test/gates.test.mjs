// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { evaluateGates, formatGates } from '../gates.mjs';

const plan = JSON.parse(fs.readFileSync('requirements/milestones.json', 'utf8'));

/**
 * The real assignment, as the harness declares it. A fourth element is the
 * requirement that declares an attack out of scope, where there is one.
 * @type {[string, string, 'detected'|'undetected', string?][]}
 */
const SUITE = [
  ['A1', 'AC-1', 'detected'], ['A2', 'AC-1', 'detected'], ['A3', 'AC-1', 'detected'],
  ['B', 'AC-1', 'detected'], ['E', 'AC-1', 'detected'],
  ['C', 'AC-2', 'detected'], ['C2', 'AC-3', 'undetected'], ['C3', 'AC-3', 'detected'],
  ['D', 'AC-4', 'undetected'], ['D2', 'AC-4', 'detected'],
  ['F', 'AC-5', 'detected'], ['F2', 'AC-5', 'detected'], ['F3', 'AC-5', 'undetected'],
  ['G', 'AC-6', 'detected'],
  // The declared limit: a patched collector reporting a valid digest. It stays
  // undetected in BOTH runs, because a witness countersigns the record and
  // this attack is about the collector.
  ['G2', 'AC-6', 'undetected', 'SEC-11, FR-25 and DOC-10 (remote attestation, rejected by SCOPE-12)'],
  ['H', 'AC-7', 'detected'], ['H2', 'AC-7', 'detected'],
];
/**
 * @param {Record<string, 'detected'|'undetected'>} overrides keyed by attack id,
 *   or `<id>:w` for the witnessed run
 * @returns {import('../gates.mjs').Observation[]}
 */
const observed = (overrides = {}) => SUITE.map(([id, gate, expect, outOfScope]) => ({
  id, gate, expect, observed: overrides[id] ?? expect,
  // The three that only close with a second party. The witnessed run is what
  // M3a's gates read, and it is the harness's own declaration. A declared
  // limit stays undetected there too: a witness countersigns the record, and
  // the limit is about the collector.
  expect_witnessed: outOfScope ? expect : /** @type {'detected'} */ ('detected'),
  observed_witnessed: overrides[`${id}:w`]
    ?? (outOfScope ? expect : /** @type {'detected'} */ ('detected')),
  ...(outOfScope ? { out_of_scope: outOfScope } : {}),
}));

test('the gates the shipped milestones claim are held by observed detections', () => {
  const r = evaluateGates(plan, observed());
  assert.equal(r.unmet, 0);
  assert.deepEqual(r.due.map((g) => g.gate).sort(),
    ['AC-1', 'AC-2', 'AC-3', 'AC-4', 'AC-5', 'AC-6', 'AC-7']);
  assert.deepEqual(r.due.find((g) => g.gate === 'AC-1')?.detected, ['A1', 'A2', 'A3', 'B', 'E']);
  // M1's two are local; M3a's three are claimed in the configuration M3a
  // delivers, and the report says which is which.
  assert.deepEqual(
    r.due.filter((g) => g.evidence === 'local').map((g) => g.gate).sort(),
    ['AC-1', 'AC-2', 'AC-6', 'AC-7']);
  assert.deepEqual(
    r.due.filter((g) => g.evidence === 'witnessed').map((g) => g.gate).sort(),
    ['AC-3', 'AC-4', 'AC-5']);
});

test('a gate is NOT MET when any assigned attack went undetected in the run', () => {
  // The whole point: B declares itself detected, and the run says otherwise.
  // The old check read the declaration and would have reported HELD.
  const r = evaluateGates(plan, observed({ B: 'undetected' }));
  assert.equal(r.unmet, 1);
  assert.equal(r.due.find((g) => g.gate === 'AC-1')?.held, false);
  assert.deepEqual(r.due.find((g) => g.gate === 'AC-1')?.outstanding, ['B']);
});

test('one outstanding attack fails the class even when every simpler one passes', () => {
  // AC-5's F and F2 are detected; F3 is not. The class is not closed.
  const shipped = { milestones: [{ id: 'M3a', gate: ['AC-5'], shipped: true }] };
  const r = evaluateGates(shipped, observed());
  assert.equal(r.unmet, 1);
  assert.deepEqual(r.due[0]?.detected, ['F', 'F2']);
  assert.deepEqual(r.due[0]?.outstanding, ['F3']);
});

test('M3a shipped holds its gates on the WITNESSED run, and says which run that is', () => {
  const r = evaluateGates(plan, observed());
  const m3a = r.due.filter((g) => g.milestone === 'M3a');
  assert.deepEqual(m3a.map((g) => g.gate).sort(), ['AC-3', 'AC-4', 'AC-5']);
  assert.ok(m3a.every((g) => g.held));
  assert.ok(m3a.every((g) => g.evidence === 'witnessed'));
  assert.match(formatGates(r), /HELD with a witness configured/);
  // And the local run is unchanged: C2, D and F3 are still undetected from
  // files alone, which is the thing M3a never claimed to fix. G2 joins them
  // with M4 and is a different kind of entry — declared out of scope rather
  // than merely open — which the next assertion separates.
  assert.deepEqual(
    observed().filter((o) => o.observed !== 'detected').map((o) => o.id),
    ['C2', 'D', 'F3', 'G2'],
  );
  assert.deepEqual(
    observed().filter((o) => o.observed !== 'detected' && !o.out_of_scope).map((o) => o.id),
    ['C2', 'D', 'F3'],
    'the three M3a closes with a second party, as distinct from the one nothing closes',
  );
});

test('M3a gates do NOT hold on local evidence, which is why they declare witnessed', () => {
  // The honest half. Evaluated from files alone, M3a's gates fail — and a
  // reader comparing the harness output to the milestone's claim deserves to
  // confirm that rather than take it on trust.
  const asIf = {
    milestones: plan.milestones.map(
      (m) => (m.id === 'M3a' ? { ...m, gate_evidence: /** @type {const} */ ('local') } : m),
    ),
  };
  const r = evaluateGates(asIf, observed());
  assert.equal(r.unmet, 3);
  assert.deepEqual(
    r.due.filter((g) => g.milestone === 'M3a').flatMap((g) => g.outstanding).sort(),
    ['C2', 'D', 'F3'],
  );
});

test('a witnessed gate still fails when a witnessed attack goes undetected', () => {
  // Declaring `witnessed` must not become a way to pass. It selects which run
  // the gate reads; it does not lower the bar within that run.
  const r = evaluateGates(plan, observed({ 'F3:w': 'undetected' }));
  assert.equal(r.unmet, 1);
  const ac5 = r.due.find((g) => g.gate === 'AC-5');
  assert.equal(ac5?.held, false);
  assert.deepEqual(ac5?.outstanding, ['F3']);
});

test('gate_evidence defaults to local, so a milestone cannot get the witnessed run by omission', () => {
  const r = evaluateGates(
    { milestones: [{ id: 'MX', gate: ['AC-5'], shipped: true }] },
    observed(),
  );
  assert.equal(r.due[0]?.evidence, 'local');
  assert.equal(r.due[0]?.held, false, 'F3 is undetected locally');
});

test('a gate no attack exercises is not closed either', () => {
  const r = evaluateGates({ milestones: [{ id: 'MX', gate: ['AC-9'], shipped: true }] }, observed());
  assert.equal(r.unmet, 1);
  assert.equal(r.due[0]?.missing, true);
  assert.equal(r.due[0]?.held, false);
});

test('unshipped gates are listed as scheduled and are never due', () => {
  const r = evaluateGates(plan, observed());
  // M4 has not shipped, so its classes are scheduled and not evaluated.
  // M4 has shipped, so AC-6 and AC-7 are due rather than scheduled. The
  // assertion this replaces was correct until it was not, which is what a
  // milestone shipping means.
  assert.ok(r.due.some((g) => g.gate === 'AC-6' && g.milestone === 'M4'));
  assert.ok(r.due.some((g) => g.gate === 'AC-7' && g.milestone === 'M4'));
  assert.ok(!r.scheduled.some((s) => s.gate === 'AC-6' || s.gate === 'AC-7'));
});

test('the suite in this test matches the attacks the harness actually declares', () => {
  // Otherwise these assertions drift away from the harness and prove nothing.
  const src = fs.readFileSync('redteam/splitstick.mjs', 'utf8');
  for (const [id, gate, expect] of SUITE) {
    const re = new RegExp(`id: '${id}'[^}]*?gate: '${gate}'[^}]*?expect: '${expect}'`, 's');
    assert.match(src, re, `${id} is not declared as ${gate}/${expect} in the harness`);
  }
  const declared = src.match(/\bid: '[A-Z]\d?',/g) ?? [];
  assert.equal(declared.length, SUITE.length, 'the harness has an attack this test does not cover');
});

// ── declared non-coverage, added with M4's AC-6 ──────────────────────────────

const PLAN = { milestones: [{ id: 'MX', gate: ['AC-X'], shipped: true }] };

test('an attack declared out of scope does not fail the gate, and is reported', () => {
  const r = evaluateGates(PLAN, [
    { id: 'P', gate: 'AC-X', expect: 'detected', observed: 'detected' },
    {
      id: 'Q', gate: 'AC-X', expect: 'undetected', observed: 'undetected',
      out_of_scope: 'SEC-11 and DOC-10',
    },
  ]);
  const g = r.due.find((x) => x.gate === 'AC-X');
  assert.equal(g.held, true, '"we said we would not" is not "we tried and failed"');
  assert.deepEqual(g.detected, ['P']);
  assert.deepEqual(g.outstanding, []);
  assert.deepEqual(g.out_of_scope, [{ id: 'Q', declared_by: 'SEC-11 and DOC-10' }]);
  // And it is never silent: a HELD line with nothing beside it would read as a
  // fully closed class.
  assert.match(formatGates(r), /NOT CLOSED: Q, declared by SEC-11 and DOC-10/);
});

test('an undetected attack with NO declaration still fails the gate', () => {
  // The rule this module exists for. If the marker were optional in effect,
  // every inconvenient result could be quieted by omitting a field.
  const r = evaluateGates(PLAN, [
    { id: 'P', gate: 'AC-X', expect: 'undetected', observed: 'undetected' },
  ]);
  const g = r.due.find((x) => x.gate === 'AC-X');
  assert.equal(g.held, false);
  assert.deepEqual(g.outstanding, ['P']);
  assert.equal(r.unmet, 1);
});

test('a class exercised ONLY by declared limits is not closed', () => {
  // Otherwise a gate could be held by declaring away everything that tests it,
  // which is the inverse of evidence.
  const r = evaluateGates(PLAN, [
    { id: 'Q', gate: 'AC-X', expect: 'undetected', observed: 'undetected', out_of_scope: 'SEC-11' },
  ]);
  const g = r.due.find((x) => x.gate === 'AC-X');
  assert.equal(g.held, false);
  assert.equal(g.missing, true, 'nothing measured means nothing demonstrated');
});

test('a declared limit that turns out to be detected is reported as stale', () => {
  // Leaving the project claiming a weakness it no longer has is its own kind
  // of dishonesty, and the declaration is the thing that went out of date.
  const r = evaluateGates(PLAN, [
    { id: 'Q', gate: 'AC-X', expect: 'undetected', observed: 'detected', out_of_scope: 'SEC-11' },
  ]);
  const g = r.due.find((x) => x.gate === 'AC-X');
  assert.equal(g.held, false);
  assert.match(g.outstanding.join(' '), /declared out of scope, yet detected/);
});
