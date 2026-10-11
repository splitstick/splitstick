// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { evaluateGates, formatGates } from '../gates.mjs';

const plan = JSON.parse(fs.readFileSync('requirements/milestones.json', 'utf8'));

/**
 * The real assignment, as the harness declares it.
 * @type {[string, string, 'detected'|'undetected'][]}
 */
const SUITE = [
  ['A1', 'AC-1', 'detected'], ['A2', 'AC-1', 'detected'], ['A3', 'AC-1', 'detected'],
  ['B', 'AC-1', 'detected'], ['E', 'AC-1', 'detected'],
  ['C', 'AC-2', 'detected'], ['C2', 'AC-3', 'undetected'], ['C3', 'AC-3', 'detected'],
  ['D', 'AC-4', 'undetected'], ['D2', 'AC-4', 'detected'],
  ['F', 'AC-5', 'detected'], ['F2', 'AC-5', 'detected'], ['F3', 'AC-5', 'undetected'],
];
/**
 * @param {Record<string, 'detected'|'undetected'>} overrides keyed by attack id,
 *   or `<id>:w` for the witnessed run
 * @returns {import('../gates.mjs').Observation[]}
 */
const observed = (overrides = {}) => SUITE.map(([id, gate, expect]) => ({
  id, gate, expect, observed: overrides[id] ?? expect,
  // The three that only close with a second party. The witnessed run is what
  // M3a's gates read, and it is the harness's own declaration.
  expect_witnessed: /** @type {'detected'} */ ('detected'),
  observed_witnessed: overrides[`${id}:w`] ?? /** @type {'detected'} */ ('detected'),
}));

test('the gates the shipped milestones claim are held by observed detections', () => {
  const r = evaluateGates(plan, observed());
  assert.equal(r.unmet, 0);
  assert.deepEqual(r.due.map((g) => g.gate).sort(), ['AC-1', 'AC-2']);
  assert.deepEqual(r.due.find((g) => g.gate === 'AC-1')?.detected, ['A1', 'A2', 'A3', 'B', 'E']);
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
  const asIf = {
    milestones: plan.milestones.map((m) => (m.id === 'M3a' ? { ...m, shipped: true } : m)),
  };
  const r = evaluateGates(asIf, observed());
  const m3a = r.due.filter((g) => g.milestone === 'M3a');
  assert.deepEqual(m3a.map((g) => g.gate).sort(), ['AC-3', 'AC-4', 'AC-5']);
  assert.ok(m3a.every((g) => g.held));
  assert.ok(m3a.every((g) => g.evidence === 'witnessed'));
  assert.match(formatGates(r), /HELD with a witness configured/);
  // And the local run is unchanged: C2, D and F3 are still undetected from
  // files alone, which is the thing M3a never claimed to fix.
  assert.deepEqual(
    observed().filter((o) => o.observed !== 'detected').map((o) => o.id),
    ['C2', 'D', 'F3'],
  );
});

test('M3a gates do NOT hold on local evidence, which is why they declare witnessed', () => {
  // The honest half. If M3a's gates were evaluated from files alone they would
  // fail, and a reader comparing the harness output to the milestone's claim
  // deserves to be able to confirm that rather than take it on trust.
  const asIf = {
    milestones: plan.milestones.map(
      (m) => (m.id === 'M3a' ? { ...m, shipped: true, gate_evidence: /** @type {const} */ ('local') } : m),
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
  const asIf = {
    milestones: plan.milestones.map((m) => (m.id === 'M3a' ? { ...m, shipped: true } : m)),
  };
  const r = evaluateGates(asIf, observed({ 'F3:w': 'undetected' }));
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
  assert.ok(r.scheduled.some((s) => s.gate === 'AC-5' && s.milestone === 'M3a'));
  assert.ok(!r.due.some((g) => g.gate === 'AC-5'));
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
