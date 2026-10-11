// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { evaluateGates } from '../gates.mjs';

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
 * @param {Record<string, 'detected'|'undetected'>} overrides
 * @returns {import('../gates.mjs').Observation[]}
 */
const observed = (overrides = {}) => SUITE.map(([id, gate, expect]) => ({
  id, gate, expect, observed: overrides[id] ?? expect,
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

test('declaring M3a shipped today fails the gate, because its attacks are open', () => {
  // This is the assertion the review asked for by name. If someone marks M3a
  // shipped before building epoch erasure and the deletion receipt, this test
  // and the harness both refuse. If someone genuinely closes C2, D and F3,
  // this test is what tells them the claim is now earned.
  const asIf = {
    milestones: plan.milestones.map((m) => (m.id === 'M3a' ? { ...m, shipped: true } : m)),
  };
  const r = evaluateGates(asIf, observed());
  const m3a = r.due.filter((g) => g.milestone === 'M3a');
  assert.deepEqual(m3a.map((g) => g.gate).sort(), ['AC-3', 'AC-4', 'AC-5']);
  assert.ok(m3a.every((g) => !g.held), 'no M3a gate may hold on today\'s results');
  assert.deepEqual(
    m3a.flatMap((g) => g.outstanding).sort(),
    ['C2', 'D', 'F3'],
    'the three attacks M3a has to close are exactly the ones still outstanding',
  );
  assert.equal(r.unmet, 3);
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
