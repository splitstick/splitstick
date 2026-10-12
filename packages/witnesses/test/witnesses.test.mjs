import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  witnessesFromConfig, describeWitnessSet, defaultWitnessWarning,
  WitnessConfigError, WITNESS_TYPES, TIME_DISCIPLINE, DEFAULT_CALENDARS,
} from '../src/index.mjs';

const DEFAULT_CONFIG = readFileSync(
  new URL('../../../design/default-config.yaml', import.meta.url), 'utf8');

test('FR-48: the shipped default is a TSA plus an OpenTimestamps roll-up', () => {
  // Read from the canonical file, so this cannot drift from what ships.
  assert.match(DEFAULT_CONFIG, /type: rfc3161/);
  assert.match(DEFAULT_CONFIG, /type: opentimestamps, tier: rollup/);
  // Rekor is commented out, and the comment says why.
  assert.match(DEFAULT_CONFIG, /#.*type: rekor.*opt-in/);
  assert.match(DEFAULT_CONFIG, /FR-47/);
  // Neither default is operated by this project, which is the whole point: a
  // default that depends on us is not independence.
  assert.ok(!/splitstick\.(dev|io|com)/.test(DEFAULT_CONFIG.split('witnesses:')[1] ?? ''));
});

test('FR-48: the default does NOT close truncation, and the warning says so', () => {
  const warnings = defaultWitnessWarning();
  const w = warnings.find(x => /sequence state/.test(x));
  assert.ok(w, JSON.stringify(warnings, null, 1));
  assert.match(w, /NOT closed/);
  assert.match(w, /FR-17|FR-14/);
  // And it says the operator's way out is free, so the warning is actionable
  // rather than a disclaimer.
  assert.match(w, /both free/);
});

test('the built set reports what each class is covered by', () => {
  const set = witnessesFromConfig({
    witnesses: [
      { id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' },
      { id: 'ots', type: 'opentimestamps' },
      { id: 'log', type: 'rekor', url: 'https://rekor.internal.example' },
    ],
  });
  const d = describeWitnessSet(set);
  assert.deepEqual(d.classes.time, ['tsa']);
  assert.deepEqual(d.classes.existence.sort(), ['log', 'ots']);
  assert.deepEqual(d.classes.sequence, []);
  assert.equal(d.closes_truncation, false);
});

test('a set with a stateful witness does close truncation', () => {
  const stateful = {
    id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit() { throw new Error('not called'); },
  };
  const d = describeWitnessSet([stateful]);
  assert.equal(d.closes_truncation, true);
  assert.ok(!d.warnings.some(w => /NOT closed/.test(w)));
});

test('SEC-25: every witness type declares where its time comes from', () => {
  // A report that presented every countersignature as equally authoritative
  // about time would be misleading in the one direction that matters.
  for (const t of WITNESS_TYPES) {
    assert.ok(TIME_DISCIPLINE[t], `${t} declares no time discipline`);
  }
  // And the declarations are honest about their limits.
  assert.match(TIME_DISCIPLINE.opentimestamps, /[Nn]ot a clock at all/);
  assert.match(TIME_DISCIPLINE.rfc3161, /and no better/);
  const d = describeWitnessSet(witnessesFromConfig({
    witnesses: [{ id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' }],
  }));
  assert.match(d.time_discipline.tsa, /TSA's own clock/);
});

test('SEC-04: a single-witness set is flagged, because one honest witness means one', () => {
  const d = describeWitnessSet(witnessesFromConfig({
    witnesses: [{ id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' }],
  }));
  assert.ok(d.warnings.some(w => /SEC-04/.test(w) && /only while that one is/.test(w)),
    JSON.stringify(d.warnings, null, 1));
});

test('SCOPE-15: no witness at all is supported, and reported as establishing nothing', () => {
  const d = describeWitnessSet([]);
  assert.deepEqual(d.classes.sequence, []);
  assert.ok(d.warnings.some(w => /supported configuration/.test(w)
    && /log you anchor to yourself/.test(w)));
});

test('an unknown witness type is refused, never skipped', () => {
  // A misspelled type that quietly anchors to nothing would leave an operator
  // believing they were anchored, which is worse than a startup error.
  assert.throws(() => witnessesFromConfig({
    witnesses: [{ id: 'x', type: 'rfc-3161', url: 'https://x.example' }],
  }), (/** @type {any} */ e) => e instanceof WitnessConfigError && /silently shrank/.test(e.message));
  assert.throws(() => witnessesFromConfig({ witnesses: [{ id: '', type: 'rfc3161' }] }),
    WitnessConfigError);
});

test('the stateful witness is not built from config, and the error says what to do', () => {
  // It needs a transport the operator chooses and a key they hold; a config
  // file cannot supply either, and pretending otherwise would produce an
  // adapter that fails at the first submission.
  assert.throws(() => witnessesFromConfig({
    witnesses: [{ id: 'audit', type: 'splitstick', url: 'https://w.internal' }],
  }), (/** @type {any} */ e) => /witness-self/.test(e.message));
});

test('the default calendars are the project ones, named in one changeable place', () => {
  assert.ok(DEFAULT_CALENDARS.every(u => /^https:\/\/[ab]\.pool\.opentimestamps\.org$/.test(u)));
  const set = witnessesFromConfig({ witnesses: [{ id: 'ots', type: 'opentimestamps' }] });
  assert.equal(set[0].tier, 'rollup');
});
