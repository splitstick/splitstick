import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pairedDifference, pairsNeededFor, verdictAgainst, clockResolution, environment } from '../precision.mjs';

test('a paired difference recovers a known offset', () => {
  const base = Array.from({ length: 200 }, (_, i) => 50 + Math.sin(i) * 5);
  const treatment = base.map(x => x + 3);
  const s = pairedDifference(base, treatment);
  assert.ok(Math.abs(s.mean_diff - 3) < 0.001);
  assert.ok(s.resolution < 0.001, 'a constant offset is resolved precisely');
  assert.equal(verdictAgainst(s, 5), 'within');
  assert.equal(verdictAgainst(s, 1), 'over');
});

/**
 * The property that matters: when the arms differ only by noise, the verdict
 * must be `unresolved` rather than a pass or a fail. Reporting noise as a
 * result is the mistake this module exists to prevent.
 */
test('noise is reported as unresolved, never as a pass or a saving', () => {
  let seed = 7;
  const rand = () => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed / 2 ** 31; };
  const base = Array.from({ length: 60 }, () => 50 + rand() * 20);
  const treatment = Array.from({ length: 60 }, () => 50 + rand() * 20);
  const s = pairedDifference(base, treatment);
  assert.equal(verdictAgainst(s, 0.5), 'unresolved',
    'a budget inside the interval cannot be declared met');
  assert.ok(s.ci95_low < 0 && s.ci95_high > 0, 'the interval straddles zero');
});

test('a difference clearly over budget is reported as over', () => {
  const base = Array.from({ length: 100 }, (_, i) => 50 + (i % 3));
  const treatment = base.map(x => x + 10);
  assert.equal(verdictAgainst(pairedDifference(base, treatment), 2), 'over');
});

test('the required sample size grows with variance and shrinks with the effect', () => {
  assert.ok(pairsNeededFor(10, 1) > pairsNeededFor(1, 1));
  assert.ok(pairsNeededFor(5, 0.5) > pairsNeededFor(5, 5));
  assert.equal(pairsNeededFor(5, 0), Infinity, 'no sample size resolves a zero effect');
  // Sanity: sd 4 ms, effect 2 ms -> about 16 pairs.
  assert.equal(pairsNeededFor(4, 2), 16);
});

test('a paired comparison refuses a sample too small to say anything', () => {
  assert.throws(() => pairedDifference([1], [2]), RangeError);
});

test('the clock is checked against what the benchmark reports', () => {
  const fine = clockResolution(1);
  assert.ok(fine.tick_ms >= 0);
  assert.equal(fine.adequate, true, 'hrtime must resolve far below a millisecond');
  // And it says so when the quantity is near the tick.
  assert.equal(clockResolution(fine.tick_ms).adequate, false);
});

test('the environment is recorded so a number is attributable', async () => {
  const env = await environment();
  for (const k of ['node', 'platform', 'arch', 'cpu', 'cpus', 'total_memory_gb']) {
    assert.ok(k in env, `missing ${k}`);
  }
  assert.match(env.node, /^v\d+/);
  assert.ok(env.cpus >= 1);
});
