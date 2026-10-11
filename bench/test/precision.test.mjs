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

import { qualifyRun } from '../precision.mjs';
import { readFileSync } from 'node:fs';

const REF = JSON.parse(readFileSync(new URL('../reference-env.json', import.meta.url), 'utf8'));

const ample = {
  env: { cpus: 8, total_memory_gb: 32, load_average_1m: 0.2 },
  events: 1_000_000, repeats: 3, clockAdequate: true,
  machine: 'bench-01, bare metal', storage: 'NVMe SSD, ext4, 40% full',
};

test('a fully specified run qualifies', () => {
  const r = qualifyRun(REF, ample);
  assert.deepEqual(r.shortfalls, []);
  assert.equal(r.qualifies, true);
});

/**
 * Review finding: node_major_at_least was declared in the reference file and
 * never read. The check is now data-driven, so a constraint without an
 * evaluator throws instead of being silently skipped — a threshold the code
 * ignores reads as enforced and is not.
 */
test('every declared constraint is evaluated, or the run refuses to start', () => {
  assert.throws(() => qualifyRun({ ...REF, max_iowait_percent: 5 }, ample),
    /has no evaluator/, 'an unevaluated constraint must not pass silently');
});

test('node_major_at_least is enforced', () => {
  const r = qualifyRun({ ...REF, node_major_at_least: 999 }, ample);
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(s => /node .* older than 999/.test(s)), JSON.stringify(r.shortfalls));
});

/**
 * And the limit the review identified: cpus, memory and load cannot establish
 * that a machine is dedicated or that its storage is comparable, so an
 * acceptance run must name both. That makes the claim attributable rather than
 * verifiable, which is the honest ceiling for a benchmark describing its host.
 */
test('an acceptance run must name its machine and storage', () => {
  for (const missing of ['machine', 'storage']) {
    const observed = { ...ample, [missing]: undefined };
    const r = qualifyRun(REF, observed);
    assert.equal(r.qualifies, false, missing);
    assert.ok(r.shortfalls.some(s => s.includes(missing)), JSON.stringify(r.shortfalls));
  }
  const blank = qualifyRun(REF, { ...ample, storage: '   ' });
  assert.equal(blank.qualifies, false, 'whitespace is not an attestation');
});

test('each shortfall is named, so a near miss is actionable', () => {
  const r = qualifyRun(REF, {
    env: { cpus: 2, total_memory_gb: 4, load_average_1m: 9 },
    events: 100, repeats: 1, clockAdequate: false,
  });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.length >= 6, JSON.stringify(r.shortfalls));
  for (const needle of ['cpus', 'memory', 'load average', 'events', 'repeats', 'clock']) {
    assert.ok(r.shortfalls.some(s => s.includes(needle)), `${needle} not named`);
  }
});
