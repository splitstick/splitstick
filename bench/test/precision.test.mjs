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
  for (const k of ['node', 'platform', 'arch', 'cpu', 'cpus', 'total_memory_gb',
    'load_average_1m', 'free_disk_gb']) {
    assert.ok(k in env, `missing ${k}`);
  }
  assert.match(env.node, /^v\d+/);
  assert.ok(env.cpus >= 1);
  // Real readings, not placeholders: a constraint evaluated against a sentinel
  // is not evaluated. free_disk_gb is NaN only when statfs itself failed, and
  // qualifyRun treats that as a shortfall rather than a pass.
  assert.equal(typeof env.free_disk_gb, 'number');
  assert.ok(Number.isFinite(env.free_disk_gb) && env.free_disk_gb > 0,
    `free_disk_gb should be a real reading on this host, got ${env.free_disk_gb}`);
  assert.ok(Number.isFinite(env.load_average_1m));
});

import { qualifyRun } from '../precision.mjs';
import { readFileSync } from 'node:fs';

const REF = JSON.parse(readFileSync(new URL('../reference-env.json', import.meta.url), 'utf8'));

const CI_MARKERS = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILDKITE', 'JENKINS_URL'];

/**
 * Run `fn` with the CI markers cleared. These tests assert what a QUALIFYING
 * host looks like, and the suite itself runs on a CI runner — which forbid_ci
 * correctly disqualifies. Without this the assertions would pass locally and
 * fail in CI, which is the wrong way round for a guard about environments.
 * @template T @param {() => T} fn
 */
const offCi = (fn) => {
  const saved = CI_MARKERS.map(k => /** @type {const} */ ([k, process.env[k]]));
  for (const k of CI_MARKERS) delete process.env[k];
  try { return fn(); } finally {
    for (const [k, v] of saved) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
};

/** A quiet, roomy host sampled before the run. */
const quiet = () => ({ cpus: 8, total_memory_gb: 32, load_average_1m: 0.2, free_disk_gb: 400 });

const ample = {
  requirement: 'NFR-01',
  before: quiet(),
  env: { ...quiet(), load_average_1m: 1.0 },   // the benchmark's own load, after the run
  events: 1_000_000, repeats: 3, clockAdequate: true,
  machine: 'bench-01, bare metal', storage: 'NVMe SSD, ext4, 40% full',
};

test('a fully specified run qualifies', () => {
  const r = offCi(() => qualifyRun(REF, ample));
  assert.deepEqual(r.shortfalls, []);
  assert.equal(r.qualifies, true);
});

/**
 * THE defect this file exists to prevent recurring. max_load_average_1m was
 * evaluated against a reading taken after the measured loop. A saturated
 * single-threaded benchmark drives its own one-minute load average to roughly
 * 1.0 and the limit is 1.0, so the constraint could not be satisfied on any
 * machine however dedicated — a gate that cannot pass, not a gate that is
 * strict. Its stated purpose is to exclude "a machine under other load"; it was
 * measuring this benchmark's load.
 *
 * A quiet machine whose load rises only because of the run must qualify.
 */
test('a quiet host whose load rises only because of the run still qualifies', () => {
  const r = offCi(() => qualifyRun(REF, {
    ...ample,
    before: { ...quiet(), load_average_1m: 0.04 },
    env: { ...quiet(), load_average_1m: 1.12 },   // the run itself, nothing else
  }));
  assert.deepEqual(r.shortfalls, [], 'the benchmark\'s own load must not disqualify it');
  assert.equal(r.qualifies, true);
});

test('pre-run load over the limit disqualifies, and says it was before the run', () => {
  const r = qualifyRun(REF, { ...ample, before: { ...quiet(), load_average_1m: 2.9 } });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(x => /load average 2\.9 > 1 before the run started/.test(x)),
    JSON.stringify(r.shortfalls));
});

/**
 * The companion the pre-run sample needs: it cannot see work that joins
 * midway. A climb larger than this single-threaded benchmark can account for
 * is other work, and must be named.
 */
test('load that climbs further than the run can account for is named', () => {
  const r = qualifyRun(REF, {
    ...ample,
    before: { ...quiet(), load_average_1m: 0.1 },
    env: { ...quiet(), load_average_1m: 6.4 },
  });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(x => /climbed 6\.3 during the run/.test(x)), JSON.stringify(r.shortfalls));
});

test('a missing post-run sample is a shortfall, not a pass', () => {
  const r = qualifyRun(REF, { ...ample, env: { ...quiet(), load_average_1m: Number.NaN } });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(x => /no post-run load average/.test(x)), JSON.stringify(r.shortfalls));
});

/**
 * An observation with no pre-run sample THROWS. Falling back to the post-run
 * reading is the original bug, so there is no fallback to fall into.
 */
test('qualifyRun refuses an observation with no pre-run host sample', () => {
  const { before, ...withoutBefore } = ample;
  assert.throws(() => qualifyRun(REF, /** @type {any} */ (withoutBefore)),
    /BEFORE the measured work/);
  const same = { ...quiet() };
  assert.throws(() => qualifyRun(REF, { ...ample, before: same, env: same }),
    /same object as both the before and after/,
    'one sample cannot serve as both');
});

/**
 * "a filesystem at or near capacity, which measurably slows file creation" was
 * declared in the excluded list and checked by nothing, while the file's own
 * note claimed every constraint here is evaluated.
 */
test('a filesystem near capacity disqualifies the run', () => {
  const r = qualifyRun(REF, { ...ample, before: { ...quiet(), free_disk_gb: 9 } });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(x => /9 GB free on the fixture volume < 20 GB/.test(x)),
    JSON.stringify(r.shortfalls));
});

test('an unreadable free-space reading is a shortfall, not a pass', () => {
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, undefined]) {
    const r = qualifyRun(REF, { ...ample, before: { ...quiet(), free_disk_gb: bad } });
    assert.equal(r.qualifies, false, String(bad));
    assert.ok(r.shortfalls.some(x => /could not be read/.test(x)), JSON.stringify(r.shortfalls));
  }
});

/** "a shared CI runner, where neighbours move the tail by a factor of two". */
test('a CI runner disqualifies the run', () => {
  const r = offCi(() => {
    process.env.GITHUB_ACTIONS = 'true';
    return qualifyRun(REF, ample);
  });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.some(x => /GITHUB_ACTIONS is set/.test(x)), JSON.stringify(r.shortfalls));
});

/**
 * NFR-04 was evaluated against NFR-01's min_events, so every NFR-04 run
 * reported "100000 events < 1000000" — a shortfall against a figure its own
 * requirement does not ask for.
 */
test('each requirement is held to its own event count', () => {
  const nfr04 = {
    ...ample, requirement: 'NFR-04', events: 100_000, repeats: 3,
  };
  const r = offCi(() => qualifyRun(REF, nfr04));
  assert.deepEqual(r.shortfalls, [], '100,000 events is what NFR-04 asks for');

  const short = qualifyRun(REF, { ...nfr04, events: 99_999 });
  assert.ok(short.shortfalls.some(x => /99999 events < 100000/.test(x)), JSON.stringify(short.shortfalls));

  const asNfr01 = qualifyRun(REF, { ...ample, events: 100_000 });
  assert.ok(asNfr01.shortfalls.some(x => /100000 events < 1000000/.test(x)),
    'NFR-01 still needs a million samples to have a tail');
});

test('a requirement the reference file does not declare throws', () => {
  assert.throws(() => qualifyRun(REF, { ...ample, requirement: 'NFR-99' }),
    /no constraint block for "NFR-99"/);
  const { requirement, ...unnamed } = ample;
  assert.throws(() => qualifyRun(REF, /** @type {any} */ (unnamed)),
    /was not told which requirement/);
});

/**
 * The unit tests above hand qualifyRun its observation, which is exactly why
 * the original defect was invisible: the guard was tested, the CALL SITE was
 * not. So assert the order in the benchmark sources themselves, and fail loudly
 * if the anchors cannot be found rather than silently checking nothing.
 */
test('both benchmarks sample the host before their measured work', () => {
  for (const [file, loopAnchor] of [
    ['../append.mjs', 'chainRuns.push(await arm(false))'],
    ['../verify.mjs', 'fixtures.push(await build(EVENTS))'],
  ]) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    const before = src.indexOf('const hostBefore = await environment()');
    const loop = src.indexOf(loopAnchor);
    const after = src.indexOf('const env = await environment()');
    assert.ok(before !== -1, `${file}: no pre-run environment() sample found`);
    assert.ok(loop !== -1, `${file}: measured-work anchor ${JSON.stringify(loopAnchor)} not found — `
      + 'this check can no longer locate its subject and must be repaired, not skipped');
    assert.ok(after !== -1, `${file}: no post-run environment() sample found`);
    assert.ok(before < loop, `${file}: the host is sampled after the measured work begins`);
    assert.ok(after > loop, `${file}: the attribution sample is taken before the work it attributes`);
  }
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
    requirement: 'NFR-01',
    before: { cpus: 2, total_memory_gb: 4, load_average_1m: 9, free_disk_gb: 3 },
    env: { cpus: 2, total_memory_gb: 4, load_average_1m: 9.4, free_disk_gb: 3 },
    events: 100, repeats: 1, clockAdequate: false,
  });
  assert.equal(r.qualifies, false);
  assert.ok(r.shortfalls.length >= 7, JSON.stringify(r.shortfalls));
  for (const needle of ['cpus', 'memory', 'load average', 'events', 'repeats', 'clock', 'GB free']) {
    assert.ok(r.shortfalls.some(s => s.includes(needle)), `${needle} not named`);
  }
});
