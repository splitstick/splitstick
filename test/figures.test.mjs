// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * tools/lint-figures.mjs — the guard between an unsettled number and a
 * published fact (TRC-04, DOC-04).
 *
 * It had no test file while it was the only thing standing between an open
 * requirement and a MEASURED claim. It is now additionally the companion to a
 * deliberate relaxation — NFR-01's "defined reference environment" clause was
 * dropped in favour of attribution — and a relaxation whose companion guard has
 * never been exercised is a deletion with extra steps.
 *
 * Two of its checks exist because of defects found in it:
 *
 *   - it read `part\d+.json` only, and there is no part1.json, so 47
 *     requirements including FR-15 were invisible. An invisible id returns
 *     undefined from its status map, which is not equal to 'open', so a
 *     MEASURED row citing one passed.
 *   - absent was therefore treated as satisfied, which is the same shape as
 *     every other finding in this project's benchmark and release tooling.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';

const GUARD = new URL('../tools/lint-figures.mjs', import.meta.url).pathname;

/** @param {string[]} args */
function run(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [GUARD, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', d => { out += d; });
    p.stderr.on('data', d => { err += d; });
    p.on('close', code => resolve({ code, out, err, all: out + err }));
  });
}

const HEADING = '## Numbers we are signing up to';

/** A good NFR-01 acceptance result, as bench/append.mjs --json emits one. */
const GOOD_NFR01 = {
  requirement: 'NFR-01', kind: 'acceptance measurement', events: 1_000_000, repeats: 3,
  machine: 'bench-01, bare metal', storage: 'NVMe SSD, ext4, 40% full',
  host_disclosures: [],
  budget: { p95_ms: 1, p99_ms: 3, p99_stretch_ms: 1 },
  arms: { full: { worst_p95_ms: 0.7587, worst_p99_ms: 2.6065 } },
  verdict: { p95: 'within', p99: 'within', p99_stretch: 'not met' },
};

/** A good NFR-04 acceptance result, as bench/verify.mjs --json emits one. */
const GOOD_NFR04 = {
  requirement: 'NFR-04', kind: 'acceptance', events: 100_000, repeats: 3,
  machine: 'bench-01, bare metal', storage: 'NVMe SSD, ext4, 40% full',
  host_disclosures: [],
  budget_ms: 30_000,
  verify_ms: { median: 13_650, worst: 14_230 },
  within_budget: true,
};

/** A good NFR-02 acceptance result, as bench/run-latency.mjs --json emits one. */
const GOOD_NFR02 = {
  requirement: 'NFR-02', kind: 'acceptance', events: 24, repeats: 1,
  machine: 'bench-01, bare metal', storage: null,
  budget_percent: 2,
  added_end_to_end_percent_ci_high: 0.29,
  verdict_end_to_end: 'WITHIN BUDGET',
  added_direct_percent_ci_high: 0.16,
  verdict_direct: 'WITHIN BUDGET',
  denominator_ms: 2725,
  added_direct: { mean_ms: 3.03 },
};

/**
 * The published figures are annotated with the evidence field each one quotes,
 * so the guard reads the PROSE rather than a constant inside itself. A markdown
 * comment renders invisibly and sits beside the number it binds.
 * @param {{ e2e?: string, direct?: string, denom?: string, directMs?: string }} [o]
 */
const nfr02Row = (o = {}) => '| **below ' + (o.e2e ?? '0.29')
  + '%**<!--=added_end_to_end_percent_ci_high--> | added end-to-end run latency (NFR-02) '
  + '| **MEASURED**, denominator ' + (o.denom ?? '2725') + '<!--=denominator_ms--> ms, journal ops '
  + (o.directMs ?? '3.03') + '<!--=added_direct.mean_ms--> ms below '
  + (o.direct ?? '0.16') + '%<!--=added_direct_percent_ci_high--> '
  + '| `bench/run-latency.mjs`, `bench/results/nfr-02.json` |';
const NFR02_ROW = nfr02Row();

const NFR01_ROW = '| **p99 2.61 ms** | append overhead (NFR-01) | **MEASURED** | '
  + '`bench/append.mjs`, `bench/results/nfr-01.json` |';
const NFR04_ROW = '| **14.2 s** | offline verification (NFR-04) | **MEASURED** | '
  + '`bench/verify.mjs`, `bench/results/nfr-04.json` |';

/**
 * A fixture world: a notes file, a requirements directory, and a root the
 * cited benchmark and result paths resolve against.
 * @param {{ rows: string[], reqs?: any[], resolved?: any[],
 *           results?: Record<string, any>, files?: string[] }} o
 */
function world(o) {
  const dir = mkdtempSync(join(tmpdir(), 'ss-fig-'));
  const reqs = join(dir, 'requirements');
  mkdirSync(reqs, { recursive: true });
  writeFileSync(join(reqs, 'backlog.json'),
    JSON.stringify({ requirements: o.reqs ?? [] }));
  if (o.resolved !== undefined) {
    writeFileSync(join(reqs, 'backlog.resolved.json'),
      JSON.stringify({ count: o.resolved.length, requirements: o.resolved }));
  }
  const notes = join(dir, 'notes.md');
  writeFileSync(notes, [
    '# notes', '', HEADING, '',
    '| Figure | What | Evidence | Benchmark |',
    '|---|---|---|---|',
    ...o.rows,
    '', '## after', '',
  ].join('\n'));
  for (const rel of o.files ?? []) {
    mkdirSync(join(dir, dirname(rel)), { recursive: true });
    writeFileSync(join(dir, rel), '// a benchmark\n');
  }
  for (const [rel, body] of Object.entries(o.results ?? {})) {
    mkdirSync(join(dir, dirname(rel)), { recursive: true });
    writeFileSync(join(dir, rel), JSON.stringify(body));
  }
  return {
    args: ['--notes', notes, '--requirements', reqs, '--root', dir],
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const req = (/** @type {string} */ id, /** @type {string} */ status) =>
  ({ id, title: `${id} title`, release: '1.0', status });

test('an honest table of figures passes', async () => {
  const w = world({
    rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: { 'bench/results/nfr-01.json': GOOD_NFR01 },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 0, r.all);
  } finally { w.cleanup(); }
});

test('a row with no evidence class is refused', async () => {
  const w = world({ rows: ['| **9 ms** | something (NFR-01) | fast | `bench/append.mjs` |'] });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /carries no evidence class/);
  } finally { w.cleanup(); }
});

test('a MEASURED figure citing a benchmark that does not exist is refused', async () => {
  const w = world({
    rows: ['| **1 ms** | x (NFR-03) | **MEASURED** | `bench/nope.mjs` |'],
    reqs: [req('NFR-03', 'done')],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /cites bench\/nope\.mjs, which does not exist/);
  } finally { w.cleanup(); }
});

test('a MEASURED figure citing an OPEN requirement is refused', async () => {
  const w = world({
    rows: ['| **1 ms** | x (NFR-02) | **MEASURED** | `bench/append.mjs` |'],
    reqs: [req('NFR-02', 'open')],
    files: ['bench/append.mjs'],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /published as MEASURED while NFR-02 is still open/);
  } finally { w.cleanup(); }
});

/**
 * The defect: ids the guard could not find returned undefined, which is not
 * equal to 'open', so the row passed. Absent is not satisfied.
 */
test('a MEASURED figure citing an id the guard cannot find is refused, not passed', async () => {
  // FR-01 makes the FR family known to the guard; FR-15 is in neither the
  // loaded files nor the resolved merge, so it is an id the guard cannot
  // resolve rather than one it failed to read.
  const w = world({
    rows: ['| **1 ms** | x (FR-15) | **MEASURED** | `bench/append.mjs` |'],
    reqs: [req('FR-01', 'done')],
    resolved: [req('FR-01', 'done')],
    files: ['bench/append.mjs'],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'an unresolvable requirement id must not pass');
    assert.match(r.all, /cites FR-15, which this guard could not find/);
  } finally { w.cleanup(); }
});

/**
 * The id pattern was /\b([A-Z]{3,5}-\d{2})\b/ — three to five letters, two
 * digits. FR and RM are two letters, so 79 of the backlog's 210 ids could not
 * match it: every FR, the largest family, and every RM. The headline check
 * could not fire for 38% of the backlog, and no test noticed because every
 * fixture used NFR ids.
 */
test('every requirement family is visible to the open-requirement check', async () => {
  for (const id of ['FR-15', 'RM-01', 'NFR-02', 'SCOPE-16', 'TRC-04', 'PRIV-01']) {
    const w = world({
      rows: [`| **1 ms** | x (${id}) | **MEASURED** | \`bench/append.mjs\` |`],
      reqs: [req(id, 'open')],
      files: ['bench/append.mjs'],
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, `${id} was not checked at all`);
      assert.match(r.all, new RegExp(`MEASURED while ${id} is still open`));
    } finally { w.cleanup(); }
  }
});

test('a string that only looks id-shaped is not mistaken for a requirement', async () => {
  const w = world({
    rows: ['| **AES-256** | content encryption (PRIV-01) | **MEASURED** | `bench/append.mjs` |'],
    reqs: [req('PRIV-01', 'done')],
    files: ['bench/append.mjs'],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 0, `AES-256 was treated as a requirement id: ${r.all}`);
  } finally { w.cleanup(); }
});

test('a backlog the guard cannot fully see is reported', async () => {
  const w = world({
    rows: ['| **10 s** | x | **TARGET** | `bench/append.mjs` |'],
    reqs: [req('NFR-02', 'done')],
    resolved: [req('NFR-02', 'done'), req('FR-15', 'open')],
    files: ['bench/append.mjs'],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /did not read FR-15/);
  } finally { w.cleanup(); }
});

// ---- the companion checks for the NFR-01 relaxation ----

test('an attributed requirement published as MEASURED must cite its run result', async () => {
  const w = world({
    rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs` |'],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'naming the harness is not naming the run');
    assert.match(r.all, /must cite its run result under/);
  } finally { w.cleanup(); }
});

test('a regression metric may not back a MEASURED figure', async () => {
  const w = world({
    rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: { 'bench/results/nfr-01.json': { ...GOOD_NFR01, kind: 'regression metric' } },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /reports kind "regression metric"/);
  } finally { w.cleanup(); }
});

test('evidence that does not name its machine or storage is refused', async () => {
  for (const missing of ['machine', 'storage']) {
    const body = { ...GOOD_NFR01, [missing]: '   ' };
    const w = world({
      rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
      reqs: [req('NFR-01', 'done')],
      files: ['bench/append.mjs'],
      results: { 'bench/results/nfr-01.json': body },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, missing);
      assert.match(r.all, new RegExp(`does not name its ${missing}`));
    } finally { w.cleanup(); }
  }
});

test('evidence short of the event or repeat count is refused', async () => {
  for (const [patch, re] of [
    [{ events: 20_000 }, /reports 20000 events, fewer than the 1000000/],
    [{ repeats: 1 }, /reports 1 repeat\(s\), fewer than 3/],
  ]) {
    const w = world({
      rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
      reqs: [req('NFR-01', 'done')],
      files: ['bench/append.mjs'],
      results: { 'bench/results/nfr-01.json': { ...GOOD_NFR01, .../** @type {any} */ (patch) } },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, JSON.stringify(patch));
      assert.match(r.all, /** @type {RegExp} */ (re));
    } finally { w.cleanup(); }
  }
});

test('evidence with no host_disclosures array is refused: silence is not an empty list', async () => {
  const { host_disclosures, ...withoutDisclosures } = GOOD_NFR01;
  const w = world({
    rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: { 'bench/results/nfr-01.json': withoutDisclosures },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /carries no host_disclosures array/);
  } finally { w.cleanup(); }
});

test('a figure whose conditions were short still passes, because they are disclosed', async () => {
  // The point of the relaxation: a measurement from an imperfect host is
  // publishable precisely BECAUSE the shortfalls travel with it.
  const w = world({
    rows: ['| **p99 1.04 ms** | append overhead (NFR-01) | **MEASURED** | `bench/append.mjs`, `bench/results/nfr-01.json` |'],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: {
      'bench/results/nfr-01.json': {
        ...GOOD_NFR01,
        host_disclosures: ['load average 2.34 > 1 before the run started'],
      },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 0, r.all);
  } finally { w.cleanup(); }
});

// ---- the guard must not pass over nothing ----

test('a missing notes file is refused, not reported clean', async () => {
  const r = await run(['--notes', join(tmpdir(), 'ss-fig-absent-notes.md')]);
  assert.equal(r.code, 2);
  assert.match(r.all, /does not exist/);
});

test('an unrecognised flag is refused', async () => {
  const r = await run(['--notez', 'x']);
  assert.equal(r.code, 2);
  assert.match(r.all, /is not a flag this reads/);
});

test('the real release notes pass this guard', async () => {
  const r = await run([]);
  assert.equal(r.code, 0, r.all);
});

// ---- the outcome, not only the qualification (PR #16 review, P1) ----

/**
 * The checks above establish that evidence EXISTS and is QUALIFIED: right
 * kind, named machine, enough events and repeats, disclosures present. None of
 * them asked whether the number in it PASSED.
 *
 * Reproduced on the committed evidence before fixing: setting
 * verify_ms.worst to 45000 and within_budget to false, against a 30,000 ms
 * budget, satisfied every check — so the figures table could go on calling
 * NFR-04 MEASURED while the evidence it cited reported a miss. Evidence being
 * present is not evidence establishing the claimed result, which is the
 * principle this project applies everywhere else.
 */
test('qualified evidence that MISSES its budget is refused — NFR-04', async () => {
  const w = world({
    rows: [NFR04_ROW],
    reqs: [req('NFR-04', 'done')],
    files: ['bench/verify.mjs'],
    results: {
      'bench/results/nfr-04.json': {
        ...GOOD_NFR04, verify_ms: { median: 44_000, worst: 45_000 }, within_budget: false,
      },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'a figure citing a failed measurement must not pass');
    assert.match(r.all, /elapsed on the worst run of 45000 ms against a budget of 30000 ms/);
    assert.match(r.all, /reports a MISS/);
  } finally { w.cleanup(); }
});

test('qualified evidence that MISSES its budget is refused — NFR-01, both percentiles', async () => {
  for (const [patch, re] of [
    [{ worst_p95_ms: 1.4, worst_p99_ms: 2.6065 }, /p95 on the worst repeat of 1\.4 ms against a budget of 1 ms/],
    [{ worst_p95_ms: 0.7587, worst_p99_ms: 9.5 }, /p99 on the worst repeat of 9\.5 ms against a budget of 3 ms/],
  ]) {
    const w = world({
      rows: [NFR01_ROW],
      reqs: [req('NFR-01', 'done')],
      files: ['bench/append.mjs'],
      results: {
        'bench/results/nfr-01.json': {
          ...GOOD_NFR01, arms: { full: /** @type {any} */ (patch) },
        },
      },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, JSON.stringify(patch));
      assert.match(r.all, /** @type {RegExp} */ (re));
    } finally { w.cleanup(); }
  }
});

/**
 * The verdict LABELS in the evidence are not trusted. A file whose numbers
 * pass but whose harness called it a miss is a disagreement between the
 * harness and this guard, and a disagreement is a finding rather than
 * something to resolve in favour of whichever is more convenient.
 */
test('the stored verdict label must agree with the recomputation', async () => {
  const w = world({
    rows: [NFR01_ROW],
    reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: {
      'bench/results/nfr-01.json': {
        ...GOOD_NFR01, verdict: { ...GOOD_NFR01.verdict, p99: 'over' },
      },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /reports verdict\.p99 = "over" rather than "within"/);
  } finally { w.cleanup(); }
});

test('within_budget false is refused even when the numbers would pass', async () => {
  const w = world({
    rows: [NFR04_ROW],
    reqs: [req('NFR-04', 'done')],
    files: ['bench/verify.mjs'],
    results: { 'bench/results/nfr-04.json': { ...GOOD_NFR04, within_budget: false } },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /reports within_budget = false rather than true/);
  } finally { w.cleanup(); }
});

/**
 * The budget is held by the guard, not read from the evidence. Comparing a
 * measurement against a budget the same file declares is not a check — this
 * was not in the review, and it would have defeated the fix for what was.
 */
test('evidence cannot supply its own budget', async () => {
  const w = world({
    rows: [NFR04_ROW],
    reqs: [req('NFR-04', 'done')],
    files: ['bench/verify.mjs'],
    results: {
      'bench/results/nfr-04.json': {
        ...GOOD_NFR04, budget_ms: 999_999,
        verify_ms: { median: 890_000, worst: 900_000 }, within_budget: true,
      },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'a file that raises its own budget must not pass');
    assert.match(r.all, /declares budget_ms = 999999, but NFR-04's budget/);
  } finally { w.cleanup(); }
});

test('an unreadable measurement is not a passing one', async () => {
  for (const bad of [undefined, null, 'fast', Number.NaN]) {
    const w = world({
      rows: [NFR04_ROW],
      reqs: [req('NFR-04', 'done')],
      files: ['bench/verify.mjs'],
      results: {
        'bench/results/nfr-04.json': {
          ...GOOD_NFR04, verify_ms: { median: 13_650, worst: bad },
        },
      },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, String(bad));
      assert.match(r.all, /no finite verify_ms\.worst/);
    } finally { w.cleanup(); }
  }
});

test('an NFR-04 figure backed by a passing measurement still passes', async () => {
  const w = world({
    rows: [NFR04_ROW],
    reqs: [req('NFR-04', 'done')],
    files: ['bench/verify.mjs'],
    results: { 'bench/results/nfr-04.json': GOOD_NFR04 },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 0, r.all);
  } finally { w.cleanup(); }
});

/** The committed evidence must itself establish the figures it backs. */
test('the real committed evidence establishes both published figures', async () => {
  const r = await run([]);
  assert.equal(r.code, 0, r.all);
  for (const rel of ['bench/results/nfr-01-append.json', 'bench/results/nfr-04-verify.json']) {
    const d = JSON.parse(readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8'));
    assert.ok(Array.isArray(d.host_disclosures), `${rel} carries its disclosures`);
    assert.ok(typeof d.machine === 'string' && d.machine.trim() !== '', `${rel} names its machine`);
  }
});

/**
 * NFR-02's budget is a PERCENTAGE, so the limit is checked in percent and the
 * measured figure is the UPPER BOUND of the interval — the requirement is met
 * only if the whole interval clears 2%, not if the point estimate does.
 */
test('NFR-02 is checked on the whole interval, in percent', async () => {
  const ok = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': GOOD_NFR02 },
  });
  try {
    assert.equal((await run(ok.args)).code, 0, 'a passing interval must pass');
  } finally { ok.cleanup(); }

  // A point estimate under budget with the interval over it must NOT pass.
  const over = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': { ...GOOD_NFR02, added_direct_percent_ci_high: 3.4 } },
  });
  try {
    const r = await run(over.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /whole interval of 3\.4 % against a budget of 2 %/);
  } finally { over.cleanup(); }
});

/**
 * Its verdict field is the DIRECT one. The paired wall-clock difference on the
 * same runs reports UNRESOLVED, so checking that field would refuse a
 * requirement its own evidence establishes.
 */
test('NFR-02 is judged on the direct verdict, not the paired one', async () => {
  const w = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: {
      'bench/results/nfr-02.json': {
        ...GOOD_NFR02, verdict: 'UNRESOLVED', verdict_direct: 'WITHIN BUDGET',
      },
    },
  });
  try {
    assert.equal((await run(w.args)).code, 0,
      'an unresolved PAIRED verdict must not block a figure the direct measure establishes');
  } finally { w.cleanup(); }

  const bad = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': { ...GOOD_NFR02, verdict_direct: 'UNRESOLVED' } },
  });
  try {
    const r = await run(bad.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /verdict_direct = "UNRESOLVED"/);
  } finally { bad.cleanup(); }
});

test('NFR-02 still has to name its machine, and cannot set its own budget', async () => {
  for (const [patch, re] of [
    [{ machine: '   ' }, /does not name its machine/],
    [{ budget_percent: 99 }, /declares budget_percent = 99/],
  ]) {
    const w = world({
      rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
      files: ['bench/run-latency.mjs'],
      results: { 'bench/results/nfr-02.json': { ...GOOD_NFR02, .../** @type {any} */ (patch) } },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, JSON.stringify(patch));
      assert.match(r.all, /** @type {RegExp} */ (re));
    } finally { w.cleanup(); }
  }
});

/**
 * bench/run-latency.mjs has no reference-environment gate, so it has nothing to
 * disclose. Requiring the array would require it to publish an empty one, and
 * an empty list claims "nothing was short" about a check never run.
 */
test('NFR-02 is exempt from host_disclosures, and the exemption is declared', async () => {
  const { host_disclosures, ...withoutDisclosures } = { ...GOOD_NFR02, host_disclosures: [] };
  const w = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': withoutDisclosures },
  });
  try {
    assert.equal((await run(w.args)).code, 0, r => r);
  } finally { w.cleanup(); }

  // But NFR-01 is NOT exempt, so the exemption is per-requirement and not a
  // weakening of the check itself.
  const nfr01 = world({
    rows: [NFR01_ROW], reqs: [req('NFR-01', 'done')],
    files: ['bench/append.mjs'],
    results: { 'bench/results/nfr-01.json': (() => {
      const { host_disclosures, ...rest } = GOOD_NFR01; return rest;
    })() },
  });
  try {
    const r = await run(nfr01.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /carries no host_disclosures array/);
  } finally { nfr01.cleanup(); }
});

// ── PR #18 review ───────────────────────────────────────────────────────────

/**
 * P2. The release notes, the requirement's evidence and the PR description
 * each quoted a DIFFERENT run: 0.088% beside a measured 0.0931%, 2.33 ms
 * beside 2.4269 ms, a 2,624 ms denominator beside 2,608 ms. Every number came
 * from a real measurement; none came from the one that shipped as the
 * evidence, because the file was regenerated after the prose was written.
 *
 * The budget OUTCOME was checked and the numerals were not, so it passed.
 */
test('a published number that is not the measured one is refused', async () => {
  for (const [patch, re] of [
    [{ added_end_to_end_percent_ci_high: 0.0931 }, /publishes 0\.29 for added_end_to_end_percent_ci_high/],
    [{ denominator_ms: 2608.019 }, /publishes 2725 for denominator_ms/],
    [{ added_direct: { mean_ms: 2.4269 } }, /publishes 3\.03 for added_direct\.mean_ms/],
  ]) {
    const w = world({
      rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
      files: ['bench/run-latency.mjs'],
      results: { 'bench/results/nfr-02.json': { ...GOOD_NFR02, .../** @type {any} */ (patch) } },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, JSON.stringify(patch));
      assert.match(r.all, /** @type {RegExp} */ (re));
      assert.match(r.all, /how a number outlives the run that produced it/);
    } finally { w.cleanup(); }
  }
});

test('a figure is judged at the precision it is quoted at, not to the last digit', async () => {
  // The declared quote is 0.29. A measurement of 0.2871 IS that number to two
  // places and must pass -- refusing it would force every published figure to
  // carry four decimals. A measurement of 0.284 is not, and must not.
  for (const [measured, shouldPass] of /** @type {[number, boolean][]} */ ([
    [0.2871, true], [0.2949, true], [0.284, false], [0.296, false],
  ])) {
    const w = world({
      rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
      files: ['bench/run-latency.mjs'],
      results: {
        'bench/results/nfr-02.json': { ...GOOD_NFR02, added_end_to_end_percent_ci_high: measured },
      },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, shouldPass ? 0 : 1,
        `${measured} should ${shouldPass ? 'pass' : 'fail'} against a published 0.29: ${r.all.slice(0, 200)}`);
    } finally { w.cleanup(); }
  }
});

/**
 * P2. Closing NFR-02 on the direct journal-operation measure alone established
 * a NARROWER property than its statement claims -- it excludes work outside an
 * append or close call. The end-to-end measure is the verdict; the direct one
 * is corroboration, and both are checked.
 */
test('NFR-02 is judged END TO END, not on journal operations alone', async () => {
  const w = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: {
      'bench/results/nfr-02.json': {
        ...GOOD_NFR02,
        // Journal operations fine; end to end over budget.
        added_end_to_end_percent_ci_high: 4.1, verdict_end_to_end: 'OVER BUDGET',
      },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'a passing journal measure must not carry a failing end-to-end one');
    assert.match(r.all, /added end-to-end run latency, whole interval of 4\.1 %/);
  } finally { w.cleanup(); }
});

test('an UNRESOLVED end-to-end verdict cannot close NFR-02', async () => {
  const w = world({
    rows: [NFR02_ROW], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: {
      'bench/results/nfr-02.json': { ...GOOD_NFR02, verdict_end_to_end: 'UNRESOLVED' },
    },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /verdict_end_to_end = "UNRESOLVED"/);
  } finally { w.cleanup(); }
});

// ── PR #18 re-review: the numeric lint must read the PUBLISHED text ─────────

/**
 * The first version of this check listed the expected numbers in the guard
 * itself, so it compared its own constant against the evidence and never
 * looked at the release notes. Editing the published headline from 0.29% to
 * 0.10% left it passing -- the exact regression the check was added to catch.
 *
 * The numbers now come out of the published row.
 */
test('mutating the PUBLISHED figure fails, with the evidence untouched', async () => {
  const w = world({
    rows: [nfr02Row({ e2e: '0.10' })],       // the note says 0.10%
    reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': GOOD_NFR02 },   // the evidence still says 0.29
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1, 'a published figure that is not the measured one must fail');
    assert.match(r.all, /publishes 0\.1 for added_end_to_end_percent_ci_high/);
    assert.match(r.all, /measured 0\.29/);
  } finally { w.cleanup(); }
});

test('every annotated figure in the row is checked, not just the headline', async () => {
  for (const [patch, re] of /** @type {[any, RegExp][]} */ ([
    [{ denom: '2600' }, /publishes 2600 for denominator_ms/],
    [{ directMs: '9.99' }, /publishes 9\.99 for added_direct\.mean_ms/],
    [{ direct: '0.01' }, /publishes 0\.01 for added_direct_percent_ci_high/],
  ])) {
    const w = world({
      rows: [nfr02Row(patch)], reqs: [req('NFR-02', 'done')],
      files: ['bench/run-latency.mjs'],
      results: { 'bench/results/nfr-02.json': GOOD_NFR02 },
    });
    try {
      const r = await run(w.args);
      assert.equal(r.code, 1, JSON.stringify(patch));
      assert.match(r.all, re);
    } finally { w.cleanup(); }
  }
});

/**
 * And the annotation cannot be removed to escape the check. A comparison that
 * does not happen is indistinguishable from one that passed, which is the
 * failure mode this whole guard exists to prevent.
 */
test('deleting an annotation fails rather than silently skipping the check', async () => {
  const stripped = NFR02_ROW.replace('<!--=denominator_ms-->', '');
  const w = world({
    rows: [stripped], reqs: [req('NFR-02', 'done')],
    files: ['bench/run-latency.mjs'],
    results: { 'bench/results/nfr-02.json': GOOD_NFR02 },
  });
  try {
    const r = await run(w.args);
    assert.equal(r.code, 1);
    assert.match(r.all, /must quote denominator_ms and annotate it in the row/);
    assert.match(r.all, /indistinguishable from it passing/);
  } finally { w.cleanup(); }
});

test('the real release notes carry an annotation for every required field', async () => {
  const { readFileSync } = await import('node:fs');
  const notes = readFileSync(
    new URL('../docs/splitstick-1.0-release-notes.md', import.meta.url), 'utf8');
  for (const field of [
    'added_end_to_end_percent_ci_high', 'added_direct_percent_ci_high',
    'denominator_ms', 'added_direct.mean_ms',
  ]) {
    assert.ok(notes.includes(`<!--=${field}-->`),
      `the published notes do not bind ${field} to its evidence`);
  }
  assert.equal((await run([])).code, 0);
});
