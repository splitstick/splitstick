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
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
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
};

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
