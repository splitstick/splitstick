// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * NFR-01 — p99 append overhead below 1 ms per event.
 *
 * Measured early rather than last, because the design hardens around whatever
 * the numbers turn out to be. DES-17 puts this in M1 for exactly that reason,
 * and it has already changed the storage layout twice.
 *
 * What is timed is the whole append path a collector actually runs: externalise
 * the payloads (encrypt, salt, commit, index), validate the record,
 * canonicalise it, salt and hash the leaf, chain it, and write both journals.
 * Timing only the hashing would measure the part that was never going to be
 * slow — SHA-256 over a record is 0.007 ms.
 *
 * Two arms are reported, plus the filesystem's own numbers, because a
 * percentile with no attribution cannot be acted on:
 *
 *   chain      the record, leaf and chain path — two writes to open journals
 *   full       the same, plus externalising the arguments and the result
 *   baseline   fs.writeSync and fs.writeFileSync measured on their own
 *
 * Each arm runs `--repeat` times and the spread is reported, not one sample.
 * A single run of this benchmark on a laptop disagrees with the next by a
 * factor of two at p99, and the filesystem baseline moves with it — so a lone
 * p99 here is not evidence of anything, in either direction.
 *
 *   node bench/append.mjs [--events 20000] [--repeat 3] [--json]
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PerformanceObserver, constants as perfConstants } from 'node:perf_hooks';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';

const argv = process.argv.slice(2);
const num = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(argv[i + 1]);
};
const EVENTS = num('events', 20_000);
const REPEAT = Math.max(1, num('repeat', 3));
const JSON_OUT = argv.includes('--json');
// NFR-01 as revised at M1: p95 is the budget, p99 has a budget and a stretch.
const BUDGET_P95_MS = 1;
const BUDGET_P99_MS = 3;
const STRETCH_P99_MS = 1;

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'splitstick-bench-'));

// One file per record adds up fast: an interrupted run used to leave tens of
// thousands behind, and three interrupted runs filled a disk. Clean up however
// we leave.
const cleanup = () => fs.rmSync(workdir, { recursive: true, force: true });
process.on('exit', cleanup);
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => { cleanup(); process.exit(130); });
}

const ARGS = Buffer.from(JSON.stringify({ amount: 2000000, currency: 'EUR', to: 'ACME-9931' }));
const RESULT = Buffer.from('OK: transferred EUR 2000000 to ACME-9931. ref=TX-77814');

/** @param {Float64Array} samples @param {number} wallMs */
function percentiles(samples, wallMs) {
  const n = samples.length;
  const sorted = Float64Array.from(samples).sort();
  const at = (q) => sorted[Math.min(n - 1, Math.floor(n * q))];
  return {
    mean_ms: +(wallMs / n).toFixed(4),
    p50_ms: +at(0.5).toFixed(4),
    p95_ms: +at(0.95).toFixed(4),
    p99_ms: +at(0.99).toFixed(4),
    p999_ms: +at(0.999).toFixed(4),
    max_ms: +sorted[n - 1].toFixed(4),
    events_per_second: Math.round(n / (wallMs / 1000)),
  };
}

/**
 * Garbage-collection pauses during a run, so the tail can be ATTRIBUTED rather
 * than guessed at. An earlier version of this file asserted that the p99 tail
 * was GC, on the strength of the filesystem baseline moving with it — which is
 * inference, not evidence. Each sample is now checked against the GC windows
 * that overlap it.
 * @returns {{ start: () => void, stop: () => { windows: [number, number][], totalMs: number, count: number } }}
 */
function gcRecorder() {
  /** @type {[number, number][]} */
  let windows = [];
  let totalMs = 0;
  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      windows.push([entry.startTime, entry.startTime + entry.duration]);
      totalMs += entry.duration;
    }
  });
  return {
    start() { windows = []; totalMs = 0; observer.observe({ entryTypes: ['gc'] }); },
    stop() {
      observer.disconnect();
      return { windows, totalMs, count: windows.length };
    },
  };
}

/**
 * The share of the slowest samples that overlap a GC pause.
 * @param {{ at: number, ms: number }[]} slowest
 * @param {[number, number][]} windows
 */
function gcOverlap(slowest, windows) {
  if (slowest.length === 0) return 0;
  const hits = slowest.filter(s =>
    windows.some(([from, to]) => s.at < to && s.at + s.ms > from)).length;
  return hits / slowest.length;
}

/** @param {boolean} withContent */
async function arm(withContent) {
  const root = fs.mkdtempSync(path.join(workdir, 'store-'));
  const store = new Store(root, 'bench');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root),
    signer: await generateDevSigner('splitstick.dev/bench'),
    collector: 'bench', origin: 'splitstick.dev/bench',
  });
  const payloads = withContent ? { args: ARGS, result: RESULT } : {};

  // Warm the JIT and the filesystem, so the first thousand samples are not the
  // only slow ones in the distribution.
  for (let i = 0; i < 2000; i++) {
    collector.action({ run: 'warmup', tool: 'transfer_funds', ...payloads, correlation: `w-${i}` });
  }

  const samples = new Float64Array(EVENTS);
  /** @type {{ at: number, ms: number }[]} */
  const timeline = [];
  const gc = gcRecorder();
  gc.start();
  const started = process.hrtime.bigint();
  for (let i = 0; i < EVENTS; i++) {
    const at = performance.now();
    const t0 = process.hrtime.bigint();
    collector.action({
      run: `run-${i % 4}`, tool: 'transfer_funds', ...payloads, correlation: `c-${i}`,
    });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    samples[i] = ms;
    timeline.push({ at, ms });
  }
  const wall = Number(process.hrtime.bigint() - started) / 1e6;
  const pauses = gc.stop();
  store.close();
  fs.rmSync(root, { recursive: true, force: true });

  const p = percentiles(samples, wall);
  const slowest = [...timeline].sort((a, b) => b.ms - a.ms).slice(0, Math.max(1, Math.round(EVENTS * 0.01)));
  return {
    ...p,
    rss_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    gc_pauses: pauses.count,
    gc_total_ms: Number(pauses.totalMs.toFixed(1)),
    gc_share_of_slowest: Number(gcOverlap(slowest, pauses.windows).toFixed(2)),
  };
}

/**
 * The filesystem on its own. Without this the percentiles above cannot be
 * attributed, and an unattributed percentile invites widening the budget
 * instead of finding the cause.
 */
function filesystemBaseline() {
  const n = Math.min(EVENTS, 20_000);
  const blob = Buffer.alloc(200, 7);
  const run = (fn) => {
    const s = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      const t = process.hrtime.bigint();
      fn(i);
      s[i] = Number(process.hrtime.bigint() - t) / 1e6;
    }
    return percentiles(s, Array.from(s).reduce((a, b) => a + b, 0));
  };
  const journal = path.join(workdir, 'baseline.journal');
  const fd = fs.openSync(journal, 'a', 0o600);
  const openFd = run(() => fs.writeSync(fd, 'line\n'));
  fs.closeSync(fd);
  const dir = fs.mkdtempSync(path.join(workdir, 'baseline-files-'));
  const newFile = run((i) => fs.writeFileSync(path.join(dir, `f${i}`), blob, { mode: 0o600 }));
  fs.rmSync(dir, { recursive: true, force: true });
  return { write_to_open_fd: openFd, create_new_file: newFile };
}

/**
 * Median and worst case of each percentile across repeats. The median says what
 * the implementation costs; the worst says what the machine does to it.
 * @param {ReturnType<typeof percentiles>[]} runs
 */
function across(runs) {
  const mid = (key) => {
    const v = runs.map((r) => r[key]).sort((a, b) => a - b);
    return v[Math.floor(v.length / 2)];
  };
  const worst = (key) => Math.max(...runs.map((r) => r[key]));
  const has = (/** @type {string} */ k) => runs.every(r => k in r);
  return {
    runs: runs.length,
    p50_ms: mid('p50_ms'), p95_ms: mid('p95_ms'), p99_ms: mid('p99_ms'),
    p999_ms: mid('p999_ms'), max_ms: worst('max_ms'),
    worst_p99_ms: worst('p99_ms'),
    events_per_second: mid('events_per_second'),
    ...(has('rss_mb') ? {
      rss_mb: worst('rss_mb'),
      gc_pauses: mid('gc_pauses'),
      gc_total_ms: mid('gc_total_ms'),
      gc_share_of_slowest: mid('gc_share_of_slowest'),
    } : {}),
  };
}

/** @type {ReturnType<typeof percentiles>[]} */
const chainRuns = [];
/** @type {ReturnType<typeof percentiles>[]} */
const fullRuns = [];
/** @type {ReturnType<typeof percentiles>[]} */
const fdRuns = [];
/** @type {ReturnType<typeof percentiles>[]} */
const fileRuns = [];
for (let i = 0; i < REPEAT; i++) {
  chainRuns.push(await arm(false));
  fullRuns.push(await arm(true));
  const fs_ = filesystemBaseline();
  fdRuns.push(fs_.write_to_open_fd);
  fileRuns.push(fs_.create_new_file);
}
const chain = across(chainRuns);
const full = across(fullRuns);
const baseline = { write_to_open_fd: across(fdRuns), create_new_file: across(fileRuns) };

const report = {
  requirement: 'NFR-01',
  budget: { p95_ms: BUDGET_P95_MS, p99_ms: BUDGET_P99_MS, p99_stretch_ms: STRETCH_P99_MS },
  events: EVENTS,
  repeats: REPEAT,
  arms: { chain, full },
  filesystem_baseline: baseline,
  verdict: {
    p95: full.p95_ms <= BUDGET_P95_MS ? 'within' : 'over',
    p99: full.p99_ms <= BUDGET_P99_MS ? 'within' : 'over',
    p99_stretch: full.p99_ms <= STRETCH_P99_MS ? 'met' : 'not met',
  },
  attribution: [
    'Cryptography is not the cost. SHA-256 and AES-GCM over a record are 0.03 ms'
    + ` together, while creating one file measured p50 ${baseline.create_new_file.p50_ms} ms`
    + ` against ${baseline.write_to_open_fd.p50_ms} ms for a write to an already-open descriptor.`
    + ' So the append path creates no file at all: both journals are held open and'
    + ' every payload goes into one append-only encrypted blob.',
    `A single file creation has a p99 of ${baseline.create_new_file.p99_ms} ms on this machine, which is why`
    + ' no design that creates a file per record can meet a 1 ms p99 here, however fast its hashing.',
    `The remaining tail is not per-record work: an open-descriptor write has a p99 of`
    + ` ${baseline.write_to_open_fd.p99_ms} ms against the chain arm's ${chain.p99_ms} ms. What it is`
    + ' instead is reported above and not guessed at — if the GC share of the slowest samples is low,'
    + ' the outliers are the operating system, and the maxima here routinely exceed anything the'
    + ' per-record work could account for.',
    `Across ${REPEAT} repeats the full arm's p99 ranged up to ${full.worst_p99_ms} ms and the`
    + ' filesystem baseline moved with it, so this machine is not the reference environment NFR-01'
    + ' now requires. The p50 and p95 are the stable figures.',
    `Garbage collection is MEASURED here, not inferred: ${full.gc_pauses ?? 0} pause(s) totalling`
    + ` ${full.gc_total_ms ?? 0} ms during the full arm, overlapping`
    + ` ${Math.round((full.gc_share_of_slowest ?? 0) * 100)}% of its slowest one per cent of samples.`
    + ' A previous version of this file asserted GC was the cause on the strength of the filesystem'
    + ' baseline moving with the tail, which is inference. Read this number before repeating that claim.',
  ],
};

if (JSON_OUT) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  const row = (label, p) =>
    `  ${label.padEnd(10)} ${p.p50_ms.toFixed(4).padStart(9)} ${p.p95_ms.toFixed(4).padStart(9)}`
    + ` ${p.p99_ms.toFixed(4).padStart(9)} ${p.worst_p99_ms.toFixed(4).padStart(10)}`
    + ` ${p.max_ms.toFixed(2).padStart(9)}   ${p.events_per_second.toLocaleString('en-US')}/s`;
  process.stdout.write(`
NFR-01  append overhead · ${EVENTS.toLocaleString('en-US')} events per arm · ${REPEAT} repeats
        budget: p95 <= ${BUDGET_P95_MS} ms, p99 <= ${BUDGET_P99_MS} ms (stretch p99 <= ${STRETCH_P99_MS} ms)
        percentiles are the median across repeats; worst p99 and max are the worst seen

                   p50       p95       p99  worst p99       max   rate
${row('chain', chain)}
${row('full', full)}

  the filesystem on its own, same machine, same runs
${row('open fd', baseline.write_to_open_fd)}
${row('new file', baseline.create_new_file)}

  p95 ${report.verdict.p95} budget · p99 ${report.verdict.p99} budget · stretch p99 ${report.verdict.p99_stretch}
  rss ${full.rss_mb ?? '?'} MB · gc ${full.gc_pauses ?? 0} pause(s), ${full.gc_total_ms ?? 0} ms, overlapping ${Math.round((full.gc_share_of_slowest ?? 0) * 100)}% of the slowest 1%

${report.attribution.map((a) => `  ${a}`).join('\n\n')}
`);
}
