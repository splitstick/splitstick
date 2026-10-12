// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * NFR-04 — verify a 100,000-event run in under 2 seconds, offline.
 *
 * What is timed is the whole verification a reader actually runs: read both
 * journals, recompute every leaf from its salt and record, walk the chain,
 * rebuild the Merkle tree, check the operator signature on every checkpoint,
 * and report. Timing only the hashing would measure the part that was never
 * going to be slow.
 *
 * TOTAL ELAPSED, not a percentile. NFR-01 is per-event and needs a tail;
 * NFR-04 is a single answer to "can an auditor run this" and the budget is
 * wall-clock for the whole run. A p99 of a one-shot operation is a statistic
 * about nothing.
 *
 * Two arms, because a number with no attribution cannot be acted on:
 *
 *   verify     the full verifyStore call — what a reader runs
 *   read       readChainDetailed alone, the floor imposed by the filesystem
 *              and JSON.parse
 *
 * The same acceptance discipline as NFR-01: a run that does not qualify under
 * bench/reference-env.json is a REGRESSION metric and says so, because a number
 * from a laptop is not an acceptance result. That distinction exists because
 * performance claims from unqualified runs had to be withdrawn once already.
 *
 *   node bench/verify.mjs [--events 100000] [--repeat 3] [--json]
 *                         [--machine "..."] [--storage "..."]
 */

import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '@splitstick/verify';
import { clockResolution, environment, qualifyRun } from './precision.mjs';

const argv = process.argv.slice(2);
/** @param {string} name @param {number} fallback */
const num = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(argv[i + 1]);
};
/** @param {string} name */
const str = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? undefined : argv[i + 1];
};
const EVENTS = num('events', 100_000);
const REPEAT = Math.max(1, num('repeat', 3));
const JSON_OUT = argv.includes('--json');

/** NFR-04's budget, for the whole run rather than per event. */
const BUDGET_MS = 2_000;

const REF = JSON.parse(readFileSync(new URL('./reference-env.json', import.meta.url), 'utf8'));

/** Build a store of `n` actions, checkpointed every 1,000. @param {number} n */
async function build(n) {
  const root = mkdtempSync(join(tmpdir(), 'ss-bench-verify-'));
  const signer = await generateDevSigner('splitstick.dev/bench');
  const store = new Store(root, 'bench');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'bench', origin: 'splitstick.dev/bench', now: () => new Date(t += 1),
  });
  const args = Buffer.from('{"amount":200000}');
  const result = Buffer.from('OK ref=TX-77814');
  for (let i = 1; i <= n; i += 1) {
    c.action({
      run: 'r-1', tool: 'transfer_funds', consequential: true, args, result,
      outcome: 'ok', attempt: 1, correlation: `c-${i}`,
    });
    // Checkpoints are part of what a verifier must check, so the store has to
    // carry a realistic number of them: one per 1,000 records at the shipped
    // default cadence. A single checkpoint over 100,000 records would measure
    // a shape no deployment has.
    if (i % 1_000 === 0) await c.checkpoint();
  }
  if (n % 1_000 !== 0) await c.checkpoint();
  store.close();
  return { root, vkey: formatVkey('splitstick.dev/bench', signer.publicKey) };
}

const env = await environment();
const clock = clockResolution(BUDGET_MS);

const fixtures = [];
for (let r = 0; r < REPEAT; r += 1) fixtures.push(await build(EVENTS));

/** @type {number[]} */
const verifyMs = [];
/** @type {number[]} */
const readMs = [];
/** @type {any} */
let lastReport = null;

for (const f of fixtures) {
  const s0 = process.hrtime.bigint();
  lastReport = await verifyStore(f.root, { collector: 'bench', vkey: f.vkey });
  verifyMs.push(Number(process.hrtime.bigint() - s0) / 1e6);

  const store = new Store(f.root, 'bench');
  const s1 = process.hrtime.bigint();
  store.readChainDetailed();
  readMs.push(Number(process.hrtime.bigint() - s1) / 1e6);
  store.close();
}
for (const f of fixtures) rmSync(f.root, { recursive: true, force: true });

const median = (/** @type {number[]} */ xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? Number(s[(s.length - 1) / 2])
    : (Number(s[s.length / 2 - 1]) + Number(s[s.length / 2])) / 2;
};
const worst = Math.max(...verifyMs);
const { qualifies, shortfalls } = qualifyRun(REF, {
  env, events: EVENTS, repeats: REPEAT, clockAdequate: clock.adequate,
  machine: str('machine'), storage: str('storage'),
});

// The WORST run against the budget, not the median. An auditor runs it once,
// and "usually under two seconds" is not what the requirement says.
const within = worst <= BUDGET_MS;

const result = {
  requirement: 'NFR-04',
  kind: qualifies ? 'acceptance' : 'regression',
  shortfalls,
  events: EVENTS,
  repeats: REPEAT,
  budget_ms: BUDGET_MS,
  verify_ms: { median: median(verifyMs), worst, all: verifyMs },
  read_ms: { median: median(readMs), worst: Math.max(...readMs) },
  within_budget: within,
  records: lastReport?.records ?? null,
  verdict: lastReport?.verdict ?? null,
  failed_checks: lastReport?.summary?.failed ?? null,
  env,
  machine: str('machine') ?? null,
  storage: str('storage') ?? null,
};

if (JSON_OUT) {
  process.stdout.write(`${JSON.stringify(result, null, 1)}\n`);
} else {
  const ms = (/** @type {number} */ v) => `${v.toFixed(1)} ms`;
  process.stdout.write(`
NFR-04  offline verification · ${EVENTS.toLocaleString('en-US')} events · ${REPEAT} repeats

  verify   median ${ms(result.verify_ms.median)}   worst ${ms(worst)}    budget ${ms(BUDGET_MS)}
  read     median ${ms(result.read_ms.median)}   worst ${ms(result.read_ms.worst)}
           the floor the filesystem and JSON.parse impose, for attribution

  records  ${result.records?.tree_size ?? '?'} in the tree, verdict ${result.verdict}, ${result.failed_checks} failing check(s)

  ${within ? 'WITHIN BUDGET' : 'OVER BUDGET'}   measured on the WORST run, not the median:
  an auditor runs this once, and "usually under two seconds" is not the claim.

  ${qualifies ? 'ACCEPTANCE RUN — this host qualifies under bench/reference-env.json'
    : `REGRESSION METRIC ONLY — this host does not qualify:\n  - ${shortfalls.join('\n  - ')}`}
`);
}

// A benchmark that cannot fail is not a budget. Exit non-zero when an
// ACCEPTANCE run misses it; a regression metric reports and does not gate,
// because failing a build on a laptop's number is how a real budget gets
// widened to fit the laptop.
process.exit(qualifies && !within ? 1 : 0);
