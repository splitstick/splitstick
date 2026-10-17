// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * NFR-02 — added end-to-end agent run latency below 2%.
 *
 * A real A/B. The same OMA agent, the same scripted model, run with OMA's own
 * JSONL journal and again with that journal wrapped by Splitstick. Every event
 * is produced by OMA's actual runtime; the only thing stubbed is the model,
 * which also makes the measurement CONSERVATIVE — a scripted adapter returns in
 * microseconds where a real one takes hundreds of milliseconds, so the overhead
 * measured here is an upper bound on the percentage a real run would see.
 *
 * Two things this harness got wrong before, both of which produced a number
 * more confident than the evidence:
 *
 * It built a store, six directories and a signing key INSIDE the measured
 * region, putting 20 ms of harness into the result. A collector is scoped to the
 * instance, not the run (FR-56), so it is opened once per arm.
 *
 * And it ran one arm to completion before the other, so machine drift landed
 * entirely on one of them — which produced a NEGATIVE overhead, reported as a
 * speedup. The arms are now interleaved, and a difference smaller than the
 * baseline arm's own spread is reported as below the noise floor rather than as
 * either a cost or a saving.
 *
 * ── The real-provider arm (NFR-02) ─────────────────────────────────────────
 *
 * `--provider anthropic` runs the SAME A/B against a real model through OMA's
 * own Anthropic adapter. It exists because M7 reverted NFR-02 from done: the
 * budget is a PERCENTAGE, and with a scripted model the denominator had to be
 * modelled as `--model-ms`, an assumption that had never met a provider.
 *
 * With a real provider that assumption disappears rather than being replaced.
 * The baseline arm's measured end-to-end time already contains the real model
 * latency, so the budget is simply 2% of what was measured. Nothing is assumed.
 *
 * What a real provider costs is PRECISION, and it is worth being explicit about
 * why. Splitstick's added work is journal writing and is independent of model
 * latency, so the signal stays at about a millisecond while each arm acquires
 * its own independent model call — model variance ADDS rather than cancelling,
 * because a paired difference only cancels what the two arms share. So the
 * spread of the difference grows by roughly sqrt(2) x the model's own spread,
 * and the pairs needed grow with the SQUARE of that. The harness reports
 * `pairs_needed_for_budget` so the required n is computed from the measured
 * spread rather than guessed: run a small pilot, read that number, then run it.
 *
 * The API key is read from ANTHROPIC_API_KEY or from bench/.env.local, which is
 * gitignored. It is never printed and never written to a result: the report is
 * scanned for it before being emitted, and the run fails rather than leaking.
 *
 *   node bench/run-latency.mjs [--runs 200] [--model-ms 400] [--json]
 *   node bench/run-latency.mjs --provider anthropic --runs 20 \
 *        [--model claude-haiku-4-5-20251001] [--json]
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OpenMultiAgent, JsonlRunJournal, defineTool } from '@open-multi-agent/core';
import { z } from 'zod';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { SplitstickRunJournal } from '@splitstick/collect-oma';
import { pairedDifference, pairsNeededFor, verdictAgainst, clockResolution, environment } from './precision.mjs';

const argv = process.argv.slice(2);
const num = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(argv[i + 1]);
};
const str = (/** @type {string} */ name) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? undefined : argv[i + 1];
};
const RUNS = num('runs', 200);
const MODEL_MS = num('model-ms', 400);
const JSON_OUT = argv.includes('--json');
const PROVIDER = str('provider') ?? 'scripted';
// The FASTEST plausible model, deliberately. A slow model inflates the
// denominator and makes a 2% budget trivial; the honest denominator for a
// percentage claim is the worst case, which is the quickest model an operator
// might realistically run.
const MODEL = str('model') ?? 'claude-haiku-4-5-20251001';

if (!['scripted', 'anthropic'].includes(PROVIDER)) {
  console.error(`\n  --provider ${PROVIDER} is not one this harness knows (scripted, anthropic).\n`);
  process.exit(2);
}
const REAL = PROVIDER !== 'scripted';

/**
 * The API key, from the environment or from bench/.env.local (gitignored).
 *
 * Never printed, never returned in a report, and never passed as a command-line
 * argument — an argv key is visible to every process on the machine through ps.
 */
function apiKey() {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  const local = new URL('./.env.local', import.meta.url).pathname;
  if (fs.existsSync(local)) {
    for (const line of fs.readFileSync(local, 'utf8').split('\n')) {
      const m = /^\s*(?:export\s+)?ANTHROPIC_API_KEY\s*=\s*(.+?)\s*$/.exec(line);
      if (m) return String(m[1]).replace(/^['"]|['"]$/g, '');
    }
  }
  console.error('\n  --provider anthropic needs an API key, and this harness will not take one on'
    + '\n  the command line (argv is visible to every process on the machine via ps).'
    + '\n  Put it in the environment as ANTHROPIC_API_KEY, or in bench/.env.local as'
    + '\n  ANTHROPIC_API_KEY=sk-ant-... — that path is gitignored.\n');
  process.exit(2);
}

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'splitstick-latency-'));
const cleanup = () => fs.rmSync(workdir, { recursive: true, force: true });
process.on('exit', cleanup);
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => { cleanup(); process.exit(130); });
}

const transferFunds = defineTool({
  name: 'transfer_funds',
  description: 'Transfer funds to a counterparty account.',
  consequential: true,
  inputSchema: z.object({ amount: z.number(), currency: z.string(), to: z.string() }),
  async execute(input) {
    return { data: `OK: transferred ${input.currency} ${input.amount} to ${input.to}. ref=TX-77814` };
  },
});

/** @returns {any} the only stub in this benchmark: a deterministic provider */
function scriptedAdapter() {
  let call = 0;
  return {
    name: 'scripted',
    async chat() {
      call += 1;
      if (call % 2 === 1) {
        return {
          id: 'msg_1', model: 'scripted-1', stop_reason: 'tool_use',
          usage: { input_tokens: 100, output_tokens: 20 },
          content: [{ type: 'tool_use', id: `call_${call}`, name: 'transfer_funds',
            input: { amount: 2000000, currency: 'EUR', to: 'ACME-9931' } }],
        };
      }
      return {
        id: 'msg_2', model: 'scripted-1', stop_reason: 'end_turn',
        usage: { input_tokens: 180, output_tokens: 25 },
        content: [{ type: 'text', text: 'Transfer complete (ref TX-77814).' }],
      };
    },
    async *stream() { throw new Error('stream() is not exercised by this benchmark'); },
  };
}

/** @type {number[]} */
const modelCallMs = [];
/** @type {number[]} */
const callsPerRun = [];

/**
 * OMA's own Anthropic adapter, wrapped only to TIME each call.
 *
 * The wrapper measures and counts; it changes nothing about the request, so the
 * arm is the real orchestrator talking to the real provider. Timing here rather
 * than inferring from the run total is what makes the denominator measured.
 */
async function realAdapter() {
  const { createAdapter } = await import('@open-multi-agent/core');
  const inner = await createAdapter('anthropic', apiKey());
  return {
    name: inner.name ?? 'anthropic',
    /** @param {any} req @param {any} [opts] */
    async chat(req, opts) {
      const t = process.hrtime.bigint();
      try {
        return await inner.chat(req, opts);
      } finally {
        modelCallMs.push(Number(process.hrtime.bigint() - t) / 1e6);
      }
    },
    /** @param {any} req @param {any} [opts] */
    async *stream(req, opts) {
      yield* inner.stream(req, opts);
    },
  };
}

/** Built once: a fresh client per run would measure connection setup, not the model. */
const sharedRealAdapter = REAL ? await realAdapter() : null;

/** One collector per arm, as a collector is actually used. */
async function openArm(withCollector) {
  if (!withCollector) return { collector: null, close: () => {} };
  const root = fs.mkdtempSync(path.join(workdir, 'store-'));
  const store = new Store(root, 'bench');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root),
    signer: await generateDevSigner('splitstick.dev/bench'),
    collector: 'bench', origin: 'splitstick.dev/bench',
  });
  return { collector, close: () => store.close() };
}

/** @param {any} collector @param {string} label @param {number} i */
async function oneRun(collector, label, i) {
  // Both arms pay for the JSONL journal; only one wraps it.
  const inner = new JsonlRunJournal(path.join(workdir, `${label}-${i}.jsonl`), { flushIntervalMs: 1 });
  const journal = collector ? new SplitstickRunJournal({ collector, journal: inner }) : inner;
  const oma = new OpenMultiAgent({ journal });
  const callsBefore = modelCallMs.length;
  const t0 = process.hrtime.bigint();
  await oma.runAgent(
    {
      name: 'treasury-agent',
      adapter: sharedRealAdapter ?? scriptedAdapter(),
      model: REAL ? MODEL : 'scripted-1',
      systemPrompt: 'You are a treasury operations agent.',
      customTools: [transferFunds],
      tools: ['transfer_funds'],
      maxTurns: 4,
    },
    'Pay invoice 4471: EUR 2,000,000 to ACME-9931.',
    { journal },
  );
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  await journal.close();
  if (REAL) callsPerRun.push(modelCallMs.length - callsBefore);
  return ms;
}

/**
 * Both arms, interleaved run by run, alternating which goes first so neither
 * systematically pays for a cold cache the other then benefits from.
 * @param {number} runs
 */
async function measureInterleaved(runs) {
  const baseArm = await openArm(false);
  const withArm = await openArm(true);
  /** @type {number[]} */
  const base = [];
  /** @type {number[]} */
  const instrumented = [];
  for (let i = 0; i < runs; i++) {
    if (i % 2 === 0) {
      base.push(await oneRun(null, 'baseline', i));
      instrumented.push(await oneRun(withArm.collector, 'splitstick', i));
    } else {
      instrumented.push(await oneRun(withArm.collector, 'splitstick', i));
      base.push(await oneRun(null, 'baseline', i));
    }
  }
  baseArm.close();
  withArm.close();
  return { base, instrumented };
}

const sorted = (/** @type {number[]} */ a) => [...a].sort((x, y) => x - y);
const median = (/** @type {number[]} */ a) => {
  const v = sorted(a);
  return /** @type {number} */ (v[Math.floor(v.length / 2)]);
};

const clock = clockResolution(1);
const env = await environment();

await measureInterleaved(5);                       // warm both arms together
const { base, instrumented } = await measureInterleaved(RUNS);

const baseMedian = median(base);
const withMedian = median(instrumented);

// Paired, because the arms are interleaved: run i of each saw the same machine.
// Comparing two medians could not separate a real 3 ms cost from drift, which
// is how an earlier version of this harness reported a negative overhead.
const stats = pairedDifference(base, instrumented);

// The budget in milliseconds.
//
// With a real provider there is NO assumption: the baseline arm's measured
// end-to-end time already contains the real model latency, so the budget is 2%
// of what was measured. With the scripted adapter the model returns in
// microseconds, so the real total has to be modelled as `baseMedian + 2 x
// MODEL_MS` — and MODEL_MS being an assumption that had never met a provider is
// exactly why M7 reverted this requirement from done.
const denominatorMs = REAL ? baseMedian : baseMedian + 2 * MODEL_MS;
const budgetMs = 0.02 * denominatorMs;
const verdict = verdictAgainst(stats, budgetMs);

const mid = (/** @type {number[]} */ a) => (a.length === 0 ? null : median(a));
/** How many pairs this spread needs for the whole interval to clear the budget. */
const pairsForBudget = pairsNeededFor(stats.sd_diff, budgetMs);

const report = {
  requirement: 'NFR-02',
  budget_percent: 2,
  budget_ms: Number(budgetMs.toFixed(3)),
  provider: PROVIDER,
  model: REAL ? MODEL : 'scripted-1',
  // Assumed OR measured, never both, and the null says which.
  model_latency_assumed_ms: REAL ? null : MODEL_MS,
  model_latency_measured_ms: REAL ? {
    calls: modelCallMs.length,
    median: Number((mid(modelCallMs) ?? 0).toFixed(3)),
    min: Number(Math.min(...modelCallMs).toFixed(3)),
    max: Number(Math.max(...modelCallMs).toFixed(3)),
  } : null,
  model_calls_per_run: REAL ? [...new Set(callsPerRun)].sort((a, b) => a - b) : null,
  denominator_ms: Number(denominatorMs.toFixed(3)),
  denominator_is_measured: REAL,
  pairs_needed_for_budget: pairsForBudget,
  runs: RUNS,
  interleaved: true,
  environment: env,
  clock,
  baseline_median_ms: Number(baseMedian.toFixed(3)),
  splitstick_median_ms: Number(withMedian.toFixed(3)),
  added_ms: Number(stats.mean_diff.toFixed(3)),
  ci95_ms: [Number(stats.ci95_low.toFixed(3)), Number(stats.ci95_high.toFixed(3))],
  resolution_ms: Number(stats.resolution.toFixed(3)),
  added_percent_at_model_latency: Number((100 * stats.mean_diff / (baseMedian + 2 * MODEL_MS)).toFixed(3)),
  ci95_percent: [
    Number((100 * stats.ci95_low / (baseMedian + 2 * MODEL_MS)).toFixed(3)),
    Number((100 * stats.ci95_high / (baseMedian + 2 * MODEL_MS)).toFixed(3)),
  ],
  pairs_needed_for_1pc: pairsNeededFor(stats.sd_diff, 0.01 * (baseMedian + 2 * MODEL_MS)),
  verdict: verdict === 'within' ? 'WITHIN BUDGET' : verdict === 'over' ? 'OVER BUDGET' : 'UNRESOLVED',
};
report.note = verdict === 'within'
  ? `The whole 95% interval [${report.ci95_ms[0]}, ${report.ci95_ms[1]}] ms sits below the `
    + `${report.budget_ms} ms the budget allows, so this run establishes the budget is met rather `
    + 'than merely failing to contradict it. The scripted model makes this an upper bound: a real '
    + 'call is hundreds of milliseconds, which only shrinks the percentage.'
  : verdict === 'over'
    ? 'The whole interval sits above the budget.'
    : `The budget falls inside the 95% interval [${report.ci95_ms[0]}, ${report.ci95_ms[1]}] ms, so `
      + 'this run is consistent with passing AND with failing. It resolves no verdict, and must not '
      + `be reported as one; about ${report.pairs_needed_for_1pc} pairs would resolve a 1% effect.`;
if (!clock.adequate) {
  report.verdict = 'INSTRUMENT INADEQUATE';
  report.note = `the clock resolves only ${clock.tick_ms} ms, too coarse for what this reports`;
}

/**
 * A secret must not leave by the same door as the result.
 *
 * The key is read from the environment or a gitignored file and is never put in
 * the report — but "never" is a claim about code that changes, so the emitted
 * bytes are checked against the secret itself before anything is printed. A
 * leak fails the run rather than being printed with an apology.
 */
function refuseToLeak(/** @type {string} */ emitted) {
  const secret = REAL ? apiKey() : null;
  if (secret && secret.length > 8 && emitted.includes(secret)) {
    console.error('\n  REFUSED: the output of this benchmark contains the API key. Nothing has been'
      + '\n  printed. This is a bug in the harness, not in your configuration.\n');
    process.exit(3);
  }
  // Also catch a partial or re-encoded key making it out some other way.
  for (const shape of [/sk-ant-[A-Za-z0-9_-]{8,}/, /\bBearer\s+sk-/i]) {
    if (shape.test(emitted)) {
      console.error('\n  REFUSED: the output of this benchmark contains something shaped like an API'
        + '\n  key. Nothing has been printed.\n');
      process.exit(3);
    }
  }
  return emitted;
}

if (JSON_OUT) {
  process.stdout.write(refuseToLeak(JSON.stringify(report, null, 2) + '\n'));
} else {
  process.stdout.write(refuseToLeak(`
NFR-02  added run latency · ${RUNS} paired runs, interleaved · real OMA orchestrator, ${
    REAL ? `REAL provider (${MODEL})` : 'scripted model'}
        ${env.cpu} · ${env.cpus} cpu · ${env.platform} · node ${env.node} · load ${env.load_average_1m}
        clock tick ${clock.tick_ms.toFixed(6)} ms (${clock.adequate ? 'adequate' : 'TOO COARSE'})

  baseline (OMA journal only)      ${report.baseline_median_ms.toFixed(3)} ms median
  with Splitstick                  ${report.splitstick_median_ms.toFixed(3)} ms median

  added (paired mean)              ${report.added_ms.toFixed(3)} ms
  95% interval                     [${report.ci95_ms[0].toFixed(3)}, ${report.ci95_ms[1].toFixed(3)}] ms
  resolution of this run           ±${report.resolution_ms.toFixed(3)} ms
  budget                           ${report.budget_ms.toFixed(3)} ms  (2% of ${
    REAL ? `the MEASURED ${report.denominator_ms.toFixed(0)} ms run`
      : `a ${MODEL_MS} ms-per-call run — ASSUMED`})

  as a percentage                  ${report.added_percent_at_model_latency.toFixed(3)} %  [${report.ci95_percent[0].toFixed(3)}, ${report.ci95_percent[1].toFixed(3)}]
${REAL ? `
  model calls                      ${report.model_latency_measured_ms.calls} total, ${
  report.model_calls_per_run.join('/')} per run
  model latency, measured          ${report.model_latency_measured_ms.median.toFixed(0)} ms median (${
  report.model_latency_measured_ms.min.toFixed(0)}–${report.model_latency_measured_ms.max.toFixed(0)})
  pairs needed for this budget     ${report.pairs_needed_for_budget}${
  report.pairs_needed_for_budget > RUNS
    ? `  — THIS RUN HAS ${RUNS}, so it cannot settle the budget`
    : '  — this run has enough'}
` : ''}
  ${report.verdict}

  ${report.note}
`));
}
