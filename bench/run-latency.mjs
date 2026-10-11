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
 *   node bench/run-latency.mjs [--runs 200] [--model-ms 400] [--json]
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
const RUNS = num('runs', 200);
const MODEL_MS = num('model-ms', 400);
const JSON_OUT = argv.includes('--json');

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
  const t0 = process.hrtime.bigint();
  await oma.runAgent(
    {
      name: 'treasury-agent',
      adapter: scriptedAdapter(),
      model: 'scripted-1',
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

// The budget in milliseconds: 2% of a run whose two model calls take MODEL_MS.
const budgetMs = 0.02 * (baseMedian + 2 * MODEL_MS);
const verdict = verdictAgainst(stats, budgetMs);

const report = {
  requirement: 'NFR-02',
  budget_percent: 2,
  budget_ms: Number(budgetMs.toFixed(3)),
  model_latency_assumed_ms: MODEL_MS,
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

if (JSON_OUT) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  process.stdout.write(`
NFR-02  added run latency · ${RUNS} paired runs, interleaved · real OMA orchestrator, scripted model
        ${env.cpu} · ${env.cpus} cpu · ${env.platform} · node ${env.node} · load ${env.load_average_1m}
        clock tick ${clock.tick_ms.toFixed(6)} ms (${clock.adequate ? 'adequate' : 'TOO COARSE'})

  baseline (OMA journal only)      ${report.baseline_median_ms.toFixed(3)} ms median
  with Splitstick                  ${report.splitstick_median_ms.toFixed(3)} ms median

  added (paired mean)              ${report.added_ms.toFixed(3)} ms
  95% interval                     [${report.ci95_ms[0].toFixed(3)}, ${report.ci95_ms[1].toFixed(3)}] ms
  resolution of this run           ±${report.resolution_ms.toFixed(3)} ms
  budget                           ${report.budget_ms.toFixed(3)} ms  (2% of a ${MODEL_MS} ms-per-call run)

  as a percentage                  ${report.added_percent_at_model_latency.toFixed(3)} %  [${report.ci95_percent[0].toFixed(3)}, ${report.ci95_percent[1].toFixed(3)}]

  ${report.verdict}

  ${report.note}
`);
}
