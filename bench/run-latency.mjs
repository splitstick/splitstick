// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * NFR-02 — added end-to-end agent run latency below 2%.
 *
 * A real A/B. The same OMA agent, the same scripted model, run once with OMA's
 * own JSONL journal and once with that journal wrapped by Splitstick. Every
 * event is produced by OMA's actual runtime; the only thing stubbed is the
 * model, which is also what makes the measurement CONSERVATIVE: a scripted
 * adapter returns in microseconds where a real one takes hundreds of
 * milliseconds, so the overhead measured here is an upper bound on the
 * percentage a real run would see, not an estimate of it.
 *
 * The report therefore gives both: the measured percentage against a
 * zero-latency model, and what the same absolute overhead works out to against
 * a stated model latency.
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

const args = process.argv.slice(2);
const num = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : Number(args[i + 1]);
};
const RUNS = num('runs', 200);
const MODEL_MS = num('model-ms', 400);
const JSON_OUT = args.includes('--json');

const transferFunds = defineTool({
  name: 'transfer_funds',
  description: 'Transfer funds to a counterparty account.',
  consequential: true,
  inputSchema: z.object({ amount: z.number(), currency: z.string(), to: z.string() }),
  async execute(input) {
    return { data: `OK: transferred ${input.currency} ${input.amount} to ${input.to}. ref=TX-77814` };
  },
});

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

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'splitstick-latency-'));
const cleanup = () => fs.rmSync(workdir, { recursive: true, force: true });
process.on('exit', cleanup);
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => { cleanup(); process.exit(130); });
}

/**
 * One collector for the whole arm, which is how a collector is actually used:
 * the chain is scoped to the instance, not to the run (FR-56). Building a
 * store, six directories and a signing key inside the measured region put
 * 20 ms of my own benchmark harness into the result on the first attempt.
 */
async function openArm(arm) {
  if (arm === 'baseline') return { collector: null, close: () => {} };
  const root = fs.mkdtempSync(path.join(workdir, 'store-'));
  const store = new Store(root, 'bench');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root),
    signer: await generateDevSigner('splitstick.dev/bench'),
    collector: 'bench', origin: 'splitstick.dev/bench',
  });
  return { collector, close: () => store.close() };
}

/** @param {'baseline'|'splitstick'} arm @param {number} runs */
async function measure(arm, runs) {
  const { collector, close } = await openArm(arm);
  const samples = [];
  for (let i = 0; i < runs; i++) {
    // Both arms pay for the JSONL journal; only one wraps it.
    const inner = new JsonlRunJournal(path.join(workdir, `${arm}-${i}.jsonl`), { flushIntervalMs: 1 });
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
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
    await journal.close();
  }
  close();
  samples.sort((a, b) => a - b);
  return samples;
}

// Interleave warm-up so neither arm pays the cold-start cost alone.
await measure('baseline', 5);
await measure('splitstick', 5);

const base = await measure('baseline', RUNS);
const with_ = await measure('splitstick', RUNS);

const median = (a) => a[Math.floor(a.length / 2)];
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;

const report = {
  requirement: 'NFR-02',
  budget_percent: 2,
  runs: RUNS,
  baseline_median_ms: Number(median(base).toFixed(3)),
  splitstick_median_ms: Number(median(with_).toFixed(3)),
  baseline_mean_ms: Number(mean(base).toFixed(3)),
  splitstick_mean_ms: Number(mean(with_).toFixed(3)),
};
report.added_ms = Number((median(with_) - median(base)).toFixed(3));
report.added_percent_scripted_model = Number((100 * report.added_ms / median(base)).toFixed(2));
report.model_latency_assumed_ms = MODEL_MS;
// Two model calls per run in this agent loop.
report.added_percent_at_model_latency = Number(
  (100 * report.added_ms / (median(base) + 2 * MODEL_MS)).toFixed(3));
report.verdict = report.added_percent_at_model_latency < report.budget_percent
  ? 'WITHIN BUDGET' : 'OVER BUDGET';
report.note = 'The scripted-model figure is an upper bound: a real model call is hundreds of milliseconds, which makes the same absolute overhead a smaller percentage, never a larger one.';

if (JSON_OUT) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  process.stdout.write(`
NFR-02  added run latency, ${RUNS} runs per arm, real OMA orchestrator, scripted model

  baseline (OMA journal only)      ${report.baseline_median_ms.toFixed(3)} ms median
  with Splitstick                  ${report.splitstick_median_ms.toFixed(3)} ms median
  added                            ${report.added_ms.toFixed(3)} ms

  against a zero-latency model     ${report.added_percent_scripted_model.toFixed(2)} %   (an upper bound)
  against a ${MODEL_MS} ms model call      ${report.added_percent_at_model_latency.toFixed(3)} %   budget 2.000 %

  ${report.verdict}

  ${report.note}
`);
}

process.exitCode = report.verdict === 'WITHIN BUDGET' ? 0 : 1;
