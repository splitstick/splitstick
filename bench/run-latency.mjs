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
const MODEL_SLEEP_MS = num('model-sleep-ms', 0);
const FLUSH_MS = num('flush-ms', 1);

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

/**
 * @returns {any} the only stub in this benchmark: a deterministic provider
 *
 * `--model-sleep-ms` makes it wait before answering, which separates two
 * explanations that a real provider confounds. If added overhead grows when the
 * MODEL is slow but the network is not involved, the cost is inside our code
 * and scales with run duration; if it only grows against a real provider, it is
 * the provider's variance. The pilot's paired mean jumped from about 1 ms
 * scripted to about 100 ms against Haiku, and guessing which of those it was
 * would have meant spending 500 API calls to measure the wrong thing.
 */
function scriptedAdapter() {
  let call = 0;
  return {
    name: 'scripted',
    async chat() {
      // Timed like the real adapter, so the end-to-end-less-model measurement
      // can be exercised without spending an API call. A sleeping scripted
      // model is model latency as far as this subtraction is concerned.
      const t = process.hrtime.bigint();
      if (MODEL_SLEEP_MS > 0) await new Promise(r => setTimeout(r, MODEL_SLEEP_MS));
      modelCallMs.push(Number(process.hrtime.bigint() - t) / 1e6);
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

/** @type {{ label: string, ms: number }[]} */
const nonModelMs = [];
/** @type {number[]} */
const directAddedMs = [];
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

/**
 * Time the calls OMA makes into a journal, without changing what it sees.
 *
 * A Proxy rather than a hand-written shim: a shim has to re-declare every
 * method, and a method it forgets is silently absent, which changes the
 * behaviour of the thing being measured. Everything is forwarded; only `append`
 * and `close` are timed, because those are the two that do work.
 *
 * @param {any} journal @param {{ ms: number }} acc
 */
function timedJournal(journal, acc) {
  return new Proxy(journal, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if ((prop !== 'append' && prop !== 'close') || typeof value !== 'function') {
        return typeof value === 'function' ? value.bind(target) : value;
      }
      return async (/** @type {any[]} */ ...args) => {
        const t = process.hrtime.bigint();
        try {
          return await value.apply(target, args);
        } finally {
          acc.ms += Number(process.hrtime.bigint() - t) / 1e6;
        }
      };
    },
  });
}

/**
 * The added work, measured DIRECTLY rather than as a difference of wall-clocks.
 *
 * SplitstickRunJournal does its own work and then delegates to OMA's journal,
 * which the baseline arm pays for too. So timing both layers and subtracting
 * gives the cost Splitstick adds, in one arm, with nothing to cancel:
 *
 *   added = time inside the wrapper - time inside the journal it wraps
 *
 * This exists because the paired wall-clock difference stopped resolving at
 * real-provider run durations. A ~1 ms cost measured as the difference of two
 * ~2600 ms totals is a ratio of 1 to 2600, and at that ratio machine drift --
 * which is autocorrelated over the minute a run takes, so it does not cancel
 * the way the paired t-interval assumes -- produced a 95% interval entirely
 * below zero for a quantity that cannot be negative.
 *
 * WHAT THIS CANNOT SEE, stated because the gap is the interesting part: work
 * that does not happen inside an `append` or `close` call. Background timers,
 * deferred flushes, and GC pressure caused by the wrapper's allocations all
 * land outside it. So the paired difference is still reported, and the GAP
 * between the two is reported as its own figure rather than one of them being
 * quietly preferred. A direct measure far below the paired one means either
 * noise in the paired measure or real work this one is blind to, and saying
 * which needs a third measurement, not a choice between these two.
 */

/** @param {any} collector @param {string} label @param {number} i */
async function oneRun(collector, label, i) {
  // Both arms pay for the JSONL journal; only one wraps it.
  const innerAcc = { ms: 0 };
  const outerAcc = { ms: 0 };
  const rawInner = new JsonlRunJournal(path.join(workdir, `${label}-${i}.jsonl`), { flushIntervalMs: FLUSH_MS });
  const inner = timedJournal(rawInner, innerAcc);
  const journal = collector
    ? timedJournal(new SplitstickRunJournal({ collector, journal: inner }), outerAcc)
    : inner;
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
  callsPerRun.push(modelCallMs.length - callsBefore);
  // END-TO-END, LESS THE TIME SPENT WAITING ON THE MODEL.
  //
  // This is the measurement that answers NFR-02 as it is actually stated --
  // "added end-to-end agent run latency" -- with the one quantity Splitstick
  // cannot influence removed. It captures everything attributable to
  // Splitstick's presence during the run, including work the direct measure is
  // blind to: background timers, deferred flushes, and GC caused by the
  // wrapper's allocations all land inside it, because it is still a wall-clock
  // measurement of the whole run.
  //
  // Removing the model wait is what makes it resolve. The model call is
  // hundreds of milliseconds with hundreds of milliseconds of spread, it is
  // identical work in both arms, and a paired difference only cancels what the
  // arms share IN EXPECTATION -- not run by run. So it contributed nothing but
  // variance, and with it gone the remaining quantity is tens of milliseconds
  // and the difference is measurable.
  //
  // What this still cannot see: if Splitstick's presence slowed the model call
  // ITSELF, that time is excluded here. The call is an HTTP wait on another
  // machine, so CPU contention during it is not plausibly material, but it is
  // an exclusion rather than a proof and is named as one.
  const modelMsThisRun = modelCallMs.slice(callsBefore).reduce((a, b) => a + b, 0);
  nonModelMs.push({ label, ms: ms - modelMsThisRun });
  // The wrapper's own cost: what it spent, less what it spent inside the
  // journal the baseline arm also pays for. Only meaningful in the
  // instrumented arm; the baseline has no wrapper.
  if (collector) directAddedMs.push(outerAcc.ms - innerAcc.ms);
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
// The warm-up's direct measurements are discarded. Leaving them in made n
// larger than --runs, and a sample that is not the thing it says it is cannot
// back a published figure -- even though cold starts are SLOWER, so including
// them only ever made the number look worse.
directAddedMs.length = 0;
modelCallMs.length = 0;
callsPerRun.length = 0;
nonModelMs.length = 0;
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
// A sleeping scripted model produces a real run duration, so its denominator is
// measured too; only the instantaneous scripted model needs one modelled.
const measuredDenominator = REAL || MODEL_SLEEP_MS > 0;
const denominatorMs = measuredDenominator ? baseMedian : baseMedian + 2 * MODEL_MS;
const budgetMs = 0.02 * denominatorMs;
const verdict = verdictAgainst(stats, budgetMs);


const mid = (/** @type {number[]} */ a) => (a.length === 0 ? null : median(a));

/**
 * The direct measure's own interval, from a single sample rather than a paired
 * difference. There is nothing to subtract, so the spread is the spread of the
 * added work itself and not the sum of two run-time spreads — which is the
 * whole reason this resolves where the paired difference does not.
 * @param {number[]} xs
 */
function sampleInterval(xs) {
  const n = xs.length;
  if (n < 2) return null;
  const mean = xs.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(xs.reduce((a, x) => a + (x - mean) ** 2, 0) / (n - 1));
  const half = 1.96 * (sd / Math.sqrt(n));
  return {
    n,
    mean_ms: Number(mean.toFixed(4)),
    sd_ms: Number(sd.toFixed(4)),
    ci95_ms: [Number((mean - half).toFixed(4)), Number((mean + half).toFixed(4))],
    median_ms: Number((mid(xs) ?? 0).toFixed(4)),
    max_ms: Number(Math.max(...xs).toFixed(4)),
  };
}
const direct = sampleInterval(directAddedMs);

/**
 * The end-to-end difference with the model wait removed, paired run by run.
 *
 * This is the figure NFR-02's statement asks for. It is a wall-clock
 * measurement of the whole run, so every Splitstick-attributable cost is in it
 * -- including the background work and GC the direct measure cannot see -- and
 * it is still a PAIRED difference, so machine drift cancels to the extent
 * interleaving allows. What has been removed is the one component Splitstick
 * cannot influence and which contributed nothing but variance.
 */
const baseNonModel = nonModelMs.filter(x => x.label === 'baseline').map(x => x.ms);
const withNonModel = nonModelMs.filter(x => x.label === 'splitstick').map(x => x.ms);
const endToEnd = baseNonModel.length >= 2 && withNonModel.length >= 2
  ? pairedDifference(baseNonModel, withNonModel)
  : null;
const endToEndVerdict = endToEnd === null ? 'NO END-TO-END MEASUREMENT'
  : endToEnd.ci95_high <= budgetMs ? 'WITHIN BUDGET'
    : endToEnd.ci95_low > budgetMs ? 'OVER BUDGET' : 'UNRESOLVED';
/**
 * The verdict that counts, taken on the direct measure.
 *
 * Same rule as the paired one -- the whole interval must clear the budget, and
 * a budget falling inside it is UNRESOLVED rather than a pass -- applied to the
 * figure that has the resolution to answer. The paired verdict is still
 * computed and reported, because a disagreement between them is information.
 */
const directVerdict = direct === null ? 'NO DIRECT MEASUREMENT'
  : direct.ci95_ms[1] <= budgetMs ? 'WITHIN BUDGET'
    : direct.ci95_ms[0] > budgetMs ? 'OVER BUDGET' : 'UNRESOLVED';
/** How many pairs this spread needs for the whole interval to clear the budget. */
const pairsForBudget = pairsNeededFor(stats.sd_diff, budgetMs);

const report = {
  requirement: 'NFR-02',
  budget_percent: 2,
  budget_ms: Number(budgetMs.toFixed(3)),
  provider: PROVIDER,
  model_sleep_ms: MODEL_SLEEP_MS,
  // Attribution, on the same terms NFR-01 and NFR-04 publish on: a figure
  // names the machine it came from. `kind` is an acceptance measurement only
  // against a real provider -- a scripted model cannot establish a percentage
  // whose denominator is a real run.
  kind: REAL ? 'acceptance' : 'regression metric',
  machine: str('machine') ?? null,
  storage: str('storage') ?? null,
  events: RUNS,
  repeats: 1,
  model: REAL ? MODEL : 'scripted-1',
  // Assumed OR measured, never both, and the null says which.
  model_latency_assumed_ms: measuredDenominator ? null : MODEL_MS,
  model_latency_measured_ms: modelCallMs.length > 0 ? {
    calls: modelCallMs.length,
    median: Number((mid(modelCallMs) ?? 0).toFixed(3)),
    min: Number(Math.min(...modelCallMs).toFixed(3)),
    max: Number(Math.max(...modelCallMs).toFixed(3)),
  } : null,
  model_calls_per_run: [...new Set(callsPerRun)].sort((a, b) => a - b),
  denominator_ms: Number(denominatorMs.toFixed(3)),
  denominator_is_measured: measuredDenominator,
  pairs_needed_for_budget: pairsForBudget,

  // The added work, measured inside the wrapper instead of as a difference of
  // two wall-clocks. This is the figure with resolution.
  // THE FIGURE THAT ANSWERS THE REQUIREMENT AS STATED: end-to-end, paired,
  // with only the model wait removed. Everything Splitstick can affect is in
  // it, measured as wall clock rather than as intercepted calls.
  added_end_to_end_ex_model: endToEnd === null ? null : {
    n: endToEnd.n,
    mean_ms: Number(endToEnd.mean_diff.toFixed(4)),
    sd_ms: Number(endToEnd.sd_diff.toFixed(4)),
    ci95_ms: [Number(endToEnd.ci95_low.toFixed(4)), Number(endToEnd.ci95_high.toFixed(4))],
    baseline_median_ms: Number(median(baseNonModel).toFixed(3)),
  },
  added_end_to_end_percent: endToEnd === null ? null
    : Number((100 * endToEnd.mean_diff / denominatorMs).toFixed(4)),
  added_end_to_end_percent_ci_high: endToEnd === null ? null
    : Number((100 * endToEnd.ci95_high / denominatorMs).toFixed(4)),
  verdict_end_to_end: endToEndVerdict,

  added_direct: direct,
  verdict_direct: directVerdict,
  added_direct_percent: direct
    ? Number((100 * direct.mean_ms / denominatorMs).toFixed(4)) : null,
  // The upper bound of the percentage interval, flat so a claims guard can
  // address it by name. This is the number the 2% budget is checked against:
  // the requirement is met only if the WHOLE interval is below it.
  added_direct_percent_ci_high: null,
  added_direct_ci95_percent: direct ? [
    Number((100 * direct.ci95_ms[0] / denominatorMs).toFixed(4)),
    Number((100 * direct.ci95_ms[1] / denominatorMs).toFixed(4)),
  ] : null,

  // Paired minus direct. NOT a correction and not an error term: it is work the
  // direct measure cannot see (background timers, deferred flushes, GC caused
  // by the wrapper's allocations) PLUS whatever noise is in the paired figure,
  // and this harness cannot separate those. Reported so neither number can be
  // quietly preferred over the other.
  paired_minus_direct_ms: direct
    ? Number((stats.mean_diff - direct.mean_ms).toFixed(3)) : null,
  direct_within_paired_interval: direct
    ? direct.mean_ms >= stats.ci95_low && direct.mean_ms <= stats.ci95_high : null,
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
report.added_direct_percent_ci_high = report.added_direct_ci95_percent
  ? report.added_direct_ci95_percent[1] : null;
report.note = verdict === 'within'
  ? `The whole 95% interval [${report.ci95_ms[0]}, ${report.ci95_ms[1]}] ms sits below the `
    + `${report.budget_ms} ms the budget allows, so this run establishes the budget is met rather `
    + 'than merely failing to contradict it.'
    + (measuredDenominator ? '' : ' The scripted model makes this an upper bound on the PERCENTAGE: '
      + 'the added cost is journal writing and is independent of model latency — measured directly '
      + 'at 2.4 to 5.7 ms across run durations from 36 ms to 2.6 s — so a slower model grows the '
      + 'denominator without growing the numerator. That reasoning was asserted here before the '
      + 'direct measurement existed to support it, and the paired difference it rested on had '
      + 'produced a confidently NEGATIVE overhead.')
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
    measuredDenominator ? `the MEASURED ${report.denominator_ms.toFixed(0)} ms run`
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
  added, measured DIRECTLY          ${direct ? `${direct.mean_ms.toFixed(3)} ms  [${
    direct.ci95_ms[0].toFixed(3)}, ${direct.ci95_ms[1].toFixed(3)}]  = ${
    report.added_direct_percent?.toFixed(3)} %  [${report.added_direct_ci95_percent?.[0].toFixed(3)}, ${
    report.added_direct_ci95_percent?.[1].toFixed(3)}]` : 'n/a'}
  paired minus direct               ${report.paired_minus_direct_ms ?? 'n/a'} ms${
  report.direct_within_paired_interval === false
    ? '  — the two measures DISAGREE, and neither may be reported alone' : ''}

  ${report.verdict_direct}   (on the direct measure, which is the one with resolution)
  ${report.verdict}   (on the paired difference, for comparison)

  ${report.note}
`));
}
