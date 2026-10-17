// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * What a benchmark can and cannot resolve.
 *
 * This exists because three of this project's performance claims have been
 * wrong in the same way: a number reported more confidently than the
 * measurement supported. An unmeasured attribution, a measurement whose
 * instrument was never validated, and a negative overhead printed as a speedup.
 *
 * So every budget here reports its own resolution alongside its result, and a
 * verdict is only allowed to say "within budget" when the budget lies outside
 * the interval the measurement could actually distinguish.
 */

/**
 * Paired analysis of two interleaved arms.
 *
 * The arms alternate run by run, so run i of each sees the same machine
 * conditions and the pairs can be differenced directly. That is far more
 * precise than comparing two medians, which was the previous approach and which
 * could not separate a real 3 ms cost from drift.
 *
 * @param {number[]} base
 * @param {number[]} treatment
 * @returns {{
 *   n: number, mean_diff: number, sd_diff: number, stderr: number,
 *   ci95_low: number, ci95_high: number, resolution: number,
 * }}
 */
export function pairedDifference(base, treatment) {
  const n = Math.min(base.length, treatment.length);
  if (n < 2) throw new RangeError('a paired comparison needs at least two pairs');
  const diffs = Array.from({ length: n }, (_, i) =>
    /** @type {number} */ (treatment[i]) - /** @type {number} */ (base[i]));
  const mean = diffs.reduce((a, b) => a + b, 0) / n;
  const variance = diffs.reduce((a, d) => a + (d - mean) ** 2, 0) / (n - 1);
  const sd = Math.sqrt(variance);
  const stderr = sd / Math.sqrt(n);
  // 1.96 is the normal approximation; with n in the hundreds the t correction
  // is immaterial, and this is a measurement resolution rather than a p-value.
  const half = 1.96 * stderr;
  return {
    n,
    mean_diff: mean,
    sd_diff: sd,
    stderr,
    ci95_low: mean - half,
    ci95_high: mean + half,
    // The smallest difference this many pairs could distinguish from zero.
    resolution: half,
  };
}

/**
 * How many pairs would be needed to resolve a given effect.
 * @param {number} sd observed standard deviation of the paired differences
 * @param {number} effect the difference that must be distinguishable
 */
export function pairsNeededFor(sd, effect) {
  if (effect <= 0) return Infinity;
  return Math.ceil(((1.96 * sd) / effect) ** 2);
}

/**
 * A verdict that will not overclaim.
 *
 * `within` requires the whole confidence interval to sit below the budget.
 * `unresolved` is returned when the budget falls inside the interval: the
 * measurement is consistent with passing and with failing, and saying either
 * would be the mistake this module exists to prevent.
 *
 * @param {{ ci95_low: number, ci95_high: number }} stats
 * @param {number} budget in the same units
 * @returns {'within'|'over'|'unresolved'}
 */
export function verdictAgainst(stats, budget) {
  if (stats.ci95_high < budget) return 'within';
  if (stats.ci95_low > budget) return 'over';
  return 'unresolved';
}

/**
 * Check the clock is fine-grained enough to measure what is being measured.
 *
 * A timer whose granularity approaches the quantity under test produces
 * plausible numbers that mean nothing, and nothing else in the harness would
 * notice.
 * @param {number} expectedMs the smallest quantity this benchmark reports
 */
export function clockResolution(expectedMs) {
  const samples = [];
  for (let i = 0; i < 200; i++) {
    const a = process.hrtime.bigint();
    let b = process.hrtime.bigint();
    while (b === a) b = process.hrtime.bigint();
    samples.push(Number(b - a) / 1e6);
  }
  samples.sort((x, y) => x - y);
  const tick = /** @type {number} */ (samples[Math.floor(samples.length / 2)]);
  return { tick_ms: tick, adequate: tick < expectedMs / 20 };
}

/**
 * The machine a measurement came from, so a number is attributable.
 *
 * A point-in-time snapshot, and the point in time matters. `load_average_1m`
 * and `free_disk_gb` both describe the host only at the instant they are read,
 * so a caller that wants to know whether the machine was QUIET must sample
 * before it does any work. See `qualifyRun`, which refuses an observation that
 * does not carry a separate pre-run sample: reading the load average after a
 * fifteen-minute benchmark measures the benchmark.
 *
 * `free_disk_gb` is read for the temporary directory, because that is the
 * volume the benchmark fixtures are written to and therefore the one whose
 * remaining capacity can slow file creation.
 */
export async function environment() {
  const os = await import('node:os');
  const fs = await import('node:fs');
  // NaN, not Infinity, and not zero. An unreadable statfs must not satisfy a
  // free-space floor (Infinity would) and must not read as a measured failure
  // either (zero would). qualifyRun treats a non-finite reading as its own
  // named shortfall: the reading could not be taken.
  let free_disk_gb = Number.NaN;
  try {
    const st = fs.statfsSync(os.tmpdir());
    free_disk_gb = Number(((Number(st.bavail) * Number(st.bsize)) / 1024 ** 3).toFixed(2));
  } catch {
    free_disk_gb = Number.NaN;
  }
  return {
    node: process.version,
    platform: `${os.platform()} ${os.release()}`,
    arch: os.arch(),
    cpu: os.cpus()[0]?.model ?? 'unknown',
    cpus: os.cpus().length,
    total_memory_gb: Math.round(os.totalmem() / 1024 ** 3),
    load_average_1m: Number(os.loadavg()[0]?.toFixed(2) ?? 0),
    free_disk_gb,
  };
}

/**
 * Does a run satisfy the reference environment, constraint by constraint?
 *
 * Data-driven on purpose. The qualification check used to hand-list the fields
 * it cared about, and `node_major_at_least` was declared in the JSON and never
 * read — a threshold the code ignores is worse than no threshold, because it
 * reads as enforced. So every constraint key in the file must have an evaluator
 * here, and a key without one throws rather than being skipped.
 *
 * Two host samples, not one. `before` is taken BEFORE any measured work and is
 * what every "was this machine quiet and did it have room" constraint is
 * evaluated against; `env` is taken after and is what the report attributes the
 * number to. A single sample cannot serve both: a review found
 * `max_load_average_1m` being evaluated against a reading taken after the
 * measured loop, which made it unsatisfiable on every machine, because one
 * saturated single-threaded process raises its own one-minute load average to
 * roughly 1.0 and the limit is 1.0. The constraint whose stated purpose is to
 * exclude "a machine under other load" was measuring this benchmark's load.
 *
 * So an observation without a distinct `before` sample THROWS rather than
 * falling back to `env`. The fallback is the bug.
 *
 * Per-requirement constraints are merged over the shared host constraints from
 * the `requirements` block, selected by `observed.requirement`. NFR-01 and
 * NFR-04 do not want the same event count — a tail needs a million samples, a
 * single wall-clock answer is about a hundred thousand — and holding both to one
 * shared `min_events` meant every NFR-04 run reported a shortfall against a
 * figure its own requirement never asks for.
 *
 * Two phases. `final` is the real verdict and needs both host samples.
 * `preflight` runs BEFORE the measurement, against what is already knowable —
 * the machine, the event count, the attestation — and defers the constraints
 * that cannot be evaluated yet instead of passing them. Its purpose is cost: a
 * million-event run takes twenty minutes, and the reference environment used to
 * be parsed and evaluated only once that was already spent, so a host that
 * could never qualify found out afterwards. A deferred constraint is reported as
 * deferred and never counted as satisfied.
 *
 * @param {Record<string, any>} ref the parsed reference-env.json
 * @param {{ requirement: string, before: any, env?: any, events: number,
 *           repeats: number, clockAdequate: boolean,
 *           machine?: string, storage?: string }} observed
 * @param {{ phase?: 'preflight'|'final' }} [opts]
 * @returns {{ qualifies: boolean, shortfalls: string[], deferred: string[] }}
 */
export function qualifyRun(ref, observed, opts = {}) {
  const phase = opts.phase ?? 'final';
  if (!observed.before || typeof observed.before !== 'object') {
    throw new Error(
      'qualifyRun needs a host sample taken BEFORE the measured work (observed.before). '
      + 'Evaluating load average or free disk against a reading taken after the run measures '
      + 'the benchmark instead of the machine, which is how max_load_average_1m became '
      + 'unsatisfiable on every host.');
  }
  if (phase === 'final' && (!observed.env || typeof observed.env !== 'object')) {
    throw new Error(
      'the final verdict needs a host sample taken AFTER the measured work (observed.env). '
      + 'Pass { phase: "preflight" } if the run has not happened yet.');
  }
  if (observed.env !== undefined && observed.before === observed.env) {
    throw new Error(
      'qualifyRun was given the same object as both the before and after host sample. '
      + 'Call environment() twice — once before the measured work and once after — or the '
      + 'pre-run constraints are evaluated against post-run readings.');
  }
  const before = observed.before;

  // Per-requirement overrides, selected by the requirement being measured. A
  // declared block that nothing selects reads as enforced and is not, so an
  // unknown or absent requirement throws rather than falling back to the
  // shared values.
  const perRequirement = ref.requirements ?? {};
  if (Object.keys(perRequirement).length > 0) {
    if (typeof observed.requirement !== 'string' || observed.requirement === '') {
      throw new Error(
        'reference-env.json declares per-requirement constraints and qualifyRun was not told '
        + `which requirement is being measured. Pass observed.requirement (one of `
        + `${Object.keys(perRequirement).join(', ')}).`);
    }
    if (!(observed.requirement in perRequirement)) {
      throw new Error(
        `reference-env.json has no constraint block for ${JSON.stringify(observed.requirement)}; `
        + `it declares ${Object.keys(perRequirement).join(', ')}. Add a block rather than `
        + 'measuring against another requirement\'s thresholds.');
    }
  }

  /** @type {Record<string, (want: any) => string|null>} */
  const evaluators = {
    min_cpus: (want) => before.cpus >= want ? null : `${before.cpus} cpus < ${want}`,
    min_memory_gb: (want) => before.total_memory_gb >= want
      ? null : `${before.total_memory_gb} GB memory < ${want} GB`,
    max_load_average_1m: (want) => before.load_average_1m <= want
      ? null : `load average ${before.load_average_1m} > ${want} before the run started`,
    max_load_increase_1m: (want) => {
      const after = observed.env?.load_average_1m;
      if (typeof after !== 'number' || !Number.isFinite(after)) {
        return 'no post-run load average, so work that piled on during the run cannot be ruled out';
      }
      const climb = Number((after - before.load_average_1m).toFixed(2));
      return climb <= want ? null
        : `load average climbed ${climb} during the run (${before.load_average_1m} to ${after}), `
          + `more than the ${want} this benchmark can account for, so other work joined it`;
    },
    min_free_disk_gb: (want) => {
      const free = before.free_disk_gb;
      if (typeof free !== 'number' || !Number.isFinite(free)) {
        return 'free disk space could not be read, and an unreadable reading is not a passing one';
      }
      return free >= want ? null
        : `${free} GB free on the fixture volume < ${want} GB; a filesystem near capacity `
          + 'measurably slows file creation, which is most of this requirement\'s tail';
    },
    forbid_ci: (want) => {
      if (!want) return null;
      const marker = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILDKITE', 'JENKINS_URL']
        .find(k => (process.env[k] ?? '') !== '');
      return marker === undefined ? null
        : `${marker} is set, so this is a shared CI runner, where neighbours move the tail by a `
          + 'factor of two';
    },
    min_events: (want) => observed.events >= want
      ? null : `${observed.events} events < ${want}`,
    min_repeats: (want) => observed.repeats >= want
      ? null : `${observed.repeats} repeats < ${want}`,
    node_major_at_least: (want) => {
      const major = Number(process.version.replace(/^v/, '').split('.')[0]);
      return major >= want ? null : `node ${process.version} is older than ${want}`;
    },
    requires_attestation: (want) => {
      const missing = /** @type {string[]} */ (want).filter((k) => {
        const value = /** @type {any} */ (observed)[k];
        return typeof value !== 'string' || value.trim() === '';
      });
      return missing.length === 0 ? null
        : `no operator attestation for ${missing.join(' and ')} (pass --${/** @type {string[]} */ (want)[0]})`;
    },
  };

  // Descriptive keys carry no constraint; everything else must be evaluated.
  const descriptive = new Set([
    'note', 'requirement', 'excluded', 'attestation_note', 'requirements', 'requirements_note',
  ]);
  /** @type {Record<string, any>} */
  const effective = { ...ref };
  for (const k of descriptive) delete effective[k];
  Object.assign(effective, perRequirement[observed.requirement] ?? {});

  // Moving min_events and min_repeats into a per-requirement block made them
  // easy to lose silently: an absent key raises no shortfall, because there is
  // nothing to evaluate. Declared-but-unevaluated already throws; this is the
  // other direction, undeclared-and-therefore-unchecked.
  for (const required of ['min_cpus', 'min_memory_gb', 'max_load_average_1m',
    'min_events', 'min_repeats', 'requires_attestation']) {
    if (!(required in effective)) {
      throw new Error(
        `reference-env.json no longer declares ${JSON.stringify(required)} for `
        + `${observed.requirement}, so nothing checks it. An absent constraint is not a `
        + 'satisfied one; restore it or decide deliberately that this requirement has no '
        + 'such threshold and remove it from the required list here.');
    }
  }

  // Evaluated only in the final phase, because they read the post-run sample.
  const needsTheRun = new Set(['max_load_increase_1m']);

  /** @type {string[]} */
  const shortfalls = [];
  /** @type {string[]} */
  const deferred = [];
  for (const [key, want] of Object.entries(effective)) {
    if (phase === 'preflight' && needsTheRun.has(key)) {
      deferred.push(`${key} cannot be evaluated until the run has finished`);
      continue;
    }
    const evaluate = evaluators[key];
    if (!evaluate) {
      throw new Error(
        `reference-env.json declares ${JSON.stringify(key)} and bench/precision.mjs has no `
        + 'evaluator for it. A declared constraint that nothing checks reads as enforced and is '
        + 'not; add an evaluator or move the key to the descriptive list.');
    }
    const shortfall = evaluate(want);
    if (shortfall) shortfalls.push(shortfall);
  }
  if (!observed.clockAdequate) shortfalls.push('clock resolution too coarse for what is reported');
  // A preflight with nothing short does not qualify anything: the deferred
  // constraints are unevaluated, not met. Only the final phase can say yes.
  return {
    qualifies: phase === 'final' && shortfalls.length === 0,
    shortfalls,
    deferred,
  };
}
