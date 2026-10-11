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

/** The machine a measurement came from, so a number is attributable. */
export async function environment() {
  const os = await import('node:os');
  return {
    node: process.version,
    platform: `${os.platform()} ${os.release()}`,
    arch: os.arch(),
    cpu: os.cpus()[0]?.model ?? 'unknown',
    cpus: os.cpus().length,
    total_memory_gb: Math.round(os.totalmem() / 1024 ** 3),
    load_average_1m: Number(os.loadavg()[0]?.toFixed(2) ?? 0),
  };
}
