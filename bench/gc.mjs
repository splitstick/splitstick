// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Garbage-collection measurement for the benchmarks.
 *
 * This exists so the append path's tail can be ATTRIBUTED rather than guessed
 * at, and it is a module with its own tests because of how the first two
 * attempts went.
 *
 * The first version asserted the tail was garbage collection, inferred from the
 * filesystem baseline moving with it. That is not evidence.
 *
 * The second version measured it with a PerformanceObserver and reported zero
 * pauses — and the zero was an artifact. Observer callbacks are delivered
 * asynchronously, and the benchmark disconnected immediately after a
 * synchronous loop, so the entries never arrived. The same allocation storm
 * yields 0 entries on immediate disconnect and 39 after a flush. Worse, the
 * check I wrote to verify the recorder DID flush, so it validated the recorder
 * under conditions the benchmark never met.
 *
 * So: `stop()` is async and lets pending entries drain, and `selfCheck()` runs
 * a deliberate allocation storm through exactly the same start/stop path. A
 * reported zero is only meaningful when the self-check saw something.
 */

import { PerformanceObserver } from 'node:perf_hooks';

/**
 * Draining waits for QUIESCENCE, not a fixed delay.
 *
 * A fixed 60 ms was enough on an idle machine and not enough under load, which
 * made the self-check intermittent — and an instrument check that fails
 * randomly is no more use than one that cannot fail. So the drain ticks until
 * two consecutive ticks bring nothing new, or the deadline passes.
 */
const DRAIN_TICK_MS = 25;
const DRAIN_DEADLINE_MS = 2000;

/**
 * @typedef {object} GcRun
 * @property {[number, number][]} windows start and end of each pause, on the
 *   `performance.now()` clock
 * @property {number} totalMs
 * @property {number} count
 */

export function gcRecorder() {
  /** @type {[number, number][]} */
  let windows = [];
  let totalMs = 0;
  /** @type {PerformanceObserver|null} */
  let observer = null;

  return {
    start() {
      windows = [];
      totalMs = 0;
      observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          windows.push([entry.startTime, entry.startTime + entry.duration]);
          totalMs += entry.duration;
        }
      });
      observer.observe({ entryTypes: ['gc'] });
    },

    /**
     * Drain, then disconnect. Awaiting a macrotask is the whole point: entries
     * queued during a synchronous loop are delivered after it, and the previous
     * version threw them away.
     * @returns {Promise<GcRun>}
     */
    async stop() {
      const deadline = Date.now() + DRAIN_DEADLINE_MS;
      let quiet = 0;
      let seen = -1;
      while (Date.now() < deadline && quiet < 2) {
        await new Promise((resolve) => setTimeout(resolve, DRAIN_TICK_MS));
        if (windows.length === seen) quiet += 1;
        else { quiet = 0; seen = windows.length; }
      }
      if (observer) observer.disconnect();
      observer = null;
      return { windows: [...windows], totalMs, count: windows.length };
    },
  };
}

/**
 * The share of the given samples that overlap a pause.
 * @param {{ at: number, ms: number }[]} samples
 * @param {[number, number][]} windows
 * @returns {number} 0 when there is nothing to compare
 */
export function gcOverlap(samples, windows) {
  if (samples.length === 0) return 0;
  const hits = samples.filter((s) =>
    windows.some(([from, to]) => s.at < to && s.at + s.ms > from)).length;
  return hits / samples.length;
}

/**
 * Prove the recorder observes real collections, through the same path the
 * benchmark uses. A zero from a recorder that cannot see anything is not a
 * measurement, and this project has shipped one check that could not fail
 * already.
 * @returns {Promise<{ verified: boolean, count: number }>}
 */
export async function selfCheck(attempts = 3) {
  let count = 0;
  for (let attempt = 0; attempt < attempts && count === 0; attempt++) {
    const gc = gcRecorder();
    gc.start();
    // Retained, so the collector has to work rather than discarding a sink the
    // optimiser could have elided entirely.
    let keep = [];
    for (let i = 0; i < 400_000; i++) {
      keep.push({ i, buf: Buffer.alloc(256, i % 256) });
      if (keep.length > 5000) keep = keep.slice(2500);
    }
    if (keep.length === 0) throw new Error('unreachable');   // keep the sink live
    const run = await gc.stop();
    count = run.count;
  }
  return { verified: count > 0, count };
}
