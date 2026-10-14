// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Settling unanswered tool calls on an interval — FR-03, FR-04, NFR-12.
 *
 * `Pairing.expire()` turns a call whose result never arrived into a timeout
 * record, and for a while NOTHING CALLED IT except `closeAll()` at shutdown.
 * A long-running proxy therefore held every unanswered invocation in memory
 * indefinitely: the call was observed, forwarded, very likely executed, and
 * had no durable record at all until the process chose to exit. If it was
 * killed instead, the record never existed.
 *
 * That is the failure this capture layer exists to prevent, so settlement is
 * now on a clock rather than on goodwill. Shared by both transports for the
 * reason the pairing core is shared: two transports with two settlement
 * policies would eventually disagree about when an invocation becomes a
 * timeout, and a verifier cannot tell which one wrote a pack.
 *
 * WHAT THIS STILL DOES NOT FIX, said plainly: a `SIGKILL` between the request
 * and the next settle loses the pending call. The window is bounded by the
 * interval rather than by the process lifetime, which is the difference
 * between a bounded loss and an open-ended one, and FR-61 already bounds the
 * observation counter the same way — at each batch flush, so an unrecoverable
 * crash loses at most the current window. Closing it completely means
 * recording the attempt BEFORE forwarding it and appending the outcome later,
 * which is two records where DES-01 specifies one. That is a record-format
 * decision and docs/m6-follow-ups.md carries it.
 */

/** How long a call may go unanswered before it is a timeout. */
export const CALL_TIMEOUT_MS = 60_000;

/** How often the sweep runs. The record lands within this of the timeout. */
export const SETTLE_INTERVAL_MS = 5_000;

/**
 * @param {object} o
 * @param {import('./pairing.mjs').Pairing} o.pairing
 * @param {{ emit: (o: import('./pairing.mjs').Observation) => boolean }} o.rec
 * @param {number} [o.timeout_ms]
 * @param {number} [o.interval_ms]
 * @param {(e: { detail: string, cause: unknown }) => void} [o.onUnrecordable]
 * @param {boolean} [o.autostart] false in tests, which drive `settle()` by hand
 */
export function settler({
  pairing, rec, timeout_ms = CALL_TIMEOUT_MS, interval_ms = SETTLE_INTERVAL_MS,
  onUnrecordable, autostart = true,
}) {
  /** @type {ReturnType<typeof setInterval>|null} */
  let timer = null;

  /** Settle whatever is overdue. Returns how many records landed. */
  const settle = () => {
    let n = 0;
    // NFR-12: nothing in here may throw into a timer callback, which would
    // reject into the event loop and take the process down — the collector
    // stopping the run it is recording.
    try {
      for (const t of pairing.expire(timeout_ms)) {
        if (rec.emit(t)) n += 1;
      }
    } catch (cause) {
      onUnrecordable?.({
        detail: 'the proxy failed while settling unanswered calls; the traffic is unaffected',
        cause,
      });
    }
    return n;
  };

  const start = () => {
    if (timer !== null) return;
    timer = setInterval(settle, interval_ms);
    // Never a reason for the process to stay alive. A proxy whose agent and
    // upstream have both finished should exit, and a timer that prevented it
    // would hang every run that used this.
    timer.unref?.();
  };

  if (autostart) start();

  return {
    settle,
    start,
    stop() {
      if (timer !== null) { clearInterval(timer); timer = null; }
    },
    get running() { return timer !== null; },
  };
}
