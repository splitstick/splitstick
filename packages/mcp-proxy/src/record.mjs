// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Turning a pairing observation into a record — FR-03, FR-04, DES-14.
 *
 * An adapter produces a DES-01 action record and hands it to core. It may not
 * touch cryptography: that is what makes the record format
 * adapter-independent, so a verifier never needs to know which collector wrote
 * a pack, and it means adding a collector cannot introduce an integrity bug.
 *
 * NFR-12 IS ABSOLUTE AND IS ENFORCED HERE. If the record cannot be written the
 * traffic still flows: the failure is surfaced out of band and the collector
 * declares the loss, because a collector that can stop an agent run is one an
 * operator will rightly disable — and then it captures nothing at all. Every
 * caller in this package goes through `emit` for exactly that reason.
 */

/**
 * @param {object} o
 * @param {import('@splitstick/core/collector').Collector} o.collector
 * @param {string|null} [o.run] the run identifier, when the deployment has one
 * @param {(e: { detail: string, cause: unknown }) => void} [o.onUnrecordable]
 *   where a failure to record is surfaced. Out of band, because the thing that
 *   failed is the place a report would otherwise go.
 */
export function recorder({ collector, run = null, onUnrecordable }) {
  /** @type {{ records: number, unrecordable: number, unparsed: number, unmatched: number,
   *            unverbatim: number, notification: number, ambiguous: number,
   *            unattributable: number }} */
  const counts = {
    records: 0, unrecordable: 0, unparsed: 0, unmatched: 0, unverbatim: 0, notification: 0,
    ambiguous: 0, unattributable: 0,
  };

  /**
   * @param {import('./pairing.mjs').Observation} o
   * @returns {boolean} whether a record landed
   */
  const emit = (o) => {
    try {
      if (o.what === 'call' || o.what === 'timeout') {
        collector.action({
          run,
          tool: o.tool ?? 'unknown',
          // Every tool call crossing a protocol boundary is consequential
          // until an operator says otherwise: the proxy cannot see which are,
          // and guessing low would understate the record.
          consequential: true,
          ...(o.args && o.args.length > 0 ? { args: o.args } : {}),
          ...(o.result ? { result: o.result } : {}),
          outcome: /** @type {'ok'|'error'|'timeout'} */ (o.outcome ?? 'ok'),
          attempt: 1,
          correlation: /** @type {string} */ (o.correlation),
        });
        counts.records += 1;
        return true;
      }
      // `unparsed` and `unmatched` are observations about the TRAFFIC, not
      // actions the agent took, so they are not action records. They are
      // surfaced out of band and counted, because a proxy that silently
      // discarded them would be hiding exactly the traffic it understood least.
      if (o.what === 'unparsed') counts.unparsed += 1;
      if (o.what === 'unmatched') counts.unmatched += 1;
      // The commitment is over a re-encoding rather than the wire bytes. Not
      // an action record — the action record still lands, when its result
      // arrives — but a reader must not be told "as sent" about bytes that
      // were not.
      if (o.what === 'unverbatim') counts.unverbatim += 1;
      // The call itself IS recorded — it is pending, and settles as an attempt
      // with no result. This counts the fact that it could never have had one.
      if (o.what === 'notification') counts.notification += 1;
      // Two outstanding calls on one id. Both are pending and both settle; what
      // is counted here is that no response can be attributed to either.
      if (o.what === 'ambiguous') counts.ambiguous += 1;
      if (o.what === 'unattributable') counts.unattributable += 1;
      onUnrecordable?.({ detail: o.detail ?? o.what, cause: null });
      return false;
    } catch (cause) {
      // NFR-12. The traffic has already been forwarded by the time this runs,
      // or is about to be regardless; nothing here may throw into the data
      // path.
      counts.unrecordable += 1;
      onUnrecordable?.({
        detail: `the proxy could not record a ${o.what}: the traffic was forwarded anyway. `
          + 'NFR-12 is absolute — a collector that can stop a run is one an operator disables. '
          + 'The loss is not silent: `Collector#action` spends the observation counter BEFORE '
          + 'anything that can fail, so an attempt that was observed and never written leaves a '
          + 'hole in source_seq and a verifier reports SEQ_BROKEN over it. Where the chain store '
          + 'itself is what failed the collector degrades instead, and the log stops rather than '
          + 'continuing from an untrustworthy position',
        cause,
      });
      return false;
    }
  };

  return { emit, counts };
}
