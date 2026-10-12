/**
 * MCP over stdio — FR-03, NFR-11.
 *
 * The agent speaks to this process's stdin/stdout; this process speaks to the
 * upstream server's. Messages are newline-delimited JSON.
 *
 * TRANSPARENCY IS THE FIRST OBLIGATION. The bytes forwarded are the bytes
 * received, unchanged and in order: the proxy writes through the ORIGINAL line
 * and parses a copy for recording. Re-serialising the parsed JSON would be
 * easier and would change key order, whitespace and number formatting — so the
 * server would receive bytes the agent never sent, and the record would attest
 * to a request that was never made.
 *
 * A line that is not JSON at all is still forwarded. The proxy is not a
 * validator: repairing traffic alters what it records, and refusing traffic
 * decides what the agent may send.
 */

import { createInterface } from 'node:readline';
import { Pairing } from './pairing.mjs';
import { recorder } from './record.mjs';

/**
 * @param {object} o
 * @param {import('node:stream').Readable} o.agentIn      agent → proxy
 * @param {import('node:stream').Writable} o.agentOut     proxy → agent
 * @param {import('node:stream').Writable} o.upstreamIn   proxy → server
 * @param {import('node:stream').Readable} o.upstreamOut  server → proxy
 * @param {import('@splitstick/core/collector').Collector} o.collector
 * @param {string|null} [o.run]
 * @param {() => string} o.newCorrelation
 * @param {(e: { detail: string, cause: unknown }) => void} [o.onUnrecordable]
 * @param {() => number} [o.now]
 */
export function stdioProxy(o) {
  const pairing = new Pairing({ newCorrelation: o.newCorrelation, ...(o.now ? { now: o.now } : {}) });
  const rec = recorder({
    collector: o.collector, run: o.run ?? null,
    ...(o.onUnrecordable ? { onUnrecordable: o.onUnrecordable } : {}),
  });

  /**
   * One direction. `observe` is the pairing call for it; the write happens
   * FIRST so that a recording failure cannot delay the traffic — NFR-12 again,
   * expressed as an ordering rather than as a try/catch.
   * @param {import('node:stream').Readable} from
   * @param {import('node:stream').Writable} to
   * @param {(b: Uint8Array) => import('./pairing.mjs').Observation|null} observe
   */
  const pipe = (from, to, observe) => {
    const lines = createInterface({ input: from, crlfDelay: Infinity });
    lines.on('line', (line) => {
      // Forward first, byte for byte. The newline is re-added because readline
      // consumed it; nothing else about the line is touched.
      to.write(`${line}\n`);
      const observation = observe(Buffer.from(line, 'utf8'));
      if (observation !== null) rec.emit(observation);
    });
    lines.on('close', () => { to.end?.(); });
    return lines;
  };

  const a = pipe(o.agentIn, o.upstreamIn, b => pairing.request(b));
  const b = pipe(o.upstreamOut, o.agentOut, x => pairing.response(x));

  return {
    pairing,
    counts: rec.counts,
    /**
     * Settle anything still outstanding, as timeouts. Nothing is dropped: a
     * call whose result never arrived is a timeout, and a dropped one would
     * make a server that stopped answering look like an agent that stopped
     * asking.
     */
    close() {
      for (const t of pairing.closeAll()) rec.emit(t);
      a.close();
      b.close();
    },
  };
}
