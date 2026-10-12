/**
 * MCP over stdio — FR-03, NFR-11.
 *
 * The agent speaks to this process's stdin/stdout; this process speaks to the
 * upstream server's. Messages are newline-delimited JSON.
 *
 * TRANSPARENCY IS THE FIRST OBLIGATION. The bytes forwarded are the bytes
 * received, unchanged and in order: the proxy writes through the ORIGINAL
 * bytes and parses a copy for recording. Re-serialising the parsed JSON would
 * be easier and would change key order, whitespace and number formatting — so
 * the server would receive bytes the agent never sent, and the record would
 * attest to a request that was never made.
 *
 * That claim used to be false by one byte. Framing was read with
 * `readline`, which strips the terminator and reports the line without it, so
 * a `\r\n`-terminated message — permitted framing, and emitted by some
 * runtimes — was forwarded as `\n`: ninety bytes in, eighty-nine out, and a
 * record attesting to a line the agent did not send. The test that guarded
 * this sent only `\n`, so it passed throughout; a seam exercised once looks
 * like a seam that works. Framing is now split by hand so the terminator
 * survives, and the test sends both.
 *
 * A line that is not JSON at all is still forwarded. The proxy is not a
 * validator: repairing traffic alters what it records, and refusing traffic
 * decides what the agent may send.
 *
 * THERE IS NO SIZE CEILING HERE, unlike the HTTP transport, and the difference
 * is the transport rather than an oversight. HTTP has to buffer a whole body
 * to forward it as one request, so a limit there is the only alternative to
 * holding an unbounded body in memory — and it refuses loudly at a stated
 * size. A stdio message is forwarded as it completes, one at a time, so the
 * exposure is a single message and the bound is the same one the agent's own
 * traffic already has. Refusing a large message here would also contradict the
 * paragraph above: a proxy that decides what the agent may send is no longer
 * recording what the agent did.
 */

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
   *
   * Framing is split here rather than by `readline` so that the message is
   * forwarded with the terminator it arrived with. What is handed to `observe`
   * is the message WITHOUT its terminator — the pairing layer parses JSON and
   * a trailing `\r` is not part of the JSON — while what is written onward is
   * the original bytes including whatever ended them.
   * @param {import('node:stream').Readable} from
   * @param {import('node:stream').Writable} to
   * @param {(b: Uint8Array) => import('./pairing.mjs').Observation|null} observe
   */
  const pipe = (from, to, observe) => {
    /** @type {Buffer} */
    let buf = Buffer.alloc(0);
    let closed = false;
    const deliver = (/** @type {Buffer} */ raw) => {
      // Forward first, byte for byte, terminator and all.
      to.write(raw);
      // The payload for recording: the message without its line terminator.
      let end = raw.length;
      if (end > 0 && raw[end - 1] === 0x0a) end -= 1;
      if (end > 0 && raw[end - 1] === 0x0d) end -= 1;
      const observation = observe(raw.subarray(0, end));
      if (observation !== null) rec.emit(observation);
    };
    const onData = (/** @type {Buffer} */ chunk) => {
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      for (let i = buf.indexOf(0x0a); i !== -1; i = buf.indexOf(0x0a)) {
        deliver(buf.subarray(0, i + 1));
        buf = buf.subarray(i + 1);
      }
    };
    const onEnd = () => {
      // A final message with no terminator is still a message. Dropping it
      // would lose the last call of a run whenever a peer exits without a
      // trailing newline, and that is the call most likely to matter.
      if (buf.length > 0) { deliver(buf); buf = Buffer.alloc(0); }
      closed = true;
      to.end?.();
    };
    from.on('data', onData);
    from.on('end', onEnd);
    return {
      close() {
        from.off('data', onData);
        from.off('end', onEnd);
        if (!closed && buf.length > 0) { deliver(buf); buf = Buffer.alloc(0); }
      },
    };
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
