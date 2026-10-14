/**
 * MCP over HTTP — FR-04, NFR-11.
 *
 * A listener the agent posts to, forwarding to an upstream URL. Same pairing
 * core as stdio, because a tool call is the same thing over either transport
 * and a verifier cannot tell which was used (DES-14).
 *
 * TRANSPARENCY, as on stdio: the request body forwarded is the body received,
 * byte for byte, and the response body returned is the body received from
 * upstream. Both are buffered as bytes and passed through — never parsed and
 * re-serialised, which would change key order and number formatting and so
 * send the server bytes the agent never wrote.
 *
 * HEADERS ARE FORWARDED, with three exceptions, and the exceptions are the
 * interesting part. `host` must name the upstream or a virtual-host server
 * answers for the wrong site. `content-length` is recomputed because the proxy
 * holds the body it is about to send, and forwarding a stale length is how a
 * request gets truncated. Hop-by-hop headers are dropped because they describe
 * the agent's connection to the proxy and not the proxy's to the upstream.
 *
 * THE UPSTREAM IS WHAT THE OPERATOR CONFIGURED, AND THE AGENT DOES NOT GET A
 * VOTE. The request's path is applied to a copy of the upstream URL rather
 * than resolved against it: `new URL(req.url, upstream)` treats a path of
 * `//evil.example/x` as a protocol-relative URL and resolves it to
 * `http://evil.example/x`, so an agent could send its tool arguments, with its
 * own headers, to any host it liked while the record said it had talked to the
 * configured server. A confused deputy at the one boundary this proxy exists
 * to police. The origin is asserted after construction as well, because
 * "assigning pathname cannot change the host" is a fact about the URL spec and
 * not a fact this file has checked.
 *
 * NFR-12: a recording failure never becomes an HTTP error, AND NOTHING HERE
 * MAY THROW OUT OF THE REQUEST HANDLER. An upstream reply whose body could not
 * be read used to reject into the event loop, which terminates the process by
 * default: the agent lost its MCP server entirely, triggered from the side of
 * the boundary that is not trusted. The handler is wrapped, and the response
 * body is capped the way the request body already was.
 */

import { createServer } from 'node:http';
import { Pairing } from './pairing.mjs';
import { recorder } from './record.mjs';
import { settler } from './settle.mjs';

/**
 * Headers that describe one connection and must not be relayed to the next.
 * RFC 9110 §7.6.1. Forwarding `connection: keep-alive` upstream is a
 * misstatement about a connection the upstream is not party to.
 */
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

/**
 * @param {object} o
 * @param {string} o.upstream the upstream MCP endpoint, as an absolute URL
 * @param {import('@splitstick/core/collector').Collector} o.collector
 * @param {() => string} o.newCorrelation
 * @param {string|null} [o.run]
 * @param {(e: { detail: string, cause: unknown }) => void} [o.onUnrecordable]
 * @param {typeof globalThis.fetch} [o.fetchImpl] injected, so a test makes no
 *   network call and a deployment can route through its own client
 * @param {number} [o.maxBodyBytes] refused loudly at a stated limit rather
 *   than silently truncated — inventory row 11. Applies to the upstream's
 *   RESPONSE as well: the request had a ceiling and the response did not, so
 *   an untrusted upstream could exhaust memory through the component whose
 *   first obligation is not to stop the run
 * @param {number} [o.call_timeout_ms] how long a call may go unanswered
 * @param {number} [o.settle_interval_ms] how often the sweep runs
 * @param {boolean} [o.autosettle] false in tests, which drive `settle()` by hand
 * @param {() => number} [o.now]
 */
export function httpProxy(o) {
  const upstream = new URL(o.upstream);
  const fetchImpl = o.fetchImpl ?? globalThis.fetch;
  const maxBodyBytes = o.maxBodyBytes ?? 32 * 1024 * 1024;
  const pairing = new Pairing({
    newCorrelation: o.newCorrelation, ...(o.now ? { now: o.now } : {}),
  });
  const rec = recorder({
    collector: o.collector, run: o.run ?? null,
    ...(o.onUnrecordable ? { onUnrecordable: o.onUnrecordable } : {}),
  });

  // On a clock, not on shutdown. An unanswered call used to sit in memory
  // until the process chose to exit, and never became a record if it was
  // killed instead.
  const sweep = settler({
    pairing, rec,
    ...(o.call_timeout_ms !== undefined ? { timeout_ms: o.call_timeout_ms } : {}),
    ...(o.settle_interval_ms !== undefined ? { interval_ms: o.settle_interval_ms } : {}),
    ...(o.onUnrecordable ? { onUnrecordable: o.onUnrecordable } : {}),
    ...(o.autosettle === false ? { autostart: false } : {}),
  });

  /** The configured origin. Nothing the agent sends may change it. */
  const origin = upstream.origin;

  const server = createServer((req, res) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    let refused = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBodyBytes) {
        // Loudly, at a stated limit. Silently truncating would hand the
        // upstream a different request than the agent made and record a third
        // thing — the worst of the three available outcomes.
        refused = true;
        res.writeHead(413, { 'content-type': 'text/plain' });
        res.end(`request body exceeds ${maxBodyBytes} bytes\n`);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', async () => {
      if (refused) return;
      try {
        await handle(req, res, chunks);
      } catch (cause) {
        // NFR-12, absolutely. This used to reject into the event loop, which
        // terminates the process by default — so an upstream that truncated a
        // reply took the agent's MCP server down with it. The agent gets an
        // answer, the proxy keeps serving, and the failure is surfaced out of
        // band where it belongs.
        o.onUnrecordable?.({
          detail: 'the proxy failed while handling a request; the agent was answered and the '
            + 'proxy is still serving, because a collector that can stop a run is one an '
            + 'operator disables',
          cause,
        });
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' });
          res.end('proxy error\n');
        } else {
          res.end();
        }
      }
    });
  });

  /**
   * Read an upstream reply, or null if it cannot be read or will not fit.
   * @param {any} response @param {number} cap
   * @returns {Promise<Buffer|null>}
   */
  async function readCapped(response, cap) {
    try {
      const declared = Number(response.headers?.get?.('content-length') ?? NaN);
      if (Number.isFinite(declared) && declared > cap) return null;
      const buf = Buffer.from(await response.arrayBuffer());
      return buf.length > cap ? null : buf;
    } catch {
      return null;
    }
  }

  /**
   * The request, once its body is in hand.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {Buffer[]} chunks
   */
  async function handle(req, res, chunks) {
    {
      const body = Buffer.concat(chunks);

      /** @type {Record<string, string>} */
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const key = k.toLowerCase();
        if (HOP_BY_HOP.has(key) || key === 'host' || key === 'content-length') continue;
        if (typeof v === 'string') headers[k] = v;
        else if (Array.isArray(v)) headers[k] = v.join(', ');
      }
      headers.host = upstream.host;
      if (body.length > 0) headers['content-length'] = String(body.length);

      // The path and query are APPLIED TO the upstream URL, never resolved
      // against it. See the header: resolution reads `//host/x` as a new
      // origin.
      const target = new URL(upstream);
      const raw = req.url ?? '/';
      const q = raw.indexOf('?');
      target.pathname = q === -1 ? raw : raw.slice(0, q);
      target.search = q === -1 ? '' : raw.slice(q);
      if (target.origin !== origin) {
        // Unreachable by construction today. Asserted anyway: the construction
        // is only safe because of how the URL pathname setter behaves, and a
        // boundary that holds because of something another specification says
        // is a boundary this file has not checked.
        o.onUnrecordable?.({
          detail: `a request for ${JSON.stringify(raw)} resolved to ${target.origin}, which is `
            + `not the configured upstream ${origin}; it was refused rather than sent`,
          cause: null,
        });
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end('the request path does not address the configured upstream\n');
        return;
      }

      let upstreamRes;
      try {
        upstreamRes = await fetchImpl(target, {
          method: req.method ?? 'POST',
          headers,
          ...(body.length > 0 ? { body } : {}),
        });
      } catch (cause) {
        // The upstream is unreachable. That is the upstream's failure and the
        // agent must see it as one — not as a proxy error, which would make a
        // server outage look like a collector fault.
        o.onUnrecordable?.({ detail: `the upstream ${target} could not be reached`, cause });
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('upstream unreachable\n');
        // The request is still a call that was attempted, so it is left
        // outstanding and settled as a timeout by expire()/close().
        //
        // Whatever the pairing layer actually says, and nothing invented. A
        // `?? { what: 'unparsed' }` used to stand here, and `request()` returns
        // null for a well-formed call — so every valid tool call to a down
        // upstream was reported as traffic the proxy could not parse, which was
        // false about the traffic and inflated the count an operator reads to
        // judge how much of it the proxy did not understand.
        const asked = pairing.request(body);
        if (asked !== null) rec.emit(asked);
        return;
      }

      const out = await readCapped(upstreamRes, maxBodyBytes);
      if (out === null) {
        // The upstream's reply could not be read, or would not fit. Returned as
        // the upstream failure it is; the call stays outstanding and settles as
        // a timeout, which is the honest end for a call whose result never
        // arrived intact.
        o.onUnrecordable?.({
          detail: `the reply from ${target} could not be read within ${maxBodyBytes} bytes; the `
            + 'call is left outstanding and settles as a timeout',
          cause: null,
        });
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('upstream reply unreadable\n');
        const asked = pairing.request(body);
        if (asked !== null) rec.emit(asked);
        return;
      }
      /** @type {Record<string, string>} */
      const back = {};
      upstreamRes.headers.forEach((v, k) => {
        if (!HOP_BY_HOP.has(k.toLowerCase()) && k.toLowerCase() !== 'content-length') back[k] = v;
      });
      // Returned FIRST, exactly as received. Recording happens after the agent
      // has its answer, so nothing on the recording side can delay or alter it.
      res.writeHead(upstreamRes.status, back);
      res.end(out);

      const asked = pairing.request(body);
      if (asked !== null) rec.emit(asked);
      const answered = pairing.response(out);
      if (answered !== null) rec.emit(answered);
    }
  }

  return {
    server,
    pairing,
    counts: rec.counts,
    /** Settle overdue calls now. The interval does this on its own. */
    settle: sweep.settle,
    /** @param {number} [port] @param {string} [host] */
    listen(port = 0, host = '127.0.0.1') {
      return new Promise((resolve) => {
        server.listen(port, host, () => resolve(/** @type {any} */ (server.address())));
      });
    },
    close() {
      sweep.stop();
      for (const t of pairing.closeAll()) rec.emit(t);
      return new Promise((resolve) => server.close(() => resolve(undefined)));
    },
  };
}
