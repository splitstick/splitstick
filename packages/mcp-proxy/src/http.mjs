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
 * NFR-12: a recording failure never becomes an HTTP error. The upstream's
 * status and body are returned exactly as received whatever happens on the
 * recording side.
 */

import { createServer } from 'node:http';
import { Pairing } from './pairing.mjs';
import { recorder } from './record.mjs';

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
 *   than silently truncated — inventory row 11
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

      const target = new URL(req.url ?? '/', upstream);

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
        rec.emit(pairing.request(body) ?? { what: 'unparsed', detail: 'forwarded, upstream down' });
        return;
      }

      const out = Buffer.from(await upstreamRes.arrayBuffer());
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
    });
  });

  return {
    server,
    pairing,
    counts: rec.counts,
    /** @param {number} [port] @param {string} [host] */
    listen(port = 0, host = '127.0.0.1') {
      return new Promise((resolve) => {
        server.listen(port, host, () => resolve(/** @type {any} */ (server.address())));
      });
    },
    close() {
      for (const t of pairing.closeAll()) rec.emit(t);
      return new Promise((resolve) => server.close(() => resolve(undefined)));
    },
  };
}
