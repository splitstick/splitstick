import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { PassThrough } from 'node:stream';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { Pairing, stdioProxy, httpProxy } from '../src/index.mjs';
import { tokenizeCommand, runProxy, parseArgs, isUrl } from '../src/cli.mjs';

const ORIGIN = 'splitstick.dev/proxy';

/** A collector whose clock the test drives. */
async function rig() {
  const root = mkdtempSync(join(tmpdir(), 'ss-mcp-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'proxy');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'proxy', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  let n = 0;
  /** @type {string[]} */
  const oob = [];
  return {
    root, store, collector,
    newCorrelation: () => `c-${++n}`,
    onUnrecordable: (/** @type {{detail: string}} */ e) => oob.push(e.detail),
    oob,
    records: () => store.readChain().map(e => e.record),
  };
}

const call = (/** @type {number|string} */ id, /** @type {string} */ name, /** @type {any} */ args) =>
  JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
const ok = (/** @type {number|string} */ id, /** @type {any} */ result) =>
  JSON.stringify({ jsonrpc: '2.0', id, result });
const err = (/** @type {number|string} */ id, /** @type {string} */ message) =>
  JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message } });

const tick = () => new Promise(r => setImmediate(r));

/** A stdio proxy with both directions wired to streams the test drives. */
function wire(/** @type {any} */ r) {
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upstreamIn = new PassThrough();
  const upstreamOut = new PassThrough();
  /** @type {string[]} */
  const upstreamSaw = [];
  /** @type {string[]} */
  const agentSaw = [];
  upstreamIn.on('data', d => upstreamSaw.push(d.toString()));
  agentOut.on('data', d => agentSaw.push(d.toString()));
  const proxy = stdioProxy({
    agentIn, agentOut, upstreamIn, upstreamOut,
    collector: r.collector, newCorrelation: r.newCorrelation, onUnrecordable: r.onUnrecordable,
  });
  return { agentIn, upstreamOut, upstreamSaw, agentSaw, proxy };
}

// ── FR-03: stdio ────────────────────────────────────────────────────────────

test('FR-03: a call and its result become one record over stdio', async () => {
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${call(1, 'transfer_funds', { amount: 200 })}\n`);
  await tick();
  w.upstreamOut.write(`${ok(1, { content: [{ type: 'text', text: 'TX-77814' }] })}\n`);
  await tick();
  w.proxy.close();
  await tick();

  const recs = r.records();
  assert.equal(recs.length, 1, 'one record, not one per direction');
  assert.equal(recs[0]?.kind, 'tool_call');
  assert.equal(recs[0]?.tool, 'transfer_funds');
  assert.equal(recs[0]?.outcome, 'ok');
  assert.equal(recs[0]?.consequential, true);
  r.store.close();
});

test('FR-03: a CRLF-terminated message is forwarded with its CRLF', async () => {
  // The transparency claim was false by one byte. `readline` strips the
  // terminator and reports the line without it, so `\r\n` went out as `\n`
  // and the record attested to a line the agent had not sent. The test beside
  // this one sent only `\n` and passed throughout — a seam exercised once.
  const { collector, store } = await rig();
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upIn = new PassThrough();
  const upOut = new PassThrough();
  /** @type {Buffer[]} */
  const seen = [];
  upIn.on('data', (d) => seen.push(d));
  stdioProxy({
    agentIn, agentOut, upstreamIn: upIn, upstreamOut: upOut,
    collector, newCorrelation: () => 'cor-crlf', onUnrecordable: () => {},
  });

  const req = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount: 1 } },
  });
  // Both framings, in one stream, because a reader that handled only one would
  // pass whichever was tested.
  const sent = Buffer.from(`${req}\r\n${req}\n`, 'utf8');
  agentIn.write(sent);
  await new Promise((r) => setTimeout(r, 60));

  assert.equal(Buffer.compare(Buffer.concat(seen), sent), 0,
    'the server did not receive the bytes the agent sent');
  // And the record parsed, so preserving the terminator did not come at the
  // cost of the \r landing inside the JSON the pairing layer reads.
  assert.equal(store.readChain().filter(e => /** @type {any} */ (e).record?.kind === 'tool_call').length, 0,
    'nothing is recorded until the results arrive, which is the pairing contract');
  store.close();
});

test('FR-03: a final message with no terminator is not dropped', async () => {
  // Splitting on the newline by hand introduces the chance of losing a
  // trailing partial, and the trailing one is the last call of a run — the
  // call most likely to be the one somebody is asking about.
  const { collector, store } = await rig();
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upIn = new PassThrough();
  const upOut = new PassThrough();
  /** @type {Buffer[]} */
  const seen = [];
  upIn.on('data', (d) => seen.push(d));
  stdioProxy({
    agentIn, agentOut, upstreamIn: upIn, upstreamOut: upOut,
    collector, newCorrelation: () => 'cor-tail', onUnrecordable: () => {},
  });
  const req = JSON.stringify({
    jsonrpc: '2.0', id: 7, method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount: 7 } },
  });
  agentIn.end(req);  // no trailing newline at all
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(Buffer.concat(seen).toString('utf8'), req,
    'the last message of the stream was dropped');
  store.close();
});

test('FR-03: the bytes the server sees are the bytes the agent sent', async () => {
  // Transparency is the proxy's first obligation. Re-serialising the parsed
  // JSON would be easier and would change key order, whitespace and number
  // formatting — so the server would receive bytes the agent never sent and the
  // record would attest to a request that was never made.
  const r = await rig();
  const w = wire(r);
  // Deliberately awkward: unsorted keys, odd spacing, a float, a unicode escape.
  const raw = '{"jsonrpc":"2.0","params":{"arguments":{"b":1.50,"a":"\\u00e9"},'
    + '"name":"t"},"method":"tools/call","id":7}';
  w.agentIn.write(`${raw}\n`);
  await tick();
  const answer = '{"result":{"x":  1},"id":7,"jsonrpc":"2.0"}';
  w.upstreamOut.write(`${answer}\n`);
  await tick();
  w.proxy.close();
  await tick();

  assert.equal(w.upstreamSaw.join(''), `${raw}\n`, 'forwarded byte for byte');
  assert.equal(w.agentSaw.join(''), `${answer}\n`, 'and back byte for byte');
  r.store.close();
});

test('FR-03 row 7: concurrent calls are paired by id, never by arrival order', async () => {
  // MCP allows concurrent requests, so the second response is routinely for the
  // first request. Pairing by order would attribute one tool's result to
  // another tool's call — a false record rather than a missing one.
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${call(1, 'transfer_funds', { amount: 200 })}\n`);
  w.agentIn.write(`${call(2, 'read_file', { path: '/etc/hosts' })}\n`);
  await tick();
  // Answered OUT OF ORDER, and the second one fails.
  w.upstreamOut.write(`${ok(2, { text: '127.0.0.1' })}\n`);
  w.upstreamOut.write(`${err(1, 'insufficient funds')}\n`);
  await tick();
  w.proxy.close();
  await tick();

  const recs = r.records();
  assert.equal(recs.length, 2);
  const byTool = new Map(recs.map(x => [x.tool, x]));
  assert.equal(byTool.get('read_file')?.outcome, 'ok');
  assert.equal(byTool.get('transfer_funds')?.outcome, 'error',
    'the failure belongs to the transfer, not to the file read');
  // Distinct correlations: two logical actions, not two attempts at one.
  assert.notEqual(byTool.get('read_file')?.correlation, byTool.get('transfer_funds')?.correlation);
  r.store.close();
});

test('FR-03 row 8: a response with an id nobody sent is reported, never matched', async () => {
  // The nearest request is a guess, and a guess here invents a tool result.
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${call(1, 'transfer_funds', { amount: 200 })}\n`);
  await tick();
  w.upstreamOut.write(`${ok(99, { looks: 'plausible' })}\n`);
  await tick();

  assert.equal(r.records().length, 0, 'nothing is recorded for an id nobody used');
  assert.equal(w.proxy.counts.unmatched, 1);
  assert.ok(r.oob.some(d => /no request used that id/.test(d)));
  assert.ok(r.oob.some(d => /the nearest call is a guess/.test(d)));
  // And the real call is still outstanding, so it settles as a timeout.
  w.proxy.close();
  await tick();
  const recs = r.records();
  assert.equal(recs.length, 1);
  assert.equal(recs[0]?.outcome, 'timeout');
  r.store.close();
});

test('FR-03 row 6: traffic that is not JSON-RPC is forwarded unchanged and reported', async () => {
  // A proxy that repaired traffic would be altering what it records; one that
  // refused it would be deciding what the agent may send.
  const r = await rig();
  const w = wire(r);
  for (const junk of ['not json at all', '[1,2,3]', '{"jsonrpc":"2.0"', 'null']) {
    w.agentIn.write(`${junk}\n`);
  }
  await tick();
  w.proxy.close();
  await tick();

  assert.equal(w.upstreamSaw.join(''), 'not json at all\n[1,2,3]\n{"jsonrpc":"2.0"\nnull\n',
    'every line forwarded unchanged, including the one that is valid JSON but not a message');
  assert.equal(r.records().length, 0, 'and none of it is an action record');
  assert.equal(w.proxy.counts.unparsed, 4);
  r.store.close();
});

test('FR-03 row 5: a call that is never answered is a timeout, never a drop', async () => {
  // Dropping it would make a server that stopped answering look like an agent
  // that stopped asking.
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${call(1, 'slow_tool', { x: 1 })}\n`);
  w.agentIn.write(`${call(2, 'other_tool', { y: 2 })}\n`);
  await tick();
  assert.equal(w.proxy.pairing.outstanding, 2);
  w.proxy.close();
  await tick();

  const recs = r.records();
  assert.equal(recs.length, 2);
  for (const x of recs) assert.equal(x.outcome, 'timeout');
  assert.deepEqual(recs.map(x => x.tool).sort(), ['other_tool', 'slow_tool']);
  r.store.close();
});

test('NFR-12: a recording failure does not stop the traffic', async () => {
  // Absolute. A collector that can halt production is one an operator will
  // rightly disable, and then it captures nothing at all.
  const r = await rig();
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upstreamIn = new PassThrough();
  const upstreamOut = new PassThrough();
  /** @type {string[]} */
  const upstreamSaw = [];
  upstreamIn.on('data', d => upstreamSaw.push(d.toString()));

  // A collector that refuses every write.
  const broken = /** @type {any} */ ({
    action() { throw new Error('the store is full'); },
  });
  const proxy = stdioProxy({
    agentIn, agentOut, upstreamIn, upstreamOut,
    collector: broken, newCorrelation: r.newCorrelation, onUnrecordable: r.onUnrecordable,
  });

  const raw = call(1, 'transfer_funds', { amount: 200 });
  agentIn.write(`${raw}\n`);
  await tick();
  upstreamOut.write(`${ok(1, { done: true })}\n`);
  await tick();

  assert.equal(upstreamSaw.join(''), `${raw}\n`, 'the traffic flowed regardless');
  assert.equal(proxy.counts.unrecordable, 1);
  assert.ok(r.oob.some(d => /NFR-12 is absolute/.test(d)),
    'and the failure is surfaced out of band for the collector to declare');
  proxy.close();
  r.store.close();
});

// ── FR-04: HTTP ─────────────────────────────────────────────────────────────

/** @param {any} r @param {(req: any) => Response|Promise<Response>} upstream */
function wireHttp(r, upstream) {
  /** @type {any[]} */
  const received = [];
  const fetchImpl = async (/** @type {any} */ url, /** @type {any} */ init) => {
    const req = {
      url: String(url), method: init.method, headers: init.headers,
      body: init.body ? Buffer.from(init.body).toString('utf8') : null,
    };
    received.push(req);
    return upstream(req);
  };
  const proxy = httpProxy({
    upstream: 'https://upstream.invalid/mcp', collector: r.collector,
    newCorrelation: r.newCorrelation, onUnrecordable: r.onUnrecordable,
    fetchImpl: /** @type {any} */ (fetchImpl),
  });
  return { proxy, received };
}

test('FR-04: the same capture over HTTP, and a verifier cannot tell the transports apart', async () => {
  // DES-14: the record format is adapter-independent. Two transports producing
  // different records would make a verifier's answer depend on a deployment
  // detail it cannot see.
  const body = call(1, 'transfer_funds', { amount: 200 });
  const answer = ok(1, { content: [{ type: 'text', text: 'TX-77814' }] });

  const overHttp = await rig();
  const h = wireHttp(overHttp, () => new Response(answer, {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  const addr = /** @type {any} */ (await h.proxy.listen());
  const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), answer, 'the upstream body is returned verbatim');
  await h.proxy.close();

  const overStdio = await rig();
  const w = wire(overStdio);
  w.agentIn.write(`${body}\n`);
  await tick();
  w.upstreamOut.write(`${answer}\n`);
  await tick();
  w.proxy.close();
  await tick();

  // Not "down to the commitments": a content cid is SALTED per store, so the
  // same bytes in two stores commit to different digests, which is the point
  // of the salt. Comparing cids across stores would be comparing two random
  // salts. What must match is the SHAPE and the PLAINTEXT.
  const strip = (/** @type {any} */ x) => {
    const { ts, record_seq, source_seq, collector, args, result, ...rest } = x;
    return { ...rest, args: { bytes: args.bytes }, result: { bytes: result.bytes, ok: result.ok } };
  };
  const a = /** @type {any} */ (overHttp.records()[0]);
  const b = /** @type {any} */ (overStdio.records()[0]);
  assert.deepEqual(strip(a), strip(b),
    'identical records from the two transports, field for field and length for length');
  // And the plaintext behind each commitment is the same, which is the
  // equivalence that actually matters to a reader.
  assert.equal(
    overHttp.store.content.get(a.args.cid).toString('utf8'),
    overStdio.store.content.get(b.args.cid).toString('utf8'),
  );
  assert.equal(
    overHttp.store.content.get(a.result.cid).toString('utf8'),
    overStdio.store.content.get(b.result.cid).toString('utf8'),
  );
  overHttp.store.close();
  overStdio.store.close();
});

test('FR-04: the request reaches the upstream byte for byte, with the headers corrected', async () => {
  // `host` must name the upstream or a virtual-host server answers for the
  // wrong site. `content-length` is recomputed because forwarding a stale
  // length is how a request gets truncated. Hop-by-hop headers describe the
  // agent's connection to the proxy, not the proxy's to the upstream.
  const r = await rig();
  const answer = ok(1, { done: true });
  const h = wireHttp(r, () => new Response(answer, {
    status: 200, headers: { 'content-type': 'application/json', 'x-upstream': 'yes' },
  }));
  const addr = /** @type {any} */ (await h.proxy.listen());
  const body = call(1, 't', { a: 1 });
  const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-trace': 'keep-me' },
    body,
  });
  await res.text();
  await h.proxy.close();

  const seen = h.received[0];
  assert.equal(seen.body, body, 'byte for byte');
  assert.equal(seen.headers.host, 'upstream.invalid', 'host names the upstream');
  assert.equal(seen.headers['x-trace'], 'keep-me', 'an ordinary header is relayed');
  assert.equal(seen.headers.connection, undefined, 'hop-by-hop is not relayed');
  assert.equal(seen.headers['content-length'], String(Buffer.byteLength(body)), 'recomputed');
  assert.equal(res.headers.get('x-upstream'), 'yes', 'and the response headers come back');
  r.store.close();
});

test('FR-04 row 4: an upstream error is the result, recorded as an outcome', async () => {
  // An error is an outcome, not an absence: a call that failed happened.
  const r = await rig();
  const h = wireHttp(r, () => new Response(err(1, 'insufficient funds'), {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  const addr = /** @type {any} */ (await h.proxy.listen());
  await (await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
    method: 'POST', body: call(1, 'transfer_funds', { amount: 1 }),
  })).text();
  await h.proxy.close();

  const recs = r.records();
  assert.equal(recs.length, 1);
  assert.equal(recs[0]?.outcome, 'error');
  assert.equal(recs[0]?.tool, 'transfer_funds');
  r.store.close();
});

test('FR-04: an unreachable upstream is the upstream\'s failure, not the proxy\'s', async () => {
  // Returning a proxy error would make a server outage look like a collector
  // fault, which is the one diagnosis that sends an operator to the wrong team.
  const r = await rig();
  const h = wireHttp(r, () => { throw new Error('ECONNREFUSED'); });
  const addr = /** @type {any} */ (await h.proxy.listen());
  const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
    method: 'POST', body: call(1, 't', { a: 1 }),
  });
  assert.equal(res.status, 502);
  await res.text();
  await h.proxy.close();

  assert.ok(r.oob.some(d => /could not be reached/.test(d)));
  // The call was attempted, so it settles as a timeout rather than vanishing.
  const recs = r.records();
  assert.equal(recs.length, 1);
  assert.equal(recs[0]?.outcome, 'timeout');
  r.store.close();
});

test('FR-04 row 11: an oversized body is refused loudly, never truncated', async () => {
  // Silently truncating would hand the upstream a different request than the
  // agent made and record a third thing — the worst of the three outcomes.
  const r = await rig();
  /** @type {any[]} */
  const received = [];
  const proxy = httpProxy({
    upstream: 'https://upstream.invalid/mcp', collector: r.collector,
    newCorrelation: r.newCorrelation, onUnrecordable: r.onUnrecordable,
    maxBodyBytes: 64,
    fetchImpl: /** @type {any} */ (async (/** @type {any} */ u, /** @type {any} */ i) => {
      received.push(i);
      return new Response('{}', { status: 200 });
    }),
  });
  const addr = /** @type {any} */ (await proxy.listen());
  const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
    method: 'POST', body: call(1, 't', { pad: 'x'.repeat(500) }),
  });
  assert.equal(res.status, 413);
  assert.match(await res.text(), /exceeds 64 bytes/);
  assert.equal(received.length, 0, 'nothing truncated was forwarded');
  assert.equal(r.records().length, 0);
  await proxy.close();
  r.store.close();
});

// ── the pairing core, directly ──────────────────────────────────────────────

test('the pairing core is transport-independent, and a notification is not a call', async () => {
  // Two transports with two pairing implementations would eventually disagree
  // about what a call is, and a verifier cannot tell which transport wrote a
  // pack — so the disagreement would surface as evidence that is subtly wrong.
  let n = 0;
  const p = new Pairing({ newCorrelation: () => `x-${++n}`, now: () => 1000 });
  const b = (/** @type {string} */ s) => Buffer.from(s, 'utf8');

  // A notification has no id and is not a call.
  assert.equal(p.request(b(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }))), null);
  assert.equal(p.outstanding, 0);

  // A non-tool request is not a call either.
  assert.equal(p.request(b(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }))), null);
  assert.equal(p.outstanding, 0, 'tools/list is not a tool call');

  // A tool call is pending until its result arrives.
  assert.equal(p.request(b(call(2, 'transfer_funds', { amount: 1 }))), null);
  assert.equal(p.outstanding, 1);
  const o = p.response(b(ok(2, { done: true })));
  assert.equal(o?.what, 'call');
  assert.equal(o?.tool, 'transfer_funds');
  assert.equal(o?.outcome, 'ok');
  assert.equal(p.outstanding, 0, 'and is no longer pending');

  // The same id again is now unmatched, not a second result for the same call.
  assert.equal(p.response(b(ok(2, { done: true })))?.what, 'unmatched');
});

test('the args committed are the arguments, not the JSON-RPC envelope', async () => {
  // Committing to the whole envelope would put the JSON-RPC id in the record,
  // and ids are a per-connection counter that says nothing about the action —
  // two identical actions on different connections would commit to different
  // bytes.
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${call(1, 't', { amount: 200 })}\n`);
  await tick();
  w.upstreamOut.write(`${ok(1, {})}\n`);
  await tick();
  w.proxy.close();
  await tick();

  const rec = /** @type {any} */ (r.records()[0]);
  assert.equal(rec?.args.bytes, Buffer.byteLength('{"amount":200}'),
    'the arguments alone');
  r.store.close();
});

test('a tool call with no arguments commits to nothing rather than to an empty object', async () => {
  const r = await rig();
  const w = wire(r);
  w.agentIn.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'ping' } })}\n`);
  await tick();
  w.upstreamOut.write(`${ok(1, { pong: true })}\n`);
  await tick();
  w.proxy.close();
  await tick();

  const rec = r.records()[0];
  assert.equal(rec?.tool, 'ping');
  assert.equal(rec?.args, undefined, 'no args commitment at all, rather than one over "{}"');
  r.store.close();
});

// ── FR-49: the CLI contract, at the seam the documentation names ───────────

test('--upstream carries a command WITH its arguments', async () => {
  // `--upstream "node ./server.mjs"` was handed to spawn() whole as the
  // PROGRAM NAME, so every realistic upstream — `node x.mjs`, `uvx server`,
  // `docker run ...` — failed with ENOENT. Every documented form was the
  // broken form.
  assert.deepEqual(tokenizeCommand('node ./server.mjs').argv, ['node', './server.mjs']);
  assert.deepEqual(tokenizeCommand('uvx  some-mcp-server  --port 9').argv,
    ['uvx', 'some-mcp-server', '--port', '9']);
  assert.deepEqual(tokenizeCommand('node "/opt/my servers/a.mjs"').argv,
    ['node', '/opt/my servers/a.mjs'], 'a path with a space is not an exotic case');
  assert.deepEqual(tokenizeCommand("node '/opt/my servers/a.mjs'").argv,
    ['node', '/opt/my servers/a.mjs']);
  assert.deepEqual(tokenizeCommand('node /opt/my\\ servers/a.mjs').argv,
    ['node', '/opt/my servers/a.mjs']);
  assert.deepEqual(tokenizeCommand('server').argv, ['server'], 'and the bare case still works');
});

test('an unterminated quote in --upstream is refused, not closed for the caller', async () => {
  // Guessing where the operator meant the argument to end is guessing which
  // process to run.
  const r = tokenizeCommand('node "/opt/a.mjs');
  assert.match(r.err, /unterminated " quote/);
  assert.deepEqual(r.argv, []);
  assert.match(tokenizeCommand('   ').err, /--upstream is empty/);
});

test('an upstream that cannot start exits non-zero, not 0', async () => {
  // Node throws an unhandled 'error' event out of the event loop as a raw
  // stack trace, and the process still exited 0: a recorder that recorded
  // nothing at all, reporting success to whatever started it.
  const dir = mkdtempSync(join(tmpdir(), 'ss-mcp-cli-'));
  const signer = await generateDevSigner(ORIGIN);
  const r = await runProxy(['--upstream', './definitely-not-here', '--out', join(dir, 'ev')],
    { signer, stdin: new PassThrough(), stdout: new PassThrough() });
  assert.equal(r.exit, 0, 'the spawn failure is asynchronous, so it is not in the return');
  await new Promise((res) => setTimeout(res, 150));
  assert.equal(process.exitCode, 4, 'but the process is left failing');
  process.exitCode = 0;
});

test('--help is an answer, so it goes to stdout', async () => {
  // It was returned in the `err` field and written to stderr, so
  // `splitstick-mcp-proxy --help > help.txt` wrote an empty file.
  const signer = await generateDevSigner(ORIGIN);
  const r = await runProxy(['--help'], { signer });
  assert.equal(r.exit, 0);
  assert.match(r.out, /^splitstick-mcp-proxy --upstream/);
  assert.equal(r.err, '', 'and nothing at all on the error stream');
});

// ── Review findings: what the record CLAIMS about the traffic ──────────────

test('the committed arguments are the wire bytes, not a re-encoding of them', async () => {
  // `JSON.stringify(msg.params.arguments)` sat under a comment saying the
  // arguments were not re-serialised. They were: `1.50` became `1.5`, `1e2`
  // became `100`, and `é` became the character. Self-consistent,
  // verifiable, and not what the agent sent — and the number of a transfer is
  // exactly where that stops being cosmetic.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  const wire = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds",'
    + '"arguments":{"amount": 1.50,"big":1e2,"note":"caf\\u00e9"}}}';
  assert.equal(p.request(Buffer.from(wire, 'utf8')), null);
  const obs = p.response(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } })));
  assert.equal(obs?.what, 'call');
  assert.equal(Buffer.from(/** @type {any} */ (obs).args).toString('utf8'),
    '{"amount": 1.50,"big":1e2,"note":"caf\\u00e9"}',
    'the commitment is not the bytes the agent sent');
});

test('the arguments span survives multi-byte characters and nested braces', async () => {
  // The scanner works on the string and converts back through the encoder; a
  // Buffer slice at a string index would cut a character in half and commit to
  // invalid UTF-8. And `"arguments"` appearing INSIDE the payload must not be
  // mistaken for the key.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  const args = '{"memo":"日本語の説明","nested":{"arguments":"not the key","a":[1,{"b":2}]}}';
  const wire = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":${args}}}`;
  p.request(Buffer.from(wire, 'utf8'));
  const obs = p.response(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })));
  assert.equal(Buffer.from(/** @type {any} */ (obs).args).toString('utf8'), args);
});

test('a response id of a different TYPE is not matched to the request', async () => {
  // JSON-RPC treats `1` and `"1"` as different ids. `String(id)` collapsed
  // them, so an upstream answering `"1"` to a request made with `1` had its
  // result attributed to a call that never received it. This module refuses to
  // match a response to the nearest request because "a guess here invents a
  // tool result"; a type coercion invents one just as effectively, and from
  // the side of the boundary that is not trusted.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  p.request(Buffer.from(JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount: 1 } },
  })));
  const obs = p.response(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: '1', result: { ok: true } })));
  assert.equal(obs?.what, 'unmatched', 'a string id was matched to a numeric request');
  assert.equal(p.outstanding, 1, 'and the real call is still awaiting its result');
  // It settles as a timeout, which is the honest end: no result ever arrived
  // for the id that was actually sent.
  const [t] = p.closeAll();
  assert.equal(t?.outcome, 'timeout');
});

test('a tools/call with no JSON-RPC id is recorded, not passed over', async () => {
  // It used to return null: the call was forwarded, a server dispatching on
  // `method` would execute it, and nothing at all was recorded. The proxy
  // exists because the agent is not trusted to report its own actions, so a
  // consequential call that leaves no trace is the one outcome it may not
  // have.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  const obs = p.request(Buffer.from(JSON.stringify({
    jsonrpc: '2.0', method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount: 2000000 } },
  })));
  assert.equal(obs?.what, 'notification');
  assert.match(String(obs?.detail), /can never receive a result/);
  assert.equal(p.outstanding, 1, 'the call is pending, so it cannot vanish');

  const settled = p.closeAll();
  assert.equal(settled.length, 1);
  assert.equal(settled[0]?.outcome, 'timeout', 'observed, and no result ever received');
  assert.equal(settled[0]?.tool, 'transfer_funds');
  assert.equal(Buffer.from(/** @type {any} */ (settled[0]).args).toString('utf8'),
    '{"amount":2000000}', 'the arguments of the invisible call are committed');
});

test('two id-less calls are two records, not one', async () => {
  // They share no id, so a single synthetic key would have collapsed them and
  // hidden the second — which is the shape of the bug being fixed, one level
  // down.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  for (const amount of [1, 2]) {
    p.request(Buffer.from(JSON.stringify({
      jsonrpc: '2.0', method: 'tools/call', params: { name: 't', arguments: { amount } },
    })));
  }
  assert.equal(p.outstanding, 2);
  assert.deepEqual(p.closeAll().map(o => Buffer.from(/** @type {any} */ (o).args).toString('utf8')),
    ['{"amount":1}', '{"amount":2}']);
});

test('a response can never collide with an id-less call\'s pending key', async () => {
  // The synthetic key is `notification:#n`, and `idKey` is always `string:` or
  // `number:`, so no response of either type can reach it. Asserted rather
  // than reasoned about, because a collision here would attribute a real
  // server result to a call that never asked for one.
  const p = new Pairing({ newCorrelation: () => 'cor' });
  p.request(Buffer.from(JSON.stringify({
    jsonrpc: '2.0', method: 'tools/call', params: { name: 't', arguments: { a: 1 } },
  })));
  for (const id of ['notification:#1', 1, 'string:notification:#1']) {
    const obs = p.response(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, result: { ok: true } })));
    assert.equal(obs?.what, 'unmatched', `id ${JSON.stringify(id)} reached the synthetic key`);
  }
  assert.equal(p.outstanding, 1);
});

// ── Review findings: the HTTP transport's boundary with the agent ──────────

/** POST to a proxy with an exact request-line path, bypassing fetch's URL normalisation. */
function rawPost(/** @type {number} */ port, /** @type {string} */ path, /** @type {string} */ body) {
  return new Promise((resolve) => {
    const r = httpRequest({
      host: '127.0.0.1', port, method: 'POST', path,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let out = '';
      res.on('data', (d) => { out += d; });
      res.on('end', () => resolve({ status: res.statusCode, body: out }));
    });
    r.on('error', (e) => resolve({ status: 0, body: String(e) }));
    r.end(body);
  });
}

const CALL = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'tools/call',
  params: { name: 'transfer_funds', arguments: { amount: 2000000 } },
});

test('FR-04: the agent cannot redirect the proxy to another host', async () => {
  // `new URL(req.url, upstream)` reads a path of `//evil.example/x` as a
  // protocol-relative URL and resolves it to `http://evil.example/x`. The
  // agent's tool arguments and headers went to a host of the agent's choosing
  // while the record said it had talked to the configured upstream — a
  // confused deputy at the one boundary this proxy exists to police.
  const { collector, store } = await rig();
  /** @type {string[]} */
  const targets = [];
  const proxy = httpProxy({
    upstream: 'http://upstream.invalid:9/mcp',
    collector, newCorrelation: () => 'cor', onUnrecordable: () => {},
    fetchImpl: async (url) => {
      targets.push(String(url));
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  const addr = /** @type {any} */ (await proxy.listen(0));
  try {
    for (const path of ['//evil.example/x', '/..//evil.example/y', '/mcp']) {
      targets.length = 0;
      await rawPost(addr.port, path, CALL);
      assert.equal(targets.length, 1, `nothing was fetched for ${path}`);
      assert.equal(new URL(String(targets[0])).origin, 'http://upstream.invalid:9',
        `a request for ${path} reached ${targets[0]}`);
    }
  } finally {
    await proxy.close();
    store.close();
  }
});

test('FR-04: a valid call to a down upstream is not reported as unparsed', async () => {
  // `pairing.request()` returns null for a well-formed call, and a
  // `?? { what: 'unparsed' }` stood behind it — so every valid tool call to an
  // unreachable upstream was reported as traffic the proxy could not parse.
  // False about the traffic, and it inflated the count an operator reads to
  // judge how much of it the proxy did not understand.
  const { collector, store } = await rig();
  const proxy = httpProxy({
    upstream: 'http://upstream.invalid:9/mcp',
    collector, newCorrelation: () => 'cor', onUnrecordable: () => {},
    fetchImpl: async () => { throw new Error('ECONNREFUSED'); },
  });
  const addr = /** @type {any} */ (await proxy.listen(0));
  try {
    const r = /** @type {any} */ (await rawPost(addr.port, '/mcp', CALL));
    assert.equal(r.status, 502, 'the agent must see the upstream failure as one');
    assert.equal(proxy.counts.unparsed, 0, 'a valid call was counted as unparsed');
    assert.equal(proxy.pairing.outstanding, 1, 'and the attempt is still outstanding');
    await proxy.close();
    // It settles as a record: the call was attempted, and an attempt with no
    // result is a timeout, never an absence.
    assert.equal(proxy.counts.records, 1);
  } finally {
    store.close();
  }
});

test('NFR-12: an unreadable upstream reply does not take the proxy down', async () => {
  // `await upstreamRes.arrayBuffer()` rejected into the event loop, which
  // terminates the process by default. An upstream that truncated a reply took
  // the agent's MCP server with it — NFR-12 broken by the component whose
  // first obligation it is, and triggerable from the side of the boundary that
  // is not trusted.
  const { collector, store } = await rig();
  const proxy = httpProxy({
    upstream: 'http://upstream.invalid:9/mcp',
    collector, newCorrelation: () => 'cor', onUnrecordable: () => {},
    fetchImpl: async () => /** @type {any} */ ({
      status: 200,
      headers: new Headers(),
      arrayBuffer: async () => { throw new Error('upstream reply truncated'); },
    }),
  });
  const addr = /** @type {any} */ (await proxy.listen(0));
  try {
    const r = /** @type {any} */ (await rawPost(addr.port, '/mcp', CALL));
    assert.equal(r.status, 502, 'the agent got no answer at all');
    assert.equal(proxy.server.listening, true, 'the proxy stopped serving');
    // And a SECOND request still works, which is the property that matters:
    // one bad reply must not end the run.
    const again = /** @type {any} */ (await rawPost(addr.port, '/mcp', CALL));
    assert.equal(again.status, 502);
  } finally {
    await proxy.close();
    store.close();
  }
});

test('NFR-12: an oversized upstream reply is refused, not buffered without limit', async () => {
  // The request body had a ceiling and the response did not, so an untrusted
  // upstream could exhaust memory through the collector.
  const { collector, store } = await rig();
  const proxy = httpProxy({
    upstream: 'http://upstream.invalid:9/mcp',
    collector, newCorrelation: () => 'cor', onUnrecordable: () => {},
    maxBodyBytes: 1024,
    fetchImpl: async () => new Response('x'.repeat(4096), { status: 200 }),
  });
  const addr = /** @type {any} */ (await proxy.listen(0));
  try {
    const r = /** @type {any} */ (await rawPost(addr.port, '/mcp', CALL));
    assert.equal(r.status, 502);
    assert.match(r.body, /unreadable/);
    assert.equal(proxy.pairing.outstanding, 1, 'the call settles as a timeout, not as a result');
  } finally {
    await proxy.close();
    store.close();
  }
});

// ── Review findings: the CLI contract ──────────────────────────────────────

test('a flag given twice is refused, not silently last-wins', async () => {
  // The operator named two evidence stores and one was discarded without a
  // word. Same class as a flag nobody reads: the tool quietly answered a
  // different question than the one asked.
  const r = parseArgs(['--upstream', 'cmd', '--out', '/a', '--out', '/b']);
  assert.notEqual(r.err, '');
  assert.equal(r.exit, 2);
  assert.match(r.err, /--out was given twice, as "\/a" and "\/b"/);
  assert.match(r.err, /an evidence store, or a server, that somebody is expecting/);

  const u = parseArgs(['--upstream', 'a', '--upstream', 'b', '--out', '/o']);
  assert.match(u.err, /--upstream was given twice/);
});

test('a flag the chosen mode does not read is refused', async () => {
  // `--listen 8080` with a command upstream was accepted and dropped, so an
  // operator who believed they were serving HTTP on a port had nothing
  // listening on it and no indication why. The project has shipped this shape
  // three times — `--vkey`, `padding`, `retention`.
  const stdio = parseArgs(['--upstream', 'node x.mjs', '--out', '/o', '--listen', '8080']);
  assert.equal(stdio.exit, 2);
  assert.match(stdio.err, /--listen only applies when --upstream is an http\(s\) URL/);
  assert.match(stdio.err, /nothing would have been listening on it/);

  // Extra arguments are a command's arguments; a URL upstream takes none.
  const http = parseArgs(['--upstream', 'http://u/', '--out', '/o', 'extra', 'args']);
  assert.equal(http.exit, 2);
  assert.match(http.err, /an http\(s\) upstream takes none/);

  // And the legitimate combinations still parse, so the check refuses the
  // wrong thing rather than everything.
  assert.equal(parseArgs(['--upstream', 'node x.mjs', '--out', '/o', '--', '--verbose']).err, '');
  assert.equal(parseArgs(['--upstream', 'http://u/', '--out', '/o', '--listen', '0']).err, '');
});

test('an upstream scheme is recognised whatever its case', async () => {
  // A scheme is case-insensitive in the URL grammar, and `HTTP://x` taken for
  // a command produces an ENOENT about a program nobody meant to run.
  assert.equal(isUrl('HTTP://u/'), true);
  assert.equal(isUrl('HttpS://u/'), true);
  assert.equal(isUrl('node ./server.mjs'), false);
  assert.equal(parseArgs(['--upstream', 'HTTP://u/', '--out', '/o', '--listen', '0']).err, '');
});

// ── PR #11 review: every observed invocation stays accountable ─────────────

test('P1: two outstanding calls on one id BOTH stay accountable', async () => {
  // `#pending.set(idKey(id), …)` overwrote, so the first invocation was erased:
  // forwarded, very likely executed, and gone from the record with no timeout
  // behind it — while the response that arrived was attributed to whichever
  // call happened to be in the map. A transfer observed crossing this boundary
  // left no trace at all.
  let n = 0;
  const p = new Pairing({ newCorrelation: () => `cor-${++n}` });
  const call = (/** @type {number} */ amount) => Buffer.from(JSON.stringify({
    jsonrpc: '2.0', id: 7, method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount } },
  }));

  assert.equal(p.request(call(1_000_000)), null);
  const clash = p.request(call(2));
  assert.equal(clash?.what, 'ambiguous');
  assert.match(String(clash?.detail), /reused the outstanding JSON-RPC id 7/);
  assert.match(String(clash?.detail), /Neither invocation is discarded/);
  assert.equal(p.outstanding, 2, 'an observed invocation was discarded');

  // A response for that id answers one of them and nothing can say which.
  const answered = p.response(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 7, result: { ok: true } })));
  assert.equal(answered?.what, 'unattributable');
  assert.match(String(answered?.detail), /attributing it would record a result against an/);
  assert.equal(p.outstanding, 2, 'a response consumed a call it could not be attributed to');

  // Both settle, each keeping ITS OWN arguments and correlation — the
  // unmatched-response diagnostic preserved neither.
  const settled = p.closeAll();
  assert.equal(settled.length, 2);
  assert.deepEqual(settled.map(o => Buffer.from(/** @type {any} */ (o).args).toString('utf8')),
    ['{"amount":1000000}', '{"amount":2}']);
  assert.deepEqual(settled.map(o => o.correlation), ['cor-1', 'cor-2']);
  for (const s of settled) assert.equal(s.outcome, 'timeout');
});

test('P1: a third call on the same id is still accountable', async () => {
  // The id is already marked ambiguous by then, so the branch that handles it
  // is a different one from the first collision — and a call arriving there
  // must not be dropped either.
  let n = 0;
  const p = new Pairing({ newCorrelation: () => `cor-${++n}` });
  for (const amount of [1, 2, 3]) {
    p.request(Buffer.from(JSON.stringify({
      jsonrpc: '2.0', id: 'x', method: 'tools/call',
      params: { name: 't', arguments: { amount } },
    })));
  }
  assert.equal(p.outstanding, 3);
  assert.deepEqual(p.closeAll().map(o => Buffer.from(/** @type {any} */ (o).args).toString('utf8')),
    ['{"amount":1}', '{"amount":2}', '{"amount":3}']);
});

test('P1: an unanswered call becomes a record while the proxy is still running', async () => {
  // `expire()` existed and NOTHING called it except `closeAll()` at shutdown,
  // so a long-running proxy held every unanswered invocation in memory
  // indefinitely — observed, forwarded, executed, and with no durable record
  // until the process chose to exit. Killed instead, the record never existed.
  const { collector, store } = await rig();
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upIn = new PassThrough();
  const upOut = new PassThrough();
  let clock = 0;
  const p = stdioProxy({
    agentIn, agentOut, upstreamIn: upIn, upstreamOut: upOut,
    collector, newCorrelation: () => 'cor-1', onUnrecordable: () => {},
    now: () => clock, call_timeout_ms: 1_000, settle_interval_ms: 20,
  });

  agentIn.write(`${JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'transfer_funds', arguments: { amount: 2_000_000 } },
  })}\n`);
  await new Promise((r) => { setTimeout(r, 40); });
  assert.equal(p.pairing.outstanding, 1);
  assert.equal(store.readChain().length, 0, 'nothing is recorded before the timeout elapses');

  // Time passes. NOTHING is closed — the proxy is still serving.
  clock = 5_000;
  await new Promise((r) => { setTimeout(r, 120); });

  assert.equal(p.pairing.outstanding, 0, 'the sweep never ran');
  const recs = store.readChain().map(e => /** @type {any} */ (e).record);
  assert.equal(recs.length, 1, 'the observed invocation has no durable record');
  assert.equal(recs[0].outcome, 'timeout');
  assert.equal(recs[0].tool, 'transfer_funds');
  p.close();
  store.close();
});

test('the settle timer never keeps the process alive', async () => {
  // A proxy whose agent and upstream have both finished should exit. A timer
  // that held the loop open would hang every run that used this.
  const { settler } = await import('../src/settle.mjs');
  const p = new Pairing({ newCorrelation: () => 'cor' });
  const s = settler({ pairing: p, rec: { emit: () => true }, interval_ms: 10 });
  assert.equal(s.running, true);
  // `unref` is what makes it safe; asserted through the handle's own state
  // rather than by hoping the test process exits.
  const handles = /** @type {any} */ (process)._getActiveHandles?.() ?? [];
  assert.ok(!handles.some((/** @type {any} */ h) => h?.hasRef?.() && h === s),
    'the settle timer is holding a reference on the event loop');
  s.stop();
  assert.equal(s.running, false);
});

test('a recording failure during settlement does not throw into the timer', async () => {
  // NFR-12. A throw from a timer callback rejects into the event loop and
  // terminates the process by default — the collector stopping the run it is
  // supposed to be recording.
  const { settler } = await import('../src/settle.mjs');
  const p = new Pairing({ newCorrelation: () => 'cor' });
  p.request(Buffer.from(JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't', arguments: { a: 1 } },
  })));
  /** @type {string[]} */
  const oob = [];
  const s = settler({
    pairing: p,
    rec: { emit: () => { throw new Error('disk full'); } },
    timeout_ms: -1, interval_ms: 10_000, autostart: false,
    onUnrecordable: (e) => oob.push(e.detail),
  });
  assert.doesNotThrow(() => s.settle());
  assert.equal(oob.length, 1);
  assert.match(String(oob[0]), /the traffic is unaffected/);
});
