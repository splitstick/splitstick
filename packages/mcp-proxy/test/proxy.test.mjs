import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { Pairing, stdioProxy, httpProxy } from '../src/index.mjs';
import { tokenizeCommand, runProxy } from '../src/cli.mjs';

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
