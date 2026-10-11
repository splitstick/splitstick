import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OpenMultiAgent, InMemoryRunJournal } from '@open-multi-agent/core';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { recomputeChain } from '@splitstick/core/chain';
import { SplitstickRunJournal } from '../src/index.mjs';
import { agent, goal, scriptedAdapter } from './fixtures/agent.mjs';

const AGENT_SRC = fileURLToPath(new URL('./fixtures/agent.mjs', import.meta.url));
const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

async function collector() {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-int-'));
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  return {
    store,
    collector: new Collector({
      store, config: parseConfig('version: 1\nstore: ./s\n', root),
      signer: await generateDevSigner('splitstick.dev/host-1'),
      collector: 'host-1', origin: 'splitstick.dev/host-1', now: () => new Date(t += 1000),
    }),
  };
}

/**
 * INT-07 — no agent code changes, verified literally.
 *
 * The agent lives in fixtures/agent.mjs and is hashed before and after. The two
 * runs below differ only in how the orchestrator is constructed, which is the
 * application's configuration; the agent definition is the same object both
 * times, imported from the same unmodified module.
 */
test('INT-07: the agent source is byte-identical before and after integration', async () => {
  const before = digest(AGENT_SRC);

  // Without Splitstick.
  const baseline = new OpenMultiAgent({ journal: new InMemoryRunJournal() });
  const plain = await baseline.runAgent({ ...agent, adapter: scriptedAdapter() }, goal);
  assert.ok(plain.status, 'the agent runs on its own');

  // With Splitstick: a dependency and a construction argument. Nothing else.
  const { collector: c, store } = await collector();
  const journal = new SplitstickRunJournal({ collector: c, journal: new InMemoryRunJournal() });
  const wired = new OpenMultiAgent({ journal });
  const observed = await wired.runAgent({ ...agent, adapter: scriptedAdapter() }, goal, { journal });
  await journal.close();

  assert.equal(digest(AGENT_SRC), before, 'integration must not touch the agent source');
  assert.deepEqual(observed.status, plain.status, 'and must not change what the run does');

  // And the record is there, from OMA's real runtime.
  const entries = store.readChain();
  assert.ok(entries.length >= 1);
  assert.equal(recomputeChain(entries).ok, true);
  const action = entries.map(e => /** @type {any} */ (e.record)).find(r => r.kind === 'tool_call');
  assert.equal(action.tool, 'transfer_funds');
  assert.equal(action.outcome, 'ok');
  assert.ok(action.args.cid && action.result.cid);
});

/**
 * SEC-14 — Splitstick must never hold, receive, request or log the operator
 * signing key. The code scan in the verifier's suite proves no module imports a
 * key-export API; this proves nothing leaves the host, by making egress fail.
 *
 * Every outbound primitive is replaced with a throw for the duration of a
 * representative run: capture the run, externalise the payloads, sign a
 * checkpoint. If any of them is reached, the test fails with the call site.
 */
test('SEC-14: a representative run performs no egress at all', async () => {
  const net = await import('node:net');
  const http = await import('node:http');
  const https = await import('node:https');
  const dns = await import('node:dns');

  /** @type {string[]} */
  const attempts = [];
  const trap = (name) => (...args) => {
    attempts.push(`${name}(${args.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(', ')})`);
    throw new Error(`egress attempted: ${name}`);
  };

  const saved = {
    connect: net.default.Socket.prototype.connect,
    netConnect: net.default.connect,
    httpRequest: http.default.request,
    httpsRequest: https.default.request,
    lookup: dns.default.lookup,
    fetch: globalThis.fetch,
  };
  const patch = /** @type {any} */ ({
    net: net.default, http: http.default, https: https.default, dns: dns.default,
  });
  patch.net.Socket.prototype.connect = trap('net.Socket.connect');
  patch.net.connect = trap('net.connect');
  patch.http.request = trap('http.request');
  patch.https.request = trap('https.request');
  patch.dns.lookup = trap('dns.lookup');
  globalThis.fetch = trap('fetch');

  try {
    // Prove the trap fires before trusting it to prove anything. A check that
    // cannot fail is documentation, not a check.
    let trapped = false;
    try {
      patch.https.request('https://example.invalid/');
    } catch {
      trapped = true;
    }
    assert.equal(trapped, true, 'the egress trap must actually intercept');
    assert.equal(attempts.length, 1, 'and must record the attempt');
    attempts.length = 0;

    const { collector: c, store } = await collector();
    const journal = new SplitstickRunJournal({ collector: c, journal: new InMemoryRunJournal() });
    const oma = new OpenMultiAgent({ journal });
    await oma.runAgent({ ...agent, adapter: scriptedAdapter() }, goal, { journal });
    await journal.close();
    const cp = await c.checkpoint();
    assert.ok(cp.note.includes('—'), 'the checkpoint was signed locally');
    assert.equal(recomputeChain(store.readChain()).ok, true);
  } finally {
    patch.net.Socket.prototype.connect = saved.connect;
    patch.net.connect = saved.netConnect;
    patch.http.request = saved.httpRequest;
    patch.https.request = saved.httpsRequest;
    patch.dns.lookup = saved.lookup;
    globalThis.fetch = saved.fetch;
  }

  assert.deepEqual(attempts, [], 'no outbound call may be attempted during a run');
});
