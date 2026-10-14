// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * No enforcement path exists — SCOPE-01, SCOPE-16, and NFR-12's absoluteness.
 *
 * `tools/lint-enforcement.mjs` checks the structure: one `on_unavailable`
 * value, no enforcement key, and forwarding ahead of recording in the source.
 * This checks the behaviour, which is the half a reader actually cares about:
 * the traffic flows no matter what the recording side is doing.
 *
 * Each case is a state in which a system that COULD block would be most
 * tempted to — the store is broken, the collector has given up, the recorder
 * throws. A collector that can stop a run is one an operator rightly disables,
 * and then it captures nothing at all.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig, ConfigError } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { stdioProxy } from '@splitstick/mcp-proxy';

const ORIGIN = 'splitstick.dev/host-1';
const CALL = `${JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'tools/call',
  params: { name: 'transfer_funds', arguments: { amount: 2_000_000 } },
})}\n`;

async function rig() {
  const root = mkdtempSync(join(tmpdir(), 'ss-enforce-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  return { root, store, collector, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** Drive one message through the stdio proxy and return what the upstream saw. */
function through(/** @type {any} */ collector, /** @type {() => void} */ sabotage) {
  const agentIn = new PassThrough();
  const agentOut = new PassThrough();
  const upIn = new PassThrough();
  const upOut = new PassThrough();
  /** @type {Buffer[]} */
  const seen = [];
  upIn.on('data', (d) => seen.push(d));
  const p = stdioProxy({
    agentIn, agentOut, upstreamIn: upIn, upstreamOut: upOut,
    collector, newCorrelation: () => 'cor-1', onUnrecordable: () => {},
  });
  sabotage();
  agentIn.write(CALL);
  return new Promise((resolve) => {
    setTimeout(() => { p.close(); resolve(Buffer.concat(seen).toString('utf8')); }, 60);
  });
}

test('SCOPE-01: the traffic flows when the store is broken', async () => {
  const r = await rig();
  try {
    const got = await through(r.collector, () => {
      r.store.append = () => { throw new Error('ENOSPC'); };
    });
    assert.equal(got, CALL, 'the agent\'s message did not reach the upstream');
  } finally {
    r.cleanup();
  }
});

test('SCOPE-01: the traffic flows when the collector has already degraded', async () => {
  const r = await rig();
  try {
    // Degrade it for real, through the path that degrades it: one failed write.
    r.store.append = () => { throw new Error('ENOSPC'); };
    try {
      r.collector.action({
        tool: 't', args: Buffer.from('{}'), result: Buffer.from('ok'), correlation: 'x',
      });
    } catch { /* expected: this is what degrades it */ }
    assert.notEqual(r.collector.degraded, null, 'the collector did not degrade, so this case is moot');

    const got = await through(r.collector, () => {});
    assert.equal(got, CALL, 'a degraded collector stopped the traffic');
  } finally {
    r.cleanup();
  }
});

test('SCOPE-01: the traffic flows when recording itself throws', async () => {
  const r = await rig();
  try {
    const got = await through(r.collector, () => {
      r.collector.action = () => { throw new Error('the recorder exploded'); };
    });
    assert.equal(got, CALL);
  } finally {
    r.cleanup();
  }
});

test('SCOPE-01: forwarding does not wait for recording to succeed', async () => {
  // The ordering, behaviourally. If the write were gated on the record, a
  // recorder that never returns would hold the traffic — and "never returns"
  // is what a hung disk looks like.
  const r = await rig();
  try {
    const got = await through(r.collector, () => {
      r.collector.action = () => {
        // Synchronously burn a moment, as a slow fsync would, and then throw.
        const until = Date.now() + 30;
        while (Date.now() < until) { /* spin */ }
        throw new Error('slow and then broken');
      };
    });
    assert.equal(got, CALL);
  } finally {
    r.cleanup();
  }
});

test('SCOPE-16: there is no configuration that makes the collector block', async () => {
  // The config half, asserted at the schema. Every word an operator might
  // reach for, refused with the reason.
  for (const value of ['block', 'fail_closed', 'halt', 'deny', 'reject', 'enforce', 'strict']) {
    assert.throws(
      () => parseConfig(`version: 1\nstore: ./s\non_unavailable: ${value}\n`, '/tmp'),
      (/** @type {any} */ e) => e instanceof ConfigError
        && /there is no fail-closed setting, by design \(SCOPE-16\)/.test(e.message),
      `on_unavailable: ${value} was accepted`);
  }
  // And the one permitted value still is, so the guard refuses the right thing
  // rather than everything.
  assert.equal(
    parseConfig('version: 1\nstore: ./s\non_unavailable: mark_gap\n', '/tmp').on_unavailable,
    'mark_gap');
});

test('SCOPE-16: an unknown config key is refused, so a blocking flag cannot be added quietly', async () => {
  // SCOPE-16 says fail-open is a design constraint and not a setting. A
  // tolerant parser would let a future flag arrive and be silently ignored —
  // which reads, to whoever added it, as the flag working.
  for (const key of ['blocking', 'enforce', 'fail_closed', 'on_failure']) {
    assert.throws(
      () => parseConfig(`version: 1\nstore: ./s\n${key}: true\n`, '/tmp'),
      (/** @type {any} */ e) => e instanceof ConfigError,
      `the config accepted ${key}`);
  }
});
