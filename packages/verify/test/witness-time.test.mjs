import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/**
 * A store with one checkpoint, countersigned at `received_at`.
 * @param {{ received_at?: string, issuer?: string,
 *           key?: import('@splitstick/core/signer').Signer,
 *           establishes?: string[] }} [o]
 */
async function witnessed(o = {}) {
  const { received_at, issuer = 'audit.internal', key, establishes = ['sequence'] } = o;
  const root = mkdtempSync(join(tmpdir(), 'ss-wt-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  const cp = await c.checkpoint();
  const wkey = key ?? await generateDevSigner(issuer);
  const text = parseNote(cp.note).text;
  const env = JSON.parse(String(store.readCheckpointEnvelope(cp.checkpoint_seq)));
  env.countersignatures = [{
    type: 'c2sp-note', issuer, covers: 'note',
    line: encodeNote(text, [await signNote(text, wkey)]).trim().split('\n').at(-1),
    ...(received_at ? { received_at } : {}),
  }];
  store.writeCheckpointEnvelope(cp.checkpoint_seq, env);
  const batchTs = store.readChain().at(-1).record.ts;
  store.close();
  return {
    root, signer, wkey, batchTs,
    vkey: formatVkey(ORIGIN, signer.publicKey),
    policy: {
      quorum: 1,
      witnesses: [{ id: issuer, establishes, public_key: wkey.publicKey.toString('base64') }],
    },
  };
}

// ── FR-39 ───────────────────────────────────────────────────────────────────

test('FR-39: a late countersignature reports the WITNESS receipt time and the gap', async () => {
  // Backdating a late countersignature to the batch would turn the one
  // independent clock in the system into an echo of the operator's.
  const w = await witnessed({ received_at: '2026-10-11T14:30:00.000Z' });
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'audit.internal');
  assert.equal(entry?.received_at, '2026-10-11T14:30:00.000Z');
  assert.ok(entry?.unwitnessed_for_ms > 0, JSON.stringify(entry));
  // The gap IS the unwitnessed window, and a reader needs its size.
  assert.ok(r.capability.cannot.some(s => /unwitnessed for/i.test(s) && /4h|hour/i.test(s)),
    JSON.stringify(r.capability.cannot.filter(x => /unwitnessed/i.test(x)), null, 1));
});

test('FR-39: a c2sp-note receipt time is labelled witness-asserted and UNSIGNED', async () => {
  // There is nowhere in a C2SP note to put a time, so `received_at` is a bare
  // claim in the envelope. Reporting it as though it were signed would be the
  // most useful-looking lie available.
  const w = await witnessed({ received_at: '2026-10-11T14:30:00.000Z' });
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'audit.internal');
  assert.equal(entry?.received_at_basis, 'witness-asserted, unsigned');
  assert.ok(r.capability.cannot.some(s => /unsigned/i.test(s) && /receipt time/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
});

test('FR-39: a receipt time EARLIER than the batch is reported, not preferred', async () => {
  // Either the witness's clock is wrong or the operator's is. A verifier that
  // quietly picked one would be deciding whose account to believe, which is
  // the one thing it must not do.
  const w = await witnessed({ received_at: '2026-10-11T09:00:00.000Z' });
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'audit.internal');
  assert.ok(entry?.clock_disagreement, JSON.stringify(entry));
  assert.ok(r.capability.cannot.some(s => /clock/i.test(s) && /disagree/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
  // Reported, not failed: a clock disagreement is not evidence of tampering.
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
});

test('FR-39: no receipt time at all is reported as absent, not assumed to be the batch time', async () => {
  const w = await witnessed({});
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'audit.internal');
  assert.equal(entry?.received_at, undefined);
  assert.equal(entry?.received_at_basis, 'absent');
  assert.ok(r.capability.cannot.some(s => /no receipt time/i.test(s)));
});

test('FR-39: a malformed receipt time is absent, not parsed into something', async () => {
  for (const bad of ['yesterday', '2026-13-45T99:99:99Z', '', '12345']) {
    const w = await witnessed({ received_at: bad });
    const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
    const entry = r.witnesses.find(x => x.id === 'audit.internal');
    assert.equal(entry?.received_at_basis, 'absent', `${bad} should not parse`);
  }
});
