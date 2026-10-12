import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/** A log that declares a compromise, then rotates to the declared new root. */
async function compromised({ rotate = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'ss-dv-'));
  const old = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer: old,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx({ correlation: 'before' }));
  await c.checkpoint();
  const fresh = await generateDevSigner(ORIGIN);
  c.declareDiscontinuity({
    last_sound_epoch: 0, new_root_public_key: fresh.publicKey,
    reason: 'signing key compromise suspected after host intrusion',
  });
  await c.checkpoint();
  if (rotate) {
    await c.rotate(fresh);
    c.action(tx({ correlation: 'after' }));
    await c.checkpoint();
  }
  store.close();
  return { root, old, fresh, oldVkey: formatVkey(ORIGIN, old.publicKey) };
}

test('SEC-24: a declared discontinuity is reported prominently', async () => {
  const s = await compromised();
  const r = await verifyStore(s.root, { collector: 'host-1', vkey: s.oldVkey });
  const f = r.findings.find(x => x.code === 'DISCONTINUITY');
  assert.ok(f, JSON.stringify(r.findings.map(x => x.code)));
  assert.match(f.detail, /host intrusion/, 'the operator\'s stated reason reaches the reader');
  assert.match(f.detail, /epoch 0/);
  assert.equal(f.verdict, 'inconclusive');
  // Prominent: it is in the capability statement, not only in the findings.
  assert.ok(r.capability.cannot.some(x => /discontinuity/i.test(x)),
    JSON.stringify(r.capability.cannot, null, 1));
});

test('SEC-24: the discontinuity is never silently bridged', async () => {
  const s = await compromised();
  const r = await verifyStore(s.root, { collector: 'host-1', vkey: s.oldVkey });
  // The reader pinned the OLD root. Records after the declaration are signed
  // under a key that root no longer vouches for, and the report must say the
  // reader has to re-pin rather than quietly carrying the old trust across.
  assert.ok(r.capability.cannot.some(x => /re-?pin|does not reach/i.test(x)),
    JSON.stringify(r.capability.cannot, null, 1));
  assert.ok(!r.capability.can.some(x => /signed the tree size/.test(x)),
    'no affirmative signing claim may span the discontinuity');
});

test('SEC-24: the report says the declaration rests on the SUSPECT key', async () => {
  // It is the only key available at that moment, so the declaration is
  // accepted — and a reader needs to know that the statement disowning the key
  // is signed by it.
  const s = await compromised();
  const r = await verifyStore(s.root, { collector: 'host-1', vkey: s.oldVkey });
  assert.ok(r.capability.cannot.some(x => /signed by the key it disowns|suspect key/i.test(x)),
    JSON.stringify(r.capability.cannot, null, 1));
});

test('SEC-24: verifying under the NEW root reports the discontinuity too', async () => {
  // A reader who re-pinned must still be told there was one: the records
  // before it are the ones in question, and a clean-looking report from the
  // new root would hide exactly that.
  const s = await compromised();
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: formatVkey(ORIGIN, s.fresh.publicKey) });
  assert.ok(r.findings.some(x => x.code === 'DISCONTINUITY'),
    JSON.stringify(r.findings.map(x => x.code)));
});

test('SEC-24: a silent re-key with NO declaration breaks the succession, as before', async () => {
  // The existing M2 behaviour, and the reason a silent re-key is
  // indistinguishable from an attack. Asserted here so the discontinuity work
  // cannot have softened it.
  const root = mkdtempSync(join(tmpdir(), 'ss-dv-'));
  const old = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer: old,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  await c.checkpoint();
  store.close();
  // Replace the succession journal's root with a key nobody endorsed.
  const stranger = await generateDevSigner(ORIGIN);
  const { readFileSync, writeFileSync } = await import('node:fs');
  const p = join(root, 'succession', 'host-1.jsonl');
  const entries = readFileSync(p, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  entries.push({ epoch: 1, public_key: stranger.publicKey.toString('base64'),
    custody: 'software', endorsement: Buffer.alloc(64).toString('base64') });
  writeFileSync(p, entries.map(e => JSON.stringify(e)).join('\n') + '\n');
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey(ORIGIN, old.publicKey) });
  assert.ok(r.findings.some(x => x.code === 'SUCCESSION_BROKEN'));
  assert.equal(r.verdict, 'fail');
  assert.ok(!r.findings.some(x => x.code === 'DISCONTINUITY'),
    'nothing was declared, so nothing explains it');
});

test('SEC-24: a clean log reports no discontinuity', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ss-dv-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  await c.checkpoint();
  store.close();
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey(ORIGIN, signer.publicKey) });
  assert.ok(!r.findings.some(x => x.code === 'DISCONTINUITY'));
  assert.ok(!r.capability.cannot.some(x => /discontinuity/i.test(x)));
});
