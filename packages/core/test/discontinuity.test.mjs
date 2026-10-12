import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { validateRecord, RECORD_KINDS, RecordError } from '../src/record.mjs';
import { recomputeChain } from '../src/chain.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh(root = mkdtempSync(join(tmpdir(), 'ss-dis-')), signer) {
  const s = signer ?? await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer: s,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer: s, c };
}

const base = (over = {}) => ({
  v: 1, kind: 'discontinuity', ts: '2026-10-11T10:00:00.000Z', record_seq: 1,
  source_seq: null, run: null, collector: 'host-1',
  last_sound_epoch: 3,
  new_root_public_key: Buffer.alloc(32, 7).toString('base64'),
  reason: 'signing key compromise suspected',
  ...over,
});

test('SEC-24: a discontinuity is its own record kind', () => {
  // DES-06 says "a policy record". It cannot be one: DES-01's allowlist is
  // exhaustive PER KIND, so a policy record carrying a last sound epoch and a
  // new root key would have to make those fields optional — and optional on
  // every ordinary policy change, where they mean nothing. A distinct kind says
  // required-here and forbidden-there, which is exactly the distinction.
  //
  // It also lets a verifier FIND discontinuities by kind rather than sniffing
  // for optional fields, which is what makes "never silently bridged" checkable.
  assert.ok(RECORD_KINDS.includes('discontinuity'));
});

test('SEC-24: it names the last sound epoch and the new root key, and nothing else', () => {
  assert.doesNotThrow(() => validateRecord(base()));
  for (const f of ['last_sound_epoch', 'new_root_public_key']) {
    const r = base();
    delete r[f];
    assert.throws(() => validateRecord(r), RecordError, `${f} is required`);
  }
  for (const extra of ['tool', 'args', 'result', 'private_key', 'previous_policy']) {
    assert.throws(() => validateRecord(base({ [extra]: 'x' })), RecordError, extra);
  }
});

test('SEC-24: the new root key must be a real key and the epoch a real epoch', () => {
  assert.throws(() => validateRecord(base({ new_root_public_key: 'not base64!!' })), RecordError);
  assert.throws(() => validateRecord(base({
    new_root_public_key: Buffer.alloc(31).toString('base64') })), RecordError);
  assert.throws(() => validateRecord(base({ last_sound_epoch: -1 })), RecordError);
  assert.throws(() => validateRecord(base({ last_sound_epoch: 1.5 })), RecordError);
  assert.throws(() => validateRecord(base({ last_sound_epoch: '3' })), RecordError);
  // Zero is valid: the very first epoch can be the compromised one.
  assert.doesNotThrow(() => validateRecord(base({ last_sound_epoch: 0 })));
});

test('SEC-24: a reason is required, because a bare discontinuity explains nothing', () => {
  const r = base();
  delete r.reason;
  assert.throws(() => validateRecord(r), RecordError);
  assert.throws(() => validateRecord(base({ reason: '' })), RecordError);
});

test('SEC-24: the collector writes it, chained like any other record', async () => {
  const { store, c, signer } = await fresh();
  c.action(tx());
  const next = await generateDevSigner(ORIGIN);
  const d = c.declareDiscontinuity({
    last_sound_epoch: 0,
    new_root_public_key: next.publicKey,
    reason: 'signing key compromise suspected',
  });
  assert.equal(d.record.kind, 'discontinuity');
  assert.equal(d.record.new_root_public_key, next.publicKey.toString('base64'));
  assert.equal(recomputeChain(store.readChain()).ok, true);
  store.close();
});

test('SEC-24: the declaration is signed by whatever key is available, including the compromised one', async () => {
  // It is the only key at that moment. A design that required a fresh key to
  // declare its predecessor compromised would make the declaration impossible
  // in the one case it exists for — the verifier reports what it rests on
  // rather than refusing it.
  const { store, c, signer } = await fresh();
  c.action(tx());
  const next = await generateDevSigner(ORIGIN);
  c.declareDiscontinuity({
    last_sound_epoch: 0, new_root_public_key: next.publicKey, reason: 'compromise',
  });
  const cp = await c.checkpoint();
  const { parseNote } = await import('../src/note.mjs');
  const { verifyNoteSignature } = await import('../src/signer.mjs');
  const note = parseNote(cp.note);
  // Still the current (suspect) epoch key, because that is what exists.
  assert.equal(await verifyNoteSignature(note.text, note.signatures[0], signer.verifier()), true);
  store.close();
});

test('SEC-24: a degraded collector will not declare one', async () => {
  // A real torn tail. A declaration written onto a damaged journal would be
  // unreadable, which is the opposite of the point — and this is the write
  // path where a new method most easily forgets the check.
  const root = mkdtempSync(join(tmpdir(), 'ss-dis-'));
  const { store, c, signer } = await fresh(root);
  c.action(tx());
  store.close();
  const { readFileSync, writeFileSync } = await import('node:fs');
  const p = join(root, 'chain', 'host-1.jsonl');
  writeFileSync(p, readFileSync(p, 'utf8').slice(0, -6));

  const store2 = new Store(root, 'host-1');
  const c2 = new Collector({ store: store2, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN });
  const { CollectorDegraded } = await import('../src/collector.mjs');
  assert.ok(c2.degraded);
  const next = await generateDevSigner(ORIGIN);
  assert.throws(() => c2.declareDiscontinuity({
    last_sound_epoch: 0, new_root_public_key: next.publicKey, reason: 'compromise',
  }), CollectorDegraded);
  store2.close();
});
