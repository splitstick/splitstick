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

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'ss-custody-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c };
}

test('custody is a record kind, so a declaration is chained like anything else', () => {
  // FR-65 — the verifier cannot tell custody from a signature: an HSM signature
  // and one from a key file are byte-identical. So the declaration has to be
  // IN the log, chained, where altering it later breaks the chain.
  assert.ok(RECORD_KINDS.includes('custody'));
});

test('a custody record declares the epoch, the key and the class — and nothing else', async () => {
  const { store, signer, c } = await fresh();
  const r = c.custody();
  assert.equal(r.record.kind, 'custody');
  assert.equal(r.record.epoch, 0);
  assert.equal(r.record.public_key, signer.publicKey.toString('base64'));
  assert.equal(r.record.custody_class, 'software');
  // The basis is in the record, not inferred by a reader. A declaration that
  // does not say it is a declaration gets read as a finding.
  assert.equal(r.record.custody_basis, 'operator-declared');
  assert.equal(r.record.run, null);
  assert.equal(r.record.source_seq, null);
  assert.equal(recomputeChain(store.readChain()).ok, true);
  store.close();
});

test('the allowlist refuses a custody record carrying anything else', () => {
  const base = {
    v: 1, kind: 'custody', ts: '2026-10-11T10:00:00.000Z', record_seq: 1,
    source_seq: null, run: null, collector: 'host-1',
    epoch: 0, public_key: Buffer.alloc(32).toString('base64'),
    custody_class: 'hsm', custody_basis: 'operator-declared',
  };
  assert.doesNotThrow(() => validateRecord(base));
  for (const extra of ['tool', 'args', 'result', 'private_key', 'attestation_pem']) {
    assert.throws(() => validateRecord({ ...base, [extra]: 'x' }), RecordError, extra);
  }
});

test('a custody record refuses an unknown class, and refuses claiming support it has not got', () => {
  const base = {
    v: 1, kind: 'custody', ts: '2026-10-11T10:00:00.000Z', record_seq: 1,
    source_seq: null, run: null, collector: 'host-1',
    epoch: 0, public_key: Buffer.alloc(32).toString('base64'),
    custody_class: 'hsm', custody_basis: 'operator-declared',
  };
  assert.throws(() => validateRecord({ ...base, custody_class: 'secure-enclave' }), RecordError);
  // `operator-declared` is the only basis a RECORD may carry. "Independently
  // supported" is a conclusion a verifier reaches from an attestation it
  // validated (FR-70) — never something the operator writes about themselves.
  assert.throws(
    () => validateRecord({ ...base, custody_basis: 'independently-supported' }),
    RecordError,
  );
  assert.throws(() => validateRecord({ ...base, custody_basis: 'verified' }), RecordError);
});

test('a custody record must agree with the epoch the collector is actually in', async () => {
  const { store, signer, c } = await fresh();
  c.heartbeat();
  const next = await generateDevSigner(ORIGIN);
  await c.rotate(next);
  const r = c.custody();
  assert.equal(r.record.epoch, 1);
  assert.equal(r.record.public_key, next.publicKey.toString('base64'));
  // Declaring epoch 0's key after rotating would put a statement in the log
  // about a key that is no longer signing anything.
  assert.notEqual(r.record.public_key, signer.publicKey.toString('base64'));
  store.close();
});

test('rotation can emit the declaration itself, so an epoch is never undeclared', async () => {
  const { store, signer, c } = await fresh();
  c.heartbeat();
  const next = await generateDevSigner(ORIGIN);
  await c.rotate(next, { declare: true });
  const records = store.readChain().map(e => e.record);
  const declarations = records.filter(r => r.kind === 'custody');
  assert.equal(declarations.length, 1);
  assert.equal(declarations[0].epoch, 1);
  assert.equal(declarations[0].public_key, next.publicKey.toString('base64'));
  store.close();
});

test('a custody declaration is refused on a degraded collector, like any other write', async () => {
  const { root, store, signer, c } = await fresh();
  c.heartbeat();
  store.close();
  // A real torn tail, not a stubbed getter. A new write path is exactly where
  // the degraded check gets forgotten, so it is exercised through the journal.
  const { readFileSync, writeFileSync } = await import('node:fs');
  const p = join(root, 'chain', 'host-1.jsonl');
  writeFileSync(p, readFileSync(p, 'utf8').slice(0, -6));
  const store2 = new Store(root, 'host-1');
  const c2 = new Collector({ store: store2, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN });
  const { CollectorDegraded } = await import('../src/collector.mjs');
  assert.ok(c2.degraded);
  assert.throws(() => c2.custody(), CollectorDegraded);
  store2.close();
});
