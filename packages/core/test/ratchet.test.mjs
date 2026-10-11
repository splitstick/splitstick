import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { successionReport } from '../src/succession.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'ss-ratchet-'));
const CFG = 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nanchor_interval: 10s\n';
const cfg = (root) => parseConfig(CFG, root);

/** A collector over a fresh store, with a software signer. */
async function open(root = tmp(), name = 'log.example/ratchet') {
  const store = new Store(root, 'c1');
  const signer = await generateDevSigner(name);
  const c = new Collector({ store, config: cfg(root), signer, collector: 'c1', origin: name });
  return { root, store, signer, c };
}

test('the root epoch is recorded on first use, so the chain always has a base', async () => {
  const { store, signer, c } = await open();
  assert.equal(c.epoch, 0);
  // Opening a store is a read: nothing is journalled until something is
  // written. A constructor that wrote made handover between two instances
  // impossible, because opening claimed the write lock.
  assert.deepEqual(store.readSuccession(), []);

  c.heartbeat();
  const chain = store.readSuccession();
  assert.equal(chain.length, 1);
  assert.equal(chain[0].epoch, 0);
  assert.equal(chain[0].public_key, signer.publicKey.toString('base64'));
  assert.equal(chain[0].custody, 'software');
  assert.equal(chain[0].endorsement, undefined);
  store.close();
});

test('rotating endorses the successor with the retiring key and walks from the root', async () => {
  const { store, signer, c } = await open();
  c.heartbeat();

  const next = await generateDevSigner(signer.name);
  const r = await c.rotate(next);
  assert.equal(r.epoch, 1);
  assert.equal(c.epoch, 1);
  assert.equal(c.signer, next);

  const rep = successionReport(signer.publicKey, store.readSuccession());
  assert.deepEqual(rep.findings, []);
  assert.equal(rep.ok, true);
  assert.deepEqual(rep.epochs.map(e => e.epoch), [0, 1]);
  // The retired epoch is retired; the live one is not, whatever its custody.
  assert.equal(rep.epochs[0].retired, true);
  assert.equal(rep.epochs[1].retired, false);
  store.close();
});

test('the pinned root does not move when the key rotates — that is the point', async () => {
  const { store, signer, c } = await open();
  c.heartbeat();
  let cur = signer;
  for (let i = 0; i < 5; i += 1) {
    const next = await generateDevSigner(signer.name);
    await c.rotate(next);
    cur = next;
  }
  // One pinned key, five rotations later, still attributes every epoch.
  const rep = successionReport(signer.publicKey, store.readSuccession());
  assert.equal(rep.ok, true);
  assert.equal(rep.epochs.length, 6);
  assert.equal(rep.epochs.at(-1).public_key, cur.publicKey.toString('base64'));
  store.close();
});

test('rotation refuses a successor under a different origin name', async () => {
  const { store, c } = await open();
  c.heartbeat();
  const stranger = await generateDevSigner('log.example/somewhere-else');
  await assert.rejects(() => c.rotate(stranger), /origin/);
  // And nothing was written: a refused rotation must not leave a half-chain.
  assert.equal(store.readSuccession().length, 1);
  store.close();
});

test('rotation refuses the same key again', async () => {
  const { store, signer, c } = await open();
  c.heartbeat();
  await assert.rejects(() => c.rotate(signer), /itself|same key/);
  assert.equal(store.readSuccession().length, 1);
  store.close();
});

test('rotation refuses a non-ed25519 or malformed signer rather than writing it', async () => {
  const { store, signer, c } = await open();
  c.heartbeat();
  const bad = { ...await generateDevSigner(signer.name), publicKey: Buffer.alloc(31) };
  await assert.rejects(() => c.rotate(bad));
  assert.equal(store.readSuccession().length, 1);
  store.close();
});

test('a degraded collector refuses to rotate', async () => {
  const root = tmp();
  const { store, signer, c } = await open(root);
  c.heartbeat();
  store.close();
  // Tear the tail, then reopen: the collector starts degraded.
  const raw = readFileSync(join(root, 'chain', 'c1.jsonl'), 'utf8');
  writeFileSync(join(root, 'chain', 'c1.jsonl'), raw.slice(0, -5));
  const store2 = new Store(root, 'c1');
  const c2 = new Collector({ store: store2, config: cfg(root), signer, collector: 'c1', origin: signer.name });
  assert.ok(c2.degraded);
  const next = await generateDevSigner(signer.name);
  await assert.rejects(() => c2.rotate(next), /degraded/);
  store2.close();
});

test('rotation survives a restart: the epoch is read back from disk, not remembered', async () => {
  const root = tmp();
  const { store, signer, c } = await open(root);
  c.heartbeat();
  const second = await generateDevSigner(signer.name);
  await c.rotate(second);
  store.close();

  const store2 = new Store(root, 'c1');
  const c2 = new Collector({ store: store2, config: cfg(root), signer: second, collector: 'c1', origin: signer.name });
  assert.equal(c2.epoch, 1);
  const third = await generateDevSigner(signer.name);
  await c2.rotate(third);
  assert.equal(c2.epoch, 2);
  assert.deepEqual(store2.readSuccession().map(e => e.epoch), [0, 1, 2]);
  store2.close();
});

test('reopening with a signer that is not the live epoch key is refused', async () => {
  const root = tmp();
  const { store, signer, c } = await open(root);
  c.heartbeat();
  const second = await generateDevSigner(signer.name);
  await c.rotate(second);
  store.close();

  // Handing the collector epoch 0's key after it has rotated would sign new
  // checkpoints with a key the chain says is retired. Starting is the moment
  // to catch that, not the first verification months later.
  const store2 = new Store(root, 'c1');
  assert.throws(
    () => new Collector({ store: store2, config: cfg(root), signer, collector: 'c1', origin: signer.name }),
    /epoch 1|retired|live epoch/,
  );
  store2.close();
});

test('the succession journal is append-only and survives a torn tail as a finding', async () => {
  const root = tmp();
  const { store, signer, c } = await open(root);
  c.heartbeat();
  const second = await generateDevSigner(signer.name);
  await c.rotate(second);
  store.close();

  const p = join(root, 'succession', 'c1.jsonl');
  assert.ok(existsSync(p));
  const raw = readFileSync(p, 'utf8');
  writeFileSync(p, raw.slice(0, -8));
  const store2 = new Store(root, 'c1');
  const read = store2.readSuccessionDetailed();
  assert.equal(read.torn, true);
  // A torn tail drops the incomplete entry rather than parsing half of it.
  assert.deepEqual(read.entries.map(e => e.epoch), [0]);
  store2.close();
});

test('a checkpoint is signed by the live epoch, and an older one stays verifiable', async () => {
  const { store, signer, c } = await open();
  c.heartbeat();
  const first = await c.checkpoint();

  const second = await generateDevSigner(signer.name);
  await c.rotate(second);
  c.heartbeat();
  const later = await c.checkpoint();

  const { parseNote } = await import('../src/note.mjs');
  const { verifyNoteSignature } = await import('../src/signer.mjs');
  const a = parseNote(first.note);
  const b = parseNote(later.note);
  // Both notes carry the same origin and different key ids — which is how a
  // verifier attributes each checkpoint to an epoch without being told.
  assert.equal(a.signatures[0].name, b.signatures[0].name);
  assert.notEqual(a.signatures[0].keyId.toString('hex'), b.signatures[0].keyId.toString('hex'));
  assert.equal(await verifyNoteSignature(a.text, a.signatures[0], signer.verifier()), true);
  assert.equal(await verifyNoteSignature(b.text, b.signatures[0], second.verifier()), true);
  // SEC-08: the live key cannot stand in for the retired one.
  assert.equal(await verifyNoteSignature(a.text, a.signatures[0], second.verifier()), false);
  store.close();
});
