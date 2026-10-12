import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote, checkpointText } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const WITNESS = 'audit.internal';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/**
 * A signed key history, as @splitstick/witness-self publishes it: the current
 * key signs a note over a digest of the whole list.
 * @param {{ public_key: string, key_id: string, from: string }[]} keys
 * @param {import('@splitstick/core/signer').Signer} signer
 */
async function keyHistory(keys, signer) {
  const digest = createHash('sha256').update(JSON.stringify(keys)).digest();
  const text = checkpointText({
    origin: `${WITNESS}/keys`, tree_size: keys.length, root: digest, suite: 'SS1' });
  return { keys, note: encodeNote(text, [await signNote(text, signer)]) };
}

const entry = (/** @type {import('@splitstick/core/signer').Signer} */ s, from) => ({
  public_key: s.publicKey.toString('base64'),
  key_id: s.keyId.toString('hex'),
  from,
});

/**
 * One checkpoint, countersigned by `by`.
 * @param {import('@splitstick/core/signer').Signer} by
 */
async function store1(by) {
  const root = mkdtempSync(join(tmpdir(), 'ss-wk-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  const cp = await c.checkpoint();
  const text = parseNote(cp.note).text;
  const env = JSON.parse(String(store.readCheckpointEnvelope(cp.checkpoint_seq)));
  env.countersignatures = [{
    type: 'c2sp-note', issuer: WITNESS, covers: 'note',
    line: encodeNote(text, [await signNote(text, by)]).trim().split('\n').at(-1),
  }];
  store.writeCheckpointEnvelope(cp.checkpoint_seq, env);
  store.close();
  return { root, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

// ── FR-51 ───────────────────────────────────────────────────────────────────

test('FR-51: a countersignature from a RETIRED witness key still verifies', async () => {
  // Rotation is not an amnesty for anything signed before it — the same
  // principle as the operator's own epoch ratchet (FR-11).
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(old);
  const history = await keyHistory(
    [entry(old, '2026-01-01T00:00:00.000Z'), entry(current, '2026-10-01T00:00:00.000Z')],
    current);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: {
      quorum: 1,
      witnesses: [{
        id: WITNESS, establishes: ['sequence'],
        public_key: current.publicKey.toString('base64'),
        key_history: history,
      }],
    },
  });
  const e = r.witnesses.find(x => x.id === WITNESS);
  assert.equal(e?.verdict, 'ok', e?.detail);
  assert.equal(e?.accepted, true);
  // The report names WHICH key, so a reader can see it was a retired one.
  assert.match(String(e?.detail), /retired|key 1 of 2|history/i);
  assert.equal(r.quorum.observed.sequence, 1);
});

test('FR-51: the CURRENT key still works with a history present', async () => {
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(current);
  const history = await keyHistory(
    [entry(old, '2026-01-01T00:00:00.000Z'), entry(current, '2026-10-01T00:00:00.000Z')],
    current);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64'), key_history: history }] },
  });
  assert.equal(r.witnesses.find(x => x.id === WITNESS)?.verdict, 'ok');
});

test('FR-51: an UNSIGNED key history is refused — a list nobody signed', async () => {
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(old);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64'),
      key_history: { keys: [entry(old, '2026-01-01T00:00:00.000Z')] } }] },
  });
  const e = r.witnesses.find(x => x.id === WITNESS);
  assert.equal(e?.verdict, 'inconclusive');
  assert.match(String(e?.detail), /unsigned|nobody signed/i);
  assert.equal(r.quorum.observed.sequence, 0, 'and it counts towards nothing');
});

test('FR-51: a history signed by a key NOT in it is refused', async () => {
  // Otherwise anyone could publish a history asserting whatever keys they
  // liked and sign it with a key of their own.
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const stranger = await generateDevSigner(WITNESS);
  const s = await store1(old);
  const history = await keyHistory([entry(old, '2026-01-01T00:00:00.000Z')], stranger);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64'), key_history: history }] },
  });
  const e = r.witnesses.find(x => x.id === WITNESS);
  assert.equal(e?.verdict, 'inconclusive');
  assert.match(String(e?.detail), /not in the history|signed by a key/i);
});

test('FR-51: a history whose digest does not cover its own key list is refused', async () => {
  // The signature is over a digest of the list. Changing the list after
  // signing must not go unnoticed, or the signature covers nothing.
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(old);
  const history = await keyHistory([entry(current, '2026-10-01T00:00:00.000Z')], current);
  history.keys.unshift(entry(old, '2026-01-01T00:00:00.000Z'));   // added after signing
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64'), key_history: history }] },
  });
  const e = r.witnesses.find(x => x.id === WITNESS);
  assert.equal(e?.verdict, 'inconclusive');
  assert.match(String(e?.detail), /digest|does not cover/i);
});

test('FR-51: a key absent from a valid history is INCONCLUSIVE, not a failure', async () => {
  // A witness this reader cannot attribute is a witness this reader does not
  // know. It is not evidence of tampering, and calling it one would make a
  // rotation somebody forgot to publish look like an attack.
  const stranger = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(stranger);
  const history = await keyHistory([entry(current, '2026-10-01T00:00:00.000Z')], current);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64'), key_history: history }] },
  });
  const e = r.witnesses.find(x => x.id === WITNESS);
  assert.equal(e?.verdict, 'inconclusive');
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.match(String(e?.detail), /not any key in/i);
});

test('FR-51: with no history, only the pinned key is accepted — unchanged behaviour', async () => {
  const old = await generateDevSigner(WITNESS);
  const current = await generateDevSigner(WITNESS);
  const s = await store1(old);
  const r = await verifyStore(s.root, {
    collector: 'host-1', vkey: s.vkey,
    policy: { quorum: 1, witnesses: [{ id: WITNESS, establishes: ['sequence'],
      public_key: current.publicKey.toString('base64') }] },
  });
  assert.equal(r.witnesses.find(x => x.id === WITNESS)?.verdict, 'fail');
});
