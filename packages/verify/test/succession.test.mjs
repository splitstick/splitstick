import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});
const sPath = (root) => join(root, 'succession', 'host-1.jsonl');
const readS = (root) => readFileSync(sPath(root), 'utf8').trim().split('\n').map(l => JSON.parse(l));
const writeS = (root, es) => writeFileSync(sPath(root), es.map(e => JSON.stringify(e)).join('\n') + '\n');

/**
 * A store whose checkpoints span `epochs` epochs: records and a checkpoint in
 * each, rotating between. The pinned vkey is always epoch 0's — that is the
 * property under test.
 * @param {number} epochs
 * @param {('software'|'kms'|'hsm')[]} [custody]
 */
async function spanning(epochs, custody = []) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-succ-'));
  const rootSigner = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer: rootSigner,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  const signers = [rootSigner];
  for (let i = 0; i < epochs; i += 1) {
    c.action(tx({ correlation: `c-${i}-a` }));
    c.action(tx({ correlation: `c-${i}-b` }));
    await c.checkpoint();
    if (i < epochs - 1) {
      const next = await generateDevSigner(ORIGIN);
      await c.rotate(next);
      signers.push(next);
    }
  }
  // Custody is an operator declaration, so a test may rewrite it: that is
  // exactly what an operator can do, and the verifier must handle it.
  if (custody.length) {
    const es = readS(root);
    writeS(root, es.map((e, i) => ({ ...e, custody: custody[i] ?? e.custody })));
  }
  store.close();
  return { root, signers, vkey: formatVkey(ORIGIN, rootSigner.publicKey), collector: c };
}

test('one pinned root verifies checkpoints signed across four epochs', async () => {
  const { root, vkey } = await spanning(4);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.equal(r.checks.find(c => c.name === 'SUCCESSION')?.verdict, 'ok');
  assert.equal(r.checks.find(c => c.name === 'OP-SIG')?.verdict, 'ok');
  assert.equal(r.succession?.epochs.length, 4);
  // The whole value of FR-11: the reader pinned one key, years of rotation ago.
  assert.ok(r.capability.can.some(s => /4 epochs/.test(s)), JSON.stringify(r.capability.can));
});

test('without the ratchet, a checkpoint from a later epoch would be unverifiable', async () => {
  // Deleting the succession journal leaves notes signed by keys the pinned
  // identity cannot vouch for. This is the state M1 was in, made explicit.
  const { root, vkey } = await spanning(3);
  writeFileSync(sPath(root), '');
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_INVALID' || f.code === 'SUCCESSION_BROKEN'));
});

test('a succession chain with an epoch removed is SUCCESSION_BROKEN and fails', async () => {
  const { root, vkey } = await spanning(4);
  const es = readS(root);
  writeS(root, [es[0], es[1], es[3]]);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN'));
  assert.equal(r.checks.find(c => c.name === 'SUCCESSION')?.verdict, 'fail');
  // And no affirmative signature claim survives a broken chain.
  assert.ok(!r.capability.can.some(s => /signed the tree size/.test(s)));
});

test('a succession chain rooted at a key the reader did not pin is refused', async () => {
  const { root } = await spanning(3);
  const stranger = await generateDevSigner(ORIGIN);
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey(ORIGIN, stranger.publicKey),
  });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'SUCCESSION_BROKEN'));
});

/**
 * @param {string} root @param {number} seq
 * @param {import('@splitstick/core/signer').Signer} with_
 */
async function resign(root, seq, with_) {
  const store = new Store(root, 'host-1');
  const { parseNote, encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const found = store.readCheckpoints().find(n => n.seq === seq);
  if (!found) throw new Error(`no checkpoint ${seq}`);
  const text = parseNote(found.note).text;
  store.writeCheckpoint(seq, encodeNote(text, [await signNote(text, with_)]));
  store.close();
}

test('SEC-08: re-signing part of the history with the live key is detected', async () => {
  // Checkpoint 1 was signed by epoch 0. Re-signed with the live key, it is now
  // attributed to epoch 2 while checkpoint 2 is still epoch 1 — an epoch that
  // runs backwards as the ordinals run forwards. Each signature is valid on its
  // own; only the ordering across them shows the rewrite.
  const { root, signers, vkey } = await spanning(3);
  await resign(root, 1, signers[signers.length - 1]);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(r.findings.some(f => f.code === 'OPSIG_EPOCH_REGRESSED'),
    `expected an epoch-ordering finding, got ${r.findings.map(f => f.code).join(', ')}`);
  assert.equal(r.verdict, 'fail');
});

test('SEC-08, honestly: a WHOLESALE re-sign is not locally detectable, and the report says so', async () => {
  // Every checkpoint re-signed with the live key leaves no ordering violation
  // to find: the epochs are all equal, which is a shape an operator who simply
  // rotated without checkpointing would also produce. Nothing local separates
  // them. This is why AC-3 is carried to M3a and closed by a countersignature
  // over the original root, and the report must not imply otherwise.
  const { root, signers, vkey } = await spanning(3);
  const live = signers[signers.length - 1];
  for (const seq of [1, 2, 3]) await resign(root, seq, live);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.ok(
    r.capability.cannot.some(s => /re-sign/i.test(s) && /countersignature/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1),
  );
  // And the thing M2 genuinely buys must not be overstated into this gap.
  assert.ok(!r.capability.can.some(s => /re-sign/i.test(s)));
});

test('an epoch declared software gets no forward-secrecy claim in the report', async () => {
  const { root, vkey } = await spanning(3, ['software', 'software', 'software']);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  // SEC-17 — the refusal is in the report a reader sees, not only in the docs.
  assert.ok(r.capability.cannot.some(s => /forward secrec/i.test(s) && /software/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
  assert.ok(!r.capability.can.some(s => /forward secrec/i.test(s)));
});

test('a kms-declared retired epoch gets the claim WITH its precondition attached', async () => {
  const { root, vkey } = await spanning(3, ['kms', 'kms', 'kms']);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  const claim = r.capability.can.find(s => /forward secrec/i.test(s));
  assert.ok(claim, JSON.stringify(r.capability.can, null, 1));
  // SEC-17's actual requirement: the precondition in the same place as the
  // claim, not a page away. Both halves — non-exportable custody, and
  // destruction — and both labelled as declarations.
  assert.match(claim, /non-exportable/i);
  assert.match(claim, /destr/i);
  assert.match(claim, /declar/i);
  assert.ok(r.trusting.some(s => /custody|destr/i.test(s)), JSON.stringify(r.trusting));
});

test('a mixed chain claims forward secrecy for no epoch while one is software', async () => {
  const { root, vkey } = await spanning(3, ['kms', 'software', 'kms']);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  // A reader asking "can yesterday's record be re-signed with today's key?"
  // gets one answer about this log, and one software epoch is enough to make
  // it no. Reporting the claim per-epoch and letting the reader aggregate is
  // how a summary ends up stronger than its parts.
  assert.ok(!r.capability.can.some(s => /forward secrec/i.test(s)),
    JSON.stringify(r.capability.can, null, 1));
  assert.ok(r.capability.cannot.some(s => /forward secrec/i.test(s) && /epoch 1/.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
});

test('custody is reported as operator-declared, never as established', async () => {
  const { root, vkey } = await spanning(2, ['hsm', 'hsm']);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  for (const e of r.succession?.epochs ?? []) {
    assert.equal(e.custody_basis, 'operator-declared');
    assert.equal(e.custody_independently_supported, false);
  }
  assert.ok(r.capability.cannot.some(s => /operator-declared/.test(s) && /custody/i.test(s)));
  // FR-70's attestation path is not built, so nothing may read as supported.
  assert.ok(!r.capability.can.some(s => /independently supported/i.test(s)));
});

test('a store with no succession journal at all is inconclusive, not failed', async () => {
  // An M1 store. One epoch, no journal, nothing wrong with it.
  const root = mkdtempSync(join(tmpdir(), 'splitstick-succ-m1-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  await c.checkpoint();
  writeFileSync(sPath(root), '');
  store.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey: formatVkey(ORIGIN, signer.publicKey) });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.equal(r.checks.find(ch => ch.name === 'SUCCESSION')?.verdict, 'inconclusive');
  assert.ok(r.capability.cannot.some(s => /epoch|ratchet|succession/i.test(s)));
});

test('an unpinned reader learns nothing from the succession chain either', async () => {
  const { root } = await spanning(3);
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.checks.find(c => c.name === 'SUCCESSION')?.verdict, 'inconclusive');
  assert.ok(r.capability.cannot.some(s => /no operator identity was pinned/.test(s)));
});
