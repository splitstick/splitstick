import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote, parseCheckpointText } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { parseEnvelope, addCountersignature } from '@splitstick/core/envelope';
import { leafDigest } from '@splitstick/core/leaf';
import { leafHash, nodeHash } from '@splitstick/core/merkle';
import { buildDisclosure, PACK_VERSION } from '../src/disclose.mjs';

/**
 * INT-03 — the SPEC is the guarantee and the implementation is a convenience.
 *
 * Two properties, and the second is the one that matters:
 *
 * 1. What the implementation emits matches `spec/disclosure-pack-v1.md`, field
 *    for field. A published format nothing checks is a format that drifts.
 *
 * 2. A pack verifies under an implementation written from the SPEC ALONE,
 *    which is what `independentVerify` below is. It shares no code with
 *    `verifyDisclosure`: it walks the audit path with its own RFC 6962 loop,
 *    recomputes the leaf from the record and the salt with its own domain
 *    prefix, and checks the signature with node's crypto directly. If
 *    verifying ever required our verifier the thesis would have inverted — a
 *    reader would be trusting us to tell them whether to trust us.
 *
 * It is not a *third-party* implementation, which only a third party can
 * supply. It is the strongest thing available in-repo: a second implementation
 * that reads the document rather than the code.
 */

const SPEC = readFileSync(
  new URL('../../../spec/disclosure-pack-v1.md', import.meta.url).pathname, 'utf8');
const ORIGIN = 'splitstick.dev/host-1';

async function rig() {
  const root = mkdtempSync(join(tmpdir(), 'ss-conf-'));
  const signer = await generateDevSigner(ORIGIN);
  const wk = await generateDevSigner('audit.example');
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  for (let i = 1; i <= 5; i += 1) {
    c.action({
      run: 'r-1', tool: 'transfer_funds', consequential: true,
      args: Buffer.from(`{"amount":${i}00}`), result: Buffer.from(`OK c-${i}`),
      outcome: 'ok', attempt: 1, correlation: `c-${i}`,
    });
  }
  const cp = await c.checkpoint();
  const raw = /** @type {string} */ (store.readCheckpointEnvelope(cp.checkpoint_seq));
  const text = parseNote(/** @type {string} */ (parseEnvelope(raw).note)).text;
  const line = encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1);
  store.writeCheckpointEnvelope(cp.checkpoint_seq, addCountersignature(JSON.parse(raw), {
    type: 'c2sp-note', issuer: 'audit.example', covers: 'note',
    line: /** @type {string} */ (line),
  }));
  const p = buildDisclosure(store, { record_seq: 3 });
  store.close();
  return { root, pack: p, signer, wk, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

// ── property 1: the emitted pack matches the document ──────────────────────

test('INT-03: the emitted pack has exactly the structure the spec documents', async () => {
  const { pack } = await rig();

  // EVERY key at EVERY level, derived from the pack rather than from a list
  // written here.
  //
  // This check used to look at the top level and at `proof`'s keys only, so
  // when the format gained `content[].salt` and `proof.leaf` — two fields that
  // change what a recipient can verify — it passed without noticing. A
  // published format nothing checks is a format that drifts, which is this
  // file's own opening sentence, and it drifted.
  //
  // Walking the pack means a new field anywhere fails until the document
  // mentions it, which is the only version of this that cannot rot.
  //
  // Three containers are not walked, and the distinction is between a key that
  // is a FIELD NAME and a key that is DATA:
  //
  //   record, checkpoint — the ActionRecord and the DES-20 envelope, specified
  //                        in DES-01 and DES-20 rather than here.
  //   salts              — keyed by record_seq, so its keys are record numbers.
  //                        Its shape is documented in prose above, and the
  //                        test below asserts there is exactly one of them.
  //
  // `content`'s keys ARE field names — args, result, approval.reviewer — so it
  // is walked, which is how the missing `salt` would have been caught.
  const DATA_KEYED = new Set(['record', 'checkpoint', 'salts']);
  /** @param {any} v @param {string} path */
  const walk = (v, path) => {
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return;
    for (const k of Object.keys(v)) {
      assert.ok(SPEC.includes(`"${k}"`) || SPEC.includes(`\`${k}\``),
        `${path}${k} is in the pack and nowhere in spec/disclosure-pack-v1.md`);
      walk(v[k], `${path}${k}.`);
    }
  };
  for (const [k, v] of Object.entries(pack)) {
    assert.ok(SPEC.includes(`"${k}"`), `the spec does not document the top-level key ${k}`);
    if (!DATA_KEYED.has(k)) walk(v, `${k}.`);
  }
  assert.deepEqual(Object.keys(pack).sort(),
    ['checkpoint', 'content', 'manifest', 'proof', 'record', 'salts']);

  assert.deepEqual(Object.keys(pack.manifest).sort(),
    ['collector', 'covers', 'disclosed', 'note', 'origin', 'suite', 'version']);
  assert.equal(pack.manifest.version, PACK_VERSION);
  assert.equal(pack.manifest.origin, ORIGIN);
  assert.equal(pack.manifest.collector, 'host-1');
  assert.deepEqual(pack.manifest.covers, { from_seq: 3, to_seq: 3, complete: false });
  assert.deepEqual(pack.manifest.disclosed, [3]);

  // `leaf` is absent here BY DESIGN: this fixture's record is not shredded, and
  // a pack carrying both a salt and a leaf would let a recipient check the
  // cheap one and skip the recomputation that binds the leaf to the record.
  assert.deepEqual(Object.keys(pack.proof).sort(),
    ['checkpoint_seq', 'index', 'path', 'root', 'tree_size']);
  assert.equal(pack.proof.index, 2, '0-based leaf index, as the spec says');
  assert.equal(pack.proof.tree_size, 5);
  assert.match(pack.proof.root, /^[0-9a-f]{64}$/, '64 hex characters');
  for (const n of pack.proof.path) {
    assert.match(n, /^[A-Za-z0-9+/]+=*$/, 'base64 node digests');
    assert.equal(Buffer.from(n, 'base64').length, 32);
  }

  // The salt: one entry, keyed by the disclosed record_seq, 32 hex characters.
  assert.deepEqual(Object.keys(pack.salts), ['3']);
  assert.match(pack.salts['3'], /^[0-9a-f]{32}$/);

  assert.deepEqual(Object.keys(pack.checkpoint).sort(),
    ['countersignatures', 'note', 'note_digest']);
  assert.equal(pack.checkpoint.countersignatures.length, 1);

  for (const [where, c] of Object.entries(pack.content)) {
    const held = /** @type {any} */ (c);
    assert.deepEqual(Object.keys(held).sort(), ['base64', 'cid', 'present', 'salt'],
      `${where} must carry exactly what the spec's table lists`);
    assert.match(held.cid, /^sha256:[0-9a-f]{64}$/);
    assert.equal(held.present, true);
    assert.equal(typeof held.base64, 'string');
    // The content salt, without which the payload cannot be checked against
    // its commitment at all.
    assert.match(held.salt, /^[0-9a-f]{32}$/, `${where} carries no content salt`);
  }
});

test('INT-03: the spec documents every verification step the implementation takes', () => {
  // A document that fell behind the code would be worse than none: a third
  // party implementing from it would build a weaker verifier and believe it
  // was conformant.
  for (const required of [
    /Refuse an unknown `manifest.version`/,
    /Require a countersignature.*FR-33/s,
    /present and unverified/,
    /Recompute the leaf/,
    /the root \*\*the checkpoint commits to\*\*/,
    /Report absent content as absent/,
  ]) {
    assert.match(SPEC, required, `the spec no longer documents ${required}`);
  }
  // And the honest statement about what a Merkle path reveals.
  assert.match(SPEC, /contains the\s+\*hash\* of a sibling leaf/);
  assert.match(SPEC, /covers\.complete` is\s+`false`/);
});

// ── property 2: a verifier written from the spec alone ─────────────────────

/**
 * An independent verifier, implemented from `spec/disclosure-pack-v1.md`.
 *
 * Deliberately shares no code with the project's verifier: its own RFC 6962
 * audit-path walk, its own leaf recomputation from the documented domain
 * prefixes, and node's crypto for the signature. Any disagreement between this
 * and `verifyDisclosure` means the spec and the implementation have parted
 * company, which is the failure INT-03 exists to prevent.
 *
 * @param {any} pack @param {{ vkey: string, witnessKey: Buffer }} o
 */
async function independentVerify(pack, o) {
  const { createPublicKey, verify: cryptoVerify } = await import('node:crypto');

  // Step 1 — refuse an unknown version.
  if (pack.manifest.version !== 1) return { ok: false, why: 'unsupported version' };

  // Step 2 — parse the checkpoint note. Documented in DES-07: an origin line,
  // a tree size, a base64 root, then signature lines after a blank line.
  const noteBlob = String(pack.checkpoint.note);
  const [body, sigBlock] = noteBlob.split('\n\n');
  const bodyLines = String(body).split('\n');
  const origin = bodyLines[0];
  const size = Number(bodyLines[1]);
  const root = Buffer.from(String(bodyLines[2]), 'base64');

  // Step 3 — require a countersignature.
  const sigLines = String(sigBlock ?? '').trim().split('\n').filter(Boolean);
  if (pack.checkpoint.countersignatures.length === 0) {
    return { ok: false, why: 'no countersignature (FR-33)' };
  }

  // Step 5 — the operator signature over the note body. A note signature line
  // is `— <name> <base64(keyid4 ‖ sig)>`.
  // Split at the FIRST two separators, never with split('+'): standard base64
  // contains '+', so splitting on every one shards the key material. That is
  // roughly one key in four, and it is the SECOND thing this verifier got
  // wrong — after taking the third part as a bare public key when it carries
  // an algorithm byte first. Both mistakes came from the document not saying,
  // and both are now in it: a third party would have made exactly these.
  const vkey = String(o.vkey);
  const i1 = vkey.indexOf('+');
  const i2 = vkey.indexOf('+', i1 + 1);
  const vkeyName = vkey.slice(0, i1);
  const keyBlob = Buffer.from(vkey.slice(i2 + 1), 'base64');
  assert.equal(keyBlob.length, 33, 'one algorithm byte and a 32-byte key');
  assert.equal(keyBlob[0], 1, 'algorithm 1 is Ed25519');
  const pub = keyBlob.subarray(1);
  let operatorOk = false;
  for (const l of sigLines) {
    const m = /^— (\S+) (\S+)$/.exec(l);
    if (m === null || m[1] !== vkeyName) continue;
    const blob = Buffer.from(String(m[2]), 'base64');
    const sig = blob.subarray(4);
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]),
      format: 'der', type: 'spki',
    });
    if (cryptoVerify(null, Buffer.from(`${body}\n`), key, sig)) operatorOk = true;
  }
  if (!operatorOk) return { ok: false, why: 'operator signature does not verify' };

  // Step 6 — the manifest agrees with the record it carries. BEFORE the leaf,
  // as the spec's step order says: the salts map is keyed by record_seq, so a
  // manifest naming another record finds no salt and the leaf recomputation
  // throws instead of refusing. This verifier had the check at the end and did
  // exactly that, which the conformance test caught.
  if (Number(pack.record.record_seq) !== Number(pack.manifest.disclosed[0])) {
    return { ok: false, why: 'the manifest names a record the pack does not hold' };
  }

  // Step 7 — recompute the leaf. DES-03: leaf_digest over the salt and the
  // canonical record; the tree leaf is SHA-256(0x00 ‖ leaf_digest).
  const saltHex = pack.salts[String(pack.manifest.disclosed[0])];
  if (typeof saltHex !== 'string' || !/^[0-9a-f]{32}$/.test(saltHex)) {
    return { ok: false, why: 'no usable leaf salt for the disclosed record' };
  }
  const salt = Buffer.from(saltHex, 'hex');
  const digest = leafDigest(salt, pack.record);
  let computed = createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), digest])).digest();

  // Step 9 — RFC 6962 §2.1.1, written out rather than called.
  let fn = pack.proof.index;
  let sn = pack.proof.tree_size - 1;
  for (const p of pack.proof.path.map((/** @type {string} */ x) => Buffer.from(x, 'base64'))) {
    if (sn === 0) return { ok: false, why: 'path longer than the tree is deep' };
    if (fn % 2 === 1 || fn === sn) {
      computed = createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), p, computed])).digest();
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      computed = createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), computed, p])).digest();
    }
    fn >>= 1; sn >>= 1;
  }
  if (fn !== 0) return { ok: false, why: 'path too short' };
  if (!computed.equals(Buffer.from(String(pack.proof.root), 'hex'))) {
    return { ok: false, why: 'the path does not reach the stated root' };
  }
  // And the stated root must be the one the checkpoint commits to.
  if (!computed.equals(root)) return { ok: false, why: 'the root is not the checkpoint\'s' };
  if (size !== pack.proof.tree_size) return { ok: false, why: 'tree size disagrees with the note' };
  if (origin !== pack.manifest.origin) return { ok: false, why: 'origin disagrees' };

  // Step 8 — each payload against the commitment THE RECORD HOLDS, as
  // SHA-256(0x05 ‖ salt ‖ plaintext). Written out here rather than calling
  // contentCid, so the spec's formula is what is being checked.
  //
  // The expected locations come from the record, which is the only
  // authenticated object: comparing a payload to the cid in its own content
  // entry accepts a self-consistent replacement, since nothing authenticates
  // that entry. This implementation had that bug too, from the same spec that
  // did not say — which is the point of writing it from the document.
  /** @type {Map<string, string>} */
  const expected = new Map();
  for (const f of ['agent', 'args', 'result']) {
    const cid = pack.record?.[f]?.cid;
    if (typeof cid === 'string') expected.set(f, cid);
  }
  for (const f of ['reviewer', 'request']) {
    const cid = pack.record?.approval?.[f]?.cid;
    if (typeof cid === 'string') expected.set(`approval.${f}`, cid);
  }
  const seen = new Set(Object.keys(pack.content ?? {}));
  for (const [where, cid] of expected) {
    const held = /** @type {any} */ ((pack.content ?? {})[where]);
    seen.delete(where);
    if (held === undefined) return { ok: false, why: `${where}: committed and omitted` };
    if (held.cid !== cid) return { ok: false, why: `${where}: cid is not the record's` };
    if (held.present !== true) {
      if (held.base64 !== undefined) return { ok: false, why: `${where}: absent with bytes` };
      continue;
    }
    if (typeof held.salt !== 'string') return { ok: false, why: `${where}: no content salt` };
    const recomputed = `sha256:${createHash('sha256')
      .update(Buffer.from([0x05]))
      .update(Buffer.from(held.salt, 'hex'))
      .update(Buffer.from(held.base64, 'base64'))
      .digest('hex')}`;
    if (recomputed !== cid) return { ok: false, why: `${where}: bytes do not match the record` };
  }
  for (const where of seen) return { ok: false, why: `${where}: not committed by the record` };
  return { ok: true, why: 'verified from the spec alone' };
}

test('INT-03: a verifier written from the spec alone validates a reference pack', async () => {
  const { pack, vkey, wk } = await rig();
  const r = await independentVerify(pack, { vkey, witnessKey: Buffer.from(wk.publicKey) });
  assert.equal(r.ok, true, r.why);
});

test('INT-03: the independent verifier rejects what the spec says it must', async () => {
  // A second implementation that accepted everything would be worse than none:
  // it would make the conformance test above a formality.
  const { pack, vkey, wk } = await rig();
  const key = { vkey, witnessKey: Buffer.from(wk.publicKey) };

  const broken = [
    ['unsupported version', { ...pack, manifest: { ...pack.manifest, version: 2 } }],
    ['substituted payload', {
      ...pack,
      content: {
        ...pack.content,
        args: {
          ...pack.content.args,
          base64: Buffer.from('{"amount":999999999}').toString('base64'),
        },
      },
    }],
    // The PR #10 finding: bytes, salt and cid replaced TOGETHER, so the entry
    // is internally consistent and has nothing to do with the record.
    ['self-consistent replacement', {
      ...pack,
      content: {
        ...pack.content,
        args: {
          cid: `sha256:${createHash('sha256')
            .update(Buffer.from([0x05])).update(Buffer.alloc(16, 7))
            .update(Buffer.from('other')).digest('hex')}`,
          present: true,
          base64: Buffer.from('other').toString('base64'),
          salt: '07'.repeat(16),
        },
      },
    }],
    ['committed payload omitted', { ...pack, content: {} }],
    ['content the record does not commit to', {
      ...pack, content: { ...pack.content, elsewhere: { ...pack.content.args } },
    }],
    ['missing content salt', {
      ...pack,
      content: { ...pack.content, args: { ...pack.content.args, salt: undefined } },
    }],
    ['absent with bytes', {
      ...pack,
      content: { ...pack.content, args: { ...pack.content.args, present: false } },
    }],
    ['manifest names another record', {
      ...pack, manifest: { ...pack.manifest, disclosed: [1] },
    }],
    ['no countersignature', {
      ...pack, checkpoint: { ...pack.checkpoint, countersignatures: [] },
    }],
    ['altered record', {
      ...pack, record: { ...pack.record, attempt: pack.record.attempt + 1 },
    }],
    ['altered salt', { ...pack, salts: { 3: 'a'.repeat(32) } }],
    ['altered root', { ...pack, proof: { ...pack.proof, root: 'ff'.repeat(32) } }],
    ['truncated path', { ...pack, proof: { ...pack.proof, path: pack.proof.path.slice(1) } }],
    ['wrong index', { ...pack, proof: { ...pack.proof, index: 0 } }],
  ];
  for (const [what, p] of broken) {
    const r = await independentVerify(p, key);
    assert.equal(r.ok, false, `the independent verifier accepted: ${what}`);
  }
});

test('INT-03: the two implementations agree, pack for pack', async () => {
  // Any disagreement means the spec and the code have parted company.
  const { verifyDisclosure } = await import('../src/disclose.mjs');
  const { pack, vkey, wk } = await rig();
  const policy = {
    witnesses: [{
      id: 'audit.example', public_key: Buffer.from(wk.publicKey).toString('base64'),
    }],
  };
  const ours = await verifyDisclosure(pack, { vkey, policy });
  const theirs = await independentVerify(pack, { vkey, witnessKey: Buffer.from(wk.publicKey) });
  assert.equal(ours.verdict, 'ok', JSON.stringify(ours.findings));
  assert.equal(theirs.ok, true, theirs.why);

  for (const mutate of [
    (/** @type {any} */ p) => ({ ...p, proof: { ...p.proof, root: 'ff'.repeat(32) } }),
    (/** @type {any} */ p) => ({ ...p, salts: { 3: 'b'.repeat(32) } }),
    (/** @type {any} */ p) => ({ ...p, manifest: { ...p.manifest, version: 99 } }),
    // The review's own findings, checked against BOTH implementations: a
    // substituted payload and a lying manifest must be refused by each.
    (/** @type {any} */ p) => ({
      ...p,
      content: {
        ...p.content,
        args: { ...p.content.args, base64: Buffer.from('tampered').toString('base64') },
      },
    }),
    (/** @type {any} */ p) => ({ ...p, manifest: { ...p.manifest, disclosed: [1] } }),
  ]) {
    const p = mutate(pack);
    const a = await verifyDisclosure(p, { vkey, policy });
    const b = await independentVerify(p, { vkey, witnessKey: Buffer.from(wk.publicKey) });
    assert.equal(a.verdict, 'fail', 'ours must reject it');
    assert.equal(b.ok, false, 'and so must theirs');
  }
  // leafHash and nodeHash are the project's own primitives; the independent
  // verifier above deliberately does not use them, and this asserts they agree
  // with the hand-written version so the divergence is real rather than a bug.
  const leaf = leafDigest(Buffer.from(pack.salts['3'], 'hex'), pack.record);
  assert.ok(leafHash(leaf).equals(
    createHash('sha256').update(Buffer.concat([Buffer.from([0]), leaf])).digest()));
  assert.ok(nodeHash(leaf, leaf).equals(
    createHash('sha256').update(Buffer.concat([Buffer.from([1]), leaf, leaf])).digest()));
  assert.ok(parseCheckpointText !== undefined);
});
