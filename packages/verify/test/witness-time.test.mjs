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

// ── LEG-09 groundwork: cosignature/v1 through the VERIFIER ──────────────────

/**
 * A store countersigned with a real cosignature/v1 line.
 *
 * FR-15 established interoperability with transparency-dev/witness and fixed
 * the ANCHORER's acceptance check. It did not fix this verifier, which computed
 * the key id with the default algorithm — so the shape check could never match
 * a cosignature/v1 key id (0x04 hashes differently from 0x01) and every real
 * witness cosignature came back `bad`. That is the worse place for it to fail:
 * the operator saw the proof attached and an auditor saw it as invalid.
 *
 * @param {{ received_at?: string, signedTs?: number, issuer?: string }} [o]
 */
async function cosigned(o = {}) {
  const { ALG_ED25519_COSIG_V1, cosignatureV1Message } = await import('@splitstick/core/note');
  const issuer = o.issuer ?? 'tlog.example';
  const root = mkdtempSync(join(tmpdir(), 'ss-cosig-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c.action(tx());
  const cp = await c.checkpoint();

  const wkey = await generateDevSigner(issuer);
  const text = parseNote(cp.note).text;
  const signedTs = o.signedTs ?? Math.floor(Date.parse('2026-10-11T14:30:00.000Z') / 1000);
  const sig = await wkey.sign(Buffer.from(cosignatureV1Message(signedTs, text), 'utf8'));
  const { noteKeyId } = await import('@splitstick/core/note');
  const ts8 = Buffer.alloc(8);
  ts8.writeBigUInt64BE(BigInt(signedTs));
  const blob = Buffer.concat([
    noteKeyId(issuer, wkey.publicKey, ALG_ED25519_COSIG_V1), ts8, sig,
  ]);

  const env = JSON.parse(String(store.readCheckpointEnvelope(cp.checkpoint_seq)));
  env.countersignatures = [{
    type: 'c2sp-note', issuer, covers: 'note',
    line: `— ${issuer} ${blob.toString('base64')}`,
    received_at: o.received_at ?? new Date(signedTs * 1000).toISOString(),
  }];
  store.writeCheckpointEnvelope(cp.checkpoint_seq, env);
  store.close();
  const { formatVkey: fv } = await import('@splitstick/core/note');
  return {
    root, signedTs,
    vkey: formatVkey(ORIGIN, signer.publicKey),
    // The policy names the key as a VKEY, which carries the algorithm byte.
    policy: {
      quorum: 1,
      witnesses: [{
        id: issuer, establishes: ['sequence', 'time'],
        public_key: fv(issuer, wkey.publicKey, ALG_ED25519_COSIG_V1),
      }],
    },
    rawKeyPolicy: {
      quorum: 1,
      witnesses: [{
        id: issuer, establishes: ['sequence', 'time'],
        public_key: wkey.publicKey.toString('base64'),   // no algorithm
      }],
    },
  };
}

test('LEG-09: the verifier ACCEPTS a cosignature/v1 countersignature', async () => {
  const w = await cosigned();
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'tlog.example');
  assert.equal(entry?.verdict, 'ok', JSON.stringify(entry));
  assert.equal(entry?.accepted, true);
});

/**
 * The algorithm comes from the READER'S POLICY and never from the line. A bare
 * base64 key still means algorithm 1, which is what every policy written
 * before cosignature/v1 existed meant by it — so a policy that has not said
 * otherwise must NOT be silently upgraded to accept a timestamped cosignature.
 * Letting the line choose would be a downgrade, or upgrade, the reader never
 * agreed to.
 */
test('LEG-09: a bare key in the policy still means algorithm 1, not whatever arrived', async () => {
  const w = await cosigned();
  const r = await verifyStore(w.root, {
    collector: 'host-1', vkey: w.vkey, policy: w.rawKeyPolicy,
  });
  const entry = r.witnesses.find(x => x.id === 'tlog.example');
  assert.notEqual(entry?.verdict, 'ok',
    'a cosignature/v1 line must not verify against a policy entry that declares no algorithm');
});

test('LEG-09: an unreadable key in the policy is a witness this reader does not know', async () => {
  const w = await cosigned();
  const r = await verifyStore(w.root, {
    collector: 'host-1',
    vkey: w.vkey,
    policy: { quorum: 1, witnesses: [{ id: 'tlog.example', public_key: 'not-base64-or-a-vkey!!' }] },
  });
  const entry = r.witnesses.find(x => x.id === 'tlog.example');
  assert.match(String(entry?.detail), /neither a 32-byte base64 key nor a vkey/);
});

/**
 * The basis the report prints. This verifier told readers that "a C2SP note has
 * nowhere inside it to carry a time... exactly as good as that witness's word"
 * — about a timestamp that is inside the signed message. Third place that
 * premise appeared after FR-15 disproved it, and the worst, because it is what
 * an auditor reads.
 */
test('LEG-09: a signed cosignature timestamp is reported as SIGNED', async () => {
  const w = await cosigned();
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'tlog.example');
  assert.equal(entry?.received_at_basis, 'signed by the witness, inside the cosignature');
  assert.ok(r.capability.cannot.some(s => /signed by the witness, inside the cosignature/.test(s)
    && /no eIDAS presumption attaches/.test(s)),
  'it must say what the signature does NOT buy: ' + JSON.stringify(r.capability.cannot));
});

/**
 * And equality is load-bearing. A received_at that merely sits BESIDE a signed
 * value is not the signed value — an adapter writing its own clock into the
 * envelope must not have it described as signed by the witness.
 */
test('LEG-09: a received_at that is not the signed one is NOT reported as signed', async () => {
  const w = await cosigned({ received_at: '2026-10-11T23:59:59.000Z' });   // the adapter's clock
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'tlog.example');
  assert.equal(entry?.received_at, '2026-10-11T23:59:59.000Z');
  assert.equal(entry?.received_at_basis, 'witness-asserted, unsigned',
    'a value beside a signed one is not the signed one');
});

test('LEG-09: a plain c2sp-note signature is still reported as unsigned', async () => {
  // The regression guard in the other direction: witness-self signs plain note
  // signatures, and those really do carry no time.
  const w = await witnessed({ received_at: '2026-10-11T14:30:00.000Z' });
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  const entry = r.witnesses.find(x => x.id === 'audit.internal');
  assert.equal(entry?.received_at_basis, 'witness-asserted, unsigned');
});

/** The real bytes, from transparency-dev/witness, so this is not self-agreement. */
test('LEG-09: the captured Go-witness cosignature verifies under this verifier', async () => {
  const { parseVkey, parseSignatureLine, ALG_ED25519_COSIG_V1, cosignatureV1Message } =
    await import('@splitstick/core/note');
  const { verifyNoteSignature } = await import('@splitstick/core/signer');
  const fixture = JSON.parse(readFileSync(
    new URL('../../witness-tlog/interop/results/cosignature-fixture.json', import.meta.url), 'utf8'));
  const { name, publicKey, algorithm } = parseVkey(fixture.witness_vkey);
  assert.equal(algorithm, ALG_ED25519_COSIG_V1);

  const text = parseNote(fixture.checkpoint_note).text;
  const sig = parseSignatureLine(fixture.cosignature_line);
  assert.equal(typeof sig.timestamp, 'bigint');
  assert.ok(cosignatureV1Message(sig.timestamp, text).startsWith('cosignature/v1\ntime '));
  assert.equal(await verifyNoteSignature(text, sig, {
    name, publicKey, algorithm, keyId: sig.keyId,
  }), true, 'the real witness cosignature must verify under the shipped verifier');
});

test('a configured, VERIFIED witness does not discharge the completeness assumption', async () => {
  // The line read "the operator for the completeness of what was captured,
  // until a witness is configured" and was pushed unconditionally, so a store
  // with a verified witness still said it -- a conditional clause on an
  // unconditional statement, promising that a witness would lift an assumption
  // no witness can lift.
  const w = await cosigned();
  const r = await verifyStore(w.root, { collector: 'host-1', vkey: w.vkey, policy: w.policy });
  assert.equal(r.witnesses.find(x => x.id === 'tlog.example')?.verdict, 'ok',
    'this test needs a verified witness to be meaningful');
  const line = r.trusting.find(t => /completeness/i.test(t));
  assert.ok(line, JSON.stringify(r.trusting));
  assert.doesNotMatch(String(line), /until a witness is configured/);
  assert.match(String(line), /No witness discharges this/);
});
