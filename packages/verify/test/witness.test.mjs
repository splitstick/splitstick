import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { Anchorer } from '@splitstick/core/anchor';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK ref=TX-77814'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/** A c2sp-note witness with a known key. */
async function sequenceWitness(id) {
  const key = await generateDevSigner(id);
  return {
    id, key,
    adapter: {
      id, proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
      tier: /** @type {const} */ ('anchor'),
      async submit(/** @type {string} */ note) {
        const text = parseNote(note).text;
        return {
          type: /** @type {const} */ ('c2sp-note'), issuer: id,
          covers: /** @type {const} */ ('note'),
          line: encodeNote(text, [await signNote(text, key)]).trim().split('\n').at(-1),
        };
      },
    },
  };
}

/** A time-only witness. Its token is opaque to an offline verifier. */
function timeWitness(id) {
  return {
    id,
    adapter: {
      id, proof_type: /** @type {const} */ ('rfc3161'), establishes: ['time'],
      tier: /** @type {const} */ ('anchor'),
      async submit() {
        return {
          type: /** @type {const} */ ('rfc3161'), issuer: id,
          covers: /** @type {const} */ ('note_digest'), token: Buffer.from('fake token').toString('base64'),
        };
      },
    },
  };
}

/** @param {{ records?: number, witnesses?: any[] }} [o] */
async function evidence({ records = 4, witnesses = [] } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'ss-wv-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < records; i += 1) c.action(tx({ correlation: `c-${i}` }));
  const cp = await c.checkpoint();
  const a = new Anchorer({ store, witnesses: witnesses.map(w => w.adapter), quorum: 1 });
  await a.anchor(cp.checkpoint_seq);
  store.close();
  return { root, signer, store, collector: c, cp, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

/** @param {{id: string, key?: any, establishes?: string[]}[]} ws */
const policy = (ws, quorum = 1) => ({
  quorum,
  witnesses: ws.map(w => ({
    id: w.id,
    ...(w.key ? { public_key: w.key.publicKey.toString('base64') } : {}),
    establishes: w.establishes ?? (w.key ? ['sequence'] : ['time']),
  })),
});

// ── Row 27 — the policy is an input ──────────────────────────────────────────

test('row 27: the same pack verifies differently under two acceptance policies', async () => {
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey } = await evidence({ witnesses: [audit] });

  const trusting = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([audit]) });
  const trustingNobody = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([]) });

  assert.equal(trusting.checks.find(c => c.name === 'WITNESS')?.verdict, 'ok');
  assert.equal(trustingNobody.checks.find(c => c.name === 'WITNESS')?.verdict, 'inconclusive');
  // Neither is wrong. The policy is an input, not a hardcoded trust store, and
  // two readers with different trust reach different conclusions from one pack.
  assert.equal(trusting.summary.failed, 0);
  assert.equal(trustingNobody.summary.failed, 0);
});

// ── Row 28 — an empty policy trusts nobody, and says that ────────────────────

test('row 28: an empty policy says the reader trusted nobody, not that nobody signed', async () => {
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey } = await evidence({ witnesses: [audit] });
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([]) });
  assert.ok(r.capability.cannot.some(s => /acceptance policy names no witness/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
  // The countersignature IS in the pack. The report must not imply otherwise.
  assert.equal(r.witnesses.length, 1);
  assert.equal(r.witnesses[0].accepted, false);
});

// ── Rows 29, 31 — quorum per capability ──────────────────────────────────────

test('row 29: quorum met for time is not quorum met for sequence', async () => {
  const a = timeWitness('tsa.a');
  const b = timeWitness('tsa.b');
  const { root, vkey } = await evidence({ witnesses: [a, b] });
  const r = await verifyStore(root, {
    collector: 'host-1', vkey, policy: policy([a, b], 2),
  });
  assert.deepEqual(r.quorum.observed, { sequence: 0, time: 2, existence: 0 });
  assert.equal(r.quorum.met.time, true);
  assert.equal(r.quorum.met.sequence, false);
  // One aggregate number would let an operator look well-witnessed while
  // unable to detect truncation at all.
  assert.ok(r.capability.cannot.some(s => /sequence state/i.test(s)));
  assert.ok(!r.capability.can.some(s => /truncation/i.test(s)));
});

test('row 31: a countersignature from a witness the policy does not name counts for nothing', async () => {
  const audit = await sequenceWitness('audit.internal');
  const stranger = await sequenceWitness('somebody.else');
  const { root, vkey } = await evidence({ witnesses: [audit, stranger] });
  const r = await verifyStore(root, {
    collector: 'host-1', vkey, policy: policy([audit]),
  });
  assert.deepEqual(r.quorum.observed.sequence, 1);
  const unnamed = r.witnesses.find(w => w.id === 'somebody.else');
  assert.equal(unnamed?.accepted, false);
  assert.match(String(unnamed?.detail), /policy/);
  // Present, reported, counted for nothing. Dropping it would hide evidence a
  // reader with a different policy could use.
});

// ── Row 30 — INT-02, our key absent entirely ─────────────────────────────────

test('row 30 / INT-02: a pack anchored only to third parties verifies', async () => {
  const tsa = timeWitness('tsa.example');
  const ots = {
    id: 'bitcoin',
    adapter: {
      id: 'bitcoin', proof_type: /** @type {const} */ ('opentimestamps'),
      establishes: ['existence'], tier: /** @type {const} */ ('anchor'),
      async submit() {
        return {
          type: /** @type {const} */ ('opentimestamps'), issuer: 'bitcoin',
          covers: /** @type {const} */ ('note_digest'), proof: 'AAAA',
        };
      },
    },
  };
  const { root, vkey } = await evidence({ witnesses: [tsa, ots] });
  const r = await verifyStore(root, {
    collector: 'host-1', vkey,
    policy: {
      quorum: 1,
      witnesses: [
        { id: 'tsa.example', establishes: ['time'] },
        { id: 'bitcoin', establishes: ['existence'] },
      ],
    },
  });
  // Our own key is nowhere in this policy. INT-02 is the requirement that this
  // still works: a verifier that only accepted witnesses we operate would make
  // independence impossible to demonstrate.
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.deepEqual(r.witnesses.map(w => w.id).sort(), ['bitcoin', 'tsa.example']);
  assert.deepEqual(r.quorum.observed, { sequence: 0, time: 1, existence: 1 });
});

// ── WITNESS_SHORT, WITNESS_MISSING, WITNESS_MISMATCH ─────────────────────────

test('WITNESS_SHORT: fewer countersignatures than the policy requires', async () => {
  const a = await sequenceWitness('audit.internal');
  const b = await sequenceWitness('audit.secondary');
  const { root, vkey } = await evidence({ witnesses: [a] });
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([a, b], 2) });
  assert.ok(r.findings.some(f => f.code === 'WITNESS_SHORT'));
  assert.equal(r.checks.find(c => c.name === 'WITNESS')?.verdict, 'fail');
});

test('WITNESS_MISSING: a policy witness with no proof in the pack, and what absence means', async () => {
  const a = await sequenceWitness('audit.internal');
  const b = await sequenceWitness('audit.secondary');
  const { root, vkey } = await evidence({ witnesses: [a] });
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([a, b], 1) });
  const f = r.findings.find(x => x.code === 'WITNESS_MISSING');
  assert.ok(f, JSON.stringify(r.findings.map(x => x.code)));
  // FR-66 — absence is consistent with several innocent causes and one guilty
  // one, and nothing in the pack distinguishes them. The finding must say so
  // rather than implying the receipt was removed.
  assert.match(f.detail, /pending|unavailable|roll-up|removed/);
  assert.equal(f.verdict, 'inconclusive');
});

test('WITNESS_MISMATCH: the witness signed a different root', async () => {
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey, store } = await evidence({ witnesses: [audit] });
  // The operator rewrote the log and re-signed the note, but the witness's
  // line is over the note the witness actually saw. This is the strongest
  // finding available: they could not forge the countersignature.
  const s2 = new Store(root, 'host-1');
  const env = JSON.parse(String(s2.readCheckpointEnvelope(1)));
  const other = await evidence({ records: 6 });
  const forged = JSON.parse(String(new Store(other.root, 'host-1').readCheckpointEnvelope(1)));
  env.note = forged.note;
  const { noteDigest } = await import('@splitstick/core/envelope');
  env.note_digest = noteDigest(env.note);
  s2.writeCheckpointEnvelope(1, env);
  s2.close();

  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([audit]) });
  assert.ok(r.findings.some(f => f.code === 'WITNESS_MISMATCH'),
    JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.verdict, 'fail');
});

test('a countersignature over a note that is not this checkpoint is not quietly accepted', async () => {
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey } = await evidence({ witnesses: [audit] });
  const s2 = new Store(root, 'host-1');
  const env = JSON.parse(String(s2.readCheckpointEnvelope(1)));
  // A valid line by the right witness — over different bytes.
  const elsewhere = await evidence({ records: 7, witnesses: [audit] });
  const otherEnv = JSON.parse(String(new Store(elsewhere.root, 'host-1').readCheckpointEnvelope(1)));
  env.countersignatures = otherEnv.countersignatures;
  s2.writeCheckpointEnvelope(1, env);
  s2.close();
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([audit]) });
  assert.ok(r.findings.some(f => f.code === 'WITNESS_MISMATCH'));
});

// ── Rows 32, 33 — truncation, with and without sequence state ────────────────

test('row 32: truncation is DETECTED when a sequence witness holds a later root', async () => {
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey } = await evidence({ records: 6, witnesses: [audit] });
  const chainPath = join(root, 'chain', 'host-1.jsonl');
  const ls = readFileSync(chainPath, 'utf8').trim().split('\n');
  writeFileSync(chainPath, ls.slice(0, 4).join('\n') + '\n');
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([audit]) });
  // The countersigned checkpoint commits to 6; the log now holds 4. The
  // DETECTION is the finding — and the report must carry no affirmative claim
  // at all once a check has failed, which is the project's own rule and the
  // reason this assertion is on `findings` and on the ABSENCE of `can`.
  assert.equal(r.verdict, 'fail');
  const f = r.findings.find(x => x.code === 'SIZE_REGRESSED' || x.code === 'TREE_MISMATCH');
  assert.ok(f, JSON.stringify(r.findings.map(x => x.code)));
  assert.match(f.detail, /6|4/);
  assert.deepEqual(r.capability.can, []);
  assert.ok(r.capability.cannot.some(s => /contradicts itself/.test(s)));
  // And the witness that makes this detectable is still reported as accepted:
  // its countersignature over the height is what the operator cannot un-sign.
  assert.equal(r.witnesses.find(w => w.id === 'audit.internal')?.accepted, true);
  assert.equal(r.quorum.observed.sequence, 1);
});

test('row 32: before truncation, the same evidence DOES claim truncation is detectable', async () => {
  // The positive half. Without this, the test above would pass on a report
  // that never makes the claim under any circumstances.
  const audit = await sequenceWitness('audit.internal');
  const { root, vkey } = await evidence({ records: 6, witnesses: [audit] });
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([audit]) });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.ok(r.capability.can.some(s => /truncation below record_seq 6 is detectable/.test(s)),
    JSON.stringify(r.capability.can, null, 1));
});

test('row 33: with time-only witnesses, truncation above the last checkpoint stays undetected and is said to be', async () => {
  const tsa = timeWitness('tsa.example');
  const { root, vkey } = await evidence({ records: 4, witnesses: [tsa] });
  const r = await verifyStore(root, { collector: 'host-1', vkey, policy: policy([tsa]) });
  assert.equal(r.summary.failed, 0);
  assert.ok(r.capability.cannot.some(s => /sequence state/i.test(s) && /truncation/i.test(s)),
    JSON.stringify(r.capability.cannot, null, 1));
});
