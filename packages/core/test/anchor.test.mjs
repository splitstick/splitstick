import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { signNote } from '../src/signer.mjs';
import { parseNote, encodeNote } from '../src/note.mjs';
import { parseEnvelope } from '../src/envelope.mjs';
import { Anchorer, CAPABILITY_CLASSES, QUEUE_CEILING } from '../src/anchor.mjs';

const ORIGIN = 'splitstick.dev/host-1';
const CFG = 'version: 1\nstore: ./s\n';
const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK ref=TX-77814'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'ss-anchor-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c };
}

/** A witness that signs honestly. */
async function goodWitness(id = 'audit.internal') {
  const key = await generateDevSigner(id);
  /** @type {string[]} */
  const seen = [];
  return {
    key,
    seen,
    adapter: {
      id, proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
      tier: /** @type {const} */ ('anchor'),
      async submit(note) {
        seen.push(note);
        const text = parseNote(note).text;
        return {
          type: /** @type {const} */ ('c2sp-note'), issuer: id, covers: /** @type {const} */ ('note'),
          line: encodeNote(text, [await signNote(text, key)]).trim().split('\n').at(-1),
        };
      },
    },
  };
}

test('a checkpoint lands as an envelope, unwitnessed, before any witness is asked', async () => {
  const { store, c, root } = await fresh();
  c.action(tx());
  const cp = await c.checkpoint();
  // Fail-open is the design (SCOPE-16): the local artefact must exist and be
  // complete whether or not a second party is reachable.
  const files = readdirSync(join(root, 'checkpoints', 'host-1'));
  assert.deepEqual(files, ['1.json']);
  const env = parseEnvelope(readFileSync(join(root, 'checkpoints', 'host-1', '1.json'), 'utf8'));
  assert.equal(env.ok, true);
  assert.equal(env.note, cp.note);
  assert.equal(env.unwitnessed, true);
  store.close();
});

test('anchoring attaches each witness countersignature to the envelope', async () => {
  const { store, c } = await fresh();
  const w = await goodWitness();
  const a = new Anchorer({ store, witnesses: [w.adapter], quorum: 1 });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 1);
  assert.deepEqual(r.failed, []);
  const env = parseEnvelope(store.readCheckpointEnvelope(cp.checkpoint_seq));
  assert.equal(env.unwitnessed, false);
  assert.deepEqual([...env.issuers], ['audit.internal']);
  // The note the witness was handed is the note on disk, byte for byte.
  assert.equal(w.seen[0], cp.note);
  store.close();
});

// ── Row 19 — every witness unreachable ───────────────────────────────────────

test('row 19: with every witness unreachable, collection continues and the checkpoint stands', async () => {
  const { store, c } = await fresh();
  const dead = {
    id: 'dead', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
    tier: /** @type {const} */ ('anchor'),
    async submit() { throw new Error('ECONNREFUSED'); },
  };
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1 });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 0);
  assert.equal(r.failed.length, 1);
  assert.match(r.failed[0].detail, /ECONNREFUSED/);
  // Never block. The collector is still writable and the checkpoint is intact.
  c.action(tx({ correlation: 'c-2' }));
  assert.equal(c.tree_size, 2);
  assert.equal(parseEnvelope(store.readCheckpointEnvelope(cp.checkpoint_seq)).ok, true);
  // And it is queued for a later attempt rather than forgotten.
  assert.deepEqual(a.queued(), [cp.checkpoint_seq]);
  store.close();
});

// ── Rows 20, 22 — a bad countersignature must not be stored ──────────────────

test('row 20: a countersignature that does not verify is discarded with a finding', async () => {
  const { store, c } = await fresh();
  const w = await goodWitness();
  const impostor = await generateDevSigner('audit.internal');
  const liar = {
    ...w.adapter,
    async submit(note) {
      const text = parseNote(note).text;
      // A valid Ed25519 signature — by a key that is not the witness's.
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.internal',
        covers: /** @type {const} */ ('note'),
        line: encodeNote(text, [await signNote(text, impostor)]).trim().split('\n').at(-1),
      };
    },
  };
  const a = new Anchorer({
    store, witnesses: [liar], quorum: 1,
    acceptance: { 'audit.internal': w.key.publicKey },
  });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 0);
  assert.equal(r.failed.length, 1);
  assert.match(r.failed[0].detail, /does not verify/);
  // A bad countersignature must not be stored as though it were good.
  assert.equal(parseEnvelope(store.readCheckpointEnvelope(cp.checkpoint_seq)).unwitnessed, true);
  store.close();
});

test('row 22: a valid signature from the wrong issuer is discarded', async () => {
  const { store, c } = await fresh();
  const w = await goodWitness('audit.internal');
  const other = await goodWitness('somebody.else');
  // The adapter claims to be audit.internal and returns somebody.else's line.
  const confused = {
    ...w.adapter,
    async submit(note) {
      const cs = await other.adapter.submit(note);
      return { ...cs, issuer: 'audit.internal' };
    },
  };
  const a = new Anchorer({
    store, witnesses: [confused], quorum: 1,
    acceptance: { 'audit.internal': w.key.publicKey },
  });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  // An issuer field is a claim; the key is the fact.
  assert.equal(r.attached.length, 0);
  assert.equal(r.failed.length, 1);
  store.close();
});

test('with no acceptance keys configured, a countersignature is attached unverified and said to be', async () => {
  const { store, c } = await fresh();
  const w = await goodWitness();
  const a = new Anchorer({ store, witnesses: [w.adapter], quorum: 1 });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 1);
  // The collector is not the verifier, and refusing to store a proof it cannot
  // check would throw away evidence a reader with the right policy could use.
  // What it must not do is imply it checked.
  assert.equal(r.attached[0].verified, false);
  store.close();
});

// ── Row 21 — a hanging witness ───────────────────────────────────────────────

test('row 21: a witness that hangs is bounded by a timeout and the checkpoint stands', async () => {
  const { store, c } = await fresh();
  let settled = false;
  /** @type {NodeJS.Timeout|undefined} */
  let pending;
  const slow = {
    id: 'slow', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
    tier: /** @type {const} */ ('anchor'),
    async submit() {
      // A real hang. The timer is kept so the test can clear it: an unref'd
      // timer with nothing to resolve it empties the event loop and Node kills
      // the whole run, which is how this test first "passed" by cancelling
      // every test after it.
      await new Promise(r => { pending = setTimeout(r, 5000); });
      settled = true;
      throw new Error('never');
    },
  };
  const a = new Anchorer({ store, witnesses: [slow], quorum: 1, timeout_ms: 25 });
  c.action(tx());
  const cp = await c.checkpoint();
  const started = Date.now();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.ok(Date.now() - started < 2000, 'the timeout must bound the wait, not the witness');
  assert.equal(r.attached.length, 0);
  assert.match(r.failed[0].detail, /timed out/);
  assert.equal(settled, false);
  clearTimeout(pending);
  store.close();
});

// ── Row 23 — the queue is bounded ────────────────────────────────────────────

test('row 23: the unwitnessed queue is bounded and reports what it dropped', async () => {
  const { store, c } = await fresh();
  const dead = {
    id: 'dead', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
    tier: /** @type {const} */ ('anchor'),
    async submit() { throw new Error('down'); },
  };
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1, queue_ceiling: 3 });
  for (let i = 0; i < 6; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    await a.anchor(cp.checkpoint_seq);
  }
  // NFR-01's revision excluded uncontrolled buffering explicitly. A queue that
  // grows without bound is how a transient outage becomes a memory incident.
  assert.equal(a.queued().length, 3);
  // The OLDEST are kept: they are the ones whose unwitnessed window is widest,
  // and the newest will be re-anchored by the next checkpoint anyway.
  assert.deepEqual(a.queued(), [1, 2, 3]);
  assert.equal(a.dropped, 3);
  assert.ok(QUEUE_CEILING > 0);
  store.close();
});

// ── Row 24 — a queued checkpoint is later witnessed, atomically ──────────────

test('row 24: retrying a queued checkpoint updates the envelope in place', async () => {
  const { store, c } = await fresh();
  let up = false;
  const w = await goodWitness();
  const flaky = {
    ...w.adapter,
    async submit(/** @type {string} */ note) {
      if (!up) throw new Error('down');
      return w.adapter.submit(note);
    },
  };
  const a = new Anchorer({ store, witnesses: [flaky], quorum: 1 });
  c.action(tx());
  const cp = await c.checkpoint();
  await a.anchor(cp.checkpoint_seq);
  assert.deepEqual(a.queued(), [cp.checkpoint_seq]);

  up = true;
  const r = await a.flush();
  assert.equal(r.anchored.length, 1);
  assert.deepEqual(a.queued(), []);
  const env = parseEnvelope(store.readCheckpointEnvelope(cp.checkpoint_seq));
  assert.deepEqual([...env.issuers], ['audit.internal']);
  // The note is untouched by the update: only the envelope around it grew.
  assert.equal(env.note, cp.note);
  store.close();
});

test('row 24: a half-written envelope is never readable', async () => {
  const { store, c, root } = await fresh();
  c.action(tx());
  const cp = await c.checkpoint();
  const path = join(root, 'checkpoints', 'host-1', `${cp.checkpoint_seq}.json`);
  const before = readFileSync(path, 'utf8');
  // Writes go through a staging file and a rename, so a reader sees the old
  // envelope or the new one and never a prefix of either.
  const w = await goodWitness();
  const a = new Anchorer({ store, witnesses: [w.adapter], quorum: 1 });
  await a.anchor(cp.checkpoint_seq);
  const after = readFileSync(path, 'utf8');
  assert.notEqual(before, after);
  assert.equal(parseEnvelope(after).ok, true);
  assert.equal(readdirSync(join(root, 'checkpoints', 'host-1')).length, 1,
    'and no staging file is left behind');
  store.close();
});

// ── Quorum, per capability ───────────────────────────────────────────────────

test('quorum is counted per capability class, never as one number', async () => {
  const { store, c } = await fresh();
  const timeOnly = (/** @type {string} */ id) => ({
    id, proof_type: /** @type {const} */ ('rfc3161'), establishes: ['time'],
    tier: /** @type {const} */ ('anchor'),
    async submit() {
      return {
        type: /** @type {const} */ ('rfc3161'), issuer: id,
        covers: /** @type {const} */ ('note_digest'), token: 'AAAA',
      };
    },
  });
  const a = new Anchorer({ store, witnesses: [timeOnly('tsa.a'), timeOnly('tsa.b')], quorum: 2 });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  assert.equal(r.attached.length, 2);
  // Two time-only witnesses buy redundancy of time, not independence of
  // sequence. A single aggregate figure would let an operator look
  // well-witnessed while unable to detect truncation at all.
  assert.deepEqual(r.quorum, { time: 2, sequence: 0, existence: 0 });
  assert.equal(r.quorum_met.time, true);
  assert.equal(r.quorum_met.sequence, false);
  assert.deepEqual([...CAPABILITY_CLASSES], ['sequence', 'time', 'existence']);
  store.close();
});

test('an adapter declaring an unknown capability class is refused at construction', async () => {
  const { store } = await fresh();
  assert.throws(() => new Anchorer({
    store, quorum: 1,
    witnesses: [{
      id: 'x', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['everything'],
      tier: /** @type {const} */ ('anchor'), async submit() { throw new Error('no'); },
    }],
  }), /capability/);
  store.close();
});

test('two adapters with the same id are refused: a quorum of one party is not a quorum', async () => {
  const { store } = await fresh();
  const w = await goodWitness('audit.internal');
  assert.throws(() => new Anchorer({
    store, witnesses: [w.adapter, { ...w.adapter }], quorum: 2,
  }), /more than once/);
  store.close();
});

// ── Tiers — FR-21, FR-22, SCOPE-15 ───────────────────────────────────────────

test('the rollup tier is not asked on every checkpoint', async () => {
  const { store, c } = await fresh();
  const anchor = await goodWitness('audit.internal');
  const rollup = await goodWitness('bitcoin');
  const a = new Anchorer({
    store, quorum: 1,
    witnesses: [anchor.adapter, { ...rollup.adapter, tier: 'rollup' }],
  });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  // FR-21 vs FR-22: the soft tier runs at anchor cadence, the hard tier at the
  // roll-up cadence, because a Bitcoin commitment per 10 seconds is neither
  // affordable nor acceptable use.
  assert.deepEqual(r.attached.map(x => x.issuer), ['audit.internal']);
  assert.equal(rollup.seen.length, 0);
  const rr = await a.rollup(cp.checkpoint_seq);
  assert.deepEqual(rr.attached.map(x => x.issuer), ['bitcoin']);
  store.close();
});

test('SCOPE-15: an empty witness set anchors nothing and says so, rather than failing', async () => {
  const { store, c } = await fresh();
  const a = new Anchorer({ store, witnesses: [], quorum: 1 });
  c.action(tx());
  const cp = await c.checkpoint();
  const r = await a.anchor(cp.checkpoint_seq);
  // The hard anchor must be disableable, and so must every other witness. A
  // configuration with no second party is a supported configuration that
  // establishes less, not an error.
  assert.deepEqual(r.attached, []);
  assert.deepEqual(r.failed, []);
  assert.equal(r.unwitnessed, true);
  assert.deepEqual(a.queued(), [], 'and nothing is queued for witnesses that do not exist');
  store.close();
});
