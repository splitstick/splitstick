import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { validateRecord, RecordError } from '../src/record.mjs';
import {
  effectivePolicy, policyDigest, policyChanges, PolicyError,
} from '../src/policy.mjs';
import { captureSurface, captureDigest, CaptureError } from '../src/capture.mjs';

const ORIGIN = 'splitstick.dev/host-1';
const tx = (/** @type {string} */ c) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('a'),
  result: Buffer.from('b'), outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: c,
});

const TWO = 'version: 1\nstore: ./s\nquorum: 2\nwitnesses:\n'
  + '  - id: audit-a\n    type: rfc3161\n    url: https://a/\n'
  + '  - id: audit-b\n    type: rfc3161\n    url: https://b/\n';
const ONE = 'version: 1\nstore: ./s\nquorum: 1\nwitnesses:\n'
  + '  - id: audit-a\n    type: rfc3161\n    url: https://a/\n';

/** @param {string} root @param {string} cfg @param {import('../src/signer.mjs').Signer} signer */
function open_(root, cfg, signer) {
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig(cfg, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  return { store, c };
}

const kinds = (/** @type {Store} */ s) => s.readChain().map(e => e.record.kind);
const records = (/** @type {Store} */ s) => s.readChain().map(e => e.record);

// ── FR-23, SEC-12 ───────────────────────────────────────────────────────────

test('SEC-12: weakening the witness set leaves the weakening IN FRONT of what follows', async () => {
  // The downgrade attack is to weaken the policy and then tamper. The defence
  // is that the weakening cannot be done quietly — so the ordering is the
  // whole point: the policy event has to be earlier in the chain than the
  // first record written under the weaker policy, not alongside it and not
  // after it.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-'));
  const signer = await generateDevSigner(ORIGIN);

  let { store, c } = open_(root, TWO, signer);
  c.heartbeat();                       // attests the strong policy
  c.action(tx('c-1'));
  store.close();

  ({ store, c } = open_(root, ONE, signer));
  c.action(tx('c-2'));                 // the first write under the weak policy
  store.close();

  const s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'tool_call', 'policy', 'tool_call']);
  const rs = records(s);
  const policy = rs[2];
  assert.equal(policy?.kind, 'policy');
  assert.equal(policy?.policy_subject, 'effective');
  // Strictly before the record written under the new policy.
  assert.ok(Number(policy?.record_seq) < Number(rs[3]?.record_seq));
  // And it moved from exactly what the earlier heartbeat attested.
  assert.equal(policy?.previous_policy, rs[0]?.policy);
  s.close();
});

test('SEC-12: the downgrade is legible, not merely detectable', async () => {
  // DES-09 specifies the record as two digests and calls the result "a record
  // of the weakening". Two opaque digests are not that: they make the CHANGE
  // detectable without making its DIRECTION identifiable, and a reader holding
  // only them cannot see that the quorum fell from two to one — which is the
  // specific thing SEC-12 is named for. The document the chain commits to is
  // what closes that, and the commitment is what makes the document
  // trustworthy: only one document hashes to the recorded digest, so the
  // operator cannot produce a stronger policy than the one they ran.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-legible-'));
  const signer = await generateDevSigner(ORIGIN);
  let { store, c } = open_(root, TWO, signer);
  c.heartbeat();
  store.close();
  ({ store, c } = open_(root, ONE, signer));
  c.action(tx('c-1'));
  store.close();

  const s = new Store(root, 'host-1');
  const policy = records(s).find(r => r.kind === 'policy');
  const before = /** @type {any} */ (s.readPolicyDocument(String(policy?.previous_policy)));
  const after = /** @type {any} */ (s.readPolicyDocument(String(policy?.next_policy)));
  assert.notEqual(before, null, 'the policy in force when the heartbeat was written is held');
  assert.notEqual(after, null);

  const changes = policyChanges(before, after);
  assert.deepEqual(changes.find(x => x.field === 'quorum'), { field: 'quorum', before: 2, after: 1 });
  assert.deepEqual(changes.find(x => x.field === 'witnesses_removed'), {
    field: 'witnesses_removed', before: ['audit-b (rfc3161/anchor)'], after: null,
  });
  s.close();
});

test('a policy document that does not hash to the name it is filed under is not returned', async () => {
  // The filename is a claim; recomputing is what makes it a commitment.
  // Returning a substituted document would let a policy the chain never
  // committed to be read as the one it did — the whole attack, carried out on
  // the file beside the chain instead of the chain.
  const { writeFileSync, readdirSync } = await import('node:fs');
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-sub-'));
  const signer = await generateDevSigner(ORIGIN);
  const { store, c } = open_(root, TWO, signer);
  c.heartbeat();
  const digest = c.policyDigest;
  store.close();

  const s = new Store(root, 'host-1');
  assert.notEqual(s.readPolicyDocument(digest), null, 'held before substitution');
  const file = readdirSync(s.policyDir)[0];
  writeFileSync(join(s.policyDir, String(file)), JSON.stringify({ quorum: 1 }));
  assert.equal(s.readPolicyDocument(digest), null,
    'a substituted document is not held, rather than being held and wrong');
  s.close();
});

test('FR-23: reopening with an unchanged policy records nothing', async () => {
  // FR-23 says record any CHANGE. A restart is not one, and a policy event per
  // restart would bury the events that matter under events that do not.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-same-'));
  const signer = await generateDevSigner(ORIGIN);
  for (let i = 0; i < 3; i += 1) {
    const { store, c } = open_(root, TWO, signer);
    c.heartbeat();
    c.action(tx(`c-${i}`));
    store.close();
  }
  const s = new Store(root, 'host-1');
  assert.deepEqual(records(s).filter(r => r.kind === 'policy'), []);
  s.close();
});

test('FR-23: a fresh store records no policy event, because nothing changed', async () => {
  // An earlier version wrote a baseline `policy` record at record_seq 1 of
  // every store. It worked, cost a record in every log, and shifted the
  // sequence of 76 existing tests. The heartbeat already commits to the policy
  // in force continuously, which is strictly better than a baseline event: a
  // reader can tell which policy ANY window ran under rather than
  // reconstructing it from change events.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-fresh-'));
  const signer = await generateDevSigner(ORIGIN);
  const { store, c } = open_(root, TWO, signer);
  const hb = c.heartbeat();
  c.action(tx('c-1'));
  store.close();
  const s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'tool_call']);
  assert.equal(hb.record.policy, c.policyDigest, 'and the heartbeat is the baseline');
  s.close();
});

test('two policy changes in one window both appear, in order', async () => {
  // Collapsing them to the latest would hide the interval the weaker policy
  // was live, which is the interval an operator would choose to act in.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-two-'));
  const signer = await generateDevSigner(ORIGIN);
  const MID = 'version: 1\nstore: ./s\nquorum: 1\nwitnesses:\n'
    + '  - id: audit-a\n    type: rfc3161\n    url: https://a/\n'
    + '  - id: audit-b\n    type: rfc3161\n    url: https://b/\n';
  for (const cfg of [TWO, MID, ONE]) {
    const { store, c } = open_(root, cfg, signer);
    c.heartbeat();
    c.action(tx(`c-${cfg.length}`));
    store.close();
  }
  const s = new Store(root, 'host-1');
  const pols = records(s).filter(r => r.kind === 'policy');
  assert.equal(pols.length, 2);
  // Each links to the one before: a chain of policies, not two unrelated events.
  assert.equal(pols[1]?.previous_policy, pols[0]?.next_policy);
  const first = policyChanges(
    /** @type {any} */ (s.readPolicyDocument(String(pols[0]?.previous_policy))),
    /** @type {any} */ (s.readPolicyDocument(String(pols[0]?.next_policy))),
  );
  assert.deepEqual(first.map(x => x.field), ['quorum'], 'the quorum fell first');
  const second = policyChanges(
    /** @type {any} */ (s.readPolicyDocument(String(pols[1]?.previous_policy))),
    /** @type {any} */ (s.readPolicyDocument(String(pols[1]?.next_policy))),
  );
  assert.deepEqual(second.map(x => x.field), ['witnesses_removed'], 'then the witness went');
  s.close();
});

test('a practice-statement version is not read as an effective-policy change', async () => {
  // Both use the `policy` record kind, and `previous_policy`/`next_policy`
  // alone never said which policy. The collector read a practice-statement
  // version as an attestation of its own effective policy, found it did not
  // match, and emitted a spurious change event — two digests compared that
  // were not about the same subject. Two tests caught it.
  const root = mkdtempSync(join(tmpdir(), 'ss-pol-subject-'));
  const signer = await generateDevSigner(ORIGIN);
  const { store, c } = open_(root, TWO, signer);
  c.heartbeat();
  c.policy({
    previous: `sha256:${'1'.repeat(64)}`,
    next: `sha256:${'2'.repeat(64)}`,
    subject: 'practice-statement',
  });
  store.close();

  const { store: s2, c: c2 } = open_(root, TWO, signer);
  c2.action(tx('c-1'));
  s2.close();
  const s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'policy', 'tool_call'],
    'no spurious effective-policy event follows the practice-statement one');
  s.close();
});

test('an unknown policy_subject is refused, and an absent one counts as neither', () => {
  const base = {
    v: 1, collector: 'host-1', run: null, record_seq: 1, source_seq: null,
    ts: '2026-10-12T10:00:00.000Z', kind: 'policy',
    previous_policy: `sha256:${'a'.repeat(64)}`, next_policy: `sha256:${'b'.repeat(64)}`,
  };
  assert.doesNotThrow(() => validateRecord(base), 'absent is valid: records predate the field');
  for (const s of ['effective', 'practice-statement']) {
    assert.doesNotThrow(() => validateRecord({ ...base, policy_subject: s }));
  }
  for (const s of ['Effective', 'wps', '', null, 1]) {
    assert.throws(() => validateRecord({ ...base, policy_subject: s }), RecordError,
      `subject ${JSON.stringify(s)}`);
  }
});

// ── FR-64, and the limits pinned by tests ───────────────────────────────────

test('FR-64: a declared upstream changes the attested digest and emits a policy record', async () => {
  // The paired half of the next test. This one must pass for that one to mean
  // anything: a test asserting a bypass produces NO signal would pass against
  // a collector with no attestation at all, so the mechanism has to be shown
  // live over the same store.
  const root = mkdtempSync(join(tmpdir(), 'ss-cap-'));
  const signer = await generateDevSigner(ORIGIN);
  const WITH = `${TWO}capture:\n  upstreams:\n    - https://api.example/v1\n`;
  const MORE = `${TWO}capture:\n  upstreams:\n    - https://api.example/v1\n    - https://api.other/v1\n`;

  let { store, c } = open_(root, WITH, signer);
  const first = c.heartbeat();
  store.close();
  ({ store, c } = open_(root, MORE, signer));
  const second = c.heartbeat();
  store.close();

  assert.notEqual(first.record.policy, second.record.policy,
    'declaring another upstream moves the attested digest');
  const s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'policy', 'heartbeat']);
  const pol = records(s).find(r => r.kind === 'policy');
  const changes = policyChanges(
    /** @type {any} */ (s.readPolicyDocument(String(pol?.previous_policy))),
    /** @type {any} */ (s.readPolicyDocument(String(pol?.next_policy))),
  );
  assert.deepEqual(changes.map(x => x.field), ['capture.upstreams']);
  s.close();
});

test('FR-64: a path created OUTSIDE the collector produces no signal, and that is the claim', async () => {
  // The limit, pinned by a test rather than by prose. An operator can stand up
  // an entirely separate execution path; this collector goes on reporting an
  // unchanged digest and heartbeating normally, and nothing diverges, because
  // nothing inside Splitstick observes the new path. FR-64 is provenance of a
  // self-report, not independent observation.
  //
  // THE PAIRING IS THE TEST. An assertion that nothing is signalled passes
  // against a function that does nothing, so the same store must also show the
  // mechanism firing for a DECLARED change. Without that half this test would
  // pass against a deleted implementation.
  const root = mkdtempSync(join(tmpdir(), 'ss-cap-bypass-'));
  const signer = await generateDevSigner(ORIGIN);
  const CFG = `${TWO}capture:\n  upstreams:\n    - https://api.example/v1\n`;

  const { store, c } = open_(root, CFG, signer);
  const before = c.heartbeat();
  // Whatever happens outside the collector happens here. Nothing is reported
  // to it, which is exactly the point: there is nothing to report to.
  const after = c.heartbeat();
  store.close();

  assert.equal(before.record.policy, after.record.policy,
    'the attested surface is unchanged, because the collector was not reconfigured');
  let s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'heartbeat'], 'and no policy event is emitted');
  s.close();

  // The live half: the same store, the same collector, a DECLARED change.
  const { store: s2, c: c2 } = open_(root, `${CFG}  interfaces:\n    - 127.0.0.1:8080\n`, signer);
  c2.heartbeat();
  s2.close();
  s = new Store(root, 'host-1');
  assert.deepEqual(kinds(s), ['heartbeat', 'heartbeat', 'policy', 'heartbeat'],
    'so the silence above was a real silence and not an absent mechanism');
  s.close();
});

// ── The digest must not move when nothing moved ─────────────────────────────

test('neither digest depends on declaration order, and duplicates are refused', () => {
  const base = {
    quorum: 2, anchor_interval_ms: 10_000, rollup_interval_ms: 60_000,
    heartbeat_interval_ms: 5_000,
    witnesses: [{ id: 'b', type: 'rfc3161' }, { id: 'a', type: 'rfc3161' }],
  };
  const reordered = { ...base, witnesses: [...base.witnesses].reverse() };
  assert.equal(
    policyDigest(effectivePolicy(/** @type {any} */ (base))),
    policyDigest(effectivePolicy(/** @type {any} */ (reordered))),
    'a digest that moved when nothing moved is an alarm that teaches people to ignore alarms',
  );
  assert.equal(
    captureDigest(captureSurface({ ...base, capture: { upstreams: ['y', 'x'] } })),
    captureDigest(captureSurface({ ...base, capture: { upstreams: ['x', 'y'] } })),
  );
  assert.throws(() => captureSurface({ ...base, capture: { upstreams: ['x', 'x'] } }), CaptureError,
    'two different declarations must not produce one digest');
  assert.throws(() => captureSurface({ ...base, capture: { upstream: ['x'] } }), CaptureError,
    'a misspelled key would attest to a narrower surface than was written');
  assert.throws(() => effectivePolicy(/** @type {any} */ ({
    ...base, witnesses: [{ id: 'a', type: 't' }, { id: 'a', type: 't' }],
  })), PolicyError, 'one party submitting twice is not a quorum');
});

test('M4 review 4: one change to the anchor interval is reported once, not twice', async () => {
  // The capture surface carries anchor_interval_ms because it is part of what
  // is attested, and it is also compared at the top level — so a single change
  // appeared in both places and read as two changes, in a list an auditor
  // counts.
  const base = {
    quorum: 1, anchor_interval_ms: 10_000, rollup_interval_ms: 60_000,
    heartbeat_interval_ms: 5_000, witnesses: [{ id: 'a', type: 'rfc3161' }],
  };
  const changes = policyChanges(
    effectivePolicy(/** @type {any} */ (base)),
    effectivePolicy(/** @type {any} */ ({ ...base, anchor_interval_ms: 20_000 })),
  );
  assert.deepEqual(changes, [{ field: 'anchor_interval_ms', before: 10_000, after: 20_000 }]);

  // The heartbeat interval lives ONLY in the capture surface, so it must still
  // be reported from there — the fix must not have silenced it.
  const hb = policyChanges(
    effectivePolicy(/** @type {any} */ (base)),
    effectivePolicy(/** @type {any} */ ({ ...base, heartbeat_interval_ms: 60_000 })),
  );
  assert.deepEqual(hb.map(x => x.field), ['capture.heartbeat_interval_ms']);
});
