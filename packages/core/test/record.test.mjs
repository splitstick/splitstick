import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../src/jcs.mjs';
import { RECORD_KINDS, validateRecord, RecordError, leafPaths } from '../src/record.mjs';

const base = () => ({
  v: 1, collector: 'host-1', run: 'r-1', record_seq: 1, source_seq: 1,
  ts: '2026-10-11T10:00:00.000Z', kind: 'tool_call', tool: 'transfer_funds',
  agent: { cid: 'sha256:aaaa' },
  args: { cid: 'sha256:bbbb', bytes: 61 },
  result: { cid: 'sha256:cccc', bytes: 54, ok: true },
  approval: null, consequential: true,
  outcome: 'ok', attempt: 1, correlation: 'c-0001',
});

// DES-01 / FR-59 — the canonicalised subject carries no chain metadata.
test('FR-59: no chain field may appear in the record', () => {
  for (const f of ['leaf', 'prev', 'head', 'salt']) {
    assert.throws(() => validateRecord({ ...base(), [f]: 'x' }), RecordError, `${f} must be rejected`);
  }
});

// DES-01 — the enum is closed, and padding is in it (round-7 finding).
test('the kind enum is closed and includes every kind the design defines', () => {
  assert.deepEqual([...RECORD_KINDS].sort(),
    ['approval', 'gap', 'gap_unknown', 'heartbeat', 'padding', 'policy', 'tool_call'].sort());
  assert.throws(() => validateRecord({ ...base(), kind: 'something_new' }), RecordError);
});

// PRIV-02 / FR-35 — no payload bytes in the record, ever, not even short ones.
test('PRIV-02: args and result must be commitments, never inline values', () => {
  assert.throws(() => validateRecord({ ...base(), args: { amount: 2000000 } }), RecordError);
  assert.throws(() => validateRecord({ ...base(), result: 'OK: transferred EUR 2000000' }), RecordError);
});

// FR-62 — retries are records, not overwrites; source_seq counts attempts.
test('FR-62: outcome, attempt and correlation are required on an action', () => {
  for (const f of ['outcome', 'attempt', 'correlation']) {
    const r = base(); delete r[f];
    assert.throws(() => validateRecord(r), RecordError, `${f} is required`);
  }
  assert.throws(() => validateRecord({ ...base(), outcome: 'maybe' }), RecordError);
});

test('FR-56: non-action kinds carry source_seq null, never a repeated value', () => {
  const hb = { v: 1, collector: 'host-1', run: null, record_seq: 2, source_seq: null,
    ts: '2026-10-11T10:00:05.000Z', kind: 'heartbeat', build: 'sha256:dddd',
    suite: 'SS1', policy: 'sha256:eeee', heartbeat_interval: '5s',
    counts: { tool_call: 1 } };
  assert.doesNotThrow(() => validateRecord(hb));
  assert.throws(() => validateRecord({ ...hb, source_seq: 5 }), RecordError);
});

test('FR-69: a padding record has a nonce, no payload fields and null source_seq', () => {
  const pad = { v: 1, collector: 'host-1', run: null, record_seq: 3, source_seq: null,
    ts: '2026-10-11T10:00:06.000Z', kind: 'padding', pad: 'f'.repeat(32) };
  assert.doesNotThrow(() => validateRecord(pad));
  assert.throws(() => validateRecord({ ...pad, tool: 'x' }), RecordError);
  assert.throws(() => validateRecord({ ...pad, pad: 'short' }), RecordError);
});

test('gap carries an exact span; gap_unknown carries an interval and never a span', () => {
  const g = { v: 1, collector: 'host-1', run: null, record_seq: 4, source_seq: null,
    ts: '2026-10-11T10:00:07.000Z', kind: 'gap',
    from_source_seq: 10, to_source_seq: 15, reason: 'queue_lost_on_disk_full' };
  assert.doesNotThrow(() => validateRecord(g));
  const gu = { v: 1, collector: 'host-1', run: null, record_seq: 5, source_seq: null,
    ts: '2026-10-11T10:00:08.000Z', kind: 'gap_unknown',
    from_ts: '2026-10-11T09:59:00.000Z', to_ts: '2026-10-11T10:00:08.000Z',
    last_checkpoint_source_seq: 9 };
  assert.doesNotThrow(() => validateRecord(gu));
  assert.throws(() => validateRecord({ ...gu, from_source_seq: 10, to_source_seq: 15 }), RecordError,
    'gap_unknown must never carry a span');
});

// NFR-07 — an unknown version fails closed rather than being partially read.
test('NFR-07: an unsupported version is rejected, never skipped', () => {
  assert.throws(() => validateRecord({ ...base(), v: 2 }), RecordError);
});

// FR-52 — every field at every depth must reach the digest. The paths are
// derived by walking the object, so a newly added field is covered automatically.
test('FR-52: mutating any field at any depth changes the canonical bytes', () => {
  const r = base();
  const paths = leafPaths(r);
  assert.ok(paths.length >= 15, `expected to walk the whole record, got ${paths.length} paths`);
  const before = canonicalize(r);
  for (const p of paths) {
    const mutated = structuredClone(r);
    let o = mutated;
    for (const k of p.slice(0, -1)) o = o[k];
    const last = p[p.length - 1];
    const v = o[last];
    o[last] = typeof v === 'number' ? v + 1
      : typeof v === 'boolean' ? !v
      : typeof v === 'string' ? v + 'x'
      : v === null ? 0 : 'mutated';
    assert.notEqual(canonicalize(mutated), before, `mutating ${p.join('.')} did not change the digest`);
  }
});

test('FR-52: the nested args commitment is inside the digest', () => {
  const a = base(), b = base();
  b.args = { ...b.args, cid: 'sha256:0000' };
  assert.notEqual(canonicalize(a), canonicalize(b));
});
