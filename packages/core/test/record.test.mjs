import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../src/jcs.mjs';
import { RECORD_KINDS, validateRecord, RecordError, leafPaths } from '../src/record.mjs';

const base = () => ({
  v: 1, collector: 'host-1', run: 'r-1', record_seq: 1, source_seq: 1,
  ts: '2026-10-11T10:00:00.000Z', kind: 'tool_call', tool: 'transfer_funds',
  agent: { cid: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
  args: { cid: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', bytes: 61 },
  result: { cid: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', bytes: 54, ok: true },
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
    ['approval', 'custody', 'discontinuity', 'gap', 'gap_unknown', 'heartbeat', 'padding',
      'policy', 'tool_call'].sort());
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
    ts: '2026-10-11T10:00:05.000Z', kind: 'heartbeat',
    build: 'sha256:' + 'dd'.repeat(32), policy: 'sha256:' + 'ee'.repeat(32) };
  assert.doesNotThrow(() => validateRecord(hb));
  assert.throws(() => validateRecord({ ...hb, source_seq: 5 }), RecordError);
  // This fixture used to carry suite, heartbeat_interval and counts, which
  // nothing defines — `suite` belongs to the checkpoint (DES-16) and coverage
  // counts arrive with DES-10 in M4. Extending the schema is now an explicit
  // act rather than something a writer can do by accident.
  assert.throws(() => validateRecord({ ...hb, suite: 'SS1' }), RecordError);
  assert.throws(() => validateRecord({ ...hb, counts: { tool_call: 1 } }), RecordError);
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
  b.args = { ...b.args, cid: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
  assert.notEqual(canonicalize(a), canonicalize(b));
});

// Found in review: `policy` had no required fields at all, so SEC-12's whole
// mechanism — a chained record carrying the digest of the previous effective
// policy and of the new one — was optional. A policy record with neither is
// not evidence of a change; it is a note saying something happened.
test('SEC-12: a policy record must carry both policy digests', () => {
  const base = {
    v: 1, collector: 'host-1', run: null, record_seq: 1, source_seq: null,
    ts: '2026-10-11T10:00:00.000Z', kind: 'policy',
  };
  assert.throws(() => validateRecord(base), RecordError, 'neither digest');
  assert.throws(() => validateRecord({ ...base, previous_policy: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }), RecordError, 'no next');
  assert.throws(() => validateRecord({ ...base, next_policy: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }), RecordError, 'no previous');
  assert.throws(() => validateRecord({ ...base, previous_policy: 'aa', next_policy: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }),
    RecordError, 'not a digest');
  assert.doesNotThrow(() => validateRecord({
    ...base, previous_policy: 'sha256:' + 'aa'.repeat(32), next_policy: 'sha256:' + 'bb'.repeat(32),
  }));
});

// Found in review: gap_unknown accepted from_ts "yesterday" and to_ts 42. The
// interval is the entire content of the record — it is what the operator is
// declaring they cannot characterise — so an unparseable one makes the record
// meaningless rather than merely untidy.
test('FR-60: a gap_unknown interval must be real timestamps in order', () => {
  const base = {
    v: 1, collector: 'host-1', run: null, record_seq: 1, source_seq: null,
    ts: '2026-10-11T10:00:00.000Z', kind: 'gap_unknown', last_checkpoint_source_seq: 4,
  };
  assert.throws(() => validateRecord({ ...base, from_ts: 'yesterday', to_ts: 42 }), RecordError);
  assert.throws(() => validateRecord({ ...base, from_ts: '2026-10-11T10:00:00.000Z', to_ts: 42 }), RecordError);
  assert.throws(() => validateRecord({
    ...base, from_ts: '2026-10-11T11:00:00.000Z', to_ts: '2026-10-11T10:00:00.000Z',
  }), RecordError, 'an interval that ends before it starts');
  assert.doesNotThrow(() => validateRecord({
    ...base, from_ts: '2026-10-11T10:00:00.000Z', to_ts: '2026-10-11T10:05:00.000Z',
  }));
});

test('a gap span must be ordered too', () => {
  const base = {
    v: 1, collector: 'host-1', run: null, record_seq: 1, source_seq: null,
    ts: '2026-10-11T10:00:00.000Z', kind: 'gap',
  };
  assert.throws(() => validateRecord({ ...base, from_source_seq: 9, to_source_seq: 5 }), RecordError);
  assert.doesNotThrow(() => validateRecord({ ...base, from_source_seq: 5, to_source_seq: 9 }));
});

// Found in review: `run` was neither required nor type-checked, although DES-13
// lists it among the fields retained forever. An action with no run cannot be
// attributed to anything.
test('FR-56: run is required and is a string or null, never absent', () => {
  const r = base();
  delete r.run;
  assert.throws(() => validateRecord(r), RecordError, 'run must be present');
  assert.throws(() => validateRecord({ ...base(), run: 42 }), RecordError);
  assert.throws(() => validateRecord({ ...base(), run: '' }), RecordError);
  assert.doesNotThrow(() => validateRecord({ ...base(), run: null }));
  assert.doesNotThrow(() => validateRecord({ ...base(), run: 'r-1' }));
});

/**
 * Review finding P1-5. The validator restricted a few fields and checked the
 * commitments it knew about, but it had no exhaustive allowed-field set, so a
 * record could carry any extra field it liked — including plaintext.
 *
 * PRIV-02 claims the record format structurally excludes payloads. With an
 * open schema that claim rested on the collector being the only writer, which
 * is exactly the assumption a tamper-evidence product may not make: the schema
 * and the verifier are reusable, and a pack arrives from somewhere else.
 */
test('PRIV-02: an undeclared field is refused on every kind', () => {
  const beat = {
    v: 1, collector: 'host-1', run: null, record_seq: 1, source_seq: null,
    ts: '2026-10-11T10:00:00.000Z', kind: 'heartbeat',
    build: 'sha256:' + 'aa'.repeat(32), policy: 'sha256:' + 'bb'.repeat(32),
  };
  assert.doesNotThrow(() => validateRecord(beat));
  assert.throws(() => validateRecord({ ...beat, iban: 'DE89370400440532013000' }),
    /not permitted|unknown field/i, 'a heartbeat must not carry plaintext');
  assert.throws(() => validateRecord({ ...beat, note: 'anything at all' }), RecordError);

  // And on an action, where the temptation to add "just one more field" lives.
  assert.throws(() => validateRecord({ ...base(), amount: 2000000 }), RecordError);
  assert.throws(() => validateRecord({ ...base(), raw_args: '{"amount":2000000}' }), RecordError);
});

test('PRIV-02: a field belonging to another kind is refused, not ignored', () => {
  assert.throws(() => validateRecord({ ...base(), pad: 'a'.repeat(32) }), RecordError,
    'pad belongs to a padding record');
  assert.throws(() => validateRecord({ ...base(), from_source_seq: 1, to_source_seq: 2 }), RecordError,
    'a span belongs to a gap record');
});

test('a commitment must be a full-length SHA-256 digest', () => {
  // A four-character "digest" is not a commitment to anything: it has 16 bits
  // of collision resistance, and the whole substitution argument rests on the
  // cid moving when the bytes move.
  for (const bad of ['sha256:' + 'aa'.repeat(2), 'sha256:' + 'aa'.repeat(16),
                     'sha256:' + 'AA'.repeat(32), 'sha1:' + 'aa'.repeat(20), 'aa'.repeat(32)]) {
    assert.throws(() => validateRecord({ ...base(), args: { cid: bad, bytes: 1 } }),
      RecordError, bad);
  }
  assert.doesNotThrow(() => validateRecord({ ...base(), args: { cid: 'sha256:' + 'ab'.repeat(32), bytes: 1 } }));
});

test('nested commitment fields are allowlisted too', () => {
  const withApproval = (approval) => validateRecord({ ...base(), approval });
  const cid = 'sha256:' + 'cd'.repeat(32);
  assert.doesNotThrow(() => withApproval({ decision: 'approve', reviewer: { cid } }));
  assert.throws(() => withApproval({ decision: 'approve', reviewer: { cid }, email: 'ops@example.com' }),
    RecordError, 'an undeclared field inside approval');
  assert.throws(() => withApproval({ decision: 'approve', reviewer: { cid, name: 'ops' } }),
    RecordError, 'an undeclared field inside a commitment');
});
