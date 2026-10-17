import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  witnessesFromConfig, describeWitnessSet, defaultWitnessWarning,
  WitnessConfigError, WITNESS_TYPES, TIME_DISCIPLINE, DEFAULT_CALENDARS,
} from '../src/index.mjs';

const DEFAULT_CONFIG = readFileSync(
  new URL('../../../design/default-config.yaml', import.meta.url), 'utf8');

test('FR-48: the shipped default is a TSA plus an OpenTimestamps roll-up', () => {
  // Read from the canonical file, so this cannot drift from what ships.
  assert.match(DEFAULT_CONFIG, /type: rfc3161/);
  assert.match(DEFAULT_CONFIG, /type: opentimestamps, tier: rollup/);
  // Rekor is commented out, and the comment says why.
  assert.match(DEFAULT_CONFIG, /#.*type: rekor.*opt-in/);
  assert.match(DEFAULT_CONFIG, /FR-47/);
  // Neither default is operated by this project, which is the whole point: a
  // default that depends on us is not independence.
  assert.ok(!/splitstick\.(dev|io|com)/.test(DEFAULT_CONFIG.split('witnesses:')[1] ?? ''));
});

test('FR-48: the default does NOT close truncation, and the warning says so', () => {
  const warnings = defaultWitnessWarning();
  const w = warnings.find(x => /sequence state/.test(x));
  assert.ok(w, JSON.stringify(warnings, null, 1));
  assert.match(w, /NOT closed/);
  assert.match(w, /FR-17|FR-14/);
  // And it says the operator's way out is free, so the warning is actionable
  // rather than a disclaimer.
  assert.match(w, /both free/);
});

test('the built set reports what each class is covered by', () => {
  const set = witnessesFromConfig({
    witnesses: [
      { id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' },
      { id: 'ots', type: 'opentimestamps' },
      { id: 'log', type: 'rekor', url: 'https://rekor.internal.example' },
    ],
  });
  const d = describeWitnessSet(set);
  assert.deepEqual(d.classes.time, ['tsa']);
  assert.deepEqual(d.classes.existence.sort(), ['log', 'ots']);
  assert.deepEqual(d.classes.sequence, []);
  assert.equal(d.closes_truncation, false);
});

test('a set with a stateful witness does close truncation', () => {
  const stateful = {
    id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit() { throw new Error('not called'); },
  };
  const d = describeWitnessSet([stateful]);
  assert.equal(d.closes_truncation, true);
  assert.ok(!d.warnings.some(w => /NOT closed/.test(w)));
});

test('SEC-25: every witness type declares where its time comes from', () => {
  // A report that presented every countersignature as equally authoritative
  // about time would be misleading in the one direction that matters.
  for (const t of WITNESS_TYPES) {
    assert.ok(TIME_DISCIPLINE[t], `${t} declares no time discipline`);
  }
  // And the declarations are honest about their limits.
  assert.match(TIME_DISCIPLINE.opentimestamps, /[Nn]ot a clock at all/);
  assert.match(TIME_DISCIPLINE.rfc3161, /and no better/);

  // EVERY type, built and described — not just `rfc3161`.
  //
  // This test used to build one witness, and it chose the single type whose
  // config name and proof type are the same string. The description looked the
  // discipline up by `proof_type`, so `rekor`, `splitstick` and `tlog-witness`
  // (all `c2sp-note`) resolved to undefined and were described with no time
  // discipline at all — Rekor's entry sat in the table, correct and
  // unreachable, and this assertion passed throughout. A table with an entry
  // for every type is not the same claim as a report that carries one.
  const built = witnessesFromConfig({
    witnesses: [
      { id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' },
      { id: 'ots', type: 'opentimestamps', url: 'https://o.example' },
      { id: 'rek', type: 'rekor', url: 'https://rekor.example', tier: 'rollup' },
      { id: 'tlg', type: 'tlog-witness', url: 'https://w.example' },
    ],
  });
  const d = describeWitnessSet(built);
  for (const w of built) {
    assert.ok(d.time_discipline[w.id],
      `${w.id} (${w.proof_type}) is described with no time discipline, so a reader is not told `
      + 'where its authority about time comes from');
  }
  assert.match(d.time_discipline.tsa, /TSA's own clock/);
  // This asserted /^NOTHING\./ on the stated grounds that "a tlog cosignature
  // has nowhere to carry a time". FR-15 ran the real transparency-dev/witness
  // and established otherwise: a cosignature/v1 signature covers
  // `cosignature/v1`, a `time <unix>` line and the note text, so the witness's
  // observation time is inside the proof. The assertion was holding the prose
  // to a claim the protocol disproves. What it must carry instead is where the
  // time comes from and, just as importantly, what it is not.
  assert.match(d.time_discipline.tlg, /cosignature\/v1/);
  assert.match(d.time_discipline.tlg, /inside the signed message/);
  assert.match(d.time_discipline.tlg, /NOT a qualified timestamp/);

  // `splitstick` is not buildable from config by design, so its declaration is
  // the one that can only be checked in the table. Named here so the gap is
  // deliberate rather than overlooked.
  assert.ok(TIME_DISCIPLINE.splitstick);
  assert.equal(Object.keys(d.time_discipline).length, built.length,
    'a witness was described with no discipline, or one appeared for a witness not in the set');
});

test('SEC-25: a witness type with no declared time discipline cannot be built', () => {
  // The guard that keeps the table and the type list in step. Adding a type to
  // WITNESS_TYPES and forgetting the declaration is how the gap above would
  // come back, and it is caught at construction rather than by a reader
  // noticing the report is missing a line.
  for (const t of WITNESS_TYPES) {
    if (t === 'splitstick') continue;
    assert.ok(/** @type {Record<string, string>} */ (TIME_DISCIPLINE)[t],
      `${t} is buildable and declares no time discipline`);
  }
});

test('SEC-04: a single-witness set is flagged, because one honest witness means one', () => {
  const d = describeWitnessSet(witnessesFromConfig({
    witnesses: [{ id: 'tsa', type: 'rfc3161', url: 'https://tsa.example' }],
  }));
  assert.ok(d.warnings.some(w => /SEC-04/.test(w) && /only while that one is/.test(w)),
    JSON.stringify(d.warnings, null, 1));
});

test('SCOPE-15: no witness at all is supported, and reported as establishing nothing', () => {
  const d = describeWitnessSet([]);
  assert.deepEqual(d.classes.sequence, []);
  assert.ok(d.warnings.some(w => /supported configuration/.test(w)
    && /log you anchor to yourself/.test(w)));
});

test('an unknown witness type is refused, never skipped', () => {
  // A misspelled type that quietly anchors to nothing would leave an operator
  // believing they were anchored, which is worse than a startup error.
  assert.throws(() => witnessesFromConfig({
    witnesses: [{ id: 'x', type: 'rfc-3161', url: 'https://x.example' }],
  }), (/** @type {any} */ e) => e instanceof WitnessConfigError && /silently shrank/.test(e.message));
  assert.throws(() => witnessesFromConfig({ witnesses: [{ id: '', type: 'rfc3161' }] }),
    WitnessConfigError);
});

test('the stateful witness is not built from config, and the error says what to do', () => {
  // It needs a transport the operator chooses and a key they hold; a config
  // file cannot supply either, and pretending otherwise would produce an
  // adapter that fails at the first submission.
  assert.throws(() => witnessesFromConfig({
    witnesses: [{ id: 'audit', type: 'splitstick', url: 'https://w.internal' }],
  }), (/** @type {any} */ e) => /witness-self/.test(e.message));
});

test('the default calendars are the project ones, named in one changeable place', () => {
  assert.ok(DEFAULT_CALENDARS.every(u => /^https:\/\/[ab]\.pool\.opentimestamps\.org$/.test(u)));
  const set = witnessesFromConfig({ witnesses: [{ id: 'ots', type: 'opentimestamps' }] });
  assert.equal(set[0].tier, 'rollup');
});

test('OPS-05, FR-48: the shipped default discloses its egress, not only its capability gap', () => {
  // M7 inventory row 6. defaultWitnessWarning() disclosed that classes 4 and 5
  // stay open and said nothing about the default reaching two public services.
  // That egress is FR-48 working as intended — a default independent of us on
  // day one — but an operator who has not read the config learns it from
  // traffic, and "has not read the documentation" is the condition a default
  // exists to serve.
  const w = defaultWitnessWarning();
  assert.ok(w.length >= 2, 'the default carries only one warning, so one of them was dropped');

  const egress = w.find(x => /ANCHORS OUTWARD/.test(x));
  assert.ok(egress, 'the shipped default no longer discloses that it reaches outward');
  // What it reaches, named — "some third parties" is not a disclosure.
  assert.match(egress, /RFC 3161/);
  assert.match(egress, /OpenTimestamps/);
  // What it carries, so the disclosure is not read as worse than it is.
  assert.match(egress, /no payload \(PRIV-01\)/);
  // And the way out, because a disclosure with no remedy is a warning label.
  assert.match(egress, /docs\/self-hosted-witness\.md/);

  // The capability gap is still there: the new disclosure must be additive.
  assert.ok(w.some(x => /classes 4 \(truncation\) and 5 \(erasure\) are NOT closed/.test(x)),
    'the capability warning was replaced rather than added to');
});

// ── PR #17 review, P2: the same witness said two contradictory things ────────

/**
 * `witnessesFromConfig` gave the tlog adapter `establishes: ['sequence','time']`
 * while `TIME_DISCIPLINE` told operators the same configured witness had
 * NOTHING — one adapter, two statements, both reaching consumers, through
 * `witnessesFromConfig` and `describeWitnessSet` respectively. FR-15 taught the
 * adapter that a cosignature/v1 signature carries a signed timestamp and did
 * not teach the prose beside it.
 *
 * The declaration is now data, and this is what holds the two to each other.
 */
test('every constructible witness type agrees with its declared time capability', async () => {
  const { witnessesFromConfig, CREDITED_WITH_TIME, TIME_DISCIPLINE, WITNESS_TYPES } =
    await import('../src/index.mjs');

  for (const [type, declared] of Object.entries(CREDITED_WITH_TIME)) {
    assert.ok(WITNESS_TYPES.includes(type), `${type} is declared but is not a witness type`);
    const url = (type === 'rfc3161' || type === 'rekor') ? 'https://w.example/' : 'http://w.example/';
    const [a] = witnessesFromConfig({ witnesses: [{ id: 'w.example', type, url }] });
    assert.equal(a?.establishes.includes('time'), declared,
      `${type}: the adapter and CREDITED_WITH_TIME disagree about time`);

    // And the PROSE a consumer reads has to agree with both.
    const prose = TIME_DISCIPLINE[type];
    assert.ok(typeof prose === 'string' && prose.length > 0, `${type} has no time discipline`);
    if (declared) {
      assert.ok(!/^NOTHING|carries no time|not a clock at all/i.test(prose),
        `${type} is credited with time and its discipline denies having one: ${prose.slice(0, 80)}`);
    } else {
      assert.ok(/NOT credited as time|not a clock at all|NOTHING/i.test(prose),
        `${type} is not credited with time and its discipline does not say so: ${prose.slice(0, 80)}`);
    }
  }
});

test('a type with no adapter to check against is left out rather than asserted', async () => {
  const { CREDITED_WITH_TIME, TIME_DISCIPLINE } = await import('../src/index.mjs');
  // `splitstick` cannot be built from config (FR-17), so there is nothing here
  // to verify a capability claim against. Absent, not false.
  assert.ok(!('splitstick' in CREDITED_WITH_TIME));
  assert.ok(typeof TIME_DISCIPLINE.splitstick === 'string',
    'it still owes operators a time-discipline statement');
});

test("the tlog discipline describes the signed timestamp and refuses the qualified reading", async () => {
  const { TIME_DISCIPLINE } = await import('../src/index.mjs');
  const prose = TIME_DISCIPLINE['tlog-witness'];
  assert.match(prose, /cosignature\/v1/, 'it must name the format that carries the time');
  assert.match(prose, /inside the signed message/, 'the time is signed, not metadata beside it');
  assert.match(prose, /NOT a qualified timestamp/, 'a signed time is not a qualified one');
  assert.match(prose, /no eIDAS presumption attaches/);
  assert.match(prose, /never written down as the witness/,
    'our submission clock must never stand in for the witness clock');
});
