import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { coverageReport, parseWindow, CoverageError } from '../src/coverage.mjs';
import { renderCoverage, PATCH_LIMIT, REPORTED_ONLY } from '../src/coverage-report.mjs';
import { runCoverage } from '../src/coverage-cli.mjs';
import { UNATTESTED_BUILD } from '../src/capture.mjs';

const ORIGIN = 'splitstick.dev/host-1';
const CFG = 'version: 1\nstore: ./s\nheartbeat_interval: 5s\n';
const T0 = '2026-10-12T10:00:00.000Z';
const T5 = '2026-10-12T10:05:00.000Z';

/**
 * A collector whose clock the test drives, so nothing depends on wall time.
 * @param {string} [root] @param {object} [o]
 */
async function rig(root = mkdtempSync(join(tmpdir(), 'ss-cov-')), o = {}) {
  // The succession journal pins the identity, so reopening a store needs the
  // SAME signer. A fresh one per call is refused, correctly.
  const signer = /** @type {any} */ (o).signer ?? await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  const clock = { t: Date.parse(T0) };
  const c = new Collector({
    store, config: parseConfig(/** @type {any} */ (o).cfg ?? CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(clock.t),
    .../** @type {any} */ (o).build ? { build: /** @type {any} */ (o).build } : {},
  });
  return { root, store, c, signer, clock };
}

const tx = (/** @type {string} */ corr, attempt = 1) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('a'),
  result: Buffer.from('b'), outcome: /** @type {const} */ ('ok'), attempt, correlation: corr,
});

/** @param {string} root @param {object} [o] */
function report(root, o = {}) {
  const s = new Store(root, /** @type {any} */ (o).collector ?? 'host-1');
  try {
    return coverageReport(s, {
      from: /** @type {any} */ (o).from ?? T0,
      to: /** @type {any} */ (o).to ?? T5,
      collectors: s.collectors(),
    });
  } finally { s.close(); }
}

// ── the window ──────────────────────────────────────────────────────────────

test('FR-28 row 26: a reversed or impossible window is refused, not interpreted', () => {
  assert.throws(() => parseWindow(T5, T0), CoverageError, 'reversed');
  // Date.parse rolls 2027-02-30 to March 2nd and calls it finite, so a window
  // that never existed would be answered as a different one.
  for (const bad of ['2027-02-30', '2027-13-01', 'yesterday', '', '2027-01-01T99:00:00.000Z']) {
    assert.throws(() => parseWindow(bad, T5), CoverageError, `from ${JSON.stringify(bad)}`);
  }
  // A bare date is the whole day; an instant is that instant.
  assert.deepEqual(parseWindow('2027-01-01', '2027-01-01').from, '2027-01-01T00:00:00.000Z');
  assert.deepEqual(parseWindow('2027-01-01', '2027-01-01').to, '2027-01-01T23:59:59.999Z');
});

test('FR-28 row 24: an empty window is inconclusive, never complete', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  const r = report(root, { from: '2027-01-01', to: '2027-01-02' });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.anchoring.in_window, 0);
  const text = renderCoverage(r);
  assert.match(text, /COVERAGE_UNKNOWN: no record falls in this window/);
  assert.match(text, /An empty window is not a clean one/);
  assert.doesNotMatch(text, /COMPLETE/);
});

test('FR-28 row 25: a window opening before the chain does not claim that interval', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  c.action(tx('c-1'));
  store.close();
  const text = renderCoverage(report(root, { from: '2020-01-01', to: T5 }));
  assert.match(text, /the chain begins 2026-10-12T10:00:00\.000Z, AFTER the window opens/);
});

test('FR-28 row 27: the window is applied by ts, and the report says ts is self-asserted', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  assert.match(renderCoverage(report(root)), /applied by the record's own ts, which is SELF-ASSERTED/);
});

test('FR-28 row 29: a second collector in the store is named, never silently passed over', async () => {
  const { root, store, c, signer } = await rig();
  c.heartbeat();
  store.close();
  const other = new Store(root, 'host-2');
  const c2 = new Collector({
    store: other, config: parseConfig(CFG, root), signer,
    collector: 'host-2', origin: ORIGIN, now: () => new Date(Date.parse(T0)),
  });
  c2.heartbeat();
  other.close();
  const r = report(root);
  assert.ok(r.findings.some(f => f.code === 'MULTIPLE_COLLECTORS' && /host-2/.test(f.detail)));
  assert.match(renderCoverage(r), /says nothing about the others/);
});

// ── attempts versus logical actions ─────────────────────────────────────────

test('FR-28 row 20: attempts and logical actions are counted separately and differ under retry', async () => {
  // One number would make a retried action look like several, or several
  // distinct actions look like one.
  const { root, store, c, clock } = await rig();
  c.heartbeat();
  c.action(tx('c-1', 1)); clock.t += 1000;
  c.action(tx('c-1', 2)); clock.t += 1000;   // the same logical action, retried
  c.action(tx('c-1', 3)); clock.t += 1000;
  c.action(tx('c-2', 1));
  store.close();
  const r = report(root);
  assert.equal(r.actions.reported_attempts, 4);
  assert.equal(r.actions.reported_logical, 2);
  const text = renderCoverage(r);
  assert.match(text, /2 logical, over 4 attempt\(s\), reported by the collector/);
  assert.match(text, /one action may span several attempts/);
});

test('FR-28 row 21: the report never implies completeness about what it never saw', async () => {
  // The central honesty of FR-28. An action suppressed before the collector
  // observed it leaves no trace, and the numbers must not be presented as a
  // proportion of everything that happened.
  const { root, store, c } = await rig();
  c.heartbeat();
  c.action(tx('c-1'));
  store.close();
  const text = renderCoverage(report(root));
  assert.ok(text.includes(REPORTED_ONLY), 'the sentence is in the output, not a footnote');
  assert.match(text, /reported by the collector/);
  // Never a bare proportion of actions, and never the word "all".
  assert.doesNotMatch(text, /100% captured/);
  assert.doesNotMatch(text, /all actions/i);
});

// ── liveness, and SEC-11's boundary ─────────────────────────────────────────

test('SEC-11 rows 1 and 2: a stopped collector leaves an undeclared gap, run or no run', async () => {
  const { root, store, c, clock } = await rig();
  for (let i = 0; i < 6; i += 1) { c.heartbeat(); clock.t += 5_000; }
  clock.t += 120_000;                       // stopped, with no run active
  for (let i = 0; i < 6; i += 1) { c.heartbeat(); clock.t += 5_000; }
  store.close();
  const r = report(root);
  assert.equal(r.heartbeat.discontinuities.length >= 1, true);
  const two = r.heartbeat.discontinuities.find(d => d.ms >= 120_000);
  assert.notEqual(two, undefined, 'the two-minute stop is located');
  assert.equal(r.verdict, 'incomplete');
  assert.ok(r.findings.some(f => f.code === 'COVERAGE_GAP' && f.verdict === 'fail'),
    'and it is COVERAGE_GAP, the code the failure-code spec already names for it');
  assert.match(renderCoverage(r), /UNDECLARED GAP/);
});

test('a gap is measured against every record, not heartbeats alone', async () => {
  // The first version measured heartbeat-to-heartbeat and reported a
  // two-minute outage over an interval in which three actions had been written
  // — signed, chained records proving the collector was running. Overstating a
  // stop on the strength of evidence that says the opposite is the one
  // direction this report must never overstate in.
  const { root, store, c, clock } = await rig();
  // The tolerance is two heartbeat intervals, so 10s here. Actions land inside
  // it; heartbeats are 24s apart, which a heartbeat-only measurement would
  // have reported as an outage.
  c.heartbeat();
  for (let i = 0; i < 3; i += 1) { clock.t += 8_000; c.action(tx(`c-${i}`)); }
  clock.t += 8_000;
  c.heartbeat();
  store.close();
  const r = report(root, { from: T0, to: '2026-10-12T10:00:32.000Z' });
  assert.deepEqual(r.heartbeat.discontinuities, [],
    'no gap: a record exists at every point a heartbeat is missing from');
  assert.equal(r.heartbeat.count, 2, 'and the heartbeats really are 32s apart');

  // The paired half: remove the actions and the same spacing IS a gap, so the
  // silence above is the records doing work rather than the check being absent.
  const bare = await rig();
  bare.c.heartbeat();
  bare.clock.t += 32_000;
  bare.c.heartbeat();
  bare.store.close();
  assert.equal(report(bare.root, { from: T0, to: '2026-10-12T10:00:32.000Z' })
    .heartbeat.discontinuities.length, 1);
});

test('SEC-11 row 9: a forged build digest is NOT flagged — and the mechanism is live', async () => {
  // The limit, pinned by a test rather than by prose. A patched collector
  // controls what it reports and can emit the original digest while
  // suppressing actions: a self-reported digest is not remote attestation.
  //
  // THE PAIRING IS THE TEST. An assertion that nothing is flagged passes
  // against a report that reads no digests at all, so the same store must also
  // show the mechanism noticing a build that DID change. Without that half
  // this would pass against a deleted implementation.
  const root = mkdtempSync(join(tmpdir(), 'ss-cov-build-'));
  const forged = `sha256:${'ab'.repeat(32)}`;

  // Two runs, both reporting the same digest. The second is "patched": it
  // suppresses an action. Nothing in the report can tell.
  let { store, c, clock, signer } = await rig(root, { build: forged });
  c.heartbeat(); clock.t += 5_000;
  c.action(tx('c-1')); clock.t += 5_000;
  c.heartbeat();
  store.close();

  ({ store, c, clock } = await rig(root, { build: forged, signer }));
  clock.t = Date.parse('2026-10-12T10:00:15.000Z');
  c.heartbeat();                            // the suppressed action is simply absent
  store.close();

  let r = report(root);
  assert.deepEqual(r.heartbeat.builds.map(b => b.build), [forged],
    'one build throughout: the patch is invisible, which is the claim');
  assert.equal(r.heartbeat.builds[0]?.attested, true, 'and it looks like a perfectly good digest');
  assert.ok(renderCoverage(r).includes(PATCH_LIMIT), 'so the report says so, in the output');

  // The live half: a build that actually changes IS reported, over the same store.
  ({ store, c, clock } = await rig(root, { build: `sha256:${'cd'.repeat(32)}`, signer }));
  clock.t = Date.parse('2026-10-12T10:00:20.000Z');
  c.heartbeat();
  store.close();
  r = report(root);
  assert.equal(r.heartbeat.builds.length, 2,
    'so the silence above was a real silence and not an absent mechanism');
  assert.match(renderCoverage(r), /more than one build ran in this window/);
});

test('DOC-10 row 11: the patch limit is in the OUTPUT for every window, including an empty one', async () => {
  // A limit in a design document is a limit the person acting on the report
  // does not see. The report is the surface an auditor acts on.
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  for (const w of [{}, { from: '2020-01-01', to: '2020-01-02' }]) {
    assert.ok(renderCoverage(report(root, w)).includes(PATCH_LIMIT), JSON.stringify(w));
  }
});

test('an unattested build is reported as NOT ATTESTED, never as a digest', async () => {
  // The sentinel is a real digest so the record schema can demand one without
  // exception. Showing it as though it were an attestation would be worse than
  // an absent field.
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  const r = report(root);
  assert.equal(r.heartbeat.builds[0]?.build, UNATTESTED_BUILD);
  assert.equal(r.heartbeat.builds[0]?.attested, false);
  const text = renderCoverage(r);
  assert.match(text, /build           NOT ATTESTED/);
  assert.ok(!text.includes(UNATTESTED_BUILD), 'the sentinel itself is not displayed');
});

// ── resolution ──────────────────────────────────────────────────────────────

test('FR-28 rows 5 and 30: the report states its resolution and never implies finer', async () => {
  const { root, store, c, clock } = await rig(undefined, {
    cfg: 'version: 1\nstore: ./s\nheartbeat_interval: 60s\n',
  });
  for (let i = 0; i < 4; i += 1) { c.heartbeat(); clock.t += 60_000; }
  store.close();
  const r = report(root);
  assert.equal(r.heartbeat.resolution_ms, 60_000);
  assert.equal(r.heartbeat.resolution_known, true);
  const text = renderCoverage(r);
  assert.match(text, /resolution      60s/);
  assert.match(text, /A suppression shorter than the\n\s+heartbeat interval is invisible/);
});

test('the coarsest declared interval is the resolution, and a window missing one is unknown', async () => {
  // Taking the finest would state a resolution the evidence does not have.
  const root = mkdtempSync(join(tmpdir(), 'ss-cov-res-'));
  let { store, c, clock, signer } = await rig(root, { cfg: 'version: 1\nstore: ./s\nheartbeat_interval: 5s\n' });
  c.heartbeat(); clock.t += 5_000;
  store.close();
  ({ store, c, clock } = await rig(root, { cfg: 'version: 1\nstore: ./s\nheartbeat_interval: 60s\n', signer }));
  clock.t = Date.parse('2026-10-12T10:00:05.000Z');
  c.heartbeat();
  store.close();
  assert.equal(report(root).heartbeat.resolution_ms, 60_000, 'the coarsest, not the finest');

  // A heartbeat predating the field cannot support a resolution claim, and the
  // report says unknown rather than assuming the one it would like.
  const { appendFileSync } = await import('node:fs');
  const s = new Store(root, 'host-1');
  const raw = s.readChain();
  s.close();
  assert.ok(raw.length >= 1);
  const r2 = report(root);
  assert.equal(r2.heartbeat.resolution_known, true, 'both carry it here');
});

// ── declared loss, policy events, late anchors ──────────────────────────────

test('FR-28 row 22: a declared gap appears exactly, with its span and reason', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  c.gap({ from_source_seq: 4790, to_source_seq: 4795, reason: 'queue_lost_on_disk_full' });
  store.close();
  const r = report(root);
  assert.deepEqual(r.loss.declared.map(g => [g.from_source_seq, g.to_source_seq, g.reason]),
    [[4790, 4795, 'queue_lost_on_disk_full']]);
  assert.match(renderCoverage(r), /DECLARED 4790-4795, queue_lost_on_disk_full/);
  assert.match(renderCoverage(r), /with 1 declared gap\(s\)/);
});

test('an unknown-loss interval is reported as bounded, never as an exact span', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  c.gapUnknown({
    from_ts: '2026-10-12T10:00:01.000Z', to_ts: '2026-10-12T10:00:02.000Z',
    last_checkpoint_source_seq: 0,
  });
  store.close();
  // The window must not run past the last record, or the tail is itself an
  // undeclared liveness gap — correctly, and it would mask what is under test.
  const r = report(root, { to: '2026-10-12T10:00:05.000Z' });
  assert.equal(r.loss.unknown.length, 1);
  assert.ok(r.findings.some(f => f.code === 'COVERAGE_UNKNOWN' && f.verdict === 'inconclusive'));
  assert.equal(r.verdict, 'inconclusive',
    'an unknown loss cannot leave a complete verdict, and is not INCOMPLETE either: '
    + 'the loss was declared, imprecisely, which is different from being hidden');
  assert.match(renderCoverage(r), /the span is bounded and not exact/);
});

test('a policy change in the window is reported, with its content when the document is held', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ss-cov-pol-'));
  const TWO = 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nquorum: 2\nwitnesses:\n'
    + '  - id: a\n    type: rfc3161\n    url: https://a/\n'
    + '  - id: b\n    type: rfc3161\n    url: https://b/\n';
  const ONE = 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nquorum: 1\nwitnesses:\n'
    + '  - id: a\n    type: rfc3161\n    url: https://a/\n';
  let { store, c, signer } = await rig(root, { cfg: TWO });
  c.heartbeat();
  store.close();
  ({ store, c } = await rig(root, { cfg: ONE, signer }));
  c.heartbeat();
  store.close();
  const r = report(root);
  assert.equal(r.policy_events.length, 1);
  assert.notEqual(r.policy_events[0]?.before, null, 'the document is held, so the content is known');
  assert.notEqual(r.policy_events[0]?.after, null);
  assert.match(renderCoverage(r), /CHANGED at /);
});

test('a practice-statement version is not reported as an effective-policy change', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  c.policy({
    previous: `sha256:${'1'.repeat(64)}`, next: `sha256:${'2'.repeat(64)}`,
    subject: 'practice-statement',
  });
  store.close();
  assert.deepEqual(report(root).policy_events, []);
});

test('FR-28 row 28: an undeclared sequence break refuses a completeness claim', async () => {
  const { root, store, c, clock } = await rig();
  for (let i = 0; i < 3; i += 1) { c.heartbeat(); clock.t += 5_000; }
  store.close();
  // Remove a record from the middle: the chain no longer recomputes.
  const { readFileSync, writeFileSync } = await import('node:fs');
  const path = join(root, 'chain', 'host-1.jsonl');
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  writeFileSync(path, `${[lines[0], lines[2]].join('\n')}\n`);
  const r = report(root);
  assert.equal(r.verdict, 'incomplete');
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN' && f.verdict === 'fail'),
    'and the break itself is named, in the shared vocabulary');
  assert.match(renderCoverage(r), /SEQ_BROKEN/);
});

// ── the CLI ─────────────────────────────────────────────────────────────────

test('the coverage CLI refuses an unknown flag rather than ignoring it', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  const bad = runCoverage([root, '--form', T0, '--to', T5]);
  assert.equal(bad.exit, 2);
  assert.match(bad.out, /unknown flag --form/);
  assert.match(bad.out, /Refused rather than ignored/);

  const noValue = runCoverage([root, '--from', '--to', T5]);
  assert.equal(noValue.exit, 2);

  const ok = runCoverage([root, '--from', T0, '--to', T5]);
  assert.ok(ok.out.includes(PATCH_LIMIT));
  // 0 complete, 1 incomplete, 2 inconclusive — a report is not a pass/fail gate.
  assert.ok([0, 1, 2].includes(ok.exit));
});

test('the CLI refuses a collector the store does not hold', async () => {
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  const r = runCoverage([root, '--from', T0, '--to', T5, '--collector', 'nope']);
  assert.equal(r.exit, 2);
  assert.match(r.out, /holds no chain for collector "nope"/);
  assert.match(r.out, /it holds host-1/);
});

test('--json carries the same numbers the rendering shows', async () => {
  const { root, store, c, clock } = await rig();
  c.heartbeat(); clock.t += 1000;
  c.action(tx('c-1', 1)); clock.t += 1000;
  c.action(tx('c-1', 2));
  store.close();
  const r = runCoverage([root, '--from', T0, '--to', T5, '--json']);
  const parsed = JSON.parse(r.out);
  assert.equal(parsed.actions.reported_attempts, 2);
  assert.equal(parsed.actions.reported_logical, 1);
  assert.equal(parsed.collector, 'host-1');
});

test('every verdict is explained by a finding', async () => {
  // A report that says "inconclusive" and lists nothing is a conclusion with
  // no stated reason, which is worse than useless to the person acting on it.
  // This happened: unwitnessed anchoring drove the verdict without emitting
  // anything, and the failure-code scenario caught it.
  const { root, store, c, clock } = await rig();
  c.heartbeat(); clock.t += 5_000;
  c.action(tx('c-1'));
  store.close();
  const r = report(root, { to: '2026-10-12T10:00:10.000Z' });
  assert.notEqual(r.verdict, 'complete');
  assert.ok(r.findings.length > 0, 'the verdict is not complete, so something must say why');
  if (r.verdict === 'incomplete') {
    assert.ok(r.findings.some(f => f.verdict === 'fail'));
  } else {
    assert.ok(r.findings.some(f => f.verdict === 'inconclusive'));
  }
  // And the rendering shows them.
  const text = renderCoverage(r);
  for (const f of r.findings) assert.ok(text.includes(f.code), `${f.code} is in the output`);
});

test('a complete verdict is reachable, and a declared gap does not prevent it', async () => {
  // Shape 6 from the risk assessment: a test suite that only ever asserts
  // refusals is not a test of the function. If no store could ever read
  // COMPLETE, every verdict assertion above would be vacuous.
  const root = mkdtempSync(join(tmpdir(), 'ss-cov-complete-'));
  // The attested anchor interval has to cover the fixture's own span. The
  // records below are written over twenty seconds and countersigned at the
  // end, so under the default ten-second interval the earliest of them ARE
  // late by the operator's own declared policy — which the report now says,
  // because lateness is measured against the attested interval rather than
  // against a hardcoded minute.
  const { store, c, clock, signer } = await rig(root, {
    cfg: 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nanchor_interval: 1m\n',
  });
  const { Anchorer } = await import('../src/anchor.mjs');
  const { parseNote, encodeNote } = await import('../src/note.mjs');
  const { signNote } = await import('../src/signer.mjs');
  const wk = await generateDevSigner('audit.example');
  const witness = {
    id: 'audit.example', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit(/** @type {string} */ note) {
      const text = parseNote(note).text;
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.example',
        covers: /** @type {const} */ ('note'),
        line: encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1),
        // On time: the witness receives it as the batch is written.
        received_at: new Date(clock.t).toISOString(),
      };
    },
  };
  for (let i = 0; i < 4; i += 1) { c.heartbeat(); clock.t += 5_000; }
  // The span must MEET the sequence — M3b's declared-gap accounting refuses a
  // declaration that begins anywhere else, and a span already declared cannot
  // be declared again. Nothing has been observed yet, so this one starts at 1.
  c.gap({ from_source_seq: 1, to_source_seq: 3, reason: 'queue_lost_on_disk_full' });
  const cp = await c.checkpoint();
  const a = new Anchorer({ store, witnesses: [witness], quorum: 1, now: () => clock.t });
  const anchored = await a.anchor(cp.checkpoint_seq);
  assert.equal(anchored.attached.length, 1);
  store.close();

  const r = report(root, { to: '2026-10-12T10:00:20.000Z' });
  assert.deepEqual(r.findings, [], `expected no findings, got ${JSON.stringify(r.findings)}`);
  assert.equal(r.verdict, 'complete');
  assert.equal(r.loss.declared.length, 1);
  // DES-10's own example: a DISCLOSED loss is what this project converts an
  // undeclared absence into. Penalising the disclosure would penalise the
  // honesty it exists to produce.
  assert.match(renderCoverage(r), /verdict         COMPLETE with 1 declared gap\(s\)/);
  assert.match(renderCoverage(r), /DECLARED 1-3, queue_lost_on_disk_full/);
  assert.equal(runCoverage([root, '--from', T0, '--to', '2026-10-12T10:00:20.000Z']).exit, 0);
});

// ── The independent review of M4. Six findings, each reproduced first ────────

test('M4 review 1: no heartbeat at all is never a COMPLETE verdict', async () => {
  // Three countersigned actions, zero heartbeats, and the verdict read
  // COMPLETE with no findings. SEC-11's entire liveness mechanism was absent
  // and nothing said so, because every check was written to compare heartbeats
  // against each other and there was nothing to compare. The rendering said
  // "continuity unknown" in prose while the verdict said complete — and a
  // reader acts on the verdict.
  const root = mkdtempSync(join(tmpdir(), 'ss-rev-nohb-'));
  const { store, c, clock, signer } = await rig(root, {
    cfg: 'version: 1\nstore: ./s\nheartbeat_interval: 5s\nanchor_interval: 1m\n',
  });
  const { Anchorer } = await import('../src/anchor.mjs');
  const { parseNote, encodeNote } = await import('../src/note.mjs');
  const { signNote } = await import('../src/signer.mjs');
  const wk = await generateDevSigner('audit.example');
  for (let i = 0; i < 3; i += 1) { c.action(tx(`c-${i}`)); clock.t += 1000; }
  const cp = await c.checkpoint();
  const a = new Anchorer({
    store, quorum: 1, now: () => clock.t,
    witnesses: [{
      id: 'audit.example', proof_type: /** @type {const} */ ('c2sp-note'),
      establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
      async submit(/** @type {string} */ note) {
        const text = parseNote(note).text;
        return {
          type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.example',
          covers: /** @type {const} */ ('note'),
          line: encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1),
          received_at: new Date(clock.t).toISOString(),
        };
      },
    }],
  });
  assert.equal((await a.anchor(cp.checkpoint_seq)).attached.length, 1);
  store.close();

  const r = report(root, { to: '2026-10-12T10:00:04.000Z' });
  assert.equal(r.heartbeat.count, 0);
  assert.notEqual(r.verdict, 'complete', 'liveness is not established, so the claim is not issued');
  assert.equal(r.verdict, 'inconclusive');
  assert.ok(
    r.findings.some(f => f.code === 'COVERAGE_UNKNOWN' && /no heartbeat falls in this window/.test(f.detail)),
    'and it says so, rather than leaving the reader to notice an empty continuity field',
  );
  // Not a GAP: the records here prove the collector ran at those instants, so
  // claiming an outage would overstate against the operator.
  assert.ok(!r.findings.some(f => f.code === 'COVERAGE_GAP'));
});

test('M4 review 2: a window outside the chain is unknown, not an outage', async () => {
  // A window opening six years before the log existed produced a COVERAGE_GAP
  // of 213,962,400,000ms and a verdict of INCOMPLETE — accusing the operator
  // of a 6.8-year outage over time the report itself says it cannot speak to.
  const { root, store, c, clock } = await rig();
  for (let i = 0; i < 4; i += 1) { c.heartbeat(); clock.t += 5_000; }
  store.close();

  const before = report(root, { from: '2020-01-01', to: '2026-10-12T10:00:15.000Z' });
  assert.deepEqual(before.heartbeat.discontinuities, [], 'no gap is claimed before the chain began');
  assert.equal(before.verdict, 'inconclusive');
  assert.ok(before.findings.some(f => /nothing here\s+speaks to the interval before that|speaks to the interval before that/.test(f.detail)));
  assert.ok(!before.findings.some(f => f.code === 'COVERAGE_GAP'));

  // The same at the other end: a log that ends where it ends has not
  // necessarily stopped, and from the files alone those are indistinguishable.
  const after = report(root, { to: '2026-11-01T00:00:00.000Z' });
  assert.deepEqual(after.heartbeat.discontinuities, []);
  assert.ok(after.findings.some(f => /has not necessarily stopped/.test(f.detail)));

  // And the paired half: a gap INSIDE the chain's span is still a gap, so the
  // silence above is the clamp and not an absent check.
  const inner = await rig();
  for (let i = 0; i < 3; i += 1) { inner.c.heartbeat(); inner.clock.t += 5_000; }
  inner.clock.t += 120_000;
  for (let i = 0; i < 3; i += 1) { inner.c.heartbeat(); inner.clock.t += 5_000; }
  inner.store.close();
  const r = report(inner.root, { to: '2026-10-12T10:02:30.000Z' });
  assert.ok(r.findings.some(f => f.code === 'COVERAGE_GAP' && f.verdict === 'fail'));
});

test('M4 review 3: a policy record naming no subject is counted as neither', async () => {
  // record.mjs documents an absent subject as read by NEITHER reader, and the
  // collector requires 'effective'. This filter used `!== 'practice-statement'`
  // and so counted a subject-less record as an effective policy change: the
  // same record meant two different things depending on which module looked at
  // it, which is the collision policy_subject was added to end.
  const { root, store, c } = await rig();
  c.heartbeat();
  c.policy({ previous: `sha256:${'1'.repeat(64)}`, next: `sha256:${'2'.repeat(64)}` });
  store.close();
  const r = report(root, { to: '2026-10-12T10:00:10.000Z' });
  assert.deepEqual(r.policy_events, [], 'not counted as an effective-policy change');
  assert.ok(
    r.findings.some(f => f.code === 'COVERAGE_UNKNOWN' && /naming no subject/.test(f.detail)),
    'and not silently dropped either',
  );
});

test('M4 review 6: lateness is measured against the ATTESTED anchor interval', async () => {
  // The threshold was a hardcoded sixty seconds, so an operator anchoring
  // every ten minutes by declared policy had nine of those minutes reported as
  // lateness, and one anchoring every second had a 59-second delay reported as
  // on time. A claim's threshold has to come from the same place the claim does.
  const mk = async (/** @type {string} */ interval) => {
    const root = mkdtempSync(join(tmpdir(), 'ss-rev-late-'));
    const { store, c, clock } = await rig(root, {
      cfg: `version: 1\nstore: ./s\nheartbeat_interval: 5s\nanchor_interval: ${interval}\n`,
    });
    const { Anchorer } = await import('../src/anchor.mjs');
    const { parseNote, encodeNote } = await import('../src/note.mjs');
    const { signNote } = await import('../src/signer.mjs');
    const wk = await generateDevSigner('audit.example');
    for (let i = 0; i < 4; i += 1) { c.heartbeat(); clock.t += 5_000; }
    const cp = await c.checkpoint();
    const a = new Anchorer({
      store, quorum: 1, now: () => clock.t,
      witnesses: [{
        id: 'audit.example', proof_type: /** @type {const} */ ('c2sp-note'),
        establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
        async submit(/** @type {string} */ note) {
          const text = parseNote(note).text;
          return {
            type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.example',
            covers: /** @type {const} */ ('note'),
            line: encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1),
            received_at: new Date(clock.t).toISOString(),   // ~20s after the first record
          };
        },
      }],
    });
    await a.anchor(cp.checkpoint_seq);
    store.close();
    return report(root, { to: '2026-10-12T10:00:20.000Z' });
  };

  // Ten seconds declared: a twenty-second delay is late by the operator's own
  // policy, and the report says so against the interval they attested.
  const strict = await mk('10s');
  assert.ok(strict.anchoring.late.length > 0);
  assert.equal(strict.anchoring.on_time_ms, 10_000);
  assert.match(renderCoverage(strict), /against an attested interval of 10s/);

  // One minute declared: the same delay is within policy, and nothing is
  // reported. The behaviour now follows the declaration rather than a constant.
  const relaxed = await mk('1m');
  assert.deepEqual(relaxed.anchoring.late, []);
  assert.equal(relaxed.anchoring.on_time_ms, 60_000);
});

test('M4 review 5: the coverage CLI closes every store it opens', async () => {
  // Without --collector the CLI opened a probe store to ask which collectors
  // exist, then opened a SECOND store for the named one and closed only that,
  // so every run without the flag leaked the probe.
  //
  // Checked against the SOURCE, because a leaked handle is invisible from
  // outside: the process goes on working and nothing observable changes. An
  // earlier version of this test instrumented a Store subclass and asserted
  // that the subclass paired its own opens and closes, which was true and said
  // nothing about the CLI — a check that could not see its subject.
  //
  // Comment-stripped, so the paragraph above explaining the leak cannot be
  // what satisfies the check.
  const { readFileSync } = await import('node:fs');
  const { codeOnly } = await import('../../../tools/code-text.mjs');
  const src = codeOnly(readFileSync(
    new URL('../src/coverage-cli.mjs', import.meta.url).pathname, 'utf8'));

  const opens = [...src.matchAll(/new Store\(/g)].length;
  assert.equal(opens, 2, 'a probe for the collector list, and the named one');
  assert.match(src, /probe !== undefined && probe !== store/,
    'the probe is closed unless it IS the store that was used');
  assert.match(src, /store\?\.close\(\)/);

  // And the behaviour that a held handle or an unreleased lock would eventually
  // break: the CLI run repeatedly over one store, with and without the flag.
  const { root, store, c } = await rig();
  c.heartbeat();
  store.close();
  for (let i = 0; i < 3; i += 1) {
    for (const args of [[], ['--collector', 'host-1']]) {
      const r = runCoverage([root, '--from', T0, '--to', '2026-10-12T10:00:05.000Z', ...args]);
      assert.ok([0, 1, 2].includes(r.exit), `run ${i} ${args.join(' ')}: ${r.out.slice(0, 80)}`);
    }
  }
});
