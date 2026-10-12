/**
 * The coverage report — FR-28, FR-40, SEC-11, DOC-10, DES-10.
 *
 * This is the differentiated claim of the whole project. Every comparable tool
 * can tell you that what was logged is unaltered; none can tell you that
 * everything was logged. The reason it is hard is that proving absence is
 * strictly harder than proving presence, and the reason it is dangerous is
 * that this file composes a human-readable assurance out of evidence — the
 * exact shape that produced four separate defects in M3b's 200-line anchoring
 * command, on a surface a fraction of this size.
 *
 * So the rules this module is written under, from docs/risk-assessment.md:
 *
 * EVERY NUMBER NAMES ITS SUBJECT. "18,422 actions" is a lie waiting to be
 * told. It is 18,422 actions THE COLLECTOR REPORTED, and the phrasing is not
 * softened into a footnote — it is the sentence.
 *
 * NO CLAIM FINER THAN ITS RESOLUTION. A sixty-second heartbeat cannot speak to
 * a fifty-second suppression. The interval comes from the RECORDS, not from
 * whatever config the reader happens to hold, and where the records do not
 * carry it the resolution is unknown and the report says so rather than
 * assuming one.
 *
 * AN EMPTY WINDOW IS NOT A CLEAN ONE. No records in range is `inconclusive`,
 * never `complete`.
 *
 * THE LIMIT IS IN THE OUTPUT. DOC-10 requires the collector-patch limit stated
 * wherever coverage is described. A limit in a design document is a limit the
 * person acting on the report does not see, so it is in the report, and a test
 * asserts it is there.
 */

import { recomputeChain } from './chain.mjs';
import { parseEnvelope } from './envelope.mjs';
import { isTimestamp } from './record.mjs';
import { verdictFor, finding, validateFindings } from './findings.mjs';
import { UNATTESTED_BUILD } from './capture.mjs';

export class CoverageError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'CoverageError'; }
}

/** Kinds that are an agent action the collector observed. */
const ACTION_KINDS = Object.freeze(['tool_call', 'approval']);

/**
 * The window a report was asked for.
 *
 * Refused rather than coerced: a reversed range is a mistake, and silently
 * swapping the bounds would answer a question nobody asked. `Date.parse` is
 * not the check — it rolls `2027-02-30` over to March 2nd and reports it
 * finite, so a range that never existed would be answered as a different one.
 *
 * @param {string} from @param {string} to
 * @returns {{ from: string, to: string, from_ms: number, to_ms: number }}
 */
export function parseWindow(from, to) {
  /** @param {string} v @param {string} which */
  const one = (v, which) => {
    if (typeof v !== 'string' || v.trim() === '') {
      throw new CoverageError(`--${which} is required: a coverage claim is about a stated window`);
    }
    // A bare date means the whole day; an instant means that instant.
    const text = /^\d{4}-\d{2}-\d{2}$/.test(v)
      ? `${v}T${which === 'from' ? '00:00:00.000' : '23:59:59.999'}Z`
      : v;
    if (!isTimestamp(text)) {
      throw new CoverageError(
        `--${which} is ${JSON.stringify(v)}, which is not a date or an RFC 3339 instant. `
        + 'Refused rather than interpreted: a window that does not exist cannot be reported on',
      );
    }
    return text;
  };
  const f = one(from, 'from');
  const t = one(to, 'to');
  const from_ms = Date.parse(f);
  const to_ms = Date.parse(t);
  if (to_ms < from_ms) {
    throw new CoverageError(
      `the window ends (${t}) before it begins (${f}). Refused rather than swapped: the bounds `
      + 'were given in an order, and guessing which was meant answers a different question',
    );
  }
  return { from: f, to: t, from_ms, to_ms };
}

/**
 * Whether a digest is a documented stand-in rather than an attestation.
 * @param {unknown} d
 */
const unattested = d => typeof d !== 'string' || d === UNATTESTED_BUILD
  || !/^sha256:[0-9a-f]{64}$/.test(d);

/**
 * Build the coverage report.
 *
 * @param {import('./store.mjs').Store} store
 * @param {object} o
 * @param {string} o.from @param {string} o.to
 * @param {string[]} [o.collectors] every collector the store holds, for row 29
 */
export function coverageReport(store, o) {
  const window = parseWindow(o.from, o.to);
  const { entries, torn, malformed } = store.readChainDetailed();
  const chain = recomputeChain(entries);

  // DES-12 FINDINGS, in the shared vocabulary, not a parallel set of note
  // codes invented here. The failure-code spec already names what a coverage
  // report can conclude — COVERAGE_GAP, COVERAGE_UNKNOWN, UNDATED_RECORD — and
  // the lint that caught the invention was right to: a second vocabulary means
  // a reader has to learn which tool is talking before they can read a code,
  // and nothing proves the two agree.
  /** @type {import('./findings.mjs').Finding[]} */
  const findings = [];
  if (torn) {
    findings.push(finding('TORN_WRITE', 'inconclusive',
      'the last line of the chain is incomplete, which is what a crash during an append leaves '
      + 'behind; the records before it are reported normally'));
  }
  for (const m of malformed) {
    findings.push(finding('MALFORMED_RECORD', 'fail',
      `chain line ${m.line} is not a readable record and is not at the end of the file: `
      + `${m.reason}`));
  }
  // A store holding several collectors reports on ONE. Picking the first and
  // saying nothing would show a reader one chain while another sat beside it
  // unexamined.
  const others = (o.collectors ?? []).filter(c => c !== store.collector);
  if (others.length > 0) {
    findings.push(finding('MULTIPLE_COLLECTORS', 'inconclusive',
      `this store also holds ${others.join(', ')}; this report is about ${store.collector} only, `
      + 'and says nothing about the others'));
  }

  const all = entries.map(e => e.record);
  const dated = all.filter(r => isTimestamp(r.ts));
  for (const r of all) {
    if (!isTimestamp(r.ts)) {
      findings.push(finding('UNDATED_RECORD', 'inconclusive',
        `record ${r.record_seq} carries no usable ts, so it cannot be placed in a window; it is `
        + 'excluded from the counts and reported here rather than silently dropped',
        { record_seq: Number(r.record_seq) }));
    }
  }

  // The window is applied by `ts`, which is SELF-ASSERTED. record_seq is the
  // order the collector wrote things in and is what the chain establishes; ts
  // is what the collector said the time was. A report that used record_seq
  // would be precise about an interval nobody asked for.
  const inWindow = dated.filter(r => {
    const ms = Date.parse(String(r.ts));
    return ms >= window.from_ms && ms <= window.to_ms;
  });

  const chainFirst = dated.length === 0 ? null : String(dated[0]?.ts);
  const chainLast = dated.length === 0 ? null : String(dated[dated.length - 1]?.ts);

  // ── actions: attempts and logical actions, separately ────────────────────
  //
  // One logical action may span several attempts, so one number would make a
  // retried action look like several — or several distinct actions look like
  // one. `correlation` is what groups attempts; counting rows alone is the
  // attempt count and nothing else.
  const actionRecords = inWindow.filter(r => ACTION_KINDS.includes(String(r.kind)));
  const attempts = actionRecords.length;
  const logical = new Set(actionRecords.map(r => String(r.correlation))).size;

  // ── heartbeat continuity ─────────────────────────────────────────────────
  const beats = inWindow.filter(r => r.kind === 'heartbeat');
  /** @type {number[]} */
  const intervals = [];
  for (const b of beats) {
    const i = b.heartbeat_interval_ms;
    if (Number.isSafeInteger(i) && Number(i) > 0) intervals.push(Number(i));
  }
  // The COARSEST interval any heartbeat in the window declares. A window that
  // ran part of the time at sixty seconds cannot support a claim at five:
  // taking the finest would state a resolution the evidence does not have.
  const resolution_ms = intervals.length === 0 ? null : Math.max(...intervals);
  const resolution_known = intervals.length === beats.length && beats.length > 0;

  /** @type {{ from: string, to: string, ms: number }[]} */
  const discontinuities = [];
  if (resolution_ms !== null && beats.length > 0) {
    // Tolerance of two intervals. One interval is the expected spacing, so
    // flagging at one would report every ordinary jitter as an outage and
    // teach a reader to ignore the field.
    const tolerance = resolution_ms * 2;
    // LIVENESS IS EVIDENCED BY ANY RECORD, not only by a heartbeat.
    //
    // The first version measured the gaps between heartbeats alone, and
    // reported a two-minute outage over an interval in which the collector had
    // written three actions. It was demonstrably running — a record exists,
    // signed and chained, at a moment inside the "outage". Reporting that as a
    // stop overstates the finding in the one direction this report must never
    // overstate: against the operator, on the strength of evidence that says
    // the opposite.
    //
    // The heartbeat remains what makes a QUIET window checkable, which is the
    // whole reason DES-10 has one: a window with no activity and no heartbeat
    // is indistinguishable from a stopped collector. Both are still caught,
    // because a stopped collector writes nothing of either sort.
    const stamps = [...new Set(inWindow.map(r => Date.parse(String(r.ts))))].sort((a, b) => a - b);
    for (let i = 1; i < stamps.length; i += 1) {
      const gap = Number(stamps[i]) - Number(stamps[i - 1]);
      if (gap > tolerance) {
        discontinuities.push({
          from: new Date(Number(stamps[i - 1])).toISOString(),
          to: new Date(Number(stamps[i])).toISOString(),
          ms: gap,
        });
      }
    }
    // The edges count too. A collector stopped before the window opened, or
    // never restarted before it closed, leaves no pair to compare — and that
    // is exactly the window an operator would choose.
    const firstGap = Number(stamps[0]) - window.from_ms;
    if (firstGap > tolerance) {
      discontinuities.push({
        from: window.from, to: new Date(Number(stamps[0])).toISOString(),
        ms: firstGap,
      });
    }
    const lastGap = window.to_ms - Number(stamps[stamps.length - 1]);
    if (lastGap > tolerance) {
      discontinuities.push({
        from: new Date(Number(stamps[stamps.length - 1])).toISOString(), to: window.to,
        ms: lastGap,
      });
    }
    discontinuities.sort((a, b) => Date.parse(a.from) - Date.parse(b.from));
  }
  const span_ms = window.to_ms - window.from_ms;
  const missing_ms = discontinuities.reduce((a, d) => a + d.ms, 0);
  const continuity = beats.length === 0 || span_ms === 0
    ? null
    : Math.max(0, Math.min(1, (span_ms - missing_ms) / span_ms));

  // ── builds and the attested policy ───────────────────────────────────────
  /** @type {{ build: string, attested: boolean, from: string }[]} */
  const builds = [];
  for (const b of beats) {
    const build = String(b.build);
    if (builds.length > 0 && builds[builds.length - 1]?.build === build) continue;
    builds.push({ build, attested: !unattested(build), from: String(b.ts) });
  }
  const policies = [...new Set(beats.map(b => String(b.policy)))];

  // ── declared loss ────────────────────────────────────────────────────────
  const declared = inWindow.filter(r => r.kind === 'gap').map(r => ({
    from_source_seq: Number(r.from_source_seq),
    to_source_seq: Number(r.to_source_seq),
    reason: typeof r.reason === 'string' ? r.reason : null,
    ts: String(r.ts),
  }));
  const unknown = inWindow.filter(r => r.kind === 'gap_unknown').map(r => ({
    from_ts: typeof r.from_ts === 'string' ? r.from_ts : null,
    to_ts: typeof r.to_ts === 'string' ? r.to_ts : null,
    ts: String(r.ts),
  }));

  // ── policy events ────────────────────────────────────────────────────────
  const policyEvents = inWindow
    .filter(r => r.kind === 'policy' && r.policy_subject !== 'practice-statement')
    .map(r => ({
      ts: String(r.ts),
      previous_policy: String(r.previous_policy),
      next_policy: String(r.next_policy),
      subject: typeof r.policy_subject === 'string' ? r.policy_subject : null,
      // Null means the change is visible and its content unestablished, which
      // is honest and is more than a digest pair alone could say.
      before: store.readPolicyDocument(String(r.previous_policy)),
      after: store.readPolicyDocument(String(r.next_policy)),
    }));

  // ── anchoring, and FR-40's late windows ──────────────────────────────────
  const anchoring = anchorCoverage(store, inWindow, window);

  // ── sequence integrity across the window ─────────────────────────────────
  //
  // An undeclared break means the report must not issue a completeness claim
  // across it. This is the one place the report is allowed to be the bearer of
  // bad news about the chain itself: a coverage claim over a chain that does
  // not verify is worth nothing, and issuing it anyway is how a broken log gets
  // a clean bill of health.
  // The severity comes from the FINDINGS TABLE, not from a field on the
  // finding: a ChainFinding carries a code and a detail and no verdict, so
  // reading `f.verdict` compared undefined against 'fail', was false for every
  // finding, and the integrity check could never have fired. The typechecker
  // caught it; nothing in the behaviour would have.
  // The chain's own findings, forwarded with the verdict the shared table
  // assigns. A ChainFinding carries a code and a detail and no verdict, so
  // reading `f.verdict` compared undefined against 'fail', was false for every
  // finding, and the integrity check could never have fired. The typechecker
  // caught that; nothing in the behaviour would have.
  for (const f of chain.findings) {
    findings.push(finding(f.code, verdictFor(f.code), f.detail,
      f.record_seq === undefined ? {} : { record_seq: f.record_seq }));
  }

  // COVERAGE_GAP — a window with no record of any kind and no declaration.
  for (const d of discontinuities) {
    findings.push(finding('COVERAGE_GAP', 'fail',
      `${d.from} .. ${d.to}: ${Math.round(d.ms / 1000)}s with no record of any kind and no `
      + 'declaration, so nothing attests the collector was running'));
  }
  // COVERAGE_UNKNOWN — the chain may be perfectly intact while the collector
  // cannot say what it observed during an interval.
  for (const g of unknown) {
    findings.push(finding('COVERAGE_UNKNOWN', 'inconclusive',
      `an unknown-loss interval ${g.from_ts ?? '?'} .. ${g.to_ts ?? '?'} is declared: the `
      + 'observation counter did not survive, so the span is bounded rather than exact'));
  }
  if (beats.length > 0 && !resolution_known) {
    findings.push(finding('COVERAGE_UNKNOWN', 'inconclusive',
      'not every heartbeat in this window records its own interval, so the resolution of the '
      + 'liveness claim is not established by the evidence'));
  }
  if (inWindow.length === 0) {
    findings.push(finding('COVERAGE_UNKNOWN', 'inconclusive',
      'no record falls in this window. An empty window is not a clean one: this says nothing '
      + 'about whether the collector was running'));
  }
  // EVERY verdict must be explained by a finding. An earlier version let
  // unwitnessed or late anchoring drive the verdict to inconclusive without
  // emitting anything, so a report could say "inconclusive" and list nothing —
  // a conclusion with no stated reason, which is worse than useless to the
  // person acting on it.
  if (anchoring.unwitnessed > 0) {
    findings.push(finding('COVERAGE_UNKNOWN', 'inconclusive',
      `${anchoring.unwitnessed} of ${inWindow.length} record(s) in this window fall under no `
      + 'countersigned checkpoint, so nothing independent establishes WHEN they were written'));
  }
  if (anchoring.late.length > 0) {
    findings.push(finding('COVERAGE_UNKNOWN', 'inconclusive',
      `${anchoring.late.length} window(s) were anchored late, by up to `
      + `${Math.round(anchoring.max_delay_ms / 1000)}s. A record anchored that long after the `
      + 'fact was mutable for that long, which is honestly weaker evidence (FR-40)'));
  }

  /**
   * The three verdicts, and the line between them is a deliberate decision
   * rather than a cascade of ifs.
   *
   * `incomplete` — something is missing or damaged that the operator did NOT
   * declare: an undeclared break in liveness, a chain that does not recompute,
   * a record that was altered. This is the only verdict that says the evidence
   * is worse than it should be.
   *
   * `inconclusive` — nothing is known to be missing, and the evidence cannot
   * support a completeness claim anyway: an empty window, a resolution the
   * records do not establish, an unknown-loss interval whose span is bounded
   * rather than exact, records nothing countersigned, windows anchored late.
   *
   * `complete` — everything the collector reported is chained, the resolution
   * is established, liveness is unbroken and every record falls under a
   * countersigned checkpoint.
   *
   * DECLARED GAPS DO NOT DOWNGRADE IT, and that is DES-10's own example
   * ("COMPLETE with 1 declared gap"). A disclosed loss is the thing this
   * project converts an undeclared absence INTO; treating the disclosure as a
   * failure would penalise the honesty it exists to produce.
   *
   * An earlier version made unwitnessed records `incomplete`, which conflated
   * two different deficiencies: every record being present but nothing
   * establishing WHEN is not the same as records being absent, and saying
   * `incomplete` of the first overstates against the operator.
   * @type {'complete'|'incomplete'|'inconclusive'}
   */
  let verdict;
  if (findings.some(f => f.verdict === 'fail')) {
    verdict = 'incomplete';
  } else if (findings.some(f => f.verdict === 'inconclusive')) {
    verdict = 'inconclusive';
  } else {
    verdict = 'complete';
  }

  return {
    window: { ...window, chain_first: chainFirst, chain_last: chainLast },
    collector: store.collector,
    // Named exactly this, everywhere, because they are not the same number and
    // the difference is the point of FR-28's sentence.
    actions: { reported_attempts: attempts, reported_logical: logical },
    heartbeat: {
      count: beats.length,
      resolution_ms,
      resolution_known,
      continuity,
      discontinuities,
      builds,
      policies,
    },
    loss: { declared, unknown },
    policy_events: policyEvents,
    anchoring,
    verdict,
    findings: validateFindings(findings, 'coverageReport'),
  };
}

/**
 * Which records in the window fall under a checkpoint, and how late it came.
 *
 * FR-40 — a window anchored eleven minutes after the fact had an eleven-minute
 * mutability window, and that is honestly weaker evidence rather than silently
 * absent. Reported as a coverage gap with its delay.
 *
 * @param {import('./store.mjs').Store} store
 * @param {Record<string, unknown>[]} inWindow
 * @param {{ from_ms: number, to_ms: number }} window
 */
function anchorCoverage(store, inWindow, window) {
  /** @type {{ seq: number, tree_size: number, witnessed_at: string|null, issuers: string[] }[]} */
  const checkpoints = [];
  for (const { seq, blob } of store.readCheckpoints()) {
    const env = parseEnvelope(blob);
    if (env.tree_size === null) continue;
    /** @type {string|null} */
    let at = null;
    for (const cs of env.countersignatures) {
      const t = cs.entry?.received_at;
      // The witness's own clock, and it is UNSIGNED for a C2SP note — there is
      // nowhere inside the note to put a time. The verifier labels that; here
      // it is used only to measure a delay, and the report says the basis.
      if (typeof t === 'string' && isTimestamp(t) && (at === null || t < at)) at = t;
    }
    checkpoints.push({
      seq, tree_size: env.tree_size, witnessed_at: at, issuers: [...env.issuers],
    });
  }
  checkpoints.sort((a, b) => a.tree_size - b.tree_size);

  let anchored = 0;
  let checkpointed_only = 0;
  let unanchored = 0;
  /** @type {{ record_seq: number, delay_ms: number, checkpoint_seq: number }[]} */
  const late = [];
  // A batch anchored within one anchor interval is on time. Beyond it, the
  // records sat mutable for the difference, and that is what gets reported.
  const onTime = 60_000;
  for (const r of inWindow) {
    const seq = Number(r.record_seq);
    const cp = checkpoints.find(c => c.tree_size >= seq);
    // Three states, not two. A record under no checkpoint at all and one under
    // a checkpoint nobody countersigned are different: the second has a signed
    // root committing to it, which establishes the operator's own claim about
    // the tree, and only the countersignature establishes WHEN. Collapsing
    // them reported the weaker of the two as if it were the absence of any
    // evidence.
    if (cp === undefined) { unanchored += 1; continue; }
    if (cp.issuers.length === 0) { checkpointed_only += 1; continue; }
    anchored += 1;
    if (cp.witnessed_at === null) continue;
    const delay = Date.parse(cp.witnessed_at) - Date.parse(String(r.ts));
    if (delay > onTime) late.push({ record_seq: seq, delay_ms: delay, checkpoint_seq: cp.seq });
  }
  return {
    anchored,
    checkpointed_only,
    unanchored,
    unwitnessed: checkpointed_only + unanchored,
    late,
    max_delay_ms: late.reduce((a, l) => Math.max(a, l.delay_ms), 0),
    in_window: inWindow.length,
    window_ms: window.to_ms - window.from_ms,
  };
}
