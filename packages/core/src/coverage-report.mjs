/**
 * Rendering the coverage report — FR-28, FR-40, DOC-10, SEC-11.
 *
 * Separate from the computation so the numbers can be tested without parsing
 * prose, and so the prose can be tested for the things it must and must not
 * say. Both halves matter: a report that computes honestly and prints
 * misleadingly is a misleading report.
 *
 * The phrasings here are load-bearing and asserted by tests. "18,422 actions"
 * is a claim this system cannot support; "18,422 actions reported by the
 * collector" is the one it can. The difference is the entire product.
 */

/** @param {number|null} ms */
function duration(ms) {
  if (ms === null) return 'unknown';
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}min`;
  return `${(m / 60).toFixed(1)}h`;
}

/**
 * The DOC-10 limit, stated wherever coverage is described.
 *
 * In the OUTPUT and not only in the design documents, because the report is
 * the surface an auditor acts on and a limit they do not see is a limit that
 * does not constrain them. Exported so the claims lint and the tests can
 * assert the exact words rather than something near them.
 */
export const PATCH_LIMIT = 'a collector patched to report a valid build digest while suppressing '
  + 'actions is NOT detectable without remote attestation, which this release does not provide';

/** What "captured" is actually a proportion of — FR-28's sentence, not a footnote. */
export const REPORTED_ONLY = 'every count here is of what the COLLECTOR REPORTED. An action the '
  + 'collector never observed leaves no trace in this evidence and is not missing from these '
  + 'numbers — it was never in them';

/**
 * @param {ReturnType<typeof import('./coverage.mjs').coverageReport>} r
 * @returns {string}
 */
export function renderCoverage(r) {
  const L = [];
  const pct = (/** @type {number|null} */ v) =>
    v === null ? 'unknown' : `${(v * 100).toFixed(2)}%`;

  L.push(`window          ${r.window.from} .. ${r.window.to}`);
  L.push('                applied by the record\'s own ts, which is SELF-ASSERTED: record_seq is');
  L.push('                what the chain establishes, ts is what the collector said the time was');
  if (r.window.chain_first === null) {
    L.push('                this chain carries no dated record at all');
  } else if (Date.parse(r.window.chain_first) > r.window.from_ms) {
    // Row 25 — never claim coverage of time that predates the chain.
    L.push(`                the chain begins ${r.window.chain_first}, AFTER the window opens; nothing`);
    L.push('                here speaks to the interval before that');
  }

  L.push('');
  L.push(`actions         ${r.actions.reported_logical} logical, over `
    + `${r.actions.reported_attempts} attempt(s), reported by the collector`);
  if (r.actions.reported_attempts !== r.actions.reported_logical) {
    L.push('                the two differ because one action may span several attempts');
  }

  L.push('');
  const hb = r.heartbeat;
  L.push(`collector       ${hb.count} heartbeat(s), continuity ${pct(hb.continuity)} of the window`);
  L.push(`resolution      ${duration(hb.resolution_ms)}`
    + `${hb.resolution_known ? '' : ' — NOT established for the whole window'}`);
  L.push('                no claim here is finer than this. A suppression shorter than the');
  L.push('                heartbeat interval is invisible to this report');
  if (!hb.resolution_known && hb.count > 0) {
    L.push('                some heartbeats do not record their own interval, so the resolution');
    L.push('                of this window is not established by the evidence');
  }
  for (const d of hb.discontinuities) {
    L.push(`                UNDECLARED GAP ${d.from} .. ${d.to} (${duration(d.ms)} with no record`);
    L.push('                of any kind, so nothing attests the collector was running)');
  }
  for (const b of hb.builds) {
    L.push(`build           ${b.attested ? b.build : 'NOT ATTESTED'} from ${b.from}`);
  }
  if (hb.builds.length > 1) {
    L.push('                more than one build ran in this window, with the change points above');
  }
  L.push(`                ${PATCH_LIMIT}`);

  L.push('');
  if (hb.policies.length === 0) {
    L.push('policy          no heartbeat in this window attests a policy');
  } else {
    L.push(`policy          ${hb.policies.length} distinct effective polic`
      + `${hb.policies.length === 1 ? 'y' : 'ies'} attested in this window`);
  }
  for (const p of r.policy_events) {
    L.push(`                CHANGED at ${p.ts}`);
    if (p.before === null || p.after === null) {
      L.push('                  the change is recorded; its CONTENT is unestablished, because the');
      L.push('                  policy document the chain commits to is not held here');
    } else {
      L.push('                  (see the stored policy documents for what moved)');
    }
  }

  L.push('');
  const a = r.anchoring;
  L.push(`anchoring       ${a.anchored} of ${a.in_window} record(s) in window fall under a `
    + 'countersigned checkpoint');
  if (a.checkpointed_only > 0) {
    L.push(`                ${a.checkpointed_only} fall under a checkpoint NOBODY countersigned: the`);
    L.push('                operator signed a root committing to them, and nothing independent');
    L.push('                establishes WHEN they were written');
  }
  if (a.unanchored > 0) {
    L.push(`                ${a.unanchored} fall under no checkpoint at all`);
  }
  if (a.on_time_ms === null && a.anchored > 0) {
    L.push('                lateness is NOT asserted: no attested policy document is held here, so');
    L.push('                there is no declared anchor interval to measure a delay against');
  }
  if (a.late.length > 0) {
    // FR-40 — honestly weaker evidence rather than silently absent.
    L.push(`                ${a.late.length} window(s) anchored LATE, max delay `
      + `${duration(a.max_delay_ms)} against an attested interval of `
      + `${duration(a.on_time_ms)} — reported as a coverage gap, because a record`);
    L.push('                anchored that long after the fact was mutable for that long');
    L.push('                the delay rests on the witness\'s own clock, which for a C2SP note is');
    L.push('                carried beside the signature rather than under it');
  }

  L.push('');
  if (r.loss.declared.length === 0 && r.loss.unknown.length === 0) {
    L.push('loss            0 declared');
  }
  for (const g of r.loss.declared) {
    L.push(`loss            DECLARED ${g.from_source_seq}-${g.to_source_seq}`
      + `${g.reason === null ? '' : `, ${g.reason}`} at ${g.ts}`);
  }
  for (const g of r.loss.unknown) {
    L.push(`loss            UNKNOWN interval ${g.from_ts ?? '?'} .. ${g.to_ts ?? '?'} — the`);
    L.push('                observation counter did not survive, so the span is bounded and not exact');
  }

  // Every finding, with the verdict class the shared table assigns it, so a
  // reader meets the same vocabulary here as in a verification report.
  for (const f of r.findings) {
    L.push('');
    L.push(`${f.verdict === 'fail' ? 'FAIL  ' : 'note  '}          ${f.code}: ${f.detail}`);
  }

  L.push('');
  L.push(`verdict         ${r.verdict.toUpperCase()}`
    + `${r.loss.declared.length > 0 ? ` with ${r.loss.declared.length} declared gap(s)` : ''}`);

  L.push('');
  L.push(`                ${REPORTED_ONLY}`);
  return `${L.join('\n')}\n`;
}
