// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The failure-code vocabulary, frozen in code — the M3a follow-up from M1's
 * retrospective (docs/m1-follow-ups.md).
 *
 * `tools/lint-failure-codes.mjs` checks statically that every code a verifier
 * emits is specified. What made that scan sound was that every emission site
 * was a string literal in a file the scan reads — and it exempted `f.code`,
 * where one layer forwards another's findings. The retrospective recorded that
 * the exemption was safe for a specific reason and would stop being safe "the
 * moment a code arrives from somewhere the scan does not reach", and named M3a
 * as when that happens, because the verifier gains witness, roll-up and
 * coverage codes and more layers to forward them through.
 *
 * It happened on schedule. So the guarantee moves from static to runtime: every
 * finding in this project is constructed through `finding()`, which throws on a
 * code that is not in this list. An unknown code can no longer be printed to a
 * reader as though the project had defined it, and the lint's job narrows to
 * asserting that this list and spec/failure-codes.json agree — a comparison it
 * can make exactly rather than approximately.
 *
 * The list is here rather than read from spec/failure-codes.json at runtime
 * because core ships as a package and the spec file is a repository artefact.
 * The lint is what keeps them from drifting.
 */

/**
 * Every code this project may emit. Adding one here without adding it to
 * spec/failure-codes.json fails the lint, and vice versa.
 */
export const FAILURE_CODES = Object.freeze([
  // M1 — local integrity
  'FORMAT_UNSUPPORTED',
  'MALFORMED_RECORD',
  'TORN_WRITE',
  'SEQ_BROKEN',
  'CHAIN_BROKEN',
  'LEAF_MISMATCH',
  'LEAF_INCONCLUSIVE',
  'CONTENT_MISMATCH',
  'CONTENT_ABSENT',
  'TREE_MISMATCH',
  'SIZE_REGRESSED',
  'CONSISTENCY_BROKEN',
  'UNANCHORED',
  'UNANCHORED_TAIL',
  'OPSIG_INVALID',
  'OPSIG_UNCHECKED',
  'IDENTITY_UNPINNED',
  'SUITE_UNDECLARED',
  'MULTIPLE_COLLECTORS',
  'CHECKPOINTS_UNATTRIBUTED',
  'NO_EVIDENCE',
  // M2 — key custody
  'SUCCESSION_BROKEN',
  'OPSIG_EPOCH_REGRESSED',
  // M3a — anchoring and sequencing
  'ENVELOPE_DIGEST_MISMATCH',
  'ENVELOPE_NOTE_MISMATCH',
  'ENVELOPE_DUPLICATE_ISSUER',
  'WITNESS_SHORT',
  'WITNESS_MISMATCH',
  'WITNESS_MISSING',
  'TRUNCATED_BELOW_DISCLOSED',
  // M3b
  'DISCONTINUITY',
  // M4 — coverage
  'COVERAGE_GAP',
  'COVERAGE_UNKNOWN',
  'UNDATED_RECORD',
  // PRIV-05, PRIV-03 — the erasure residue scan. In the shared vocabulary
  // rather than a second one, because a reader should not have to know which
  // instrument is talking before they can read a code.
  'RESIDUE_UNCLASSIFIED_FIELD',
  'RESIDUE_UNEXPECTED_FIELD',
  'RESIDUE_SALT_RETAINED',
  'RESIDUE_CONTENT_RETAINED',
]);

/** DES-12's three verdicts. There is no fourth, and no absent one. */
export const VERDICTS = Object.freeze(['ok', 'fail', 'inconclusive']);

/**
 * What a reader may conclude from each code — the verdict, in one place.
 *
 * This is here because the verdict was being decided at the call site, twice,
 * and both times wrongly:
 *
 * One forwarding site derived it from the code's NAME, treating anything ending
 * `_INCONCLUSIVE` as inconclusive and everything else as a failure. That is
 * correct today only by luck: `TORN_WRITE` is specified inconclusive and does
 * not end that way, and it reaches a reader through a different path.
 *
 * Another hard-coded `fail` for every envelope finding, which made a duplicated
 * witness retry — a benign event the witness itself treats as idempotent — fail
 * the whole verification. A false accusation, from a product whose only asset
 * is not making them.
 *
 * `tools/lint-failure-codes.mjs` asserts this table and
 * spec/failure-codes.json agree exactly, so the document a reader is pointed at
 * and the behaviour they get cannot drift.
 */
export const DEFAULT_VERDICTS = Object.freeze({
  // M1
  FORMAT_UNSUPPORTED: 'fail',
  MALFORMED_RECORD: 'fail',
  TORN_WRITE: 'inconclusive',
  SEQ_BROKEN: 'fail',
  CHAIN_BROKEN: 'fail',
  LEAF_MISMATCH: 'fail',
  LEAF_INCONCLUSIVE: 'inconclusive',
  CONTENT_MISMATCH: 'fail',
  CONTENT_ABSENT: 'inconclusive',
  TREE_MISMATCH: 'fail',
  SIZE_REGRESSED: 'fail',
  CONSISTENCY_BROKEN: 'fail',
  UNANCHORED: 'inconclusive',
  UNANCHORED_TAIL: 'inconclusive',
  OPSIG_INVALID: 'fail',
  OPSIG_UNCHECKED: 'inconclusive',
  IDENTITY_UNPINNED: 'fail',
  SUITE_UNDECLARED: 'inconclusive',
  MULTIPLE_COLLECTORS: 'inconclusive',
  CHECKPOINTS_UNATTRIBUTED: 'inconclusive',
  NO_EVIDENCE: 'inconclusive',
  // M2
  SUCCESSION_BROKEN: 'fail',
  OPSIG_EPOCH_REGRESSED: 'fail',
  // M3a
  ENVELOPE_DIGEST_MISMATCH: 'fail',
  ENVELOPE_NOTE_MISMATCH: 'fail',
  ENVELOPE_DUPLICATE_ISSUER: 'inconclusive',
  WITNESS_SHORT: 'fail',
  WITNESS_MISMATCH: 'fail',
  WITNESS_MISSING: 'inconclusive',
  TRUNCATED_BELOW_DISCLOSED: 'fail',
  // M3b — a declared discontinuity is reported prominently and never silently
  // bridged, but it is the operator telling you something rather than evidence
  // contradicting itself, so the specification makes it inconclusive. The
  // SILENT re-key is the one that fails, by breaking the succession chain.
  DISCONTINUITY: 'inconclusive',
  // M4
  COVERAGE_GAP: 'fail',
  COVERAGE_UNKNOWN: 'inconclusive',
  UNDATED_RECORD: 'inconclusive',
  // All `fail`: each is a privacy claim broken, not a weaker one.
  RESIDUE_UNCLASSIFIED_FIELD: 'fail',
  RESIDUE_UNEXPECTED_FIELD: 'fail',
  RESIDUE_SALT_RETAINED: 'fail',
  RESIDUE_CONTENT_RETAINED: 'fail',
});

/**
 * The specified verdict for a code. Throws on an unknown one for the same
 * reason finding() does.
 * @param {string} code
 * @returns {'ok'|'fail'|'inconclusive'}
 */
export function verdictFor(code) {
  const v = DEFAULT_VERDICTS[/** @type {keyof typeof DEFAULT_VERDICTS} */ (code)];
  if (!v) {
    throw new FindingError(
      `${JSON.stringify(code)} has no specified verdict. Add it to DEFAULT_VERDICTS in `
      + 'packages/core/src/findings.mjs and to spec/failure-codes.json — the lint requires both.',
    );
  }
  return /** @type {'ok'|'fail'|'inconclusive'} */ (v);
}

const CODES = new Set(FAILURE_CODES);

export class FindingError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'FindingError'; }
}

/**
 * @typedef {object} Finding
 * @property {string} code one of FAILURE_CODES
 * @property {'ok'|'fail'|'inconclusive'} verdict
 * @property {string} detail what a reader may conclude, in their words not ours
 * @property {number} [record_seq]
 * @property {number} [checkpoint_seq]
 * @property {number} [epoch]
 */

/**
 * The only way to construct a finding.
 *
 * It throws rather than returning a placeholder, because a finding that cannot
 * be named is a bug in this code, and the one thing worse than crashing on it
 * is printing an unrecognised code to someone deciding whether to rely on the
 * evidence.
 *
 * @param {string} code
 * @param {'ok'|'fail'|'inconclusive'} verdict
 * @param {string} detail
 * @param {{ record_seq?: number, checkpoint_seq?: number, epoch?: number }} [where]
 * @returns {Finding}
 */
export function finding(code, verdict, detail, where = {}) {
  if (!CODES.has(code)) {
    throw new FindingError(
      `${JSON.stringify(code)} is not a failure code this project defines. Add it to `
      + 'FAILURE_CODES in packages/core/src/findings.mjs and to spec/failure-codes.json with what '
      + 'a reader may conclude from it — the lint requires both.',
    );
  }
  if (!VERDICTS.includes(verdict)) {
    throw new FindingError(
      `${JSON.stringify(verdict)} is not one of DES-12's verdicts (${VERDICTS.join(', ')})`,
    );
  }
  if (typeof detail !== 'string' || detail === '') {
    throw new FindingError(`finding ${code} has no detail; a code alone tells a reader nothing`);
  }
  return { code, verdict, detail, ...where };
}

/**
 * Re-emit a finding produced by another layer, having checked its code.
 *
 * This replaces the `f.code` forwarding the lint had to exempt: the check now
 * happens where the forwarding does, at runtime, on the value that will
 * actually be printed.
 *
 * @param {{ code: string, detail: string, record_seq?: number, epoch?: number }} f
 * @param {'ok'|'fail'|'inconclusive'} verdict
 * @param {string} [prefix] context the outer layer can add, e.g. `checkpoint 3`
 * @returns {Finding}
 */
export function forward(f, verdict, prefix) {
  const detail = prefix ? `${prefix}: ${f.detail}` : f.detail;
  return finding(f.code, verdict, detail, {
    ...(f.record_seq === undefined ? {} : { record_seq: f.record_seq }),
    ...(f.epoch === undefined ? {} : { epoch: f.epoch }),
  });
}

/**
 * Assert that every finding leaving a module names a code this project defines.
 *
 * Called at each module's return boundary rather than at its fifty push sites:
 * the push sites are string literals the lint already reads, and what the lint
 * cannot read is a code arriving through a layer. The boundary is exactly where
 * that happens, so one check there covers every path out, including the ones
 * added later by someone who has not read this comment.
 *
 * It throws. A finding whose code this project does not define is a bug in this
 * code, and the only thing worse than crashing on it is printing it to someone
 * deciding whether to rely on the evidence.
 *
 * @template {{ code: string, verdict?: string, detail?: string }} T
 * @param {T[]} findings
 * @param {string} where the module, for the error message
 * @returns {T[]} the same array
 */
export function validateFindings(findings, where) {
  for (const f of findings) {
    if (!CODES.has(f.code)) {
      throw new FindingError(
        `${where} produced finding code ${JSON.stringify(f.code)}, which this project does not `
        + 'define. Add it to FAILURE_CODES in packages/core/src/findings.mjs and to '
        + 'spec/failure-codes.json with what a reader may conclude from it — the lint requires both.',
      );
    }
    if (f.verdict !== undefined && !VERDICTS.includes(f.verdict)) {
      throw new FindingError(
        `${where} produced finding ${f.code} with verdict ${JSON.stringify(f.verdict)}, which is `
        + `not one of DES-12's (${VERDICTS.join(', ')})`,
      );
    }
  }
  return findings;
}
