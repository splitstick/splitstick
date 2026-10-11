/**
 * The action record schema — DES-01.
 *
 * Two structures, never one. The ActionRecord validated here is the
 * canonicalised, hashed subject and carries no chain metadata: a digest that
 * depended on a value derived from itself would be circular (FR-59). prev,
 * leaf, head and the leaf salt live in the ChainEntry wrapper (chain.mjs),
 * which is never canonicalised as a unit.
 *
 * No payload is in either structure. Arguments and results are salted content
 * commitments (FR-35); the plaintext lives encrypted in the deletable store,
 * which is what makes PRIV-02 literally true rather than true of large
 * payloads only.
 */

export class RecordError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'RecordError'; }
}

export const SCHEMA_VERSION = 1;
export const SUITE = 'SS1';

/** Closed enum. An unknown kind makes a record unverifiable, not ignorable. */
export const RECORD_KINDS = Object.freeze(
  ['tool_call', 'approval', 'heartbeat', 'gap', 'gap_unknown', 'policy', 'padding']);

/** Kinds that represent an observation and therefore carry a source_seq. */
const OBSERVATION_KINDS = new Set(['tool_call', 'approval']);

/** Chain metadata must never appear inside the canonicalised subject — FR-59. */
const FORBIDDEN = Object.freeze(['leaf', 'prev', 'head', 'salt']);

export const OUTCOMES = Object.freeze(['ok', 'error', 'timeout', 'denied']);

const HEX32 = /^[0-9a-f]{32}$/;
const CID = /^sha256:[0-9a-f]{4,64}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** @param {unknown} v @returns {v is Record<string, unknown>} */
const isObj = v => typeof v === 'object' && v !== null && !Array.isArray(v);

/** @param {Record<string, unknown>} r @param {string} f */
function req(r, f) {
  if (!(f in r) || r[f] === undefined) throw new RecordError(`missing required field: ${f}`);
}

/**
 * A content commitment: a salted digest of the plaintext plus its length.
 * Never the plaintext. FR-35.
 * @param {unknown} v @param {string} field
 */
function assertCommitment(v, field) {
  if (!isObj(v)) throw new RecordError(`${field} must be a content commitment { cid, bytes }, not a value`);
  if (typeof v.cid !== 'string' || !CID.test(v.cid)) throw new RecordError(`${field}.cid must be a sha256 commitment`);
  if ('bytes' in v && !Number.isInteger(v.bytes)) throw new RecordError(`${field}.bytes must be an integer`);
  for (const k of Object.keys(v)) {
    if (!['cid', 'bytes', 'ok'].includes(k)) throw new RecordError(`${field}.${k} is not permitted: payloads are externalised`);
  }
}

/**
 * Validate a record against the version-1 schema. Throws rather than returning
 * a verdict, because a malformed record is a programming error at capture time,
 * not a verification outcome.
 * @param {unknown} rec
 * @returns {Record<string, unknown>}
 */
export function validateRecord(rec) {
  if (!isObj(rec)) throw new RecordError('record must be an object');
  const r = rec;

  for (const f of FORBIDDEN) {
    if (f in r) throw new RecordError(`${f} belongs to the ChainEntry, not the record (FR-59)`);
  }
  req(r, 'v');
  if (r.v !== SCHEMA_VERSION) throw new RecordError(`unsupported schema version ${String(r.v)}: fails closed (NFR-07)`);

  for (const f of ['collector', 'record_seq', 'ts', 'kind']) req(r, f);
  if (typeof r.collector !== 'string' || !r.collector) throw new RecordError('collector must be a non-empty string');
  if (!Number.isInteger(r.record_seq) || /** @type {number} */ (r.record_seq) < 1) {
    throw new RecordError('record_seq must be an integer from 1');
  }
  if (typeof r.ts !== 'string' || !RFC3339.test(r.ts)) throw new RecordError('ts must be RFC 3339 UTC with milliseconds');
  if (typeof r.kind !== 'string' || !RECORD_KINDS.includes(r.kind)) {
    throw new RecordError(`unknown kind ${String(r.kind)}: the enum is closed (DES-01)`);
  }
  const kind = r.kind;

  // source_seq: present on an observation, null on everything else. Null states
  // "this record is not an observation", which is checkable; a repeated value
  // would be indistinguishable from a second observation of the same action.
  if (!('source_seq' in r)) throw new RecordError('source_seq must be present, null on non-observations');
  if (OBSERVATION_KINDS.has(kind)) {
    if (!Number.isInteger(r.source_seq) || /** @type {number} */ (r.source_seq) < 1) {
      throw new RecordError(`${kind} must carry an integer source_seq`);
    }
  } else if (r.source_seq !== null) {
    throw new RecordError(`${kind} must carry source_seq: null (DES-04)`);
  }

  if (kind === 'tool_call' || kind === 'approval') {
    req(r, 'tool'); req(r, 'consequential');
    if (typeof r.tool !== 'string' || !r.tool) throw new RecordError('tool must be a non-empty string');
    if (typeof r.consequential !== 'boolean') throw new RecordError('consequential must be a boolean the tool declared');
    if (r.agent !== undefined) assertCommitment(r.agent, 'agent');
    if (r.args !== undefined) assertCommitment(r.args, 'args');
    if (r.result !== undefined) assertCommitment(r.result, 'result');

    // FR-62 — a timeout or error is an outcome, not an absence.
    for (const f of ['outcome', 'attempt', 'correlation']) req(r, f);
    if (typeof r.outcome !== 'string' || !OUTCOMES.includes(r.outcome)) {
      throw new RecordError(`outcome must be one of ${OUTCOMES.join(' | ')}`);
    }
    if (!Number.isInteger(r.attempt) || /** @type {number} */ (r.attempt) < 1) {
      throw new RecordError('attempt must be an integer from 1');
    }
    if (typeof r.correlation !== 'string' || !r.correlation) {
      throw new RecordError('correlation must be an opaque identifier grouping attempts');
    }

    if (r.approval !== undefined && r.approval !== null) {
      if (!isObj(r.approval)) throw new RecordError('approval must be null or an object');
      if (r.approval.decision !== 'approve' && r.approval.decision !== 'deny') {
        throw new RecordError('approval.decision must be approve or deny');
      }
      if (r.approval.reviewer !== undefined) assertCommitment(r.approval.reviewer, 'approval.reviewer');
      if (r.approval.request !== undefined) assertCommitment(r.approval.request, 'approval.request');
    }
  }

  if (kind === 'padding') {
    req(r, 'pad');
    if (typeof r.pad !== 'string' || !HEX32.test(r.pad)) {
      throw new RecordError('pad must be 16 random bytes as 32 hex characters (FR-69)');
    }
    for (const f of ['tool', 'args', 'result', 'agent', 'approval']) {
      if (f in r) throw new RecordError(`padding must not carry ${f}`);
    }
  }

  if (kind === 'gap') {
    for (const f of ['from_source_seq', 'to_source_seq']) {
      req(r, f);
      if (!Number.isInteger(r[f])) throw new RecordError(`${f} must be an integer`);
    }
  }

  if (kind === 'gap_unknown') {
    for (const f of ['from_ts', 'to_ts']) req(r, f);
    // Never a span: inventing one would assert what was lost with the counter.
    for (const f of ['from_source_seq', 'to_source_seq']) {
      if (f in r) throw new RecordError(`gap_unknown must never carry ${f} (FR-60)`);
    }
  }

  if (kind === 'heartbeat') {
    for (const f of ['build', 'policy']) req(r, f);
  }

  return r;
}

/**
 * Every leaf path in an object, as key arrays. Used by FR-52's property test so
 * that a field added later is covered without anyone remembering to extend a
 * list.
 * @param {unknown} v
 * @param {(string|number)[]} [path]
 * @returns {(string|number)[][]}
 */
export function leafPaths(v, path = []) {
  if (Array.isArray(v)) return v.flatMap((x, i) => leafPaths(x, [...path, i]));
  if (isObj(v)) return Object.keys(v).flatMap(k => leafPaths(v[k], [...path, k]));
  return [path];
}
