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
  ['tool_call', 'approval', 'heartbeat', 'gap', 'gap_unknown', 'policy', 'custody',
    'discontinuity', 'padding']);

/** Kinds that represent an observation and therefore carry a source_seq. */
const OBSERVATION_KINDS = new Set(['tool_call', 'approval']);

/** Chain metadata must never appear inside the canonicalised subject — FR-59. */
const FORBIDDEN = Object.freeze(['leaf', 'prev', 'head', 'salt']);

/** Fields every record carries. */
export const ENVELOPE = Object.freeze(
  ['v', 'collector', 'run', 'record_seq', 'source_seq', 'ts', 'kind']);

/**
 * The exhaustive set of fields each kind may carry — PRIV-02.
 *
 * An open schema made PRIV-02's claim depend on the collector being the only
 * writer, which is precisely the assumption a tamper-evidence product cannot
 * make: both the schema and the verifier are reusable, and a pack arrives from
 * somewhere else. A field that is not here is refused, so "the record format
 * excludes payloads" is a property of the format rather than of our own
 * discipline in writing it.
 */
export const ALLOWED = Object.freeze({
  tool_call: [...ENVELOPE, 'tool', 'consequential', 'agent', 'args', 'result', 'approval',
    'outcome', 'attempt', 'correlation'],
  approval: [...ENVELOPE, 'tool', 'consequential', 'agent', 'args', 'result', 'approval',
    'outcome', 'attempt', 'correlation'],
  heartbeat: [...ENVELOPE, 'build', 'policy', 'heartbeat_interval_ms', 'counts'],
  gap: [...ENVELOPE, 'from_source_seq', 'to_source_seq', 'reason'],
  gap_unknown: [...ENVELOPE, 'from_ts', 'to_ts', 'last_checkpoint_source_seq'],
  policy: [...ENVELOPE, 'previous_policy', 'next_policy', 'policy_subject'],
  // FR-65 — the operator's declaration of how the epoch's key is held.
  //
  // It is a RECORD rather than a field on the checkpoint because a verifier
  // cannot tell custody from a signature: an HSM signature and one produced
  // from a PEM file on disk are byte-identical. Putting the declaration in the
  // chain means altering it later breaks the chain, and countersigning the
  // checkpoint above it fixes when it was made.
  //
  // It establishes that the operator ASSERTED a class. It does not establish
  // the class. `custody_basis` is therefore constrained to the single value
  // 'operator-declared': 'independently-supported' is a conclusion a verifier
  // reaches by validating a provider attestation (FR-70), never something the
  // operator writes about themselves.
  custody: [...ENVELOPE, 'epoch', 'public_key', 'custody_class', 'custody_basis'],
  // SEC-24 — a declared key compromise, rather than a silent re-key.
  //
  // DES-06 calls this "a policy record". It cannot be one: this allowlist is
  // exhaustive PER KIND, so a policy record carrying a last sound epoch and a
  // new root key would have to make those fields optional — optional on every
  // ordinary policy change, where they mean nothing. A distinct kind says
  // required-here and forbidden-there, which is exactly the distinction, and it
  // lets a verifier FIND discontinuities by kind rather than sniffing for
  // optional fields. That is what makes "never silently bridged" checkable.
  discontinuity: [...ENVELOPE, 'last_sound_epoch', 'new_root_public_key', 'reason'],
  padding: [...ENVELOPE, 'pad'],
});

/**
 * The only basis a custody RECORD may declare. See the `custody` allowlist
 * above for why there is exactly one.
 */
export const CUSTODY_BASES = Object.freeze(['operator-declared']);

/**
 * Mirrors signer.mjs's list. Imported rather than duplicated would be cleaner,
 * but record.mjs is the one module a pack validator can be handed on its own,
 * and it must not pull in the signer seam to check a string.
 */
const CUSTODY_CLASSES = Object.freeze(['software', 'kms', 'hsm']);

/** Fields an approval object may carry. */
const APPROVAL_FIELDS = ['decision', 'reviewer', 'request'];

export const OUTCOMES = Object.freeze(['ok', 'error', 'timeout', 'denied']);

const HEX32 = /^[0-9a-f]{32}$/;
// A full-length digest, lower-case. A shortened "cid" is not a commitment: the
// substitution argument in FR-35 rests entirely on the identifier moving when
// the bytes move, and 16 bits of collision resistance does not carry it.
const CID = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * A timestamp must match the SHAPE and name a real instant.
 *
 * The regex alone accepted `2026-13-45T99:99:99.999Z` — month thirteen, day
 * forty-five — because every digit is in the right place. Anything that later
 * computed with the value got NaN: FR-39's unwitnessed window, M4's coverage
 * reasoning, any ordering by time. A regex that checks the shape of a
 * timestamp does not check that it is one.
 *
 * `Date.parse` is not the check either: it rejects month thirteen but ROLLS
 * `2026-02-30` over to March 2nd and reports it finite, so a date that does
 * not exist would be read back as a different date than the one written.
 * The round trip is the check — the required format is exactly the one
 * `toISOString` emits, so a string naming a real instant is reproduced
 * character for character and anything normalised away fails to match.
 *
 * Found reviewing M3b; the hole was in M1's schema from the beginning.
 * @param {unknown} v
 */
export function isTimestamp(v) {
  if (typeof v !== 'string' || !RFC3339.test(v)) return false;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) return false;
  return new Date(ms).toISOString() === v;
}
/** Exactly 32 bytes, base64 — 43 characters and one '=' of padding. */
const B64_32 = /^[A-Za-z0-9+/]{43}=$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** @param {Record<string, unknown>} r @param {string} f */
function reqTimestamp(r, f) {
  req(r, f);
  if (typeof r[f] !== 'string' || !isTimestamp(/** @type {string} */ (r[f]))) {
    throw new RecordError(`${f} must be RFC 3339 UTC with milliseconds, got ${JSON.stringify(r[f])}`);
  }
}

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
    if (!['cid', 'bytes', 'ok'].includes(k)) {
      throw new RecordError(`${field}.${k} is not permitted: payloads are externalised`);
    }
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

  for (const f of ['collector', 'record_seq', 'ts', 'kind', 'run']) req(r, f);
  // run is retained forever (DES-13), and an action attributable to no run is
  // not attributable to anything. null is the explicit "no run", which is what
  // a heartbeat carries.
  if (r.run !== null && (typeof r.run !== 'string' || r.run === '')) {
    throw new RecordError('run must be a non-empty string or null');
  }
  if (typeof r.collector !== 'string' || !r.collector) throw new RecordError('collector must be a non-empty string');
  if (!Number.isInteger(r.record_seq) || /** @type {number} */ (r.record_seq) < 1) {
    throw new RecordError('record_seq must be an integer from 1');
  }
  if (typeof r.ts !== 'string' || !isTimestamp(r.ts)) throw new RecordError('ts must be RFC 3339 UTC with milliseconds');
  if (typeof r.kind !== 'string' || !RECORD_KINDS.includes(r.kind)) {
    throw new RecordError(`unknown kind ${String(r.kind)}: the enum is closed (DES-01)`);
  }
  const kind = /** @type {keyof typeof ALLOWED} */ (r.kind);

  // The allowlist, before anything kind-specific: an unexpected field is
  // refused rather than validated around.
  const allowed = ALLOWED[kind];
  for (const k of Object.keys(r)) {
    if (!allowed.includes(k)) {
      throw new RecordError(
        `field ${JSON.stringify(k)} is not permitted on a ${kind} record: the schema is a closed `
        + 'allowlist so that PRIV-02 is a property of the format, not of the writer (PRIV-02)');
    }
  }

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
      for (const k of Object.keys(r.approval)) {
        if (!APPROVAL_FIELDS.includes(k)) {
          throw new RecordError(`approval.${k} is not permitted: the schema is a closed allowlist (PRIV-02)`);
        }
      }
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
      // source_seq starts at 1 (DES-01), so a span bounded by 0 names an
      // observation that cannot exist — and a gap's whole value is that its
      // span is exact.
      if (/** @type {number} */ (r[f]) < 1) {
        throw new RecordError(`${f} must be at least 1: source_seq counts observations from 1`);
      }
    }
    if (/** @type {number} */ (r.from_source_seq) > /** @type {number} */ (r.to_source_seq)) {
      throw new RecordError('a gap span must not end before it starts');
    }
  }

  if (kind === 'gap_unknown') {
    // The interval is the whole content of this record — it is what the
    // operator is declaring they cannot characterise — so an unparseable one
    // makes the record meaningless rather than merely untidy.
    for (const f of ['from_ts', 'to_ts']) reqTimestamp(r, f);
    if (/** @type {string} */ (r.from_ts) > /** @type {string} */ (r.to_ts)) {
      throw new RecordError('an unknown-loss interval must not end before it starts');
    }
    // Never a span: inventing one would assert what was lost with the counter.
    for (const f of ['from_source_seq', 'to_source_seq']) {
      if (f in r) throw new RecordError(`gap_unknown must never carry ${f} (FR-60)`);
    }
  }

  if (kind === 'heartbeat') {
    for (const f of ['build', 'policy']) req(r, f);

    // THESE CHECKS ARE DELIBERATELY NOT TIGHTENED, and the reason matters more
    // than the checks would.
    //
    // `policy` existed with the collector defaulting it to the string
    // `sha256:unset` — a placeholder that satisfied a presence check and looked
    // like an attestation, so FR-64's attested surface could be nothing at all.
    // The obvious fix is to demand a well-formed digest here. It is the wrong
    // fix: validateRecord is also the READ path, so every heartbeat written
    // before the change would become MALFORMED_RECORD, which the verifier
    // reports as `fail` — a false tampering signal over evidence that was
    // correct when it was written, raised by the tool whose job is to tell
    // those apart. Manufacturing that is worse than the hole.
    //
    // So the hole is closed at the two ends that can close it without
    // reclassifying old evidence: the collector now attests a real digest
    // computed from its own config (capture.mjs), and the coverage report
    // reads a non-digest or sentinel value as NOT ATTESTED rather than
    // displaying it as though it were an attestation. A value that is present
    // and malformed is reported, not accepted and not called tampering.
    //
    // Same reasoning for the two fields below: absent means an older record
    // that cannot support the claim, which the report states; present means it
    // must be well formed, because a present-but-nonsense value is damage.
    if ('heartbeat_interval_ms' in r) {
      if (!Number.isSafeInteger(r.heartbeat_interval_ms) || Number(r.heartbeat_interval_ms) <= 0) {
        throw new RecordError(
          'a heartbeat\'s heartbeat_interval_ms is the resolution of its liveness claim, so '
          + `${JSON.stringify(r.heartbeat_interval_ms)} resolves nothing. Absent is a record from `
          + 'before the field existed and is reported as resolution-unknown; present and '
          + 'nonsensical is damage',
        );
      }
    }
    if ('counts' in r) {
      const c = r.counts;
      if (c === null || typeof c !== 'object' || Array.isArray(c)) {
        throw new RecordError('a heartbeat\'s counts is a mapping of record kind to a count');
      }
      for (const [k, n] of Object.entries(c)) {
        if (!Number.isSafeInteger(n) || /** @type {number} */ (n) < 0) {
          throw new RecordError(`counts.${k} is ${JSON.stringify(n)}; a count is a non-negative integer`);
        }
      }
    }
  }

  if (kind === 'policy') {
    // WHICH policy. Two different things use this record kind — the effective
    // anchoring-and-capture policy (FR-23, SEC-12) and the practice
    // statement's version chain (LEG-09) — and `previous_policy`/`next_policy`
    // alone never said which. The collector then read a practice-statement
    // version as an attestation of its own effective policy, found it did not
    // match, and emitted a spurious change event: two digests compared that
    // were not about the same subject.
    //
    // Optional, and an ABSENT subject is not read as either. A record written
    // before the field existed is evidence that something moved, and inferring
    // which policy it was about would reintroduce the same guess that caused
    // the collision.
    if ('policy_subject' in r) {
      if (r.policy_subject !== 'effective' && r.policy_subject !== 'practice-statement') {
        throw new RecordError(
          `policy_subject is ${JSON.stringify(r.policy_subject)}; expected 'effective' or `
          + "'practice-statement'. An unknown subject is refused rather than ignored, because a "
          + 'record about an unknown policy would be counted towards whichever one read it',
        );
      }
    }
    // SEC-12's downgrade defence IS these two digests: a policy record carrying
    // neither is a note saying something happened, not evidence of what.
    for (const f of ['previous_policy', 'next_policy']) {
      req(r, f);
      if (typeof r[f] !== 'string' || !DIGEST.test(/** @type {string} */ (r[f]))) {
        throw new RecordError(`${f} must be a full sha256 digest of the effective policy`);
      }
    }
  }

  if (kind === 'discontinuity') {
    for (const f of ['last_sound_epoch', 'new_root_public_key', 'reason']) req(r, f);
    if (!Number.isSafeInteger(r.last_sound_epoch) || /** @type {number} */ (r.last_sound_epoch) < 0) {
      throw new RecordError(
        `last_sound_epoch ${JSON.stringify(r.last_sound_epoch)} is not a non-negative integer. `
        + 'Zero is valid: the very first epoch can be the compromised one.',
      );
    }
    if (typeof r.new_root_public_key !== 'string' || !B64_32.test(r.new_root_public_key)) {
      throw new RecordError('new_root_public_key must be a 32-byte Ed25519 key, base64');
    }
    if (typeof r.reason !== 'string' || r.reason === '') {
      throw new RecordError(
        'a discontinuity needs a reason: a bare declaration tells a reader that something happened '
        + 'and nothing about what, and this is the one record whose whole purpose is to explain',
      );
    }
  }

  if (kind === 'custody') {
    for (const f of ['epoch', 'public_key', 'custody_class', 'custody_basis']) req(r, f);
    if (!Number.isSafeInteger(r.epoch) || /** @type {number} */ (r.epoch) < 0) {
      throw new RecordError(`epoch ${JSON.stringify(r.epoch)} is not a non-negative integer`);
    }
    if (typeof r.public_key !== 'string' || !B64_32.test(r.public_key)) {
      throw new RecordError('public_key must be a 32-byte Ed25519 key, base64');
    }
    if (!CUSTODY_CLASSES.includes(/** @type {string} */ (r.custody_class))) {
      throw new RecordError(
        `custody_class ${JSON.stringify(r.custody_class)} is not one of ${CUSTODY_CLASSES.join(', ')}`,
      );
    }
    if (!CUSTODY_BASES.includes(/** @type {string} */ (r.custody_basis))) {
      throw new RecordError(
        `custody_basis ${JSON.stringify(r.custody_basis)} is refused: a record may only declare `
        + `${CUSTODY_BASES.join(', ')}. Independent support is a conclusion a verifier reaches by `
        + 'validating a provider attestation (FR-70), not a claim an operator makes about itself',
      );
    }
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
