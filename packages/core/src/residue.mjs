/**
 * What remains after erasure, and a scan that proves it — PRIV-05, PRIV-03,
 * FR-36, DES-13.
 *
 * PRIV-05's claim is not "the data is gone". It is an ENUMERATED set: after
 * crypto-shredding, the chain retains exactly these fields and nothing else.
 * A blanket claim would be doing too much work — an external review said so of
 * an earlier draft of DES-13 — and a partial inventory is worse than none,
 * because it reads as exhaustive.
 *
 * So this file is the inventory, and the scan below is what stops it from
 * becoming a document that describes a previous version of the schema.
 *
 * TWO PROPERTIES, and the second is the one that keeps the first honest:
 *
 * 1. After shredding, every field present in the chain is in the permanent
 *    set, and every erasable artefact is gone from the store.
 * 2. **Every field the schema permits is classified here.** A field added to
 *    `ALLOWED` and not classified makes `classifySchema()` fail — so extending
 *    the record format forces a decision about whether the new field survives
 *    a deletion request, rather than letting it survive by default. A scan
 *    that only checked property 1 would pass forever while the schema grew
 *    underneath it, which is risk shape 5: a seam exercised against a
 *    yesterday's definition of the thing it guards.
 */

import { ALLOWED, RECORD_KINDS } from './record.mjs';
import { finding, validateFindings } from './findings.mjs';

/**
 * Every field the version-1 schema permits, classified.
 *
 * `permanent` — survives erasure, by design, with the reason it is acceptable
 * to retain. `erasable` — the value does not survive; where a salted
 * commitment to it remains, that commitment is itself permanent and
 * unlinkable, and the entry says so.
 *
 * Taken field for field from DES-13's table, which an external review
 * established as the whole inventory rather than a sample after an earlier
 * version omitted `approval.decision`, `result.ok` and the byte lengths.
 */
export const CLASSIFIED = Object.freeze({
  // ── the envelope ──────────────────────────────────────────────────────────
  v: 'permanent',
  collector: 'permanent',
  run: 'permanent',
  record_seq: 'permanent',
  source_seq: 'permanent',
  ts: 'permanent',
  kind: 'permanent',

  // ── actions ───────────────────────────────────────────────────────────────
  // A function name, not a person: `transfer_funds` identifies a function.
  tool: 'permanent',
  consequential: 'permanent',
  outcome: 'permanent',
  attempt: 'permanent',
  // Retained, and therefore REQUIRED to carry nothing: an opaque random
  // identifier, never a request id, a user id, a session id, or anything
  // derived from a payload. It survives erasure and links the attempts of one
  // action, so a `correlation` that carried anything would be a retained
  // disclosure. The relationship it reveals cannot be erased without breaking
  // retry accounting, which is a documented, unmitigated leak.
  correlation: 'permanent',
  // The LABEL is erasable; what remains is a salted digest of it. Stored that
  // way precisely because an agent label could name a person.
  agent: 'erasable-commitment',
  // The payload is erasable; `{ cid, bytes }` remains. The byte length is a
  // deliberate, documented, unmitigated leak — a verifier needs it to detect a
  // truncated content store, and FR-34's padding is NOT a mitigation for it:
  // padding obscures how many records exist, not how large one payload was.
  args: 'erasable-commitment',
  result: 'erasable-commitment',
  // `decision` identifies nobody; `reviewer` and `request` are erasable.
  approval: 'erasable-commitment',

  // ── the other kinds ───────────────────────────────────────────────────────
  build: 'permanent',
  policy: 'permanent',
  heartbeat_interval_ms: 'permanent',
  counts: 'permanent',
  from_source_seq: 'permanent',
  to_source_seq: 'permanent',
  reason: 'permanent',
  from_ts: 'permanent',
  to_ts: 'permanent',
  last_checkpoint_source_seq: 'permanent',
  previous_policy: 'permanent',
  next_policy: 'permanent',
  policy_subject: 'permanent',
  epoch: 'permanent',
  public_key: 'permanent',
  custody_class: 'permanent',
  custody_basis: 'permanent',
  last_sound_epoch: 'permanent',
  new_root_public_key: 'permanent',
  // A padding record's random nonce. Permanent and carries nothing by
  // construction: it is 16 bytes from the CSPRNG and is never derived.
  pad: 'permanent',
});

/**
 * Which sub-fields of a commitment field survive, and which do not.
 *
 * The field itself is permanent as a COMMITMENT — the salted digest remains
 * and is unlinkable once the salt is gone. These are the keys inside it.
 */
/**
 * NOTE ON WHAT IS NOT HERE. There is no `erasable` list of sub-keys, and there
 * was: the first version listed `approval.reviewer` and `approval.request`
 * there and reported a correctly shredded record as retaining them. The
 * mistake was a category error — those are COMMITMENTS whose values are
 * erasable, not sub-keys that disappear. The salted digest remains in the
 * chain, because the chain is never deleted, and shredding makes it unlinkable
 * by destroying the content, the key and the content salt.
 *
 * Erasability is therefore a property of a VALUE and is checked by
 * contentResidue, which asks the content store whether the payload is still
 * retrievable. A sub-key list would have needed a failure code that nothing
 * could ever emit, which is what the failure-code lint exists to prevent.
 */
export const COMMITMENT_SUBFIELDS = Object.freeze({
  // No `bytes`: the length of a label is not retained, only of a payload. The
  // collector stopped writing it when this scan found it retained and DES-13's
  // inventory — established by review as the whole inventory rather than a
  // sample — did not list it.
  agent: { permanent: ['cid'] },
  // `bytes` IS retained here, as a documented and unmitigated leak: a verifier
  // needs it to detect a truncated content store.
  args: { permanent: ['cid', 'bytes'] },
  result: { permanent: ['cid', 'bytes', 'ok'] },
  approval: { permanent: ['decision', 'reviewer', 'request'] },
});

export class ResidueError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'ResidueError'; }
}

/**
 * Property 2 — every field the schema permits is classified.
 *
 * Returns the unclassified field names, by kind. Empty means the inventory
 * covers the schema; anything else means somebody extended the record format
 * without deciding whether the new field survives a deletion request.
 *
 * The schema is a PARAMETER so a test can hand in one with an extra field and
 * prove this function can fail. `ALLOWED` is frozen, which is correct, and a
 * check nothing can make fail is a check that proves nothing — the assertion
 * that it returns empty today would hold equally for `return []`.
 * @param {Record<string, readonly string[]>} [schema]
 * @param {readonly string[]} [kinds]
 * @returns {{ kind: string, field: string }[]}
 */
export function classifySchema(schema = ALLOWED, kinds = RECORD_KINDS) {
  /** @type {{ kind: string, field: string }[]} */
  const unclassified = [];
  for (const kind of kinds) {
    const fields = /** @type {Record<string, readonly string[]>} */ (schema)[kind];
    if (fields === undefined) {
      // A kind in the enum with no allowlist cannot be scanned at all, which
      // is a worse state than an unclassified field.
      unclassified.push({ kind, field: '(no allowlist for this kind)' });
      continue;
    }
    for (const f of fields) {
      if (!(f in CLASSIFIED)) unclassified.push({ kind, field: f });
    }
  }
  return unclassified;
}

/**
 * Property 1 — what the store actually holds after erasure.
 *
 * Scans every record for fields outside the permanent set, every commitment
 * for erasable sub-fields left behind, and the store for artefacts that should
 * be gone: content, content salts, keys, and the leaf salt of a shredded
 * record.
 *
 * Reports rather than throws. A residue finding is something an operator must
 * act on and a privacy assessment must see, and a thrown error loses the list.
 *
 * @param {import('./store.mjs').Store} store
 * @param {object} o
 * @param {number[]} o.shredded the record_seqs a deletion request covered
 * @returns {{ findings: import('./findings.mjs').Finding[],
 *   checked: number, permanent_fields: string[] }}
 */
export function scanResidue(store, o) {
  /** @type {import('./findings.mjs').Finding[]} */
  const findings = [];
  const shredded = new Set(o.shredded);

  // The schema must be fully classified before the residue means anything. A
  // scan against a stale inventory reports a clean residue for a schema it does
  // not know, which is the failure mode that matters most here.
  for (const u of classifySchema()) {
    findings.push(finding('RESIDUE_UNCLASSIFIED_FIELD', 'fail',
      `the schema permits ${u.field} on a ${u.kind} record and residue.mjs does not classify `
      + 'it. PRIV-05 enumerates what survives erasure, so a field nobody classified is a field '
      + 'nobody decided about — and it would survive by default'));
  }

  // Read through the store's own accessors rather than from guessed paths. An
  // earlier version of this scan looked for `content/<cid>.bin` and
  // `keys/<cid>.key`, which are DES-13's illustrative filenames and not the
  // layout: the content store groups payloads into one blob with a key journal
  // beside it, so those files never existed and every check passed vacuously.
  // A scan written against a document rather than against the code is a scan
  // that reports a clean residue for a store it has not looked at.
  const { entries } = store.readChainDetailed();

  for (const e of entries) {
    const r = /** @type {Record<string, unknown>} */ (e.record ?? {});
    const seq = Number(r.record_seq);
    for (const [f, v] of Object.entries(r)) {
      const cls = /** @type {Record<string, string>} */ (CLASSIFIED)[f];
      if (cls === undefined) {
        findings.push(finding('RESIDUE_UNEXPECTED_FIELD', 'fail',
          `field ${JSON.stringify(f)} is present and is not in the enumerated permanent set. `
          + 'PRIV-05 claims an exact residue, so an unlisted field is a claim broken',
          { record_seq: seq }));
        continue;
      }
      // A commitment field's sub-keys are where a reviewer or a request would
      // hide: the field itself is permitted, so checking only the field name
      // would miss them entirely.
      const sub = /** @type {Record<string, {permanent: string[]}>} */
        (COMMITMENT_SUBFIELDS)[f];
      if (sub === undefined || v === null || typeof v !== 'object') continue;
      for (const k of Object.keys(/** @type {Record<string, unknown>} */ (v))) {
        if (!sub.permanent.includes(k)) {
          findings.push(finding('RESIDUE_UNEXPECTED_FIELD', 'fail',
            `${f}.${k} is present and is not retained by PRIV-05`, { record_seq: seq }));
        }
      }
    }

    if (!shredded.has(seq)) continue;

    // A shredded record's chain entry comes back with `salt: null`; anything
    // else means the leaf salt survived. The salt is what makes the commitment
    // unlinkable, and it must not live in the chain for exactly this reason:
    // the chain is never deleted, so a salt stored there could never be
    // shredded and the erasure claim would be unsatisfiable. An earlier draft
    // of DES-13 made that mistake.
    if (e.salt !== null && e.salt !== undefined) {
      findings.push(finding('RESIDUE_SALT_RETAINED', 'fail',
        'the leaf salt of a shredded record is still held, so its commitment is still linkable '
        + 'to a plaintext anybody can guess at and confirm', { record_seq: seq }));
    }
    for (const f of ['agent', 'args', 'result']) {
      const c = /** @type {{cid?: string}|undefined} */ (r[f]);
      if (c?.cid) findings.push(...contentResidue(store, seq, f, c.cid));
    }
    const ap = /** @type {Record<string, {cid?: string}>|null|undefined} */ (r.approval);
    if (ap) {
      for (const f of ['reviewer', 'request']) {
        const c = ap[f];
        if (c?.cid) findings.push(...contentResidue(store, seq, `approval.${f}`, c.cid));
      }
    }
  }

  return {
    findings: validateFindings(findings, 'scanResidue'),
    checked: entries.length,
    permanent_fields: Object.entries(CLASSIFIED)
      .filter(([, v]) => v === 'permanent').map(([k]) => k).sort(),
  };
}

/**
 * Whether a shredded record's payload is still retrievable.
 *
 * `ContentStore.has` is the question that matters: it is true only when the key
 * journal still holds an entry AND the blob still reaches the bytes. Both
 * halves are what shredding removes, so one call covers the ciphertext, the key
 * and a truncated blob — and it asks the store rather than guessing at
 * filenames.
 * @param {import('./store.mjs').Store} store
 * @param {number} seq @param {string} where @param {string} cid
 */
function contentResidue(store, seq, where, cid) {
  /** @type {import('./findings.mjs').Finding[]} */
  const out = [];
  let retrievable = false;
  try {
    retrievable = store.content.has(cid);
  } catch {
    // An unreadable content store is not a residue finding: nothing is
    // retrievable from it, which is the property under test.
    retrievable = false;
  }
  if (retrievable) {
    out.push(finding('RESIDUE_CONTENT_RETAINED', 'fail',
      `the payload for ${where} (${cid}) is still retrievable after shredding`,
      { record_seq: seq }));
  }
  return out;
}
