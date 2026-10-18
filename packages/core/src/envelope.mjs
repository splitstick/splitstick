// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The countersignature envelope — DES-20, FR-12, FR-31.
 *
 * Three signers, three incompatible proof formats, over one checkpoint. A
 * timestamp authority cannot produce a C2SP signed-note line: RFC 3161 defines
 * a CMS SignedData over a MessageImprint, its own format with its own
 * verification path. OpenTimestamps is further away still — a .ots proof is not
 * a signature at all but a chain of commitment operations ending in a Bitcoin
 * block header. An earlier draft of DES-07 showed a TSA appearing as a note
 * signature line; it would have produced an interface nobody could implement.
 *
 * So the note is the signed subject and countersignatures sit BESIDE it in a
 * typed envelope, never inside it. Each entry says in `covers` which bytes it
 * is over, explicitly, because two signers signing different bytes and both
 * appearing valid is exactly how a confused deputy enters a verifier.
 *
 * This module parses and builds. It verifies nothing: each proof type needs its
 * own verification path, and those live with their adapters so that the
 * offline verifier does not acquire a dependency per witness type.
 */

import { createHash } from 'node:crypto';
import { parseNote, parseCheckpointText } from './note.mjs';
import { validateFindings } from './findings.mjs';

export class EnvelopeError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'EnvelopeError'; }
}

/**
 * The proof types this project implements. An entry of any other type is
 * INCONCLUSIVE and never a failure: a pack carrying a format this verifier does
 * not implement is not evidence of tampering (DES-12).
 */
export const COUNTERSIGNATURE_TYPES = Object.freeze(['c2sp-note', 'rfc3161', 'opentimestamps']);

/**
 * Which subject each type signs. A signed-note line is over the note text; a
 * token or a commitment is over the digest. Letting either claim the other's
 * subject is how a verifier ends up checking a signature against bytes nobody
 * signed, so the pairing is enforced rather than documented.
 */
const COVERS = Object.freeze({
  'c2sp-note': 'note',
  rfc3161: 'note_digest',
  opentimestamps: 'note_digest',
});

/** @param {string} noteBlob @returns {string} `sha256:<hex>` over the exact bytes */
export function noteDigest(noteBlob) {
  return 'sha256:' + createHash('sha256').update(Buffer.from(noteBlob, 'utf8')).digest('hex');
}

/**
 * @typedef {object} Countersignature
 * @property {string} type
 * @property {string} issuer
 * @property {'note'|'note_digest'} covers which bytes this proof is over
 * @property {string} [line] c2sp-note: the signature line
 * @property {string} [token] rfc3161: base64 DER TimeStampToken
 * @property {string} [proof] opentimestamps: base64 .ots
 * @property {string} [received_at] FR-39 — when the WITNESS says it received
 *   the root, by its own clock. Carried for a `c2sp-note` proof because a C2SP
 *   note has nowhere to put a time, which makes this a bare claim in the
 *   envelope rather than something signed; an `rfc3161` token carries its
 *   genTime INSIDE the signature and does not need this field. The verifier
 *   labels the difference, because reporting an unsigned claim as a signed one
 *   would be the most useful-looking lie available.
 */

/**
 * @typedef {object} Envelope
 * @property {string} note the exact note bytes
 * @property {string} note_digest
 * @property {Countersignature[]} countersignatures
 */

/** @param {string} noteBlob @returns {Envelope} */
export function buildEnvelope(noteBlob) {
  if (typeof noteBlob !== 'string') throw new EnvelopeError('a note is a string of bytes');
  return { note: noteBlob, note_digest: noteDigest(noteBlob), countersignatures: [] };
}

/**
 * Return a NEW envelope with the entry appended. Immutable on purpose: a failed
 * write must not leave the in-memory copy ahead of the file.
 * @param {Envelope} env
 * @param {Countersignature} cs
 * @returns {Envelope}
 */
export function addCountersignature(env, cs) {
  if (cs === null || typeof cs !== 'object') throw new EnvelopeError('a countersignature is an object');
  if (typeof cs.type !== 'string' || !cs.type) throw new EnvelopeError('a countersignature has a type');
  if (typeof cs.issuer !== 'string' || !cs.issuer) throw new EnvelopeError('a countersignature has an issuer');
  if (cs.covers !== 'note' && cs.covers !== 'note_digest') {
    throw new EnvelopeError(
      `covers must be 'note' or 'note_digest', not ${JSON.stringify(cs.covers)}: a proof that does `
      + 'not say which bytes it is over cannot be checked against them',
    );
  }
  const expected = COVERS[/** @type {keyof typeof COVERS} */ (cs.type)];
  if (expected && cs.covers !== expected) {
    throw new EnvelopeError(
      `a ${cs.type} proof is over the ${expected}, not the ${cs.covers}`,
    );
  }
  return { ...env, countersignatures: [...env.countersignatures, cs] };
}

/**
 * @typedef {object} ParsedCountersignature
 * @property {string} type
 * @property {string} issuer
 * @property {string} [covers]
 * @property {'ok'|'fail'|'inconclusive'} verdict the SHAPE verdict only.
 *   Cryptographic verification happens in the adapter for this type; `ok` here
 *   means the entry is well-formed and names a subject that exists, nothing more.
 * @property {string} [detail]
 * @property {Countersignature} [entry] present when the shape is usable
 */

/**
 * @param {string} raw the envelope JSON
 * @param {{ expectNote?: string }} [opts] the note bytes this envelope must carry
 * @returns {{
 *   ok: boolean,
 *   note: string|null,
 *   note_digest: string|null,
 *   tree_size: number|null,
 *   countersignatures: ParsedCountersignature[],
 *   issuers: Set<string>,
 *   unwitnessed: boolean,
 *   findings: { code: string, detail: string }[],
 * }}
 */
export function parseEnvelope(raw, opts = {}) {
  /** @type {{ code: string, detail: string }[]} */
  const findings = [];
  /** @type {ParsedCountersignature[]} */
  const countersignatures = [];
  /** @type {Set<string>} */
  const issuers = new Set();
  const no = () => ({
    ok: false, note: null, note_digest: null, tree_size: null,
    countersignatures: [], issuers, unwitnessed: true,
    findings: validateFindings(findings, 'parseEnvelope'),
  });
  /** @param {string} code @param {string} detail */
  const bad = (code, detail) => { findings.push({ code, detail }); return no(); };

  /** @type {any} */
  let env;
  try {
    env = JSON.parse(raw);
  } catch (e) {
    return bad('FORMAT_UNSUPPORTED',
      `the checkpoint envelope is not JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (env === null || typeof env !== 'object' || Array.isArray(env)) {
    return bad('FORMAT_UNSUPPORTED', 'the checkpoint envelope is not a JSON object');
  }
  if (typeof env.note !== 'string' || env.note === '') {
    return bad('FORMAT_UNSUPPORTED', 'the checkpoint envelope carries no note');
  }

  // The digest first, because every other entry names it. A wrong digest makes
  // each countersignature vouch for bytes nobody has, so nothing is reported as
  // verified once it is wrong.
  if (typeof env.note_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(env.note_digest)) {
    return bad('FORMAT_UNSUPPORTED',
      `note_digest ${JSON.stringify(env.note_digest)} is not a sha256:<64 hex> digest. It is not `
      + 'recomputed from the note: the point of storing it is that the countersignatures name it');
  }
  if (env.note_digest !== noteDigest(env.note)) {
    return bad('ENVELOPE_DIGEST_MISMATCH',
      'note_digest is not the digest of the note beside it, so every countersignature in this '
      + 'envelope covers bytes that are not here');
  }
  if (opts.expectNote !== undefined && opts.expectNote !== env.note) {
    return bad('ENVELOPE_NOTE_MISMATCH',
      'the envelope carries a different note than the one it was checked against: a reader must '
      + 'never verify one artefact and report on another');
  }

  /** @type {number|null} */
  let tree_size = null;
  try {
    tree_size = parseCheckpointText(parseNote(env.note).text).tree_size;
  } catch (e) {
    return bad('FORMAT_UNSUPPORTED',
      `the note inside the envelope is not a parseable checkpoint: ${e instanceof Error ? e.message : String(e)}`);
  }

  const list = env.countersignatures;
  if (list !== undefined && !Array.isArray(list)) {
    findings.push({ code: 'FORMAT_UNSUPPORTED', detail: 'countersignatures is not an array' });
  }
  for (const cs of Array.isArray(list) ? list : []) {
    if (cs === null || typeof cs !== 'object' || Array.isArray(cs)
      || typeof cs.type !== 'string' || !cs.type
      || typeof cs.issuer !== 'string' || !cs.issuer) {
      findings.push({
        code: 'FORMAT_UNSUPPORTED',
        detail: 'a countersignature entry has no usable type and issuer, so it cannot be attributed',
      });
      countersignatures.push({
        type: typeof cs?.type === 'string' ? cs.type : '(absent)',
        issuer: typeof cs?.issuer === 'string' ? cs.issuer : '(absent)',
        verdict: 'inconclusive',
        detail: 'the entry has no usable type and issuer',
      });
      continue;
    }
    const expected = COVERS[/** @type {keyof typeof COVERS} */ (cs.type)];
    if (cs.received_at !== undefined && typeof cs.received_at !== 'string') {
      findings.push({
        code: 'FORMAT_UNSUPPORTED',
        detail: `${cs.issuer}'s received_at is not a string`,
      });
    }
    if (cs.covers !== 'note' && cs.covers !== 'note_digest') {
      countersignatures.push({
        type: cs.type, issuer: cs.issuer, covers: cs.covers, verdict: 'inconclusive',
        detail: `covers is ${JSON.stringify(cs.covers)}, which names nothing in this envelope, so `
          + 'there are no bytes to check this proof against',
      });
      continue;
    }
    if (!COUNTERSIGNATURE_TYPES.includes(cs.type)) {
      countersignatures.push({
        type: cs.type, issuer: cs.issuer, covers: cs.covers, verdict: 'inconclusive',
        detail: `this verifier does not implement proof type ${cs.type}; an unimplemented format `
          + 'is not evidence of tampering',
      });
      if (issuers.has(cs.issuer)) {
        findings.push({ code: 'ENVELOPE_DUPLICATE_ISSUER', detail: `${cs.issuer} appears more than once` });
      }
      issuers.add(cs.issuer);
      continue;
    }
    if (expected && cs.covers !== expected) {
      countersignatures.push({
        type: cs.type, issuer: cs.issuer, covers: cs.covers, verdict: 'inconclusive',
        detail: `a ${cs.type} proof is over the ${expected}, but this entry covers the ${cs.covers}`,
      });
      continue;
    }
    // One issuer, one vote. Both entries are still reported — hiding one would
    // hide a duplicate submission — but a quorum counts issuers.
    if (issuers.has(cs.issuer)) {
      findings.push({
        code: 'ENVELOPE_DUPLICATE_ISSUER',
        detail: `${cs.issuer} appears more than once in this envelope and counts once towards any quorum`,
      });
    }
    issuers.add(cs.issuer);
    countersignatures.push({
      type: cs.type, issuer: cs.issuer, covers: cs.covers, verdict: 'ok', entry: cs,
    });
  }

  return {
    ok: true,
    note: env.note,
    note_digest: env.note_digest,
    tree_size,
    countersignatures,
    issuers,
    unwitnessed: countersignatures.length === 0,
    findings: validateFindings(findings, 'parseEnvelope'),
  };
}
