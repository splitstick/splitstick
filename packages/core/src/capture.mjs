// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The capture surface the collector reports for itself — FR-64, DES-10.
 *
 * A digest of what the collector says it is watching: the upstreams it
 * proxies, the interfaces it binds, and the two intervals that set the
 * resolution of every claim built on top of it. Carried in each heartbeat, so
 * a change to that configuration is a recorded, chained, countersignable event
 * rather than a quiet one.
 *
 * WHAT THIS IS NOT, and the reason it is a small claim honestly made rather
 * than a large one dishonestly made:
 *
 * It is provenance of a SELF-REPORT. An operator can stand up an execution
 * path entirely outside the collector; this collector goes on reporting an
 * unchanged digest and heartbeating normally, and nothing diverges, because
 * nothing inside Splitstick observes the new path. FR-64 says so, DES-10 says
 * so, and a test asserts the bypass produces no signal — while asserting in
 * the same test that a DECLARED change does produce one, because a test that
 * only proves silence would pass against a function that does nothing.
 *
 * The digest is over JCS bytes (RFC 8785) like every other digest here. A
 * digest that changed when nothing changed would be an alarm that teaches
 * people to ignore alarms, which is worse than no alarm.
 */

import { createHash } from 'node:crypto';
import { canonicalBytes } from './jcs.mjs';

/**
 * Documented, reproducible stand-ins for "nobody told me".
 *
 * They are REAL digests — of a fixed ASCII label — so the record schema can
 * demand a digest without exception, which is what stops a field that exists
 * to record a configuration from being satisfiable by the word `unset`. The
 * coverage report recognises them and reports *not attested* rather than
 * printing a digest that means nothing; a test asserts that, because a
 * sentinel shown as though it were evidence is worse than an absent field.
 */
export const UNATTESTED_BUILD = `sha256:${createHash('sha256')
  .update('splitstick/unattested-build').digest('hex')}`;

export class CaptureError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'CaptureError'; }
}

/**
 * @typedef {object} CaptureSurface
 * @property {string[]} upstreams the upstreams the collector proxies, sorted
 * @property {string[]} interfaces the interfaces it binds, sorted
 * @property {number} heartbeat_interval_ms the resolution of a liveness claim
 * @property {number} anchor_interval_ms how long a batch can sit unwitnessed
 */

/**
 * A list of declared endpoints, normalised for digesting.
 *
 * Sorted, because key and element order must not change a digest. Duplicates
 * are REFUSED rather than collapsed: silently deduplicating means two
 * different declarations produce one digest, and the whole point of the field
 * is that a change to the declaration is visible.
 * @param {unknown} v @param {string} field
 * @returns {string[]}
 */
function endpoints(v, field) {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) {
    throw new CaptureError(`capture.${field} must be a list of strings, not ${typeof v}`);
  }
  /** @type {string[]} */
  const out = [];
  for (const e of v) {
    if (typeof e !== 'string' || e.trim() === '') {
      throw new CaptureError(
        `capture.${field} contains ${JSON.stringify(e)}: every entry is a non-empty string. `
        + 'An unreadable entry is refused rather than skipped, because a declared surface with a '
        + 'silently dropped entry attests to a surface nobody declared',
      );
    }
    if (out.includes(e)) {
      throw new CaptureError(
        `capture.${field} lists ${JSON.stringify(e)} twice. Duplicates are refused rather than `
        + 'collapsed: two different declarations must not produce one digest',
      );
    }
    out.push(e);
  }
  return out.sort();
}

/**
 * Build the surface from a parsed config.
 *
 * An absent `capture` block means an empty declaration — the collector says it
 * proxies nothing — and not a missing one. Those are the same claim, so
 * inventing a distinction between them would add a state nobody can act on.
 * Adding the first upstream still changes the digest, which is what FR-64 is
 * for.
 * @param {{ capture?: unknown, heartbeat_interval_ms: number, anchor_interval_ms: number }} config
 * @returns {CaptureSurface}
 */
export function captureSurface(config) {
  const c = config.capture;
  if (c !== undefined && c !== null && (typeof c !== 'object' || Array.isArray(c))) {
    throw new CaptureError('capture must be a mapping of upstreams and interfaces');
  }
  const o = /** @type {Record<string, unknown>} */ (c ?? {});
  for (const k of Object.keys(o)) {
    // Refused rather than ignored: a misspelled `upstream:` that attested to
    // an empty surface would be a narrower declaration than the operator
    // wrote, recorded as though they had written it.
    if (k !== 'upstreams' && k !== 'interfaces') {
      throw new CaptureError(`capture.${k} is not a known key; expected upstreams or interfaces`);
    }
  }
  for (const [k, v] of /** @type {const} */ ([
    ['heartbeat_interval_ms', config.heartbeat_interval_ms],
    ['anchor_interval_ms', config.anchor_interval_ms],
  ])) {
    if (!Number.isSafeInteger(v) || v <= 0) {
      throw new CaptureError(
        `${k} is ${JSON.stringify(v)}; the attested surface carries the resolution of every claim `
        + 'built on it, and a zero or absent interval would attest to a resolution of nothing',
      );
    }
  }
  return {
    upstreams: endpoints(o.upstreams, 'upstreams'),
    interfaces: endpoints(o.interfaces, 'interfaces'),
    heartbeat_interval_ms: config.heartbeat_interval_ms,
    anchor_interval_ms: config.anchor_interval_ms,
  };
}

/**
 * `sha256:` over the surface's JCS bytes.
 * @param {CaptureSurface} surface
 * @returns {string}
 */
export function captureDigest(surface) {
  return `sha256:${createHash('sha256').update(canonicalBytes(surface)).digest('hex')}`;
}

/**
 * One call: config in, digest out, for the heartbeat to carry.
 * @param {{ capture?: unknown, heartbeat_interval_ms: number, anchor_interval_ms: number }} config
 */
export function captureAttestation(config) {
  const surface = captureSurface(config);
  return { surface, digest: captureDigest(surface) };
}
