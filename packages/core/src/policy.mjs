// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The effective policy, as a document the chain commits to — FR-23, SEC-12,
 * DES-09.
 *
 * Any change to the witness set, the quorum, the anchor or roll-up intervals,
 * or the declared capture surface emits a `policy` record carrying the digest
 * of the previous effective policy and of the new one. Chained and anchored
 * like anything else, so weakening the policy and *then* tampering leaves a
 * timestamped, countersigned record of the weakening.
 *
 * WHY THE DOCUMENT IS STORED AND NOT ONLY ITS DIGEST. DES-09 specifies the
 * record as two digests and says the result is "a record of the weakening,
 * detectable, attributable, and impossible to do quietly". Two opaque digests
 * are not quite that: they make the CHANGE detectable without making its
 * DIRECTION identifiable. An auditor holding only them can see that the policy
 * moved and cannot see that it moved from two witnesses to one, which is the
 * specific thing SEC-12 is named for.
 *
 * So the effective policy document is written beside the chain under its own
 * digest, and the chain's commitment is what makes it trustworthy: the
 * operator cannot produce a stronger document than the one they ran, because
 * only one document hashes to the recorded digest. If the document is missing
 * the report says the change is visible and its content unestablished — which
 * is honest, and is strictly more than a digest pair alone could say. The
 * deviation from DES-09 is recorded there.
 *
 * Nothing secret is in it. The witness ids and the quorum are already in every
 * reader's acceptance policy (DES-09) and the quorum is already printed per
 * class by FR-57; the capture surface is the collector's own declaration.
 */

import { createHash } from 'node:crypto';
import { canonicalBytes } from './jcs.mjs';
import { captureSurface } from './capture.mjs';

export class PolicyError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'PolicyError'; }
}

/**
 * @typedef {object} EffectivePolicy
 * @property {number} quorum
 * @property {{ id: string, type: string, tier: string }[]} witnesses sorted by id
 * @property {number} anchor_interval_ms
 * @property {number} rollup_interval_ms
 * @property {import('./capture.mjs').CaptureSurface} capture
 */

/**
 * The policy this collector is actually running, normalised for digesting.
 *
 * Sorted by witness id so declaration order cannot move the digest — an alarm
 * that fires when nothing changed teaches people to ignore alarms. Only the
 * fields that bear on what the evidence establishes: a witness's URL can move
 * without weakening anything, and treating a relocation as a policy downgrade
 * would bury the real ones.
 *
 * @param {import('./config.mjs').Config} config
 * @returns {EffectivePolicy}
 */
export function effectivePolicy(config) {
  for (const [k, v] of /** @type {const} */ ([
    ['quorum', config.quorum],
    ['anchor_interval_ms', config.anchor_interval_ms],
    ['rollup_interval_ms', config.rollup_interval_ms],
  ])) {
    if (!Number.isSafeInteger(v) || v <= 0) {
      throw new PolicyError(
        `${k} is ${JSON.stringify(v)}; the effective policy needs a positive integer`,
      );
    }
  }
  /** @type {{ id: string, type: string, tier: string }[]} */
  const witnesses = [];
  for (const w of config.witnesses ?? []) {
    if (typeof w?.id !== 'string' || !w.id) {
      throw new PolicyError(
        'every witness in the effective policy needs an id: it is what a quorum counts',
      );
    }
    if (witnesses.some(x => x.id === w.id)) {
      throw new PolicyError(
        `witness ${w.id} appears twice in the effective policy. A quorum made of one party `
        + 'submitting twice is not a quorum, and collapsing the duplicate would hide that',
      );
    }
    witnesses.push({ id: w.id, type: String(w.type), tier: String(w.tier ?? 'anchor') });
  }
  witnesses.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {
    quorum: config.quorum,
    witnesses,
    anchor_interval_ms: config.anchor_interval_ms,
    rollup_interval_ms: config.rollup_interval_ms,
    capture: captureSurface(config),
  };
}

/**
 * The digest the chain commits to.
 * @param {EffectivePolicy} policy
 */
export function policyDigest(policy) {
  return `sha256:${createHash('sha256').update(canonicalBytes(policy)).digest('hex')}`;
}

/**
 * The digest of the first policy, which supersedes nothing.
 *
 * The digest of the empty string: a documented, reproducible constant rather
 * than a pretend predecessor. The same constant the practice-statement chain
 * uses, for the same reason.
 */
export const GENESIS_POLICY = `sha256:${createHash('sha256').update('').digest('hex')}`;

/**
 * What changed between two policies, for a report to state.
 *
 * Each difference as a before/after pair. It does NOT rank them: calling a
 * change a "weakening" would require this code to decide that two witnesses
 * are better than one in the reader's threat model, which is the reader's
 * judgement and not ours. It reports the movement and lets the reader
 * conclude — the same division FR-30 draws for acceptance.
 *
 * @param {EffectivePolicy|null} before
 * @param {EffectivePolicy} after
 * @returns {{ field: string, before: unknown, after: unknown }[]}
 */
export function policyChanges(before, after) {
  if (before === null) return [{ field: 'policy', before: null, after: 'first recorded policy' }];
  /** @type {{ field: string, before: unknown, after: unknown }[]} */
  const out = [];
  for (const f of /** @type {const} */ (['quorum', 'anchor_interval_ms', 'rollup_interval_ms'])) {
    if (before[f] !== after[f]) out.push({ field: f, before: before[f], after: after[f] });
  }
  const ids = (/** @type {EffectivePolicy} */ p) =>
    p.witnesses.map(w => `${w.id} (${w.type}/${w.tier})`);
  const was = ids(before);
  const now = ids(after);
  const removed = was.filter(x => !now.includes(x));
  const added = now.filter(x => !was.includes(x));
  if (removed.length > 0) out.push({ field: 'witnesses_removed', before: removed, after: null });
  if (added.length > 0) out.push({ field: 'witnesses_added', before: null, after: added });
  for (const f of /** @type {const} */ (['upstreams', 'interfaces'])) {
    const b = before.capture[f].join(' ');
    const a = after.capture[f].join(' ');
    if (b !== a) {
      out.push({ field: `capture.${f}`, before: before.capture[f], after: after.capture[f] });
    }
  }
  // `heartbeat_interval_ms` only. The capture surface carries
  // `anchor_interval_ms` too, because it is part of what is attested, but it is
  // already compared at the top level above — reporting it in both places made
  // one change read as two, in a list an auditor counts.
  if (before.capture.heartbeat_interval_ms !== after.capture.heartbeat_interval_ms) {
    out.push({
      field: 'capture.heartbeat_interval_ms',
      before: before.capture.heartbeat_interval_ms,
      after: after.capture.heartbeat_interval_ms,
    });
  }
  return out;
}
