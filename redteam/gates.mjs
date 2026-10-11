// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Whether a milestone's attack classes are actually closed.
 *
 * Extracted from the harness so it can be tested, because the first version was
 * wrong in two ways a review caught, and neither was visible from reading the
 * printed output:
 *
 * It asked whether an attack **declared** itself detected, not whether it
 * **was** detected. A declaration is an expectation; a gate is a result.
 *
 * And it looked only at attacks expected to be detected, ignoring the ones on
 * the same class that are still open. AC-5 has three attacks — F and F2 are
 * detected, F3 is not until M3a — so the gate would have reported HELD on the
 * strength of the easy two while the thorough erasure stood. A gate that passes
 * while an assigned attack succeeds is worse than no gate, because it is
 * reported as assurance.
 *
 * The rule is now: for a gate belonging to a shipped milestone, **every** attack
 * assigned to it must have been observed as detected. One outstanding attack
 * fails the class, however many simpler ones pass.
 */

/**
 * @typedef {object} Observation
 * @property {string} id
 * @property {string} gate
 * @property {'detected'|'undetected'} expect what the suite declares
 * @property {'detected'|'undetected'} observed what the run actually produced
 */

/**
 * @typedef {object} Gate
 * @property {string} gate
 * @property {string} milestone
 * @property {boolean} held
 * @property {boolean} missing true when no attack exercises the class at all
 * @property {string[]} detected
 * @property {string[]} outstanding
 */

/**
 * @param {{ milestones: { id: string, gate?: string[], shipped?: boolean }[] }} plan
 * @param {Observation[]} observations
 * @returns {{ due: Gate[], scheduled: { gate: string, milestone: string }[], unmet: number }}
 */
export function evaluateGates(plan, observations) {
  /** @type {{ gate: string, milestone: string }[]} */
  const scheduled = [];
  /** @type {Gate[]} */
  const due = [];

  for (const m of plan.milestones) {
    for (const gate of m.gate ?? []) {
      if (!m.shipped) { scheduled.push({ gate, milestone: m.id }); continue; }
      const assigned = observations.filter(o => o.gate === gate);
      const detected = assigned.filter(o => o.observed === 'detected').map(o => o.id);
      const outstanding = assigned.filter(o => o.observed !== 'detected').map(o => o.id);
      due.push({
        gate,
        milestone: m.id,
        // A class with no attack at all is not closed either: a gate nothing
        // exercises cannot be evidence of anything.
        missing: assigned.length === 0,
        held: assigned.length > 0 && outstanding.length === 0,
        detected,
        outstanding,
      });
    }
  }

  return { due, scheduled, unmet: due.filter(g => !g.held).length };
}

/** @param {ReturnType<typeof evaluateGates>} result @returns {string} */
export function formatGates(result) {
  const lines = result.due
    .sort((a, b) => a.gate.localeCompare(b.gate))
    .map(g => {
      if (g.missing) return `gate ${g.gate}   NOT MET   (${g.milestone} claims it and no attack exercises it)`;
      if (g.held) return `gate ${g.gate}   HELD      (${g.detected.join(', ')})`;
      return `gate ${g.gate}   NOT MET   (still undetected: ${g.outstanding.join(', ')})`;
    });
  if (result.scheduled.length) {
    lines.push('', 'scheduled   ' + result.scheduled
      .map(s => `${s.gate} (${s.milestone})`).sort().join(', '));
  }
  return lines.join('\n');
}
