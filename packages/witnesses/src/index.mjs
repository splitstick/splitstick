/**
 * Building the configured witness set — FR-13, FR-48, SEC-04, SEC-25.
 *
 * This package depends on every adapter, which is exactly why it is separate
 * from `@splitstick/core`: the offline verifier must not acquire an HTTP client
 * through a transitive dependency, and a single "all the witnesses" package
 * would have put one there.
 *
 * ## The shipped default — FR-48
 *
 * An RFC 3161 timestamp authority for the per-batch countersignature and clock,
 * plus an OpenTimestamps roll-up on a slow interval. Both are things the project
 * neither operates nor overloads, which is the point: a default that depends on
 * us is not independence, and a default that hammers a public good is not
 * acceptable use.
 *
 * **The default does not close attack classes 4 and 5.** It gives real
 * independent time and closes 1, 2, 3, 6 and 7. Truncation and erasure need a
 * party that remembers your sequence, and neither a TSA nor a calendar does —
 * they sign your hash and forget you. Closing those needs a stateful witness
 * (FR-17) or an enumerable log (FR-14), both free, both requiring the operator
 * to stand up a second party. DES-08 says that is not a limitation of scope but
 * the shape of the problem, and `defaultWitnessWarning()` is here so an operator
 * is told rather than left to read the design.
 *
 * ## SEC-04, the assumption, stated
 *
 * Security holds if at least ONE witness in the configured set is honest. Not a
 * majority, and not a specific one: a single honest witness retaining a root
 * the operator later contradicts is enough to produce the contradiction. The
 * corollary is the uncomfortable half — a set whose members share an interest
 * is one witness wearing several hats, and no quorum number fixes that.
 */

import { CAPABILITY_CLASSES } from '@splitstick/core/anchor';
import { tsaWitness } from '@splitstick/witness-tsa';
import { otsWitness } from '@splitstick/witness-ots';
import { rekorWitness } from '@splitstick/witness-rekor';

export class WitnessConfigError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'WitnessConfigError'; }
}

/**
 * SEC-25 — each witness type's time discipline, so the verifier can surface
 * where a timestamp's authority comes from instead of presenting every
 * countersignature as equally authoritative about time.
 */
export const TIME_DISCIPLINE = Object.freeze({
  rfc3161: 'the TSA\'s own clock, disciplined as its published practice statement says and no '
    + 'better. A qualified TSA under eIDAS states its traceability to UTC(k); a free public one '
    + 'may state nothing, and the operator chose which',
  opentimestamps: 'a Bitcoin block header. Not a clock at all: block timestamps are loosely '
    + 'bounded by consensus rules, so this establishes "no later than", which is weaker than a '
    + 'timestamp and harder to forge',
  splitstick: 'the witness host\'s clock, recorded as received_at. Trustworthy exactly as far as '
    + 'the party running it, which is the point of it being a different party',
  rekor: 'the log\'s own signed entry timestamp, disciplined as its operator says',
});

/** The types this builder knows. An unknown type is refused, never ignored. */
export const WITNESS_TYPES = Object.freeze(['rfc3161', 'opentimestamps', 'rekor', 'splitstick']);

/**
 * @param {{ witnesses?: { id: string, type: string, url?: string, tier?: string,
 *   calendars?: string[], key?: string, self_hosted?: boolean, qualified?: boolean }[] }} config
 * @param {{ fetchImpl?: typeof globalThis.fetch }} [opts]
 * @returns {import('@splitstick/core/anchor').WitnessAdapter[]}
 */
export function witnessesFromConfig(config, opts = {}) {
  const entries = config.witnesses ?? [];
  /** @type {import('@splitstick/core/anchor').WitnessAdapter[]} */
  const out = [];
  for (const w of entries) {
    if (typeof w?.id !== 'string' || !w.id) {
      throw new WitnessConfigError('every witness needs an id: it is what a quorum counts');
    }
    if (!WITNESS_TYPES.includes(w.type)) {
      // Ignoring an unknown type would silently reduce the witness set, and a
      // misspelled `type: rfc3161` that quietly anchors to nothing is exactly
      // the failure config validation exists to prevent.
      throw new WitnessConfigError(
        `witness ${w.id} has type ${JSON.stringify(w.type)}, which is not one of `
        + `${WITNESS_TYPES.join(', ')}. An unknown type is refused rather than skipped: a witness `
        + 'set that silently shrank would leave an operator believing they were anchored',
      );
    }
    const tier = /** @type {'anchor'|'rollup'|undefined} */ (w.tier);
    switch (w.type) {
      case 'rfc3161':
        out.push(tsaWitness({
          id: w.id,
          url: /** @type {string} */ (w.url),
          ...(w.qualified ? { qualified: true } : {}),
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        }));
        break;
      case 'opentimestamps':
        out.push(otsWitness({
          id: w.id,
          calendars: w.calendars ?? [...DEFAULT_CALENDARS],
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        }));
        break;
      case 'rekor':
        out.push(rekorWitness({
          id: w.id,
          url: /** @type {string} */ (w.url),
          ...(tier ? { tier } : {}),
          ...(w.self_hosted ? { selfHosted: true } : {}),
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        }));
        break;
      case 'splitstick':
        throw new WitnessConfigError(
          `witness ${w.id} is type splitstick, the operator-hosted stateful witness (FR-17). It is `
          + 'not built here because it needs a transport the operator chooses and a key they hold; '
          + 'construct it with @splitstick/witness-self and pass the adapter in directly.',
        );
      default:
        throw new WitnessConfigError(`unreachable: ${w.type}`);
    }
  }
  return out;
}

/**
 * The public calendars the OpenTimestamps project operates. Named here rather
 * than in the adapter so that the default is visible in one place an operator
 * can read and change.
 */
export const DEFAULT_CALENDARS = Object.freeze([
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
]);

/**
 * What the configured set can and cannot establish — FR-57's input, and the
 * honest warning FR-48 requires.
 *
 * @param {import('@splitstick/core/anchor').WitnessAdapter[]} witnesses
 * @returns {{ classes: Record<string, string[]>, closes_truncation: boolean,
 *             warnings: string[], time_discipline: Record<string, string> }}
 */
export function describeWitnessSet(witnesses) {
  /** @type {Record<string, string[]>} */
  const classes = Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, []]));
  /** @type {Record<string, string>} */
  const time_discipline = {};
  for (const w of witnesses) {
    for (const c of w.establishes) classes[c]?.push(w.id);
    const d = TIME_DISCIPLINE[/** @type {keyof typeof TIME_DISCIPLINE} */ (w.proof_type)];
    if (d) time_discipline[w.id] = d;
  }
  const closes_truncation = (classes.sequence ?? []).length > 0;
  /** @type {string[]} */
  const warnings = [];
  if (witnesses.length === 0) {
    warnings.push(
      'no witness is configured. This is a supported configuration (SCOPE-15) and it establishes '
      + 'nothing beyond internal consistency: a log you anchor to yourself is a log you could '
      + 'rewrite',
    );
  } else if (!closes_truncation) {
    warnings.push(
      'no witness in this set maintains sequence state, so attack classes 4 (truncation) and 5 '
      + '(erasure) are NOT closed. A TSA and a calendar sign your hash and forget you; neither can '
      + 'tell you that a checkpoint it signed last week is missing from the log you show it today. '
      + 'Closing them needs a stateful witness (FR-17) or an enumerable log (FR-14) — both free, '
      + 'both requiring a second party. That is the shape of the problem, not a gap in scope',
    );
  }
  if (witnesses.length === 1) {
    warnings.push(
      'one witness is configured. SEC-04 holds if at least one witness is honest, which a set of '
      + 'one satisfies only while that one is — and a quorum above 1 is unreachable, so the '
      + 'acceptance policy cannot ask for more than this set can give',
    );
  }
  return { classes, closes_truncation, warnings, time_discipline };
}

/** FR-48 — the warning an operator leaving the default in place must be given. */
export function defaultWitnessWarning() {
  return describeWitnessSet(witnessesFromConfig({
    witnesses: [
      { id: 'tsa', type: 'rfc3161', url: 'https://tsa.invalid' },
      { id: 'ots', type: 'opentimestamps', tier: 'rollup' },
    ],
  })).warnings;
}
