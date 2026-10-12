/**
 * The witness list, as data — FR-47, GOV-05, GOV-08, GOV-09.
 *
 * `spec/witnesses.json` is a list of witnesses known to be conformant. It is
 * NOT an endorsement and not a ranking: nobody vets, ranks or charges for
 * inclusion, entries arrive by pull request, and anyone — including
 * competitors and hyperscalers — may run a conformant witness.
 *
 * WHAT THE PARSER REFUSES, and why each matters more than it looks:
 *
 * An entry missing its acceptable-use position, its rate limits or its
 * retention disclosure is REFUSED. An absent position reads as "no
 * restriction", which is the one reading that is never safe: an operator
 * choosing a witness is choosing who learns their anchor cadence (PRIV-08) and
 * under whose terms, and a blank is not an answer to either.
 *
 * A field expressing preference — recommended, rating, rank, tier, score,
 * verified, trusted — is REFUSED. GOV-09 says this project does not gatekeep
 * the list, and a `recommended: true` would be gatekeeping wearing a different
 * name. The refusal is here rather than in a review checklist because a review
 * is a thing somebody skips.
 *
 * An unknown witness type is REFUSED rather than skipped, for the same reason
 * `witnessesFromConfig` refuses one: a silently shrunk witness set leaves an
 * operator believing they are anchored.
 */

import { readFileSync } from 'node:fs';
import { WITNESS_TYPES, WitnessConfigError } from './index.mjs';

/** Fields every entry must state. An absent one is not a permissive default. */
const REQUIRED = Object.freeze([
  'id', 'type', 'operator', 'operated_by_splitstick', 'endpoints', 'establishes',
  'acceptable_use', 'rate_limits', 'retains_publicly',
]);

/**
 * Field names that would express a preference. GOV-09.
 *
 * Matched as whole words against the entry's own keys, so a `retention_note`
 * is not caught by `note` and an honest field is never refused for containing
 * a letter sequence.
 */
const RANKING_FIELDS = Object.freeze([
  'recommended', 'recommendation', 'rating', 'rank', 'ranking', 'score',
  'tier_rating', 'preferred', 'endorsed', 'verified', 'trusted', 'certified',
  'quality', 'stars', 'grade',
]);

/**
 * @typedef {object} WitnessListEntry
 * @property {string} id
 * @property {string} type
 * @property {string} operator who runs it
 * @property {boolean} operated_by_splitstick GOV-09's own check: a list that is
 *   all ours is a list nobody else is in
 * @property {string[]} endpoints
 * @property {string[]} establishes capability classes — DES-08
 * @property {string} acceptable_use
 * @property {string} rate_limits
 * @property {boolean} retains_publicly whether submissions become public
 * @property {string} [retention_note]
 */

/**
 * @param {unknown} raw the parsed JSON
 * @returns {{ version: number, entries: WitnessListEntry[] }}
 */
export function parseWitnessList(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new WitnessConfigError('the witness list is an object with a version and entries');
  }
  const o = /** @type {Record<string, unknown>} */ (raw);
  if (o.version !== 1) {
    throw new WitnessConfigError(
      `the witness list declares version ${JSON.stringify(o.version)} and this reader implements `
      + '1; it is refused rather than partially read',
    );
  }
  if (!Array.isArray(o.entries)) throw new WitnessConfigError('the witness list has no entries');

  /** @type {WitnessListEntry[]} */
  const entries = [];
  for (const e of o.entries) {
    if (e === null || typeof e !== 'object' || Array.isArray(e)) {
      throw new WitnessConfigError('every witness list entry is an object');
    }
    const entry = /** @type {Record<string, unknown>} */ (e);
    const id = typeof entry.id === 'string' ? entry.id : '(unnamed)';

    for (const f of REQUIRED) {
      if (entry[f] === undefined || entry[f] === null || entry[f] === '') {
        throw new WitnessConfigError(
          `witness list entry ${id} states no ${f}. Every entry states its acceptable use, its `
          + 'rate limits and whether it retains submissions publicly, because an absent position '
          + 'reads as "no restriction" — the one reading that is never safe (FR-47)',
        );
      }
    }
    for (const k of Object.keys(entry)) {
      if (RANKING_FIELDS.includes(k)) {
        throw new WitnessConfigError(
          `witness list entry ${id} carries a ${JSON.stringify(k)} field. GOV-09: this project `
          + 'does not vet, rank or charge for inclusion, and a field expressing preference is '
          + 'gatekeeping wearing a different name',
        );
      }
    }
    if (!WITNESS_TYPES.includes(/** @type {string} */ (entry.type))) {
      throw new WitnessConfigError(
        `witness list entry ${id} has type ${JSON.stringify(entry.type)}, which is not one of `
        + `${WITNESS_TYPES.join(', ')}. Refused rather than skipped: a silently shrunk list `
        + 'leaves an operator believing a witness is available that this build cannot build',
      );
    }
    if (!Array.isArray(entry.endpoints) || !Array.isArray(entry.establishes)) {
      throw new WitnessConfigError(`witness list entry ${id} needs endpoints and establishes as lists`);
    }
    if (typeof entry.retains_publicly !== 'boolean'
      || typeof entry.operated_by_splitstick !== 'boolean') {
      throw new WitnessConfigError(
        `witness list entry ${id} must answer retains_publicly and operated_by_splitstick with a `
        + 'boolean: "probably" is not a disclosure',
      );
    }
    if (entries.some(x => x.id === entry.id)) {
      throw new WitnessConfigError(`witness list entry ${id} appears twice`);
    }
    entries.push(/** @type {WitnessListEntry} */ (entry));
  }
  return { version: 1, entries };
}

/** @param {string} path */
export function readWitnessList(path) {
  return parseWitnessList(JSON.parse(readFileSync(path, 'utf8')));
}

/**
 * What an operator is told before choosing — FR-47.
 *
 * Every entry, in the order the file lists them, with no ordering applied here.
 * Sorting by anything would be a ranking, and GOV-09 is the reason there is not
 * one — including the subtle kind where "we just put the good ones first".
 * @param {{ entries: WitnessListEntry[] }} list
 */
export function describeWitnessList(list) {
  const lines = [`${list.entries.length} known conformant witness(es), in file order.`,
    'This list is not a ranking and not an endorsement: nobody vets, ranks or charges for',
    'inclusion, and entries arrive by pull request (GOV-05, GOV-08, GOV-09).',
    ''];
  for (const e of list.entries) {
    lines.push(`${e.id}  [${e.type}] — ${e.operator}`);
    lines.push(`  establishes     ${e.establishes.join(', ')}`);
    lines.push(`  acceptable use  ${e.acceptable_use}`);
    lines.push(`  rate limits     ${e.rate_limits}`);
    lines.push(`  retains public  ${e.retains_publicly ? 'YES' : 'no'}`
      + `${e.retention_note ? ` — ${e.retention_note}` : ''}`);
    lines.push('');
  }
  return lines.join('\n');
}
