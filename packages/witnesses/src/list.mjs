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
 * A field this reader does not know is REFUSED, and that is an ALLOWLIST on
 * purpose. GOV-09 says this project does not vet, rank OR CHARGE for
 * inclusion, and the first version of this check was a list of forbidden
 * words — `recommended`, `rating`, `rank`, `score`. `sponsored`, `premium`,
 * `featured`, `official`, `vetted` and `best_for` all walked straight through
 * it, and `sponsored` is precisely the charging case the requirement names. A
 * denylist of words has to anticipate the word somebody chooses; an allowlist
 * makes a new field a deliberate act. The forbidden words are kept only to
 * give a sharper message when an unknown field is obviously one of them.
 *
 * An unknown witness type is REFUSED rather than skipped, for the same reason
 * `witnessesFromConfig` refuses one: a silently shrunk witness set leaves an
 * operator believing they are anchored.
 */

import { readFileSync } from 'node:fs';
import { CAPABILITY_CLASSES } from '@splitstick/core/anchor';
import { WITNESS_TYPES, WitnessConfigError } from './index.mjs';

/** Fields every entry must state. An absent one is not a permissive default. */
const REQUIRED = Object.freeze([
  'id', 'type', 'operator', 'operated_by_splitstick', 'endpoints', 'establishes',
  'acceptable_use', 'rate_limits', 'retains_publicly',
]);

/** Fields an entry may also carry. Everything outside REQUIRED + these is refused. */
const OPTIONAL = Object.freeze(['retention_note']);

/**
 * Names that are obviously a preference or a payment, for a better message.
 *
 * NOT the check — the check is the allowlist above, because a denylist has to
 * anticipate the word somebody chooses and this one did not anticipate
 * `sponsored`. These only decide which refusal an author is shown.
 */
const RANKING_FIELDS = Object.freeze([
  'recommended', 'recommendation', 'rating', 'rank', 'ranking', 'score',
  'tier_rating', 'preferred', 'endorsed', 'verified', 'trusted', 'certified',
  'quality', 'stars', 'grade', 'sponsored', 'premium', 'featured', 'official',
  'approved', 'vetted', 'curated', 'popularity', 'best_for', 'recommended_for',
  'partner', 'paid', 'promoted',
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
      if (REQUIRED.includes(k) || OPTIONAL.includes(k)) continue;
      throw new WitnessConfigError(
        RANKING_FIELDS.includes(k)
          ? `witness list entry ${id} carries a ${JSON.stringify(k)} field. GOV-09: this project `
            + 'does not vet, rank or charge for inclusion, and a field expressing preference or '
            + 'payment is gatekeeping wearing a different name'
          : `witness list entry ${id} carries a ${JSON.stringify(k)} field, which this reader does `
            + `not know. Entries carry ${[...REQUIRED, ...OPTIONAL].join(', ')} and nothing else: `
            + 'an unknown field is refused rather than ignored because GOV-09 cannot be enforced '
            + 'by a list of forbidden words, and adding one has to be a deliberate act',
      );
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
    // An entry that claims nothing is an entry an operator cannot choose on
    // informed grounds, which is the whole point of FR-47. `[]` passed the
    // required-field check because it is neither undefined nor '' — the same
    // "absent reads as permissive" hole the check exists to close, through a
    // different door.
    if (entry.establishes.length === 0) {
      throw new WitnessConfigError(
        `witness list entry ${id} establishes nothing. An entry that claims no capability class `
        + 'cannot be chosen on informed grounds, and an empty list is not a disclosure (FR-47)',
      );
    }
    for (const cls of entry.establishes) {
      if (!CAPABILITY_CLASSES.includes(/** @type {string} */ (cls))) {
        throw new WitnessConfigError(
          `witness list entry ${id} claims to establish ${JSON.stringify(cls)}, which is not one `
          + `of ${CAPABILITY_CLASSES.join(', ')}. An unrecognised class is refused for the same `
          + 'reason an unknown type is: an operator reading it would choose this witness '
          + 'believing it covers something nothing here can deliver',
        );
      }
    }
    // Only the operator-hosted witness has no public endpoint — it is the one
    // you stand up yourself (FR-17). For anything else, no endpoint means an
    // entry nobody can reach, listed as though they could.
    if (entry.endpoints.length === 0 && entry.type !== 'splitstick') {
      throw new WitnessConfigError(
        `witness list entry ${id} names no endpoint. Only the self-hosted type may omit one, `
        + 'because it is the one an operator stands up themselves',
      );
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
