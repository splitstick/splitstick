// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

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
import { tlogWitness } from '@splitstick/witness-tlog';

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
  rekor: 'the log\'s own signed entry timestamp, disciplined as its operator says. NOT credited '
    + 'as time here: the adapter establishes existence only, because the timestamp is the log '
    + 'operator\'s assertion about their own clock and nothing in the proof constrains it. The '
    + 'timestamp is real; crediting it would be a trust decision this project does not make for '
    + 'you',
  'tlog-witness': 'the witness host\'s own clock, signed. A cosignature/v1 signature covers '
    + '`cosignature/v1`, a `time <unix seconds>` line and the note text, so the timestamp is '
    + 'inside the signed message rather than metadata beside it, and it is recorded as '
    + 'received_at. Trustworthy exactly as far as the party running the witness and the clock on '
    + 'that host: it is NOT a qualified timestamp, nothing here disciplines the witness\'s clock '
    + 'to UTC(k), and no eIDAS presumption attaches to it. A line carrying no timestamp yields no '
    + 'received_at, because our submission clock is never written down as the witness\'s '
    + 'observation',
});

/**
 * Whether each type's proof is CREDITED with establishing time, as data rather
 * than as prose.
 *
 * This exists because the prose above and the adapter's `establishes` array
 * drifted apart: FR-15 taught the tlog adapter that a cosignature/v1 signature
 * carries a signed timestamp and set `establishes: ['sequence','time']`, while
 * TIME_DISCIPLINE went on telling operators the same witness had NOTHING. One
 * configured adapter, two contradictory statements, both reaching consumers —
 * through `witnessesFromConfig` and `describeWitnessSet` respectively.
 *
 * A test asserts every constructible type's adapter agrees with this table, and
 * that the prose agrees with it too, so the next capability change has to touch
 * the declaration rather than quietly contradict it.
 *
 * Note that "credited with time" is not "has a timestamp". Rekor's entries carry
 * a signed timestamp and this project credits it with existence only; the
 * distinction is the operator's trust decision, not an oversight, and the prose
 * now says so rather than leaving a reader to infer it from an array.
 */
export const CREDITED_WITH_TIME = Object.freeze({
  rfc3161: true,            // establishes: ['time']
  opentimestamps: false,    // establishes: ['existence'] — a block header is not a clock
  rekor: false,             // establishes: ['existence'] — it HAS a timestamp; we do not credit it
  'tlog-witness': true,     // establishes: ['sequence', 'time'] — cosignature/v1 signs one
  // `splitstick` is deliberately absent, not false. witnessesFromConfig refuses
  // to build it (FR-17: it needs a transport the operator chooses and a key
  // they hold), so there is no adapter here to check a declaration against, and
  // asserting a capability with nothing to verify it against is the thing this
  // table exists to stop.
});

/**
 * An `auth` block from a witness config — LEG-13.
 *
 * Shape-checked before it reaches the adapter. The credential itself is NOT
 * read here: this validates that the config says where to find it, which is a
 * different thing from the secret being present. A missing environment
 * variable is reported at submission time, by name, because that is when the
 * operator can act on it.
 *
 * @param {string} id
 * @param {any} auth
 * @returns {{ scheme: 'bearer'|'basic'|'header', env: string, header?: string }}
 */
function validateTsaAuth(id, auth) {
  if (typeof auth !== 'object' || auth === null) {
    throw new WitnessConfigError(`witness ${id}: auth must be an object, not ${typeof auth}`);
  }
  const SCHEMES = ['bearer', 'basic', 'header'];
  if (!SCHEMES.includes(auth.scheme)) {
    throw new WitnessConfigError(
      `witness ${id}: auth.scheme ${JSON.stringify(auth.scheme)} is not one of `
      + `${SCHEMES.join(', ')}. Refused rather than defaulted: guessing a scheme would send a `
      + 'credential in a form the TSA does not expect, which looks like a bad credential.');
  }
  if (typeof auth.env !== 'string' || !/^[A-Z_][A-Z0-9_]*$/.test(auth.env)) {
    throw new WitnessConfigError(
      `witness ${id}: auth.env must be the NAME of an environment variable, got `
      + `${JSON.stringify(auth.env)}. The config names where the secret is; it never holds it, `
      + 'because a witness config file gets committed.');
  }
  // The commonest way to get this wrong is to paste the secret in.
  if (/^(?:sk-|Bearer |Basic )/i.test(auth.env) || auth.env.length > 64) {
    throw new WitnessConfigError(
      `witness ${id}: auth.env looks like a credential rather than a variable name. It must be the `
      + 'NAME of an environment variable holding the secret.');
  }
  if (auth.scheme === 'header') {
    if (typeof auth.header !== 'string' || auth.header === '') {
      throw new WitnessConfigError(`witness ${id}: auth.scheme "header" needs auth.header`);
    }
    if (/[^A-Za-z0-9-]/.test(auth.header)) {
      throw new WitnessConfigError(
        `witness ${id}: auth.header ${JSON.stringify(auth.header)} is not a valid header token. A `
        + 'newline in a header name is request splitting.');
    }
    // Checked HERE as well as in the adapter. The adapter is the last line and
    // must refuse regardless of how it was constructed, but an operator should
    // learn about a bad config when the witness set is built -- not on the
    // first checkpoint, after the request has already been malformed once.
    const RESERVED = ['content-type', 'accept', 'authorization', 'host', 'content-length'];
    if (RESERVED.includes(auth.header.toLowerCase())) {
      throw new WitnessConfigError(
        `witness ${id}: auth.header may not be ${JSON.stringify(auth.header)}. The auth headers are `
        + 'applied over the request\'s own, so this one would replace part of the RFC 3161 request '
        + 'with the credential — the submission would stop being a timestamp query and the secret '
        + `would go into a header the TSA logs. Reserved: ${RESERVED.join(', ')}. For `
        + 'authorization use scheme bearer or basic.');
    }
  }
  return {
    scheme: auth.scheme, env: auth.env,
    ...(auth.header ? { header: auth.header } : {}),
  };
}

/**
 * A credential may not be configured against a cleartext endpoint — LEG-13.
 *
 * The adapter refuses this at construction too, and that is the line that
 * actually protects the secret. This exists so the refusal names the WITNESS
 * and arrives while the operator is reading their config, rather than as an
 * adapter error from inside the anchoring loop.
 *
 * @param {string} id @param {string|undefined} url
 */
function refuseCleartextCredential(id, url) {
  if (typeof url !== 'string') return;
  let host = null;
  try { host = new URL(url).hostname.replace(/^\[|\]$/g, ''); } catch { host = null; }
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (!url.startsWith('https://') && !loopback) {
    throw new WitnessConfigError(
      `witness ${id} is configured with a credential and a plain-HTTP endpoint (${url}). A bearer `
      + 'token or basic credential on the wire in the clear is readable by anything on the path, '
      + 'and basic auth is base64 — an encoding, not encryption. Use https://, or a loopback '
      + 'address for a local test server.');
  }
}

/** The types this builder knows. An unknown type is refused, never ignored. */
export const WITNESS_TYPES = Object.freeze([
  'rfc3161', 'opentimestamps', 'rekor', 'tlog-witness', 'splitstick',
]);

/**
 * @param {{ witnesses?: { id: string, type: string, url?: string, tier?: string,
 *   calendars?: string[], key?: string, self_hosted?: boolean, qualified?: boolean,
 *   auth?: { scheme?: string, env?: string, header?: string } }[] }} config
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
    // SEC-25's declaration, attached HERE because this is the only place that
    // knows the configured type.
    //
    // It used to be looked up by `proof_type` at description time, and the two
    // are not the same vocabulary: `splitstick`, `rekor` and `tlog-witness`
    // all have proof_type `c2sp-note`, so the lookup returned undefined and
    // those witnesses were described with NO time discipline at all. Rekor's
    // entry had been sitting in the table unreachable. The test did not see it
    // because it only ever built an `rfc3161` witness, the one type whose
    // config name and proof type happen to be the same string — a seam
    // exercised once.
    const discipline = /** @type {Record<string, string>} */ (TIME_DISCIPLINE)[w.type];
    if (discipline === undefined) {
      throw new WitnessConfigError(
        `witness type ${JSON.stringify(w.type)} declares no time discipline (SEC-25). A report `
        + 'that presented its countersignature beside the others would imply an authority about '
        + 'time that nothing here established.',
      );
    }
    const declare = (/** @type {any} */ a) => { a.time_discipline = discipline; return a; };
    switch (w.type) {
      case 'rfc3161':
        out.push(declare(tsaWitness({
          id: w.id,
          url: /** @type {string} */ (w.url),
          ...(w.qualified ? { qualified: true } : {}),
          // LEG-13 — a credential for a commercial qualified service. Validated
          // HERE rather than at submission time: a config whose auth block is
          // malformed should fail when the witness set is built, not minutes
          // later on a checkpoint, and not silently as an anonymous request
          // that the TSA then rejects.
          ...(w.auth ? (refuseCleartextCredential(w.id, w.url),
            { auth: validateTsaAuth(w.id, w.auth) }) : {}),
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        })));
        break;
      case 'opentimestamps':
        out.push(declare(otsWitness({
          id: w.id,
          calendars: w.calendars ?? [...DEFAULT_CALENDARS],
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        })));
        break;
      case 'rekor':
        out.push(declare(rekorWitness({
          id: w.id,
          url: /** @type {string} */ (w.url),
          ...(tier ? { tier } : {}),
          ...(w.self_hosted ? { selfHosted: true } : {}),
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        })));
        break;
      case 'tlog-witness':
        out.push(declare(tlogWitness({
          id: w.id,
          url: /** @type {string} */ (w.url),
          ...(tier ? { tier } : {}),
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
        })));
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
    // From the adapter, which carries what its configured type declared.
    const d = /** @type {any} */ (w).time_discipline;
    if (typeof d === 'string' && d !== '') time_discipline[w.id] = d;
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
  return [
    ...describeWitnessSet(witnessesFromConfig({
      witnesses: [
        { id: 'tsa', type: 'rfc3161', url: 'https://tsa.invalid' },
        { id: 'ots', type: 'opentimestamps', tier: 'rollup' },
      ],
    })).warnings,
    // THE EGRESS, disclosed rather than discovered — added in M7.
    //
    // This function disclosed the capability gap and said nothing about the
    // fact that the shipped default reaches two public third-party services.
    // That is FR-48 working as intended: a default the project neither
    // operates nor overloads, independent of us on day one. But an operator
    // who has not read design/default-config.yaml learns it from traffic, and
    // "has not read the documentation" is the condition a default exists to
    // serve. OPS-05 supports a zero-egress deployment; it does not make this
    // one silent.
    'the shipped default ANCHORS OUTWARD: a public RFC 3161 timestamp authority per batch and '
    + 'the OpenTimestamps calendars on the roll-up tier. Both are third parties this project '
    + 'neither operates nor pays for (FR-48), which is what makes the default independent of us '
    + '— and it is still traffic leaving your perimeter, carrying a checkpoint note: an origin, '
    + 'a tree size, a root and signatures, and no payload (PRIV-01). For a deployment with no '
    + 'egress at all, configure a witness you host yourself and remove these — see '
    + 'docs/self-hosted-witness.md (OPS-03, OPS-05)',
  ];
}
