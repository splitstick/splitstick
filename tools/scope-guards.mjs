// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The scope guards, as patterns — SCOPE-01 to SCOPE-16, LEG-14 to LEG-16,
 * SEC-16, TRC-05.
 *
 * Sixteen MUST NOTs whose stated verify is "claims audit across all surfaces".
 * A review is a thing somebody skips, so they are checked — but a check whose
 * pattern is too narrow is WORSE than the review it replaced: a skipped review
 * fails visibly, because nobody signed it off, while a narrow check goes green
 * and the release ships. The conclusion being reported here is "we have not
 * overclaimed", which makes this the worst file in the repository to be
 * casually optimistic in.
 *
 * So each guard is a pair: `forbids`, which must fire on a violation, and
 * `allows`, which exempts the legitimate way to use the same words — because
 * the correct way to write about "tamper-proof" is to say we do not claim it,
 * and a guard that punished that would be switched off within a week.
 *
 * Matching is SENTENCE-SCOPED through the shared helper, for the reason LEG-12
 * is: a disclaimer three sentences later satisfies a paragraph check while the
 * reader takes the claim from the first sentence and stops.
 *
 * EVERY GUARD HAS A COMPANION TEST that breaks it on purpose. Not a sample —
 * each one, against text violating exactly that guard and against honest prose
 * that must not fire. See test/scope-guards.test.mjs; the list there is
 * asserted to cover every entry in this file, so a guard added without a
 * companion fails the suite.
 */

import { NEGATION } from './claim-text.mjs';

/**
 * @typedef {object} Guard
 * @property {string} id the requirement it enforces
 * @property {string} what the one-line rule
 * @property {RegExp} forbids what a violation looks like
 * @property {RegExp} [absolute] a violation NO negation can rescue, because the
 *   forbidden claim is itself phrased in the negative. "A record cannot be
 *   altered" is the tamper-proof claim, and the negation exemption swallowed it
 *   whole — found by the companion test, which is what the companion is for.
 * @property {RegExp} [allows] the legitimate use of the same words
 * @property {boolean} [negationExempt] when a denial in the sentence is enough
 *   to make it honest. True for most claim guards; false where the forbidden
 *   thing is a WORD we will not print at all.
 * @property {string} why what goes wrong if this ships
 */

/** @type {Guard[]} */
export const GUARDS = [
  {
    id: 'SCOPE-02, SEC-16',
    what: 'never tamper-proof; tamper-evident with attribution',
    // `immutable` is restricted to the PRODUCT-LEVEL noun. "An immutable
    // record kind" in a schema specification means the kind is not rewritten;
    // "an immutable audit log" is the marketing claim SEC-16 forbids, and a
    // guard that conflated them fired on DES-05 for describing a padding leaf.
    forbids: /\btamper[\s-]?proof(?:ing)?\b|\bimmutable (?:audit )?(?:log|ledger|trail)\b/i,
    // These need no negation to be an overclaim — they ARE the overclaim,
    // written in the negative. `cannot` is in the negation set, so
    // `negationExempt` exempted "a record cannot be altered" from the guard
    // against claiming records cannot be altered.
    absolute: /\bunalterable\b|\bcannot be (?:altered|modified|tampered|changed|rewritten)\b|\bimpossible to (?:alter|modify|tamper|rewrite)\b/i,
    // …unless the sentence says what is actually true: it cannot be altered
    // WITHOUT DETECTION, which is the whole product.
    allows: /\bwithout detection\b|\bundetected\b|\bwithout leaving\b|\bwithout being detected\b|\btamper[\s-]?evident\b/i,
    negationExempt: true,
    why: 'the product detects and attributes tampering; it does not prevent it, and an operator '
      + 'who believes otherwise will not keep the second party the detection depends on',
  },
  {
    id: 'LEG-14',
    what: 'no EU AI Act conformity claim',
    forbids: /\b(?:AI Act|EU AI Act)\b[^.]{0,80}\b(?:conform\w*|compliant|compliance)\b|\b(?:conform\w*|compliant)\b[^.]{0,40}\b(?:AI Act|EU AI Act)\b/i,
    negationExempt: true,
    why: 'conformity is assessed by a body, not asserted by a vendor, and a tool cannot confer it',
  },
  {
    id: 'LEG-15, SCOPE-03',
    what: 'never certify the customer or imply a compliance certificate',
    forbids: /\b(?:certif\w+|attest\w+)\b[^.]{0,60}\b(?:your|the customer'?s?|client'?s?)\b[^.]{0,40}\b(?:compliance|conformity|obligations?)\b|\bcompliance certificate\b|\bcertificate of compliance\b|\bcertifies? (?:your|their|the customer'?s?)\b/i,
    negationExempt: true,
    why: 'we produce evidence; a conclusion about somebody else\'s legal obligations belongs to '
      + 'them and their counsel',
  },
  {
    id: 'SCOPE-04',
    what: 'not a replacement for traces, SIEM or dashboards',
    forbids: /\breplace(?:s|ment for)?\b[^.]{0,60}\b(?:SIEM|observability|tracing|traces|dashboards?|APM|monitoring)\b|\b(?:instead of|in place of)\b[^.]{0,40}\b(?:SIEM|observability|tracing|dashboards?)\b/i,
    negationExempt: true,
    why: 'it is an evidence recorder, and an observability claim invites an operator to stop '
      + 'keeping the thing they actually need for operations',
  },
  {
    id: 'SCOPE-12',
    what: 'no TEE suppression claim',
    forbids: /\b(?:TEE|enclave|SGX|SEV|trusted execution)\b[^.]{0,90}\b(?:impossible|prevents?|guarantees?|eliminat\w+|rules? out)\b[^.]{0,40}\b(?:suppress\w*|omission|drop\w*|withhold\w*)\b|\b(?:suppress\w*|omission)\b[^.]{0,60}\bimpossible\b/i,
    // The same shape as SEC-16's: this claim is naturally phrased in the
    // NEGATIVE — "guarantees no action can be dropped", "ensures nothing is
    // suppressed" — so the negation exemption handed it a pass for being
    // written the way such a claim is always written.
    absolute: /\b(?:TEE|enclave|SGX|SEV|trusted execution)\b[^.]{0,70}\b(?:guarantees?|ensures?|means|makes it so)\b[^.]{0,40}\b(?:no|nothing|none|cannot|can't|never)\b/i,
    // The honest sentence says the opposite, and must survive: "a TEE does not
    // make suppression impossible: it cannot make a collector report an action
    // it never observed".
    allows: /\b(?:does not|doesn't|cannot|can't|will not|won't) (?:make|render|prevent)\b|\bnot a guarantee\b|\bwould narrow\b/i,
    negationExempt: true,
    why: 'a TEE does not make a collector report an action it never observed, and this exact '
      + 'claim was rejected by SCOPE-12 rather than scheduled',
  },
  {
    id: 'SCOPE-14',
    what: 'no self-scored attacks-defeated metric',
    // ORDER-AGNOSTIC. The first version required the figure before the noun
    // before the verb, so `defeats 12 of 12 attacks` — the most natural way to
    // write the forbidden claim — walked straight past it.
    //
    // What distinguishes the forbidden metric from honest reporting is the
    // VERB, not the arithmetic: a regex cannot tell 12-of-12 from 9-of-12, and
    // it does not need to. "9 of 12 tampers are detected and the other three
    // are named" is the red-team suite doing its job; "defeats 12 of 12" is a
    // score. `detect` is not a defeat verb, which is the whole distinction.
    forbids: /\b(?:defeat\w*|thwart\w*|beat\w*|neutralis\w*|neutraliz\w*)\b[^.]{0,60}\b(?:attacks?|tampers?)\b|\b(?:attacks?|tampers?)\b[^.]{0,60}\b(?:defeated|thwarted|neutralised|neutralized)\b|\b(?:block\w*|stop\w*|prevent\w*)\b[^.]{0,40}\b(?:all|every|100%|\d+\s*(?:of|\/|out of)\s*\d+)\b[^.]{0,30}\b(?:attacks?|tampers?)\b|\b100%\s*(?:of\s*)?(?:attacks?|tampers?)\b/i,
    // DOC-03 requires publishing rejected designs with reasons, and the
    // N-of-N metric is one of the things this project rejected BY NAME. The
    // log that records that must be able to say so.
    allows: /\b(?:cut|rejected|reject|considered and rejected|not on the roadmap|proposed as|out of scope|we will not|declined|in place of)\b/i,
    negationExempt: true,
    why: 'a self-scored defeat metric is marketing in a benchmark\'s clothes. The red-team suite '
      + 'reports which classes are NOT closed, which is the opposite discipline',
  },
  {
    id: 'SCOPE-01, SCOPE-16',
    what: 'never blocks, gates or filters an agent action',
    // PRODUCT VOICE only. The first version matched any sentence containing
    // "stop an agent run", which caught DES-09 explaining that a configuration
    // able to stop a run is a configuration that will, at 3 a.m. — the project
    // refusing the thing, in the words of the thing, with no negation token to
    // save it. Prose cannot reliably tell "we do X" from "doing X would be
    // bad", so the prose guard is narrowed to offers of the capability and the
    // REAL guard for SCOPE-01 and SCOPE-16 is structural: their stated verifies
    // are "code review; no enforcement path exists" and "config schema review",
    // which tools/lint-enforcement.mjs checks against the code.
    forbids: /\b(?:splitstick|the collector|the proxy|it)\s+(?:can |will |may )?(?:block|gate|filter|deny|veto)s?\b|\b(?:configure|enable|set)\w*\b[^.]{0,30}\bto (?:block|gate|deny|halt)\b|\bfail[\s-]closed\s+(?:mode|option|setting|flag|build)\b|\benforcement (?:mode|path|option)\b/i,
    negationExempt: true,
    why: 'fail-open is a design constraint and not a setting (SCOPE-16). A collector that can '
      + 'stop a run is one an operator rightly disables, and then it captures nothing',
  },
  {
    id: 'SCOPE-11',
    what: 'no zero-knowledge compliance proofs, not even on the roadmap',
    forbids: /\bzero[\s-]knowledge\b|\bzk[\s-](?:proof|snark|stark|compliance)\b|\bZK(?:P|-SNARK|-STARK)\b/i,
    // DOC-03 REQUIRES publishing rejected designs with reasons, so the
    // considered-and-rejected log names this by obligation. A guard that
    // forbade naming it would forbid DOC-03.
    allows: /\b(?:cut|rejected|reject|considered and rejected|not on the roadmap|proposed as|out of scope|we will not|declined)\b/i,
    negationExempt: true,
    why: 'SCOPE-11 forbids it in the tree AND on the roadmap, so even a plan is a violation',
  },
  {
    id: 'SCOPE-10',
    what: 'no verifiable delay function',
    forbids: /\bverifiable delay function\b|\bVDF\b/i,
    allows: /\b(?:cut|rejected|reject|considered and rejected|not on the roadmap|proposed as|out of scope|we will not|declined)\b/i,
    negationExempt: true,
    why: 'SCOPE-10 rejects it; shipping or planning one re-opens a decision already taken',
  },
  {
    id: 'SCOPE-13',
    what: 'no blockchain as the primary ledger',
    forbids: /\b(?:blockchain|on[\s-]chain|smart contract)\b[^.]{0,50}\b(?:primary|the ledger|as the log|stores? the (?:log|record))\b|\bledger\b[^.]{0,30}\bon (?:a |the )?(?:blockchain|chain)\b/i,
    allows: /\b(?:cut|rejected|reject|considered and rejected|not on the roadmap|proposed as|out of scope|we will not|declined)\b/i,
    negationExempt: true,
    why: 'a public chain is permitted only as the optional hard anchor, which the OpenTimestamps '
      + 'tier already is. As the ledger it would make every record public and the cost per '
      + 'record somebody else\'s decision',
  },
  {
    id: 'DOC-04, TRC-04',
    what: 'an unverified figure is a target, not a measurement',
    forbids: /\b(?:achieves?|delivers?|measured at|sustains?|guarantees?)\b[^.]{0,30}\b(?:p9[59]|sub-?millisecond|under \d+\s*(?:ms|µs|us))\b/i,
    negationExempt: true,
    why: 'NFR-01, NFR-02 and NFR-04 have no qualifying run; a figure stated as fact without one '
      + 'is the overclaim TRC-04 exists to block',
  },
];

/**
 * Guards over the TREE rather than the prose — the "release inventory" and
 * "code review" verifies.
 *
 * Separate because the question is different: not "what did we say" but "what
 * did we ship". A positioning statement can be corrected in an afternoon; a
 * reviewer UI in the open-source release is a different product.
 *
 * @typedef {object} TreeGuard
 * @property {string} id
 * @property {string} what
 * @property {RegExp} forbids matched against SOURCE with comments stripped, so
 *   a paragraph explaining that we do not ship RBAC is not read as RBAC
 * @property {string} why
 */

/** @type {TreeGuard[]} */
export const TREE_GUARDS = [
  {
    id: 'SCOPE-05',
    what: 'no reviewer surface in the open-source release',
    forbids: /\b(?:reviewer|approval)\s*(?:UI|dashboard|console|web\s*app)\b/i,
    why: 'SCOPE-05 keeps the reviewer surface out of the OSS release',
  },
  {
    id: 'SCOPE-06',
    what: 'no SSO in the open-source release',
    forbids: /\b(?:SSO|SAML|OIDC|OpenID Connect)\b/i,
    why: 'SCOPE-06 keeps SSO out of the OSS release',
  },
  {
    id: 'SCOPE-07',
    what: 'no RBAC in the open-source release',
    forbids: /\bRBAC\b|\brole[\s-]based access\b/i,
    why: 'SCOPE-07 keeps RBAC out of the OSS release',
  },
  {
    id: 'SCOPE-08',
    what: 'no multi-tenancy in the open-source release',
    forbids: /\bmulti[\s-]?tenan\w+\b|\btenant[\s_]?id\b/i,
    why: 'SCOPE-08 keeps multi-tenancy out of the OSS release',
  },
  {
    id: 'SCOPE-09',
    what: 'no retention tiers in the open-source release',
    forbids: /\bretention\s*(?:tier|policy|class|plan)s?\b|\b(?:hot|warm|cold)\s*(?:tier|storage)\b/i,
    why: 'SCOPE-09 keeps retention tiers out of the OSS release',
  },
  {
    id: 'SCOPE-10',
    what: 'no verifiable delay function in the tree',
    forbids: /\bverifiable delay function\b|\bVDF\b/i,
    why: 'SCOPE-10 rejects it',
  },
  {
    id: 'SCOPE-11',
    what: 'no zero-knowledge proofs in the tree',
    forbids: /\bzero[\s-]knowledge\b|\bzk[\s-](?:proof|snark|stark)\b|\bsnarkjs\b|\bcircomlib\b/i,
    why: 'SCOPE-11 rejects it in the tree and on the roadmap',
  },
  {
    id: 'SCOPE-13',
    what: 'no blockchain dependency as a ledger',
    forbids: /\b(?:web3|ethers|solana|bitcoinjs|smart[\s-]?contract)\b/i,
    why: 'SCOPE-13 permits a public chain only as the optional hard anchor, which the '
      + 'OpenTimestamps adapter reaches over plain HTTP without a chain client',
  },
];

/**
 * Does `sentence` violate `guard`?
 *
 * A sentence containing a denial passes a `negationExempt` guard, because the
 * correct way to write about a claim we refuse is to refuse it by name. That
 * exemption is the guard's biggest hole and it is deliberate: without it the
 * guards would forbid the project's own honesty, and a guard that forbids
 * honesty is a guard somebody deletes.
 * @param {Guard} guard @param {string} sentence
 */
export function violates(guard, sentence) {
  if (guard.allows?.test(sentence)) return false;
  // Checked FIRST and never exempted. A claim phrased in the negative carries
  // a negation token by construction, so running it through the exemption
  // would hand it a pass for being written the way it is written.
  if (guard.absolute?.test(sentence)) return true;
  if (!guard.forbids.test(sentence)) return false;
  if (guard.negationExempt && NEGATION.test(sentence)) return false;
  return true;
}
