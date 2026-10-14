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
 *
 * ── AND THE COMPANIONS WERE NOT ENOUGH ───────────────────────────────────
 *
 * The first version of this file passed its companions and then missed TWENTY
 * OUT OF TWENTY realistic violations when the review probed it with sentences
 * a marketer would actually write: "Your agent logs become permanent and
 * unchangeable", "Be audit-ready for the EU AI Act in an afternoon", "Hand
 * your auditor a Splitstick report and you are compliant", "retire your SIEM",
 * "we withstood every attack tried". Every one walked through.
 *
 * The reason is worth stating plainly, because it is the exact failure this
 * milestone was built to prevent and it landed here first: the companions were
 * written from the patterns. Each violating example was phrased to match a
 * regex that had just been typed, so the test asked "does this pattern fire on
 * text I wrote for it" and not "does it catch what somebody would actually
 * write". docs/risk-assessment.md already said a companion has to answer the
 * second question. It did not.
 *
 * So the corpus in test/scope-guards.test.mjs is now written FIRST, in the
 * voice of somebody selling the product or shipping the feature, and the
 * patterns are fitted to it. That ordering is the whole correction.
 */

import { NEGATION, clauseAt } from './claim-text.mjs';

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
    forbids: /\btamper[\s-]?proof(?:ing)?\b|\bimmutable (?:audit )?(?:log|ledger|trail)\b|\bforgery[\s-]?(?:proof|resistant)\b|\b(?:permanent|unchangeable|unmodifiable|indelible|write[\s-]once|WORM)\b[^.]{0,40}\b(?:record|log|trail|histor\w+|evidence)\b|\b(?:record|log|trail|histor\w+|evidence)s?\b[^.]{0,40}\b(?:permanent|unchangeable|unmodifiable|indelible|final and|tamper[\s-]?resistant)\b/i,
    // These need no negation to be an overclaim — they ARE the overclaim,
    // written in the negative. `cannot` is in the negation set, so
    // `negationExempt` exempted "a record cannot be altered" from the guard
    // against claiming records cannot be altered.
    // THE OBJECT HAS TO BE THE RECORD. Without that, this fired on eleven
    // honest sentences across the repository — "Nobody can prove they deleted
    // a key", "nothing here changes that", and the verifier's own
    // "the signature could not be forged", which is TRUE and is the product's
    // actual claim. A negative sentence containing an alteration verb is not
    // an integrity overclaim; a negative sentence saying the RECORD cannot be
    // altered is exactly one.
    absolute: /\bunalterable\b[^.]{0,30}\b(?:record|log|trail|histor\w+|evidence|entr\w+)\b|\b(?:record|log|trail|histor\w+|evidence|entr\w+)s?\b[^.]{0,30}\bunalterable\b|\b(?:cannot|can't|could not|couldn't) be (?:altered|modified|tampered with|changed|rewritten|edited|deleted|removed|faked|forged)\b[^.]{0,40}\b(?:record|log|trail|histor\w+|evidence|entr\w+)\b|\b(?:record|log|trail|histor\w+|evidence|entr\w+)s?\b[^.]{0,50}\b(?:cannot|can't|could not|couldn't) be (?:altered|modified|tampered with|changed|rewritten|edited|deleted|removed|faked|forged)\b|\bimpossible to (?:alter|modify|tamper with|rewrite|edit|delete|forge)\b[^.]{0,40}\b(?:record|log|trail|histor\w+|evidence|entr\w+)\b|\b(?:nobody|no one|no-one|not even you)\b[^.]{0,50}\b(?:rewrite|alter|modify|change|edit|delete|tamper with)\w*\b[^.]{0,30}\b(?:record|log|trail|histor\w+|evidence|entr\w+)\b/i,
    // …unless the sentence says what is actually true: it cannot be altered
    // WITHOUT DETECTION, which is the whole product.
    // …unless the sentence says what is actually true: it cannot be altered
    // WITHOUT DETECTION, which is the whole product. And unless it is about
    // somebody else's public log — `spec/witnesses.json` discloses that an
    // OpenTimestamps or Rekor entry is public and cannot be removed, which is
    // a true statement about a third party's retention and an FR-47
    // obligation, not an integrity claim about our records.
    allows: /\bwithout detection\b|\bundetected\b|\bwithout leaving\b|\bwithout being detected\b|\btamper[\s-]?evident\b|\bretains?_publicly\b|\bretention_note\b/i,
    negationExempt: true,
    why: 'the product detects and attributes tampering; it does not prevent it, and an operator '
      + 'who believes otherwise will not keep the second party the detection depends on',
  },
  {
    id: 'LEG-14',
    what: 'no EU AI Act conformity claim',
    // The AI Act named alongside ANY product positioning. A vendor does not
    // write "we assert conformity"; they write "your AI Act solution" and
    // "audit-ready for the EU AI Act", and both were missed.
    // POSITIONING OF THE PRODUCT, not discussion of the statute. `Article \d+`
    // and `requirements` were in this list and fired on
    // docs/threat-model.md's "EU AI Act Article 12 asks for tamper-evident
    // records, not impossible ones" — which describes what the regulation
    // asks for and claims nothing. Naming what a statute requires is how you
    // write honestly about it; a guard that forbade that would forbid the
    // threat model.
    forbids: /\b(?:EU )?AI Act\b[^.]{0,90}\b(?:conform\w*|compliant|compliance|solution|ready|covered|handled|satisf\w+|take care of)\b|\b(?:conform\w*|compliant|compliance|audit[\s-]ready|ready)\b[^.]{0,60}\b(?:EU )?AI Act\b/i,
    negationExempt: true,
    why: 'conformity is assessed by a body, not asserted by a vendor, and a tool cannot confer it',
  },
  {
    id: 'LEG-15, SCOPE-03',
    what: 'never certify the customer or imply a compliance certificate',
    forbids: /\b(?:certif\w+|attest\w+)\b[^.]{0,60}\b(?:your|the customer'?s?|client'?s?)\b[^.]{0,40}\b(?:compliance|conformity|obligations?)\b|\bcompliance (?:certificate|attestation|report that)\b|\bcertificate of compliance\b|\bcertifies? (?:your|their|the customer'?s?)\b|\byou (?:are|become|will be) compliant\b|\bmakes? you compliant\b|\b(?:signed|issues?) (?:a )?compliance attestation\b|\bproof of compliance\b|\bcompliance (?:is )?(?:proven|established|demonstrated)\b/i,
    negationExempt: true,
    why: 'we produce evidence; a conclusion about somebody else\'s legal obligations belongs to '
      + 'them and their counsel',
  },
  {
    id: 'SCOPE-04',
    what: 'not a replacement for traces, SIEM or dashboards',
    forbids: /\b(?:replace\w*|retire|rip out|drop|decommission|supersede\w*|sunset)\b[^.]{0,60}\b(?:SIEM|observability|tracing|traces|dashboards?|APM|monitoring|log aggregation)\b|\b(?:instead of|in place of|no longer need)\b[^.]{0,50}\b(?:SIEM|observability|tracing|dashboards?|APM|monitoring)\b|\bone pane of glass\b|\bsingle source of truth\b[^.]{0,40}\b(?:observability|operations?|monitoring)\b/i,
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
    absolute: /\b(?:TEE|enclave|SGX|SEV|trusted execution|secure enclave)\b[^.]{0,80}\b(?:guarantees?|ensures?|means|makes it so|so)\b[^.]{0,50}\b(?:no|nothing|none|cannot|can't|never)\b|\b(?:TEE|enclave|SGX|SEV|secure enclave)\b[^.]{0,80}\bnothing (?:can be )?(?:hidden|suppressed|dropped|withheld|concealed)\b/i,
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
    forbids: /\b(?:defeat\w*|thwart\w*|beat\w*|neutralis\w*|neutraliz\w*)\b[^.]{0,60}\b(?:attacks?|tampers?)\b|\b(?:attacks?|tampers?)\b[^.]{0,60}\b(?:defeated|thwarted|neutralised|neutralized)\b|\b(?:block\w*|stop\w*|prevent\w*)\b[^.]{0,40}\b(?:all|every|100%|\d+\s*(?:of|\/|out of)\s*\d+)\b[^.]{0,30}\b(?:attacks?|tampers?)\b|\b100%\s*(?:of\s*)?(?:attacks?|tampers?)\b|\b(?:withstood|survived|resisted|repelled|held against)\b[^.]{0,40}\b(?:every|all|each)\b[^.]{0,30}\b(?:attack|tamper|attempt)\w*\b|\bno attack\b[^.]{0,40}\b(?:succeeded|worked|got through|defeated)\b|\bunbeaten\b|\bnever been (?:broken|beaten|defeated)\b/i,
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
    forbids: /\b(?:splitstick|the collector|the proxy|it)\s+(?:can |will |may )?(?:block|gate|filter|deny|veto|intercept|prevent)s?\b|\b(?:configure|enable|set)\w*\b[^.]{0,30}\bto (?:block|gate|deny|halt|intercept)\b|\bfail[\s-]closed\s+(?:mode|option|setting|flag|build)\b|\benforcement (?:mode|path|option)\b|\b(?:intercepted|blocked|stopped|prevented|refused|rejected)\b[^.]{0,50}\bbefore\b[^.]{0,40}\b(?:tool|action|call|runs?|executes?)\b|\b(?:policy|policies)\b[^.]{0,40}\b(?:enforced|enforcement)\b/i,
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
    forbids: /\b(?:achieves?|achieved|delivers?|measured at|benchmarked at|sustains?|guarantees?|runs at|clocks? in at)\b[^.]{0,40}\b(?:p9[59]|sub-?millisecond|[\d.]+\s*(?:ms|µs|us|%)|under [\d.]+\s*(?:ms|µs|us))\b|\b[\d.]+\s*(?:ms|µs|us)\b[^.]{0,30}\bin production\b/i,
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

/**
 * @type {TreeGuard[]}
 *
 * FITTED TO WHAT AN IMPLEMENTATION LOOKS LIKE, not to the word in the
 * requirement. The first version matched `reviewer UI`, `SSO`, `RBAC`,
 * `multi-tenant`, `retention tier` — the vocabulary of the prohibition — and
 * missed every realistic addition the review probed it with:
 * `renderApprovalConsole`, `new OidcClient`, `user.roles.includes`,
 * `resolveTenant`, `moveToColdStorage`, `wesolowskiProof`,
 * `groth16.fullProve`, `wallet.sendTransaction`. Eight for eight.
 *
 * These are the worse half of the audit to get wrong, because they are the
 * RELEASE INVENTORY — the question is not what we said but what we shipped,
 * and a reviewer UI does not announce itself by containing the string
 * "reviewer UI".
 *
 * Two kinds of signal, because identifiers alone are guessable and
 * dependencies alone are evadable:
 *
 *   identifiers   what the code would be called
 *   dependencies  what it would have to import. A ZK proof needs a proving
 *                 library; SSO needs an OIDC or SAML client; a chain write
 *                 needs a wallet or an RPC client. Those are hard to do
 *                 without and easy to see.
 */
export const TREE_GUARDS = [
  {
    id: 'SCOPE-05',
    what: 'no reviewer surface in the open-source release',
    forbids: /\b(?:reviewer|approval|review)\s*(?:UI|dashboard|console|web\s*app|page|screen|view)\b|\brender(?:Approval|Review|Reviewer)\w*\b|\b(?:approve|reject)(?:Button|Action|Handler)\b|\bexpress\b|\bfastify\b|\breact-dom\b/i,
    why: 'SCOPE-05 keeps the reviewer surface out of the OSS release. A web framework in this '
      + 'tree is the shape that arrives first, and nothing here needs one',
  },
  {
    id: 'SCOPE-06',
    what: 'no SSO in the open-source release',
    forbids: /\b(?:SSO|SAML|OIDC|OpenID Connect)\b|\b(?:oidc|saml|passport|openid)[-\w]*client\b|\bOidcClient\b|\bpassport-\w+\b|\bauthorization_endpoint\b|\bid_token\b/i,
    why: 'SCOPE-06 keeps SSO out of the OSS release',
  },
  {
    id: 'SCOPE-07',
    what: 'no RBAC in the open-source release',
    forbids: /\bRBAC\b|\brole[\s-]based access\b|\b(?:user|actor|principal)\.roles?\b|\bhasRole\b|\brequireRole\b|\bpermissions?\.(?:includes|has)\b|\bcan(?:Read|Write|View|Edit)\b/i,
    why: 'SCOPE-07 keeps RBAC out of the OSS release. A role check is the whole of RBAC in '
      + 'embryo, whatever the file is called',
  },
  {
    id: 'SCOPE-08',
    what: 'no multi-tenancy in the open-source release',
    forbids: /\bmulti[\s-]?tenan\w+\b|\btenant[\s_]?id\b|\bresolveTenant\b|\btenantFor\b|\bper[\s-]tenant\b|\borg(?:anisation|anization)?[\s_]?id\b/i,
    why: 'SCOPE-08 keeps multi-tenancy out of the OSS release',
  },
  {
    id: 'SCOPE-09',
    what: 'no retention tiers in the open-source release',
    forbids: /\bretention\s*(?:tier|policy|class|plan|schedule)s?\b|\b(?:hot|warm|cold|archive|glacier)\s*(?:tier|storage)\b|\bmoveTo(?:Cold|Warm|Archive|Glacier)\w*\b|\bexpireAfter\b|\bttlDays\b/i,
    why: 'SCOPE-09 keeps retention tiers out of the OSS release. DES-13 is erasure on request, '
      + 'which is a different thing from a lifecycle that ages evidence out on a schedule',
  },
  {
    id: 'SCOPE-10',
    what: 'no verifiable delay function in the tree',
    forbids: /\bverifiable delay function\b|\bVDF\b|\bwesolowski\w*\b|\bpietrzak\w*\b|\bsequential(?:Work|Proof)\b|\bclass ?group\b/i,
    why: 'SCOPE-10 rejects it. The construction names are the giveaway: nobody writes a VDF '
      + 'without naming Wesolowski or Pietrzak somewhere',
  },
  {
    id: 'SCOPE-11',
    what: 'no zero-knowledge proofs in the tree',
    forbids: /\bzero[\s-]knowledge\b|\bzk[\s-]?(?:proof|snark|stark|circuit)\b|\bsnarkjs\b|\bcircomlib\b|\bcircom\b|\bgroth16\b|\bplonk\b|\bhalo2\b|\bbellman\b|\barkworks\b|\.zkey\b|\bwitnessCalculator\b/i,
    why: 'SCOPE-11 rejects it in the tree and on the roadmap. A ZK proof cannot be built '
      + 'without a proving library, and the library names are the reliable signal',
  },
  {
    id: 'SCOPE-13',
    what: 'no blockchain dependency as a ledger',
    forbids: /\b(?:web3|ethers|viem|solana|bitcoinjs|@solana|wagmi)\b|\bsmart[\s-]?contract\b|\bsendTransaction\b|\bsignTransaction\b|\bJsonRpcProvider\b|\beth_(?:sendRawTransaction|call)\b|\bwallet\.(?:send|sign)\w*\b/i,
    why: 'SCOPE-13 permits a public chain only as the optional hard anchor, which the '
      + 'OpenTimestamps adapter reaches over plain HTTP with no chain client, no wallet and no '
      + 'transaction. A wallet or an RPC provider in this tree is the ledger arriving',
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
  // Detection reads the WHOLE sentence; exemption reads only the clause the
  // match sits in.
  //
  // Both used to read the whole sentence, and nine of ten crafted evasions got
  // through: a denial about something else, or an exemption word in an
  // unrelated clause, shielded the overclaim. "Splitstick is not slow, and
  // your logs are permanent and unchangeable" passed because of `not slow`.
  // "Splitstick is tamper-evident, and your records are permanent and
  // unchangeable" passed because `tamper-evident` is in `allows`. Marketing
  // copy pairs a negative hook with a positive claim as a matter of course, so
  // in the real world the exemption was nearly always available.
  //
  // An exemption has to be attached to the thing it exempts. "tamper-evident,
  // not tamper-proof" and "we do not claim an immutable audit log" keep the
  // denial in the same clause as the phrase, which is what makes them honest
  // rather than merely adjacent to something honest.
  const exempt = (/** @type {RegExp|undefined} */ re, /** @type {number} */ at) => {
    if (re === undefined) return false;
    return re.test(clauseAt(sentence, at));
  };

  const abs = guard.absolute?.exec(sentence) ?? null;
  if (abs !== null) {
    if (exempt(guard.allows, abs.index)) return false;
    // Never negation-exempted: a claim phrased in the negative carries a
    // negation token by construction.
    return true;
  }

  const hit = guard.forbids.exec(sentence);
  if (hit === null) return false;
  if (exempt(guard.allows, hit.index)) return false;
  if (guard.negationExempt && exempt(NEGATION, hit.index)) return false;
  return true;
}
