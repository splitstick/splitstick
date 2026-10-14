// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Every assurance claim names its evidence — DOC-11.
 *
 * DOC-11's own statement says why it exists: *the design repeatedly acquired
 * guarantees its own threat model excludes.* This project has the receipts.
 * Presence counted as anchoring three times — PR #8's finding 15, PR #9's P1,
 * and M6's conformance `C1`, which certified a witness that never signed
 * anything. A coverage report said ANCHORED on the strength of an issuer's
 * name being present. A disclosure pack compared an unsalted digest against a
 * salted cid, a comparison that could never be true, and reported `ok`.
 *
 * None of those was a lie. Each was a claim that drifted one step past its
 * evidence, in a place where the step was easy to take and hard to see. The
 * register is the countermeasure: the evidence CLASS is written next to the
 * claim, so drifting requires editing the class, which is a thing a reviewer
 * can see.
 *
 * Four checks:
 *
 *   1. every registered claim's text actually appears in the surface it names.
 *      A register that drifts from the prose is a second document to keep in
 *      step, and a document that drifts.
 *   2. every claim declares one of the three classes and a reason for it.
 *   3. a claim classed `operator-declared` or `none` is NOT worded as a
 *      verified guarantee. This is the rule DOC-11 states in so many words,
 *      and the curated phrasings below are its teeth.
 *   4. DRIFT, the direction a launch gate actually leaks: an
 *      assurance-shaped sentence in the release notes that is not in the
 *      register at all. Additive, which is how a new claim arrives.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { paragraphs, sentences, clauseAt } from './claim-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const REGISTER = join(ROOT, 'spec/assurance-register.json');
const CLASSES = ['independent', 'operator-declared', 'none'];

/**
 * The curated overclaim phrasings — DOC-11's verify names exactly this.
 *
 * These are the words that turn an assertion into a guarantee. A claim the
 * operator merely declares may not borrow them, because a reader cannot tell
 * "we verified this" from "they told us this" once the sentence says
 * "guarantees".
 */
const OVERCLAIM = /\b(?:guarantee[sd]?|guaranteeing|prove[sdn]?|proof that|ensure[sd]?|ensuring|certif\w+|verified|impossible|never fails?|always detects?|cannot happen)\b/i;

/**
 * What rescues a sentence that uses one: it names the precondition, or marks
 * the limit, IN THE SAME CLAUSE. This is the SEC-17 discipline — a
 * precondition a page away is read without it — and the review found it had
 * to be the clause rather than the sentence, for the same reason the scope
 * guards did: a bare `only` anywhere exempted "It guarantees completeness,
 * and only takes a second". The qualifying forms are `only under`, `only
 * when`, `proves only`, and their kin; `only` on its own is an adverb about
 * anything.
 *
 * The bare negation tokens went for the same reason, and this one is the third
 * instance of the shape in M7: `\bno\b` exempted "It ENSURES NO tool call
 * escapes the record", which is a guarantee phrased in the negative — exactly
 * what SEC-16's `absolute` slot exists for. Every honest limit statement in
 * this project carries a SPECIFIC marker instead: `the collector reported`,
 * `self-reported`, `witness-asserted`, `not remote attestation`, `not
 * externally verifiable`. Specific markers are what a qualification looks
 * like; a bare negative is what a claim looks like when it is about absence.
 */
const QUALIFIED = /\bonly (?:under|when|if|that|to the extent)\b|\b(?:prove[sdn]?|establishes?|says?|shows?|means) only\b|\bprecondition\b|\bnot externally verifiable\b|\boperator-declared\b|\bself-reported\b|\bdeclared\b|\basserts?\b|\bassertion\b|\bthe collector reported\b|\bnot remote attestation\b|\bwitness-asserted\b|\bunsigned\b|\bnot (?:remote attestation|externally verifiable|established|verified here|confirmed)\b|\bprovides? none\b|\b(?:do|does|did|will|would|can|could|is|are)(?:n't| not) (?:prove|guarantee|ensure|establish|verif\w+|certif\w+|detect|close)\b|\bonly remote attestation\b/i;

/** Sentences in the notes that look like an assurance claim and must be registered. */
const ASSURANCE_SHAPED = /\b(?:guarantee[sd]?|prove[sdn]?|ensure[sd]?|detects?|establishes?|cannot be (?:altered|forged|rewritten)|never (?:holds?|sees?|leaves?))\b/i;

/** @type {string[]} */
const findings = [];

const register = JSON.parse(readFileSync(REGISTER, 'utf8'));
if (register.version !== 1) {
  findings.push(`the register declares version ${register.version} and this reader implements 1`);
}

/** @type {Map<string, string>} cached surface text */
const surfaces = new Map();
const surfaceText = (/** @type {string} */ rel) => {
  if (!surfaces.has(rel)) surfaces.set(rel, readFileSync(join(ROOT, rel), 'utf8'));
  return /** @type {string} */ (surfaces.get(rel));
};

/**
 * Whitespace-normalised, so a registered claim need not reproduce the line
 * wrapping of the document it is quoted from. Requiring that would make the
 * register fail every time somebody reflowed a paragraph, which is how a check
 * earns a reputation for noise and then gets deleted.
 * @param {string} t
 */
const flat = (t) => t.replace(/\s+/g, ' ');

for (const c of register.claims ?? []) {
  const where = `${c.id ?? '(no id)'}`;
  if (!c.id || !c.claim || !c.surface || !c.class || !c.why) {
    findings.push(`${where}: a register entry needs id, claim, surface, class and why. A class `
      + 'with no reason is a label, and a label is what DOC-11 is trying to replace');
    continue;
  }
  if (!CLASSES.includes(c.class)) {
    findings.push(`${where}: class ${JSON.stringify(c.class)} is not one of ${CLASSES.join(', ')}`);
    continue;
  }

  // 1. the claim is really there.
  let text;
  try { text = surfaceText(c.surface); } catch {
    findings.push(`${where}: names surface ${c.surface}, which cannot be read`);
    continue;
  }
  if (!flat(text).includes(flat(c.claim))) {
    findings.push(`${where}: the registered text is not in ${c.surface} — the register and the `
      + `prose have drifted apart. Registered: ${JSON.stringify(c.claim.slice(0, 80))}`);
    continue;
  }

  // 3. an operator-declared or unestablished claim is not worded as a guarantee.
  if (c.class === 'independent') continue;
  for (const para of paragraphs(text)) {
    if (!flat(para).includes(flat(c.claim))) continue;
    for (const s of sentences(para)) {
      if (!flat(s).includes(flat(c.claim)) && !flat(c.claim).includes(flat(s))) continue;
      const hit = OVERCLAIM.exec(s);
      if (hit === null) continue;
      // Clause-local, so a qualification attached to something else does not
      // rescue the claim.
      if (QUALIFIED.test(clauseAt(s, hit.index))) continue;
      findings.push(`${where} [${c.class}]: worded as a verified guarantee with nothing in the `
        + 'sentence marking what it rests on. DOC-11: a claim resting only on the '
        + 'operator-controlled collector is worded as an assertion, never as a verified '
        + `guarantee.\n      ${s.replace(/\s+/g, ' ').slice(0, 150)}`);
    }
  }
}

// 4. drift: an assurance-shaped sentence the register does not know about.
const REGISTERED = (register.claims ?? []).map((/** @type {any} */ c) => c.claim);
const NOTES = 'docs/splitstick-1.0-release-notes.md';
const notes = surfaceText(NOTES);
// Only the sections that make assurance claims about the product. The rejected
// log, the bounty terms and the review history discuss claims rather than make
// them, and auditing them would make the drift check fire on this project's own
// honesty — the row-2 failure.
const CLAIM_SECTIONS = /## What ships in 1\.0([\s\S]*?)\n## Witness Practice Statement/;
const body = CLAIM_SECTIONS.exec(notes);
if (body === null) {
  findings.push(`${NOTES}: the "What ships in 1.0" section could not be located, so the drift `
    + 'check ran against nothing. Update this guard deliberately rather than leaving it inert');
} else {
  /**
   * A paragraph that declares itself a limit is already doing what DOC-11
   * asks, and its sentences are the explanation.
   *
   * The release notes' selective-disclosure section opens "**The honest
   * limit:**" and then reasons about why the limit is unavoidable — "you
   * cannot simultaneously claim 'nobody knows how many actions I took' and
   * 'you can prove I deleted none'". That quotes a claim in order to deny it,
   * and the drift check flagged it as an unregistered claim once the sentence
   * splitter was fixed and could finally see it.
   */
  const LIMIT_PARA = /\bhonest limit\b|\bthe limit\b|\bwhat (?:this|it) does not\b|\bunavoidable\b|\btrade[\s-]?off\b|\bNOT closed\b|\bnot detectable\b/i;

  /** @type {string[]} */
  const unregistered = [];
  for (const para of paragraphs(body[1] ?? '')) {
    if (LIMIT_PARA.test(para)) continue;
    for (const s of sentences(para)) {
      // A heading is not a claim. "### Disclosure — prove one action, reveal
      // one action" is a section title, and auditing titles would make the
      // check fire on the table of contents.
      if (/^#{1,6}\s/.test(s)) continue;
      if (!ASSURANCE_SHAPED.test(s)) continue;
      if (REGISTERED.some((/** @type {string} */ r) => flat(s).includes(flat(r))
        || flat(r).includes(flat(s)))) continue;
      // A sentence that states its own limit is not an unregistered claim; it
      // is the project doing what DOC-11 asks — and the limit has to be in the
      // clause that makes the claim, not merely in the sentence.
      const shaped = ASSURANCE_SHAPED.exec(s);
      if (shaped !== null && QUALIFIED.test(clauseAt(s, shaped.index))) continue;
      unregistered.push(s.replace(/\s+/g, ' ').slice(0, 130));
    }
  }
  for (const u of unregistered) {
    findings.push(`${NOTES}: an assurance claim that is not in the register and does not state `
      + `its own limit. Register it with a class, or qualify it.\n      ${u}`);
  }
}

if (findings.length > 0) {
  console.error('\nASSURANCE LINT FAILED — DOC-11\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

const byClass = (register.claims ?? []).reduce((/** @type {any} */ a, /** @type {any} */ c) => {
  a[c.class] = (a[c.class] ?? 0) + 1; return a;
}, {});
console.log(`\n  assurance: ${register.claims.length} claim(s) registered — `
  + `${CLASSES.map(c => `${byClass[c] ?? 0} ${c}`).join(', ')} (DOC-11)`);
console.log('             each names its evidence, and no operator-declared claim is worded');
console.log('             as a verified guarantee\n');
