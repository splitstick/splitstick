// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * LEG-12 as a check rather than a documentation review.
 *
 * LEG-12 has two halves, and a surface can get either wrong on its own:
 *
 *   the precondition   the Art. 41 presumption attaches only when anchored to
 *                      a QUALIFIED trust service
 *   the disclaimer     and not via a witness this project operates
 *
 * "Documentation review; no contrary claim anywhere" is the stated verify, and
 * a review is a thing somebody skips. So the two halves are two rules:
 *
 *   R1  every paragraph that mentions the presumption names `qualified`
 *   R2  no SENTENCE claims the presumption alongside us or our witness without
 *       a negation in it
 *
 * R2 is scoped to the sentence rather than the paragraph on purpose. Negation
 * binds inside a sentence; across a paragraph a disclaimer three sentences
 * later would satisfy a check while a reader takes the claim from the first
 * sentence and stops. That is the SEC-17 lesson — a precondition a page away
 * is read without it — applied one level down.
 *
 * This stays a shallow textual check and cannot tell a claim from a mention of
 * one, so it errs towards asking: a sentence that merely discusses the topic
 * satisfies it by carrying the disclaimer too, which costs a clause and is
 * never wrong.
 */

/** Art. 41 itself, however it is spelled. Not every mention of eIDAS: the
 *  requirement is about the PRESUMPTION, and a page may reference the
 *  regulation for other reasons. */
export const PRESUMPTION =
  /\bart(?:icle)?\.?\s*41\b|eIDAS presumption|presumption of (?:integrity|accuracy|origin)/i;

/** The precondition R1 requires in the same paragraph. */
export const QUALIFIED = /\bqualified\b/i;

/** Us, or anything of ours a presumption might be wrongly attributed to. */
export const OURS =
  /splitstick'?s own witness|splitstick'?s witness|our own witness|our witness|the hosted witness|self-hosted witness|witness (?:this project|we) operates?|\bsplitstick\b|\bwe\b|\bus\b|\bour\b/i;

/** Anything that turns the sentence into a denial. */
export const NEGATION =
  /\bnot\b|\bn't\b|\bnever\b|\bno\b|\bnone\b|\bnothing\b|\bnobody\b|\bneither\b|\bnor\b|\bcannot\b|\bcan't\b|\bwithout\b|\bunless\b|\bonly (?:when|if|via|through|by)\b|\bexcept\b|\brather than\b|\bfails? to\b/i;

/**
 * Sentences, roughly, plus the separators this repository's prose uses to join
 * clauses a negation does NOT carry across — semicolons and bullet boundaries.
 *
 * The lookahead for a capital is load-bearing, and its absence was a real bug:
 * splitting on any `.` plus space cut `Art. 41` in half, so neither fragment
 * matched the presumption pattern and R2 could NEVER fire on the one sentence
 * it exists to catch — `Splitstick's witness gives you the eIDAS Art. 41
 * presumption.` A check that cannot fire is worse than no check, because the
 * build goes green and somebody stops looking.
 *
 * Where it is wrong it is wrong towards splitting MORE (an abbreviation
 * followed by a capitalised word), and a shorter fragment is less likely to
 * contain a negation, so the error lands on the side of asking rather than of
 * passing a claim.
 * @param {string} para
 */
const sentences = (para) => para
  .split(/(?<=[.!?])\s+(?=["'(\[]?[A-Z])|\n\s*[-*|]\s*|;\s+/)
  .map(s => s.trim())
  .filter(s => s !== undefined && s !== '');

/**
 * @param {string} text
 * @returns {{ rule: 'R1'|'R2', para: number, text: string }[]}
 */
export function presumptionFindings(text) {
  /** @type {{ rule: 'R1'|'R2', para: number, text: string }[]} */
  const out = [];
  const paras = text.split(/\n\s*\n/);
  for (let i = 0; i < paras.length; i += 1) {
    const para = paras[i] ?? '';
    if (!PRESUMPTION.test(para)) continue;
    if (!QUALIFIED.test(para)) {
      out.push({ rule: 'R1', para: i, text: para.slice(0, 200).replace(/\s+/g, ' ') });
    }
    for (const s of sentences(para)) {
      if (!PRESUMPTION.test(s)) continue;
      if (!OURS.test(s)) continue;
      if (NEGATION.test(s)) continue;
      out.push({ rule: 'R2', para: i, text: s.slice(0, 200).replace(/\s+/g, ' ') });
    }
  }
  return out;
}
