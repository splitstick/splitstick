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

import { NEGATION, sentences, paragraphs } from './claim-text.mjs';

export { NEGATION };

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

/**
 * @param {string} text
 * @returns {{ rule: 'R1'|'R2', para: number, text: string }[]}
 */
export function presumptionFindings(text) {
  /** @type {{ rule: 'R1'|'R2', para: number, text: string }[]} */
  const out = [];
  const paras = paragraphs(text);
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
