// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Reading prose for claims: paragraphs, sentences, negation, and the surfaces.
 *
 * Extracted from `tools/leg12.mjs` when M7 needed a second claims guard,
 * because `tools/code-text.mjs` already made this argument about a different
 * helper and it holds here too: the same mistake made by four instruments is
 * an argument for one shared helper rather than a habit. Two sentence
 * splitters would eventually disagree about where a negation stops carrying,
 * and the guard with the worse splitter would be the one that silently could
 * not fire.
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

/** Directories no claim lives in. */
/**
 * Directories no claim can live in: dependencies, history, and BUILD OUTPUT.
 *
 * Exported because lint-scope had its own copy of this list and the two
 * drifted — its copy omitted `dist`, so after `npm pack` the claims audit read
 * the generated SBOM and failed on a dependency name containing "sso". CI only
 * passed because `npm run lint` happens to run before the SBOM step, which
 * made a load-bearing ordering invisible. One list, imported.
 *
 * A generated artefact is not a surface: nobody reads a tarball manifest as a
 * promise, and a guard that fails on one is noise that teaches people to
 * ignore it.
 */
export const SKIP = new Set(['node_modules', '.git', 'out', 'coverage', 'dist']);

/**
 * Anything that turns a sentence into a denial.
 *
 * `nothing` and `nobody` were added after `rests on nothing we do` was flagged
 * as a claim — a sentence that plainly denies one. `refus…` joined them for
 * M7, where "we refuse to claim X" is the correct way to write about X.
 *
 * Deliberately no `does not` / `is not` / `are not`: `\bnot\b` already covers
 * them, and listing them again would look like the set does more than it does.
 */
export const NEGATION =
  /\bnot\b|\bn't\b|\bnever\b|\bno\b|\bnone\b|\bnothing\b|\bnobody\b|\bneither\b|\bnor\b|\bcannot\b|\bcan't\b|\bwithout\b|\bunless\b|\bonly (?:when|if|via|through|by)\b|\bexcept\b|\brather than\b|\bfails? to\b|\brefus\w+\b/i;

/**
 * Sentences, roughly, plus the separators this repository's prose uses to join
 * clauses a negation does NOT carry across — semicolons and bullet boundaries.
 *
 * Markdown emphasis is admitted on BOTH sides of the break — up to three
 * characters after the terminator and before the capital. Without that, a
 * sentence ending `…(NFR-09).** The KMS half is…` did not split at all, so a
 * whole paragraph became one unit and the assurance lint's per-sentence check
 * landed on text it was not about. The first fix only handled emphasis AFTER
 * the space, which is the rarer of the two placements.
 *
 * The lookahead for a capital is load-bearing, and its absence was a real bug:
 * splitting on any `.` plus space cut the eIDAS article reference in half, so
 * neither fragment matched the presumption pattern and the rule could NEVER
 * fire on the one sentence it exists to catch. A check that cannot fire is
 * worse than no check, because the build goes green and somebody stops
 * looking.
 *
 * Where it is wrong it is wrong towards splitting MORE (an abbreviation
 * followed by a capitalised word), and a shorter fragment is less likely to
 * contain a negation, so the error lands on the side of asking rather than of
 * passing a claim.
 * @param {string} para
 * @returns {string[]}
 */
export const sentences = (para) => {
  /** @type {string[]} */
  const units = [];
  /** @type {string[]} */
  let current = [];
  const close = () => { if (current.length > 0) { units.push(current.join(' ')); current = []; } };

  for (const line of para.split(/\n/)) {
    // A MARKDOWN TABLE ROW IS ONE UNIT. Splitting a row on `;` threw away the
    // cells before the fragment, which is where a row keeps its context: the
    // release notes' rejected-designs log has rows like
    // `| 3 | CUT | Verifiable delay function; zero-knowledge compliance
    // proofs; … |`, and every item after the first lost the `CUT` that made it
    // honest. A reader takes a row together, so the check does too.
    if (/^\s*\|/.test(line)) { close(); units.push(line); continue; }
    // A LIST ITEM IS A UNIT TOO, and it may wrap across lines. Treating every
    // newline as a boundary broke sentences at the wrap, and a shorter
    // fragment is less likely to contain the negation that makes it honest —
    // the error direction that gets a guard deleted. Treating none as a
    // boundary merged neighbouring bullets into one, which hid a claim inside
    // a long run of unrelated prose. Both of those were real, in that order.
    if (/^\s*(?:[-*+]|\d+\.)\s+/.test(line) || /^\s*#{1,6}\s/.test(line)) close();
    current.push(line);
  }
  close();

  return units
    .flatMap(u => (/^\s*\|/.test(u) ? [u]
      : u.split(/(?<=[.!?][*_`"')\]]{0,3})\s+(?=[*_`"'(\[]{0,3}[A-Z])|;\s+/)))
    .map(x => x.trim())
    .filter(x => x !== '');
};

/**
 * Blank-line separated paragraphs, which is also how a reader takes prose in.
 * @param {string} text
 * @returns {string[]}
 */
export const paragraphs = (text) => text.split(/\n\s*\n/);

/**
 * Every markdown file under `root`, DERIVED rather than listed.
 *
 * A hand-kept list of claim surfaces is a list that a new document is not on,
 * and a new document is exactly where a new claim appears. Inventory row 3.
 * @param {string} root
 * @returns {string[]}
 */
export function markdown(root) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(root)) {
    if (SKIP.has(name)) continue;
    const p = join(root, name);
    if (statSync(p).isDirectory()) out.push(...markdown(p));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

/**
 * Every surface a reader could take a claim from, as `{ label, text }`.
 *
 * Markdown is the obvious one. The others are not, and leaving them out is how
 * an audit passes while the claim sits where somebody will actually meet it:
 *
 *   package descriptions   what npm shows, and the first thing many readers see
 *   spec/*.json            published data an operator reads to choose
 *   the verifier's output  the strings a reader is shown about their own
 *                          evidence, which is the most load-bearing prose in
 *                          the project
 *
 * The verifier's strings are taken from the SOURCE of the reporting modules
 * rather than by running it, because a claim in a branch no fixture reaches is
 * still a claim that ships.
 * @param {string} root
 * @returns {{ label: string, text: string }[]}
 */
export function claimSurfaces(root) {
  /** @type {{ label: string, text: string }[]} */
  const out = markdown(root).map(f => ({ label: relative(root, f), text: readFileSync(f, 'utf8') }));

  const pkgs = join(root, 'packages');
  if (existsSync(pkgs)) {
    for (const d of readdirSync(pkgs)) {
      const man = join(pkgs, d, 'package.json');
      if (!existsSync(man)) continue;
      const m = JSON.parse(readFileSync(man, 'utf8'));
      if (typeof m.description === 'string') {
        out.push({ label: `packages/${d}/package.json (description)`, text: m.description });
      }
    }
  }

  const spec = join(root, 'spec');
  if (existsSync(spec)) {
    for (const name of readdirSync(spec)) {
      if (!name.endsWith('.json')) continue;
      out.push({ label: `spec/${name}`, text: readFileSync(join(spec, name), 'utf8') });
    }
  }

  for (const rel of ['packages/verify/src/cli.mjs', 'packages/verify/src/verify.mjs',
    'packages/verify/src/coverage-report.mjs', 'packages/verify/src/disclose-cli.mjs',
    'packages/verify/src/coverage-cli.mjs', 'packages/witnesses/src/index.mjs']) {
    const p = join(root, rel);
    if (existsSync(p)) out.push({ label: rel, text: readFileSync(p, 'utf8') });
  }

  return out;
}

/**
 * The clause a match sits in.
 *
 * An exemption has to be ATTACHED to the thing it exempts. Checking for a
 * denial anywhere in the sentence let nine of ten crafted evasions through,
 * because marketing copy pairs a negative hook with a positive claim as a
 * matter of course: "Splitstick is not slow, and your logs are permanent and
 * unchangeable", "No setup required: be audit-ready for the EU AI Act",
 * "Never lose an action again: we withstood every attack tried". The denial is
 * real, it is just about something else.
 *
 * Clauses are split on PUNCTUATION ONLY — commas, semicolons, colons, dashes.
 * Not on conjunctions: splitting on `and` broke "Zero-knowledge compliance
 * proofs were considered and rejected", where the exemption is the second half
 * of a fixed phrase about the subject. Punctuation alone handles every case in
 * the corpus, catches all ten crafted evasions, and errs towards a longer
 * clause — which is the safe direction here, because the failure it risks is
 * missing an overclaim rather than firing on an honest refusal, and an honest
 * refusal firing is what gets a guard deleted.
 *
 * A TABLE ROW IS NOT CLAUSE-SPLIT. Its cells are the context: the
 * rejected-designs log keeps `CUT` in one cell and the design name in another,
 * and splitting them is how that log stopped reading as honest in the first
 * place.
 * @param {string} sentence
 * @param {number} at index of the match within the sentence
 * @returns {string}
 */
export function clauseAt(sentence, at) {
  if (/^\s*\|/.test(sentence)) return sentence;
  const BREAK = /[,;:—–]/g;
  let start = 0;
  let end = sentence.length;
  for (let m = BREAK.exec(sentence); m !== null; m = BREAK.exec(sentence)) {
    if (m.index + m[0].length <= at) start = m.index + m[0].length;
    else if (m.index >= at) { end = m.index; break; }
  }
  return sentence.slice(start, end);
}

