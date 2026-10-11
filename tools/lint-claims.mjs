/**
 * SEC-17 as a check rather than a documentation review.
 *
 * SEC-17 says any forward-secrecy claim must state its non-exportable key
 * custody precondition **in the same place**. A precondition a page away is
 * read without it, which is the failure the requirement exists to prevent, and
 * "documentation review" is not a thing that fails a build.
 *
 * So every paragraph in the repository that claims forward secrecy must also
 * name its precondition within that same paragraph. The verifier's own report
 * is covered separately and executably, by
 * packages/verify/test/succession.test.mjs, which asserts the claim string
 * carries both declarations it rests on.
 *
 * This is deliberately a shallow textual check. It cannot tell a real claim
 * from a mention of one, so it errs towards asking — a paragraph that merely
 * discusses the topic satisfies it by naming the precondition too, which costs
 * a clause and is never wrong.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { code } from './code-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const SKIP = new Set(['node_modules', '.git', 'out', 'coverage', 'tools']);

/** A paragraph mentioning forward secrecy. */
const CLAIMS = /forward[- ]secrec|forward[- ]secure|forward security/i;

/**
 * Two kinds of paragraph mention the property without claiming it, and
 * demanding a precondition from them would make the lint noise that people
 * learn to edit around:
 *
 * A REFUSAL. "refuses to claim forward secrecy for any epoch declared
 * software-keyed" is the opposite of a claim, and attaching a precondition to
 * it would read as though the refusal were conditional.
 *
 * A CITATION. Schneier and Kelsey's 1999 work is named in the
 * acknowledgements; that is their term for their own work, not an assertion
 * about this system. Detected by a bibliographic cue — a year, "work on", or
 * "et al" — rather than by matching the authors, so the rule generalises to
 * the next citation instead of hardcoding this one.
 */
const REFUSAL = /refuses? to claim|refused|no forward[- ](?:secrecy|security) claim|is NOT claimed|not claimed/i;
const CITATION = /\b(?:19|20)\d{2}\b|\bwork on\b|\bet al\b/i;

/**
 * The precondition, in any of the forms the project actually uses. Destruction
 * counts too: the claim rests on custody AND destruction, and a paragraph that
 * names either is at least pointing the reader at the dependency.
 */
const PRECONDITION = /non-exportable|not externally verifiable|destruct|destroy|destroyed|HSM|KMS|custody|SEC-17|operator-declared/i;

/** @param {string} dir @returns {string[]} */
function markdown(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...markdown(p));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

/** @type {{ file: string, line: number, text: string }[]} */
const findings = [];

for (const file of markdown(ROOT)) {
  const text = readFileSync(file, 'utf8');
  let line = 1;
  // Paragraph-wise: blank-line separated, which is also how a reader takes it in.
  for (const para of text.split(/\n\s*\n/)) {
    const mentions = CLAIMS.test(para);
    const claims = mentions && !REFUSAL.test(para) && !CITATION.test(para);
    if (claims && !PRECONDITION.test(para)) {
      findings.push({
        file: relative(ROOT, file),
        line,
        text: para.replace(/\s+/g, ' ').slice(0, 110),
      });
    }
    line += para.split('\n').length + 1;
  }
}

if (findings.length > 0) {
  console.error('\nCLAIMS LINT FAILED — SEC-17\n');
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}`);
    console.error(`    claims forward secrecy without naming its precondition in the same paragraph`);
    console.error(`    ${f.text}\n`);
  }
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log('\n  claims: every forward-secrecy claim states its precondition in the same place (SEC-17)\n');
