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
import { paragraphs, svgText } from './claim-text.mjs';
import { presumptionFindings } from './leg12.mjs';

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

/**
 * The brand assets, derived rather than listed — a new card is exactly where a
 * new claim appears.
 * @returns {string[]}
 */
function brandAssets() {
  const dir = join(ROOT, 'brand');
  try {
    return readdirSync(dir).filter(n => n.endsWith('.svg')).map(n => `brand/${n}`);
  } catch {
    return [];
  }
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

// SEC-17 over the brand assets too: a forward-secrecy claim is likelier on a
// card than in a design document, and it has less room for its precondition —
// which is the argument for the requirement, not an exemption from it.
for (const rel of brandAssets()) {
  for (const para of paragraphs(svgText(readFileSync(join(ROOT, rel), 'utf8')))) {
    const mentions = CLAIMS.test(para);
    const claims = mentions && !REFUSAL.test(para) && !CITATION.test(para);
    if (claims && !PRECONDITION.test(para)) {
      findings.push({ file: rel, line: 1, text: para.replace(/\s+/g, ' ').slice(0, 110) });
    }
  }
}

/**
 * DOC-10 — the collector-patch limit, required in three places.
 *
 * "Documentation review" is not a thing that fails a build, which is the same
 * reason SEC-17 is checked above rather than read. DOC-10 asks for the limit
 * wherever coverage attestation is described: the threat model, DES-10, and
 * the coverage report's own OUTPUT. The last of those is the one that matters
 * most and the one most easily lost in a refactor — an auditor acts on the
 * report, and a limit they never see does not constrain them.
 *
 * Checked by looking for the two things the limit must join: that a patched
 * collector is not detectable, and that remote attestation is what would
 * change it and is not provided here.
 */
const PATCHED = /patch(ed|ing)?[^.]{0,140}(not|neither|never|NOT)[^.]{0,80}detect/i;
const ATTESTATION = /remote attestation/i;
/** @type {{ file: string, missing: string }[]} */
const disclosures = [];
for (const rel of ['docs/threat-model.md', 'design/DES-10-coverage-model.md',
  'packages/verify/src/coverage-report.mjs']) {
  const text = readFileSync(join(ROOT, rel), 'utf8');
  if (!PATCHED.test(text)) disclosures.push({ file: rel, missing: 'that a patched collector is NOT detectable' });
  else if (!ATTESTATION.test(text)) disclosures.push({ file: rel, missing: 'that remote attestation is what would change it, and is not provided' });
}

if (disclosures.length > 0) {
  console.error('\nCLAIMS LINT FAILED — DOC-10\n');
  for (const d of disclosures) {
    console.error(`  ${d.file}`);
    console.error(`    does not state ${d.missing}.`);
    console.error('    DOC-10 requires the collector-patch limit wherever coverage attestation is');
    console.error('    described, including in the report output itself.\n');
  }
  process.exit(1);
}

// ── LEG-12 — the eIDAS presumption, and what it does not attach to ────────
/** @type {{ file: string, rule: string, text: string }[]} */
const presumption = [];
for (const file of markdown(ROOT)) {
  for (const f of presumptionFindings(readFileSync(file, 'utf8'))) {
    presumption.push({ file: relative(ROOT, file), rule: f.rule, text: f.text });
  }
}
// The witness list is data an operator reads to choose, so it is a claim
// surface too — and it is JSON, not markdown. The brand assets are the same
// argument at a louder volume: "qualified" or "legally presumed" set in 88px
// on the social card reaches a reader who never opens a document.
for (const rel of ['spec/witnesses.json']) {
  for (const f of presumptionFindings(readFileSync(join(ROOT, rel), 'utf8'))) {
    presumption.push({ file: rel, rule: f.rule, text: f.text });
  }
}
for (const rel of brandAssets()) {
  for (const f of presumptionFindings(svgText(readFileSync(join(ROOT, rel), 'utf8')))) {
    presumption.push({ file: rel, rule: f.rule, text: f.text });
  }
}

if (presumption.length > 0) {
  console.error('\nCLAIMS LINT FAILED — LEG-12\n');
  for (const p of presumption) {
    console.error(`  ${p.file}`);
    console.error(p.rule === 'R1'
      ? '    mentions the Art. 41 presumption without naming the QUALIFIED precondition'
      : '    claims the presumption alongside us or our witness, with no negation in the sentence');
    console.error(`    ${p.text}\n`);
  }
  console.error('  LEG-12: the presumption attaches only via a qualified trust service,');
  console.error("  and never via a witness this project operates.\n");
  process.exit(1);
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

console.log('\n  claims: every forward-secrecy claim states its precondition in the same place (SEC-17)');
console.log('  claims: the collector-patch limit is stated in all three coverage surfaces (DOC-10)');
console.log('  claims: no surface attaches the eIDAS presumption to a witness we operate (LEG-12)\n');
