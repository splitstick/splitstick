/**
 * The Witness Practice Statement, checked against the code — LEG-01 to LEG-09,
 * LEG-19.
 *
 * Eleven of M3b's twenty-two requirements are claims in a document. The test
 * for a document is whether a specific claim appears in a specific place AND
 * whether the code agrees with it, because a practice statement the software
 * contradicts is worse than no practice statement: somebody will rely on it,
 * and the gap between the promise and the behaviour is exactly where they will
 * be hurt.
 *
 * So each row below pairs a REQUIRED CLAIM in the statement with a WITNESS in
 * the source — a behaviour that must exist for the claim to be true, or must
 * NOT exist for a disclaimer to hold. Both halves are checked. A statement that
 * says the right thing while the code does something else fails here, and so
 * does a statement that has quietly dropped a disclaimer.
 *
 * This is a shallow textual check and cannot prove the behaviours are correct —
 * the test suites do that. What it catches is drift: a requirement reworded, a
 * disclaimer deleted, a behaviour removed while the promise stays.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { code } from './code-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const WPS = join(ROOT, 'docs/witness-practice-statement.md');

/** @param {string} dir @returns {string[]} */
function sources(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    if (['node_modules', '.git', 'out'].includes(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (name.endsWith('.mjs') && p.includes('/src/')) out.push(p);
  }
  return out;
}

/**
 * The statement, with markdown emphasis and line wrapping flattened.
 *
 * The patterns below describe sentences, and a sentence in this document is
 * wrapped across lines and interrupted by `**bold**` — four claims failed to
 * match on that alone, which would have meant either weakening the patterns to
 * fragments or flattening prose that reads better for a human. The reader of
 * this document is the point; the lint can do the adapting.
 */
const flatten = (/** @type {string} */ t) =>
  t.replace(/\*\*/g, '').replace(/\s*\n\s*/g, ' ');

const wps = flatten(readFileSync(WPS, 'utf8'));
const wpsRaw = readFileSync(WPS, 'utf8');
const src = code(sources(join(ROOT, 'packages')).map(f => readFileSync(f, 'utf8')).join('\n'));

// The tools are a separate corpus. `absent` rows check that no code CLAIMS
// something the statement disclaims, and folding the tools into `src` would
// widen every one of those at once; a row that means to pin a tool's behaviour
// says so with `tool`.
const toolSrc = code(readFileSync(join(ROOT, 'tools/anchor-wps.mjs'), 'utf8'));

/**
 * Each row: the requirement, a pattern the STATEMENT must contain, and a
 * pattern the SOURCE must contain for that claim to be implemented.
 *
 * `absent` instead of `source` means the opposite: the source must NOT contain
 * the pattern, which is how a disclaimer is checked. A disclaimer saying we do
 * not assert completeness is contradicted the moment some code claims it.
 */
const ROWS = [
  {
    req: 'LEG-01', what: 'the statement is versioned',
    // No `^` anchor: flatten() removes the newlines the anchor needs.
    statement: /Version \d+\.\d+ · \d{4}-\d{2}-\d{2}/,
    also: /### Change history/,
  },
  {
    req: 'LEG-02', what: 'receipt at the stated time, by the witness clock',
    statement: /received the submitted root at the time it records/i,
    source: /received_at/,
  },
  {
    req: 'LEG-02', what: 'and that a c2sp-note receipt time is UNSIGNED',
    statement: /witness-asserted, unsigned/,
    source: /witness-asserted, unsigned/,
  },
  {
    req: 'LEG-03', what: 'extension proved by a consistency proof, NOT immediate succession',
    statement: /extends the history it last held/i,
    source: /verifyConsistency/,
  },
  {
    req: 'LEG-03', what: 'and the statement does not promise immediate succession',
    statement: /not the same as "immediate successor"/i,
  },
  {
    req: 'LEG-04', what: 'retention in the witness own append-only store',
    statement: /retained the submitted root in its own append-only store/i,
    source: /rootsPath/,
  },
  {
    req: 'LEG-05', what: 'disclaims that the actions occurred',
    statement: /says nothing about whether the actions/i,
    absent: /establishes that the action(s)? occurred/i,
  },
  {
    req: 'LEG-06', what: 'disclaims that the content is true',
    statement: /neither is in a position to say it is accurate/i,
    absent: /the recorded content is true/i,
  },
  {
    req: 'LEG-07', what: 'disclaims completeness and points at coverage attestation',
    statement: /nothing about actions the collector never observed/i,
    also: /coverage attestation/i,
  },
  {
    req: 'LEG-08', what: 'disclaims lawfulness or authorisation',
    statement: /lawful, authorised, within policy/i,
    absent: /asserts that the action was (lawful|authorised)/i,
  },
  {
    req: 'LEG-09', what: 'the statement is itself anchored, not merely published',
    statement: /anchored like any other record/i,
    // The honest half. An earlier version of §7 said the digest "is written
    // into a Splitstick log and countersigned", which was not true of the
    // copy anybody could read: the command deleted its own history on every
    // run and no witness had ever signed it. If that disclosure is ever
    // deleted while the claim above stays, this is what fails.
    also: /that half of LEG-09 is\s+outstanding/i,
    // And the command must keep taking the word from the VERIFIER. Issuer
    // presence was the first version of this and was not enough: an envelope
    // can carry a proof the operator could not check, so the pinned property
    // is that the status comes from verifyStore's accepted+ok witnesses, which
    // is also what makes the TSA token and trust-path checks apply here.
    tool: /verified = present\.filter\(w => w\.accepted && w\.verdict === 'ok'\)/,
    tool2: /await verifyStore\(/,
    // And the verdict must be SCOPED to the version being reported. The
    // verifier answers about the whole store; reading that aggregate
    // attributed one version's countersignature to another.
    tool3: /w\.tree_size !== null && w\.tree_size >= recordSeq/,
  },
  {
    req: 'LEG-19', what: 'names the time source and the limits of the time assertion',
    statement: /The limits of the time assertion/i,
    also: /not a clock at all/i,
  },
  {
    req: 'SEC-25', what: 'every witness type declares its time discipline',
    statement: /\| `rfc3161` \|/,
    source: /TIME_DISCIPLINE/,
  },
  {
    req: 'OPS-06', what: 'a recovery point objective and a runnable drill',
    statement: /Recovery point objective/i,
    also: /witness-restore-drill/,
  },
  {
    req: 'SEC-04', what: 'the one-honest-witness assumption and its uncomfortable half',
    statement: /at least one witness in the configured set is honest/i,
    also: /one witness wearing several hats/i,
  },
];

/** @type {string[]} */
const errs = [];

for (const row of ROWS) {
  if (!row.statement.test(wps)) {
    errs.push(
      `${row.req}: the practice statement does not state ${row.what}. Expected to match `
      + `${row.statement}.`,
    );
  }
  if (row.also && !row.also.test(wps)) {
    errs.push(`${row.req}: the statement is missing its second half (${row.also}).`);
  }
  for (const key of /** @type {const} */ (['tool', 'tool2', 'tool3'])) {
    const pat = row[key];
    if (pat && !pat.test(toolSrc)) {
      errs.push(
        `${row.req}: the statement claims ${row.what}, and tools/anchor-wps.mjs no longer matches `
        + `${pat}. The command must take its verdict from the verifier rather than assert one.`,
      );
    }
  }
  if (row.source && !row.source.test(src)) {
    errs.push(
      `${row.req}: the statement claims ${row.what}, and no source matches ${row.source}. `
      + 'A claim the code does not implement is the failure this lint exists for.',
    );
  }
  if (row.absent && row.absent.test(src)) {
    errs.push(
      `${row.req}: the statement DISCLAIMS ${row.what}, and the source contains ${row.absent}, `
      + 'which contradicts it. A disclaimer the code works around is worse than no disclaimer.',
    );
  }
}

// The version in the statement must match the one the change history ends with,
// or a reader cannot tell which version they are holding.
const version = /^\*\*Version (\d+\.\d+)\*\*/m.exec(wpsRaw)?.[1];
const rows = [...wpsRaw.matchAll(/^\| (\d+\.\d+) \| \d{4}-\d{2}-\d{2} \|/gm)].map(m => m[1]);
if (version && rows.length > 0 && !rows.includes(version)) {
  errs.push(
    `the statement declares version ${version} and its change history does not mention it `
    + `(${rows.join(', ')}). A reader cannot tell which version they are holding.`,
  );
}

if (errs.length > 0) {
  console.error('\nPRACTICE-STATEMENT LINT FAILED\n');
  for (const e of errs) console.error(`  ${e}\n`);
  console.error(`  ${errs.length} finding(s).\n`);
  process.exit(1);
}

console.log(
  `\n  practice statement: ${ROWS.length} claim(s) stated and matched against the code `
  + '(LEG-01 to LEG-09, LEG-19, SEC-25, OPS-06, SEC-04)\n',
);
