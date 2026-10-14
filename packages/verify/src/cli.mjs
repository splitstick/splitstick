#!/usr/bin/env node
/**
 * splitstick verify — the command-line surface of FR-29.
 *
 * Prints the verdict, the check table, every finding with what a reader may
 * conclude from it, and FR-57's capability statement. "Verification failed" on
 * its own is useless; so is a bare "ok".
 *
 * Exit codes, so this is usable in a pipeline:
 *   0  ok
 *   1  inconclusive — a check could not be answered
 *   2  fail — the evidence contradicts itself
 *   3  usage error
 *
 * Note that 1 is the normal exit for a 1.0 store with no witness configured.
 * That is not a defect in the store; it is the honest verdict, and the
 * capability block says which checks went unanswered.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyStore } from './verify.mjs';

const EXIT = { ok: 0, inconclusive: 1, fail: 2 };

const USAGE = `splitstick-verify <store> [options]

  --collector <id>   the collector instance whose chain to read
  --key <vkey>       the operator identity you pin, as name+keyid+base64key
  --policy <file>    your acceptance policy: which witnesses you accept, what
                     each establishes, their keys or trust anchors, and the
                     quorum you require. It is an INPUT, not a registry — two
                     readers with different trust get different, internally
                     consistent answers from the same pack (FR-30).
  --disclosed <file> heights you already hold from another pack, as
                     [{ "tree_size": N, "root": "<base64>" }], for the
                     cross-pack comparison (FR-54, SEC-26)
  --json             machine-readable output
  --explain          print what the verdict depends on and nothing else

Verification is offline: it opens files and does arithmetic. It makes no
network call and reads no credential. Trust anchors are inputs, not a registry.
`;

/** @param {string[]} argv */
export async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(USAGE);
    return args.length === 0 ? 3 : 0;
  }
  /** @type {Record<string, string|boolean>} */
  const opts = {};
  /** @type {string[]} */
  const positional = [];
  /**
   * Flags are checked against this list. An unrecognised one used to be
   * accepted and ignored, so `--vkey` — a plausible misremembering of `--key`,
   * the flag that pins the identity everything else depends on — produced a
   * clean-looking report saying no identity was pinned. Silently doing less
   * than the reader asked for is the one failure mode this tool cannot have.
   */
  const FLAGS = new Set(['collector', 'key', 'policy', 'disclosed', 'json', 'explain']);
  for (let i = 0; i < args.length; i++) {
    const a = /** @type {string} */ (args[i]);
    if (a.startsWith('--') && !FLAGS.has(a.slice(2))) {
      process.stderr.write(
        `${a} is not a flag this reads. Known flags: ${[...FLAGS].map(f => `--${f}`).join(', ')}.\n`
        + 'Refusing rather than ignoring it: a misspelled flag that is skipped silently makes the '
        + 'report answer a different question than the one asked.\n',
      );
      return 3;
    }
    if (a === '--json' || a === '--explain') { opts[a.slice(2)] = true; continue; }
    if (a.startsWith('--')) {
      const v = args[i + 1];
      if (v === undefined || v.startsWith('--')) {
        process.stderr.write(`${a} needs a value\n`);
        return 3;
      }
      opts[a.slice(2)] = v; i++; continue;
    }
    positional.push(a);
  }
  const root = positional[0];
  if (!root) { process.stderr.write(USAGE); return 3; }

  /** @type {unknown} */
  let policy;
  /** @type {unknown} */
  let disclosed;
  for (const flag of /** @type {const} */ (['policy', 'disclosed'])) {
    const value = opts[flag];
    if (typeof value !== 'string') continue;
    try {
      const parsed = JSON.parse(readFileSync(value, 'utf8'));
      if (flag === 'policy') policy = parsed; else disclosed = parsed;
    } catch (e) {
      // Refused rather than ignored, for the same reason as an unknown flag: a
      // policy that failed to load would make the report say the reader
      // trusted nobody, which is a different and much weaker answer.
      process.stderr.write(
        `--${flag} could not be read: ${e instanceof Error ? e.message : String(e)}\n`,
      );
      return 3;
    }
  }

  const report = await verifyStore(root, {
    ...(typeof opts.collector === 'string' ? { collector: opts.collector } : {}),
    ...(typeof opts.key === 'string' ? { vkey: opts.key } : {}),
    ...(policy ? { policy: /** @type {any} */ (policy) } : {}),
    ...(disclosed ? { disclosed: /** @type {any} */ (disclosed) } : {}),
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, (_k, v) =>
      (v && v.type === 'Buffer' ? Buffer.from(v.data).toString('hex') : v), 2) + '\n');
    return EXIT[report.verdict];
  }

  const out = [];
  if (!opts.explain) {
    const s = report.summary;
    out.push('');
    out.push(`verdict     ${report.verdict.toUpperCase()}  (${s.passed} checks passed, ${s.unanswered} could not be answered, ${s.failed} failed)`);
    out.push(`records     ${report.tree_size}`);
    out.push('');
    for (const c of report.checks) {
      const mark = c.verdict === 'ok' ? ' ok ' : c.verdict === 'fail' ? 'FAIL' : ' ?? ';
      out.push(`  [${mark}] ${c.name.padEnd(9)} ${c.detail ?? ''}`.trimEnd());
    }
    if (report.findings.length) {
      out.push('');
      for (const f of report.findings) {
        const at = f.record_seq === undefined ? '' : ` at record_seq ${f.record_seq}`;
        out.push(`  ${f.verdict === 'fail' ? 'FAIL' : ' ?? '} ${f.code}${at}`);
        out.push(`       ${f.detail}`);
      }
    }
    out.push('');
    out.push(report.witnesses.length
      ? 'witnesses   ' + report.witnesses.map(w =>
        `${w.accepted ? '' : '[not accepted] '}${w.id} (${w.type}, ${w.establishes})`
        + `\n              ${w.detail}`).join('\n            ')
      : 'witnesses   none in this evidence');
    // Quorum PER CLASS, printed as three numbers. One aggregate figure would
    // let an operator look well-witnessed while unable to detect truncation at
    // all, which is the failure DES-20's review named — so the shape of this
    // line is load-bearing, not cosmetic.
    if (report.witnesses.length) {
      out.push('quorum      ' + Object.entries(report.quorum.observed)
        .map(([k, n]) => `${k} ${n}/${report.quorum.required}${report.quorum.met[k] ? '' : ' (not met)'}`)
        .join(', '));
    }
    if (report.succession) {
      out.push('epochs      ' + report.succession.epochs.map(e =>
        `${e.epoch}: custody ${e.custody} (${e.custody_basis}), forward secrecy ${e.forward_secrecy}`)
        .join('\n            '));
      out.push('            destruction is ' + report.succession.destruction_basis
        + ' and is not verifiable by anyone');
    }
  }
  out.push('');
  out.push('capability  ' + (report.capability.can[0] ?? 'nothing could be established'));
  for (const c of report.capability.can.slice(1)) out.push('            ' + c);
  for (const c of report.capability.cannot) out.push('            NOT: ' + c);
  out.push('');
  // Printed whether or not it attaches. An absent line is read as "probably
  // fine" by a reader hoping for one, and this is the field most likely to be
  // quoted at somebody outside the room.
  const wrap = (/** @type {string} */ t) => {
    /** @type {string[]} */
    const lines = [];
    let cur = '';
    for (const word of t.split(' ')) {
      if (cur !== '' && `${cur} ${word}`.length > 76) { lines.push(cur); cur = word; }
      else cur = cur === '' ? word : `${cur} ${word}`;
    }
    if (cur !== '') lines.push(cur);
    return lines.join('\n            ');
  };
  out.push(`eIDAS       ${report.presumption.attaches ? 'Art. 41 presumption ATTACHES' : 'no Art. 41 presumption'}`);
  out.push(`            ${wrap(report.presumption.detail)}`);
  out.push('');
  out.push('trusting    ' + report.trusting.join('\n            '));
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  return EXIT[report.verdict];
}

/**
 * Run when this file IS the program, not when it is imported.
 *
 * `file://${process.argv[1]}` was wrong in the one case that matters: npm
 * installs a bin as a symlink, so argv[1] is `.bin/splitstick-verify` while
 * `import.meta.url` is the realpath of this file. They never matched, the
 * guard never fired, and the only published entry point in this project
 * printed nothing and exited 0 — the shape of failure a verifier is least
 * allowed to have, since silence reads as "nothing wrong". Compare realpaths,
 * and build the URL with pathToFileURL so a path containing a space or a `#`
 * is not a second way to miss.
 */
const invokedAs = process.argv[1] === undefined
  ? '' : pathToFileURL(realpathSync(process.argv[1])).href;
if (import.meta.url === invokedAs) {
  process.exitCode = await main(process.argv);
}
