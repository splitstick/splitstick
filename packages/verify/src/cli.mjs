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

import { verifyStore } from './verify.mjs';

const EXIT = { ok: 0, inconclusive: 1, fail: 2 };

const USAGE = `splitstick verify <store> [options]

  --collector <id>   the collector instance whose chain to read
  --key <vkey>       the operator identity you pin, as name+keyid+base64key
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
  for (let i = 0; i < args.length; i++) {
    const a = /** @type {string} */ (args[i]);
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

  const report = await verifyStore(root, {
    ...(typeof opts.collector === 'string' ? { collector: opts.collector } : {}),
    ...(typeof opts.key === 'string' ? { vkey: opts.key } : {}),
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
      ? 'witnesses   ' + report.witnesses.map(w => `${w.id} (${w.type}, ${w.establishes})`).join('\n            ')
      : 'witnesses   none in this evidence');
  }
  out.push('');
  out.push('capability  ' + (report.capability.can[0] ?? 'nothing could be established'));
  for (const c of report.capability.can.slice(1)) out.push('            ' + c);
  for (const c of report.capability.cannot) out.push('            NOT: ' + c);
  out.push('');
  out.push('trusting    ' + report.trusting.join('\n            '));
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  return EXIT[report.verdict];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main(process.argv);
}
