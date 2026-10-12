/**
 * `splitstick coverage` — FR-28, FR-40, DOC-10.
 *
 * Unknown flags are REFUSED rather than ignored. A misspelled `--form` that
 * silently reported on the default window would answer a question nobody
 * asked, and the reader would have no way to tell. This already happened once
 * in this project: `--vkey` was accepted and ignored by the verifier because
 * the flag is `--key`.
 */

import { readFileSync } from 'node:fs';
import { Store } from '@splitstick/core/store';
import { coverageReport, CoverageError } from './coverage.mjs';
import { renderCoverage } from './coverage-report.mjs';

const USAGE = `splitstick coverage <store> --from <date> --to <date> [--collector <name>] [--policy <file>] [--json]

  --from, --to     the window, as a date (2027-01-01) or an RFC 3339 instant.
                   A bare date means the whole day in UTC.
  --collector      which collector's chain to report on. A store may hold
                   several; without this the first is used and the others are
                   named in the output rather than passed over in silence.
  --json           the structured report instead of the rendered one.
  --policy         your acceptance policy (DES-09): whose countersignature you
                   accept. WITHOUT IT nothing can be verified, so anchoring is
                   reported as present-but-unverified rather than established.
`;

/**
 * @param {string[]} argv
 * @returns {Promise<{ exit: number, out: string }>}
 */
export async function runCoverage(argv) {
  const FLAGS = new Set(['from', 'to', 'collector', 'json', 'policy']);
  /** @type {Record<string, string|boolean>} */
  const flags = {};
  /** @type {string[]} */
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = String(argv[i]);
    if (a === '--help' || a === '-h') return { exit: 0, out: USAGE };
    if (!a.startsWith('--')) { positional.push(a); continue; }
    const name = a.slice(2);
    if (!FLAGS.has(name)) {
      return {
        exit: 2,
        out: `unknown flag ${a}. Refused rather than ignored: a misspelled flag that silently `
          + `reported on a different window would be read as a report on this one.\n\n${USAGE}`,
      };
    }
    if (name === 'json') { flags.json = true; continue; }
    const v = argv[i + 1];
    if (v === undefined || String(v).startsWith('--')) {
      return { exit: 2, out: `${a} needs a value\n\n${USAGE}` };
    }
    flags[name] = String(v);
    i += 1;
  }
  const root = positional[0];
  if (root === undefined) return { exit: 2, out: `a store directory is required\n\n${USAGE}` };

  let store;
  /** @type {import('@splitstick/core/store').Store|undefined} */
  let probe;
  try {
    // Opened with a placeholder first only to ask which collectors exist. A
    // store holding several must not have one picked for it in silence.
    //
    // Tracked separately and closed in the `finally` below. When no collector
    // was named a SECOND Store was opened and only that one was closed, so
    // every run without --collector leaked the probe.
    probe = new Store(root, String(flags.collector ?? 'unknown'));
    const available = probe.collectors();
    const collector = flags.collector === undefined
      ? (available[0] ?? 'unknown')
      : String(flags.collector);
    if (flags.collector !== undefined && !available.includes(collector)) {
      return {
        exit: 2,
        out: `this store holds no chain for collector ${JSON.stringify(collector)}`
          + `${available.length === 0 ? '' : `; it holds ${available.join(', ')}`}\n`,
      };
    }
    store = flags.collector === undefined ? new Store(root, collector) : probe;
    const report = await coverageReport(store, {
      from: String(flags.from ?? ''),
      to: String(flags.to ?? ''),
      collectors: available,
      ...(flags.policy ? { policy: JSON.parse(readFileSync(String(flags.policy), 'utf8')) } : {}),
    });
    const out = flags.json ? `${JSON.stringify(report, null, 1)}\n` : renderCoverage(report);
    // Named `exit`, not `code`: in this project `code` is a DES-12 failure
    // code everywhere else, and the failure-code lint reads these literals as
    // if they were failure codes — correctly, given the name.
    //
    // A report is not a pass/fail gate, so the exit status says whether a claim
    // could be issued and not whether the operator is in trouble: 0 complete,
    // 1 incomplete, 2 inconclusive. An auditor reads the report; a pipeline
    // reads this.
    const exit = report.verdict === 'complete' ? 0 : report.verdict === 'incomplete' ? 1 : 2;
    return { exit, out };
  } catch (e) {
    if (e instanceof CoverageError) return { exit: 2, out: `${e.message}\n` };
    throw e;
  } finally {
    store?.close();
    if (probe !== undefined && probe !== store) probe.close();
  }
}
