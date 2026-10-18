// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * `splitstick disclose` and `splitstick verify-disclosure` — FR-32, INT-03.
 *
 * Unknown flags are REFUSED rather than ignored. `--vkey` was once accepted and
 * skipped by the verifier because the flag is `--key`, producing a clean-looking
 * report that silently answered a different question.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { Store } from '@splitstick/core/store';
import { buildDisclosure, verifyDisclosure, DiscloseError } from './disclose.mjs';

const USAGE = `splitstick-disclose <store> --event <seq> [--collector <name>] [--out <file>]
splitstick-disclose --verify <pack.json> [--key <vkey>] [--policy <file>]

  --event          the single record_seq to disclose. One event, by design.
  --collector      which collector's chain to disclose from.
  --out            write the pack here instead of to stdout.
  --verify         verify a pack instead of building one. Needs nothing else:
                   no store, no network, no credential.
  --key            the operator identity you pin. WITHOUT IT the signature over
                   the root is not checked against anything you chose.
  --policy         whose countersignature you accept (DES-09). Without it a
                   proof is present-and-unverified, never verified.
`;

/**
 * @param {string[]} argv
 * @returns {Promise<{ exit: number, out: string, err?: string }>}
 */
export async function runDisclose(argv) {
  const FLAGS = new Set(['event', 'collector', 'out', 'verify', 'key', 'policy']);
  /** @type {Record<string, string>} */
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
        exit: 3, out: '',
        err: `${a} is not a flag this reads. Refused rather than ignored: a misspelled flag `
          + `that silently disclosed a different record would be read as disclosing this `
          + `one.\n\n${USAGE}`,
      };
    }
    const v = argv[i + 1];
    if (v === undefined || String(v).startsWith('--')) {
      return { exit: 3, out: '', err: `${a} needs a value\n\n${USAGE}` };
    }
    flags[name] = String(v);
    i += 1;
  }

  const policy = flags.policy === undefined
    ? undefined
    : JSON.parse(readFileSync(flags.policy, 'utf8'));

  // ── verifying a pack: the recipient's side ────────────────────────────────
  if (flags.verify !== undefined) {
    const pack = JSON.parse(readFileSync(flags.verify, 'utf8'));
    const r = await verifyDisclosure(pack, {
      ...(flags.key ? { vkey: flags.key } : {}),
      ...(policy ? { policy } : {}),
    });
    const lines = [
      `pack            version ${pack?.manifest?.version}, `
        + `${pack?.manifest?.covers?.complete ? 'COMPLETE range' : 'selective disclosure'}`,
      `disclosed       record ${r.disclosed.join(', ')}`,
      '                this proves the included record and says NOTHING about any other',
    ];
    for (const w of r.witnesses) {
      lines.push(`witness         ${w.issuer}: `
        + `${w.verified ? 'VERIFIED' : w.accepted ? 'does not verify' : 'not accepted by your policy'}`);
    }
    for (const f of r.findings) {
      lines.push(`${f.verdict === 'fail' ? 'FAIL  ' : 'note  '}          ${f.code}: ${f.detail}`);
    }
    lines.push('', `verdict         ${r.verdict.toUpperCase()}`, '');
    // 0 ok, 1 fail, 2 inconclusive — a VERDICT about the pack. Refusals exit
    // 3 and never land in this range: a recipient scripting this who mistyped
    // a flag used to get 2, indistinguishable from "the pack is inconclusive",
    // so a refusal read as a verdict about evidence.
    const exit = r.verdict === 'ok' ? 0 : r.verdict === 'fail' ? 1 : 2;
    return { exit, out: `${lines.join('\n')}\n` };
  }

  // ── building a pack: the operator's side ──────────────────────────────────
  const root = positional[0];
  if (root === undefined) return { exit: 3, out: '', err: `a store directory is required\n\n${USAGE}` };
  const seq = Number(flags.event);
  if (!Number.isSafeInteger(seq)) {
    return { exit: 3, out: '', err: `--event needs a record_seq\n\n${USAGE}` };
  }

  const probe = new Store(root, flags.collector ?? 'unknown');
  let store;
  try {
    const available = probe.collectors();
    const collector = flags.collector ?? available[0] ?? 'unknown';
    if (flags.collector !== undefined && !available.includes(collector)) {
      return {
        exit: 3, out: '',
        err: `this store holds no chain for collector ${JSON.stringify(collector)}`
          + `${available.length === 0 ? '' : `; it holds ${available.join(', ')}`}\n`,
      };
    }
    store = flags.collector === undefined ? new Store(root, collector) : probe;
    const pack = buildDisclosure(store, { record_seq: seq });
    const json = `${JSON.stringify(pack, null, 1)}\n`;
    if (flags.out !== undefined) {
      writeFileSync(flags.out, json, { mode: 0o600 });
      return { exit: 0, out: `wrote a disclosure of record ${seq} to ${flags.out}\n` };
    }
    return { exit: 0, out: json };
  } catch (e) {
    if (e instanceof DiscloseError) return { exit: 3, out: '', err: `${e.message}\n` };
    throw e;
  } finally {
    store?.close();
    if (probe !== store) probe.close();
  }
}
