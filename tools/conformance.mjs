#!/usr/bin/env node
/**
 * `npm run conformance` — FR-46, GOV-06.
 *
 * Runs the witness conformance suite against the reference witness, and then
 * runs the suite against deliberately broken witnesses to show it can FAIL.
 * A green result from a suite nothing can fail certifies nothing, so the
 * second half is not optional and exits non-zero with the first.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { StatefulWitness } from '@splitstick/witness-self';
import { runConformance, selfTest, formatConformance } from '@splitstick/witnesses/conformance';

const ORIGIN = 'conformance.test/log';
const signer = await generateDevSigner(ORIGIN);
const witnessKey = await generateDevSigner('reference.witness');

/** @type {string[]} */
const dirs = [];
const makeWitness = () => {
  const dir = mkdtempSync(join(tmpdir(), 'ss-conformance-'));
  dirs.push(dir);
  // Whatever an implementation needs before it accepts a submission belongs in
  // the factory — the reference witness enrols an operator identity.
  const make = () => {
    const w = new StatefulWitness({ dir, signer: witnessKey });
    try { w.enrol(ORIGIN, signer.publicKey); } catch { /* already enrolled */ }
    return w;
  };
  const w = /** @type {any} */ (make());
  w.reopen = make;
  return w;
};

const r = await runConformance({ makeWitness, signer, origin: ORIGIN });
process.stdout.write(formatConformance(r));

const st = await selfTest({ signer, witnessKey });
process.stdout.write('\nself-test — can this suite fail?\n\n');
for (const x of st.results) {
  process.stdout.write(`  ${x.caught ? `caught by ${x.expect}` : `MISSED (wanted ${x.expect})`}`
    + `  — a witness that ${x.broken}\n`);
}
process.stdout.write(st.passed
  ? '\n  Each broken witness was caught BY THE CHECK FOR THE PROPERTY IT BREAKS, not\n'
    + '  incidentally. A self-test satisfied by any failure would pass on a suite whose\n'
    + '  checks all fired for the wrong reason.\n\n'
  : '\n  THE SUITE DID NOT CATCH A BROKEN WITNESS. A green result above means nothing.\n\n');

for (const d of dirs) rmSync(d, { recursive: true, force: true });
process.exit(r.passed && st.passed ? 0 : 1);
