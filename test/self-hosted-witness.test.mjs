// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * OPS-03 — the self-hosted witness guide, followed end to end.
 *
 * "Guide published; followed end to end in a clean environment" is the stated
 * verify, and a human following it once proves it worked once. So the guide's
 * own code blocks are CONCATENATED AND RUN, in a directory that holds nothing
 * else, with only the bindings the guide explicitly says come from elsewhere
 * supplied around it. A guide that drifts from the API stops running.
 *
 * The prelude is deliberately minimal: `store`, `collector` and
 * `operatorPublicKey` are the three things the guide names without defining,
 * because they belong to the collector side. Anything beyond those three would
 * be this test quietly doing the work the guide was supposed to describe.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const GUIDE = join(REPO, 'docs', 'self-hosted-witness.md');

/** @param {string} lang */
function blocks(lang) {
  const md = readFileSync(GUIDE, 'utf8');
  /** @type {string[]} */
  const out = [];
  const re = new RegExp(`\`\`\`${lang}\\n([\\s\\S]*?)\`\`\``, 'g');
  for (let m = re.exec(md); m !== null; m = re.exec(md)) out.push(String(m[1]));
  return out;
}

const PRELUDE = `
import { mkdtempSync } from 'node:fs';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner as __gen } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '@splitstick/verify';

// The collector side, which the guide names and does not define.
const __origin = 'splitstick.dev/host-1';
const __signer = await __gen(__origin);
const operatorPublicKey = __signer.publicKey;
const store = new Store('./evidence', 'host-1');
let __t = Date.parse('2026-10-11T10:00:00.000Z');
const collector = new Collector({
  store, config: parseConfig('version: 1\\nstore: ./s\\n', '.'), signer: __signer,
  collector: 'host-1', origin: __origin, now: () => new Date(__t += 1000),
});
for (let i = 1; i <= 3; i += 1) {
  collector.action({
    run: 'r-1', tool: 'transfer_funds', consequential: true,
    args: Buffer.from('{"amount":' + i + '00}'), result: Buffer.from('OK'),
    outcome: 'ok', attempt: 1, correlation: 'c-' + i,
  });
}
`;

const EPILOGUE = `
// The guide's own closing claim: the reader verifies it, and audit's
// countersignature verifies against the key audit publishes.
if (result.attached.length !== 1) {
  throw new Error('the guide anchored nothing: ' + JSON.stringify(result));
}
if (result.attached[0].verified !== true) {
  throw new Error('the countersignature did not verify');
}
store.close();
const report = await verifyStore('./evidence', {
  collector: 'host-1', vkey: formatVkey(__origin, __signer.publicKey),
  policy: { quorum: 1, witnesses: [{
    id: 'audit.internal',
    public_key: Buffer.from(witnessKey.publicKey).toString('base64'),
    establishes: ['sequence'],
  }] },
});
if (report.summary.failed !== 0) throw new Error('verify found failures');
const w = report.witnesses.find((x) => x.id === 'audit.internal');
if (!w || w.verdict !== 'ok') throw new Error('audit.internal did not verify: ' + JSON.stringify(w));

// And the guide's stated limit, asserted rather than asserted ABOUT: a
// sequence-only witness leaves time unanswered, so the verdict is
// inconclusive. If this ever became 'ok' the guide would be overclaiming.
if (report.verdict !== 'inconclusive') {
  throw new Error('expected inconclusive, got ' + report.verdict);
}
process.stdout.write('GUIDE OK\\n');
`;

test('OPS-03: the guide runs, in a directory that holds nothing else', async () => {
  const js = blocks('js');
  assert.equal(js.length, 3, 'the guide documents standing up, wiring, and anchoring');
  // Inside the repo so `@splitstick/*` resolves by name, but otherwise empty:
  // no store, no state directory, no key — a clean environment.
  const dir = mkdtempSync(join(REPO, '.ops03-'));
  try {
    writeFileSync(join(dir, 'run.mjs'), PRELUDE + js.join('\n') + EPILOGUE);
    const r = await new Promise((resolve) => {
      execFile(process.execPath, [join(dir, 'run.mjs')], { cwd: dir },
        (err, stdout, stderr) => resolve({ err, stdout, stderr }));
    });
    assert.match(r.stdout, /GUIDE OK/,
      `the guide does not run end to end:\n${r.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('OPS-03: the guide leads with the separation, not the mechanics', () => {
  // The mechanics are reproducible from the source. The thing a reader can get
  // catastrophically wrong while following every command correctly is holding
  // both keys — so it has to be stated before anything else and stated as the
  // requirement it is, not as advice among advice.
  const md = readFileSync(GUIDE, 'utf8');
  const separation = md.indexOf('does not operate the collector');
  const firstCode = md.indexOf('```');
  assert.notEqual(separation, -1, 'the guide never states who must hold the witness key');
  assert.ok(separation < firstCode,
    'the key-separation requirement appears after the first code block, where it reads as a note');
  assert.match(md, /the same party agreeing with itself/,
    'the guide does not say what goes wrong when one team holds both keys');
});

test('OPS-03: the guide refuses the claim a self-hosted witness cannot support', () => {
  // LEG-12 lives here too: this is the page an operator reads while deciding
  // what their deployment proves, and it is the likeliest place to imply that
  // an internal witness carries a presumption it cannot.
  const md = readFileSync(GUIDE, 'utf8');
  assert.match(md, /does \*\*not\*\* establish \*\*time\*\*/);
  assert.match(md, /no self-hosted witness and no witness\s+this project operates can provide/,
    'the guide does not say the Art. 41 presumption needs a qualified TSA');
  assert.match(md, /reports `inconclusive`, not `ok`/,
    'the guide does not say what the verifier actually reports for this deployment');
});
