/**
 * Anchor the Witness Practice Statement — LEG-09.
 *
 * The statement is versioned AND anchored like any other record, so the claim
 * "this is what version 1.0 said" is checkable rather than asserted. A
 * published document can be edited; a digest in a chained, countersigned log
 * cannot be edited without breaking the chain.
 *
 * What this writes is a `policy` record carrying the statement's digest, then a
 * checkpoint over it. The artefact lands in `out/wps-anchor/` and verifies with
 * the ordinary verifier — there is no special path for it, which is the point of
 * "like any other record".
 *
 * Run with `npm run anchor-wps`.
 */

import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';

const ROOT = new URL('..', import.meta.url).pathname;
const WPS = join(ROOT, 'docs/witness-practice-statement.md');
const OUT = join(ROOT, 'out/wps-anchor');

const text = readFileSync(WPS, 'utf8');
const version = /^\*\*Version (\d+\.\d+)\*\*/m.exec(text)?.[1];
if (!version) {
  console.error('the practice statement declares no version; refusing to anchor an unversioned document');
  process.exit(1);
}
const digest = `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

/**
 * The previous version's digest. For 1.0 there is none, and rather than invent
 * one the record cites the digest of the empty string — which is a documented,
 * reproducible constant and not a pretend predecessor.
 */
const GENESIS_POLICY = `sha256:${createHash('sha256').update('').digest('hex')}`;
const previousPath = join(OUT, 'previous.json');
let previous = GENESIS_POLICY;
try {
  previous = JSON.parse(readFileSync(previousPath, 'utf8')).digest ?? GENESIS_POLICY;
} catch { /* first run */ }

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

// A development signer, because this repository holds no operator key and must
// not. An operator anchoring their own copy uses their own signer; what this
// run produces is a reproducible artefact for THIS text, not a claim by anyone.
const signer = await generateDevSigner('splitstick.dev/wps');
const store = new Store(OUT, 'wps');
const collector = new Collector({
  store,
  config: parseConfig('version: 1\nstore: ./s\n', OUT),
  signer,
  collector: 'wps',
  origin: 'splitstick.dev/wps',
});
collector.policy({ previous, next: digest });
const cp = await collector.checkpoint();
writeFileSync(previousPath, JSON.stringify({ version, digest }, null, 1) + '\n');
store.close();

console.log(`
Witness Practice Statement v${version} anchored.

  digest        ${digest}
  previous      ${previous}
  tree_size     ${cp.tree_size}
  store         out/wps-anchor
  identity      ${formatVkey('splitstick.dev/wps', signer.publicKey)}

Verify it the ordinary way — there is no special path, which is what "anchored
like any other record" means:

  node packages/verify/src/cli.mjs out/wps-anchor --collector wps --key <identity>

Recompute the digest yourself:

  shasum -a 256 docs/witness-practice-statement.md

THE LIMIT. This run is signed by a throwaway development key and countersigned
by nobody, so what it establishes is that the digest above is the digest of this
text. An operator anchoring their own copy, with their own signer and their own
witness set, is what makes the TIME of the statement independently established —
and under the shipped default (FR-48) that time comes from a TSA, with nothing
maintaining sequence state over it.
`);
