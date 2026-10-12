/**
 * Record — and optionally anchor — the Witness Practice Statement. LEG-09.
 *
 * The statement is versioned and chained like any other record, so the claim
 * "this is what version 1.0 said" is checkable rather than asserted: a
 * published document can be edited, a digest in a chained log cannot be edited
 * without breaking the chain.
 *
 * TWO THINGS, kept apart on purpose, because an earlier version of this script
 * conflated them and the review caught it:
 *
 *   RECORDING is what this repository can do by itself. It appends a `policy`
 *   record carrying the statement's digest and the digest of the version it
 *   supersedes, and checkpoints it. That establishes the version chain. It
 *   establishes nothing about WHEN, because the signer is a local development
 *   key and nobody has countersigned it.
 *
 *   ANCHORING needs a second party, and therefore needs an operator's witness
 *   configuration: `--config <file>`. Only a checkpoint that comes back with a
 *   countersignature is described as anchored, and the word is chosen by
 *   reading the envelope rather than by the script's intent.
 *
 * The store is APPEND-ONLY across runs, which an earlier version was not: it
 * deleted the directory on every run, so each version's record was the only
 * one that survived and the chain linking the versions existed solely as text
 * inside the newest record. A log that discards its own history to record its
 * history is the thing this project exists not to do.
 *
 * Run with `npm run anchor-wps [-- --config witnesses.yaml]`.
 */

import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { Anchorer } from '@splitstick/core/anchor';
import { parseConfig } from '@splitstick/core/config';
import { fileSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { parseEnvelope } from '@splitstick/core/envelope';
import { witnessesFromConfig } from '@splitstick/witnesses';

const ROOT = new URL('..', import.meta.url).pathname;
const DEFAULT_WPS = join(ROOT, 'docs/witness-practice-statement.md');
const DEFAULT_OUT = join(ROOT, 'out/wps-anchor');
const ORIGIN = 'splitstick.dev/wps';

// ── arguments ───────────────────────────────────────────────────────────────
/** @type {string|null} */
let configPath = null;
let OUT = DEFAULT_OUT;
let WPS = DEFAULT_WPS;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const a = argv[i];
  if (a === '--config') {
    configPath = argv[i + 1] ?? null;
    if (configPath === null) { console.error('--config needs a path'); process.exit(2); }
    i += 1;
  } else if (a === '--statement') {
    // An operator publishes their OWN practice statement; this project's copy
    // is the default, not the only thing worth recording.
    const v = argv[i + 1];
    if (v === undefined) { console.error('--statement needs a path'); process.exit(2); }
    WPS = v;
    i += 1;
  } else if (a === '--out') {
    // So the append-only behaviour can be exercised by a test without writing
    // into the repository's own artefact directory.
    const v = argv[i + 1];
    if (v === undefined) { console.error('--out needs a path'); process.exit(2); }
    OUT = v;
    i += 1;
  } else {
    // An unknown flag is refused rather than ignored. A misspelled --config
    // that silently produced an unwitnessed artefact would be read as anchored.
    console.error(`unknown argument ${JSON.stringify(a)}; usage: anchor-wps [--config <file>] [--statement <file>] [--out <dir>]`);
    process.exit(2);
  }
}

// ── the statement ───────────────────────────────────────────────────────────
const text = readFileSync(WPS, 'utf8');
const version = /^\*\*Version (\d+\.\d+)\*\*/m.exec(text)?.[1];
if (!version) {
  console.error('the practice statement declares no version; refusing to anchor an unversioned document');
  process.exit(1);
}
const digest = `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

/**
 * The digest the first version supersedes. There is no predecessor, and rather
 * than invent one the record cites the digest of the empty string — a
 * documented, reproducible constant and not a pretend ancestor.
 */
const GENESIS_POLICY = `sha256:${createHash('sha256').update('').digest('hex')}`;

const KEY = join(OUT, 'wps-dev-key.pem');
mkdirSync(OUT, { recursive: true });

// One identity across every run, so the records form one chain under one key.
// A fresh key per run would have left each version's record unverifiable
// against the one before it even if the store had survived.
if (!existsSync(KEY)) {
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(KEY, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
}
chmodSync(KEY, 0o600);
const signer = await fileSigner(ORIGIN, KEY);

const store = new Store(OUT, 'wps');

// An existing store is bound to the key that opened it, by the succession
// journal, which is never deleted. If the key beside it no longer matches, the
// store was made by something else — in practice by the version of this script
// that generated a throwaway key per run. Say so, rather than letting the
// Collector's epoch refusal surface as a stack trace.
const live = store.readSuccession().at(-1);
if (live !== undefined && live.public_key !== signer.publicKey.toString('base64')) {
  console.error(`${OUT} is bound to a different identity than ${KEY}.

The store's live epoch ${live.epoch} names another public key, and the succession
journal is never rewritten — that refusal is the mechanism working, not a bug.
This happens with a store left by the earlier version of this script, which
generated a fresh key on every run.

It is a local, gitignored artefact. To start the chain over:

  rm -rf ${OUT}
`);
  store.close();
  process.exit(1);
}

const collector = new Collector({
  store,
  config: parseConfig('version: 1\nstore: ./s\n', OUT),
  signer,
  collector: 'wps',
  origin: ORIGIN,
});

// The predecessor comes from THE CHAIN, not from a file beside it. A side file
// is a claim about the history; the chain is the history.
const policyRecords = store.readChain().map(e => e.record).filter(r => r?.kind === 'policy');
for (const r of policyRecords) {
  // A policy record that does not name the version it introduces is damage.
  // Reading the wrong field name here produced an EMPTY list, which read as
  // "no previous version" and appended a duplicate record of the same version
  // on every run — one publication looking like two, which is the thing the
  // check below exists to prevent. An absent field is now refused, not treated
  // as an absent record.
  if (typeof r.next_policy !== 'string' || !r.next_policy) {
    console.error(
      `record ${r.record_seq} in ${OUT} is a policy record with no next_policy: `
      + 'refusing to work out the current version from a chain with a damaged entry in it',
    );
    store.close();
    process.exit(1);
  }
}
const policies = policyRecords;
const current = policies.at(-1);
if (current?.next_policy === digest) {
  console.log(`
Witness Practice Statement v${version} is already the current recorded version.

  digest        ${digest}
  records       ${policies.length} version(s) in ${OUT}

Nothing appended: re-recording an unchanged statement would put a second record
of the same version in the chain and make one publication look like two.
`);
  store.close();
  process.exit(0);
}
const previous = current?.next_policy ?? GENESIS_POLICY;

collector.policy({ previous, next: digest });
const cp = await collector.checkpoint();

// ── anchoring, if and only if a witness was configured ──────────────────────
/** @type {import('@splitstick/core/anchor').WitnessAdapter[]} */
let witnesses = [];
if (configPath !== null) {
  const cfg = parseConfig(readFileSync(configPath, 'utf8'), OUT);
  witnesses = witnessesFromConfig(cfg);
  if (witnesses.length === 0) {
    console.error(`${configPath} configures no witnesses, so there is nothing to anchor to`);
    store.close();
    process.exit(1);
  }
  const anchorer = new Anchorer({ store, witnesses, quorum: 1 });
  const r = await anchorer.anchor(cp.checkpoint_seq);
  for (const f of r.failed) console.error(`  witness ${f.issuer} failed: ${f.detail}`);
}

// Whether this is anchored is read off the envelope, not decided by intent.
const env = store.readCheckpointEnvelope(cp.checkpoint_seq);
const parsed = env === null ? null : parseEnvelope(env);
const issuers = parsed === null ? [] : [...parsed.issuers];

console.log(`
Witness Practice Statement v${version} ${issuers.length > 0 ? 'ANCHORED' : 'RECORDED (not anchored)'}.

  digest        ${digest}
  supersedes    ${previous}
  tree_size     ${cp.tree_size}
  versions      ${policies.length + 1} in this chain
  store         ${OUT}
  identity      ${formatVkey(ORIGIN, signer.publicKey)}
  countersigned ${issuers.length > 0 ? issuers.join(', ') : 'nobody'}

Verify it the ordinary way — there is no special path, which is what "chained
like any other record" means:

  node packages/verify/src/cli.mjs ${OUT} --collector wps --key <identity>

Recompute the digest yourself:

  shasum -a 256 ${WPS}
${issuers.length > 0 ? `
Anchored: the digest above fell under a checkpoint countersigned by
${issuers.map(i => `  - ${i}`).join('\n')}
so the TIME of this version is established by those parties and not by this
operator. Under the shipped default (FR-48) that time comes from a TSA, with
nothing maintaining sequence state over it.
` : `
THE LIMIT, stated because LEG-09 asks for anchored and this is not that. This
run is signed by a local development key and countersigned by nobody, so what
it establishes is the version chain and the digest of this text — NOT when the
statement was published. The repository holds no operator key and must not.

To actually anchor it, run it against a witness configuration:

  npm run anchor-wps -- --config path/to/witnesses.yaml

Until an operator does that with their own witness set, the external-anchoring
half of LEG-09 is outstanding, and docs/m3b-follow-ups.md says so.
`}`);
store.close();
