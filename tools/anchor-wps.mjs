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
import { verifyStore } from '@splitstick/verify';

const ROOT = new URL('..', import.meta.url).pathname;
const DEFAULT_WPS = join(ROOT, 'docs/witness-practice-statement.md');
const DEFAULT_OUT = join(ROOT, 'out/wps-anchor');
const ORIGIN = 'splitstick.dev/wps';

// ── arguments ───────────────────────────────────────────────────────────────
/** @type {string|null} */
let configPath = null;
let OUT = DEFAULT_OUT;
let WPS = DEFAULT_WPS;
/** @type {any} */
let acceptance = null;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const a = argv[i];
  if (a === '--config') {
    configPath = argv[i + 1] ?? null;
    if (configPath === null) { console.error('--config needs a path'); process.exit(2); }
    i += 1;
  } else if (a === '--policy') {
    // The ACCEPTANCE policy — whose signature counts. A separate file from
    // --config by DES-09, because a verification that terminates at the key of
    // the party who asked for the signature establishes nothing.
    const v = argv[i + 1];
    if (v === undefined) { console.error('--policy needs a path'); process.exit(2); }
    acceptance = JSON.parse(readFileSync(v, 'utf8'));
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
    console.error(`unknown argument ${JSON.stringify(a)}; usage: anchor-wps [--config <file>] [--policy <file>] [--statement <file>] [--out <dir>]`);
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

// RECORDING and ANCHORING are separate steps, and this used to exit here when
// the digest was unchanged — before the witness configuration was even read.
// So the natural sequence, record the statement now and anchor it when a
// witness set exists, was impossible: the second run saw an unchanged digest
// and went home without contacting anybody. "Already recorded" is not "already
// anchored", and only the first of those is a reason to append nothing.
const unchanged = current?.next_policy === digest;
const previous = unchanged
  ? /** @type {string} */ (current?.previous_policy)
  : (current?.next_policy ?? GENESIS_POLICY);

/** @type {number} */
let recordSeq;
if (unchanged) {
  recordSeq = Number(current?.record_seq);
} else {
  collector.policy({ previous, next: digest, subject: 'practice-statement' });
  await collector.checkpoint();
  const appended = store.readChain().map(e => e.record).filter(r => r?.kind === 'policy').at(-1);
  recordSeq = Number(appended?.record_seq);
}

/**
 * The checkpoint the statement's record falls under: the earliest one whose
 * tree size reaches it. That is the artefact a witness countersigns, and on a
 * later run it has to be FOUND rather than assumed to be the one just written.
 */
let cpSeq = null;
let cpTreeSize = null;
for (const { seq, blob } of store.readCheckpoints()) {
  const p = parseEnvelope(blob);
  if (p.tree_size === null || p.tree_size < recordSeq) continue;
  if (cpSeq === null || seq < cpSeq) { cpSeq = seq; cpTreeSize = p.tree_size; }
}
if (cpSeq === null) {
  console.error(
    `record ${recordSeq} in ${OUT} is under no checkpoint, so there is nothing a witness `
    + 'could countersign. A checkpoint covering it has to exist before it can be anchored.',
  );
  store.close();
  process.exit(1);
}

// ── anchoring, if and only if a witness was configured ──────────────────────
if (configPath !== null) {
  const cfg = parseConfig(readFileSync(configPath, 'utf8'), OUT);
  const witnesses = witnessesFromConfig(cfg);
  if (witnesses.length === 0) {
    console.error(`${configPath} configures no witnesses, so there is nothing to anchor to`);
    store.close();
    process.exit(1);
  }
  // Issuers already on the envelope are skipped by the Anchorer, so running
  // this against an already-anchored checkpoint adds nothing and breaks
  // nothing.
  const anchorer = new Anchorer({ store, witnesses, quorum: 1 });
  const r = await anchorer.anchor(cpSeq);
  for (const f of r.failed) console.error(`  witness ${f.issuer} failed: ${f.detail}`);
}

// ── what may be claimed, decided by the VERIFIER ────────────────────────────
//
// Three states, not two. Issuer presence is not verification: an envelope can
// carry a countersignature this operator could not check, and reporting that
// as anchored states as established exactly what has not been established.
//
//   RECORDED                 nothing countersigned it.
//   COUNTERSIGNED (unverified)  a proof is present and nothing checked it —
//                            either no acceptance policy was supplied, or it
//                            does not accept that issuer.
//   ANCHORED (verified)      the proof validates against the acceptance policy.
//
// The verdict comes from verifyStore, the shipped verification path, rather
// than from a check written here: that is what "no special path" means, and it
// is also the only way the TSA token verification, trust path and EKU checks
// apply to this artefact as they do to any other.
//
// DES-09 keeps the two policy files apart on purpose — --config says who is
// ASKED, --policy says whose signature is ACCEPTED. Collapsing them would make
// every verification terminate at the asker's own key, so with no --policy the
// honest answer is "unverified" and never "anchored".
const report = await verifyStore(OUT, {
  collector: 'wps',
  ...(acceptance ? { policy: acceptance } : {}),
});

// SCOPED TO THIS VERSION. verifyStore reports every countersignature in the
// store, across every checkpoint, and reading that aggregate as the answer
// attributed one version's evidence to another: with v1.0 witnessed and v1.1's
// own checkpoint signed by nobody, v1.1 was reported ANCHORED (verified) on
// the strength of v1.0's proof — a false assurance about exactly the thing
// anchoring is for, the publication time of the newer statement.
//
// A proof is evidence about this record when the tree its checkpoint committed
// to REACHES this record. That covers the checkpoint found above and any later
// one, and excludes every earlier one however well it verifies.
const covers = (/** @type {{ tree_size: number|null }} */ w) =>
  w.tree_size !== null && w.tree_size >= recordSeq;
const present = report.witnesses.filter(covers);
const verified = present.filter(w => w.accepted && w.verdict === 'ok');
const elsewhere = report.witnesses.filter(w => !covers(w));
const status = verified.length > 0
  ? 'ANCHORED (verified)'
  : present.length > 0 ? 'COUNTERSIGNED (unverified)' : 'RECORDED (not anchored)';

console.log(`
Witness Practice Statement v${version} — ${status}${unchanged ? ', already recorded' : ''}.

  digest        ${digest}
  supersedes    ${previous}
  record_seq    ${recordSeq}
  checkpoint    ${cpSeq} (tree_size ${cpTreeSize})
  versions      ${policies.length + (unchanged ? 0 : 1)} in this chain
  store         ${OUT}
  identity      ${formatVkey(ORIGIN, signer.publicKey)}
  countersigned ${present.length === 0 ? 'nobody' : present.map(w => `${w.id} [${w.accepted ? w.verdict : 'not accepted by your policy'}]`).join(', ')}${elsewhere.length > 0 ? `
  not counted   ${elsewhere.length} proof(s) on checkpoint(s) ${[...new Set(elsewhere.map(w => w.checkpoint_seq))].sort((a, b) => a - b).join(', ')}, whose tree does not reach record ${recordSeq}` : ''}
${unchanged ? `
Nothing appended: re-recording an unchanged statement would put a second record
of the same version in the chain and make one publication look like two. The
existing record's checkpoint was used, so a statement recorded earlier can be
anchored later.
` : ''}
Verify it the ordinary way — there is no special path, which is what "chained
like any other record" means:

  node packages/verify/src/cli.mjs ${OUT} --collector wps --key <identity>

Recompute the digest yourself:

  shasum -a 256 ${WPS}
${verified.length > 0 ? `
Anchored: the digest above fell under a checkpoint countersigned by
${verified.map(w => `  - ${w.id} (${w.establishes})`).join('\n')}
and those proofs verify against the acceptance policy you supplied, so the TIME
of this version is established by those parties and not by this operator. Under
the shipped default (FR-48) that time comes from a TSA, with nothing
maintaining sequence state over it.
` : present.length > 0 ? `
Countersigned, NOT verified. ${present.length} proof(s) are on the envelope and
nothing here checked them:
${present.map(w => `  - ${w.id}: ${w.accepted ? w.verdict : 'no acceptance policy accepts this issuer'}`).join('\n')}
A proof nobody checked is a proof that may not verify later, and the first
anyone would hear of it is an auditor's report. Supply the acceptance policy
that names these issuers and their keys:

  npm run anchor-wps -- --config <witnesses> --policy <acceptance.json>
` : `
THE LIMIT, stated because LEG-09 asks for anchored and this is not that. This
run is signed by a local development key and countersigned by nobody, so what
it establishes is the version chain and the digest of this text — NOT when the
statement was published. The repository holds no operator key and must not.

To actually anchor it, submit it to a witness set and name whose signatures you
accept. The statement does not have to be re-recorded first: an existing
record's checkpoint is found and submitted.

  npm run anchor-wps -- --config path/to/witnesses.yaml --policy path/to/acceptance.json

Until an operator does that with their own witness set, the external-anchoring
half of LEG-09 is outstanding, and docs/m3b-follow-ups.md says so.
`}`);
store.close();
