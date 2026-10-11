import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { verifyStore } from '../src/verify.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';

const tx = (over = {}) => ({
  run: 'r-1', tool: 'transfer_funds', consequential: true,
  args: Buffer.from('{"amount":2000000}'),
  result: Buffer.from('OK ref=TX-77814'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

/** A store with four records and a signed checkpoint. */
async function evidence(n = 4) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < n; i++) c.action(tx({ correlation: `c-${i}` }));
  await c.checkpoint();
  return { root, store, signer, collector: c, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

const chainFile = root => join(root, 'chain', 'host-1.jsonl');
const readLines = root => readFileSync(chainFile(root), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
const writeLines = (root, ls) => writeFileSync(chainFile(root), ls.map(l => JSON.stringify(l)).join('\n') + '\n');

// A flawless M1 store reads INCONCLUSIVE, not ok. There is no countersignature
// in it, so four of DES-12's ten checks cannot be answered, and a bare `ok`
// would imply more than was checked — the exact overclaim an external review
// pushed back on. What a clean store asserts is zero failures.
test('a clean store has no failures and is inconclusive only for what it cannot answer', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.tree_size, 4);
  // SUCCESSION passes on a one-epoch log: the chain walks from the pinned root
  // and has nothing else in it, which is a true answer rather than an absent one.
  for (const name of ['FORMAT', 'SEQUENCE', 'CHAIN', 'LEAF', 'CONTENT', 'TREE', 'OP-SIG', 'SUCCESSION']) {
    assert.equal(r.checks.find(c => c.name === name).verdict, 'ok', name);
  }
  assert.deepEqual(
    r.checks.filter(c => c.verdict === 'inconclusive').map(c => c.name),
    ['WITNESS', 'ROLLUP', 'COVERAGE', 'POLICY'],
    'and exactly the checks that need a second party are the unanswered ones');
  assert.equal(r.summary.passed, 8);
  assert.equal(r.summary.unanswered, 4);
});

// SEC-06 / red-team A — alter the recorded action.
test('SEC-06: an altered argument is LEAF_MISMATCH and the verdict is fail', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[1].record.args.cid = 'sha256:' + 'ab'.repeat(32);
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

// SEC-07 / red-team C — alter an event and repair the citing digest.
test('SEC-07: a repaired citation is still detected', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[1].record.outcome = 'denied';
  writeLines(root, lines);
  const bad = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(bad.verdict, 'fail');
  assert.ok(bad.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

test('a deleted middle record is SEQ_BROKEN', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines.splice(1, 1);
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'SEQ_BROKEN'));
});

// FR-35 — substituting stored content while preserving the pointer.
test('FR-35: a swapped payload is CONTENT_MISMATCH', async () => {
  const { root, store, vkey } = await evidence();
  const cid = readLines(root)[0].record.args.cid;
  store.content.overwriteForTest(cid, Buffer.from('{"amount":25}'));
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'CONTENT_MISMATCH'), JSON.stringify(r.findings));
});

// DES-12 / DES-13 — lawful erasure must never read as a tamper.
test('a shredded record is inconclusive, never fail', async () => {
  const { root, store, vkey } = await evidence();
  store.shredRecord(2);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.summary.failed, 0, 'erasure must add no failure');
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
  assert.ok(!r.findings.some(f => f.code === 'LEAF_MISMATCH'));
  assert.equal(r.checks.find(c => c.name === 'CHAIN').verdict, 'ok',
    'the chain still verifies — only the content check cannot be answered');
});

test('inconclusive never upgrades to fail, and a single fail outranks it', async () => {
  const { root, store, vkey } = await evidence();
  store.shredRecord(2);
  const lines = readLines(root);
  lines[3].record.outcome = 'denied';
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail', 'one fail makes the whole run fail');
  assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
  assert.ok(r.findings.some(f => f.code === 'LEAF_MISMATCH'));
});

// FR-10 / OPSIG_INVALID — and FR-63's half of the identity problem.
test('OPSIG_INVALID: a re-signed checkpoint under another key does not pass', async () => {
  const { root, vkey } = await evidence();
  const other = await generateDevSigner(ORIGIN);
  const otherVkey = formatVkey(ORIGIN, other.publicKey);
  const r = await verifyStore(root, { collector: 'host-1', vkey: otherVkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_INVALID' || f.code === 'IDENTITY_UNPINNED'),
    JSON.stringify(r.findings));
  assert.equal((await verifyStore(root, { collector: 'host-1', vkey })).summary.failed, 0);
});

test('IDENTITY_UNPINNED: a checkpoint under an origin the reader did not pin', async () => {
  const { root } = await evidence();
  const elsewhere = await generateDevSigner('splitstick.dev/host-2');
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey('splitstick.dev/host-2', elsewhere.publicKey) });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'IDENTITY_UNPINNED'), JSON.stringify(r.findings));
});

test('TREE_MISMATCH: a checkpoint root that is not the root of this log', async () => {
  const { root, signer, vkey } = await evidence();
  const { checkpointText, encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const text = checkpointText({ origin: ORIGIN, tree_size: 4, root: Buffer.alloc(32, 7) });
  new Store(root, 'host-1').writeCheckpoint(1, encodeNote(text, [await signNote(text, signer)]));
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH'), JSON.stringify(r.findings));
});

// AC-4, stated honestly: truncation above the last checkpoint is not detectable here.
test('truncation above the last checkpoint is not detected, and the report says so', async () => {
  const { root, vkey } = await evidence(4);
  const lines = readLines(root);
  writeLines(root, lines.slice(0, 3));   // drop the tail, below the checkpointed size
  const below = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(below.verdict, 'fail', 'below a checkpointed size, truncation IS caught');
  assert.ok(below.findings.some(f => f.code === 'TREE_MISMATCH' || f.code === 'SIZE_REGRESSED'));

  // Now a log whose tail was never checkpointed.
  const { root: r2, vkey: v2, store, signer: s2 } = await evidence(4);
  let t = Date.parse('2026-10-11T11:00:00.000Z');
  // The same epoch key: a reopened collector must present the live one, and a
  // fresh key here would be refused rather than silently signing unendorsed.
  const c2 = new Collector({ store, config: parseConfig(CFG, r2),
    signer: s2, collector: 'host-1', origin: ORIGIN,
    now: () => new Date(t += 1000) });
  c2.action(tx({ correlation: 'c-tail' }));
  const full = await verifyStore(r2, { collector: 'host-1', vkey: v2 });
  assert.equal(full.summary.failed, 0);
  writeLines(r2, readLines(r2).slice(0, 4));
  const cut = await verifyStore(r2, { collector: 'host-1', vkey: v2 });
  assert.equal(cut.summary.failed, 0, 'a prefix at or above the checkpoint is internally perfect');
  assert.ok(cut.capability.cannot.some(s => /truncation/i.test(s)),
    'so the capability statement must say truncation is not detectable');
});

// FR-57 — a verdict is incomplete without saying what the evidence could establish.
test('FR-57: the capability statement is derived from the evidence, not from config', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(Array.isArray(r.capability.can));
  assert.ok(r.capability.cannot.length > 0);
  assert.ok(r.capability.cannot.some(s => /no witness/i.test(s)),
    'with no countersignature present, that is the headline limit');
  assert.ok(r.trusting.some(s => /primitive/i.test(s)));
  assert.ok(r.trusting.some(s => new RegExp(ORIGIN).test(s)));
  assert.equal(r.witnesses.length, 0, 'quorum is reported from proofs present, never from config');
});

test('a run with no key supplied reports OP-SIG inconclusive rather than ok', async () => {
  const { root } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.summary.failed, 0);
  const opsig = r.checks.find(c => c.name === 'OP-SIG');
  assert.equal(opsig.verdict, 'inconclusive');
  assert.ok(r.findings.some(f => f.code === 'OPSIG_UNCHECKED'));
  assert.equal(r.checks.find(c => c.name === 'CHAIN').verdict, 'ok');
});

// NFR-07 / DES-16 — an unknown version stops, never partially verifies.
test('FORMAT_UNSUPPORTED: an unknown record version fails closed', async () => {
  const { root, vkey } = await evidence();
  const lines = readLines(root);
  lines[2].record.v = 2;
  writeLines(root, lines);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'FORMAT_UNSUPPORTED'));
});

test('an empty store is inconclusive, not ok — there is nothing to attest', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  new Store(root, 'host-1');
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.verdict, 'inconclusive');
  assert.ok(r.findings.some(f => f.code === 'NO_EVIDENCE'));
});

/**
 * NFR-05, NFR-06 — offline by construction, enforced at the code level.
 *
 * This used to scan `packages/verify/src` alone, which left a hole found while
 * writing M2's failure-mode inventory: a network import in `core` would leave
 * the verifier passing its own offline test while transitively depending on
 * networking. The guarantee is about what the verifier PULLS IN, not only what
 * it contains, so the scan now follows the in-repository dependency graph from
 * the verifier's entry point.
 *
 * It is also why the AWS KMS signer is its own package: core cannot acquire a
 * cloud SDK without contradicting this.
 */
const NETWORK_MODULES = ['node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls', 'node:dns', 'node:http2'];

/** Every in-repo module the verifier reaches, transitively. @returns {Set<string>} */
function reachableFromVerifier() {
  const roots = [fileURLToPath(new URL('../src/index.mjs', import.meta.url)),
                 fileURLToPath(new URL('../src/verify.mjs', import.meta.url)),
                 fileURLToPath(new URL('../src/cli.mjs', import.meta.url))];
  /** @type {Set<string>} */
  const seen = new Set();
  /** @param {string} file */
  const visit = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/from\s+'([^']+)'/g)) {
      const spec = /** @type {string} */ (m[1]);
      let resolved = null;
      if (spec.startsWith('.')) {
        resolved = fileURLToPath(new URL(spec, pathToFileURL(file)));
      } else if (spec.startsWith('@splitstick/')) {
        // Workspace sibling: @splitstick/core/store -> packages/core/src/store.mjs
        const [, pkg, ...rest] = spec.split('/');
        const sub = rest.length ? rest.join('/') : 'index';
        resolved = fileURLToPath(new URL(
          `../../${pkg}/src/${sub}${sub.endsWith('.mjs') ? '' : '.mjs'}`, import.meta.url));
      }
      if (resolved && existsSync(resolved)) visit(resolved);
    }
  };
  roots.filter(existsSync).forEach(visit);
  return seen;
}

/**
 * Comments stripped before scanning for network use.
 *
 * The check matched the word `fetch` in a comment explaining that this verifier
 * does NOT fetch — so prose saying the right thing failed the test asserting
 * it. That is the third instrument in this project to read its own
 * documentation as code; the other two are tools/lint-failure-codes.mjs and
 * tools/lint-claims.mjs. Stripping comments is the fix in all three.
 * @param {string} t
 */
const code = (t) => t.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

test('NFR-05: nothing the verifier reaches imports a network module', () => {
  const reached = reachableFromVerifier();
  assert.ok(reached.size >= 8, `the walk should reach core, not just verify: ${reached.size} modules`);
  assert.ok([...reached].some(f => f.includes('/core/src/')), 'core must be in the graph');

  for (const file of reached) {
    const text = code(readFileSync(file, 'utf8'));
    for (const m of NETWORK_MODULES) {
      assert.ok(!text.includes(m), `${file} imports ${m}`);
    }
    assert.ok(!/\bfetch\s*\(/.test(text), `${file} calls fetch`);
    assert.ok(!/@aws-sdk\//.test(text), `${file} imports an AWS SDK — the verifier must not`);
  }
});

test('NFR-05: the offline scan still catches a real network call in code', () => {
  // The instrument, proved. Stripping comments must not have stripped the
  // check's teeth: a fetch in code still has to fail, and a fetch in a comment
  // must not.
  const real = code('import https from "node:https";\nawait fetch("https://x");');
  assert.match(real, /\bfetch\s*\(/);
  assert.ok(real.includes('node:https'));
  const prose = code('// this verifier never calls fetch( ) and imports no node:https\nconst a = 1;');
  assert.ok(!/\bfetch\s*\(/.test(prose));
  assert.ok(!prose.includes('node:https'));
});

test('NFR-05: the offline scan would notice a network import in core', () => {
  // The check that the check can fail. Previously it could not have: core was
  // outside the scan entirely.
  const reached = reachableFromVerifier();
  const core = [...reached].filter(f => f.includes('/core/src/'));
  assert.ok(core.length >= 5, `core modules reached: ${core.length}`);
  for (const m of NETWORK_MODULES) {
    assert.ok(!core.some(f => readFileSync(f, 'utf8').includes(m)), `a core module imports ${m}`);
  }
});

// SEC-14's code check: no verifier or collector module imports a key-export API.
test('SEC-14: no private-key API outside the one development signer module', () => {
  const roots = [
    new URL('../src/', import.meta.url),
    new URL('../../core/src/', import.meta.url),
    new URL('../../collect-oma/src/', import.meta.url),
  ];
  const banned = /createPrivateKey|generateKeyPair|privateEncrypt|privateDecrypt|type:\s*['"]pkcs8['"]/;
  let allowed = 0;
  for (const dir of roots) {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      if (!f.isFile() || !f.name.endsWith('.mjs')) continue;
      const text = readFileSync(new URL(f.name, dir), 'utf8');
      if (!banned.test(text)) continue;
      assert.equal(f.name, 'signer-file.mjs',
        `${f.name} touches private key material; only the development signer may`);
      allowed++;
    }
  }
  assert.equal(allowed, 1, 'and exactly one module does');
});

// DES-14 — an adapter may not touch cryptography.
test('DES-14: the OMA adapter contains no cryptography', () => {
  const dir = new URL('../../collect-oma/src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.mjs')) continue;
    const text = readFileSync(new URL(f, dir), 'utf8');
    for (const m of ['node:crypto', 'createHash', 'sha256', 'leafDigest', 'chainHead']) {
      assert.ok(!text.includes(m), `${f} touches ${m}: an adapter produces a record and nothing else`);
    }
  }
});

// DES-16 / NFR-07 — the suite travels in the signed subject, and a verifier
// either knows it or refuses the batch.
test('the checkpoint declares its algorithm suite and the verifier reads it', async () => {
  const { root, vkey } = await evidence();
  const note = JSON.parse(
    readFileSync(join(root, 'checkpoints', 'host-1', '1.json'), 'utf8')).note;
  assert.match(note, /\nsuite SS1\n/);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  assert.ok(!r.findings.some(f => f.code === 'SUITE_UNDECLARED'));
});

test('an unknown suite is FORMAT_UNSUPPORTED, never partially verified', async () => {
  const { root, signer, vkey } = await evidence();
  const { encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const { Store } = await import('@splitstick/core/store');
  const leaves = new Store(root, 'host-1').readChain().map(e => e.leaf);
  // Hand-built, because checkpointText refuses to emit an unknown suite — the
  // case under test is a note written by something else, or by a later release.
  const text = `${ORIGIN}\n${leaves.length}\n${treeRoot(leaves).toString('base64')}\nsuite SS9\n`;
  new Store(root, 'host-1').writeCheckpoint(1, encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  const f = r.findings.find(x => x.code === 'FORMAT_UNSUPPORTED');
  assert.ok(f, JSON.stringify(r.findings));
  assert.match(f.detail, /SS9/);
});

test('a checkpoint with no suite line is inconclusive, not assumed current', async () => {
  const { root, signer, vkey } = await evidence();
  const { encodeNote, checkpointText } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const { Store } = await import('@splitstick/core/store');
  const leaves = new Store(root, 'host-1').readChain().map(e => e.leaf);
  const text = checkpointText({ origin: ORIGIN, tree_size: leaves.length, root: treeRoot(leaves) });
  new Store(root, 'host-1').writeCheckpoint(1, encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, 'an undeclared suite is not a contradiction');
  assert.ok(r.findings.some(f => f.code === 'SUITE_UNDECLARED'));
  assert.equal(r.verdict, 'inconclusive');
});

/**
 * Found in review. With nine records and a newest checkpoint committing to
 * five, the verifier reported ZERO findings and said nothing about the four
 * records anchored by nothing. The capability statement said truncation was
 * undetectable but not from WHERE — and the height is the number a reader
 * actually needs: DES-12's own FR-57 example prints "truncation above
 * record_seq 4812 is NOT detectable", and DES-19's cross-pack mechanism has
 * nothing to key on without it.
 */
test('FR-57: the report names the height above which truncation is undetectable', async () => {
  const { root, store, signer, vkey } = await evidence(4);
  let t = Date.parse('2026-10-11T11:00:00.000Z');
  const c2 = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  c2.action(tx({ correlation: 'c-tail-1' }));
  c2.action(tx({ correlation: 'c-tail-2' }));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  assert.equal(r.tree_size, 6);
  assert.equal(r.anchored_tree_size, 4, 'four records are committed to by a checkpoint');
  assert.ok(r.findings.some(f => f.code === 'UNANCHORED_TAIL'));
  assert.ok(r.capability.cannot.some(s => /above record_seq 4/.test(s)),
    `the height must appear in the capability block: ${JSON.stringify(r.capability.cannot)}`);
});

test('a fully anchored log reports no unanchored tail', async () => {
  const { root, vkey } = await evidence(4);
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.anchored_tree_size, 4);
  assert.ok(!r.findings.some(f => f.code === 'UNANCHORED_TAIL'));
  assert.ok(r.capability.cannot.some(s => /above record_seq 4/.test(s)),
    'and the height is still stated, because the tail above it is still the gap');
});

/**
 * Found in review: merkle.mjs implemented and tested consistency proofs and the
 * verifier never called them, so a later checkpoint that did NOT extend an
 * earlier one went unnoticed. Dead code and a missing check at once.
 */
test('a later checkpoint that does not extend an earlier one is CONSISTENCY_BROKEN', async () => {
  const { root, store, signer, vkey } = await evidence(3);
  const { checkpointText, encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');

  // A second checkpoint over a DIFFERENT history of the same size: the first
  // record's leaf replaced. Both are correctly signed; they cannot both be
  // checkpoints of one append-only log.
  const leaves = store.readChain().map(e => e.leaf);
  const forged = [Buffer.alloc(32, 9), ...leaves.slice(1)];
  const text = checkpointText({ origin: ORIGIN, tree_size: forged.length, root: treeRoot(forged), suite: 'SS1' });
  new Store(root, 'host-1').writeCheckpoint(2, encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'TREE_MISMATCH' || f.code === 'CONSISTENCY_BROKEN'),
    JSON.stringify(r.findings.map(f => f.code)));
});

test('checkpoints must not go backwards in tree_size', async () => {
  const { root, store, signer, vkey } = await evidence(4);
  const { checkpointText, encodeNote } = await import('@splitstick/core/note');
  const { signNote } = await import('@splitstick/core/signer');
  const { treeRoot } = await import('@splitstick/core/merkle');
  const leaves = store.readChain().map(e => e.leaf);
  // Checkpoint 2 commits to fewer records than checkpoint 1 — a rollback.
  const text = checkpointText({ origin: ORIGIN, tree_size: 2, root: treeRoot(leaves.slice(0, 2)), suite: 'SS1' });
  new Store(root, 'host-1').writeCheckpoint(2, encodeNote(text, [await signNote(text, signer)]));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.findings.some(f => f.code === 'CONSISTENCY_BROKEN'), JSON.stringify(r.findings.map(f => f.code)));
});

/**
 * Found in review: a crash during an append leaves a partial JSON line, and
 * readChain threw a raw SyntaxError out of the verifier. A torn write is the
 * ordinary consequence of a crash, so it has to be a verdict, not a stack
 * trace — and it must not be reported as a tamper either.
 */
test('a torn final line is reported, not thrown', async () => {
  const { root, vkey } = await evidence(3);
  const path = join(root, 'chain', 'host-1.jsonl');
  writeFileSync(path, readFileSync(path, 'utf8') + '{"record":{"v":1},"lea');

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'inconclusive', 'a half-written line is not a contradiction');
  assert.equal(r.summary.failed, 0);
  const f = r.findings.find(x => x.code === 'TORN_WRITE');
  assert.ok(f, JSON.stringify(r.findings.map(x => x.code)));
  assert.match(f.detail, /last line/i);
  assert.equal(r.tree_size, 3, 'and the records before it still verify');
});

test('a corrupted line in the MIDDLE is a failure, not a torn write', async () => {
  const { root, vkey } = await evidence(3);
  const path = join(root, 'chain', 'host-1.jsonl');
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  lines[1] = '{"record":{"v":1},"lea';
  writeFileSync(path, lines.join('\n') + '\n');

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail', 'only the LAST line can be explained by a crash');
  assert.ok(r.findings.some(f => f.code === 'FORMAT_UNSUPPORTED' || f.code === 'MALFORMED_RECORD'));
});

// Found in review: with two collectors in one store and no --collector, the
// verifier silently picked the first chain and never mentioned the other.
test('a store holding several collectors says so instead of picking one quietly', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    const c = new Collector({ store, config: parseConfig(CFG, root),
      signer: await generateDevSigner(`o/${id}`), collector: id, origin: `o/${id}` });
    c.action(tx({ correlation: 'c-1' }));
    store.close();
  }
  const r = await verifyStore(root, {});
  assert.ok(r.findings.some(f => f.code === 'MULTIPLE_COLLECTORS'), JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.verdict, 'inconclusive');
  // Naming one is unambiguous and verifies normally.
  const one = await verifyStore(root, { collector: 'host-a' });
  assert.ok(!one.findings.some(f => f.code === 'MULTIPLE_COLLECTORS'));
});

/**
 * Review finding. The capability block asserted chain integrity whenever any
 * record existed, so a verification that FAILED with LEAF_MISMATCH still
 * printed "no record was altered, inserted, removed or reordered". The block
 * contradicted the verdict directly above it. An affirmative capability must
 * depend on the checks that actually passed.
 */
test('FR-57: a failed verification claims no integrity it did not establish', async () => {
  const { root, vkey } = await evidence();
  const path = join(root, 'chain', 'host-1.jsonl');
  const lines = readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  lines[1].record.outcome = 'denied';
  writeFileSync(path, lines.map(l => JSON.stringify(l)).join('\n') + '\n');

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.deepEqual(r.capability.can, [], 'a contradicted record establishes nothing about this chain');
  assert.ok(r.capability.cannot.some(s => /contradicts itself|failed/i.test(s)),
    `the block must say the evidence failed: ${JSON.stringify(r.capability.cannot)}`);
});

test('FR-57: an unchecked operator signature is not claimed as established', async () => {
  const { root } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1' });   // no key pinned
  assert.ok(!r.capability.can.some(s => /signed the tree size/.test(s)),
    'OP-SIG was inconclusive, so nothing about the signature may be claimed');
  assert.ok(r.capability.can.some(s => /ordering and content integrity/.test(s)),
    'but the chain checks did pass and may be claimed');
});

test('FR-57: a clean run claims exactly what passed', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0);
  assert.ok(r.capability.can.some(s => /ordering and content integrity/.test(s)));
  assert.ok(r.capability.can.some(s => /signed the tree size/.test(s)));
});

test('FR-57: content that could not be reproduced is not claimed either', async () => {
  const { root, store, vkey } = await evidence();
  const cid = readFileSync(join(root, 'chain', 'host-1.jsonl'), 'utf8')
    .trim().split('\n').map(l => JSON.parse(l))[0].record.args.cid;
  store.content.overwriteForTest(cid, Buffer.from('{"amount":25}'));
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.verdict, 'fail');
  assert.deepEqual(r.capability.can, []);
});

/**
 * Review finding P1-3. Chains and salts were collector-scoped but checkpoints
 * were not: every collector wrote `checkpoints/<n>.note` into one shared
 * directory, and the verifier read that directory whole.
 *
 * The consequence was worse than a collision. Two HONEST collectors sharing a
 * store root each verified as `fail` with TREE_MISMATCH and CONSISTENCY_BROKEN,
 * because each was being asked to account for the other's signed notes. A
 * tamper-evidence product accusing a correct operator is the worst failure it
 * has.
 */
test('two collectors in one store each verify against their own checkpoints', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  /** @type {Record<string, string>} */
  const keys = {};
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    const signer = await generateDevSigner(`o/${id}`);
    keys[id] = formatVkey(`o/${id}`, signer.publicKey);
    let t = Date.parse('2026-10-11T10:00:00.000Z');
    const c = new Collector({ store, config: parseConfig(CFG, root), signer,
      collector: id, origin: `o/${id}`, now: () => new Date(t += 1000) });
    for (let i = 0; i < 3; i++) c.action(tx({ correlation: `${id}-${i}` }));
    await c.checkpoint();
    c.action(tx({ correlation: `${id}-late` }));
    await c.checkpoint();
    store.close();
  }

  for (const id of ['host-a', 'host-b']) {
    const r = await verifyStore(root, { collector: id, vkey: keys[id] });
    assert.equal(r.summary.failed, 0, `${id}: ${JSON.stringify(r.findings.map(f => f.code))}`);
    assert.equal(r.tree_size, 4);
    assert.equal(r.anchored_tree_size, 4, 'its own second checkpoint anchors its own tail');
    assert.ok(!r.findings.some(f => /TREE_MISMATCH|CONSISTENCY_BROKEN|IDENTITY_UNPINNED/.test(f.code)));
  }
});

test('each collector keeps its own checkpoint ordinals', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  /** @type {Record<string, number[]>} */
  const seqs = {};
  for (const id of ['host-a', 'host-b']) {
    const store = new Store(root, id);
    const c = new Collector({ store, config: parseConfig(CFG, root),
      signer: await generateDevSigner(`o/${id}`), collector: id, origin: `o/${id}` });
    c.action(tx({ correlation: 'c-1' }));
    const first = await c.checkpoint();
    c.action(tx({ correlation: 'c-2' }));
    const second = await c.checkpoint();
    seqs[id] = [first.checkpoint_seq, second.checkpoint_seq];
    store.close();
  }
  assert.deepEqual(seqs['host-a'], [1, 2]);
  assert.deepEqual(seqs['host-b'], [1, 2], 'an ordinal is per collector, not per directory');
});

// Evidence must never be silently ignored: a note that does not sit under a
// collector cannot be attributed, and saying nothing about it would hide it.
test('an unattributable checkpoint is reported, not skipped', async () => {
  const { root, vkey } = await evidence(3);
  writeFileSync(join(root, 'checkpoints', 'stray.note'), 'o\n9\n' + Buffer.alloc(32).toString('base64') + '\n\n— o AAAA\n');
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.ok(r.findings.some(f => f.code === 'CHECKPOINTS_UNATTRIBUTED'),
    JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.summary.failed, 0, 'a stray file is not a contradiction');
});

// CONTENT_ABSENT had no test until tools/lint-failure-codes.mjs asked for one.
// A shredded payload must read as inconclusive, never as a substitution.
test('CONTENT_ABSENT: a shredded payload is inconclusive, not a mismatch', async () => {
  const { root, store, vkey } = await evidence(3);
  const first = store.readChain()[0];
  store.shredRecord(Number(/** @type {any} */ (first.record).record_seq));

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, 'erasure adds no failure');
  assert.ok(r.findings.some(f => f.code === 'CONTENT_ABSENT'), JSON.stringify(r.findings.map(f => f.code)));
  assert.ok(!r.findings.some(f => f.code === 'CONTENT_MISMATCH'));
  assert.equal(r.verdict, 'inconclusive');
});

// UNANCHORED had no test either, and the lint's own substring bug had been
// excusing it: a search for UNANCHORED was satisfied by UNANCHORED_TAIL.
test('UNANCHORED: records with no checkpoint at all fix the log extent to nothing', async () => {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-verify-'));
  const store = new Store(root, 'host-1');
  const signer = await generateDevSigner(ORIGIN);
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN });
  for (let i = 0; i < 3; i++) c.action(tx({ correlation: `c-${i}` }));
  // Deliberately no checkpoint().
  const r = await verifyStore(root, { collector: 'host-1', vkey: formatVkey(ORIGIN, signer.publicKey) });
  assert.equal(r.summary.failed, 0, 'an unanchored log is not a contradiction');
  assert.ok(r.findings.some(f => f.code === 'UNANCHORED'), JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.anchored_tree_size, 0);
  assert.equal(r.verdict, 'inconclusive');
  assert.ok(r.capability.cannot.some(s => /truncation anywhere/.test(s)),
    'and with no committed height, truncation is undetectable anywhere');
});
