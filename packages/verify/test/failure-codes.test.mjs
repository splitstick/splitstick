import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, checkpointText, encodeNote, parseNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot } from '@splitstick/core/merkle';
import { coverageReport } from '../src/coverage.mjs';
import { verifyStore } from '../src/verify.mjs';

/**
 * Every delivered failure code is PRODUCED here, by a real verifier run over a
 * real store.
 *
 * The lint that specifies the vocabulary used to check coverage by searching
 * the test files for each code's name, which a review pointed out a comment
 * would satisfy — and a comment did, when they tried it. A static reference is
 * not a demonstration that a failure mode can occur.
 *
 * So the guarantee lives here instead, where it is executable: the table below
 * must cover exactly the codes spec/failure-codes.json marks delivered, and
 * each scenario must actually make the verifier emit its code. The lint keeps
 * only the checks it can genuinely make.
 */

const SPEC = JSON.parse(readFileSync(new URL('../../../spec/failure-codes.json', import.meta.url), 'utf8'));
const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';

const tx = (over = {}) => ({
  tool: 'transfer_funds', args: Buffer.from('{"amount":2000000}'),
  result: Buffer.from('OK ref=TX-77814'), correlation: 'c-1', ...over,
});
const chainPath = (root) => join(root, 'chain', 'host-1.jsonl');
const lines = (root) => readFileSync(chainPath(root), 'utf8').trim().split('\n').map(l => JSON.parse(l));
const write = (root, ls) => writeFileSync(chainPath(root), ls.map(l => JSON.stringify(l)).join('\n') + '\n');

/** A store with `n` records, checkpointed unless told otherwise. */
async function build({ records = 3, checkpoint = true, collector = 'host-1', origin = ORIGIN } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-codes-'));
  const signer = await generateDevSigner(origin);
  const store = new Store(root, collector);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector, origin, now: () => new Date(t += 1000) });
  for (let i = 0; i < records; i++) c.action(tx({ correlation: `c-${i}` }));
  if (checkpoint) await c.checkpoint();
  return { root, store, signer, collector: c, vkey: formatVkey(origin, signer.publicKey) };
}

/** Re-sign the current log at a given size and root, as the operator would. */
async function writeCheckpoint(ctx, seq, tree_size, root, suite = 'SS1') {
  const text = suite
    ? checkpointText({ origin: ORIGIN, tree_size, root, suite })
    : checkpointText({ origin: ORIGIN, tree_size, root });
  // Through the store, so the artefact is a DES-20 envelope. Writing a bare
  // `.note` beside an existing envelope is now its own finding
  // (ENVELOPE_NOTE_MISMATCH) and would mask the code each scenario is for.
  ctx.store.writeCheckpoint(seq, encodeNote(text, [await signNote(text, ctx.signer)]));
}

/**
 * One scenario per delivered code. Each returns the verifyStore options it
 * wants; the harness then asserts the code appears in the report.
 * @type {Record<string, (ctx: any) => Promise<Record<string, unknown>|void>>}
 */
/**
 * Codes produced by the COVERAGE REPORT rather than by verifyStore.
 *
 * The same guarantee, driven through the other entry point: these three are
 * what a coverage claim can conclude, and a code nobody has seen a real run
 * emit is a failure mode nobody has seen occur. Each returns the window to
 * report on.
 */
const COVERAGE_SCENARIOS = {
  /** A window with no record of any kind and no declaration. */
  async COVERAGE_GAP(ctx) {
    // The store built below heartbeats for a minute, stops for five, and
    // resumes. The stop is the gap.
    return { from: '2026-10-11T10:00:00.000Z', to: '2026-10-11T10:07:00.000Z' };
  },
  /** An unknown-loss interval: the chain is intact and the span is not exact. */
  async COVERAGE_UNKNOWN(ctx) {
    // Written at the collector's CURRENT clock, which the heartbeat loop has
    // advanced past the window. Reset it, or the record lands outside the
    // window under test and the scenario proves nothing.
    ctx.collector.now = () => new Date(Date.parse('2026-10-11T10:00:10.000Z'));
    ctx.collector.gapUnknown({
      from_ts: '2026-10-11T10:00:01.000Z', to_ts: '2026-10-11T10:00:02.000Z',
      last_checkpoint_source_seq: 0,
    });
    return { from: '2026-10-11T10:00:00.000Z', to: '2026-10-11T10:00:30.000Z' };
  },
  /** A record that cannot be placed in a window at all. */
  async UNDATED_RECORD(ctx) {
    const ls = lines(ctx.root);
    // Not a date, and not the right shape either: the point is that it cannot
    // be placed, and the report excludes it loudly rather than quietly.
    ls[1].record.ts = 'whenever';
    write(ctx.root, ls);
    return { from: '2026-10-11T10:00:00.000Z', to: '2026-10-11T10:00:30.000Z' };
  },
};

const SCENARIOS = {
  async NO_EVIDENCE(ctx) {
    rmSync(chainPath(ctx.root), { force: true });
  },
  async FORMAT_UNSUPPORTED(ctx) {
    const ls = lines(ctx.root);
    ls[1].record.v = 2;
    write(ctx.root, ls);
  },
  async MALFORMED_RECORD(ctx) {
    const ls = readFileSync(chainPath(ctx.root), 'utf8').trim().split('\n');
    ls.splice(1, 0, '{"record":{"v":1},"lea');
    writeFileSync(chainPath(ctx.root), ls.join('\n') + '\n');
  },
  async TORN_WRITE(ctx) {
    appendFileSync(chainPath(ctx.root), '{"record":{"v":1},"lea');
  },
  async SEQ_BROKEN(ctx) {
    const ls = lines(ctx.root);
    ls.splice(1, 1);
    write(ctx.root, ls);
  },
  async CHAIN_BROKEN(ctx) {
    const ls = lines(ctx.root);
    ls[1].prev = 'ff'.repeat(32);
    write(ctx.root, ls);
  },
  async LEAF_MISMATCH(ctx) {
    const ls = lines(ctx.root);
    ls[1].record.outcome = 'denied';
    write(ctx.root, ls);
  },
  async LEAF_INCONCLUSIVE(ctx) {
    ctx.store.shredRecord(2);
  },
  async CONTENT_ABSENT(ctx) {
    ctx.store.shredRecord(2);
  },
  async CONTENT_MISMATCH(ctx) {
    const cid = lines(ctx.root)[0].record.args.cid;
    ctx.store.content.overwriteForTest(cid, Buffer.from('{"amount":25}'));
  },
  async TREE_MISMATCH(ctx) {
    await writeCheckpoint(ctx, 1, 3, Buffer.alloc(32, 7));
  },
  async SIZE_REGRESSED(ctx) {
    write(ctx.root, lines(ctx.root).slice(0, 2));
  },
  async CONSISTENCY_BROKEN(ctx) {
    const leaves = ctx.store.readChain().map(e => e.leaf);
    await writeCheckpoint(ctx, 2, 2, treeRoot(leaves.slice(0, 2)));
  },
  async UNANCHORED() {
    // Built without a checkpoint; see `setup` below.
  },
  async UNANCHORED_TAIL(ctx) {
    ctx.collector.action(tx({ correlation: 'c-tail' }));
  },
  async OPSIG_INVALID(ctx) {
    // Same origin, different key: the signature line is there and does not verify.
    const other = await generateDevSigner(ORIGIN);
    const leaves = ctx.store.readChain().map(e => e.leaf);
    const text = checkpointText({ origin: ORIGIN, tree_size: leaves.length, root: treeRoot(leaves), suite: 'SS1' });
    ctx.store.writeCheckpoint(1, encodeNote(text, [await signNote(text, other)]));
  },
  async SUCCESSION_BROKEN(ctx) {
    // Rotate twice, then remove the middle epoch from the journal. Every
    // remaining endorsement is valid; the chain simply no longer walks.
    const second = await generateDevSigner(ORIGIN);
    await ctx.collector.rotate(second);
    const third = await generateDevSigner(ORIGIN);
    await ctx.collector.rotate(third);
    await ctx.collector.checkpoint();
    const p = join(ctx.root, 'succession', 'host-1.jsonl');
    const es = readFileSync(p, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    writeFileSync(p, [es[0], es[2]].map(e => JSON.stringify(e)).join('\n') + '\n');
  },
  async OPSIG_EPOCH_REGRESSED(ctx) {
    // Checkpoint 1 is signed by epoch 0 and checkpoint 2 by epoch 1. Re-signing
    // checkpoint 1 with epoch 2's key makes the ordinals run forwards while the
    // epochs run backwards. Two rotations are needed, not one: re-signing with
    // the immediate successor would make both checkpoints epoch 1, and equal
    // epochs are not a regression — which is the wholesale case this check
    // deliberately does not claim to catch.
    const second = await generateDevSigner(ORIGIN);
    await ctx.collector.rotate(second);
    ctx.collector.action(tx({ correlation: 'c-after-rotation' }));
    await ctx.collector.checkpoint();
    const third = await generateDevSigner(ORIGIN);
    await ctx.collector.rotate(third);
    const first = ctx.store.readCheckpoints().find((/** @type {any} */ n) => n.seq === 1);
    const { parseNote } = await import('@splitstick/core/note');
    const text = parseNote(first.note).text;
    ctx.store.writeCheckpoint(1, encodeNote(text, [await signNote(text, third)]));
  },
  async ENVELOPE_DIGEST_MISMATCH(ctx) {
    const env = JSON.parse(String(ctx.store.readCheckpointEnvelope(1)));
    env.note_digest = 'sha256:' + 'ab'.repeat(32);
    ctx.store.writeCheckpointEnvelope(1, env);
  },
  async ENVELOPE_NOTE_MISMATCH(ctx) {
    // An M1 `.note` left beside an M3a `.json` envelope for the same ordinal,
    // holding a DIFFERENT note. Both are internally consistent — the envelope's
    // digest matches its own note — so only comparing the two artefacts catches
    // it, which is the point: one checkpoint, two stories.
    const stale = checkpointText({
      origin: ORIGIN, tree_size: 2, root: Buffer.alloc(32, 3), suite: 'SS1',
    });
    writeFileSync(join(ctx.root, 'checkpoints', 'host-1', '1.note'),
      encodeNote(stale, [await signNote(stale, ctx.signer)]));
  },
  async ENVELOPE_DUPLICATE_ISSUER(ctx) {
    const env = JSON.parse(String(ctx.store.readCheckpointEnvelope(1)));
    const entry = {
      type: 'rfc3161', issuer: 'tsa.example', covers: 'note_digest',
      token: Buffer.from('token').toString('base64'),
    };
    env.countersignatures = [entry, { ...entry }];
    ctx.store.writeCheckpointEnvelope(1, env);
  },
  async WITNESS_MISSING(ctx) {
    return {
      policy: { quorum: 1, witnesses: [{ id: 'audit.internal', establishes: ['sequence'] }] },
    };
  },
  async WITNESS_SHORT(ctx) {
    // One CHECKABLE time proof, and a policy demanding two of them.
    //
    // The first version of this used a placeholder RFC 3161 token, which was
    // credited when nothing verified tokens. Now that FR-16 does, an
    // unparseable token is credited with nothing — the class count stays at
    // zero and the "short of quorum" branch is never reached, because "no
    // accepted proof at all" is a different finding. A quorum can only be
    // short if something counted.
    const witness = await generateDevSigner('audit.internal');
    const env = JSON.parse(String(ctx.store.readCheckpointEnvelope(1)));
    const text = parseNote(env.note).text;
    env.countersignatures = [{
      type: 'c2sp-note', issuer: 'audit.internal', covers: 'note',
      line: encodeNote(text, [await signNote(text, witness)]).trim().split('\n').at(-1),
    }];
    ctx.store.writeCheckpointEnvelope(1, env);
    return {
      policy: {
        quorum: 2,
        witnesses: [
          {
            id: 'audit.internal', establishes: ['time'],
            public_key: witness.publicKey.toString('base64'),
          },
          { id: 'audit.secondary', establishes: ['time'] },
        ],
      },
    };
  },
  async WITNESS_MISMATCH(ctx) {
    const witness = await generateDevSigner('audit.internal');
    const env = JSON.parse(String(ctx.store.readCheckpointEnvelope(1)));
    // A line signed over OTHER bytes by the right witness key: the shape a
    // rewritten history leaves, because the signature cannot be forged.
    const elsewhere = checkpointText({
      origin: ORIGIN, tree_size: 99, root: Buffer.alloc(32, 7), suite: 'SS1',
    });
    env.countersignatures = [{
      type: 'c2sp-note', issuer: 'audit.internal', covers: 'note',
      line: encodeNote(elsewhere, [await signNote(elsewhere, witness)]).trim().split('\n').at(-1),
    }];
    ctx.store.writeCheckpointEnvelope(1, env);
    return {
      policy: {
        quorum: 1,
        witnesses: [{
          id: 'audit.internal', establishes: ['sequence'],
          public_key: witness.publicKey.toString('base64'),
        }],
      },
    };
  },
  async TRUNCATED_BELOW_DISCLOSED(ctx) {
    // A pack already in a counterparty's hands holds a height above where this
    // record ends. The operator cannot un-disclose it (DES-19).
    return {
      disclosed: [{ tree_size: 99, root: Buffer.alloc(32).toString('base64') }],
    };
  },
  async DISCONTINUITY(ctx) {
    // The operator declares a key compromise, naming the last epoch they
    // believe sound and a new root. The declaration is signed by the key it
    // disowns, because that is the only key that exists at that moment.
    const fresh = await generateDevSigner(ORIGIN);
    ctx.collector.declareDiscontinuity({
      last_sound_epoch: 0,
      new_root_public_key: fresh.publicKey,
      reason: 'signing key compromise suspected after host intrusion',
    });
    await ctx.collector.checkpoint();
  },
  async OPSIG_UNCHECKED() {
    return { vkey: undefined };          // nothing pinned
  },
  async IDENTITY_UNPINNED(ctx) {
    const elsewhere = await generateDevSigner('splitstick.dev/host-2');
    return { vkey: formatVkey('splitstick.dev/host-2', elsewhere.publicKey) };
  },
  async SUITE_UNDECLARED(ctx) {
    const leaves = ctx.store.readChain().map(e => e.leaf);
    await writeCheckpoint(ctx, 1, leaves.length, treeRoot(leaves), null);
  },
  async MULTIPLE_COLLECTORS(ctx) {
    const second = new Store(ctx.root, 'host-b');
    const c = new Collector({ store: second, config: parseConfig(CFG, ctx.root),
      signer: await generateDevSigner('o/host-b'), collector: 'host-b', origin: 'o/host-b' });
    c.action(tx({ correlation: 'b-1' }));
    second.close();
    return { collector: undefined };     // name none, so the ambiguity is reported
  },
  async CHECKPOINTS_UNATTRIBUTED(ctx) {
    writeFileSync(join(ctx.root, 'checkpoints', 'stray.note'),
      `o\n9\n${Buffer.alloc(32).toString('base64')}\n\n— o ${Buffer.alloc(68).toString('base64')}\n`);
  },
};

/** Codes whose scenario needs the store built differently. */
const SETUP = {
  UNANCHORED: { checkpoint: false },
  UNANCHORED_TAIL: { records: 3, checkpoint: true },
};

const delivered = SPEC.codes
  .filter((/** @type {any} */ c) => SPEC.delivered_milestones.includes(c.milestone))
  .map((/** @type {any} */ c) => c.code);

test('the scenario table covers exactly the delivered codes', () => {
  const covered = [...Object.keys(SCENARIOS), ...Object.keys(COVERAGE_SCENARIOS)].sort();
  assert.deepEqual(covered, [...delivered].sort(),
    'a delivered code with no scenario here is a failure mode nobody has seen occur, '
    + 'and a scenario for an undelivered code means the spec is stale');
});

for (const code of delivered.filter(c => c in COVERAGE_SCENARIOS)) {
  test(`${code} is produced by a real coverage run`, async () => {
    // Heartbeats for a minute, a five-minute stop, then heartbeats again. The
    // same store for all three, so each scenario perturbs a log that is
    // otherwise sound.
    const ctx = await build({ records: 1, checkpoint: true });
    let t = Date.parse('2026-10-11T10:00:00.000Z');
    const beat = () => { ctx.collector.now = () => new Date(t); ctx.collector.heartbeat(); };
    for (let i = 0; i < 12; i += 1) { beat(); t += 5_000; }
    t += 300_000;
    for (let i = 0; i < 12; i += 1) { beat(); t += 5_000; }
    const window = await COVERAGE_SCENARIOS[code](ctx);
    ctx.store.close();

    const store = new Store(ctx.root, 'host-1');
    const report = await coverageReport(store, { ...window, collectors: store.collectors() });
    store.close();
    const codes = report.findings.map(f => f.code);
    assert.ok(codes.includes(code),
      `${code} was not emitted; got ${JSON.stringify(codes)} (verdict ${report.verdict})`);
    const promised = SPEC.codes.find(c => c.code === code)?.verdict;
    assert.equal(report.findings.find(f => f.code === code)?.verdict, promised,
      `${code} was emitted with a verdict the specification does not promise`);
  });
}

for (const code of delivered.filter(c => !(c in COVERAGE_SCENARIOS))) {
  test(`${code} is produced by a real verifier run`, async () => {
    const scenario = SCENARIOS[code];
    assert.ok(scenario, `no scenario for ${code}`);
    const ctx = await build(SETUP[code] ?? {});
    const override = /** @type {Record<string, unknown>} */ ((await scenario(ctx)) ?? {});
    // Defaults, then the scenario's overrides. An override of `undefined` means
    // "do not pass this at all", which is how OPSIG_UNCHECKED pins no key and
    // MULTIPLE_COLLECTORS names no collector.
    const opts = /** @type {Record<string, unknown>} */ ({ collector: 'host-1', vkey: ctx.vkey });
    for (const [k, v] of Object.entries(override)) {
      if (v === undefined) delete opts[k];
      else opts[k] = v;
    }

    const report = await verifyStore(ctx.root, /** @type {any} */ (opts));
    const codes = report.findings.map(f => f.code);
    assert.ok(codes.includes(code),
      `${code} was not emitted; got ${JSON.stringify(codes)} (verdict ${report.verdict})`);

    // And its verdict class matches what the specification promises.
    const spec = SPEC.codes.find((/** @type {any} */ c) => c.code === code);
    const finding = report.findings.find(f => f.code === code);
    assert.equal(finding.verdict, spec.verdict,
      `${code} is specified as ${spec.verdict} and was emitted as ${finding.verdict}`);
  });
}
