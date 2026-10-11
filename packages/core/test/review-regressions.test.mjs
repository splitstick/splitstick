import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Store } from '../src/store.mjs';
import { Collector } from '../src/collector.mjs';
import { parseConfig } from '../src/config.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { parseNote, encodeNote } from '../src/note.mjs';
import { signNote } from '../src/signer.mjs';
import { Anchorer } from '../src/anchor.mjs';
import { describeOtsProof, FILE_MAGIC } from '../src/opentimestamps.mjs';

const CFG = 'version: 1\nstore: ./s\n';
const ORIGIN = 'splitstick.dev/host-1';
const tx = (over = {}) => ({
  run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'), result: Buffer.from('y'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function fresh() {
  const root = mkdtempSync(join(tmpdir(), 'ss-rev-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  return { root, store, signer, c };
}

// ── The retry queue keeps the heights that are worth retrying ────────────────

test('an overflowing queue keeps the NEWEST checkpoints, not the oldest', async () => {
  // It kept the oldest, on the stated reasoning that their unwitnessed window
  // was widest. That is backwards. The tree is append-only, so a
  // countersignature at the highest height establishes every record below it —
  // retaining heights 1 to 3 and discarding 4 to 6 meant that when the witness
  // returned, the operator could prove height 3 when height 6 was available.
  const { store, c } = await fresh();
  const dead = {
    id: 'w', proof_type: /** @type {const} */ ('c2sp-note'), establishes: ['sequence'],
    tier: /** @type {const} */ ('anchor'), async submit() { throw new Error('down'); },
  };
  const a = new Anchorer({ store, witnesses: [dead], quorum: 1, queue_ceiling: 3 });
  for (let i = 0; i < 6; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    await a.anchor(cp.checkpoint_seq);
  }
  assert.deepEqual(a.queued(), [4, 5, 6]);
  assert.equal(a.dropped, 3);
  store.close();
});

test('a flush anchors the highest first, and drops the rest as superseded', async () => {
  // Anchoring the newest makes the older queued entries not merely redundant
  // but unsubmittable: a stateful witness that has moved to height 6 refuses
  // height 4 as a regression. Retrying them oldest-first would have produced a
  // run of 400s and a log full of failures that were the queue's own doing.
  const { store, c } = await fresh();
  let up = false;
  const wkey = await generateDevSigner('audit.internal');
  /** @type {number[]} */
  const submitted = [];
  const flaky = {
    id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
    establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
    async submit(/** @type {string} */ note) {
      if (!up) throw new Error('down');
      const text = parseNote(note).text;
      submitted.push(Number(text.split('\n')[1]));
      return {
        type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.internal',
        covers: /** @type {const} */ ('note'),
        line: encodeNote(text, [await signNote(text, wkey)]).trim().split('\n').at(-1),
      };
    },
  };
  const a = new Anchorer({ store, witnesses: [flaky], quorum: 1,
    acceptance: { 'audit.internal': wkey.publicKey } });
  for (let i = 0; i < 3; i += 1) {
    c.action(tx({ correlation: `c-${i}` }));
    const cp = await c.checkpoint();
    await a.anchor(cp.checkpoint_seq);
  }
  assert.deepEqual(a.queued(), [1, 2, 3]);

  up = true;
  const r = await a.flush();
  assert.deepEqual(submitted, [3], 'only the highest is submitted');
  assert.deepEqual(r.anchored, [3]);
  assert.deepEqual(r.superseded, [1, 2]);
  assert.deepEqual(a.queued(), []);
  store.close();
});

// ── Refuted versus malformed is a type, not a message ───────────────────────

test('an OTS proof over other bytes is refuted even if the wording changes', () => {
  // It was decided by matching the text of an error message. Rewording that
  // message would have silently downgraded a `fail` to an `inconclusive`,
  // turning a proof that contradicts this checkpoint into one that merely
  // could not be read.
  const varuint = (/** @type {number} */ n) => {
    const out = [];
    for (;;) { if (n < 0x80) { out.push(n); break; } out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
    return Buffer.from(out);
  };
  const varbytes = (/** @type {Buffer} */ b) => Buffer.concat([varuint(b.length), b]);
  const digest = createHash('sha256').update('the real note').digest();
  const proof = Buffer.concat([
    FILE_MAGIC, varuint(1), Buffer.from([0x08]), digest,
    Buffer.from([0x00]), Buffer.from('0588960d73d71901', 'hex'), varbytes(varuint(900_000)),
  ]);
  const over = describeOtsProof(proof, { imprint: createHash('sha256').update('other').digest() });
  assert.equal(over.inconclusive, false, 'a proof about another document refutes this one');
  assert.equal(over.refuted, true);
  assert.notEqual(over.malformed, true);

  const mangled = describeOtsProof(Buffer.from('rubbish'), { imprint: digest });
  assert.equal(mangled.refuted, false);
  assert.equal(mangled.malformed, true);
  assert.equal(mangled.inconclusive, true);
});

// ── Dead code that read as a decision ───────────────────────────────────────

test('no branch in the anchoring path is unreachable by construction', async () => {
  // Three expressions here looked like decisions and were not: a condition that
  // could never be true, a ternary whose branches were identical, and a
  // predicate forced constant by `&& false`. All three are the kind of thing a
  // reader trusts as intent.
  //
  // Comments stripped, string literals KEPT. The first version of this test
  // matched the comments describing the removals — the fourth time an
  // instrument here read its own documentation as code, which is why
  // tools/code-text.mjs is now shared. The second version stripped literals
  // too, and then every ternary over two strings looked identical: it flagged
  // `f.code.endsWith('_INCONCLUSIVE') ? 'inconclusive' : 'fail'`, which is a
  // real decision. An instrument that cannot tell those apart is the wrong
  // instrument for this question.
  const { readFileSync } = await import('node:fs');
  const { code: strip } = await import('../../../tools/code-text.mjs');
  const src = (/** @type {string} */ rel) =>
    strip(readFileSync(new URL(rel, import.meta.url), 'utf8'));
  assert.ok(!/parsed\.note === raw/.test(src('../src/anchor.mjs')),
    'a condition that is never true');
  assert.ok(!/\? 'fail' : 'fail'/.test(src('../../verify/src/verify.mjs')),
    'a ternary with identical branches');
  assert.ok(!/&& false\b/.test(src('../src/rfc3161.mjs')), 'a predicate forced constant');
  // The instrument, proved on both sides: it sees these in code, and not in
  // the prose that describes them.
  assert.match(strip("const x = a === b ? 'fail' : 'fail';"), /\? 'fail' : 'fail'/);
  assert.ok(!/\? 'fail' : 'fail'/.test(strip("// it was ? 'fail' : 'fail' once")));
});
