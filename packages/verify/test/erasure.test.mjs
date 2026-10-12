import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig, ConfigError } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';
import { ALLOWED, RECORD_KINDS } from '@splitstick/core/record';
import { ContentMissing } from '@splitstick/core/content';
import { scanResidue, classifySchema, CLASSIFIED } from '@splitstick/core/residue';
import { verifyStore } from '../src/verify.mjs';

const ORIGIN = 'splitstick.dev/host-1';

/** A store holding one record with every erasable field populated. */
async function rig(root = mkdtempSync(join(tmpdir(), 'ss-erase-'))) {
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-12T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  c.action({
    run: 'r-1', tool: 'transfer_funds', consequential: true,
    agent: Buffer.from('alice@example.com'),
    args: Buffer.from('{"amount":200000}'),
    result: Buffer.from('OK ref=TX-77814'),
    outcome: 'ok', attempt: 1, correlation: 'c-1',
    approval: {
      decision: 'approve',
      reviewer: Buffer.from('bob@example.com'),
      request: Buffer.from('approve the transfer please'),
    },
  });
  c.action({
    run: 'r-1', tool: 't', consequential: true, args: Buffer.from('x'),
    result: Buffer.from('y'), outcome: 'ok', attempt: 1, correlation: 'c-2',
  });
  c.heartbeat();
  return { root, store, c, signer, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

// ── PRIV-05: the residue is the enumerated set, and the schema says so ──────

test('PRIV-05: every field the schema permits is classified', () => {
  // The property that keeps the inventory from describing a previous version of
  // the schema. A field added to ALLOWED and left unclassified would survive a
  // deletion request BY DEFAULT, and a scan checking only the residue would
  // pass forever while the schema grew underneath it.
  assert.deepEqual(classifySchema(), [],
    'extend residue.mjs: a field nobody classified is a field nobody decided about');
});

test('PRIV-05: the classification is a decision about every kind, not just actions', () => {
  // Asserted against the schema itself, so this cannot drift into checking a
  // hardcoded list of kinds that is shorter than the enum.
  assert.ok(RECORD_KINDS.length >= 9, `only ${RECORD_KINDS.length} kinds — did the enum shrink?`);
  for (const kind of RECORD_KINDS) {
    const fields = /** @type {Record<string, readonly string[]>} */ (ALLOWED)[kind];
    assert.ok(Array.isArray(fields), `${kind} has no allowlist`);
    for (const f of fields) {
      assert.ok(f in CLASSIFIED, `${kind}.${f} is unclassified`);
    }
  }
});

test('PRIV-05: a new schema field fails the scan rather than passing silently', () => {
  // The paired half. The assertions above pass when everything is classified;
  // this one proves they would FAIL if something were not — otherwise they are
  // assertions about a function that could be `return []`.
  // ALLOWED is frozen, correctly, so the schema is handed in rather than
  // mutated — and classifySchema taking it as a parameter is what makes this
  // provable at all.
  const extended = { ...ALLOWED, tool_call: [...ALLOWED.tool_call, 'subject_email'] };
  const missing = classifySchema(extended);
  assert.deepEqual(missing, [{ kind: 'tool_call', field: 'subject_email' }],
    'an unclassified field must be reported, naming the kind it appeared on');

  // A kind in the enum with no allowlist at all cannot be scanned, which is a
  // worse state than an unclassified field and must also be reported.
  const { tool_call, ...withoutActions } = ALLOWED;
  assert.ok(classifySchema(/** @type {any} */ (withoutActions))
    .some(u => u.kind === 'tool_call' && /no allowlist/.test(u.field)));

  assert.deepEqual(classifySchema(), [], 'and the real schema is still fully classified');
});

test('PRIV-05: after shredding, the residue matches the permanent set exactly', async () => {
  const { root, store, c } = await rig();
  await c.checkpoint();
  store.close();

  let s = new Store(root, 'host-1');
  // Before: the payloads are retrievable, so the scan reports them against a
  // record a deletion request covers. This is what makes the "after" assertion
  // meaningful rather than a check of an empty store.
  const before = scanResidue(s, { shredded: [1] });
  assert.ok(before.findings.some(f => f.code === 'RESIDUE_CONTENT_RETAINED'));
  assert.ok(before.findings.some(f => f.code === 'RESIDUE_SALT_RETAINED'));
  assert.ok(before.findings.every(f => f.verdict === 'fail'),
    'a residue finding is a privacy claim broken, not a weaker one');
  s.shredRecord(1);
  s.close();

  s = new Store(root, 'host-1');
  const after = scanResidue(s, { shredded: [1] });
  assert.deepEqual(after.findings, [],
    `residue after shredding: ${JSON.stringify(after.findings, null, 1)}`);
  assert.equal(after.checked, 3);
  s.close();
});

test('PRIV-03: the enumerated set is unrecoverable after the procedure', async () => {
  // Every payload a deletion request covers: the agent label, both payloads,
  // the reviewer and the reviewed request.
  const { root, store, c } = await rig();
  await c.checkpoint();
  const rec = store.readChain()[0]?.record ?? {};
  const cids = [
    /** @type {any} */ (rec.agent)?.cid,
    /** @type {any} */ (rec.args)?.cid,
    /** @type {any} */ (rec.result)?.cid,
    /** @type {any} */ (rec.approval)?.reviewer?.cid,
    /** @type {any} */ (rec.approval)?.request?.cid,
  ].filter(Boolean);
  assert.equal(cids.length, 5, 'all five erasable payloads are committed to begin with');
  for (const cid of cids) assert.equal(store.content.has(cid), true);
  store.close();

  let s = new Store(root, 'host-1');
  s.shredRecord(1);
  s.close();
  s = new Store(root, 'host-1');
  for (const cid of cids) {
    assert.equal(s.content.has(cid), false, `${cid} is still retrievable`);
    assert.throws(() => s.content.get(cid), ContentMissing);
  }
  // And the SECOND record's payloads are untouched: a deletion request is for
  // one data subject, and shredding everything would be a different operation.
  const other = /** @type {any} */ (s.readChain()[1]?.record);
  assert.equal(s.content.has(other.args.cid), true, 'an unrelated record is not collateral');
  s.close();
});

test('PRIV-04, FR-36: the chain still verifies after erasure, and erasure is not tampering', async () => {
  // Reporting a lawful deletion as `fail` would make compliance look like an
  // attack, which is the single most damaging thing the verifier could say
  // about an operator who did the right thing.
  const { root, store, c, vkey } = await rig();
  await c.checkpoint();
  store.close();

  const clean = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(clean.summary.failed, 0);

  let s = new Store(root, 'host-1');
  s.shredRecord(1);
  s.close();

  const after = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(after.summary.failed, 0, JSON.stringify(after.findings));
  assert.ok(after.findings.length > 0, 'and the absence is reported, not passed over');
  for (const f of after.findings) {
    assert.notEqual(f.verdict, 'fail', `${f.code} must not be fail: erasure is lawful`);
  }
  assert.ok(after.findings.some(f => f.code === 'CONTENT_ABSENT'));
  assert.ok(after.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
});

test('a leaf salt deleted without the content is inconclusive, and the content still disclosable',
  async () => {
    // Inventory row 24. The two artefacts are independent, and a partial
    // erasure must not read as either complete or as damage.
    const { root, store, c, vkey } = await rig();
    await c.checkpoint();
    const cid = /** @type {any} */ (store.readChain()[0]?.record).args.cid;
    store.close();

    // Remove the leaf salt only, leaving the payload in place.
    let s = new Store(root, 'host-1');
    const { readFileSync, writeFileSync } = await import('node:fs');
    const path = join(root, 'salts', 'host-1.jsonl');
    const kept = readFileSync(path, 'utf8').trim().split('\n')
      .filter(l => JSON.parse(l).record_seq !== 1);
    writeFileSync(path, kept.length ? `${kept.join('\n')}\n` : '');
    s.close();

    const r = await verifyStore(root, { collector: 'host-1', vkey });
    assert.equal(r.summary.failed, 0, JSON.stringify(r.findings));
    assert.ok(r.findings.some(f => f.code === 'LEAF_INCONCLUSIVE'));
    s = new Store(root, 'host-1');
    assert.equal(s.content.has(cid), true, 'the payload is still there and still disclosable');
    s.close();
  });

test('PRIV-05: the agent label\'s LENGTH is not retained, and a payload\'s is', async () => {
  // Found by the residue scan on its first run: `agent.bytes` was retained and
  // DES-13's table — established by review as the whole inventory rather than a
  // sample — does not list it. Nothing reads it, and a label's length is more
  // identifying per byte than a payload's, because an address or a name is
  // short and its length narrows a guess at a person.
  const { root, store, c } = await rig();
  await c.checkpoint();
  const rec = /** @type {any} */ (store.readChain()[0]?.record);
  assert.equal(rec.agent.bytes, undefined, 'a label length is not retained');
  assert.equal(rec.approval.reviewer.bytes, undefined);
  assert.equal(rec.approval.request.bytes, undefined);
  // And the payload lengths ARE retained: a verifier needs them to detect a
  // truncated content store, which is the documented and unmitigated trade.
  assert.equal(typeof rec.args.bytes, 'number');
  assert.equal(typeof rec.result.bytes, 'number');
  assert.equal(rec.args.bytes, 17);
  store.close();
});

test('PRIV-05: an erasable value left behind is named by the scan', async () => {
  // The scan must be able to fail. Shredding the content but keeping the leaf
  // salt leaves the commitment linkable — a plaintext anybody can guess at can
  // still be confirmed against it.
  const { root, store, c } = await rig();
  await c.checkpoint();
  store.close();

  let s = new Store(root, 'host-1');
  const rec = /** @type {any} */ (s.readChain()[0]?.record);
  // Content gone, leaf salt deliberately kept.
  s.content.shredAll([rec.args.cid, rec.result.cid, rec.agent.cid,
    rec.approval.reviewer.cid, rec.approval.request.cid]);
  s.close();

  s = new Store(root, 'host-1');
  const r = scanResidue(s, { shredded: [1] });
  assert.ok(r.findings.some(f => f.code === 'RESIDUE_SALT_RETAINED' && f.record_seq === 1),
    `expected the retained salt to be named, got ${JSON.stringify(r.findings)}`);
  assert.ok(!r.findings.some(f => f.code === 'RESIDUE_CONTENT_RETAINED'),
    'and the content it did remove is not reported');
  s.close();
});

test('PRIV-09, FR-37: retention is a storage setting, and the chain is untouched', async () => {
  // The key was in the config's known-key list and never parsed, so
  // `retention: 30d` was accepted and silently meant "keep forever" — the
  // third instance of this shape in the project, after `padding` and the
  // verifier's `--vkey`.
  const dir = mkdtempSync(join(tmpdir(), 'ss-ret-'));
  assert.equal(parseConfig('version: 1\nstore: ./s\n', dir).retention_ms, null,
    'absent means keep everything');
  assert.equal(parseConfig('version: 1\nstore: ./s\nretention: 30d\n', dir).retention_ms,
    30 * 86_400_000);
  for (const bad of ['retention: 0\n', 'retention: -5d\n', 'retention: soon\n']) {
    assert.throws(() => parseConfig(`version: 1\nstore: ./s\n${bad}`, dir), ConfigError, bad);
  }

  // A sweep shreds what is older than the window and leaves the chain alone.
  const { root, store, c, vkey } = await rig();
  await c.checkpoint();
  const before = store.readChain().map(e => e.leaf.toString('hex'));
  const heads = store.readChain().map(e => e.head.toString('hex'));
  const cid = /** @type {any} */ (store.readChain()[0]?.record).args.cid;
  store.close();

  let s = new Store(root, 'host-1');
  // Ninety days later, with a thirty-day window: everything here is older.
  const swept = s.applyRetention({
    retention_ms: 30 * 86_400_000,
    now: Date.parse('2027-01-10T10:00:00.000Z'),
  });
  assert.deepEqual(swept.shredded, [1, 2, 3]);
  assert.equal(swept.kept, 0);
  assert.deepEqual(swept.undated, []);
  assert.equal(s.content.has(cid), false, 'the payload is gone');
  s.close();

  // THE CHAIN IS BYTE-IDENTICAL. Retention governs the deletable store and
  // nothing else; a setting that reached the leaf would make the cryptography
  // and the policy inseparable.
  s = new Store(root, 'host-1');
  assert.deepEqual(s.readChain().map(e => e.leaf.toString('hex')), before, 'leaves unchanged');
  assert.deepEqual(s.readChain().map(e => e.head.toString('hex')), heads, 'heads unchanged');
  s.close();

  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, 'and it still verifies');
  assert.deepEqual(scanResidue(new Store(root, 'host-1'), { shredded: swept.shredded }).findings,
    [], 'with a residue matching the permanent set');
});

test('FR-37: a sweep keeps what is inside the window, and never guesses at an undated record',
  async () => {
    // A record that cannot be placed in time is not swept: guessing would mean
    // deleting evidence on the strength of a field we just refused to read.
    const { root, store, c } = await rig();
    await c.checkpoint();
    store.close();

    const { readFileSync, writeFileSync } = await import('node:fs');
    const path = join(root, 'chain', 'host-1.jsonl');
    const ls = readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    ls[1].record.ts = 'whenever';
    writeFileSync(path, `${ls.map(l => JSON.stringify(l)).join('\n')}\n`);

    const s = new Store(root, 'host-1');
    const swept = s.applyRetention({
      retention_ms: 365 * 86_400_000,
      now: Date.parse('2026-10-12T10:00:10.000Z'),
    });
    assert.deepEqual(swept.shredded, [], 'nothing is a year old yet');
    assert.equal(swept.kept, 2);
    assert.deepEqual(swept.undated, [2], 'and the unplaceable record is named, not swept');
    s.close();
  });

test('FR-37: a sweep with no window is refused rather than treated as "delete nothing"',
  () => {
    // Absent retention means keep everything, which is the caller's decision to
    // skip the sweep — not to call it with nothing and have it quietly no-op.
    const root = mkdtempSync(join(tmpdir(), 'ss-ret-none-'));
    const s = new Store(root, 'host-1');
    for (const bad of [null, 0, -1, undefined, '30d']) {
      assert.throws(() => s.applyRetention({ retention_ms: /** @type {any} */ (bad) }), TypeError,
        JSON.stringify(bad));
    }
    s.close();
  });
