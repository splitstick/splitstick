import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
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
  args: Buffer.from('{"amount":2000000}'), result: Buffer.from('OK'),
  outcome: /** @type {const} */ ('ok'), attempt: 1, correlation: 'c-1', ...over,
});

async function evidence() {
  const root = mkdtempSync(join(tmpdir(), 'ss-assume-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig(CFG, root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < 4; i += 1) c.action(tx({ correlation: `c-${i}` }));
  await c.checkpoint();
  store.close();
  return { root, signer, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

test('SEC-03: the report names everything the reader is trusting, and the operator is only on it for completeness', async () => {
  const { root, vkey } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  // The list is the requirement. A verifier that silently relied on something
  // would be the failure SEC-03 describes, so the honest form is to enumerate.
  assert.ok(r.trusting.length > 0);
  assert.ok(r.trusting.some(s => /SHA-256|Ed25519/.test(s)), JSON.stringify(r.trusting));
  // The operator appears for COMPLETENESS of capture, and for nothing else:
  // not for integrity, not for ordering, not for content.
  const operatorLines = r.trusting.filter(s => /operator/i.test(s));
  assert.ok(operatorLines.length > 0);
  assert.ok(operatorLines.every(s => /completeness|identity|custody|destr/i.test(s)),
    JSON.stringify(operatorLines));
  // And nothing in the list is US. Matched on the software rather than on the
  // string "splitstick", which also appears in the operator's own origin —
  // the first version of this assertion failed on `splitstick.dev/host-1`,
  // which is the operator's identity and exactly what a reader SHOULD be
  // trusting themselves to have pinned correctly.
  assert.ok(!r.trusting.some(s => /this software|the collector binary|@splitstick|the vendor/i.test(s)),
    JSON.stringify(r.trusting));
});

test('SEC-03: verification does not read the operator config', async () => {
  const { root, vkey } = await evidence();
  // An operator's configuration is not evidence. A verifier that read it would
  // let the party under examination choose what it was examined against.
  writeFileSync(join(root, 'splitstick.yaml'),
    'version: 1\nwitnesses:\n  - { id: imaginary, type: rfc3161, url: "https://nope" }\nquorum: 9\n');
  const r = await verifyStore(root, { collector: 'host-1', vkey });
  assert.equal(r.summary.failed, 0, JSON.stringify(r.findings, null, 1));
  // The imaginary witness does not appear, and quorum 9 is not adopted.
  assert.ok(!r.witnesses.some(w => w.id === 'imaginary'));
  assert.equal(r.quorum.required, 1);
});

test('SEC-03: the verifier source reaches no config loader', () => {
  // Asserted structurally, because the test above only shows that one file was
  // ignored. The verifier must not be able to read a config at all.
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.mjs')) continue;
    const text = readFileSync(new URL(f, dir), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
    assert.ok(!/from '@splitstick\/core\/config'/.test(text),
      `${f} imports the config loader; the operator's configuration is not evidence`);
    assert.ok(!/parseConfig|loadConfig/.test(text), `${f} parses a config`);
  }
});

test('FR-63: a pack under a different origin is reported, not silently accepted', async () => {
  const { root } = await evidence();
  const elsewhere = await generateDevSigner('splitstick.dev/host-2');
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey('splitstick.dev/host-2', elsewhere.publicKey),
  });
  // Nothing prevents an operator maintaining a second log. The guarantee is
  // that a reader who pinned an identity is TOLD when they are shown another.
  assert.ok(r.findings.some(f => f.code === 'IDENTITY_UNPINNED'),
    JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.verdict, 'fail');
});

test('FR-63: a pack under the right origin but the wrong key is reported too', async () => {
  const { root } = await evidence();
  const impostor = await generateDevSigner(ORIGIN);
  const r = await verifyStore(root, {
    collector: 'host-1', vkey: formatVkey(ORIGIN, impostor.publicKey),
  });
  // The origin matches and the key does not. An identity is the pair.
  assert.ok(r.findings.some(f => f.code === 'OPSIG_INVALID' || f.code === 'SUCCESSION_BROKEN'),
    JSON.stringify(r.findings.map(f => f.code)));
  assert.equal(r.verdict, 'fail');
});

test('FR-63: pinning nothing is reported as pinning nothing, not as a pass', async () => {
  const { root } = await evidence();
  const r = await verifyStore(root, { collector: 'host-1' });
  assert.equal(r.checks.find(c => c.name === 'OP-SIG')?.verdict, 'inconclusive');
  assert.ok(r.capability.cannot.some(s => /no operator identity was pinned/.test(s)));
  assert.ok(!r.capability.can.some(s => /signed the tree size/.test(s)));
});

test('SEC-04: the one-honest-witness assumption is documented where an operator will meet it', () => {
  // SEC-04 asks for the assumption to be documented. "Documented" is checked
  // here rather than reviewed, because a documentation requirement nobody
  // enforces is a documentation requirement nobody keeps.
  const design = readFileSync(
    new URL('../../../design/DES-08-witness-protocol.md', import.meta.url), 'utf8');
  assert.match(design, /one honest witness|at least one witness/i);
  const threat = readFileSync(
    new URL('../../../docs/threat-model.md', import.meta.url), 'utf8');
  assert.match(threat, /collusion/i);
  // And the uncomfortable half: a set whose members share an interest is one
  // witness wearing several hats, and no quorum number fixes it.
  const witnesses = readFileSync(
    new URL('../../witnesses/src/index.mjs', import.meta.url), 'utf8');
  assert.match(witnesses, /share an interest/);
});
