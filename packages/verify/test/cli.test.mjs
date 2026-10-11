import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey } from '@splitstick/core/note';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const ORIGIN = 'splitstick.dev/host-1';

/** @returns {Promise<{ code: number, stdout: string, stderr: string }>} */
const run = (args, env = {}) => new Promise((resolve) => {
  execFile(process.execPath, [CLI, ...args], { env: { ...process.env, ...env } },
    (err, stdout, stderr) => resolve({
      code: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr,
    }));
});

async function evidence() {
  const root = mkdtempSync(join(tmpdir(), 'splitstick-cli-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({ store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000) });
  for (let i = 0; i < 3; i++) {
    c.action({ tool: 'transfer_funds', args: Buffer.from(`{"amount":${i}}`),
      result: Buffer.from(`OK ref=TX-${i}`), correlation: `c-${i}` });
  }
  await c.checkpoint();
  store.close();
  return { root, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

// The exit code is the contract for anyone scripting this, so it is pinned.
// 1 is the normal code for a 1.0 store with no witness: the honest verdict is
// inconclusive, and a reader who treats 1 as failure will mis-read every pack.
test('a clean store exits 1 for inconclusive, with no failures', async () => {
  const { root, vkey } = await evidence();
  const r = await run([root, '--collector', 'host-1', '--key', vkey]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict\s+INCONCLUSIVE\s+\(8 checks passed, 4 could not be answered, 0 failed\)/);
  assert.match(r.stdout, /\[ ok \] CHAIN/);
  assert.match(r.stdout, /\[ ok \] OP-SIG/);
  assert.match(r.stdout, /\[ \?\? \] WITNESS/);
});

test('a tampered store exits 2 and names what a reader may conclude', async () => {
  const { root, vkey } = await evidence();
  const path = join(root, 'chain', 'host-1.jsonl');
  const lines = readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  lines[1].record.outcome = 'denied';
  writeFileSync(path, lines.map(l => JSON.stringify(l)).join('\n') + '\n');

  const r = await run([root, '--collector', 'host-1', '--key', vkey]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /verdict\s+FAIL/);
  assert.match(r.stdout, /FAIL LEAF_MISMATCH at record_seq 2/);
  assert.match(r.stdout, /is not what was committed/);
});

test('--json emits a machine-readable report and the same exit code', async () => {
  const { root, vkey } = await evidence();
  const r = await run([root, '--collector', 'host-1', '--key', vkey, '--json']);
  assert.equal(r.code, 1);
  const report = JSON.parse(r.stdout);
  assert.equal(report.verdict, 'inconclusive');
  assert.equal(report.summary.failed, 0);
  assert.equal(report.tree_size, 3);
  assert.ok(report.capability.cannot.some(s => /truncation/i.test(s)));
});

// FR-57 — the capability statement is the part a reader needs most, so it is
// available on its own.
test('--explain prints only what the verdict depends on', async () => {
  const { root, vkey } = await evidence();
  const r = await run([root, '--collector', 'host-1', '--key', vkey, '--explain']);
  assert.match(r.stdout, /capability/);
  assert.match(r.stdout, /trusting/);
  assert.ok(!/\[ ok \]/.test(r.stdout), 'the check table is suppressed');
});

test('no arguments prints usage and exits 3', async () => {
  const r = await run([]);
  assert.equal(r.code, 3);
  assert.match(r.stdout, /splitstick verify <store>/);
});

test('a flag with no value is a usage error, not a silent default', async () => {
  const { root } = await evidence();
  const r = await run([root, '--key']);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /--key needs a value/);
});

// NFR-05, NFR-06 — offline by construction. The suite runs the CLI with an
// empty environment, so there is no proxy, no credential and no registry to
// reach even if something tried.
test('NFR-05: the CLI runs with an empty environment', async () => {
  const { root, vkey } = await evidence();
  const r = await new Promise((resolve) => {
    execFile(process.execPath, [CLI, root, '--collector', 'host-1', '--key', vkey],
      { env: {} }, (err, stdout, stderr) => resolve({
        code: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr,
      }));
  });
  assert.equal(r.code, 1, r.stderr);
  assert.match(r.stdout, /verdict\s+INCONCLUSIVE/);
});
