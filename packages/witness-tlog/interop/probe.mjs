// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * FR-15 interop probe — the shipped tlog adapter against the REAL
 * transparency-dev/witness Go binary.
 *
 * Not a unit test, and deliberately not in `npm run test:unit`: it needs a Go
 * toolchain and the witness binary, which CI does not have. The suite in
 * ../test/tlog.test.mjs covers the adapter's logic against a server built from
 * @splitstick/witness-self; what THIS establishes is the thing that suite
 * structurally cannot — that our reading of c2sp.org/tlog-witness matches the
 * reading the reference implementation was written against.
 *
 * It found four defects on its first run, every one invisible to a suite where
 * we wrote both sides. See interop/README.md for how to reproduce, and
 * interop/results/fr-15-interop.json for the recorded outcome.
 */
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { Anchorer } from '@splitstick/core/anchor';
import { formatVkey, parseVkey } from '@splitstick/core/note';
import { tlogWitness, TlogWitnessError, TlogConflict } from '@splitstick/witness-tlog';

// Runtime inputs (keys, the witness DB, the generated log config) live in a
// scratch directory; the EVIDENCE always lands next to this file, in the
// repository, because that is what the requirement cites.
const HERE = process.env.FR15_DIR ?? new URL('.', import.meta.url).pathname;
const OUT = new URL('.', import.meta.url).pathname;
const ORIGIN = 'splitstick.dev/fr15-host';
const WITNESS_ID = 'fr15.witness.local';
// A fresh port per run, and the readiness check below refuses to talk to
// anything this process did not start. A stray witness from an earlier run held
// the fixed port once: the new process failed to bind, the readiness probe got
// a cheerful answer from the STALE one, and its older enrolled key produced a
// 403 that was indistinguishable from a real interop failure. A probe that can
// be answered by a stranger is not a probe.
const PORT = 20000 + Math.floor(Math.random() * 20000);

const keys = readFileSync(join(HERE, 'run/witness-keys.txt'), 'utf8').trim().split('\n');
const wPriv = keys[0], wVkey = keys[1];
const wPub = parseVkey(wVkey).publicKey;

const root = mkdtempSync(join(tmpdir(), 'ss-fr15-'));
const signer = await generateDevSigner(ORIGIN);
const ourVkey = formatVkey(ORIGIN, signer.publicKey);
console.log('our log origin :', ORIGIN);
console.log('our log vkey   :', ourVkey);
console.log('witness vkey   :', wVkey);

// Enrol our log with the real witness, through its documented YAML.
const yaml = `Logs:\n  - Origin: ${ORIGIN}\n    PublicKey: ${ourVkey}\n`;
writeFileSync(join(HERE, 'run/additional-logs.yaml'), yaml);
writeFileSync(join(HERE, 'run/witness.key'), wPriv + '\n');

// A FRESH database directory per run, not a deleted file. Deleting
// chkpts.db alone leaves chkpts.db-wal and -shm behind, and SQLite recovers the
// previous run's state from them -- which silently resurrected an older
// enrolled key and made the witness reject the operator's signature with a 403
// that looked exactly like a real interop failure. Cost twenty minutes.
const dbDir = mkdtempSync(join(tmpdir(), 'fr15-witness-db-'));
const dbFile = join(dbDir, 'chkpts.db');
const proc = spawn('/tmp/fr15-omniwitness', [
  '--listen', `127.0.0.1:${PORT}`,
  '--metrics_listen', '127.0.0.1:8098',
  '--private_key_path', join(HERE, 'run/witness.key'),
  '--additional_logs', join(HERE, 'run/additional-logs.yaml'),
  '--db_file', dbFile,
  '--logtostderr',
], { stdio: ['ignore', 'pipe', 'pipe'] });
let log = '';
proc.stdout.on('data', d => { log += d; });
proc.stderr.on('data', d => { log += d; });

const up = async () => {
  for (let i = 0; i < 60; i += 1) {
    // If our own process died -- most likely because it could not bind -- stop.
    // Otherwise the next successful fetch is somebody else's witness.
    if (proc.exitCode !== null || proc.signalCode !== null) {
      console.error(`the witness we started exited (code ${proc.exitCode}, signal ${proc.signalCode}).`);
      return false;
    }
    if (/address already in use|bind:/i.test(log)) {
      console.error('the witness we started could not bind its port, so anything answering on it '
        + 'is a different process:\n' + log.slice(-600));
      return false;
    }
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/add-checkpoint`, { method: 'POST', body: 'x' });
      if (r.status) return true;
    } catch { await new Promise(r => setTimeout(r, 500)); }
  }
  return false;
};
if (!await up()) { console.error('witness did not start:\n' + log.slice(-3000)); proc.kill('SIGKILL'); process.exit(1); }
console.log('\nthe real Go witness is listening on', PORT, '\n');

const store = new Store(root, 'fr15-host');
let t = Date.parse('2026-10-17T10:00:00.000Z');
const c = new Collector({
  store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
  collector: 'fr15-host', origin: ORIGIN, now: () => new Date(t += 1000),
});
const adapter = tlogWitness({ id: WITNESS_ID, url: `http://127.0.0.1:${PORT}` });
const anchorer = new Anchorer({
  store, witnesses: [adapter], quorum: 1, acceptance: { [WITNESS_ID]: wVkey },
});

const results = [];
for (let batch = 0; batch < 4; batch += 1) {
  for (let i = 0; i < 3; i += 1) {
    c.action({
      run: 'r-1', tool: 'transfer_funds', consequential: true,
      args: Buffer.from(`{"amount":${batch}${i}00}`), result: Buffer.from('OK'),
      outcome: 'ok', attempt: 1, correlation: `c-${batch}-${i}`,
    });
  }
  const cp = await c.checkpoint();
  try {
    const r = await anchorer.anchor(cp.checkpoint_seq);
    results.push({
      batch, tree_size: cp.tree_size,
      attached: r.attached.length, verified: r.attached[0]?.verified ?? null,

      failed: r.failed,
    });
    console.log(`batch ${batch}  size ${cp.tree_size}  attached ${r.attached.length}  verified ${r.attached[0]?.verified}  failed ${JSON.stringify(r.failed)}`);
  } catch (e) {
    console.log(`batch ${batch}  size ${cp.tree_size}  THREW ${e?.name}: ${e?.message?.slice(0, 300)}`);
    results.push({ batch, tree_size: cp.tree_size, threw: `${e?.name}: ${e?.message}` });
  }
}

const envs = store.readCheckpoints().map(x => JSON.parse(x.blob));
console.log('\n--- persisted countersignatures ---');
for (const e of envs) {
  for (const cs of e.countersignatures ?? []) {
    console.log(JSON.stringify({ issuer: cs.issuer, type: cs.type, covers: cs.covers, received_at: cs.received_at ?? null, line: (cs.line||'').slice(0,28)+'...' }));
  }
}
const evidence = {
  requirement: 'FR-15',
  kind: 'interop measurement',
  implementation: 'transparency-dev/witness (Go), built with CGO_ENABLED=0 from a shallow clone',
  protocol: 'c2sp.org/tlog-witness, cosignature/v1 (c2sp.org/tlog-cosignature)',
  our_log_vkey: ourVkey,
  witness_vkey: wVkey,
  checkpoints: results,
  countersignatures: envs.flatMap(e => (e.countersignatures ?? []).map(cs => ({
    issuer: cs.issuer, type: cs.type, covers: cs.covers, received_at: cs.received_at ?? null,
  }))),
  taken_at: new Date().toISOString(),
};
writeFileSync(join(OUT, 'results/fr-15-interop.json'), JSON.stringify(evidence, null, 2) + '\n');
console.log('\n--- witness log tail ---\n' + log.split('\n').slice(-12).join('\n'));
store.close();
proc.kill('SIGKILL');
rmSync(root, { recursive: true, force: true });
rmSync(dbDir, { recursive: true, force: true });
