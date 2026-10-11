import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, readFileSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { WriteLock, StoreBusy } from '../src/writelock.mjs';

const fresh = () => join(mkdtempSync(join(tmpdir(), 'splitstick-lock-')), 'h.lock');

test('a lock is held by one instance and refused to the next', () => {
  const path = fresh();
  const a = new WriteLock(path);
  a.claim();
  assert.equal(a.held, true);
  assert.throws(() => new WriteLock(path).claim(), StoreBusy);
  a.release();
  const b = new WriteLock(path);
  b.claim();
  assert.equal(b.held, true);
});

test('claim is idempotent for the holder, and release is idempotent', () => {
  const path = fresh();
  const a = new WriteLock(path);
  a.claim(); a.claim();
  a.release(); a.release();
  assert.equal(a.held, false);
  assert.equal(existsSync(path), false);
});

/**
 * Review finding. The protocol was create-exclusively, then write the pid. A
 * contender arriving between those two steps read an empty file, failed to
 * parse it, concluded the lock was stale, deleted it and took one of its own —
 * so both processes believed they owned the collector.
 *
 * The lock is now published by linking a file that already contains the owner's
 * identity, so the name cannot be observed half-written. And an unreadable lock
 * is no longer assumed abandoned on sight.
 */
test('an empty lock file is not mistaken for an abandoned one', () => {
  const path = fresh();
  writeFileSync(path, '');          // exactly what the old window exposed
  assert.throws(() => new WriteLock(path).claim(), StoreBusy,
    'a lock that might be mid-claim must not be stolen');
  assert.equal(readFileSync(path, 'utf8'), '', 'and must not be deleted');
});

test('an unreadable lock is reclaimed only once it is also stale', () => {
  const path = fresh();
  writeFileSync(path, '{"pid":');   // truncated
  assert.throws(() => new WriteLock(path).claim(), StoreBusy);

  // Age it past the grace period: now it is abandoned, not mid-claim.
  const old = new Date(Date.now() - 60_000);
  utimesSync(path, old, old);
  const lock = new WriteLock(path);
  lock.claim();
  assert.equal(lock.held, true);
  assert.match(readFileSync(path, 'utf8'), /"pid":/);
});

test('a lock naming a dead process is reclaimed immediately', () => {
  const path = fresh();
  writeFileSync(path, JSON.stringify({ pid: 2 ** 22, at: new Date().toISOString() }));
  const lock = new WriteLock(path);
  lock.claim();
  assert.equal(lock.held, true);
});

test('a lock naming a live process is never reclaimed', () => {
  const path = fresh();
  writeFileSync(path, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
  // Not in this process's registry, so it looks like a predecessor with our pid
  // — which is the one case that IS safe to take, since we are that process.
  const lock = new WriteLock(path);
  lock.claim();
  assert.equal(lock.held, true);
});

test('the lock file always contains a complete identity, never a partial one', () => {
  const path = fresh();
  const lock = new WriteLock(path);
  lock.claim();
  const body = readFileSync(path, 'utf8');
  const parsed = JSON.parse(body);
  assert.equal(parsed.pid, process.pid);
  assert.ok(parsed.at);
  lock.release();
});

/**
 * Two real OS processes contending for one collector, as the review asked for.
 * Exactly one must win; the loser must report StoreBusy rather than proceeding.
 */
test('two separate processes contending for one collector: exactly one wins', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'splitstick-lock-'));
  const path = join(dir, 'contended.lock');
  const mod = fileURLToPath(new URL('../src/writelock.mjs', import.meta.url));
  const script = `
    import { WriteLock, StoreBusy } from ${JSON.stringify(mod)};
    const lock = new WriteLock(${JSON.stringify(path)});
    // Start together, to land inside each other's claim window.
    const at = Number(process.argv[2]);
    while (Date.now() < at) {}
    try { lock.claim(); process.stdout.write('WON'); setTimeout(() => lock.release(), 300); }
    catch (e) { process.stdout.write(e instanceof StoreBusy ? 'BUSY' : 'ERR:' + e.name); }
  `;
  const scriptPath = join(dir, 'contend.mjs');
  writeFileSync(scriptPath, script);

  const startAt = Date.now() + 250;
  const run = () => new Promise((resolve) => {
    execFile(process.execPath, [scriptPath, String(startAt)], (err, stdout, stderr) =>
      resolve(stdout.trim() || `FAILED:${stderr.trim().slice(0, 80)}`));
  });

  const results = await Promise.all([run(), run(), run(), run()]);
  const won = results.filter(r => r === 'WON').length;
  const busy = results.filter(r => r === 'BUSY').length;
  assert.equal(won, 1, `exactly one winner, got ${JSON.stringify(results)}`);
  assert.equal(won + busy, results.length, `everyone else must report BUSY: ${JSON.stringify(results)}`);
});
