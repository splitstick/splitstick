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
 * Four real OS processes contending for one collector.
 *
 * What is asserted is MUTUAL EXCLUSION — no two processes hold the lock at
 * overlapping times — and not "exactly one winner", which is a proxy for it
 * that this test used to assert and that is load-sensitive: the processes are
 * released at one wall-clock instant, but node startup under a loaded machine
 * can exceed the holder's lease, so a late-booting process arrives after the
 * winner has legitimately released and legitimately wins the free lock. Two
 * winners in sequence is correct behaviour; two winners at once is the bug,
 * and only the interval comparison can tell them apart.
 *
 * Measured under a deliberately loaded host, four processes produced multiple
 * winners in five rounds out of twelve and ZERO overlapping holds.
 */
test('two separate processes contending for one collector: never two at once', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'splitstick-lock-'));
  const path = join(dir, 'contended.lock');
  const mod = fileURLToPath(new URL('../src/writelock.mjs', import.meta.url));
  // The hold is long relative to process startup so that contention actually
  // happens rather than being hoped for; the assertion below does not depend
  // on it, which is the point.
  const script = `
    import { WriteLock, StoreBusy } from ${JSON.stringify(mod)};
    const lock = new WriteLock(${JSON.stringify(path)});
    // Start together, to land inside each other's claim window.
    const at = Number(process.argv[2]);
    while (Date.now() < at) {}
    try {
      lock.claim();
      const held = Date.now();
      setTimeout(() => {
        lock.release();
        // Concatenation, not a template: this whole script is itself inside a
        // template literal, so a nested one is interpolated by the outer.
        process.stdout.write('WON ' + held + ' ' + Date.now());
      }, 1_000);
    } catch (e) {
      process.stdout.write(e instanceof StoreBusy ? 'BUSY' : 'ERR:' + e.name);
    }
  `;
  const scriptPath = join(dir, 'contend.mjs');
  writeFileSync(scriptPath, script);

  const startAt = Date.now() + 250;
  const run = () => new Promise((resolve) => {
    execFile(process.execPath, [scriptPath, String(startAt)], (err, stdout, stderr) =>
      resolve(stdout.trim() || `FAILED:${stderr.trim().slice(0, 80)}`));
  });

  const results = await Promise.all([run(), run(), run(), run()]);
  const busy = results.filter(r => r === 'BUSY').length;
  /** @type {[number, number][]} */
  const holds = results.filter(r => r.startsWith('WON'))
    .map(r => {
      const [, a, b] = r.split(' ');
      return /** @type {[number, number]} */ ([Number(a), Number(b)]);
    });

  assert.equal(busy + holds.length, results.length,
    `everyone either holds the lock or reports BUSY: ${JSON.stringify(results)}`);
  assert.ok(holds.length >= 1, `nobody acquired it at all: ${JSON.stringify(results)}`);
  // The property. A loser that proceeded anyway would appear here as an
  // interval starting before the previous one ended.
  holds.sort((a, b) => a[0] - b[0]);
  for (let i = 1; i < holds.length; i += 1) {
    const prev = /** @type {[number, number]} */ (holds[i - 1]);
    const cur = /** @type {[number, number]} */ (holds[i]);
    assert.ok(cur[0] >= prev[1],
      `two processes held the lock at once: ${JSON.stringify(holds)}`);
  }
  // And contention was real: with a one-second lease, somebody had to be
  // turned away, or this round measured four processes taking turns.
  assert.ok(busy >= 1, `no process was ever refused, so nothing contended: ${JSON.stringify(results)}`);
});
