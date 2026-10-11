import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, openSync, writeSync, closeSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ContentStore, ContentMissing, StoreBusy } from '../src/content.mjs';

const fresh = () => new ContentStore(mkdtempSync(join(tmpdir(), 'splitstick-blob-')));

/**
 * Found in review, and it would have shipped broken on the platform CI runs on.
 *
 * The blob was opened with 'a+' and erasure zeroed an extent with a positional
 * write. Node documents that on Linux a positional write is IGNORED when the
 * file is opened in append mode — the kernel appends instead. So on Linux
 * crypto-shredding would have appended zeros to the end of the blob and left
 * the ciphertext exactly where it was, silently weakening FR-36 from "the bytes
 * are gone" to "the key is gone". macOS honours the position, which is why the
 * suite was green locally.
 *
 * This test is platform-independent: it asserts the file does not GROW, which
 * is what an ignored position does.
 */
test('erasure overwrites in place and never appends', () => {
  const s = fresh();
  const [a, b] = s.putGroup([
    { bytes: Buffer.from('erase this one please') },
    { bytes: Buffer.from('but keep this one') },
  ]);
  const path = s.pathFor(a.cid);
  const sizeBefore = statSync(path).size;
  const dead = s.rangeForTest(a.cid);

  s.shred(a.cid);
  s.close();

  assert.equal(statSync(path).size, sizeBefore,
    'a positional write that got ignored would have grown the blob instead of erasing');
  const blob = readFileSync(path);
  assert.ok(blob.subarray(dead.offset, dead.offset + dead.length).every(byte => byte === 0),
    'the dead extent must be zeroed in place');
  assert.equal(s.get(b.cid).toString(), 'but keep this one');
});

// The same hazard, demonstrated on the raw primitive so the reason is recorded
// next to the fix rather than only in a commit message.
test('append mode is not used for the blob, because positional writes need r+', () => {
  const dir = mkdtempSync(join(tmpdir(), 'splitstick-blob-'));
  const path = join(dir, 'probe');
  writeFileSync(path, Buffer.from('AAAABBBB'));
  const fd = openSync(path, 'r+');
  writeSync(fd, Buffer.alloc(4), 0, 4, 4);
  closeSync(fd);
  const after = readFileSync(path);
  assert.equal(after.length, 8, 'r+ writes where it is told');
  assert.ok(after.subarray(4).every(b => b === 0));
});

/**
 * Found in review, and a regression my own performance change introduced.
 *
 * With one file per content object two writers could not collide. With one
 * shared blob they both cache the append offset, both start at the same place,
 * and the second silently overwrites the first — whose payload then becomes
 * unrecoverable. DES-13 already says one writer per collector, so this is a
 * programming error; it should be reported as one rather than losing data
 * quietly.
 */
test('a second writer on the same store is refused, not allowed to corrupt it', () => {
  const first = fresh();
  first.put(Buffer.from('first writer payload'));
  assert.throws(() => new ContentStore(first.root).put(Buffer.from('second writer payload')),
    StoreBusy, 'the second writer must be told, not silently interleaved');
  // The first writer is unharmed and still usable.
  const again = first.put(Buffer.from('still mine'));
  assert.equal(first.get(again.cid).toString(), 'still mine');
});

test('the lock is released on close, so a later process can take over', () => {
  const s = fresh();
  const a = s.put(Buffer.from('from the first process'));
  s.close();

  const next = new ContentStore(s.root);
  const b = next.put(Buffer.from('from the second process'));
  assert.equal(next.get(a.cid).toString(), 'from the first process', 'and nothing was clobbered');
  assert.equal(next.get(b.cid).toString(), 'from the second process');
  assert.notEqual(next.rangeForTest(a.cid).offset, next.rangeForTest(b.cid).offset);
});

test('a reader needs no lock, and takes none', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('readable'));
  const reader = new ContentStore(s.root);
  assert.equal(reader.get(cid).toString(), 'readable', 'reads are always allowed');
  assert.equal(reader.reproduces(cid), true);
  // And the writer still holds the write lock.
  assert.throws(() => reader.put(Buffer.from('nope')), StoreBusy);
});

test('a stale lock from a dead process does not wedge the store forever', () => {
  const s = fresh();
  s.put(Buffer.from('x'));
  s.close();
  // Simulate a crash: a lock file naming a pid that is not running.
  writeFileSync(join(s.root, 'content', '.writer.lock'), JSON.stringify({ pid: 2 ** 22, at: new Date().toISOString() }));
  const next = new ContentStore(s.root);
  const { cid } = next.put(Buffer.from('after the crash'));
  assert.equal(next.get(cid).toString(), 'after the crash');
});

test('a corrupted extent reports a typed error rather than a raw cipher failure', () => {
  const s = fresh();
  const { cid } = s.put(Buffer.from('EUR 2000000'));
  const e = s.rangeForTest(cid);
  s.close();
  const blob = readFileSync(s.pathFor(cid));
  blob[e.offset + e.length - 1] ^= 0xff;
  writeFileSync(s.pathFor(cid), blob);
  const reader = new ContentStore(s.root);
  assert.throws(() => reader.get(cid), ContentMissing);
  assert.equal(reader.reproduces(cid), false, 'and verification calls it a mismatch, not an absence');
});
