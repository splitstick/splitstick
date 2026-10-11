/**
 * The collector-scoped write lock — DES-13.
 *
 * One writer per collector. Two writers sharing a collector identity each
 * assign record_seq from their own in-memory position and chain from their own
 * view of the head, so the file ends up holding two interleaved chains and a
 * verifier reports SEQ_BROKEN, CHAIN_BROKEN and LEAF_MISMATCH — two honest
 * collectors, one corrupt log, read as tampering. The invariant is therefore
 * enforced rather than documented.
 *
 * It lives here, in one place, because it has to cover BOTH the content store
 * and the chain and salt journals. Holding it inside ContentStore.putGroup()
 * meant a record that externalises nothing — a heartbeat, a padding leaf, a gap
 * or a policy change — took no lock at all.
 *
 * Advisory and process-scoped: exclusive file creation plus a pid, which
 * answers the case that actually happens — two stores in one program, or a
 * second collector started by mistake — and claims nothing about a shared
 * filesystem. A lock naming a process that is gone is taken over rather than
 * left to wedge the store, since otherwise a crash would need manual recovery
 * before collection could resume.
 *
 * Readers never take it. A verifier must be able to open a live store, and
 * cannot damage one.
 *
 * Creation is atomic by `link()`, not by exclusive `open()`. With open-then-
 * write the file exists empty for an instant, and a contender arriving in that
 * window read it, failed to parse it, concluded it was stale, deleted it and
 * took a lock of its own — so both processes believed they owned the collector.
 * A hard link of a file that already contains the owner's identity cannot be
 * observed half-written: either the name exists with complete contents, or it
 * does not exist.
 *
 * An unreadable lock is therefore no longer assumed stale on sight. It is
 * re-read a few times, and only a lock that stays unreadable AND is older than
 * the grace period below is reclaimed, because the one thing worse than a
 * wedged store is two writers that both think they own it.
 */

/** How long an unreadable lock must persist before it is treated as abandoned. */
const UNREADABLE_GRACE_MS = 2000;

import { writeFileSync, readFileSync, rmSync, mkdirSync, existsSync, linkSync, statSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';

/**
 * Lock paths held in THIS process.
 *
 * The file alone cannot separate "another instance in this program" from "my
 * own lock, left behind by a crash with the same pid", and the first is by far
 * the likelier mistake.
 * @type {Set<string>}
 */
const HELD_IN_PROCESS = new Set();

export class StoreBusy extends Error {
  /** @param {string} path @param {number} pid */
  constructor(path, pid) {
    super(`another writer holds ${path} (pid ${pid}); DES-13 allows one writer per collector`);
    this.name = 'StoreBusy';
    this.pid = pid;
  }
}

export class WriteLock {
  #held = false;

  /** @param {string} path */
  constructor(path) {
    this.path = path;
  }

  get held() { return this.#held; }

  /** Claim the lock, once. Idempotent for the holder. */
  claim() {
    if (this.#held) return;
    if (HELD_IN_PROCESS.has(this.path)) throw new StoreBusy(this.path, process.pid);
    mkdirSync(dirname(this.path), { recursive: true });

    for (let attempt = 0; attempt < 3; attempt++) {
      // Build the lock's contents first, then publish it under its real name
      // with a single atomic link. The name never exists without the identity.
      const staging = join(dirname(this.path), `.claim-${process.pid}-${randomBytes(6).toString('hex')}`);
      writeFileSync(staging, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }) + '\n',
        { mode: 0o600 });
      try {
        linkSync(staging, this.path);
        this.#held = true;
        HELD_IN_PROCESS.add(this.path);
        return;
      } catch (err) {
        if (/** @type {{code?: string}} */ (err).code !== 'EEXIST') throw err;
        if (!this.#reclaim()) throw new StoreBusy(this.path, this.#holder() ?? -1);
      } finally {
        rmSync(staging, { force: true });
      }
    }
    throw new StoreBusy(this.path, this.#holder() ?? -1);
  }

  /**
   * Is the existing lock abandoned, and now removed?
   * @returns {boolean} true when the caller may retry
   */
  #reclaim() {
    const pid = this.#holder();
    // A live holder elsewhere is a real conflict.
    if (pid !== null && pid !== process.pid && this.#alive(pid)) return false;
    if (pid === null) {
      // Unreadable. Most likely a contender mid-claim under an older protocol,
      // or a truncated file. Give it time to become readable rather than
      // assuming it is dead, and require it to be stale as well.
      for (let i = 0; i < 3; i++) {
        if (this.#holder() !== null) return this.#reclaim();
        try {
          if (Date.now() - statSync(this.path).mtimeMs < UNREADABLE_GRACE_MS) return false;
        } catch {
          return true;   // it vanished while we looked: the name is free
        }
      }
    }
    rmSync(this.path, { force: true });
    return true;
  }

  /** Release it. Idempotent. */
  release() {
    if (!this.#held) return;
    if (this.#holder() === process.pid) rmSync(this.path, { force: true });
    HELD_IN_PROCESS.delete(this.path);
    this.#held = false;
  }

  /** @returns {number|null} */
  #holder() {
    try {
      if (!existsSync(this.path)) return null;
      const pid = JSON.parse(readFileSync(this.path, 'utf8')).pid;
      return Number.isInteger(pid) ? pid : null;
    } catch {
      return null;   // unreadable or truncated: treat as stale
    }
  }

  /** @param {number} pid */
  #alive(pid) {
    try {
      process.kill(pid, 0);
      return true;
    } catch (err) {
      return /** @type {{code?: string}} */ (err).code === 'EPERM';   // exists, not ours
    }
  }
}
