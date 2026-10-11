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
 */

import { openSync, writeSync, closeSync, readFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';

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
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = openSync(this.path, 'wx', 0o600);
        writeSync(fd, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
        closeSync(fd);
        this.#held = true;
        HELD_IN_PROCESS.add(this.path);
        return;
      } catch (err) {
        if (/** @type {{code?: string}} */ (err).code !== 'EEXIST') throw err;
        const pid = this.#holder();
        // A live holder elsewhere is a real conflict. Our own pid with nothing
        // in the registry is a lock this process left before being restarted.
        if (pid !== null && pid !== process.pid && this.#alive(pid)) {
          throw new StoreBusy(this.path, pid);
        }
        rmSync(this.path, { force: true });
      }
    }
    throw new StoreBusy(this.path, -1);
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
