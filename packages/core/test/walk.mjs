import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Every file under a directory, recursively.
 *
 * Hand-rolled rather than `readdirSync(dir, { recursive: true })` because that
 * option arrived in Node 20.1 and `Dirent.parentPath` in 20.12, while the
 * project supports Node 20 and later. A test suite that fails on the oldest
 * supported runtime for a reason unrelated to what it tests is worse than a
 * three-line helper.
 *
 * @param {string} dir
 * @returns {string[]} absolute paths
 */
export function walkFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walkFiles(path));
    else out.push(path);
  }
  return out;
}
