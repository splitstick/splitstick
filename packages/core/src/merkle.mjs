// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * The Merkle tree — DES-05, RFC 6962 §2.
 *
 * Adopted, not invented (DES-14, INT-06). RFC 6962 gets right the two things a
 * hand-rolled tree gets wrong: it does not duplicate the last leaf to pad an
 * odd count (the shape behind CVE-2012-2459), and it domain-separates leaves
 * from interior nodes. Both properties are asserted in the test suite rather
 * than assumed from the citation.
 *
 * The tree is over every leaf in the collector's log so far, never over an
 * isolated batch: a checkpoint says "this log now has tree_size entries and
 * this is its root", which is what makes tree_size monotonic and a rollback
 * visible.
 */

import { createHash } from 'node:crypto';

/** 0x00 — leaf. Shared with DES-03's leaf construction, deliberately. */
export const LEAF_PREFIX = 0x00;
/** 0x01 — interior node. */
export const NODE_PREFIX = 0x01;

/** @param {Uint8Array[]} parts */
const sha256 = parts => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

/** MTH({d0}) = SHA-256(0x00 ‖ d0) @param {Uint8Array} d @returns {Buffer} */
export const leafHash = d => sha256([Buffer.from([LEAF_PREFIX]), d]);

/** @param {Uint8Array} l @param {Uint8Array} r @returns {Buffer} */
export const nodeHash = (l, r) => sha256([Buffer.from([NODE_PREFIX]), l, r]);

/** The largest power of two strictly less than n. @param {number} n */
function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * MTH(D[n]). An empty tree is SHA-256 of the empty string, which RFC 6962
 * specifies and which is worth keeping rather than erroring: a collector with
 * no records yet has a well-defined root.
 * @param {Uint8Array[]} leaves raw leaf data, pre-hash
 * @returns {Buffer}
 */
export function treeRoot(leaves) {
  if (leaves.length === 0) return sha256([]);
  if (leaves.length === 1) return leafHash(/** @type {Uint8Array} */ (leaves[0]));
  const k = split(leaves.length);
  return nodeHash(treeRoot(leaves.slice(0, k)), treeRoot(leaves.slice(k)));
}

/**
 * PATH(m, D[n]) — the audit path for the leaf at index m.
 * @param {Uint8Array[]} leaves
 * @param {number} m
 * @returns {Buffer[]}
 */
export function inclusionProof(leaves, m) {
  const n = leaves.length;
  if (!Number.isInteger(m) || m < 0 || m >= n) {
    throw new RangeError(`no leaf at index ${m} in a tree of ${n}`);
  }
  if (n === 1) return [];
  const k = split(n);
  return m < k
    ? [...inclusionProof(leaves.slice(0, k), m), treeRoot(leaves.slice(k))]
    : [...inclusionProof(leaves.slice(k), m - k), treeRoot(leaves.slice(0, k))];
}

/**
 * Verify an audit path against a root. Returns a boolean rather than throwing,
 * because a failed proof is a verification outcome (DES-12), not an error.
 * @param {Uint8Array} leaf raw leaf data, pre-hash
 * @param {number} index
 * @param {number} size
 * @param {Uint8Array[]} path
 * @param {Uint8Array} root
 * @returns {boolean}
 */
export function verifyInclusion(leaf, index, size, path, root) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index, sn = size - 1;
  let r = leafHash(leaf);
  for (const p of path) {
    if (sn === 0) return false;              // proof longer than the tree is deep
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && Buffer.from(r).equals(Buffer.from(root));
}

/**
 * PROOF(m, D[n]) — evidence that the tree of n leaves extends the tree of m.
 * This is how append-only is checked rather than assumed (DES-04 rule 4).
 * @param {Uint8Array[]} leaves
 * @param {number} m
 * @returns {Buffer[]}
 */
export function consistencyProof(leaves, m) {
  const n = leaves.length;
  if (!Number.isInteger(m) || m < 0 || m > n) {
    throw new RangeError(`cannot prove a prefix of ${m} against a tree of ${n}`);
  }
  if (m === 0 || m === n) return [];
  return subProof(leaves, m, true);
}

/**
 * @param {Uint8Array[]} leaves
 * @param {number} m
 * @param {boolean} complete true while the prefix is still the whole left subtree
 * @returns {Buffer[]}
 */
function subProof(leaves, m, complete) {
  const n = leaves.length;
  if (m === n) return complete ? [] : [treeRoot(leaves)];
  const k = split(n);
  return m <= k
    ? [...subProof(leaves.slice(0, k), m, complete), treeRoot(leaves.slice(k))]
    : [...subProof(leaves.slice(k), m - k, false), treeRoot(leaves.slice(0, k))];
}

/** @param {number} n count of trailing zero bits */
const trailingZeros = n => (n === 0 ? 0 : 31 - Math.clz32(n & -n));

/**
 * Verify that `root2` over `size2` leaves extends `root1` over `size1`.
 * @param {number} size1
 * @param {Uint8Array} root1
 * @param {number} size2
 * @param {Uint8Array} root2
 * @param {Uint8Array[]} proof
 * @returns {boolean}
 */
export function verifyConsistency(size1, root1, size2, root2, proof) {
  const eq = (/** @type {Uint8Array} */ a, /** @type {Uint8Array} */ b) =>
    Buffer.from(a).equals(Buffer.from(b));
  if (size2 < size1 || size1 < 0) return false;
  if (size1 === size2) return proof.length === 0 && eq(root1, root2);
  if (size1 === 0) return proof.length === 0;   // every tree extends the empty one
  if (proof.length === 0) return false;

  // When size1 is a power of two its own root is the seed; otherwise the first
  // proof element is. The proof length is NOT prechecked: the loop below rejects
  // a proof that is too long (sn reaches 0 early) and one that is too short
  // (sn is non-zero at the end), and an arithmetic precheck written from the
  // wrong formula silently rejects valid proofs — it rejected PROOF(5, D[6]),
  // which RFC 6962 gives as three elements, not four.
  const shift = trailingZeros(size1);
  let seed = proof[0], start = 1;
  if (size1 === 1 << shift) { seed = root1; start = 0; }

  let mask = (size1 - 1) >> shift, sn = (size2 - 1) >> shift;
  let h1 = /** @type {Uint8Array} */ (seed), h2 = /** @type {Uint8Array} */ (seed);
  for (const p of proof.slice(start)) {
    if (sn === 0) return false;
    if (mask % 2 === 1 || mask === sn) {
      h1 = nodeHash(p, h1);
      h2 = nodeHash(p, h2);
      while (mask % 2 === 0 && mask !== 0) { mask >>= 1; sn >>= 1; }
    } else {
      h2 = nodeHash(h2, p);
    }
    mask >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(h1, root1) && eq(h2, root2);
}

/**
 * The root of every PREFIX of a leaf list, in one pass — NFR-04.
 *
 * A verifier checks each checkpoint against the root of the tree it committed
 * to, which is a prefix of the leaves on disk. Calling `treeRoot` once per
 * checkpoint is O(checkpoints · n): at 100 checkpoints over 100,000 records
 * that is 10^7 leaf operations and roughly a minute, and it was the single
 * largest cost in verification — 585 ms of a 2.3 s run over only 8,000
 * records, which extrapolates to about 59 s at the size NFR-04 names.
 *
 * This computes them all in one left-to-right pass instead, O(n log n) total,
 * by keeping the standard forest of complete subtree roots and folding it at
 * each requested size. RFC 6962's tree is history-independent, so the fold of
 * the forest at size k IS the root at size k — the same value `treeRoot` would
 * return, which a test asserts for every size rather than for a sample.
 *
 * @param {Buffer[]} leaves
 * @param {number[]} sizes the prefix sizes wanted; 0 maps to the empty root
 * @returns {Map<number, Buffer>} size -> root
 */
export function prefixRoots(leaves, sizes) {
  const want = [...new Set(sizes)].filter(n => Number.isInteger(n) && n >= 0).sort((a, b) => a - b);
  /** @type {Map<number, Buffer>} */
  const out = new Map();
  if (want.length === 0) return out;

  // A forest of complete-subtree roots, smallest last. Appending a leaf and
  // merging equal-height neighbours is the standard incremental construction.
  /** @type {{ root: Buffer, size: number }[]} */
  const forest = [];
  let next = 0;
  /** Fold the forest right-to-left: the root of the tree built so far. */
  const fold = () => {
    if (forest.length === 0) return treeRoot([]);
    let acc = /** @type {{root: Buffer}} */ (forest[forest.length - 1]).root;
    for (let i = forest.length - 2; i >= 0; i -= 1) {
      acc = nodeHash(/** @type {{root: Buffer}} */ (forest[i]).root, acc);
    }
    return acc;
  };

  while (next < want.length && want[next] === 0) { out.set(0, fold()); next += 1; }
  for (let i = 0; i < leaves.length && next < want.length; i += 1) {
    forest.push({ root: leafHash(/** @type {Buffer} */ (leaves[i])), size: 1 });
    // Merge while the last two subtrees are the same height.
    while (forest.length > 1
      && /** @type {{size: number}} */ (forest[forest.length - 1]).size
         === /** @type {{size: number}} */ (forest[forest.length - 2]).size) {
      const r = /** @type {{root: Buffer, size: number}} */ (forest.pop());
      const l = /** @type {{root: Buffer, size: number}} */ (forest.pop());
      forest.push({ root: nodeHash(l.root, r.root), size: l.size + r.size });
    }
    while (next < want.length && want[next] === i + 1) { out.set(i + 1, fold()); next += 1; }
  }
  return out;
}
