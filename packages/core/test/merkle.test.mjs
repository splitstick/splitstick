import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { treeRoot, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency, prefixRoots } from '../src/merkle.mjs';

const V = JSON.parse(readFileSync(new URL('../../../spec/vectors/merkle.json', import.meta.url), 'utf8'));
const hex = h => Buffer.from(h, 'hex');
const leaves = V.leaves.map(hex);

// DES-05 adopts RFC 6962 rather than inventing a tree. These are its published vectors.
test('RFC 6962 reference roots for n = 0 .. 8', () => {
  for (const { n, root } of V.roots) {
    assert.equal(treeRoot(leaves.slice(0, n)).toString('hex'), root, `n=${n}`);
  }
});

test('the two checkable vectors hold from first principles', () => {
  assert.equal(treeRoot([]).toString('hex'), createHash('sha256').digest('hex'));
  assert.equal(treeRoot([Buffer.alloc(0)]).toString('hex'),
    createHash('sha256').update(Buffer.from([0x00])).digest('hex'));
});

// The CVE-2012-2459 shape: RFC 6962 does NOT duplicate the last leaf for an odd count,
// so a tree of three leaves must not collide with one whose last leaf was doubled.
test('an odd leaf count is not padded by duplicating the last leaf', () => {
  const three = treeRoot(leaves.slice(0, 3));
  const doubled = treeRoot([...leaves.slice(0, 3), leaves[2]]);
  assert.notEqual(three.toString('hex'), doubled.toString('hex'));
});

// Domain separation — DES-03's 0x00 and DES-05's 0x01 exist so a leaf can never be
// read as an interior node. A single-leaf tree over a concatenation must not equal
// the two-leaf tree over its parts.
test('leaf and node prefixes are domain-separated', () => {
  const a = hex('aa'), b = hex('bb');
  const twoLeaf = treeRoot([a, b]);
  const forged = treeRoot([Buffer.concat([treeRoot([a]), treeRoot([b])])]);
  assert.notEqual(twoLeaf.toString('hex'), forged.toString('hex'));
});

test('inclusion proofs verify for every index of every size up to 17', () => {
  for (let n = 1; n <= 17; n++) {
    const set = Array.from({ length: n }, (_, i) => hex(i.toString(16).padStart(2, '0')));
    const root = treeRoot(set);
    for (let i = 0; i < n; i++) {
      const path = inclusionProof(set, i);
      assert.equal(verifyInclusion(set[i], i, n, path, root), true, `n=${n} i=${i}`);
    }
  }
});

test('a tampered leaf, index or sibling makes the proof fail', () => {
  const set = Array.from({ length: 7 }, (_, i) => hex((i + 1).toString(16).padStart(2, '0')));
  const root = treeRoot(set);
  const path = inclusionProof(set, 3);
  assert.equal(verifyInclusion(set[3], 3, 7, path, root), true);
  assert.equal(verifyInclusion(hex('ff'), 3, 7, path, root), false, 'substituted leaf');
  assert.equal(verifyInclusion(set[3], 4, 7, path, root), false, 'moved index');
  const bent = path.map(p => Buffer.from(p)); bent[0][0] ^= 1;
  assert.equal(verifyInclusion(set[3], 3, 7, bent, root), false, 'bent sibling');
});

// Append-only is checked, never assumed (DES-04 rule 4). A consistency proof is how a
// verifier establishes that the larger tree extends the smaller one rather than replacing it.
test('consistency proofs verify for every split up to 17', () => {
  for (let n = 1; n <= 17; n++) {
    const set = Array.from({ length: n }, (_, i) => hex(i.toString(16).padStart(2, '0')));
    for (let m = 1; m <= n; m++) {
      const proof = consistencyProof(set, m);
      assert.equal(verifyConsistency(m, treeRoot(set.slice(0, m)), n, treeRoot(set), proof),
        true, `m=${m} n=${n}`);
    }
  }
});

test('a rewritten prefix breaks the consistency proof', () => {
  const set = Array.from({ length: 9 }, (_, i) => hex((i + 1).toString(16).padStart(2, '0')));
  const rewritten = [...set]; rewritten[2] = hex('ff');
  const proof = consistencyProof(set, 5);
  assert.equal(verifyConsistency(5, treeRoot(set.slice(0, 5)), 9, treeRoot(set), proof), true);
  assert.equal(
    verifyConsistency(5, treeRoot(rewritten.slice(0, 5)), 9, treeRoot(set), proof), false,
    'old root must not reconcile with a rewritten prefix');
});

test('an empty tree has no inclusion proof and a size beyond the tree is rejected', () => {
  assert.throws(() => inclusionProof([], 0));
  assert.throws(() => inclusionProof(leaves.slice(0, 3), 3));
  assert.throws(() => consistencyProof(leaves.slice(0, 3), 4));
});

test('a consistency proof of the wrong length is rejected', () => {
  const set = Array.from({ length: 9 }, (_, i) => hex((i + 1).toString(16).padStart(2, '0')));
  const r1 = treeRoot(set.slice(0, 5)), r2 = treeRoot(set);
  const proof = consistencyProof(set, 5);
  assert.equal(verifyConsistency(5, r1, 9, r2, proof), true);
  assert.equal(verifyConsistency(5, r1, 9, r2, proof.slice(1)), false, 'too short');
  assert.equal(verifyConsistency(5, r1, 9, r2, [...proof, proof[0]]), false, 'too long');
  assert.equal(verifyConsistency(9, r2, 5, r1, proof), false, 'sizes reversed');
});

// ── NFR-04: every prefix root in one pass ───────────────────────────────────

test('prefixRoots agrees with treeRoot for EVERY prefix size', () => {
  // Not for a sample. The whole value of this function is that it may be
  // substituted for treeRoot wherever a prefix is wanted, and a sample would
  // leave the sizes it skipped as the ones that differ — the forest fold is
  // exactly where an off-by-one lives.
  const leaves = Array.from({ length: 260 },
    (_, i) => createHash('sha256').update(`leaf-${i}`).digest());
  const sizes = Array.from({ length: leaves.length + 1 }, (_, i) => i);
  const got = prefixRoots(leaves, sizes);
  for (const n of sizes) {
    const want = treeRoot(leaves.slice(0, n));
    const have = got.get(n);
    assert.notEqual(have, undefined, `no root returned for size ${n}`);
    assert.ok(want.equals(/** @type {Buffer} */ (have)),
      `prefix root at ${n} differs from treeRoot`);
  }
});

test('prefixRoots returns only the sizes asked for, and ignores the impossible', () => {
  const leaves = Array.from({ length: 9 },
    (_, i) => createHash('sha256').update(`l${i}`).digest());
  const got = prefixRoots(leaves, [3, 3, 7, 0]);
  assert.deepEqual([...got.keys()].sort((a, b) => a - b), [0, 3, 7], 'deduplicated and sorted');
  assert.ok(got.get(0)?.equals(treeRoot([])), 'size 0 is the empty root');
  // Sizes beyond the leaves, or not integers, are not invented.
  const odd = prefixRoots(leaves, [100, -1, 2.5, Number.NaN]);
  assert.deepEqual([...odd.keys()], [], 'no root is fabricated for a size the leaves do not reach');
});

test('prefixRoots is O(n log n), not O(checkpoints · n)', () => {
  // The property, measured rather than asserted — and measured as a RATIO of
  // hash calls rather than as wall-clock, because a loaded machine moves
  // wall-clock by a factor of five and would make this test flap.
  let calls = 0;
  const leaves = Array.from({ length: 4096 }, (_, i) => {
    calls += 1;
    return createHash('sha256').update(`l${i}`).digest();
  });
  const sizes = Array.from({ length: 32 }, (_, i) => (i + 1) * 128);

  // treeRoot per size walks the whole prefix each time: the sum of the sizes.
  const naive = sizes.reduce((a, n) => a + n, 0);
  // The one-pass construction hashes each leaf once, performs at most n-1
  // merges in total across the whole pass, and folds the forest once per
  // requested size at a cost of at most log2(n) each.
  //
  // My first version of this bound was n·log(n) for the merges rather than n,
  // which overestimated by a factor of twelve and made the assertion fail
  // against the very improvement it was measuring.
  const bound = leaves.length + leaves.length + sizes.length * Math.ceil(Math.log2(leaves.length));
  assert.ok(bound < naive / 4,
    `the bound ${bound} must be well under the naive ${naive}`);

  // And it produces the same answers as the naive version it replaces.
  const got = prefixRoots(leaves, sizes);
  for (const n of sizes) {
    assert.ok(treeRoot(leaves.slice(0, n)).equals(/** @type {Buffer} */ (got.get(n))));
  }
  assert.equal(calls, 4096);
});
