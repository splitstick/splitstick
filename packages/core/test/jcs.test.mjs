import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize, CanonicalizeError } from '../src/jcs.mjs';

const spec = JSON.parse(readFileSync(new URL('../../../spec/vectors/jcs.json', import.meta.url), 'utf8'));

// DES-02 / FR-52 — the canonical form is a published contract, not an implementation detail.
for (const v of spec.vectors) {
  test(`jcs vector: ${v.name}`, () => {
    assert.equal(canonicalize(v.input), v.canonical);
  });
}

test('jcs is idempotent through a parse round trip', () => {
  for (const v of spec.vectors) {
    assert.equal(canonicalize(JSON.parse(canonicalize(v.input))), v.canonical);
  }
});

test('non-integer floats are rejected rather than silently encoded', () => {
  assert.throws(() => canonicalize({ a: 0.1 }), CanonicalizeError);
  assert.throws(() => canonicalize({ a: [1, 2.5] }), CanonicalizeError);
  assert.throws(() => canonicalize({ a: { b: 1.0000001 } }), CanonicalizeError);
});

test('NaN and Infinity are rejected', () => {
  assert.throws(() => canonicalize({ a: NaN }), CanonicalizeError);
  assert.throws(() => canonicalize({ a: Infinity }), CanonicalizeError);
  assert.throws(() => canonicalize({ a: -Infinity }), CanonicalizeError);
});

test('undefined and functions are rejected, never dropped', () => {
  assert.throws(() => canonicalize({ a: undefined }), CanonicalizeError);
  assert.throws(() => canonicalize({ a: () => 1 }), CanonicalizeError);
});

// SEC-07 — the whole point: semantically equal inputs must agree byte for byte.
test('semantically identical numbers canonicalise identically', () => {
  assert.equal(canonicalize({ a: 2000000 }), canonicalize({ a: 2.0e6 }));
  assert.equal(canonicalize({ a: 2000000 }), canonicalize({ a: 2000000.0 }));
  assert.notEqual(canonicalize({ a: 2000000 }), canonicalize({ a: 2000001 }));
});

test('key insertion order cannot change the output', () => {
  assert.equal(canonicalize({ b: 1, a: 2, c: 3 }), canonicalize({ c: 3, a: 2, b: 1 }));
});
