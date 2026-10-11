import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize, CanonicalizeError, canonicalBytes } from '../src/jcs.mjs';

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

// A collision found in review, in the exact bug class this project exists
// because of: `for...of` yields an unpaired surrogate as a one-character
// string, it is appended literally, and Buffer.from(s, 'utf8') then replaces it
// with U+FFFD. Two different records therefore produced identical canonical
// bytes and identical leaves, which is precisely what FR-52 forbids.
//
// RFC 8785 serialises only well-formed Unicode, so the fix is to refuse the
// input rather than to escape it into something else.
test('an unpaired surrogate is refused, not silently replaced', () => {
  for (const bad of ['\ud800', '\udfff', 'a\ud800b', '\ud800\ud800', '\udc00\ud800']) {
    assert.throws(() => canonicalize({ note: bad }), CanonicalizeError, JSON.stringify(bad));
  }
  // A well-formed pair is fine, and stays literal UTF-8.
  assert.equal(canonicalize({ note: '😀' }), '{"note":"\u{1f600}"}');
  assert.equal(canonicalize({ note: '\u{1f600}' }), '{"note":"\u{1f600}"}');
});

test('a lone surrogate and U+FFFD no longer canonicalise alike', () => {
  assert.throws(() => canonicalBytes({ note: '\ud800' }), CanonicalizeError);
  assert.equal(canonicalize({ note: '�' }), '{"note":"�"}');
});

test('an unpaired surrogate in a KEY is refused too', () => {
  assert.throws(() => canonicalize({ ['\ud800']: 1 }), CanonicalizeError);
});

// Non-integers are rejected because a float cannot be canonicalised
// unambiguously. Integers past 2^53 have the same ambiguity — 2^53 and 2^53+1
// are the same double — so they are rejected for the same reason rather than
// accepted and quietly conflated.
test('integers beyond the safe range are refused for the same reason floats are', () => {
  assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), '9007199254740991');
  assert.equal(canonicalize(-Number.MAX_SAFE_INTEGER), '-9007199254740991');
  for (const n of [2 ** 53, 2 ** 53 + 2, 1e21, -(2 ** 53)]) {
    assert.throws(() => canonicalize(n), CanonicalizeError, String(n));
  }
});

/**
 * The published rejected-case vectors, driven rather than restated.
 *
 * Found in review: these vectors existed and no test read them. Two of them
 * encoded NaN and Infinity as `{"a": null, "_nan": true}` — a marker flag,
 * because JSON cannot hold those values — so canonicalising the vector's input
 * SUCCEEDED. An independent implementer driving the published file would have
 * concluded that NaN is acceptable. The file now states an explicit encoding
 * for values with no JSON form, and this test is what keeps it honest.
 */
const SPECIAL = /** @type {Record<string, () => unknown>} */ ({
  nan: () => NaN,
  infinity: () => Infinity,
  '-infinity': () => -Infinity,
  undefined: () => ({ a: undefined }),
  function: () => ({ a: () => 1 }),
  bigint: () => ({ a: 1n }),
  symbol: () => ({ a: Symbol('s') }),
});

test('every published rejected vector is in fact rejected', () => {
  const rejected = spec.rejected ?? [];
  assert.ok(rejected.length >= 9, 'the rejected set should not shrink silently');
  for (const v of rejected) {
    const forms = ['input', 'input_json', 'special'].filter(k => k in v);
    assert.deepEqual(forms.length, 1, `${v.name}: exactly one input form`);
    let input;
    if ('special' in v) {
      const make = SPECIAL[v.special];
      assert.ok(make, `unknown special form ${v.special} — the driver must not skip it silently`);
      input = make();
    } else {
      input = 'input_json' in v ? JSON.parse(v.input_json) : v.input;
    }
    assert.throws(() => canonicalize(input), CanonicalizeError, v.name);
  }
});
