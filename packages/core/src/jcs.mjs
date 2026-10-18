// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * RFC 8785 — JSON Canonicalization Scheme.
 *
 * DES-02. The highest-risk element in the project relative to its size: a
 * canonical form that silently omits or reshapes a field makes every downstream
 * guarantee hollow while every other check still passes. Implemented against
 * published vectors (spec/vectors/jcs.json) rather than approximated.
 *
 * Two deliberate departures from "whatever JSON.stringify does":
 *
 *   - Non-integer numbers are REJECTED, not encoded. RFC 8785 mandates
 *     ECMAScript Number::toString, which is well defined, but round-trip
 *     equality for fractional doubles is not a property worth betting evidence
 *     on. DES-02 rule 3 coerces them to decimal strings at capture instead, so
 *     a float never reaches this function and never causes an action to go
 *     unrecorded.
 *   - undefined, functions and symbols are rejected rather than dropped.
 *     Dropping a field is exactly the defect FR-52 exists to prevent.
 */

export class CanonicalizeError extends Error {
  /** @param {string} message @param {string} path */
  constructor(message, path) {
    super(`${message} at ${path || '<root>'}`);
    this.name = 'CanonicalizeError';
    this.path = path;
  }
}

/** Characters with a defined two-character escape in RFC 8259. */
const SHORT_ESCAPE = /** @type {Record<string, string>} */ ({
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
  '\n': '\\n', '\r': '\\r', '\t': '\\t',
});

/**
 * Minimal, deterministic string escaping. Everything printable stays literal —
 * including `/` and all non-ASCII, which are emitted as UTF-8 rather than \u
 * sequences. Only the seven short escapes and the remaining C0 controls escape.
 * @param {string} s
 */
function encodeString(s, path = '') {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);

    // An unpaired surrogate is not well-formed Unicode and has no canonical
    // encoding. Left alone it was appended literally and then turned into
    // U+FFFD by the UTF-8 conversion, so a record containing one produced the
    // same bytes — and the same leaf — as a record containing U+FFFD. That is a
    // canonicalisation collision, which is the defect this whole project exists
    // because of, so it fails loudly here rather than quietly downstream.
    if (unit >= 0xd800 && unit <= 0xdfff) {
      const high = unit <= 0xdbff;
      const next = high ? s.charCodeAt(i + 1) : NaN;
      const paired = high && next >= 0xdc00 && next <= 0xdfff;
      if (!paired) {
        throw new CanonicalizeError(
          `unpaired surrogate \\u${unit.toString(16).padStart(4, '0')} is not well-formed Unicode `
          + 'and has no canonical encoding', path);
      }
      out += `${s[i]}${s[i + 1]}`;
      i += 1;
      continue;
    }

    const ch = /** @type {string} */ (s[i]);
    const short = SHORT_ESCAPE[ch];
    if (short !== undefined) { out += short; continue; }
    out += unit < 0x20 ? '\\u' + unit.toString(16).padStart(4, '0') : ch;
  }
  return out + '"';
}

/**
 * @param {number} n
 * @param {string} path
 */
function encodeNumber(n, path) {
  if (!Number.isFinite(n)) throw new CanonicalizeError('NaN and Infinity have no JSON form', path);
  if (!Number.isInteger(n)) {
    throw new CanonicalizeError(
      'non-integer number rejected: coerce it to a decimal string at capture (DES-02 rule 3)', path);
  }
  // Beyond 2^53 a double no longer distinguishes consecutive integers — 2^53
  // and 2^53+1 are the same value — so two different intended amounts would
  // canonicalise identically. That is the same ambiguity non-integers are
  // rejected for, and it gets the same answer. Above this range, use a string.
  if (!Number.isSafeInteger(n)) {
    throw new CanonicalizeError(
      `integer ${String(n)} is outside the exactly representable range: `
      + 'two different values would canonicalise alike, so encode it as a decimal string', path);
  }
  // RFC 8785 number serialisation is ECMAScript Number::toString. Within the
  // safe-integer range that is always the plain digits, and -0 normalises to 0.
  return String(n === 0 ? 0 : n);
}

/**
 * Sort by UTF-16 code unit, which is what RFC 8785 specifies — not locale
 * order, and not code point order.
 *
 * That is exactly what JavaScript's own relational operators do on strings, so
 * this is a two-line comparator rather than a hand-rolled code-unit walk. The
 * walk it replaces was verified to produce identical orderings and allocated
 * two arrays per comparison, on the one path NFR-01 measures. `localeCompare`
 * would be wrong here, and `sort()` with no comparator is right but reads like
 * an oversight, so the intent is stated.
 * @param {string} a @param {string} b
 */
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * @param {unknown} v
 * @param {string} path
 * @returns {string}
 */
function enc(v, path) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'number': return encodeNumber(v, path);
    case 'string': return encodeString(v, path);
    case 'bigint': throw new CanonicalizeError('bigint has no JSON form; use a string', path);
    case 'undefined': throw new CanonicalizeError('undefined would be dropped; omit the key or use null', path);
    case 'function': throw new CanonicalizeError('function is not serialisable', path);
    case 'symbol': throw new CanonicalizeError('symbol is not serialisable', path);
    case 'object': break;
    default: throw new CanonicalizeError(`unsupported type ${typeof v}`, path);
  }
  if (Array.isArray(v)) {
    // Array order is semantic. It is never sorted.
    return '[' + v.map((x, i) => enc(x, `${path}[${i}]`)).join(',') + ']';
  }
  const keys = Object.keys(/** @type {object} */ (v)).sort(byCodeUnit);
  const body = keys.map(k => {
    const val = /** @type {Record<string, unknown>} */ (v)[k];
    const at = path ? `${path}.${k}` : k;
    return encodeString(k, at) + ':' + enc(val, at);
  });
  return '{' + body.join(',') + '}';
}

/**
 * Canonical RFC 8785 encoding of a JSON-safe value.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  return enc(value, '');
}

/**
 * Canonical bytes, which is what every digest in this system is taken over.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}
