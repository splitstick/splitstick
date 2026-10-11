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
function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const short = SHORT_ESCAPE[ch];
    if (short !== undefined) { out += short; continue; }
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 ? '\\u' + code.toString(16).padStart(4, '0') : ch;
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
  // Number::toString already renders an integer-valued double without an
  // exponent or trailing zero for every magnitude Number.isInteger admits,
  // and normalises -0 to "0".
  return String(n === 0 ? 0 : n);
}

/**
 * Sort by UTF-16 code unit, which is what RFC 8785 specifies — not locale
 * order, and not code point order. The difference shows up above the BMP.
 * @param {string} a @param {string} b
 */
function byCodeUnit(a, b) {
  const ua = [...a].flatMap(c => {
    const s = c.charCodeAt(0);
    return c.length > 1 ? [s, c.charCodeAt(1)] : [s];
  });
  const ub = [...b].flatMap(c => {
    const s = c.charCodeAt(0);
    return c.length > 1 ? [s, c.charCodeAt(1)] : [s];
  });
  const n = Math.min(ua.length, ub.length);
  for (let i = 0; i < n; i++) {
    const x = ua[i] ?? 0, y = ub[i] ?? 0;
    if (x !== y) return x - y;
  }
  return ua.length - ub.length;
}

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
    case 'string': return encodeString(v);
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
    return encodeString(k) + ':' + enc(val, path ? `${path}.${k}` : k);
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
