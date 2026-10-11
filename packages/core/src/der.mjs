/**
 * A minimal, strict DER reader.
 *
 * Written rather than depended on because the alternative is an ASN.1 library
 * in the dependency closure of `@splitstick/verify`, which NFR-05 and NFR-06
 * require to be offline and auditable by construction. The verifier's whole
 * claim is that a reader can check evidence without trusting the operator; a
 * reader who must first audit a transitive dependency tree to believe that has
 * been handed a weaker claim.
 *
 * It reads only what RFC 3161 token verification needs, and it is STRICT where
 * being lenient would be a vulnerability:
 *
 * - A length that overruns the buffer is an error, never a short read. A parser
 *   that clamps turns a malformed token into a partially-read one, and the
 *   fields it did not reach keep whatever the caller initialised them to.
 * - Indefinite-length encoding is refused. It is BER, not DER, and accepting it
 *   would mean two byte sequences could encode the same token — the kind of
 *   ambiguity that signature verification cannot tolerate.
 * - Trailing bytes after the top-level value are an error, because "the
 *   signature is valid over the first N bytes and here is some more" is an
 *   attack, not a parse.
 */

export class DerError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'DerError'; }
}

export const TAG = Object.freeze({
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
});

/**
 * @typedef {object} Tlv
 * @property {number} tag
 * @property {Buffer} value the contents, excluding tag and length
 * @property {Buffer} der the whole encoding, tag and length included
 * @property {number} end offset just past this value in the parent buffer
 */

/**
 * Read one TLV at `offset`.
 * @param {Buffer} buf @param {number} [offset]
 * @returns {Tlv}
 */
export function readTlv(buf, offset = 0) {
  if (offset + 2 > buf.length) throw new DerError(`truncated at offset ${offset}: no tag and length`);
  const tag = buf[offset];
  if (tag === undefined) throw new DerError('no tag');
  // High-tag-number form (tag byte 0x1f in the low bits) is not used by
  // anything here and is refused rather than half-supported.
  if ((tag & 0x1f) === 0x1f) throw new DerError(`high-tag-number form at offset ${offset} is not supported`);
  const first = buf[offset + 1];
  if (first === undefined) throw new DerError('no length');
  let length;
  let header;
  if (first < 0x80) {
    length = first;
    header = 2;
  } else if (first === 0x80) {
    throw new DerError(`indefinite length at offset ${offset} is BER, not DER`);
  } else {
    const n = first & 0x7f;
    if (n > 4) throw new DerError(`length of ${n} bytes at offset ${offset} is beyond anything this reads`);
    if (offset + 2 + n > buf.length) throw new DerError(`truncated length at offset ${offset}`);
    length = 0;
    for (let i = 0; i < n; i += 1) length = length * 256 + /** @type {number} */ (buf[offset + 2 + i]);
    // DER requires the shortest form. A long form encoding a small length is
    // a second encoding of the same value.
    if (length < 0x80) throw new DerError(`non-minimal length encoding at offset ${offset}`);
    header = 2 + n;
  }
  const start = offset + header;
  const end = start + length;
  if (end > buf.length) {
    throw new DerError(
      `value at offset ${offset} claims ${length} bytes but only ${buf.length - start} remain: `
      + 'refused rather than read short, because a partially-read structure leaves its unread '
      + 'fields at whatever the caller initialised them to',
    );
  }
  return { tag, value: buf.subarray(start, end), der: buf.subarray(offset, end), end };
}

/**
 * Read the single top-level value, refusing trailing bytes.
 * @param {Buffer} buf @param {number} [expectTag]
 * @returns {Tlv}
 */
export function readOnly(buf, expectTag) {
  const t = readTlv(buf, 0);
  if (t.end !== buf.length) {
    throw new DerError(
      `${buf.length - t.end} trailing byte(s) after the top-level value: "valid over the first `
      + 'part, and here is some more" is an attack, not a parse',
    );
  }
  if (expectTag !== undefined && t.tag !== expectTag) {
    throw new DerError(`expected tag 0x${expectTag.toString(16)}, found 0x${t.tag.toString(16)}`);
  }
  return t;
}

/**
 * Every TLV inside a constructed value, in order.
 * @param {Buffer} value @returns {Tlv[]}
 */
export function children(value) {
  /** @type {Tlv[]} */
  const out = [];
  let o = 0;
  while (o < value.length) {
    const t = readTlv(value, o);
    out.push(t);
    o = t.end;
  }
  return out;
}

/** @param {Buffer} value @returns {string} dotted OID */
export function readOid(value) {
  if (value.length === 0) throw new DerError('an empty OID');
  const first = /** @type {number} */ (value[0]);
  const parts = [Math.floor(first / 40), first % 40];
  let acc = 0n;
  for (let i = 1; i < value.length; i += 1) {
    const b = /** @type {number} */ (value[i]);
    acc = (acc << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(Number(acc));
      acc = 0n;
    }
  }
  if (acc !== 0n) throw new DerError('an OID ending mid-arc');
  return parts.join('.');
}

/** @param {Buffer} value @returns {string} decimal, as a string because serials are large */
export function readInteger(value) {
  if (value.length === 0) throw new DerError('an empty INTEGER');
  let acc = 0n;
  const negative = (/** @type {number} */ (value[0]) & 0x80) !== 0;
  for (const b of value) acc = (acc << 8n) | BigInt(b);
  if (!negative) return acc.toString();
  const bits = BigInt(value.length) * 8n;
  return (acc - (1n << bits)).toString();
}

/**
 * RFC 5280 time. GeneralizedTime is `YYYYMMDDHHMMSSZ`; UTCTime is `YYMMDDHHMMSSZ`
 * with the two-digit year windowed at 2050, per RFC 5280 4.1.2.5.1.
 * @param {number} tag @param {Buffer} value @returns {Date}
 */
export function readTime(tag, value) {
  const s = value.toString('ascii');
  const m = tag === TAG.GENERALIZED_TIME
    ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s)
    : /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) throw new DerError(`${JSON.stringify(s)} is not a DER time (Z-terminated, no offset)`);
  let year = Number(m[1]);
  if (tag === TAG.UTC_TIME) year += year >= 50 ? 1900 : 2000;
  const ms = m[7] ? Number(`0.${m[7]}`) * 1000 : 0;
  return new Date(Date.UTC(
    year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]), ms,
  ));
}

/**
 * Encode a TLV. Only the shapes a TimeStampReq needs.
 * @param {number} tag @param {Buffer} value @returns {Buffer}
 */
export function encodeTlv(tag, value) {
  /** @type {Buffer} */
  let len;
  if (value.length < 0x80) {
    len = Buffer.from([value.length]);
  } else {
    const bytes = [];
    let n = value.length;
    while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
    len = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), len, value]);
}

/** @param {string} dotted @returns {Buffer} the OID's contents, for encodeTlv */
export function encodeOidValue(dotted) {
  const parts = dotted.split('.').map(Number);
  if (parts.length < 2 || parts.some(p => !Number.isSafeInteger(p) || p < 0)) {
    throw new DerError(`${JSON.stringify(dotted)} is not an OID`);
  }
  const out = [/** @type {number} */ (parts[0]) * 40 + /** @type {number} */ (parts[1])];
  for (const p of parts.slice(2)) {
    const bytes = [p & 0x7f];
    let n = p >> 7;
    while (n > 0) { bytes.unshift((n & 0x7f) | 0x80); n >>= 7; }
    out.push(...bytes);
  }
  return Buffer.from(out);
}
