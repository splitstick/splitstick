/**
 * Build X.509 attestation certificates, by hand, for FR-70's tests.
 *
 * This exists because the OpenSSL on this machine (LibreSSL 2.8.3) has no
 * Ed25519, so it cannot issue a certificate over an Ed25519 epoch key — and an
 * attestation whose subject is not the epoch key cannot exercise check 3 at
 * all. It is also the honest state of FR-70 as docs/m3a-failure-modes.md
 * records: there is no cloud path to a real Ed25519 attestation document, so the
 * validator ships as a correct procedure for which no genuine instance exists.
 *
 * A document we built ourselves proves the procedure. It does NOT prove
 * interoperability with any provider's real attestation, and nothing in these
 * tests may be read as doing so. That difference is written down here rather
 * than left for a reader to discover.
 */

import { generateKeyPairSync, createPublicKey, sign as cryptoSign, X509Certificate } from 'node:crypto';
import { encodeTlv, encodeOidValue, TAG } from '../src/der.mjs';

const OID_ED25519 = '1.3.101.112';
const OID_CN = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';

/**
 * YubiHSM 2's attestation extensions, as Yubico documents them and as their own
 * reference parser decodes them.
 *
 * An earlier version of this file had `.5` as Origin and invented a
 * `non_exportable` BOOLEAN at `.6`. Both were wrong: `.5` is Capabilities, `.6`
 * is the Object ID, Origin is `.3`, and there is no non-exportable extension at
 * all — the property has to be derived from Origin and Capabilities, which are
 * BIT STRINGs. A review caught it, and Yubico's OID reference and the
 * YubicoLabs parser confirm the correction.
 *
 * Sources: docs.yubico.com/hardware/oid/oid-product-arc.html for the table, and
 * github.com/YubicoLabs/yubihsm-parse-attestation for the bit indexing.
 */
export const YUBIHSM_OID = Object.freeze({
  firmware_version: '1.3.6.1.4.1.41482.4.1',   // Octet String
  serial_number: '1.3.6.1.4.1.41482.4.2',      // Integer
  origin: '1.3.6.1.4.1.41482.4.3',             // Bit String
  domains: '1.3.6.1.4.1.41482.4.4',            // Bit String
  capabilities: '1.3.6.1.4.1.41482.4.5',       // Bit String
  object_id: '1.3.6.1.4.1.41482.4.6',          // Integer
  label: '1.3.6.1.4.1.41482.4.9',              // Utf8String
  fips: '1.3.6.1.4.1.41482.4.10',              // Integer
  fips_approved: '1.3.6.1.4.1.41482.4.12',     // Boolean
});

/**
 * Origin bits, LSB-first within the FIRST content octet — matching the masks
 * Yubico documents (generated 0x01, imported 0x02, imported_wrapped 0x10) and
 * how their parser reads `bs.Bytes[0]` as a uint8.
 */
export const ORIGIN_BIT = Object.freeze({ generated: 0, imported: 1, imported_wrapped: 4 });

/**
 * Capability bits, LSB-first in the 8 content octets read as a big-endian
 * uint64 — again matching their parser. `exportable-under-wrap` is documented
 * with mask 0x0000000000010000, which is bit 16.
 */
export const CAPABILITY_BIT = Object.freeze({
  generate_asymmetric_key: 4,
  sign_eddsa: 8,
  export_wrapped: 12,
  exportable_under_wrap: 16,
  sign_attestation_certificate: 34,
});

/**
 * A DER BIT STRING whose content octets, read big-endian, have the given bits
 * set — the vendor's encoding, not X.690's MSB-first bit numbering.
 * @param {number[]} bits @param {number} [byteLength]
 */
export function bitStringFor(bits, byteLength = 8) {
  const value = Buffer.alloc(byteLength);
  for (const bit of bits) {
    // Big-endian: bit 0 is the LSB of the LAST octet.
    const byte = byteLength - 1 - Math.floor(bit / 8);
    if (byte < 0) throw new RangeError(`bit ${bit} does not fit in ${byteLength} bytes`);
    value[byte] |= 1 << (bit % 8);
  }
  // One leading octet counting unused trailing bits: zero, because whole
  // octets are always emitted.
  return encodeTlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0]), value]));
}

/** The extensions a genuine YubiHSM 2 attestation of a generated, non-exportable key carries. */
export function yubihsmExtensions({ origin = ['generated'], capabilities = ['sign_eddsa'] } = {}) {
  return [
    {
      oid: YUBIHSM_OID.origin,
      value: bitStringFor(origin.map(o => ORIGIN_BIT[/** @type {keyof typeof ORIGIN_BIT} */ (o)]), 1),
    },
    {
      oid: YUBIHSM_OID.capabilities,
      value: bitStringFor(
        capabilities.map(c => CAPABILITY_BIT[/** @type {keyof typeof CAPABILITY_BIT} */ (c)]), 8),
    },
  ];
}

const b = (/** @type {number[]} */ a) => Buffer.from(a);

/** @param {string} cn */
const name = (cn) => encodeTlv(TAG.SEQUENCE, encodeTlv(TAG.SET, encodeTlv(TAG.SEQUENCE, Buffer.concat([
  encodeTlv(TAG.OID, encodeOidValue(OID_CN)),
  encodeTlv(TAG.UTF8_STRING, Buffer.from(cn, 'utf8')),
]))));

/**
 * RFC 5280 4.1.2.5 requires UTCTime through 2049 and GeneralizedTime after. A
 * GeneralizedTime before 2050 parses as DER but Node's X509Certificate reports
 * "Bad time value" for it, which is the right thing for it to do and was how
 * this fixture's first version went wrong.
 * @param {Date} d
 */
const certTime = (d) => {
  // No 'T' and no fractional seconds: UTCTime is YYMMDDHHMMSSZ exactly, and
  // leaving the separator in produced a certificate Node read as "Bad time
  // value" while still verifying its signature — valid DER, invalid X.509.
  const iso = d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '').replace('T', '');
  return d.getUTCFullYear() < 2050
    ? encodeTlv(TAG.UTC_TIME, Buffer.from(iso.slice(2), 'ascii'))
    : encodeTlv(TAG.GENERALIZED_TIME, Buffer.from(iso, 'ascii'));
};

const ed25519AlgId = () => encodeTlv(TAG.SEQUENCE, encodeTlv(TAG.OID, encodeOidValue(OID_ED25519)));

/** @param {string} oid @param {Buffer} value @param {boolean} [critical] */
function extension(oid, value, critical = false) {
  return encodeTlv(TAG.SEQUENCE, Buffer.concat([
    encodeTlv(TAG.OID, encodeOidValue(oid)),
    ...(critical ? [encodeTlv(TAG.BOOLEAN, b([0xff]))] : []),
    encodeTlv(TAG.OCTET_STRING, value),
  ]));
}

/** An Ed25519 key pair with its raw public bytes and SPKI DER. */
export function key() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return { privateKey, publicKey, spki, raw: Buffer.from(spki).subarray(-32) };
}

/**
 * @param {object} o
 * @param {string} o.subject
 * @param {Buffer} o.subjectSpki
 * @param {string} o.issuer
 * @param {import('node:crypto').KeyObject} o.issuerKey
 * @param {Date} o.notBefore
 * @param {Date} o.notAfter
 * @param {boolean} [o.ca]
 * @param {{ oid: string, value: Buffer, critical?: boolean }[]} [o.extensions]
 * @param {number} [o.serial]
 * @param {boolean} [o.corruptSignature]
 * @returns {X509Certificate}
 */
export function certificate(o) {
  /** @type {Buffer[]} */
  const exts = [];
  if (o.ca) {
    exts.push(extension(OID_BASIC_CONSTRAINTS, encodeTlv(TAG.SEQUENCE, encodeTlv(TAG.BOOLEAN, b([0xff]))), true));
  } else {
    exts.push(extension(OID_BASIC_CONSTRAINTS, encodeTlv(TAG.SEQUENCE, Buffer.alloc(0)), true));
  }
  for (const e of o.extensions ?? []) exts.push(extension(e.oid, e.value, e.critical));

  const tbs = encodeTlv(TAG.SEQUENCE, Buffer.concat([
    encodeTlv(0xa0, encodeTlv(TAG.INTEGER, b([2]))),              // version v3
    encodeTlv(TAG.INTEGER, b([o.serial ?? 1])),
    ed25519AlgId(),
    name(o.issuer),
    encodeTlv(TAG.SEQUENCE, Buffer.concat([certTime(o.notBefore), certTime(o.notAfter)])),
    name(o.subject),
    o.subjectSpki,
    encodeTlv(0xa3, encodeTlv(TAG.SEQUENCE, Buffer.concat(exts))),
  ]));
  const sig = cryptoSign(null, tbs, o.issuerKey);
  if (o.corruptSignature) sig[0] ^= 0xff;
  const cert = encodeTlv(TAG.SEQUENCE, Buffer.concat([
    tbs,
    ed25519AlgId(),
    encodeTlv(TAG.BIT_STRING, Buffer.concat([b([0]), sig])),
  ]));
  return new X509Certificate(cert);
}

/**
 * A root, and an attestation over `attested` issued by it.
 * @param {object} o
 * @param {Buffer} o.attestedSpki the epoch key's SPKI
 * @param {Date} [o.notBefore] @param {Date} [o.notAfter]
 * @param {boolean} [o.nonExportable] @param {boolean} [o.corruptSignature]
 * @param {string[]} [o.origin] origin bit names, e.g. ['imported']
 * @param {{ oid: string, value: Buffer, critical?: boolean }[]} [o.extensions]
 * @param {string} [o.rootName] so a test can build an anchor whose NAME does
 *   not collide: Node's checkIssued is name-based, and a collision is a
 *   different case from a stranger
 */
export function attestation(o) {
  const rootKey = key();
  const rootName = o.rootName ?? 'Test Provider Attestation Root';
  const root = certificate({
    subject: rootName, issuer: rootName,
    subjectSpki: Buffer.from(rootKey.spki), issuerKey: rootKey.privateKey,
    notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2040-01-01T00:00:00Z'),
    ca: true, serial: 1,
  });
  const leafIssuer = rootName;
  // Vendor format: Origin and Capabilities as BIT STRINGs with the bit layout
  // Yubico's own parser uses. `nonExportable: false` adds the
  // exportable-under-wrap capability, which is how a real device says a key
  // can leave it — there is no boolean to flip.
  const extensions = o.extensions ?? yubihsmExtensions({
    origin: o.origin ?? ['generated'],
    capabilities: o.nonExportable === false
      ? ['sign_eddsa', 'exportable_under_wrap']
      : ['sign_eddsa'],
  });
  const leaf = certificate({
    subject: 'Attested Key', issuer: leafIssuer,
    subjectSpki: o.attestedSpki, issuerKey: rootKey.privateKey,
    notBefore: o.notBefore ?? new Date('2026-10-01T00:00:00Z'),
    notAfter: o.notAfter ?? new Date('2027-10-01T00:00:00Z'),
    extensions, serial: 2,
    ...(o.corruptSignature ? { corruptSignature: true } : {}),
  });
  return { root, leaf, rootKey };
}
