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
 * Yubico's attestation extensions, as documented for the YubiHSM 2 / YubiKey
 * attestation certificates. They are the shape FR-70's check 5 looks for; the
 * values below are ours, because the OIDs are theirs and the document is not.
 */
export const OID_ORIGIN = '1.3.6.1.4.1.41482.4.5';
export const OID_NON_EXPORTABLE = '1.3.6.1.4.1.41482.4.6';

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
  const extensions = [
    { oid: OID_ORIGIN, value: encodeTlv(TAG.UTF8_STRING, Buffer.from('generated-on-device', 'utf8')) },
  ];
  if (o.nonExportable !== false) {
    extensions.push({
      oid: OID_NON_EXPORTABLE,
      value: encodeTlv(TAG.BOOLEAN, b([0xff])),
    });
  }
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
