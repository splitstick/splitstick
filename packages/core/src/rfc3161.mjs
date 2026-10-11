/**
 * RFC 3161 TimeStampToken verification — FR-16, DES-20.
 *
 * A TSA cannot produce a C2SP signed-note line. It produces a CMS `SignedData`
 * over a `TSTInfo`, DER-encoded: its own format, its own verification path.
 * DES-20 carries it in the envelope beside the note with `covers: "note_digest"`,
 * and this module is what checks that claim.
 *
 * Verification is here, in core, rather than in the adapter package, because
 * it is pure computation over bytes — no network, no credential — and the
 * offline verifier needs it. SUBMISSION is what needs a network, and that lives
 * in `@splitstick/witness-tsa`, so the verifier never acquires an HTTP client.
 *
 * What a valid token establishes, exactly: that the TSA asserts it saw this
 * 32-byte imprint no later than `genTime`. Not that the imprint is of anything
 * in particular — that is what the envelope's `covers` is for — and not that
 * the TSA's clock is right. It is one party's statement, which is worth having
 * because it is not the operator's.
 *
 * The five things that must all hold, and each of which has a test that breaks
 * only it:
 *
 * 1. The DER parses strictly, with no trailing bytes and no overrunning length.
 * 2. `MessageImprint.hashedMessage` is the imprint the caller is asking about.
 *    A verifier that checked the CMS signature and skipped this would accept a
 *    valid timestamp over somebody else's document as a timestamp over yours.
 * 3. The signature verifies over the DER-encoded `SignedAttributes`, with the
 *    implicit `[0]` tag replaced by `SET` as RFC 5652 requires.
 * 4. The `messageDigest` signed attribute is the digest of the `eContent`, so
 *    the signature actually reaches the TSTInfo rather than only the attributes.
 * 5. The signer certificate chains to an anchor THIS READER supplied. Not "to
 *    a valid CA" — FR-30 makes the trust store an input, and a token chaining
 *    to some CA the reader never named establishes nothing for them.
 */

import { createHash, createVerify, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import {
  TAG, DerError, readTlv, readOnly, children, readOid, readInteger, readTime,
  encodeTlv, encodeOidValue,
} from './der.mjs';

export class Rfc3161Error extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'Rfc3161Error'; }
}

const OID = Object.freeze({
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  sha1: '1.3.14.3.2.26',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ed25519: '1.3.101.112',
});

/** @type {Record<string, string>} */
const DIGESTS = {
  [OID.sha256]: 'sha256',
  [OID.sha384]: 'sha384',
  [OID.sha512]: 'sha512',
  [OID.sha1]: 'sha1',
};

/**
 * @typedef {object} ParsedToken
 * @property {number} version TSTInfo version, 1
 * @property {string} policy the TSA policy OID
 * @property {string} hashAlgorithm the imprint's algorithm, e.g. 'sha256'
 * @property {Buffer} imprint MessageImprint.hashedMessage
 * @property {string} serialNumber
 * @property {Date} genTime
 * @property {Buffer} tstInfoDer the signed content, verbatim
 * @property {X509Certificate[]} certificates
 * @property {X509Certificate} signerCertificate
 * @property {Buffer} signedAttrsDer re-tagged as SET, which is what is signed
 * @property {Buffer} signature
 * @property {string} digestAlgorithm
 * @property {Buffer} messageDigestAttr the digest the signature commits to
 * @property {string} signatureAlgorithmOid
 */

/**
 * Parse a DER TimeStampToken. Throws on anything malformed; verification is a
 * separate step, so that "this is not a token" and "this token does not verify"
 * are different answers.
 * @param {Buffer|Uint8Array} der
 * @returns {ParsedToken}
 */
export function parseTimeStampToken(der) {
  const buf = Buffer.from(der);
  try {
    const ci = children(readOnly(buf, TAG.SEQUENCE).value);
    const ctype = ci[0];
    if (!ctype || ctype.tag !== TAG.OID || readOid(ctype.value) !== OID.signedData) {
      throw new Rfc3161Error('the outer ContentInfo is not a CMS SignedData');
    }
    const wrapper = ci[1];
    if (!wrapper || wrapper.tag !== 0xa0) throw new Rfc3161Error('no [0] EXPLICIT content');
    const sd = children(readOnly(wrapper.value, TAG.SEQUENCE).value);

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //                           certificates [0]?, crls [1]?, signerInfos }
    const eci = sd[2];
    if (!eci || eci.tag !== TAG.SEQUENCE) throw new Rfc3161Error('no EncapsulatedContentInfo');
    const eciKids = children(eci.value);
    const eContentType = eciKids[0];
    if (!eContentType || readOid(eContentType.value) !== OID.tstInfo) {
      throw new Rfc3161Error('the encapsulated content is not a TSTInfo');
    }
    const eContentWrap = eciKids[1];
    if (!eContentWrap || eContentWrap.tag !== 0xa0) {
      throw new Rfc3161Error('the TSTInfo is absent: this is a detached signature, not a token');
    }
    const eContent = readTlv(eContentWrap.value, 0);
    if (eContent.tag !== TAG.OCTET_STRING) throw new Rfc3161Error('the TSTInfo is not an OCTET STRING');
    const tstInfoDer = Buffer.from(eContent.value);

    /** @type {X509Certificate[]} */
    const certificates = [];
    for (const k of sd.slice(3)) {
      if (k.tag !== 0xa0) continue;
      for (const c of children(k.value)) {
        if (c.tag === TAG.SEQUENCE) certificates.push(new X509Certificate(Buffer.from(c.der)));
      }
    }

    const siSet = sd.find((k, i) => i >= 3 && k.tag === TAG.SET);
    if (!siSet) throw new Rfc3161Error('no SignerInfos');
    const sis = children(siSet.value);
    if (sis.length !== 1) {
      // More than one signer over a timestamp is not a shape RFC 3161 uses, and
      // picking one would mean choosing which party the reader is trusting.
      throw new Rfc3161Error(`${sis.length} SignerInfos; exactly one is expected`);
    }
    const si = children(/** @type {import('./der.mjs').Tlv} */ (sis[0]).value);

    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
    //                           signedAttrs [0]?, signatureAlgorithm,
    //                           signature, unsignedAttrs [1]? }
    const digAlg = si[2];
    if (!digAlg) throw new Rfc3161Error('no digestAlgorithm');
    const digOid = readOid(/** @type {import('./der.mjs').Tlv} */ (children(digAlg.value)[0]).value);
    const digestAlgorithm = DIGESTS[digOid];
    if (!digestAlgorithm) throw new Rfc3161Error(`digest algorithm ${digOid} is not implemented`);

    const signedAttrsTlv = si.find(k => k.tag === 0xa0);
    if (!signedAttrsTlv) {
      throw new Rfc3161Error('no SignedAttributes: a token without them does not commit to its own content type');
    }
    // RFC 5652 5.4 — what is signed is the DER SET OF, not the implicit [0].
    const signedAttrsDer = encodeTlv(TAG.SET, Buffer.from(signedAttrsTlv.value));

    /** @type {Buffer|null} */
    let messageDigestAttr = null;
    let sawContentType = false;
    for (const attr of children(signedAttrsTlv.value)) {
      const kids = children(attr.value);
      const oidTlv = kids[0];
      const valsTlv = kids[1];
      if (!oidTlv || !valsTlv) continue;
      const oid = readOid(oidTlv.value);
      const first = children(valsTlv.value)[0];
      if (!first) continue;
      if (oid === OID.messageDigest) messageDigestAttr = Buffer.from(first.value);
      if (oid === OID.contentType) sawContentType = readOid(first.value) === OID.tstInfo;
    }
    if (!messageDigestAttr) throw new Rfc3161Error('no messageDigest signed attribute');
    if (!sawContentType) {
      throw new Rfc3161Error('the signed attributes do not bind the content type to TSTInfo');
    }

    const afterAttrs = si.slice(si.indexOf(signedAttrsTlv) + 1);
    const sigAlg = afterAttrs.find(k => k.tag === TAG.SEQUENCE);
    const sigOctet = afterAttrs.find(k => k.tag === TAG.OCTET_STRING);
    if (!sigAlg || !sigOctet) throw new Rfc3161Error('no signatureAlgorithm or signature');
    const sigAlgOid = readOid(/** @type {import('./der.mjs').Tlv} */ (children(sigAlg.value)[0]).value);

    // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
    //                        genTime, accuracy?, ordering?, nonce?, tsa?, ext? }
    const ti = children(readOnly(tstInfoDer, TAG.SEQUENCE).value);
    const vTlv = ti[0];
    const polTlv = ti[1];
    const impTlv = ti[2];
    const serTlv = ti[3];
    const genTlv = ti[4];
    if (!vTlv || !polTlv || !impTlv || !serTlv || !genTlv) throw new Rfc3161Error('a truncated TSTInfo');
    const impKids = children(impTlv.value);
    const impAlg = impKids[0];
    const impVal = impKids[1];
    if (!impAlg || !impVal || impVal.tag !== TAG.OCTET_STRING) {
      throw new Rfc3161Error('a malformed MessageImprint');
    }
    const impOid = readOid(/** @type {import('./der.mjs').Tlv} */ (children(impAlg.value)[0]).value);
    const hashAlgorithm = DIGESTS[impOid];
    if (!hashAlgorithm) throw new Rfc3161Error(`imprint algorithm ${impOid} is not implemented`);

    const signerCertificate = pickSigner(certificates, si[1]);
    return {
      version: Number(readInteger(vTlv.value)),
      policy: readOid(polTlv.value),
      hashAlgorithm,
      imprint: Buffer.from(impVal.value),
      serialNumber: toHexish(readInteger(serTlv.value)),
      genTime: readTime(genTlv.tag, genTlv.value),
      tstInfoDer,
      certificates,
      signerCertificate,
      signedAttrsDer,
      signature: Buffer.from(sigOctet.value),
      digestAlgorithm,
      messageDigestAttr,
      signatureAlgorithmOid: sigAlgOid,
    };
  } catch (e) {
    if (e instanceof Rfc3161Error) throw e;
    throw new Rfc3161Error(
      `not a parseable RFC 3161 TimeStampToken: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/** OpenSSL prints serials in hex; a decimal string is unhelpful next to its output. */
const toHexish = (/** @type {string} */ dec) => BigInt(dec).toString(16);

/**
 * @param {X509Certificate[]} certs
 * @param {import('./der.mjs').Tlv|undefined} sid SignerIdentifier
 * @returns {X509Certificate}
 */
function pickSigner(certs, sid) {
  if (certs.length === 0) {
    throw new Rfc3161Error(
      'the token carries no certificates, so there is nothing to check the signature with. '
      + 'Request the token with the certificate included (RFC 3161 certReq).',
    );
  }
  // IssuerAndSerialNumber is a SEQUENCE; SubjectKeyIdentifier is [0]. Rather
  // than decoding the issuer name, match on serial, which is what distinguishes
  // certificates from one issuer — and fall back to the leaf.
  if (sid && sid.tag === TAG.SEQUENCE) {
    const kids = children(sid.value);
    const serialTlv = kids[1];
    if (serialTlv && serialTlv.tag === TAG.INTEGER) {
      const want = BigInt(readInteger(serialTlv.value)).toString(16).padStart(2, '0');
      const found = certs.find(c => c.serialNumber.replace(/^0+/, '').toLowerCase() === want.replace(/^0+/, ''));
      if (found) return found;
    }
  }
  const leaf = certs.find(c => !certs.some(other => other !== c && isIssuedBy(c, other) === false && false))
    ?? certs[0];
  return /** @type {X509Certificate} */ (leaf);
}

/** @param {X509Certificate} cert @param {X509Certificate} issuer */
function isIssuedBy(cert, issuer) {
  try {
    return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

/**
 * @param {Buffer|Uint8Array} der the token
 * @param {{ imprint: Uint8Array, anchors?: (string|Buffer|X509Certificate)[],
 *           at?: Date }} opts
 * @returns {Promise<{ ok: boolean, inconclusive?: boolean, malformed?: boolean,
 *                     detail: string, genTime: Date|null, tsa: string|null,
 *                     serialNumber?: string }>}
 */
export async function verifyTimeStampToken(der, opts) {
  /** @type {ParsedToken} */
  let t;
  try {
    t = parseTimeStampToken(der);
  } catch (e) {
    // Malformed is not refuted. A blob that does not parse is broken evidence —
    // a mangled adapter, a truncated field — and calling it "the witness signed
    // a different root" would hand a reader the project's strongest finding on
    // the project's weakest grounds.
    return {
      ok: false, malformed: true, inconclusive: true,
      detail: `this is not a parseable RFC 3161 token, so it refutes nothing and establishes `
        + `nothing: ${e instanceof Error ? e.message : String(e)}`,
      genTime: null, tsa: null,
    };
  }
  const tsa = t.signerCertificate.subject;

  // 2 — the imprint. Before anything cryptographic, because a token over other
  // bytes is not a weaker proof about these bytes, it is no proof about them.
  const want = Buffer.from(opts.imprint);
  if (!t.imprint.equals(want)) {
    return {
      ok: false,
      detail: `the token's MessageImprint is over ${t.imprint.toString('hex').slice(0, 16)}… but the `
        + `bytes being checked digest to ${want.toString('hex').slice(0, 16)}…: this is a valid `
        + 'timestamp over something else',
      genTime: t.genTime, tsa,
    };
  }
  if (t.hashAlgorithm !== 'sha256' || want.length !== 32) {
    return {
      ok: false,
      detail: `the imprint is ${t.hashAlgorithm}; this suite commits to SHA-256 (DES-16)`,
      genTime: t.genTime, tsa,
    };
  }

  // 4 — the signature reaches the content, not only the attributes.
  const contentDigest = createHash(t.digestAlgorithm).update(t.tstInfoDer).digest();
  if (!contentDigest.equals(t.messageDigestAttr)) {
    return {
      ok: false,
      detail: 'the messageDigest signed attribute is not the digest of the TSTInfo, so the signature '
        + 'does not reach the timestamp it appears to cover',
      genTime: t.genTime, tsa,
    };
  }

  // 3 — the signature over the re-tagged SignedAttributes.
  if (!verifySignature(t)) {
    return {
      ok: false,
      detail: `the TSA signature does not verify under ${tsa}'s public key`,
      genTime: t.genTime, tsa,
    };
  }

  // 5 — the chain, to an anchor the READER named.
  const anchors = (opts.anchors ?? []).map(toCert).filter(c => c !== null);
  if (anchors.length === 0) {
    return {
      ok: false,
      inconclusive: true,
      detail: `the token is internally valid and signed by ${tsa}, but no trust anchor was supplied, `
        + 'so it is not established that this TSA is one you accept. The acceptance policy is an '
        + 'input (FR-30): nothing is claimed without it',
      genTime: t.genTime, tsa,
    };
  }
  const chain = chainTo(t.signerCertificate, t.certificates, anchors);
  if (!chain) {
    return {
      ok: false,
      detail: `${tsa}'s certificate does not chain to any anchor this reader supplied. "Chains to a `
        + 'valid CA" is not the question; chaining to an anchor the reader named is',
      genTime: t.genTime, tsa,
    };
  }
  const at = opts.at;
  if (at) {
    for (const c of chain) {
      if (at < new Date(c.validFrom) || at > new Date(c.validTo)) {
        return {
          ok: false,
          detail: `${c.subject} was not valid at ${at.toISOString()}`,
          genTime: t.genTime, tsa,
        };
      }
    }
  }

  return {
    ok: true,
    detail: `verified: ${tsa} asserts it saw this imprint no later than ${t.genTime.toISOString()}, `
      + `chaining to an anchor this reader supplied. That is one party's statement about time, worth `
      + "having because it is not the operator's — it is not a claim that the clock is right",
    genTime: t.genTime,
    tsa,
    serialNumber: t.serialNumber,
  };
}

/** @param {ParsedToken} t */
function verifySignature(t) {
  try {
    const key = t.signerCertificate.publicKey;
    if (t.signatureAlgorithmOid === OID.ed25519) {
      // PureEdDSA signs the message, so there is no createVerify path for it.
      return cryptoVerify(null, t.signedAttrsDer, key, t.signature);
    }
    const v = createVerify(t.digestAlgorithm);
    v.update(t.signedAttrsDer);
    return v.verify(key, t.signature);
  } catch {
    return false;
  }
}

/** @param {string|Buffer|X509Certificate} a @returns {X509Certificate|null} */
function toCert(a) {
  try {
    return a instanceof X509Certificate ? a : new X509Certificate(a);
  } catch {
    return null;
  }
}

/**
 * Walk from the signer to an anchor, checking each link's signature. Depth is
 * bounded: a cycle in a supplied bundle must not hang a verifier.
 * @param {X509Certificate} leaf
 * @param {X509Certificate[]} bundle
 * @param {X509Certificate[]} anchors
 * @returns {X509Certificate[]|null}
 */
function chainTo(leaf, bundle, anchors) {
  /** @type {X509Certificate[]} */
  const chain = [leaf];
  let current = leaf;
  for (let depth = 0; depth < 8; depth += 1) {
    const anchor = anchors.find(a => isIssuedBy(current, a));
    if (anchor) return [...chain, anchor];
    if (anchors.some(a => a.raw.equals(current.raw))) return chain;
    const next = bundle.find(c => c !== current && isIssuedBy(current, c));
    if (!next) return null;
    chain.push(next);
    current = next;
  }
  return null;
}

/**
 * A `TimeStampReq` over a SHA-256 imprint, with `certReq` set.
 *
 * PRIV-01 — a request carries a 32-byte hash and nothing else. No tool name, no
 * arguments, no result, no salt. There is nothing in here to redact because
 * there is nothing in here.
 *
 * @param {Uint8Array} imprint 32 bytes
 * @returns {Buffer} DER
 */
export function timeStampRequest(imprint) {
  if (!(imprint instanceof Uint8Array) || imprint.length !== 32) {
    throw new Rfc3161Error('an imprint is 32 bytes of SHA-256');
  }
  const algId = encodeTlv(TAG.SEQUENCE, Buffer.concat([
    encodeTlv(TAG.OID, encodeOidValue(OID.sha256)),
    encodeTlv(TAG.NULL, Buffer.alloc(0)),
  ]));
  const messageImprint = encodeTlv(TAG.SEQUENCE, Buffer.concat([
    algId,
    encodeTlv(TAG.OCTET_STRING, Buffer.from(imprint)),
  ]));
  return encodeTlv(TAG.SEQUENCE, Buffer.concat([
    encodeTlv(TAG.INTEGER, Buffer.from([1])),
    messageImprint,
    // certReq TRUE: without the certificate the token cannot be verified by
    // anyone who does not already have it, which defeats the purpose.
    encodeTlv(TAG.BOOLEAN, Buffer.from([0xff])),
  ]));
}
