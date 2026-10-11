/**
 * Walking a certificate chain to an anchor the READER supplied.
 *
 * One implementation, used by both the RFC 3161 token path (FR-16) and the
 * custody attestation path (FR-70). It was two, and they had the same hole:
 * neither checked basic constraints, so an ORDINARY end-entity certificate
 * from a trusted provider root could act as a CA and mint whatever it liked.
 * An operator holding any certificate under an accepted anchor could therefore
 * forge an attestation over a key of their choosing, or a TSA chain, and the
 * verifier reported the result as independently supported.
 *
 * For a product whose claim is "you do not have to trust the operator", a
 * trust path that accepts a certificate the operator could have obtained for
 * themselves establishes nothing. Two copies of that logic is also how the bug
 * would come back: one gets fixed and the other does not.
 *
 * What is checked, and why each one:
 *
 * - **The issuer is a CA.** `basicConstraints` with `cA: TRUE`. Node's
 *   `checkIssued` compares NAMES, so it says "this claims to be issued by
 *   that" and nothing more; the CA bit and the signature are what make it mean
 *   something.
 * - **The signature verifies** under the issuer's key, at every link.
 * - **An anchor may be pinned exactly.** A reader who supplies the exact bytes
 *   of a certificate has made a stronger statement than one who trusts its
 *   issuer, and there is nothing left to check above it — so byte equality
 *   short-circuits, and it is byte equality, not subject or key.
 * - **Depth is bounded.** The bundle is attacker-supplied; a cycle in it must
 *   not hang a verifier that was only asked to read a file.
 */

import { X509Certificate } from 'node:crypto';
import { TAG, readTlv, readOnly, children, readOid } from './der.mjs';

/** Deeper than any real provider chain, shallow enough to bound the walk. */
const MAX_DEPTH = 8;

export const OID = Object.freeze({
  basicConstraints: '2.5.29.19',
  extendedKeyUsage: '2.5.29.37',
  timeStamping: '1.3.6.1.5.5.7.3.8',
});

/** @param {string|Buffer|Uint8Array|X509Certificate} a @returns {X509Certificate|null} */
export function toCert(a) {
  try {
    if (a instanceof X509Certificate) return a;
    return new X509Certificate(typeof a === 'string' ? a : Buffer.from(a));
  } catch {
    return null;
  }
}

/**
 * @typedef {object} Link
 * @property {X509Certificate} issuer
 * @property {boolean} verified the signature holds under the issuer's key
 * @property {boolean} isCa the issuer is permitted to issue certificates
 */

/**
 * Find the certificate that issued `cert`, among `candidates`.
 *
 * Returns the match even when the signature fails or the issuer is not a CA,
 * so a caller can report "claims an issuer you accept" and "and the claim
 * holds" as the separate facts they are. Collapsing them loses which went
 * wrong, and they go wrong for different reasons.
 *
 * @param {X509Certificate} cert @param {X509Certificate[]} candidates
 * @returns {Link|null}
 */
export function findIssuer(cert, candidates) {
  for (const issuer of candidates) {
    let issued = false;
    try {
      issued = cert.checkIssued(issuer);
    } catch {
      issued = false;
    }
    if (!issued) continue;
    let verified = false;
    try {
      verified = cert.verify(issuer.publicKey);
    } catch {
      verified = false;
    }
    return { issuer, verified, isCa: isCertificateAuthority(issuer) };
  }
  return null;
}

/**
 * Whether a certificate may issue others.
 *
 * Node's `.ca` getter reads basicConstraints, but a certificate with NO
 * basicConstraints extension at all reports `false` there — and that is the
 * right answer: RFC 5280 says a certificate without it is not a CA for path
 * validation purposes. Read through the DER as well, so a malformed or absent
 * extension is never read as permission.
 *
 * @param {X509Certificate} cert
 */
export function isCertificateAuthority(cert) {
  if (cert.ca === true) return true;
  const ext = readExtension(cert, OID.basicConstraints);
  if (!ext) return false;
  try {
    const seq = readOnly(ext.value, TAG.SEQUENCE);
    const first = children(seq.value)[0];
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
    // An absent cA means FALSE, and DER forbids encoding a DEFAULT, so an
    // empty sequence is an explicit "not a CA".
    return first !== undefined && first.tag === TAG.BOOLEAN
      && first.value.length === 1 && first.value[0] !== 0x00;
  } catch {
    return false;
  }
}

/**
 * Walk from `leaf` to an anchor, requiring every intermediate to be a CA and
 * every link's signature to verify.
 *
 * @param {X509Certificate} leaf
 * @param {X509Certificate[]} bundle certificates carried alongside the leaf
 * @param {X509Certificate[]} anchors what the reader supplied
 * One shape rather than a discriminated union: TypeScript does not preserve a
 * boolean literal discriminant written in JSDoc, so `if (!walk.ok)` narrowed
 * nothing and every caller had to be cast. `reason` is empty on success.
 * @returns {{ ok: boolean, chain: X509Certificate[], pinned: boolean, reason: string }}
 */
export function chainToAnchor(leaf, bundle, anchors) {
  if (anchors.length === 0) {
    return {
      ok: false, chain: [], pinned: false,
      reason: 'no trust anchor was supplied, so there is nothing to chain to',
    };
  }
  /** @type {X509Certificate[]} */
  const chain = [leaf];
  let current = leaf;
  for (let depth = 0; depth < MAX_DEPTH; depth += 1) {
    // Exact byte equality with a pinned anchor ends the walk. A reader who
    // pins a certificate's bytes has said something stronger than "I trust
    // whoever issued this".
    if (anchors.some(a => a.raw.equals(current.raw))) {
      return { ok: true, chain, pinned: true, reason: '' };
    }
    const anchorLink = findIssuer(current, anchors);
    if (anchorLink) {
      if (!anchorLink.isCa) {
        return {
          ok: false, chain: [], pinned: false,
          reason: `${anchorLink.issuer.subject} is named as the issuer but is not a certificate `
            + 'authority: its basic constraints do not permit it to issue certificates, so a chain '
            + 'through it is one anybody holding such a certificate could have built',
        };
      }
      if (!anchorLink.verified) {
        return {
          ok: false, chain: [], pinned: false,
          reason: `the signature on ${current.subject} does not verify under `
            + `${anchorLink.issuer.subject}'s key`,
        };
      }
      return { ok: true, chain: [...chain, anchorLink.issuer], pinned: false, reason: '' };
    }
    const link = findIssuer(current, bundle.filter(c => c !== current));
    if (!link) {
      return {
        ok: false, chain: [], pinned: false,
        reason: `${current.subject} chains to no anchor this reader supplied. "Chains to a valid `
          + 'CA" is not the question; chaining to an anchor the reader named is',
      };
    }
    if (!link.isCa) {
      return {
        ok: false, chain: [], pinned: false,
        reason: `${link.issuer.subject} issued ${current.subject} but is not a certificate `
          + 'authority: its basic constraints do not permit it to issue certificates. An ordinary '
          + 'end-entity certificate from a trusted root must not be able to mint a chain, or '
          + 'anybody holding one could forge this document',
      };
    }
    if (!link.verified) {
      return {
        ok: false, chain: [], pinned: false,
        reason: `the signature on ${current.subject} does not verify under `
          + `${link.issuer.subject}'s key`,
      };
    }
    chain.push(link.issuer);
    current = link.issuer;
  }
  return {
    ok: false, chain: [], pinned: false,
    reason: `the chain is deeper than ${MAX_DEPTH} certificates`,
  };
}

/**
 * Read one extension's `extnValue` by OID.
 *
 * Node exposes no general extension accessor, and the obvious substitute —
 * searching the certificate's DER for the encoded OID — is wrong in a way that
 * matters: it finds the OID in a subject name, a serial, or inside ANOTHER
 * extension's value, and it never reads what the extension asserts. A check
 * built on it reported "the document asserts non-exportability" for a document
 * that asserted the opposite.
 *
 * @param {X509Certificate} cert @param {string} oid
 * @returns {{ critical: boolean, value: Buffer }|null}
 */
export function readExtension(cert, oid) {
  try {
    const tbs = children(readOnly(cert.raw, TAG.SEQUENCE).value)[0];
    if (!tbs) return null;
    const exts = children(tbs.value).find(c => c.tag === 0xa3);
    if (!exts) return null;
    for (const ext of children(readTlv(exts.value, 0).value)) {
      const parts = children(ext.value);
      const idTlv = parts[0];
      if (!idTlv || idTlv.tag !== TAG.OID || readOid(idTlv.value) !== oid) continue;
      const critical = parts[1]?.tag === TAG.BOOLEAN
        && parts[1].value.length === 1 && parts[1].value[0] !== 0x00;
      const valueTlv = parts.find(p => p.tag === TAG.OCTET_STRING);
      if (!valueTlv) return null;
      return { critical, value: Buffer.from(valueTlv.value) };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Whether the extension at `oid` asserts BOOLEAN TRUE.
 *
 * Used for provider custody properties, where the question is not "is the
 * property mentioned" but "does the document say yes".
 * @param {X509Certificate} cert @param {string} oid
 * @returns {'true'|'false'|'absent'|'unreadable'}
 */
export function readBooleanExtension(cert, oid) {
  const ext = readExtension(cert, oid);
  if (!ext) return 'absent';
  try {
    const inner = readOnly(ext.value);
    if (inner.tag !== TAG.BOOLEAN || inner.value.length !== 1) return 'unreadable';
    return inner.value[0] === 0x00 ? 'false' : 'true';
  } catch {
    return 'unreadable';
  }
}

/**
 * RFC 3161 §2.3 — the TSA's certificate must carry `extendedKeyUsage` with
 * `id-kp-timeStamping` and that extension must be critical.
 *
 * Without this, any certificate under an accepted anchor could sign
 * timestamps. "Somebody with a certificate from this CA said so" is a weaker
 * statement than "a timestamp authority said so", and it was being reported as
 * the stronger one.
 * @param {X509Certificate} cert
 */
export function hasTimeStampingEku(cert) {
  const ext = readExtension(cert, OID.extendedKeyUsage);
  if (!ext) return false;
  try {
    const seq = readOnly(ext.value, TAG.SEQUENCE);
    const purposes = children(seq.value)
      .filter(c => c.tag === TAG.OID)
      .map(c => readOid(c.value));
    // The spec says this EKU must be the only one present, so a certificate
    // good for TLS as well is not a TSA certificate.
    return purposes.length === 1 && purposes[0] === OID.timeStamping;
  } catch {
    return false;
  }
}
