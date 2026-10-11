/**
 * Validating a provider custody attestation — FR-70, DES-06.
 *
 * The PRESENCE of an attestation document establishes nothing. Before a
 * verifier may report custody as *independently supported* rather than
 * *operator-declared*, all five of these must hold, and the result reports each
 * one separately because a collapsed boolean would hide which failed — and
 * which failed is the only thing a reader can act on.
 *
 * 1. **Issuer** — chains to a provider root in the reader's acceptance policy.
 *    Not merely to some valid CA.
 * 2. **Signature** — valid over the exact bytes presented.
 * 3. **Key identity** — the attested key is the one that signed this epoch's
 *    checkpoints. A provider will attest any key the account holds; whether it
 *    attested THIS one is the question.
 * 4. **Epoch applicability** — the document covers the period the epoch spans.
 *    An attestation issued after the fact says nothing about earlier
 *    signatures, and one that expired mid-epoch covers half of it.
 * 5. **Custody properties** — it asserts non-exportability, rather than the
 *    mere existence of a managed key. A key that could be exported is a managed
 *    key, not a custody guarantee.
 *
 * And all five together still do not establish historical destruction.
 * Non-exportability says a key could not leave the module; it does not say a
 * retired key was deleted. `establishes_destruction` is therefore hard-coded
 * false, and SEC-17's claim keeps its precondition.
 *
 * ## What this has been tested against
 *
 * Constructed documents, not a provider's. There is currently no cloud path to
 * an Ed25519 attestation at all: the product that issues per-key attestations
 * (GCP Cloud HSM) cannot sign Ed25519, and the product that signs Ed25519 under
 * HSM protection (AWS KMS) issues service compliance reports rather than a
 * per-key document (DES-06, docs/kms-capability-matrix.md). YubiHSM 2's
 * attestation is documented — an X.509 certificate over the attested key,
 * chaining through a Yubico intermediate, with origin and capabilities in named
 * extensions — but that purchase is on hold.
 *
 * So this is a correct procedure for which no genuine instance has been
 * produced, and `provider_untested` is set on every result to say so in the
 * report rather than only here. NFR-09's HSM half stays open.
 */

import { X509Certificate } from 'node:crypto';
import { toCert, chainToAnchor, findIssuer, readBooleanExtension } from './trustpath.mjs';

export const ATTESTATION_CHECKS = Object.freeze([
  'issuer', 'signature', 'key_identity', 'epoch_applicability', 'custody_properties',
]);

/**
 * Yubico's documented attestation extension OIDs. Named here because check 5
 * has to read a property rather than infer one from the issuer, and the OID is
 * the only part of a provider's document that is stable enough to look for.
 */
export const CUSTODY_PROPERTY_OIDS = Object.freeze({
  non_exportable: '1.3.6.1.4.1.41482.4.6',
  origin: '1.3.6.1.4.1.41482.4.5',
});

/** @typedef {{ ok: boolean, detail: string }} Check */

/**
 * @param {Buffer|Uint8Array|string} document DER or PEM
 * @param {object} opts
 * @param {(string|Buffer|X509Certificate)[]} [opts.anchors] provider roots the
 *   READER accepts (FR-30). Without them nothing is established.
 * @param {Uint8Array} [opts.epochPublicKey] raw 32 bytes — the key that signed
 *   this epoch's checkpoints
 * @param {{ from: Date, to: Date }} [opts.epochSpan]
 * @param {string[]} [opts.requireProperties] property names from
 *   CUSTODY_PROPERTY_OIDS; defaults to ['non_exportable']. An empty array
 *   waives check 5, and the result says the reader waived it.
 * @param {(string|Buffer|X509Certificate)[]} [opts.intermediates]
 * @returns {{
 *   supported: boolean, inconclusive: boolean, detail: string,
 *   checks: Record<string, Check>,
 *   establishes_destruction: false, provider_untested: boolean,
 *   attested_key: string|null,
 * }}
 */
export function validateAttestation(document, opts = {}) {
  /** @type {Record<string, Check>} */
  const checks = Object.fromEntries(
    ATTESTATION_CHECKS.map(c => [c, { ok: false, detail: 'not evaluated' }]),
  );
  /** @param {string} detail @param {boolean} [inconclusive] */
  const no = (detail, inconclusive = false) => ({
    supported: false, inconclusive, detail, checks,
    establishes_destruction: /** @type {false} */ (false),
    provider_untested: true, attested_key: null,
  });

  /** @type {X509Certificate} */
  let cert;
  try {
    cert = new X509Certificate(typeof document === 'string' ? document : Buffer.from(document));
  } catch (e) {
    return no(`this is not a parseable X.509 attestation document: ${e instanceof Error ? e.message : String(e)}`);
  }

  const attestedSpki = Buffer.from(cert.publicKey.export({ format: 'der', type: 'spki' }));
  const attested = attestedSpki.subarray(-32);

  // 1 and 2 together: a chain link is a signature check, so verifying the
  // signature IS how the issuer is established. They are reported separately
  // because a document signed by nobody the reader trusts is a different
  // problem from a document whose signature is broken.
  const anchors = (opts.anchors ?? []).map(toCert).filter(c => c !== null);
  const intermediates = (opts.intermediates ?? []).map(toCert).filter(c => c !== null);
  if (anchors.length === 0) {
    checks.issuer = {
      ok: false,
      detail: 'no provider root was supplied, so there is nothing to chain this document to. The '
        + 'acceptance policy is an input (FR-30): a document chaining to a CA the reader never '
        + 'named establishes nothing for them',
    };
    checks.signature = { ok: false, detail: 'not evaluated: there is no issuer to check against' };
    return no('no provider root was supplied, so this attestation establishes nothing', true);
  }

  // The walk is the shared one (trustpath.mjs), which requires every issuer to
  // be a certificate authority. It did not, and an ordinary end-entity
  // certificate from a trusted provider root could therefore mint an
  // attestation over any key — making this whole procedure worth nothing to
  // anybody who already held such a certificate, which an operator does.
  const walk = chainToAnchor(cert, [...intermediates, ...anchors], anchors);
  const link = findIssuer(cert, [...intermediates, ...anchors]);
  if (!walk.ok) {
    checks.issuer = {
      ok: !!link && link.isCa,
      detail: walk.reason,
    };
    // Reported separately so a reader learns WHICH of the two went wrong:
    // "claims an issuer you accept" and "and the signature holds" fail for
    // different reasons and need different responses.
    checks.signature = link && link.verified
      ? { ok: true, detail: `the signature verifies under ${link.issuer.subject}'s key, but the chain was not accepted` }
      : { ok: false, detail: link
        ? `the document's signature does NOT verify under ${link.issuer.subject}'s key`
        : 'not evaluated: no issuer among the supplied anchors' };
    return no(`the attestation does not chain to a provider root the reader accepts: ${walk.reason}`);
  }
  const anchor = walk.chain[walk.chain.length - 1];
  checks.issuer = {
    ok: true,
    detail: walk.pinned
      ? `this document's exact bytes were pinned by the reader`
      : `chains to ${anchor?.subject}, an anchor this reader supplied, through `
        + `${walk.chain.length - 1} certificate authority link(s)`,
  };
  checks.signature = { ok: true, detail: 'every link in the chain verifies, including this document' };

  // 3 — the attested key is this epoch's key.
  if (!opts.epochPublicKey) {
    checks.key_identity = {
      ok: false,
      detail: 'no epoch public key was supplied, so it cannot be established that this document '
        + 'attests the key that signed these checkpoints rather than another key in the same account',
    };
  } else if (!attested.equals(Buffer.from(opts.epochPublicKey))) {
    checks.key_identity = {
      ok: false,
      detail: 'this document attests another key, not the key that signed this epoch. A provider '
        + 'will attest any key the account holds; that it attested one is not that it attested this one',
    };
  } else {
    checks.key_identity = { ok: true, detail: "the attested key is this epoch's signing key" };
  }

  // 4 — applicability.
  const span = opts.epochSpan;
  const from = cert.validFromDate ?? new Date(cert.validFrom);
  const to = cert.validToDate ?? new Date(cert.validTo);
  if (!span) {
    checks.epoch_applicability = {
      ok: false,
      detail: 'no epoch span was supplied, so whether this document covers the period the epoch '
        + 'spans cannot be judged',
    };
  } else if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    checks.epoch_applicability = { ok: false, detail: "the document's validity period is unreadable" };
  } else if (from > span.from) {
    checks.epoch_applicability = {
      ok: false,
      detail: `the document is valid from ${from.toISOString()}, after the epoch begins at `
        + `${span.from.toISOString()}: an attestation issued after the fact says nothing about `
        + 'signatures made before it',
    };
  } else if (to < span.to) {
    checks.epoch_applicability = {
      ok: false,
      detail: `the document expires at ${to.toISOString()}, before the epoch ends at `
        + `${span.to.toISOString()}, so it does not cover the whole epoch. Partial cover is not `
        + 'cover: signatures from the uncovered part would be reported on the strength of an '
        + 'expired document',
    };
  } else {
    checks.epoch_applicability = {
      ok: true,
      detail: `the document covers ${span.from.toISOString()} to ${span.to.toISOString()}`,
    };
  }

  // 5 — custody properties.
  const required = opts.requireProperties ?? ['non_exportable'];
  if (required.length === 0) {
    checks.custody_properties = {
      ok: true,
      detail: 'no custody properties were required: the reader waived this check, so support here '
        + 'rests on their judgement rather than on the document asserting non-exportability',
    };
  } else {
    // Reading the extension's VALUE, not merely looking for its OID in the
    // certificate's bytes. The containment test it replaces reported "the
    // document asserts non-exportability" for a document that asserted the
    // opposite, and would also have been satisfied by the OID appearing in a
    // subject name or inside another extension's value.
    /** @type {string[]} */
    const problems = [];
    for (const name of required) {
      const oid = CUSTODY_PROPERTY_OIDS[/** @type {keyof typeof CUSTODY_PROPERTY_OIDS} */ (name)];
      if (!oid) {
        problems.push(`${name} is not a property this verifier knows how to read`);
        continue;
      }
      const state = readBooleanExtension(cert, oid);
      if (state === 'true') continue;
      problems.push(
        state === 'false' ? `the document asserts ${name} is FALSE`
          : state === 'absent' ? `the document does not assert ${name}`
            : `the document's ${name} extension is not a readable BOOLEAN`,
      );
    }
    checks.custody_properties = problems.length === 0
      ? { ok: true, detail: `the document asserts ${required.join(', ')}` }
      : {
        ok: false,
        detail: `${problems.join('; ')}. A certificate proving a key exists in a managed service is `
          + 'not a custody guarantee: a key that could be exported is a managed key, and accepting '
          + 'its existence certificate would launder the weaker claim into the stronger one',
      };
  }

  const supported = ATTESTATION_CHECKS.every(c => /** @type {Check} */ (checks[c]).ok);
  return {
    supported,
    inconclusive: false,
    detail: supported
      ? 'all five FR-70 checks pass, so custody may be reported as independently supported for this '
        + 'epoch. It still does not establish destruction: non-exportability says the key could not '
        + 'leave the module, not that a retired key was deleted — that stays operator-declared. And '
        + 'this validator has only ever been run against constructed documents, because no cloud '
        + 'path issues an Ed25519 attestation (DES-06)'
      : 'this attestation does not support a custody claim: '
        + ATTESTATION_CHECKS.filter(c => !(/** @type {Check} */ (checks[c]).ok))
          .map(c => `${c} — ${/** @type {Check} */ (checks[c]).detail}`).join('; '),
    checks,
    establishes_destruction: /** @type {false} */ (false),
    // Set on every result, passing or failing. A reader of the report should
    // not have to find DES-06 to learn that no provider document has ever been
    // put through this.
    provider_untested: true,
    attested_key: attested.toString('base64'),
  };
}
