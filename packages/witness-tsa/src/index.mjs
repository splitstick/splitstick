/**
 * The RFC 3161 witness adapter — FR-16, FR-21, FR-48, PRIV-01, SEC-15.
 *
 * Submission only. Verification lives in `@splitstick/core/rfc3161` because it
 * is pure computation that the offline verifier needs; this package is where
 * the HTTP goes, so that `@splitstick/verify` never acquires a network client
 * in its dependency closure (NFR-05, NFR-06). The split is the point of having
 * two packages rather than one.
 *
 * What leaves the host is a `TimeStampReq`: a version, an algorithm identifier,
 * 32 bytes of SHA-256, and a `certReq` flag. No tool name, no arguments, no
 * result, no salt, no note text — not even the note, only its digest. There is
 * nothing in the request to redact because there is nothing in it, which is
 * what makes a TSA usable from a regulated account and what the egress test
 * asserts against the fixture strings rather than by inspection.
 *
 * What a TSA gives back, and what it does not: a signature and an independent
 * clock, per batch. No retention, no enumeration, and NO SEQUENCE MEMORY. It
 * signs your hash and forgets you, so it cannot tell you that a checkpoint it
 * signed last week is missing from the log you show it today. That is why
 * DES-08 says the shipped default closes attack classes 1, 2, 3, 6 and 7 and
 * not 4 and 5, and why `establishes` here is `['time']` and nothing more.
 */

import { timeStampRequest, verifyTimeStampToken } from '@splitstick/core/rfc3161';
import { readOnly, children, readInteger, TAG } from '@splitstick/core/der';

export class TsaError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'TsaError'; }
}

const CONTENT_TYPE_REQ = 'application/timestamp-query';
const CONTENT_TYPE_RES = 'application/timestamp-reply';

/**
 * RFC 3161 2.4.2 — PKIStatus. Anything but granted or grantedWithMods means the
 * TSA declined, and the reason is worth surfacing verbatim rather than
 * collapsing into "failed".
 */
const STATUS = Object.freeze({
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification',
});

/**
 * @param {object} o
 * @param {string} o.id the issuer identity, which is what a quorum counts
 * @param {string} o.url the TSA endpoint
 * @param {string[]} [o.anchors] PEM trust anchors. Supplied here ONLY so the
 *   adapter can refuse a token it can already tell is unusable; the reader's
 *   acceptance policy is what decides trust at verification time (FR-30).
 * @param {boolean} [o.qualified] LEG-13 — the operator declaring this TSA a
 *   qualified trust service under eIDAS. A declaration, never a verification.
 * @param {number} [o.timeout_ms]
 * @param {typeof globalThis.fetch} [o.fetchImpl] injected for tests, so the
 *   adapter's own tests never make a network call
 * @returns {import('@splitstick/core/anchor').WitnessAdapter}
 */
export function tsaWitness({ id, url, anchors = [], timeout_ms = 10_000, fetchImpl, qualified = false }) {
  if (typeof id !== 'string' || !id) throw new TsaError('a witness needs an id');
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    throw new TsaError(`${JSON.stringify(url)} is not an http(s) TSA endpoint`);
  }
  const doFetch = fetchImpl ?? globalThis.fetch;

  return {
    id,
    proof_type: 'rfc3161',
    // Time, and only time. See the module comment: a TSA has no sequence memory
    // and declaring otherwise here would make the verifier's capability
    // statement a lie by configuration.
    establishes: ['time'],
    tier: 'anchor',
    // LEG-13 — the operator saying this endpoint is a qualified trust service
    // under eIDAS. A DECLARATION, carried so the deployment can be described
    // and audited, and never a verification: the EU trusted list is not
    // reachable from here and NFR-05 says it never will be. Nothing in the
    // report rests on this flag; the Art. 41 statement rests on the READER's
    // policy, because the presumption is a conclusion the reader draws.
    qualified,

    /**
     * @param {string} note
     * @returns {Promise<import('@splitstick/core/envelope').Countersignature>}
     */
    async submit(note) {
      const { createHash } = await import('node:crypto');
      const imprint = createHash('sha256').update(Buffer.from(note, 'utf8')).digest();
      const body = timeStampRequest(imprint);

      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeout_ms);
      timer.unref?.();
      /** @type {Response} */
      let res;
      try {
        res = await doFetch(url, {
          method: 'POST',
          headers: { 'content-type': CONTENT_TYPE_REQ, accept: CONTENT_TYPE_RES },
          body,
          signal: ac.signal,
        });
      } catch (e) {
        throw new TsaError(`${id} was unreachable: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        clearTimeout(timer);
      }
      if (!res.ok) throw new TsaError(`${id} returned HTTP ${res.status}`);
      const der = Buffer.from(await res.arrayBuffer());
      const token = extractToken(der, id);

      // Checked here as well as at verification time. The adapter holds the
      // imprint it just submitted, so it is the only place that can catch a TSA
      // returning a token over something else — and storing such a token would
      // put a proof in the evidence that fails an auditor's check months later.
      const r = await verifyTimeStampToken(token, { imprint, anchors });
      if (!r.ok && !r.inconclusive) {
        throw new TsaError(`${id} returned a token that does not verify: ${r.detail}`);
      }
      return {
        type: 'rfc3161',
        issuer: id,
        covers: 'note_digest',
        token: token.toString('base64'),
      };
    },
  };
}

/**
 * A TSA may return a bare `TimeStampToken` or a `TimeStampResp` wrapping one.
 * Both are seen in the wild, and guessing wrong looks like a malformed token.
 * @param {Buffer} der @param {string} id @returns {Buffer}
 */
function extractToken(der, id) {
  // A TimeStampResp is SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }, so
  // its first child is a SEQUENCE; a bare token's first child is an OID
  // (the ContentInfo contentType).
  /** @type {ReturnType<typeof readOnly>} */
  let top;
  try {
    top = readOnly(der, TAG.SEQUENCE);
  } catch (e) {
    throw new TsaError(`${id} returned bytes that are not DER: ${e instanceof Error ? e.message : String(e)}`);
  }
  const kids = children(top.value);
  const first = kids[0];
  if (!first) throw new TsaError(`${id} returned an empty response`);
  if (first.tag === TAG.OID) return der;        // already a bare token

  if (first.tag !== TAG.SEQUENCE) throw new TsaError(`${id} returned an unrecognised response`);
  const statusKids = children(first.value);
  const statusTlv = statusKids[0];
  const status = statusTlv ? Number(readInteger(statusTlv.value)) : -1;
  const tokenTlv = kids[1];
  if (status !== 0 && status !== 1) {
    throw new TsaError(
      `${id} declined: PKIStatus ${status} (${STATUS[/** @type {keyof typeof STATUS} */ (status)] ?? 'unknown'})`,
    );
  }
  if (!tokenTlv) throw new TsaError(`${id} granted the request but returned no token`);
  return Buffer.from(tokenTlv.der);
}
