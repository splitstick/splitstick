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

import { timeStampRequest, verifyTimeStampToken, parseTimeStampToken } from '@splitstick/core/rfc3161';
import { readOnly, children, readInteger, readOid, TAG } from '@splitstick/core/der';

export class TsaError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'TsaError'; }
}

/**
 * Header names a custom auth header may not take.
 *
 * The auth headers are spread last over the request's own, so a custom header
 * named `content-type` replaced the RFC 3161 content type with the credential
 * -- the request stopped being a timestamp query, and the secret went into a
 * header the TSA logs. `authorization` is reserved too: an operator reaching
 * for it wants the bearer or basic scheme, and two mechanisms writing one
 * header is a silent precedence question nobody should have to reason about.
 */
const RESERVED_HEADERS = new Set([
  'content-type', 'accept', 'authorization', 'host', 'content-length',
]);

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
 * The ETSI statements that mark a QUALIFIED timestamp service, as DER OID
 * content bytes: id-etsi-qcs-QcCompliance 0.4.0.1862.1.1 and id-etsi-qct-qtst
 * 0.4.0.1862.1.6.3.
 *
 * Searched for in the signer certificate so that `qualified: true` -- which is
 * and remains an OPERATOR DECLARATION about a legal status this code cannot
 * adjudicate -- can be checked against what the certificate actually carries.
 *
 * The declaration is not overruled. Of nine free public RFC 3161 endpoints
 * surveyed for LEG-13, none was qualified while five belonged to companies
 * that ARE qualified trust service providers; Certum, for one, runs a free
 * BASIC endpoint next to its commercial qualified service. So pointing
 * `qualified: true` at a free endpoint is the expected mistake rather than an
 * exotic one, and it is a mistake with legal consequences: the verifier reports
 * the eIDAS Art. 41 presumption as attaching on the strength of that flag.
 *
 * Refusing outright was considered and rejected. These statements are defined
 * for certificates by ETSI EN 319 412-5 and this project cannot be certain
 * every genuinely qualified TSA's signer certificate carries them, so a refusal
 * would risk blocking a real qualified service on this project's incomplete
 * knowledge. What the adapter does instead is record what it saw, so the
 * mismatch travels with the proof and a reader is told rather than left to
 * assume.
 */
const OID_QC_STATEMENTS = '1.3.6.1.5.5.7.1.3';
const OID_QC_COMPLIANCE = '0.4.0.1862.1.1';
const OID_QC_TYPE = '0.4.0.1862.1.6';
const OID_QC_TYPE_QTST = '0.4.0.1862.1.6.3';

/**
 * The statement OIDs in a certificate's QCStatements extension, parsed
 * STRUCTURALLY — RFC 3739 §3.2.6, ETSI EN 319 412-5.
 *
 * The first version of this searched the certificate's raw DER for the OID
 * byte sequences. A review was right that this establishes only that the bytes
 * occur SOMEWHERE in the encoding: a serial number, a subject string or an
 * unrelated extension could contain them, and the result was being reported in
 * a field about qualified status. Finding a needle in a certificate is not the
 * same as the certificate making a statement.
 *
 * So the extension is located by OID among the extensions, its OCTET STRING is
 * parsed as `QCStatements ::= SEQUENCE OF QCStatement`, and the statementId of
 * each is read. The qcType statement (0.4.0.1862.1.6) carries its own SEQUENCE
 * OF OID, so `esi4-qtstStatement-1` (…1.6.3) is read from inside it rather
 * than matched as a loose string.
 *
 * Returns null when the certificate cannot be walked — unknown, which is not
 * the same as absent, and the caller reports it as unknown.
 *
 * @param {Buffer} der the signer certificate
 * @returns {{ compliance: boolean, qtst: boolean }|null}
 */
export function qcStatements(der) {
  try {
    const cert = readOnly(der, TAG.SEQUENCE);
    const tbs = children(cert.value)[0];
    if (!tbs || tbs.tag !== TAG.SEQUENCE) return null;
    // Extensions are [3] EXPLICIT, the last optional field of TBSCertificate.
    const extsHolder = children(tbs.value).find(c => c.tag === 0xa3);
    if (!extsHolder) return { compliance: false, qtst: false };
    const exts = children(extsHolder.value)[0];
    if (!exts || exts.tag !== TAG.SEQUENCE) return null;

    for (const ext of children(exts.value)) {
      if (ext.tag !== TAG.SEQUENCE) continue;
      const parts = children(ext.value);
      const idTlv = parts[0];
      if (!idTlv || idTlv.tag !== TAG.OID || readOid(idTlv.value) !== OID_QC_STATEMENTS) continue;
      // `critical` is optional, so extnValue is the last OCTET STRING.
      const extnValue = parts.filter(x => x.tag === TAG.OCTET_STRING).at(-1);
      if (!extnValue) return null;

      const statements = readOnly(extnValue.value, TAG.SEQUENCE);
      let compliance = false;
      let qtst = false;
      for (const st of children(statements.value)) {
        if (st.tag !== TAG.SEQUENCE) continue;
        const inner = children(st.value);
        const sid = inner[0];
        if (!sid || sid.tag !== TAG.OID) continue;
        const oid = readOid(sid.value);
        if (oid === OID_QC_COMPLIANCE) compliance = true;
        if (oid === OID_QC_TYPE) {
          // statementInfo for qcType is SEQUENCE OF OBJECT IDENTIFIER.
          const info = inner[1];
          if (info && info.tag === TAG.SEQUENCE) {
            for (const t of children(info.value)) {
              if (t.tag === TAG.OID && readOid(t.value) === OID_QC_TYPE_QTST) qtst = true;
            }
          }
        }
      }
      return { compliance, qtst };
    }
    // No QCStatements extension at all: a definite absence, not an unknown.
    return { compliance: false, qtst: false };
  } catch {
    return null;
  }
}

/**
 * The credential a commercial TSA needs, resolved from the ENVIRONMENT.
 *
 * LEG-13's surface. A qualified trust service is an audited, billable service,
 * so every provider meters it behind an account -- which the adapter could not
 * reach at all: the request's headers were hardcoded and the config builder
 * passed only id, url and qualified. An operator with an account had no way in.
 *
 * The configuration names WHERE the secret is, never what it is. `env` holds
 * the name of an environment variable; the value never appears in a config
 * file, in a store, in a result, or in this process's argv -- argv being
 * readable by every process on the machine through ps. That is the same
 * discipline bench/run-latency.mjs uses for a model provider's key, for the
 * same reason.
 *
 * @typedef {{ scheme: 'bearer'|'basic'|'header', env: string, header?: string }} TsaAuth
 */

/**
 * @param {TsaAuth} auth
 * @param {string} id
 * @returns {Record<string, string>}
 */
function authHeaders(auth, id) {
  // The SCHEME first. An unknown scheme is a malformed configuration whether or
  // not the secret happens to be set, and reporting the missing variable first
  // would send an operator looking for the wrong thing.
  if (!['bearer', 'basic', 'header'].includes(auth.scheme)) {
    throw new TsaError(
      `${id} declares auth scheme ${JSON.stringify(/** @type {any} */ (auth).scheme)}, which `
      + 'this adapter does not know. Refused rather than submitted anonymously: silently '
      + 'dropping a credential would look like an authentication failure at the TSA.');
  }
  const value = process.env[auth.env];
  if (typeof value !== 'string' || value === '') {
    throw new TsaError(
      `${id} is configured to authenticate with the environment variable ${auth.env}, and it is `
      + 'not set. The credential is read from the environment on purpose: a secret in a witness '
      + 'config file gets committed, and one on the command line is readable by every process on '
      + 'the machine. Set it, or remove the auth block to submit anonymously.');
  }
  switch (auth.scheme) {
    case 'bearer':
      return { authorization: `Bearer ${value}` };
    case 'basic':
      // The operator supplies `user:password`; this encodes it. Pre-encoding in
      // the environment would work too, but it reads as opaque and invites
      // somebody to double-encode it.
      if (!value.includes(':')) {
        throw new TsaError(
          `${id} uses basic authentication, so ${auth.env} must hold "user:password". The value `
          + 'present has no colon, and this adapter will not guess which half it is.');
      }
      return { authorization: `Basic ${Buffer.from(value, 'utf8').toString('base64')}` };
    case 'header': {
      if (typeof auth.header !== 'string' || auth.header === '') {
        throw new TsaError(`${id} uses header authentication but names no header`);
      }
      if (/[^A-Za-z0-9-]/.test(auth.header)) {
        // A header name is not a place to accept arbitrary bytes: a newline
        // here is request splitting.
        throw new TsaError(
          `${id}'s auth header name ${JSON.stringify(auth.header)} is not a valid header token`);
      }
      if (RESERVED_HEADERS.has(auth.header.toLowerCase())) {
        // The auth headers are spread LAST, so a custom header named
        // content-type replaced the RFC 3161 content type with the credential:
        // the request stopped being a timestamp query at all, and the secret
        // went into a header the TSA logs. Rejected rather than reordered,
        // because an operator who asked for a header named `authorization`
        // wants the bearer or basic scheme and should be told so.
        throw new TsaError(
          `${id}'s auth header may not be ${JSON.stringify(auth.header)}: it is part of the RFC `
          + `3161 request or is the authorization header. Reserved: `
          + `${[...RESERVED_HEADERS].join(', ')}. For authorization use scheme bearer or basic.`);
      }
      return { [auth.header.toLowerCase()]: value };
    }
    default:
      // Unreachable: the scheme was checked above. Kept so that adding a
      // scheme to the list without adding its branch fails loudly here rather
      // than returning no headers.
      throw new TsaError(`${id}: auth scheme ${auth.scheme} has no implementation`);
  }
}

/**
 * @param {object} o
 * @param {string} o.id the issuer identity, which is what a quorum counts
 * @param {string} o.url the TSA endpoint
 * @param {string[]} [o.anchors] PEM trust anchors. Supplied here ONLY so the
 *   adapter can refuse a token it can already tell is unusable; the reader's
 *   acceptance policy is what decides trust at verification time (FR-30).
 * @param {boolean} [o.qualified] LEG-13 — the operator declaring this TSA a
 *   qualified trust service under eIDAS. A declaration, never a verification.
 * @param {TsaAuth} [o.auth] LEG-13 — how to authenticate, for a commercial
 *   qualified service. Names an environment variable; never the secret itself.
 * @param {number} [o.timeout_ms]
 * @param {typeof globalThis.fetch} [o.fetchImpl] injected for tests, so the
 *   adapter's own tests never make a network call
 * @returns {import('@splitstick/core/anchor').WitnessAdapter}
 */
export function tsaWitness({
  id, url, anchors = [], timeout_ms = 10_000, fetchImpl, qualified = false, auth,
}) {
  if (typeof id !== 'string' || !id) throw new TsaError('a witness needs an id');
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    throw new TsaError(`${JSON.stringify(url)} is not an http(s) TSA endpoint`);
  }
  // A CREDENTIAL MAY NOT TRAVEL OVER CLEARTEXT.
  //
  // An anonymous TSA request carries nothing worth protecting -- a version, an
  // algorithm identifier and 32 bytes of hash -- so plain HTTP has always been
  // allowed for it. A credential is different in kind, and basic auth in
  // particular is base64, which is an encoding and not encryption. An operator
  // mistyping http:// for a commercial endpoint would have put a bearer token
  // on the wire in the clear, and this adapter would have sent it.
  //
  // Refused at CONSTRUCTION, before any network call, so a misconfiguration
  // cannot leak once and then be fixed. Loopback is the one exception, for a
  // local test server, and it is narrow by hostname rather than by a substring
  // match on the URL -- "http://127.0.0.1.evil.example/" must not qualify.
  if (auth) {
    let host = null;
    try { host = new URL(url).hostname.replace(/^\[|\]$/g, ''); } catch { host = null; }
    const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
    if (!url.startsWith('https://') && !loopback) {
      throw new TsaError(
        `${id} is configured with a credential and a plain-HTTP endpoint (${url}). Refused before `
        + 'any request: a bearer token or basic credential on the wire in the clear is readable by '
        + 'anything on the path, and basic auth is base64, which is an encoding and not '
        + 'encryption. Use https://, or a loopback address for a local test server.');
    }
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

      // BEFORE the try below. A credential problem is a configuration error, and
      // the catch around doFetch reports "was unreachable" -- which sent an
      // operator with an unset variable to check their network. A misdiagnosis
      // is worse than a bare error: it is a confident answer in the wrong
      // direction.
      const extraHeaders = auth ? authHeaders(auth, id) : {};

      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeout_ms);
      timer.unref?.();
      /** @type {Response} */
      let res;
      try {
        res = await doFetch(url, {
          method: 'POST',
          // A REDIRECT MUST NOT CARRY THE CREDENTIAL ONWARD. fetch strips
          // `authorization` across origins but not a custom header, so an
          // endpoint that redirects could collect an API key. With a credential
          // present a redirect is an error the operator should see and fix in
          // the URL, not something to follow quietly.
          ...(auth ? { redirect: /** @type {const} */ ('error') } : {}),
          headers: {
            'content-type': CONTENT_TYPE_REQ,
            accept: CONTENT_TYPE_RES,
            // Resolved per submission rather than once at construction, so a
            // rotated credential takes effect without rebuilding the witness
            // set, and so a missing one fails at the moment it is needed with
            // the variable's name in the message.
            ...extraHeaders,
          },
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
      // WHAT THE CERTIFICATE CARRIES, beside what the operator declared. Only
      // reported when `qualified` was declared: on an ordinary TSA the absence
      // of qualified statements is unremarkable and noting it would be noise.
      let qualifiedStatements;
      if (qualified) {
        /** @type {{ compliance: boolean, qtst: boolean }|null} */
        let found = null;
        try {
          found = qcStatements(Buffer.from(parseTimeStampToken(token).signerCertificate.raw));
        } catch {
          found = null;
        }
        // null is UNKNOWN, not false: a certificate this adapter could not walk
        // has not been shown to lack the statements.
        qualifiedStatements = {
          qc_compliance: found === null ? null : found.compliance,
          qc_qtst: found === null ? null : found.qtst,
          // Named so the field cannot be read as a verification of qualified
          // STATUS. It is what the certificate asserts about itself, parsed
          // structurally; qualified status lives on an EU Trusted List, which
          // NFR-05 forbids this code from consulting.
          basis: found === null
            ? 'the signer certificate could not be parsed for QCStatements'
            : 'QCStatements parsed from the signer certificate (RFC 3739 3.2.6); '
              + 'self-asserted, NOT checked against an EU Trusted List',
        };
        if (qualifiedStatements.qc_qtst === false) {
          // Loud, and not fatal. See QC_QTST's comment: the operator's
          // declaration about a legal status is not overruled by this
          // project's incomplete knowledge of certificate profiles.
          console.error(
            `  WARNING: ${id} is configured qualified: true, and its signer certificate carries no`
            + '\n  ETSI qualified-timestamp statement (id-etsi-qct-qtst). The eIDAS Art. 41'
            + '\n  presumption is reported on the strength of that declaration, so if this is a'
            + "\n  provider's FREE endpoint rather than its qualified service, the report will"
            + '\n  overstate what the proof establishes. Several qualified providers run both.',
          );
        }
      }

      return {
        type: 'rfc3161',
        issuer: id,
        covers: 'note_digest',
        token: token.toString('base64'),
        ...(qualifiedStatements ? { qualified_statements: qualifiedStatements } : {}),
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
