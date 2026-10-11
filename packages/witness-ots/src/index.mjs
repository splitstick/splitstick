/**
 * The OpenTimestamps witness adapter — FR-22, FR-48, FR-53, PRIV-01.
 *
 * The hard tier. Its guarantee is the only one in this design that does not
 * rest on an organisation continuing to behave: a TSA can be compelled, lose
 * its key or go out of business, and a transparency log operator can be
 * replaced, but a Bitcoin block header cannot be un-mined by the operator, by
 * us, or by anyone the operator can reach.
 *
 * It runs on the ROLL-UP tier, never per batch. A calendar submission every ten
 * seconds is not acceptable use of a public good, and FR-48 makes that an
 * explicit property of the shipped default rather than an operator's problem to
 * discover.
 *
 * What leaves the host is 32 bytes. A calendar is handed the digest and nothing
 * else — it never learns the note, the origin, or that Splitstick is involved.
 *
 * What comes back is usually PENDING: the calendar holds the digest but it is
 * not yet in a block, which is the ordinary state for the first hour or so. The
 * adapter stores the pending proof, because that is the receipt that the
 * submission happened, and a later upgrade replaces it with one that reaches a
 * block.
 */

import { describeOtsProof, parseOtsProof, FILE_MAGIC } from '@splitstick/core/opentimestamps';

export class OtsWitnessError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'OtsWitnessError'; }
}

/**
 * @param {object} o
 * @param {string} [o.id]
 * @param {string[]} o.calendars calendar base URLs
 * @param {number} [o.timeout_ms]
 * @param {typeof globalThis.fetch} [o.fetchImpl]
 * @returns {import('@splitstick/core/anchor').WitnessAdapter}
 */
export function otsWitness({ id = 'bitcoin', calendars, timeout_ms = 15_000, fetchImpl }) {
  if (!Array.isArray(calendars) || calendars.length === 0) {
    throw new OtsWitnessError('at least one calendar URL is required');
  }
  for (const u of calendars) {
    if (typeof u !== 'string' || !/^https?:\/\//.test(u)) {
      throw new OtsWitnessError(`${JSON.stringify(u)} is not an http(s) calendar URL`);
    }
  }
  const doFetch = fetchImpl ?? globalThis.fetch;

  return {
    id,
    proof_type: 'opentimestamps',
    // Existence, and only existence. No clock discipline to surface (SEC-25)
    // and no sequence memory: a calendar does not remember your heights.
    establishes: ['existence'],
    // FR-22 and FR-48: the hard tier is the slow tier, by design and not by
    // configuration accident.
    tier: 'rollup',

    /**
     * @param {string} note
     * @returns {Promise<import('@splitstick/core/envelope').Countersignature>}
     */
    async submit(note) {
      const { createHash } = await import('node:crypto');
      const digest = createHash('sha256').update(Buffer.from(note, 'utf8')).digest();

      /** @type {string[]} */
      const failures = [];
      for (const base of calendars) {
        const url = `${base.replace(/\/$/, '')}/digest`;
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), timeout_ms);
        timer.unref?.();
        try {
          const res = await doFetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/vnd.opentimestamps.v1', accept: 'application/vnd.opentimestamps.v1' },
            body: digest,
            signal: ac.signal,
          });
          if (!res.ok) {
            failures.push(`${base} returned HTTP ${res.status}`);
            continue;
          }
          const body = Buffer.from(await res.arrayBuffer());
          // A calendar returns a bare timestamp, not a complete file. Wrapping
          // it here means the stored proof is self-describing, so a reader does
          // not need to know which calendar it came from to parse it.
          const proof = completeProof(digest, body);
          const described = describeOtsProof(proof, { imprint: digest });
          if (described.malformed) {
            failures.push(`${base} returned a proof that does not parse: ${described.detail}`);
            continue;
          }
          return {
            type: 'opentimestamps',
            issuer: id,
            covers: 'note_digest',
            proof: proof.toString('base64'),
          };
        } catch (e) {
          failures.push(`${base}: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
          clearTimeout(timer);
        }
      }
      throw new OtsWitnessError(
        `no calendar accepted the submission: ${failures.join('; ')}`,
      );
    },
  };
}

/**
 * Wrap a calendar's bare timestamp in the complete-file framing.
 * @param {Buffer} digest @param {Buffer} timestamp
 * @returns {Buffer}
 */
function completeProof(digest, timestamp) {
  const out = Buffer.concat([FILE_MAGIC, Buffer.from([1, 0x08]), digest, timestamp]);
  // Parsed before returning, so a proof that cannot be read is never stored as
  // though it were evidence.
  parseOtsProof(out, { expectDigest: digest });
  return out;
}
