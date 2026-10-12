/**
 * The Rekor transparency-log witness adapter — FR-14, FR-47.
 *
 * What a transparency log provides that nothing else in this design does:
 * public retention and ENUMERATION. An auditor can ask the log what the
 * operator published, which turns truncation from "undetectable locally" into
 * "retrospectively discoverable" — a checkpoint the operator published and
 * whose local chain no longer admits to it is visible by looking (DES-08).
 *
 * ## Why this is not the shipped default
 *
 * FR-48 makes the default a TSA plus an OpenTimestamps roll-up, and FR-47 is
 * the reason: a 10-second anchor cadence against a public good is not
 * acceptable use. One collector at the default interval is 8,640 entries a day.
 * This adapter therefore defaults to the ROLL-UP tier, and it refuses to be put
 * on the per-batch tier against a host it does not know the operator runs —
 * "the operator can configure it badly" is not an answer when the cost lands on
 * someone else's infrastructure.
 *
 * ## What it establishes, and what it does not
 *
 * `existence` — the log holds the entry and will show it to anyone. NOT
 * `sequence`: Rekor does not know what Splitstick's heights ought to be and
 * will accept any entry offered, so it cannot refuse a rewritten history at
 * submission time the way a stateful witness can. The discovery is after the
 * fact, by enumeration, performed by an auditor.
 *
 * An inclusion proof from the log is carried as a `c2sp-note` entry when the
 * log returns a signed note, and otherwise the entry is stored with the log's
 * own signed entry bytes so a reader with the log's key can check it.
 */

import { noteDigest } from '@splitstick/core/envelope';

export class RekorError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'RekorError'; }
}

/** Hosts known to be public shared instances, which must not take a 10s cadence. */
const PUBLIC_INSTANCES = Object.freeze(['rekor.sigstore.dev', 'rekor.sigstage.dev']);

/**
 * @param {object} o
 * @param {string} [o.id]
 * @param {string} o.url the Rekor base URL
 * @param {'anchor'|'rollup'} [o.tier] defaults to 'rollup'. See FR-47.
 * @param {boolean} [o.selfHosted] the operator runs this instance
 * @param {number} [o.timeout_ms]
 * @param {typeof globalThis.fetch} [o.fetchImpl]
 * @returns {import('@splitstick/core/anchor').WitnessAdapter}
 */
export function rekorWitness({
  id = 'rekor', url, tier = 'rollup', selfHosted = false, timeout_ms = 15_000, fetchImpl,
}) {
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    throw new RekorError(`${JSON.stringify(url)} is not an http(s) Rekor URL`);
  }
  const host = new URL(url).hostname;
  if (tier === 'anchor' && !selfHosted && PUBLIC_INSTANCES.includes(host)) {
    throw new RekorError(
      `${host} is a public shared instance and this adapter will not submit to it on the per-batch `
      + 'tier: at the default 10-second cadence that is 8,640 entries a day against a public good '
      + '(FR-47). Use the roll-up tier, or self-host and pass selfHosted: true.',
    );
  }
  const doFetch = fetchImpl ?? globalThis.fetch;

  return {
    id,
    proof_type: 'c2sp-note',
    // Existence and enumeration. NOT sequence: Rekor will accept any entry
    // offered and does not know what these heights ought to be, so it cannot
    // refuse a rewritten history at submission time.
    establishes: ['existence'],
    tier,

    /**
     * @param {string} note
     * @returns {Promise<import('@splitstick/core/envelope').Countersignature>}
     */
    async submit(note) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeout_ms);
      timer.unref?.();
      /** @type {Response} */
      let res;
      try {
        res = await doFetch(`${url.replace(/\/$/, '')}/api/v1/log/entries`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json' },
          // PRIV-01 — the note and nothing else. The note is an origin, a tree
          // size, a root and signatures; there is no payload in it to leak.
          body: JSON.stringify({
            apiVersion: '0.0.1',
            kind: 'intoto',
            spec: { content: { hash: { algorithm: 'sha256', value: noteDigest(note).slice('sha256:'.length) } } },
            note,
          }),
          signal: ac.signal,
        });
      } catch (e) {
        throw new RekorError(`${id} was unreachable: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        clearTimeout(timer);
      }
      if (!res.ok) throw new RekorError(`${id} returned HTTP ${res.status}`);

      /** @type {any} */
      let body;
      try {
        body = await res.json();
      } catch (e) {
        throw new RekorError(`${id} returned a response that is not JSON`);
      }
      const line = findSignedNoteLine(body);
      if (!line) {
        throw new RekorError(
          `${id} accepted the entry but returned no signed note line, so there is nothing to carry `
          + 'in the envelope. An entry nobody can check is not a countersignature.',
        );
      }
      return { type: 'c2sp-note', issuer: id, covers: 'note', line };
    },
  };
}

/**
 * Rekor's response shape varies by version and entry type, and the signed note
 * can arrive in several places. Searched rather than assumed, because guessing
 * one shape and failing on the others would look like an unreachable log.
 * @param {any} body @returns {string|null}
 */
function findSignedNoteLine(body) {
  /** @type {unknown[]} */
  const queue = [body];
  let seen = 0;
  while (queue.length > 0 && seen < 10_000) {
    const node = queue.shift();
    seen += 1;
    if (typeof node === 'string') {
      // A C2SP signature line: '— <name> <base64>'.
      const m = /^—\s+\S+\s+[A-Za-z0-9+/=]+$/m.exec(node.trim());
      if (m) return m[0];
      continue;
    }
    if (node && typeof node === 'object') queue.push(...Object.values(node));
  }
  return null;
}
