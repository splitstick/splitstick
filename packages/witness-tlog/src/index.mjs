// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * FR-15 — transparency-dev/witness, over the C2SP `tlog-witness` protocol.
 *
 * Why this witness and not another: it is the one that REFUSES. A TSA stamps
 * whatever digest it is handed and Rekor appends whatever entry it is offered,
 * so neither can tell a rewritten history from a new one — they establish time
 * and existence, never sequence. A tlog-witness remembers the size it last
 * cosigned and demands a consistency proof from that size, so an operator who
 * rewrote their own past cannot get a second signature over the replacement.
 * That is the only class of witness that detects the attack this whole system
 * exists for, and depending on a single implementation of it (our own) is what
 * FR-15 exists to end.
 *
 * ── What this adapter is, and what it is not ────────────────────────────────
 *
 * The wire format below is written to the published `tlog-witness` protocol:
 *
 *   POST <url>/add-checkpoint
 *   Content-Type: text/plain
 *
 *   old <size>\n
 *   <consistency proof hash, base64>\n        (zero or more, in order)
 *   \n
 *   <the signed checkpoint note>
 *
 *   200  the body is the cosignature line(s) to append to the note
 *   409  the witness disagrees about the size; the body is its own view, as
 *        `<size>\n<root base64>\n`, so the caller can re-prove from there
 *   403  the witness does not know this log's key
 *
 * INTEROPERABILITY WITH THE GO IMPLEMENTATION IS NOT YET ESTABLISHED. The
 * tests here drive a server built from @splitstick/witness-self, whose
 * semantics the published conformance suite checks independently — but a
 * server written against the same reading of the same document cannot discover
 * that the reading is wrong. M5 produced two verifier bugs of exactly that
 * shape, both from gaps in a spec this project wrote itself, and both found
 * only when something external was involved. FR-15's stated verify is "anchor
 * against a local instance"; until that has been run against the real binary
 * this adapter is a careful implementation of a document and is labelled as
 * one. docs/m6-follow-ups.md carries it.
 */

import { noteKeyId } from '@splitstick/core/note';

export class TlogWitnessError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'TlogWitnessError'; }
}

/**
 * Raised when the witness disagrees about the size, carrying its own view.
 *
 * A distinct type because the caller's response is different in kind: a
 * conflict is not a failure to reach the witness, it is the witness telling
 * you what it remembers, and the Anchorer can re-prove from there. Collapsing
 * it into a generic error would turn a recoverable disagreement into an
 * outage, and an outage into a gap in the coverage report.
 */
export class TlogConflict extends TlogWitnessError {
  /** @param {string} m @param {{ size: number, root: string }} view */
  constructor(m, view) {
    super(m);
    this.name = 'TlogConflict';
    this.size = view.size;
    this.root = view.root;
  }
}

/** The protocol's own path. Not configurable: a witness that served this at
 *  some other path would not be speaking the protocol. */
const PATH = '/add-checkpoint';

/**
 * @param {object} o
 * @param {string} o.id the issuer identity, which is what a quorum counts
 * @param {string} o.url the witness base URL
 * @param {'anchor'|'rollup'} [o.tier]
 * @param {number} [o.timeout_ms]
 * @param {typeof globalThis.fetch} [o.fetchImpl] injected for tests, so the
 *   suite never depends on a network being there
 * @returns {import('@splitstick/core/anchor').WitnessAdapter}
 */
export function tlogWitness({ id, url, tier = 'anchor', timeout_ms = 10_000, fetchImpl }) {
  if (typeof id !== 'string' || !id) throw new TlogWitnessError('a witness needs an id');
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    throw new TlogWitnessError(`${JSON.stringify(url)} is not an http(s) witness URL`);
  }
  const doFetch = fetchImpl ?? globalThis.fetch;
  const base = url.replace(/\/$/, '');

  return {
    id,
    proof_type: 'c2sp-note',
    // SEQUENCE. This is the point of the adapter: the witness holds state and
    // refuses a history that does not extend what it already signed. It says
    // nothing about WHEN — a cosignature carries no time inside the note, and
    // claiming `time` here would make the verifier's capability statement a
    // lie by configuration, the same way it would for a TSA claiming sequence.
    establishes: ['sequence'],
    tier,

    /**
     * @param {string} note
     * @param {{ old_size: number, consistency_proof: string[] }} ctx
     * @returns {Promise<import('@splitstick/core/envelope').Countersignature>}
     */
    async submit(note, ctx) {
      // The proof is the caller's, computed over the operator's own tree. It
      // is sent as given: recomputing it here would be this adapter proving a
      // claim to itself.
      const body = `old ${ctx.old_size}\n${ctx.consistency_proof.join('\n')}`
        + `${ctx.consistency_proof.length > 0 ? '\n' : ''}\n${note}`;

      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeout_ms);
      timer.unref?.();
      /** @type {Response} */
      let res;
      try {
        res = await doFetch(`${base}${PATH}`, {
          method: 'POST',
          // PRIV-01 — the note and the proof, and nothing else. A note is an
          // origin, a size, a root and signatures; there is no payload in it.
          headers: { 'content-type': 'text/plain' },
          body,
          signal: ac.signal,
        });
      } catch (e) {
        throw new TlogWitnessError(
          `${id} was unreachable: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        clearTimeout(timer);
      }

      const text = await res.text();

      if (res.status === 409) {
        const [size, root] = text.trim().split('\n');
        throw new TlogConflict(
          `${id} disagrees about the tree: it last cosigned size ${size ?? '?'}, and this `
          + `submission proved from ${ctx.old_size}. Re-prove from the size it remembers. A `
          + 'conflict is the witness WORKING — it is what refusing a rewritten history looks '
          + 'like, and it must not be recorded as the log being fine.',
          { size: Number(size ?? NaN), root: String(root ?? '') },
        );
      }
      if (res.status === 403) {
        throw new TlogWitnessError(
          `${id} does not know this log's key (HTTP 403). The operator identity has to be enrolled `
          + 'with the witness before it will cosign; this is not a transient failure and retrying '
          + 'will not fix it.',
        );
      }
      if (!res.ok) throw new TlogWitnessError(`${id} returned HTTP ${res.status}: ${text.slice(0, 200)}`);

      // The body is signature lines. Take the LAST one that is a signature
      // line and is not already in the note: a witness returns its own
      // cosignature, and echoing the operator's line back as a
      // countersignature would make the operator their own witness — the
      // defect this project has already had once, where presence was counted
      // as anchoring.
      const own = new Set(note.trimEnd().split('\n').filter(l => l.startsWith('— ')));
      const lines = text.trimEnd().split('\n')
        .map(l => l.trim())
        .filter(l => l.startsWith('— ') && !own.has(l));
      const line = lines.at(-1);
      if (line === undefined) {
        throw new TlogWitnessError(
          `${id} returned no cosignature line of its own. ${lines.length === 0 && text.trim() !== ''
            ? 'The body carried only lines already in the note, which would make the operator '
              + 'their own witness.'
            : `The body was ${JSON.stringify(text.slice(0, 120))}.`}`,
        );
      }

      return {
        type: 'c2sp-note',
        issuer: id,
        covers: 'note',
        line,
        // No received_at. The protocol gives the witness nowhere to put one,
        // and inventing the submission time here would record OUR clock as the
        // witness's observation — a time the witness never asserted, attached
        // to a proof that does not cover it.
      };
    },
  };
}

export { noteKeyId };
