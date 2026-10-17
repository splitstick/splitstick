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

import { noteKeyId, parseSignatureLine } from '@splitstick/core/note';

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
  /**
   * `root` is null against a conforming witness: the protocol's 409 body is
   * `<size>\n` and carries no root. It stays on the type because a witness MAY
   * send more, and because a caller that wants to re-prove needs the size,
   * which is the part that is always there. Null, not '': an empty string reads
   * as a root that was sent and was empty.
   *
   * @param {string} m @param {{ size: number, root: string|null }} view
   */
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
    // SEQUENCE and TIME. Sequence is the point of the adapter: the witness
    // holds state and refuses a history that does not extend what it already
    // signed.
    //
    // Time was added by FR-15, after running the real implementation. This
    // comment used to say a cosignature carries no time and that claiming
    // `time` would make the verifier's capability statement a lie — which was a
    // reading of our own document, not of c2sp.org/tlog-cosignature. A
    // cosignature/v1 signature covers `cosignature/v1\ntime <unix>\n<text>`, so
    // the witness's observation time is signed over the same message as the
    // root, by the same key the reader's policy names. It is not metadata
    // beside the proof; it is inside it.
    //
    // What it is NOT is a qualified timestamp: nothing here makes the witness's
    // clock trustworthy to a court, and the eIDAS Art. 41 presumption is
    // computed from the proof type elsewhere and is unaffected by this.
    establishes: ['sequence', 'time'],
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

      // The status map below is the REAL implementation's, read out of
      // transparency-dev/witness rather than inferred from the protocol
      // document. Three of these were wrong, and each wrong one turned a
      // specific, actionable condition into a generic failure.
      if (res.status === 409) {
        // `<size>\n` and NOTHING ELSE. This adapter used to parse
        // `<size>\n<root>\n` and silently kept root as an empty string — the
        // extra line exists only in OUR witness, which is where the assumption
        // came from. A conflict carries the size to re-prove from; the root is
        // not on offer, and pretending it was gave callers a blank.
        const size = Number(text.trim().split('\n')[0]);
        throw new TlogConflict(
          `${id} disagrees about the tree: it last cosigned size ${Number.isFinite(size) ? size : '?'}, `
          + `and this submission proved from ${ctx.old_size}. Re-prove from the size it remembers. A `
          + 'conflict is the witness WORKING — it is what refusing a rewritten history looks '
          + 'like, and it must not be recorded as the log being fine.',
          { size, root: null },
        );
      }
      if (res.status === 404) {
        // ErrUnknownLog. THIS is the unenrolled case, and this adapter had the
        // message on 403, where it told an operator whose SIGNATURE had failed
        // to go and enrol a key that was already enrolled.
        throw new TlogWitnessError(
          `${id} does not know this log (HTTP 404). The log's origin and public key have to be `
          + 'enrolled with the witness before it will cosign; this is not a transient failure and '
          + 'retrying will not fix it.',
        );
      }
      if (res.status === 403) {
        // ErrNoValidSignature — the witness knows the log and could not verify
        // the operator's own signature on the checkpoint it was handed.
        throw new TlogWitnessError(
          `${id} rejected the operator's signature on this checkpoint (HTTP 403). The witness knows `
          + "this log but the note's own signature did not verify under the key enrolled for it, so "
          + 'either the signing key has rotated without the witness being told, or the note was '
          + 'altered after signing. Retrying will not fix it.',
        );
      }
      if (res.status === 422) {
        // ErrInvalidProof or ErrRootMismatch. A REFUSAL, not an outage: the
        // witness is saying the proof does not carry its remembered root into
        // the one being claimed. Reported as a conflict-class failure rather
        // than a generic error, because folding it into "HTTP 422" loses the
        // one signal this whole witness class exists to produce.
        throw new TlogWitnessError(
          `${id} REFUSED this checkpoint (HTTP 422): the consistency proof did not carry the tree `
          + `it last cosigned into the one claimed here. This is the witness detecting that the `
          + 'history it was shown is not an extension of the history it already signed — it is '
          + 'the refusal this witness class exists for, and it must not be read as the witness '
          + 'being unavailable.',
        );
      }
      if (res.status === 429) {
        // ErrPushback. Transient, and the only status here that is.
        throw new TlogWitnessError(
          `${id} is rate-limiting submissions (HTTP 429). Unlike the other refusals this is `
          + 'transient: the same checkpoint and proof will be accepted later.',
        );
      }
      if (!res.ok) throw new TlogWitnessError(`${id} returned HTTP ${res.status}: ${text.slice(0, 200)}`);

      // The body is signature lines. Lines already in the note are discarded:
      // a witness returns its OWN cosignature, and echoing the operator's line
      // back as a countersignature would make the operator their own witness —
      // the defect this project has already had once, where presence was
      // counted as anchoring.
      const own = new Set(note.trimEnd().split('\n').filter(l => l.startsWith('— ')));
      const lines = text.trimEnd().split('\n')
        .map(l => l.trim())
        .filter(l => l.startsWith('— ') && !own.has(l));

      if (lines.length === 0) {
        throw new TlogWitnessError(
          `${id} returned no cosignature line of its own. ${text.trim() !== ''
            ? 'The body carried only lines already in the note, which would make the operator '
              + 'their own witness.'
            : `The body was ${JSON.stringify(text.slice(0, 120))}.`}`,
        );
      }
      // More than one, and this adapter will not choose. It used to take
      // `.at(-1)` — nothing makes the last line authoritative, and the others
      // were dropped in silence. A witness cosigning under two keys during a
      // rotation is a real case, and losing one of them quietly is losing
      // evidence; picking one fabricates a decision the adapter has no basis
      // for. The envelope carries one line per countersignature, so the honest
      // response is to say what arrived.
      if (lines.length > 1) {
        throw new TlogWitnessError(
          `${id} returned ${lines.length} cosignature lines and this adapter will not choose `
          + 'between them: nothing makes one of them the countersignature, and keeping one '
          + `silently would discard evidence. The lines were ${JSON.stringify(lines)}`,
        );
      }
      const line = /** @type {string} */ (lines[0]);

      // The line must be signed UNDER THE NAME this countersignature will be
      // attributed to. It is returned as `issuer: id`, and a line signed by
      // somebody else carried that label all the way into the envelope — so a
      // reader's policy for `id` was used to check a signature `id` never
      // made, and the result is a mismatch finding whose stated meaning is
      // "the operator rewrote history". A bad or hostile witness response
      // would have read as tampering by the operator.
      //
      // This checks the NAME only, which nothing here authenticates — the body
      // came from the witness. That is deliberate: the key is authenticated by
      // the READER's acceptance policy, which is where it belongs (FR-30), and
      // the adapter's whole job is to not mislabel what it hands over.
      const signedBy = /^— (\S+) /.exec(line)?.[1];
      if (signedBy !== id) {
        throw new TlogWitnessError(
          `${id} returned a cosignature signed under the name ${JSON.stringify(signedBy ?? '')}. `
          + `It is refused rather than attributed to ${id}: a line labelled with one identity and `
          + 'signed by another is checked against the wrong key by every reader, and reads as the '
          + 'operator having rewritten history rather than as a witness misbehaving.',
        );
      }

      // The witness's OWN observation time, out of the signature rather than
      // off our clock. A cosignature/v1 blob is keyId ‖ timestamp ‖ signature,
      // and the timestamp is inside the signed message — so recording it is
      // reporting what the witness asserted, not what we observed.
      //
      // This adapter used to record no time at all, on the stated grounds that
      // "the protocol gives the witness nowhere to put one". It does; we had
      // read our own document. Where the earlier reasoning still holds is in
      // what is NOT done here: our clock is never substituted when the
      // timestamp is absent, because a plain note signature really does carry
      // no time, and inventing one would attach a time to a proof that does
      // not cover it.
      let received_at;
      try {
        const sig = parseSignatureLine(line);
        if (sig.timestamp !== undefined) {
          received_at = new Date(Number(sig.timestamp) * 1000).toISOString();
        }
      } catch {
        // A line this adapter cannot parse is not a time it may guess at. The
        // cosignature is still returned: the READER verifies it, and a
        // malformed line must fail there as a signature rather than here as a
        // missing timestamp.
      }

      return {
        type: 'c2sp-note',
        issuer: id,
        covers: 'note',
        line,
        ...(received_at ? { received_at } : {}),
      };
    },
  };
}

export { noteKeyId };
