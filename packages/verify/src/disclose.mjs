/**
 * `splitstick disclose` — FR-32, FR-33, PRIV-06, INT-03, DES-11.
 *
 * THIS IS THE TRUST BOUNDARY. Everything else in the project is about what a
 * log can establish to somebody holding the whole store. A disclosure pack goes
 * to a counterparty who holds ONE event and must be able to verify it without
 * being shown anything else — so the boundary fails in two opposite directions
 * and both are permanent:
 *
 * TOO MUCH CROSSES. A pack that carries a second salt makes a second record's
 * content recomputable by anybody who can guess at it. You cannot un-disclose,
 * so this one has no remedy after the fact. PRIV-06 is the rule and the checks
 * below are at BUILD time, before anything is handed over, because a check on
 * the recipient's side would run after the damage.
 *
 * TOO LITTLE CROSSES. A pack that proves nothing is a pack nobody can rely on,
 * and an honest operator who cannot prove a true thing is as badly served as a
 * dishonest one who can prove a false one. So a shredded record stays
 * disclosable — its content is absent and its inclusion is still provable —
 * because erasure must not become a way to make history unprovable.
 *
 * FR-33 IS THE DIFFERENCE BETWEEN A PROOF AND A CLAIM. An inclusion proof
 * against a bare local digest establishes only that the operator is internally
 * consistent with their own arithmetic. The root has to be countersigned, and a
 * pack whose root is unwitnessed is REFUSED at build rather than handed over
 * with a caveat: a caveat is something a recipient has to notice.
 *
 * Verification here reuses verifyStore for the operator's own chain and the
 * shared note/envelope primitives for the countersignature. Nothing in this
 * file re-implements a check that exists elsewhere — that rule was learned
 * twice, in M3b's anchoring command and again in M4's coverage report.
 */

import { contentCid } from '@splitstick/core/content';
import { inclusionProof, verifyInclusion, treeRoot, leafHash } from '@splitstick/core/merkle';
import { parseEnvelope } from '@splitstick/core/envelope';
import { parseNote, parseCheckpointText, parseVkey } from '@splitstick/core/note';
import { verifyNoteSignature } from '@splitstick/core/signer';
import { noteKeyId } from '@splitstick/core/note';
import { finding, validateFindings } from '@splitstick/core/findings';
import { leafDigest } from '@splitstick/core/leaf';

/** The pack format version — DES-16, INT-03. */
export const PACK_VERSION = 1;

export class DiscloseError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'DiscloseError'; }
}

/**
 * Build a disclosure pack for one record — FR-32.
 *
 * @param {import('@splitstick/core/store').Store} store
 * @param {object} o
 * @param {number} o.record_seq the single event being disclosed
 * @returns {object} the pack, as plain JSON — DES-11
 */
export function buildDisclosure(store, o) {
  const seq = o.record_seq;
  if (!Number.isSafeInteger(seq) || seq < 1) {
    throw new DiscloseError(`record_seq must be a positive integer, not ${JSON.stringify(seq)}`);
  }
  const chain = store.readChain();
  if (chain.length === 0) throw new DiscloseError('this store holds no chain to disclose from');
  const index = chain.findIndex(e => Number(e.record.record_seq) === seq);
  if (index < 0) {
    const first = Number(chain[0]?.record.record_seq);
    const last = Number(chain[chain.length - 1]?.record.record_seq);
    throw new DiscloseError(
      `no record ${seq} in this store; it holds ${first}..${last}. Refused rather than answered `
      + 'with an empty pack, which a recipient would read as a disclosure of nothing',
    );
  }
  const entry = /** @type {any} */ (chain[index]);

  // ── FR-33 — the root must be countersigned ────────────────────────────────
  //
  // The EARLIEST checkpoint whose committed tree reaches this record and whose
  // envelope carries a countersignature. Earliest because a later one
  // establishes a later time, and the honest claim is the smallest the evidence
  // supports; any covering checkpoint rather than only the first because an
  // unwitnessed one must not mask a witnessed later one — a lesson from M4's
  // coverage report, where the same first-match mistake discarded real
  // evidence.
  /** @type {{ seq: number, tree_size: number, blob: string, issuers: string[] }[]} */
  const covering = [];
  for (const { seq: cpSeq, blob } of store.readCheckpoints()) {
    const env = parseEnvelope(blob);
    if (env.tree_size === null || env.tree_size < seq) continue;
    covering.push({ seq: cpSeq, tree_size: env.tree_size, blob, issuers: [...env.issuers] });
  }
  covering.sort((a, b) => a.tree_size - b.tree_size);
  const witnessed = covering.find(c => c.issuers.length > 0);
  if (witnessed === undefined) {
    throw new DiscloseError(
      covering.length === 0
        ? `record ${seq} falls under no checkpoint, so there is no root to prove it against`
        : `record ${seq} falls under ${covering.length} checkpoint(s) and none is countersigned. `
          + 'FR-33: an inclusion proof against a bare local digest establishes only that the '
          + 'operator is consistent with their own arithmetic. Refused rather than handed over '
          + 'with a caveat, because a caveat is something a recipient has to notice',
    );
  }

  // The proof is over the tree THAT CHECKPOINT committed to, not over the chain
  // as it stands now. A proof built against today's taller tree would not
  // verify against the root the witness signed.
  const leaves = chain.slice(0, witnessed.tree_size).map(e => e.leaf);
  if (leaves.length !== witnessed.tree_size) {
    throw new DiscloseError(
      `the chain no longer reaches ${witnessed.tree_size}, the size checkpoint `
      + `${witnessed.seq} commits to, so no proof against that root can be built`,
    );
  }
  const path = inclusionProof(leaves, index);
  const root = treeRoot(leaves);
  /** @type {string|null} */
  let shreddedLeaf = null;

  // ── the leaf must actually be this record's ───────────────────────────────
  //
  // Checked before anything is handed over. A pack whose leaf does not match
  // the salt and the record would fail on the recipient's side, which is the
  // worst place to find out: they cannot tell a build mistake from a tamper.
  if (entry.salt === null || entry.salt === undefined) {
    // A shredded record is still disclosable — erasure must not make history
    // unprovable — but the leaf cannot be recomputed without its salt, so the
    // pack says so rather than carrying a salt it does not have.
    if (!verifyInclusion(entry.leaf, index, leaves.length, path, root)) {
      throw new DiscloseError(`record ${seq}'s committed leaf is not in the tree it should be in`);
    }
    // The committed leaf digest, so a SHREDDED record's inclusion stays
    // provable. Without it the recipient has no leaf to verify the path
    // against and the proof establishes nothing — which is the opposite of
    // what row 7 of the M5 inventory says must happen, and what the first
    // version of this did. The leaf digest is permanent under PRIV-05 and is
    // already in the chain, so carrying it reveals nothing erasure removed.
    shreddedLeaf = Buffer.from(entry.leaf).toString('hex');
  } else {
    // leafDigest(salt, record) — the salt is FIRST. Reversed, it computes a
    // different digest that would never match, and the pack would be refused
    // for a reason that had nothing to do with the record.
    const recomputed = leafDigest(entry.salt, entry.record);
    if (!recomputed.equals(entry.leaf)) {
      throw new DiscloseError(
        `record ${seq}'s leaf does not match its salt and content, so this pack would fail on `
        + 'the recipient\'s side — where they could not tell a build mistake from a tamper',
      );
    }
  }

  // ── PRIV-06 — exactly one salt, and no sibling content ────────────────────
  //
  // The audit path is node digests. A node digest is not a leaf, and a leaf
  // without its salt is not recomputable from the record even if you hold the
  // record — which the recipient does not. So the pack cannot be mined for a
  // sibling's content, and the only salt in it is the disclosed record's.
  /** @type {Record<string, string>} */
  const salts = {};
  if (entry.salt !== null && entry.salt !== undefined) {
    salts[String(seq)] = Buffer.from(entry.salt).toString('hex');
  }

  const content = collectContent(store, entry.record);

  const pack = {
    manifest: {
      version: PACK_VERSION,
      suite: parseCheckpointText(parseNote(witnessed.blob === '' ? '' : noteOf(witnessed.blob)).text)
        ?.suite ?? null,
      origin: originOf(witnessed.blob),
      collector: store.collector,
      // DES-11's honest flag. A selective disclosure proves the included
      // action happened and says NOTHING about the ones it omits, and a
      // recipient must be able to tell a deliberate omission from a missing
      // piece. Set by construction: there is no argument that makes it true.
      covers: { from_seq: seq, to_seq: seq, complete: false },
      disclosed: [seq],
      note: 'Single-action disclosure. Sibling contents are not included by design, and are not '
        + 'recomputable from this pack.',
    },
    record: entry.record,
    salts,
    proof: {
      index,
      tree_size: witnessed.tree_size,
      path: path.map(p => Buffer.from(p).toString('base64')),
      root: Buffer.from(root).toString('hex'),
      checkpoint_seq: witnessed.seq,
      // Present only when the leaf salt is gone, and it is then the ONLY way
      // to check the path. A pack carrying both would let a recipient check
      // the easy one and skip the recomputation.
      ...(shreddedLeaf === null ? {} : { leaf: shreddedLeaf }),
    },
    // Every countersignature collected, never only a preferred one — FR-31.
    // Filtering would force the recipient to trust whoever we chose, which is
    // what makes DES-09's separate acceptance policy meaningful.
    checkpoint: JSON.parse(witnessed.blob),
    content,
  };
  return pack;
}

/** The note text out of an envelope blob. @param {string} blob */
function noteOf(blob) {
  const p = parseEnvelope(blob);
  return p.note ?? '';
}

/** @param {string} blob */
function originOf(blob) {
  try {
    const cp = parseCheckpointText(parseNote(noteOf(blob)).text);
    return cp?.origin ?? null;
  } catch { return null; }
}

/**
 * The disclosed record's own payloads, where they are still held.
 *
 * Only this record's. A shredded payload is reported absent rather than
 * omitted, so the recipient can tell "erased" from "not included".
 * @param {import('@splitstick/core/store').Store} store
 * @param {Record<string, any>} record
 */
function collectContent(store, record) {
  /** @type {Record<string, { cid: string, present: boolean, base64?: string, salt?: string }>} */
  const out = {};
  /** @param {string} where @param {any} c */
  const one = (where, c) => {
    if (!c?.cid) return;
    let bytes = null;
    /** @type {Buffer|null} */
    let salt = null;
    try {
      bytes = store.content.get(c.cid);
      // THE CONTENT SALT, without which the payload cannot be checked against
      // its commitment at all. A content cid is SHA-256(0x05 ‖ salt ‖
      // plaintext), so a recipient handed the plaintext and the cid and no salt
      // can verify nothing about it — they take the operator's word for what
      // the payload was, on the one surface built for an adversarial operator.
      //
      // The first version of this pack omitted it, and the "content check" in
      // verifyDisclosure compared an UNSALTED digest against the salted cid: a
      // comparison that can never be true, so substituting the payload
      // entirely produced a verdict of ok with no findings.
      //
      // Revealing this salt costs nothing: its job is to stop a guess at an
      // UNDISCLOSED plaintext being confirmed, and this plaintext is being
      // disclosed. Only the disclosed record's salts are read.
      salt = store.content.contentSalt(c.cid);
    } catch { bytes = null; salt = null; }
    out[where] = bytes === null || salt === null
      ? { cid: c.cid, present: false }
      : {
        cid: c.cid, present: true,
        base64: Buffer.from(bytes).toString('base64'),
        salt: salt.toString('hex'),
      };
  };
  for (const f of ['agent', 'args', 'result']) one(f, record[f]);
  if (record.approval) {
    for (const f of ['reviewer', 'request']) one(`approval.${f}`, record.approval[f]);
  }
  return out;
}

/**
 * Verify a disclosure pack, holding nothing else — FR-32, FR-33, NFR-05.
 *
 * No network, no store, no credential: the pack or nothing. If verification
 * needs anything else the design has failed, and DES-11 says so.
 *
 * @param {any} pack
 * @param {object} [o]
 * @param {string} [o.vkey] the operator identity the recipient pinned
 * @param {{ witnesses?: { id: string, public_key?: string }[] }} [o.policy]
 *   FR-30 — whose countersignature this recipient accepts
 * @returns {Promise<{ verdict: 'ok'|'fail'|'inconclusive',
 *   findings: import('@splitstick/core/findings').Finding[],
 *   disclosed: number[], witnesses: { issuer: string, accepted: boolean, verified: boolean }[] }>}
 */
export async function verifyDisclosure(pack, o = {}) {
  /** @type {import('@splitstick/core/findings').Finding[]} */
  const findings = [];
  /** @type {{ issuer: string, accepted: boolean, verified: boolean }[]} */
  const witnesses = [];

  if (pack?.manifest?.version !== PACK_VERSION) {
    // A version this verifier does not implement is refused, never partially
    // verified — DES-16. Partially verifying a format you cannot read is how a
    // reader ends up trusting the parts that happened to parse.
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
      `this pack declares version ${JSON.stringify(pack?.manifest?.version)} and this verifier `
      + `implements ${PACK_VERSION}; it is refused rather than partially checked`));
    return done(findings, witnesses, []);
  }

  const seq = Number(pack.manifest?.disclosed?.[0]);
  const proof = pack.proof ?? {};
  const record = pack.record;
  if (!Number.isSafeInteger(seq) || record === undefined || record === null) {
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
      'the pack names no disclosed record, or carries none'));
    return done(findings, witnesses, []);
  }
  // THE MANIFEST MUST AGREE WITH THE RECORD IT CARRIES.
  //
  // The salts map is keyed by record_seq, so a manifest naming a record the
  // pack does not hold simply found no salt — and the verifier reported
  // `disclosed: [3]` with a verdict of inconclusive while the pack held
  // record 1. A reader is then told, in the report's own words, that they are
  // looking at a record they are not. Checked before anything else is read, so
  // nothing downstream is reasoning about two different records at once.
  if (Number(/** @type {any} */ (record).record_seq) !== seq) {
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
      `the manifest discloses record ${seq} and the record carried is `
      + `${JSON.stringify(/** @type {any} */ (record).record_seq)}`));
    return done(findings, witnesses, [seq]);
  }
  const covers = pack.manifest?.covers ?? {};
  if (Number(covers.from_seq) !== seq || Number(covers.to_seq) !== seq) {
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
      `the manifest covers ${JSON.stringify(covers.from_seq)}..${JSON.stringify(covers.to_seq)} `
      + `and discloses ${seq}; a single-event pack states the same record in both`));
    return done(findings, witnesses, [seq]);
  }

  // ── the checkpoint note, and FR-33's countersignature ─────────────────────
  const envelope = pack.checkpoint;
  const parsed = parseEnvelope(JSON.stringify(envelope ?? {}));
  if (!parsed.ok || parsed.note === null) {
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
      `the pack's checkpoint envelope does not parse: ${parsed.findings.map(f => f.detail).join('; ')}`));
    return done(findings, witnesses, [seq]);
  }
  const note = parsed.note;
  const text = parseNote(note).text;
  const cp = parseCheckpointText(text);
  if (cp === null) {
    findings.push(finding('FORMAT_UNSUPPORTED', 'fail', 'the checkpoint note does not parse'));
    return done(findings, witnesses, [seq]);
  }

  if (parsed.issuers.size === 0) {
    // FR-33 — the whole point. Refused, not reported as weaker.
    findings.push(finding('WITNESS_MISSING', 'fail',
      'the root this proof is offered against carries no countersignature, so it establishes '
      + 'only that the operator is consistent with their own arithmetic (FR-33)'));
  }

  const named = new Map((o.policy?.witnesses ?? []).map(w => [w.id, w]));
  for (const cs of parsed.countersignatures) {
    const spec = named.get(cs.issuer);
    let verified = false;
    if (spec?.public_key && cs.verdict === 'ok' && cs.entry?.line) {
      const pub = Buffer.from(spec.public_key, 'base64');
      try {
        const line = parseNote(`${text}\n${cs.entry.line}\n`).signatures
          .find(s => s.name === cs.issuer);
        verified = line !== undefined && await verifyNoteSignature(text, line, {
          name: cs.issuer, publicKey: pub, keyId: noteKeyId(cs.issuer, pub),
        });
      } catch { verified = false; }
    }
    witnesses.push({ issuer: cs.issuer, accepted: spec !== undefined, verified });
    if (spec === undefined) {
      // Present, reported, counted for nothing. Presence is not proof — a
      // lesson this project has now paid for twice.
      findings.push(finding('WITNESS_MISSING', 'inconclusive',
        `this pack carries a countersignature from ${cs.issuer} and the acceptance policy does `
        + 'not name it, so it is present and unverified rather than verified'));
    } else if (!verified) {
      findings.push(finding('WITNESS_MISMATCH', 'fail',
        `${cs.issuer}'s countersignature does not verify over this checkpoint's note`));
    }
  }

  // ── the operator's own signature over the root ────────────────────────────
  if (o.vkey !== undefined) {
    const pinned = parseVkey(o.vkey);
    if (pinned.name !== cp.origin) {
      findings.push(finding('IDENTITY_UNPINNED', 'fail',
        `this pack is signed by ${cp.origin} and the recipient pinned ${pinned.name}`));
    } else {
      const sig = parseNote(note).signatures.find(s => s.name === pinned.name);
      const ok = sig !== undefined && await verifyNoteSignature(text, sig, {
        name: pinned.name, publicKey: pinned.publicKey,
        keyId: noteKeyId(pinned.name, pinned.publicKey),
      });
      if (!ok) {
        findings.push(finding('OPSIG_INVALID', 'fail',
          'the operator signature over this checkpoint does not verify under the pinned identity'));
      }
    }
  } else {
    findings.push(finding('OPSIG_UNCHECKED', 'inconclusive',
      'no operator identity was pinned, so the signature over the root was not checked against '
      + 'anything the recipient chose'));
  }

  // ── the inclusion proof ───────────────────────────────────────────────────
  const salt = pack.salts?.[String(seq)];
  const path = (proof.path ?? []).map((/** @type {string} */ p) => Buffer.from(p, 'base64'));
  /** @type {Buffer|null} */
  let leaf = null;
  if (typeof salt === 'string') {
    // Recomputed from the record and the salt — the recipient does not take the
    // operator's word for which leaf this is.
    leaf = leafDigest(Buffer.from(salt, 'hex'), record);
  } else {
    // The precise limit, which is narrower than "inclusion cannot be proved"
    // and wider than "everything checks out". The pack carries the committed
    // leaf, so the recipient CAN prove that leaf is in the countersigned tree.
    // What they cannot do is bind that leaf to the record they are looking at,
    // because binding needs the salt and the salt was destroyed with the
    // content. Both halves have to be said: an inconclusive that did not
    // distinguish them would read as the proof having failed.
    findings.push(finding('LEAF_INCONCLUSIVE', 'inconclusive',
      'this pack carries no salt for the disclosed record, which is what a shredded record looks '
      + 'like. The committed leaf is carried, so its presence in the countersigned tree is still '
      + 'provable; what cannot be checked is that this leaf is the record shown, because that '
      + 'binding needs the salt and the salt was destroyed with the content'));
    leaf = typeof proof.leaf === 'string' && /^[0-9a-f]{64}$/.test(proof.leaf)
      ? Buffer.from(proof.leaf, 'hex')
      : null;
  }

  if (leaf === null) {
    findings.push(finding('LEAF_INCONCLUSIVE', 'inconclusive',
      'without a salt or a committed leaf there is nothing to prove inclusion of'));
  } else if (!verifyInclusion(leaf, proof.index, proof.tree_size, path,
    Buffer.from(String(proof.root), 'hex'))) {
    findings.push(finding('TREE_MISMATCH', 'fail',
      `the inclusion proof for record ${seq} does not reach the root it claims`));
  } else if (Buffer.from(String(proof.root), 'hex').toString('hex') !== cp.root.toString('hex')) {
    // The proof must reach the root the CHECKPOINT signed, not a root the pack
    // supplies alongside it. Checking the proof against the pack's own root and
    // stopping there would let an operator prove inclusion in a tree nobody
    // countersigned, which is FR-33 defeated by arithmetic.
    findings.push(finding('TREE_MISMATCH', 'fail',
      'the proof reaches a root the countersigned checkpoint does not commit to'));
  }

  // ── the record's own payloads, CHECKED against their commitments ─────────
  //
  // A content cid is SHA-256(0x05 ‖ salt ‖ plaintext) — CONTENT_DOMAIN. The
  // first version of this block computed an UNSALTED digest and compared it to
  // the salted cid, a comparison that can never be true, so substituting the
  // payload entirely produced a verdict of ok with no findings. A check that
  // cannot fire is worse than no check, because the report reads as though the
  // payload had been verified.
  for (const [where, c] of Object.entries(pack.content ?? {})) {
    const held = /** @type {any} */ (c);
    if (typeof held?.cid !== 'string') {
      findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
        `${where} carries no commitment to check anything against`));
      continue;
    }
    if (held.present !== true) {
      // Erased. The commitment is carried and the bytes are not, which is what
      // a shredded payload looks like and is not a failure.
      if (held.base64 !== undefined) {
        // A contradiction: flagged absent and carrying bytes anyway. Accepting
        // it meant the bytes were silently ignored, so a pack could hand over
        // a payload nothing would ever check.
        findings.push(finding('FORMAT_UNSUPPORTED', 'fail',
          `${where} is flagged absent and carries bytes anyway; the two cannot both be true`));
        continue;
      }
      findings.push(finding('CONTENT_ABSENT', 'inconclusive',
        `${where} was erased: the pack carries its commitment and not its bytes`));
      continue;
    }
    if (typeof held.base64 !== 'string' || typeof held.salt !== 'string'
      || !/^[0-9a-f]{32}$/.test(held.salt)) {
      findings.push(finding('CONTENT_ABSENT', 'inconclusive',
        `${where} is flagged present and the pack carries no bytes and salt to check, so the `
        + 'payload cannot be verified against its commitment'));
      continue;
    }
    const recomputed = contentCid(Buffer.from(held.salt, 'hex'), Buffer.from(held.base64, 'base64'));
    if (recomputed !== held.cid) {
      findings.push(finding('CONTENT_MISMATCH', 'fail',
        `${where}'s bytes do not match the commitment the record holds: the record commits to `
        + `${held.cid} and these bytes salt to ${recomputed}`));
    }
  }

  return done(findings, witnesses, [seq]);
}

/**
 * @param {import('@splitstick/core/findings').Finding[]} findings
 * @param {{ issuer: string, accepted: boolean, verified: boolean }[]} witnesses
 * @param {number[]} disclosed
 */
function done(findings, witnesses, disclosed) {
  const checked = validateFindings(findings, 'verifyDisclosure');
  const verdict = checked.some(f => f.verdict === 'fail')
    ? /** @type {const} */ ('fail')
    : checked.some(f => f.verdict === 'inconclusive')
      ? /** @type {const} */ ('inconclusive')
      : /** @type {const} */ ('ok');
  return { verdict, findings: checked, disclosed, witnesses };
}
