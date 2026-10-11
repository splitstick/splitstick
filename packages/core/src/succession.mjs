/**
 * The epoch ratchet and its succession chain — FR-11, SEC-08, SEC-17, DES-06.
 *
 * Each epoch has its own key pair. Before an epoch retires it signs an
 * endorsement of its successor, so a verifier that has pinned one root public
 * key can walk forward and attribute every later epoch without pinning
 * anything again. Signatures from retired keys stay verifiable forever:
 * rotation is not an amnesty for anything signed before it.
 *
 * What this module does NOT do, and must not be read as doing:
 *
 * It does not establish forward secrecy. Forward secrecy needs the retired
 * private key to be genuinely gone, and key destruction is not externally
 * verifiable — nobody can prove they deleted a key. The ratchet is a
 * precondition for the claim, not the claim.
 *
 * It does not establish custody. An HSM signature and a signature from a PEM
 * file on disk are byte-identical, so the custody class in each entry is an
 * operator declaration. This module reports it labelled as one. Only FR-70's
 * five attestation checks, which land in M3a, can raise an epoch above that,
 * and until an attestation is supplied every epoch reads as operator-declared.
 *
 * It does not claim forward secrecy for the current epoch. The newest epoch is
 * still signing with the key in question; there is nothing retired about it.
 * DES-06 states this directly: a key in an HSM that is never rotated has no
 * forward secrecy whatever its custody class.
 */

import { verify as cryptoVerify } from 'node:crypto';
import { publicKeyFromRaw, CUSTODY_CLASSES } from './signer.mjs';
import { validateFindings } from './findings.mjs';

/** 0x04 — key succession. Distinct from 0x00, 0x01, 0x02 and 0x05. */
export const SUCCESSION_DOMAIN = 0x04;

export class SuccessionError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'SuccessionError'; }
}

/**
 * `0x04 ‖ pub(K_(n+1)) ‖ u64be(n+1)` — DES-06.
 *
 * The epoch number is inside the subject, not merely beside it. Without it an
 * endorsement of a key for epoch 1 would be a valid endorsement of the same key
 * for epoch 2, which is exactly how a skipped epoch would be dressed up as a
 * contiguous one.
 *
 * @param {Uint8Array} successorPublicKey raw 32 bytes
 * @param {number} successorEpoch
 * @returns {Buffer}
 */
export function endorsementSubject(successorPublicKey, successorEpoch) {
  if (successorPublicKey.length !== 32) {
    throw new SuccessionError('an Ed25519 public key is 32 bytes');
  }
  if (!Number.isSafeInteger(successorEpoch) || successorEpoch < 1) {
    throw new SuccessionError(
      `epoch ${successorEpoch} cannot be endorsed: epoch 0 is the pinned root and has no `
      + 'predecessor to endorse it, and epochs are positive integers',
    );
  }
  const out = Buffer.alloc(1 + 32 + 8);
  out[0] = SUCCESSION_DOMAIN;
  Buffer.from(successorPublicKey).copy(out, 1);
  out.writeBigUInt64BE(BigInt(successorEpoch), 33);
  return out;
}

/**
 * Endorse the successor key for `successorEpoch`, using the retiring epoch's
 * signer. The signer is the only thing that touches private material.
 *
 * @param {import('./signer.mjs').Signer} signer the retiring epoch's signer
 * @param {Uint8Array} successorPublicKey raw 32 bytes
 * @param {number} successorEpoch
 * @returns {Promise<Buffer>}
 */
export async function endorse(signer, successorPublicKey, successorEpoch) {
  const subject = endorsementSubject(successorPublicKey, successorEpoch);
  if (Buffer.from(successorPublicKey).equals(signer.publicKey)) {
    throw new SuccessionError(
      'an epoch cannot endorse itself: the successor key is the same key that is endorsing it, '
      + 'so the chain would advance without any key ever being retired',
    );
  }
  // Through the seam, exactly as checkpoint signing goes: a KMS signer endorses
  // its successor inside KMS, and no code path here sees private material.
  const sig = await signer.sign(subject);
  if (sig.length !== 64) {
    throw new SuccessionError(`the signer returned ${sig.length} bytes, not a 64-byte signature`);
  }
  return sig;
}

/**
 * @typedef {object} SuccessionEntry
 * @property {number} epoch
 * @property {string} public_key base64, raw 32 bytes
 * @property {'software'|'kms'|'hsm'} custody OPERATOR-DECLARED
 * @property {string} [endorsement] base64 Ed25519 signature by epoch-1's key.
 *   Absent on the root entry, and forbidden there.
 */

/**
 * @typedef {object} SuccessionFinding
 * @property {string} code
 * @property {string} detail
 * @property {number} [epoch]
 */

/**
 * Walk the succession chain from a pinned root public key.
 *
 * Every refusal here is a refusal to attribute, not a weaker attribution. A
 * chain that does not start at the pinned root yields no epochs at all rather
 * than a chain rooted somewhere else, because silently rebasing onto whatever
 * root was supplied is the failure this check exists to prevent.
 *
 * @param {Uint8Array|null|undefined} rootPublicKey raw 32 bytes, pinned out of band
 * @param {SuccessionEntry[]} entries in any order
 * @returns {{ ok: boolean, findings: SuccessionFinding[], epochs: SuccessionEntry[] }}
 */
export function verifySuccession(rootPublicKey, entries) {
  /** @type {SuccessionFinding[]} */
  const findings = [];
  const no = () => ({ ok: false, findings: validateFindings(findings, 'verifySuccession'), epochs: [] });

  if (!rootPublicKey || rootPublicKey.length !== 32) {
    findings.push({
      code: 'IDENTITY_UNPINNED',
      detail: 'no root public key was pinned, so the succession chain attributes nothing: '
        + 'a chain walked from a root supplied by the same party that wrote it is not evidence',
    });
    return no();
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    findings.push({ code: 'SUCCESSION_BROKEN', detail: 'no epoch entries were supplied' });
    return no();
  }

  // Shape first, so a malformed entry is a finding rather than a throw from
  // inside a crypto call.
  /** @type {Map<number, { entry: SuccessionEntry, raw: Buffer, sig: Buffer|null }>} */
  const byEpoch = new Map();
  for (const entry of entries) {
    const shaped = shape(entry, findings);
    if (!shaped) continue;
    const existing = byEpoch.get(shaped.entry.epoch);
    if (existing) {
      // Both endorsements can be individually valid. Only this check sees it.
      const same = existing.raw.equals(shaped.raw);
      findings.push({
        code: 'SUCCESSION_BROKEN',
        epoch: shaped.entry.epoch,
        detail: same
          ? `epoch ${shaped.entry.epoch} appears twice`
          : `epoch ${shaped.entry.epoch} is presented with two keys, which is a forked succession`,
      });
      continue;
    }
    byEpoch.set(shaped.entry.epoch, shaped);
  }
  if (findings.length > 0) return no();

  const epochs = [...byEpoch.keys()].sort((a, b) => a - b);
  const first = byEpoch.get(/** @type {number} */ (epochs[0]));
  if (!first || !first.raw.equals(Buffer.from(rootPublicKey))) {
    findings.push({
      code: 'SUCCESSION_BROKEN',
      detail: 'the chain does not begin at the pinned root public key, so nothing in it is '
        + 'attributed; it is not rebased onto the root that was supplied',
    });
    return no();
  }
  if (first.sig) {
    findings.push({
      code: 'SUCCESSION_BROKEN',
      epoch: first.entry.epoch,
      detail: 'the root entry carries an endorsement, but the root is pinned out of band and '
        + 'has no predecessor; an endorsement here could only be self-issued',
    });
    return no();
  }

  /** @type {SuccessionEntry[]} */
  const walked = [first.entry];
  let prev = first;
  for (let i = 1; i < epochs.length; i += 1) {
    const epoch = /** @type {number} */ (epochs[i]);
    const cur = /** @type {NonNullable<ReturnType<typeof shape>>} */ (byEpoch.get(epoch));
    const expected = /** @type {number} */ (epochs[i - 1]) + 1;
    if (epoch !== expected) {
      findings.push({
        code: 'SUCCESSION_BROKEN',
        epoch: expected,
        detail: `epoch ${expected} is missing: the chain jumps from ${epochs[i - 1]} to ${epoch}, `
          + 'and an epoch nobody endorsed cannot be attributed to the pinned root',
      });
      return no();
    }
    if (!cur.sig) {
      findings.push({
        code: 'SUCCESSION_BROKEN', epoch,
        detail: `epoch ${epoch} carries no endorsement from epoch ${epoch - 1}`,
      });
      return no();
    }
    if (cur.raw.equals(prev.raw)) {
      findings.push({
        code: 'SUCCESSION_BROKEN', epoch,
        detail: `epoch ${epoch} endorses itself — it presents the same key as epoch ${epoch - 1}, `
          + 'so no key is ever retired and the ratchet does not turn',
      });
      return no();
    }
    const subject = endorsementSubject(cur.raw, epoch);
    if (!cryptoVerify(null, subject, publicKeyFromRaw(prev.raw), cur.sig)) {
      findings.push({
        code: 'SUCCESSION_BROKEN', epoch,
        detail: `epoch ${epoch}'s endorsement does not verify under epoch ${epoch - 1}'s public `
          + 'key; the signature may be valid under some other key, which is not the question',
      });
      return no();
    }
    walked.push(cur.entry);
    prev = cur;
  }

  return { ok: true, findings: validateFindings(findings, 'verifySuccession'), epochs: walked };
}

/**
 * @param {SuccessionEntry} entry
 * @param {SuccessionFinding[]} findings
 * @returns {{ entry: SuccessionEntry, raw: Buffer, sig: Buffer|null }|null}
 */
function shape(entry, findings) {
  /** @param {string} detail */
  const bad = (detail) => {
    findings.push({ code: 'SUCCESSION_BROKEN', detail });
    return null;
  };
  if (entry === null || typeof entry !== 'object') return bad('a succession entry is not an object');
  if (!Number.isSafeInteger(entry.epoch) || entry.epoch < 0) {
    return bad(`epoch ${JSON.stringify(entry.epoch)} is not a non-negative integer`);
  }
  if (typeof entry.public_key !== 'string') return bad(`epoch ${entry.epoch} has no public_key`);
  const raw = decodeBase64(entry.public_key);
  if (!raw || raw.length !== 32) {
    return bad(`epoch ${entry.epoch}'s public_key is not 32 base64-encoded bytes`);
  }
  if (!CUSTODY_CLASSES.includes(entry.custody)) {
    // Defaulting an unknown class would be the worst outcome: it decides a
    // forward-secrecy claim, so an unrecognised value must stop the walk
    // rather than fall back to the permissive or the restrictive reading.
    return bad(
      `epoch ${entry.epoch} declares custody ${JSON.stringify(entry.custody)}, which is not one `
      + `of ${CUSTODY_CLASSES.join(', ')}`,
    );
  }
  /** @type {Buffer|null} */
  let sig = null;
  if (entry.endorsement !== undefined) {
    if (typeof entry.endorsement !== 'string') return bad(`epoch ${entry.epoch}'s endorsement is not a string`);
    sig = decodeBase64(entry.endorsement);
    if (!sig || sig.length !== 64) {
      return bad(`epoch ${entry.epoch}'s endorsement is not 64 base64-encoded bytes`);
    }
  }
  return { entry, raw, sig };
}

/** Strict base64: Buffer.from is lenient and would accept rubbish. @param {string} s */
function decodeBase64(s) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  return b.toString('base64').replace(/=+$/, '') === s.replace(/=+$/, '') ? b : null;
}

/**
 * @typedef {object} EpochReport
 * @property {number} epoch
 * @property {string} public_key
 * @property {'software'|'kms'|'hsm'} custody
 * @property {'operator-declared'} custody_basis
 * @property {boolean} custody_independently_supported FR-70; false until an
 *   attestation is supplied and passes all five checks (M3a).
 * @property {boolean} retired whether a later epoch exists
 * @property {'claimed'|'refused'|'not-yet'} forward_secrecy
 * @property {string} why
 */

/**
 * The verifier-facing view: the walk, plus what may and may not be claimed for
 * each epoch. SEC-17 is enforced here — the precondition is attached to every
 * claim rather than documented beside it.
 *
 * @param {Uint8Array|null|undefined} rootPublicKey
 * @param {SuccessionEntry[]} entries
 * @returns {{ ok: boolean, findings: SuccessionFinding[], epochs: EpochReport[],
 *             destruction_basis: 'operator-declared' }}
 */
export function successionReport(rootPublicKey, entries) {
  const walk = verifySuccession(rootPublicKey, entries);
  const last = walk.epochs[walk.epochs.length - 1];
  const newest = last ? last.epoch : -1;
  /** @type {EpochReport[]} */
  const epochs = walk.epochs.map(e => {
    const retired = e.epoch < newest;
    const { forward_secrecy, why } = claim(e.custody, retired);
    return {
      epoch: e.epoch,
      public_key: e.public_key,
      custody: e.custody,
      custody_basis: 'operator-declared',
      custody_independently_supported: false,
      retired,
      forward_secrecy,
      why,
    };
  });
  return { ok: walk.ok, findings: walk.findings, epochs, destruction_basis: 'operator-declared' };
}

/**
 * @param {'software'|'kms'|'hsm'} custody
 * @param {boolean} retired
 * @returns {{ forward_secrecy: 'claimed'|'refused'|'not-yet', why: string }}
 */
function claim(custody, retired) {
  if (custody === 'software') {
    return {
      forward_secrecy: 'refused',
      why: 'the epoch is declared software-keyed, so the private key existed outside any module '
        + 'and may have been copied before rotation; forward secrecy is refused outright rather '
        + 'than reported as weaker',
    };
  }
  if (!retired) {
    return {
      forward_secrecy: 'not-yet',
      why: 'this is the newest epoch and is still signing with the key in question, so nothing '
        + 'about it is retired; a key that is never rotated has no forward secrecy whatever its '
        + 'custody class',
    };
  }
  return {
    forward_secrecy: 'claimed',
    why: `forward secrecy is claimed for this epoch ONLY under its precondition: custody is `
      + `declared ${custody} and non-exportable, and the retired private key was destroyed. `
      + 'Both are operator declarations. Key destruction is not externally verifiable by anyone, '
      + 'so this claim is exactly as strong as that declaration and no stronger',
  };
}
