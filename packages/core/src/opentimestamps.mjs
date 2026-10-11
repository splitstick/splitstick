/**
 * OpenTimestamps proof parsing — FR-22, DES-20.
 *
 * A `.ots` proof is not a signature. It is a chain of commitment operations —
 * append these bytes, prepend those, hash — ending in an *attestation* that
 * names where the resulting digest was published. For the Bitcoin attestation
 * that is a block height, and the claim is "this digest was committed to by the
 * merkle root of block N", which with the block's timestamp means the digest
 * existed no later than that block.
 *
 * Why that is worth having: no party can withdraw it. A TSA can be compelled,
 * go out of business, or lose its key; a transparency log operator can be
 * replaced. A Bitcoin block header cannot be un-mined by the operator, by us,
 * or by anyone the operator can reach. It is the only tier in this design whose
 * guarantee does not rest on an organisation continuing to behave.
 *
 * What this module does NOT do is confirm the attestation. Walking the proof
 * yields a commitment to a block header; confirming that the header is in the
 * chain needs a chain source, and NFR-05 requires the verifier to be offline by
 * construction. So the result reports the block height the proof commits to and
 * says plainly that confirmation is out of band. Reaching for the network here
 * would trade the offline guarantee for a convenience, and pretending the
 * commitment is a confirmation would be worse.
 *
 * A PENDING attestation is the ordinary state for the first hour or so after
 * submission: the calendar has the digest but it is not yet in a block. That is
 * reported as pending, not as a failure — treating it as one would make the
 * hard tier look broken for most of its first hour every time.
 */

import { createHash } from 'node:crypto';

export class OtsError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'OtsError'; }
}

/** The magic that opens a complete `.ots` file. */
export const FILE_MAGIC = Buffer.from(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex',
);

const ATTESTATION_TAG = 0x00;
const FORK_TAG = 0xff;

/** Attestation magics, as the OpenTimestamps format defines them. */
const ATTESTATIONS = Object.freeze({
  '0588960d73d71901': 'bitcoin',
  '06869a0d73d71b45': 'litecoin',
  '30fe8087b5c7ead7': 'ethereum',
  '83dfe30d2e906c6e': 'pending',
});

/** Operations. Binary ops carry a length-prefixed argument. */
const OPS = Object.freeze({
  0xf0: 'append',
  0xf1: 'prepend',
  0x02: 'sha1',
  0x03: 'ripemd160',
  0x08: 'sha256',
  0x67: 'keccak256',
});

/** A reader that refuses to run off the end rather than returning short. */
class Cursor {
  /** @param {Buffer} buf */
  constructor(buf) {
    this.buf = buf;
    this.at = 0;
  }

  /** @param {number} n */
  take(n) {
    if (this.at + n > this.buf.length) {
      throw new OtsError(`the proof ends mid-value: ${n} bytes wanted at offset ${this.at}`);
    }
    const out = this.buf.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  byte() { return /** @type {number} */ (this.take(1)[0]); }

  /** A varuint, 7 bits at a time, little-endian. */
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return value;
      shift += 7;
      if (shift > 56) throw new OtsError('a varuint beyond anything this reads');
    }
  }

  varbytes() { return this.take(this.varuint()); }

  get done() { return this.at >= this.buf.length; }
}

/**
 * @typedef {object} Attestation
 * @property {string} chain 'bitcoin' | 'litecoin' | 'ethereum' | 'pending' | 'unknown'
 * @property {number} [height] the block height, for a chain attestation
 * @property {string} [uri] the calendar, for a pending attestation
 * @property {string} magic hex
 * @property {string} digest hex — the digest this attestation is over
 */

/**
 * Parse a `.ots` proof and collect every attestation it reaches.
 *
 * @param {Buffer|Uint8Array} proof
 * @param {{ expectDigest?: Uint8Array }} [opts] the digest the proof must START
 *   from. Without it, a proof over somebody else's document parses perfectly.
 * @returns {{ digest: string, algorithm: string, attestations: Attestation[] }}
 */
export function parseOtsProof(proof, opts = {}) {
  const c = new Cursor(Buffer.from(proof));
  if (c.buf.length < FILE_MAGIC.length
    || !c.buf.subarray(0, FILE_MAGIC.length).equals(FILE_MAGIC)) {
    throw new OtsError('this does not begin with the OpenTimestamps proof magic');
  }
  c.at = FILE_MAGIC.length;
  const version = c.varuint();
  if (version !== 1) throw new OtsError(`proof version ${version} is not implemented`);

  const algByte = c.byte();
  const algorithm = OPS[/** @type {keyof typeof OPS} */ (algByte)];
  if (algorithm !== 'sha256') {
    throw new OtsError(
      `the proof's file digest is ${algorithm ?? `op 0x${algByte.toString(16)}`}; this suite `
      + 'commits to SHA-256 (DES-16)',
    );
  }
  const digest = Buffer.from(c.take(32));
  if (opts.expectDigest && !digest.equals(Buffer.from(opts.expectDigest))) {
    throw new OtsError(
      `the proof is over ${digest.toString('hex').slice(0, 16)}… but the bytes being checked digest `
      + `to ${Buffer.from(opts.expectDigest).toString('hex').slice(0, 16)}…: this is a valid proof `
      + 'about something else',
    );
  }

  /** @type {Attestation[]} */
  const attestations = [];
  walk(c, digest, attestations, 0);
  return { digest: digest.toString('hex'), algorithm, attestations };
}

/**
 * Walk the operation tree from `current`, collecting attestations.
 *
 * Depth is bounded. A proof is attacker-supplied data and a deeply nested or
 * cyclic-looking one must not exhaust the stack of a verifier that is only
 * being asked to read it.
 *
 * @param {Cursor} c @param {Buffer} current @param {Attestation[]} out @param {number} depth
 */
function walk(c, current, out, depth) {
  if (depth > 256) throw new OtsError('the proof nests deeper than this reads');
  for (;;) {
    if (c.done) return;
    const tag = c.byte();
    if (tag === FORK_TAG) {
      // A fork duplicates the current digest down two paths. The first is
      // walked recursively; the second continues this loop.
      walk(c, current, out, depth + 1);
      continue;
    }
    if (tag === ATTESTATION_TAG) {
      const magic = Buffer.from(c.take(8)).toString('hex');
      const payload = new Cursor(Buffer.from(c.varbytes()));
      /** @type {string} */
      const chain = ATTESTATIONS[/** @type {keyof typeof ATTESTATIONS} */ (magic)] ?? 'unknown';
      /** @type {Attestation} */
      const att = { chain, magic, digest: current.toString('hex') };
      if (chain === 'pending') {
        att.uri = Buffer.from(payload.varbytes()).toString('utf8');
      } else if (chain !== 'unknown') {
        att.height = payload.varuint();
      }
      out.push(att);
      return;
    }
    const op = OPS[/** @type {keyof typeof OPS} */ (tag)];
    if (!op) throw new OtsError(`unknown operation 0x${tag.toString(16)} in the proof`);
    current = apply(op, current, c);
  }
}

/** @param {string} op @param {Buffer} current @param {Cursor} c @returns {Buffer} */
function apply(op, current, c) {
  switch (op) {
    case 'append': return Buffer.concat([current, Buffer.from(c.varbytes())]);
    case 'prepend': return Buffer.concat([Buffer.from(c.varbytes()), current]);
    case 'sha256': return createHash('sha256').update(current).digest();
    case 'sha1': return createHash('sha1').update(current).digest();
    case 'ripemd160': return createHash('ripemd160').update(current).digest();
    default:
      // keccak256 is in the opcode table because proofs carry it; node:crypto
      // has no keccak, and guessing is worse than refusing.
      throw new OtsError(`operation ${op} is not implemented by this verifier`);
  }
}

/**
 * What a proof establishes, reported rather than confirmed.
 *
 * @param {Buffer|Uint8Array} proof
 * @param {{ imprint: Uint8Array }} opts
 * @returns {{ ok: boolean, inconclusive: boolean, malformed?: boolean, detail: string,
 *             heights: number[], pending: string[] }}
 */
export function describeOtsProof(proof, opts) {
  /** @type {ReturnType<typeof parseOtsProof>} */
  let p;
  try {
    p = parseOtsProof(proof, { expectDigest: opts.imprint });
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    // A proof over other bytes is REFUTED; a proof that does not parse is
    // merely broken. Collapsing them would let a mangled adapter produce this
    // project's strongest accusation.
    const refuted = /valid proof about something else/.test(detail);
    return {
      ok: false,
      inconclusive: !refuted,
      ...(refuted ? {} : { malformed: true }),
      detail,
      heights: [],
      pending: [],
    };
  }
  const heights = p.attestations.filter(a => a.chain === 'bitcoin' && a.height !== undefined)
    .map(a => /** @type {number} */ (a.height));
  const pending = p.attestations.filter(a => a.chain === 'pending')
    .map(a => /** @type {string} */ (a.uri ?? '(no uri)'));
  if (heights.length === 0 && pending.length > 0) {
    return {
      ok: false,
      inconclusive: true,
      detail: `the proof is PENDING at ${pending.join(', ')}: the calendar holds the digest but it `
        + 'is not yet in a block. That is the ordinary state for the first hour after submission, '
        + 'not a failure',
      heights,
      pending,
    };
  }
  if (heights.length === 0) {
    return {
      ok: false,
      inconclusive: true,
      detail: p.attestations.length === 0
        ? 'the proof reaches no attestation at all, so it commits to nothing'
        : `the proof reaches only ${[...new Set(p.attestations.map(a => a.chain))].join(', ')} `
          + 'attestations, which this verifier does not read',
      heights,
      pending,
    };
  }
  return {
    // Never `ok`. Walking the proof establishes a commitment to a block header;
    // confirming that header is in the chain needs a chain source, which
    // NFR-05 forbids this verifier from having.
    ok: false,
    inconclusive: true,
    detail: `the proof commits this digest to Bitcoin block ${heights.join(', ')}. Confirming that `
      + 'block is in the chain needs a chain source, which an offline verifier does not have '
      + '(NFR-05) — so this is reported, not confirmed. Check the block header out of band and the '
      + 'claim becomes: the digest existed no later than that block, with no party able to withdraw it',
    heights,
    pending,
  };
}
