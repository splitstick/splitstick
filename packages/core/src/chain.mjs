/**
 * Chain construction — DES-04, FR-08, SEC-06, SEC-07.
 *
 *   h_0 = 0x00 * 32                              // genesis, fixed
 *   h_i = SHA-256( 0x02 ‖ h_(i-1) ‖ leaf_i )     // 0x02 = chain domain
 *
 * One chain per collector instance, not per run (FR-56). Concurrent runs
 * interleave and each record carries its run as a field; heartbeats carry none.
 * That is what lets coverage attestation later prove the collector was alive
 * between runs, which is the window that matters.
 *
 * What a break proves, and what it does not: a chain over a prefix is
 * internally perfect, so truncation is NOT detectable from inside the record.
 * The test suite asserts that limit rather than leaving it to the prose. DES-07
 * and DES-08 close it by putting the record count somewhere the operator does
 * not control.
 */

import { createHash } from 'node:crypto';
import { leafDigest } from './leaf.mjs';
import { validateRecord } from './record.mjs';

/** 0x02 — chain. Distinct from 0x00 (leaf) and 0x01 (Merkle node). */
export const CHAIN_DOMAIN = 0x02;

/**
 * The fixed genesis value — 32 zero bytes. A configurable genesis is a way to
 * fork a chain quietly (DES-04 rule 3), so the authoritative value is
 * module-private and every caller gets a copy. Writing to what `genesis()`
 * returns changes nothing: the next call, and the verifier, still start here.
 */
const G = Buffer.alloc(32);

/** @returns {Buffer} a fresh copy of the genesis digest. */
export const genesis = () => Buffer.from(G);

/** The genesis digest as hex, for specs and error messages. */
export const GENESIS_HEX = G.toString('hex');

/**
 * @param {Uint8Array} prev
 * @param {Uint8Array} leaf
 * @returns {Buffer}
 */
export function chainHead(prev, leaf) {
  if (prev.length !== 32) throw new RangeError('prev is a 32-byte digest');
  if (leaf.length !== 32) throw new RangeError('leaf is a 32-byte digest');
  return createHash('sha256')
    .update(Buffer.from([CHAIN_DOMAIN]))
    .update(prev)
    .update(leaf)
    .digest();
}

/**
 * @typedef {object} ChainEntry
 * @property {Record<string, unknown>} record the canonicalised subject — no chain metadata
 * @property {Buffer} salt the per-leaf salt, held alongside and deletable (DES-13)
 * @property {Buffer} leaf
 * @property {Buffer} prev
 * @property {Buffer} head
 */

/**
 * Wrap a validated record as a chain entry. The record is not mutated and gains
 * no field: the digest of a record can never depend on a value derived from it
 * (FR-59).
 * @param {unknown} record
 * @param {Uint8Array} salt
 * @param {Uint8Array} prev
 * @returns {ChainEntry}
 */
export function chainEntry(record, salt, prev) {
  const r = validateRecord(record);
  const leaf = leafDigest(salt, r);
  return { record: r, salt: Buffer.from(salt), leaf, prev: Buffer.from(prev), head: chainHead(prev, leaf) };
}

/**
 * @typedef {object} Finding
 * @property {string} code a DES-12 failure code
 * @property {number} [record_seq]
 * @property {string} detail what a reader may conclude
 */

/**
 * Recompute a collector's chain from genesis. Checks run in DES-12's order:
 * FORMAT, then SEQUENCE, then CHAIN, then LEAF — a stream that is not a stream
 * should say so before it is interrogated about content.
 *
 * Returns findings rather than throwing: a contradiction is a verdict.
 * @param {ChainEntry[]} entries
 * @returns {{ ok: boolean, tree_size: number, findings: Finding[] }}
 */
export function recomputeChain(entries) {
  /** @type {Finding[]} */
  const findings = [];
  let prev = genesis();
  let lastSeq = 0;
  /** @type {number|null} */
  let lastSource = null;

  for (const e of entries) {
    const seq = Number(e.record.record_seq);

    // FORMAT + SEQUENCE
    try {
      validateRecord(e.record);
    } catch (err) {
      findings.push({ code: 'FORMAT_UNSUPPORTED', record_seq: seq, detail: String(err instanceof Error ? err.message : err) });
      break;   // DES-16: never skip, never guess, never partially verify
    }
    if (seq !== lastSeq + 1) {
      findings.push({
        code: 'SEQ_BROKEN', record_seq: seq,
        detail: `record_seq jumped from ${lastSeq} to ${seq}: an event was inserted, removed or reordered`,
      });
    }

    // Observation gaps are read from consecutive persisted source_seq values,
    // independently of record_seq. The two counters are never compared.
    const src = e.record.source_seq;
    if (typeof src === 'number') {
      if (lastSource !== null && src !== lastSource + 1) {
        findings.push({
          code: 'SEQ_BROKEN', record_seq: seq,
          detail: `source_seq jumped from ${lastSource} to ${src}: ${src - lastSource - 1} observed attempt(s) were never written`,
        });
      }
      lastSource = src;
    }

    // CHAIN
    if (!e.prev.equals(prev)) {
      findings.push({
        code: 'CHAIN_BROKEN', record_seq: seq,
        detail: seq === 1
          ? 'the first entry does not cite genesis'
          : 'prev does not match the predecessor head: an event was inserted, removed or reordered',
      });
    }

    // LEAF — a missing salt is inconclusive, never a failure, because lawful
    // erasure under DES-13 deletes exactly that (DES-12 check 4).
    if (e.salt === undefined || e.salt === null) {
      findings.push({ code: 'LEAF_INCONCLUSIVE', record_seq: seq, detail: 'salt absent: shredded or lost, so this leaf cannot be reproduced' });
    } else if (!leafDigest(e.salt, e.record).equals(e.leaf)) {
      findings.push({ code: 'LEAF_MISMATCH', record_seq: seq, detail: "this record's content is not what was committed" });
    } else if (!chainHead(e.prev, e.leaf).equals(e.head)) {
      findings.push({ code: 'CHAIN_BROKEN', record_seq: seq, detail: 'head is not the hash of its own prev and leaf' });
    }

    prev = e.head;
    lastSeq = seq;
  }

  return {
    ok: findings.every(f => f.code.endsWith('_INCONCLUSIVE')) && findings.length === 0,
    tree_size: entries.length,
    findings,
  };
}
