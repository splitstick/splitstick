// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Leaf and salt — DES-03, FR-09, SEC-13.
 *
 *   salt_i = CSPRNG(16 bytes)
 *   leaf_i = SHA-256( 0x00 ‖ salt_i ‖ JCS(record_i) )
 *
 * The salt exists because an action record is short and low-entropy — a
 * transfer has perhaps three unknowns — so an unsalted digest answers "was the
 * amount 2,000,000?" by enumeration. The test suite performs that enumeration
 * both ways rather than asserting the property.
 *
 * Salts live in salts/<collector>.json, never in the chain (DES-13). The chain
 * is never deleted, so a salt stored there could never be crypto-shredded and
 * FR-36 would be unsatisfiable.
 */

import { createHash, randomBytes } from 'node:crypto';
import { canonicalBytes } from './jcs.mjs';

export const SALT_BYTES = 16;

/** 0x00 — the same prefix RFC 6962 gives a leaf, deliberately (DES-05). */
export const LEAF_DOMAIN = 0x00;

/** @returns {Buffer} a fresh per-leaf salt. Never derived from the record. */
export const newSalt = () => randomBytes(SALT_BYTES);

/**
 * @param {Uint8Array} salt
 * @param {unknown} record a DES-01 ActionRecord, with no chain metadata (FR-59)
 * @returns {Buffer}
 */
export function leafDigest(salt, record) {
  if (salt.length !== SALT_BYTES) {
    throw new RangeError(`a leaf salt is exactly ${SALT_BYTES} bytes, got ${salt.length}`);
  }
  return createHash('sha256')
    .update(Buffer.from([LEAF_DOMAIN]))
    .update(salt)
    .update(canonicalBytes(record))
    .digest();
}
