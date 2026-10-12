/**
 * splitstick.yaml — DES-09, FR-41.
 *
 * Two policy files exist, deliberately separate: this one says who gets *asked*
 * to countersign, and acceptance.json (the verifier's, DES-09) says whose
 * signature is *accepted*. Collapsing them would make the openness decorative,
 * because every verification would terminate at this project's own key.
 *
 * YAML is parsed by the `yaml` package rather than by a hand-rolled subset.
 * INT-06 says reuse rather than reimplement, and a hand-rolled parser is
 * exactly the shape of defect FR-52 exists because of.
 *
 * Unknown keys are refused rather than ignored. Forward compatibility by
 * ignoring unknown fields is right for configuration an operator cannot get
 * wrong; a misspelled `witnes:` that silently disables anchoring is not that.
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';

export class ConfigError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'ConfigError'; }
}

export const CONFIG_VERSION = 1;

/** kms | hsm | file. file is development only — DES-06. */
export const SIGNER_TYPES = Object.freeze(['kms', 'hsm', 'file']);

/**
 * SCOPE-16 — the only accepted value. It is a key rather than a hardcoded
 * behaviour so the file documents itself: there is no fail-closed setting, by
 * design. A configuration that can stop an agent run is one that will, at 3 a.m.
 */
export const ON_UNAVAILABLE_VALUES = Object.freeze(['mark_gap']);

export const DEFAULTS = Object.freeze({
  anchor_interval_ms: 10_000,
  rollup_interval_ms: 3_600_000,
  heartbeat_interval_ms: 5_000,
  unwitnessed_ceiling_ms: 3_600_000,
  epoch_ms: 86_400_000,
  on_unavailable: 'mark_gap',
  quorum: 1,
});

const KNOWN = new Set([
  'version', 'store', 'signer', 'anchor_interval', 'rollup_interval',
  'heartbeat_interval', 'unwitnessed_ceiling', 'on_unavailable', 'witnesses',
  'quorum', 'retention', 'origin', 'collector', 'padding',
]);

const UNITS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/**
 * @param {unknown} v e.g. '10s', '1h', '250ms'
 * @returns {number} milliseconds
 */
export function parseDuration(v) {
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) throw new ConfigError(`not a duration: ${v}`);
    return v;
  }
  if (typeof v !== 'string') throw new ConfigError(`not a duration: ${String(v)}`);
  const m = /^([0-9]+)(ms|s|m|h|d)$/.exec(v);
  if (!m) throw new ConfigError(`not a duration: ${JSON.stringify(v)} — use 250ms, 10s, 15m, 1h or 7d`);
  return Number(m[1]) * UNITS[/** @type {keyof UNITS} */ (m[2])];
}

/**
 * A duration that must be greater than zero — FR-68.
 *
 * A ceiling of zero would make every batch instantly overdue, which makes the
 * alert meaningless rather than strict: an alarm that is always sounding is an
 * alarm nobody looks at, and the point of the ceiling is that somebody does.
 * @param {string} key @param {number} ms @returns {number}
 */
function positive(key, ms) {
  if (!Number.isInteger(ms) || ms <= 0) {
    throw new ConfigError(
      `${key} must be greater than zero, not ${ms}. Zero would make every batch instantly `
      + 'overdue, so the alert would fire constantly and mean nothing.',
    );
  }
  return ms;
}

/**
 * @typedef {object} Witness
 * @property {string} id
 * @property {string} type
 * @property {string} [url]
 * @property {string} [tier]
 * @property {string} [key]
 *
 * @typedef {object} Config
 * @property {number} version
 * @property {string} store
 * @property {string} storePath absolute, resolved against the config file
 * @property {{ type: string, key?: string, epoch_ms: number }} signer
 * @property {number} anchor_interval_ms
 * @property {number} rollup_interval_ms
 * @property {number} heartbeat_interval_ms
 * @property {number} unwitnessed_ceiling_ms
 * @property {'mark_gap'} on_unavailable
 * @property {Witness[]} witnesses
 * @property {number} quorum
 * @property {string} [origin]
 * @property {string} [collector]
 */

/**
 * @param {string} text
 * @param {string} [baseDir] directory to resolve `store` against
 * @returns {Config}
 */
export function parseConfig(text, baseDir = process.cwd()) {
  /** @type {unknown} */
  let raw;
  try {
    raw = parseYaml(text);
  } catch (e) {
    throw new ConfigError(`splitstick.yaml is not valid YAML: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError('splitstick.yaml must be a mapping');
  }
  const o = /** @type {Record<string, unknown>} */ (raw);

  for (const k of Object.keys(o)) {
    if (!KNOWN.has(k)) throw new ConfigError(`unknown key ${JSON.stringify(k)} in splitstick.yaml`);
  }

  if (o.version !== CONFIG_VERSION) {
    throw new ConfigError(`unsupported config version ${String(o.version)}: fails closed (DES-16)`);
  }
  if (typeof o.store !== 'string' || !o.store) throw new ConfigError('store is required');

  const signerRaw = o.signer === undefined ? { type: 'file' } : o.signer;
  if (typeof signerRaw !== 'object' || signerRaw === null || Array.isArray(signerRaw)) {
    throw new ConfigError('signer must be a mapping');
  }
  const sr = /** @type {Record<string, unknown>} */ (signerRaw);
  for (const k of Object.keys(sr)) {
    if (!['type', 'key', 'epoch'].includes(k)) throw new ConfigError(`unknown signer key ${JSON.stringify(k)}`);
  }
  if (typeof sr.type !== 'string' || !SIGNER_TYPES.includes(sr.type)) {
    throw new ConfigError(`signer.type must be one of ${SIGNER_TYPES.join(' | ')}`);
  }
  /** @type {{ type: string, key?: string, epoch_ms: number }} */
  const signer = {
    type: sr.type,
    epoch_ms: sr.epoch === undefined ? DEFAULTS.epoch_ms : parseDuration(sr.epoch),
  };
  if (sr.key !== undefined) {
    if (typeof sr.key !== 'string') throw new ConfigError('signer.key must be a string');
    // A key *reference* — a KMS resource name or a path. Never key material:
    // Splitstick must never hold, receive, request or log the key (SEC-14).
    signer.key = sr.key;
  }

  const onUnavailable = o.on_unavailable === undefined ? DEFAULTS.on_unavailable : o.on_unavailable;
  if (typeof onUnavailable !== 'string' || !ON_UNAVAILABLE_VALUES.includes(onUnavailable)) {
    throw new ConfigError(
      `on_unavailable must be ${ON_UNAVAILABLE_VALUES.join(' | ')}; there is no fail-closed setting, by design (SCOPE-16)`);
  }

  /** @type {Witness[]} */
  const witnesses = [];
  if (o.witnesses !== undefined) {
    if (!Array.isArray(o.witnesses)) throw new ConfigError('witnesses must be a list');
    const seen = new Set();
    for (const w of o.witnesses) {
      if (w === null || typeof w !== 'object' || Array.isArray(w)) throw new ConfigError('each witness is a mapping');
      const e = /** @type {Record<string, unknown>} */ (w);
      if (typeof e.id !== 'string' || !e.id) throw new ConfigError('a witness needs an id');
      if (typeof e.type !== 'string' || !e.type) throw new ConfigError(`witness ${e.id} needs a type`);
      if (seen.has(e.id)) throw new ConfigError(`duplicate witness id ${e.id}`);
      seen.add(e.id);
      for (const k of Object.keys(e)) {
        if (!['id', 'type', 'url', 'tier', 'key'].includes(k)) {
          throw new ConfigError(`unknown witness key ${JSON.stringify(k)} on ${e.id}`);
        }
      }
      witnesses.push(/** @type {Witness} */ (e));
    }
  }

  const quorum = o.quorum === undefined ? DEFAULTS.quorum : o.quorum;
  if (!Number.isInteger(quorum) || /** @type {number} */ (quorum) < 1) {
    throw new ConfigError('quorum must be a positive integer');
  }
  if (witnesses.length > 0 && /** @type {number} */ (quorum) > witnesses.length) {
    throw new ConfigError(`quorum ${quorum} exceeds the ${witnesses.length} configured witness(es)`);
  }

  const dur = (/** @type {string} */ k, /** @type {number} */ d) =>
    o[k] === undefined ? d : parseDuration(o[k]);

  return {
    version: CONFIG_VERSION,
    store: o.store,
    storePath: isAbsolute(o.store) ? o.store : resolve(baseDir, o.store),
    signer,
    anchor_interval_ms: dur('anchor_interval', DEFAULTS.anchor_interval_ms),
    rollup_interval_ms: dur('rollup_interval', DEFAULTS.rollup_interval_ms),
    heartbeat_interval_ms: dur('heartbeat_interval', DEFAULTS.heartbeat_interval_ms),
    unwitnessed_ceiling_ms: positive(
      'unwitnessed_ceiling', dur('unwitnessed_ceiling', DEFAULTS.unwitnessed_ceiling_ms)),
    on_unavailable: /** @type {'mark_gap'} */ (onUnavailable),
    witnesses,
    quorum: /** @type {number} */ (quorum),
    ...(typeof o.origin === 'string' ? { origin: o.origin } : {}),
    ...(typeof o.collector === 'string' ? { collector: o.collector } : {}),
  };
}

/**
 * @param {string} pathOrDir a splitstick.yaml, or a directory holding one
 * @returns {Config}
 */
export function loadConfig(pathOrDir) {
  const path = existsSync(pathOrDir) && statSync(pathOrDir).isDirectory()
    ? join(pathOrDir, 'splitstick.yaml')
    : pathOrDir;
  if (!existsSync(path)) throw new ConfigError(`no config at ${path}`);
  return parseConfig(readFileSync(path, 'utf8'), dirname(resolve(path)));
}
