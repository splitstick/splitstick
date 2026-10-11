import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, parseConfig, parseDuration, ConfigError, DEFAULTS } from '../src/config.mjs';

const DEFAULT_PATH = new URL('../../../design/default-config.yaml', import.meta.url);

// FR-41's verification clause, literally: the documented example config is loaded
// in test and each key is asserted to take effect. design/default-config.yaml is
// the single source of truth the docs are already linted against.
test('FR-41: the shipped default config loads and every key takes effect', () => {
  const c = parseConfig(readFileSync(DEFAULT_PATH, 'utf8'));
  assert.equal(c.version, 1);
  assert.equal(c.store, './splitstick');
  assert.equal(c.signer.type, 'kms');
  assert.equal(c.signer.epoch_ms, 24 * 3600_000);
  assert.equal(c.anchor_interval_ms, 10_000, 'the mutability window — NFR-03');
  assert.equal(c.rollup_interval_ms, 3600_000);
  assert.equal(c.heartbeat_interval_ms, 5_000, 'the resolution of every coverage claim — FR-24');
  assert.equal(c.unwitnessed_ceiling_ms, 3600_000);
  assert.equal(c.on_unavailable, 'mark_gap');
  assert.equal(c.quorum, 1);
  assert.deepEqual(c.witnesses.map(w => w.id), ['tsa', 'ots']);
  assert.equal(c.witnesses[0].type, 'rfc3161');
  assert.equal(c.witnesses[1].type, 'opentimestamps');
  assert.equal(c.witnesses[1].tier, 'rollup');
});

test('the commented-out witness options stay comments, not configuration', () => {
  const c = parseConfig(readFileSync(DEFAULT_PATH, 'utf8'));
  assert.equal(c.witnesses.length, 2, 'rekor is opt-in and must not load by default — FR-47');
  assert.ok(!c.witnesses.some(w => w.type === 'rekor'));
});

// SCOPE-16 — there is no fail-closed setting, by design. The key exists so the
// file documents itself; a configuration that can stop an agent run will.
test('SCOPE-16: on_unavailable accepts exactly one value', () => {
  const base = readFileSync(DEFAULT_PATH, 'utf8');
  for (const bad of ['fail_closed', 'block', 'halt', 'stop', 'error']) {
    assert.throws(() => parseConfig(base.replace('on_unavailable: mark_gap', `on_unavailable: ${bad}`)),
      ConfigError, bad);
  }
  assert.doesNotThrow(() => parseConfig(base));
});

test('durations are parsed, not assumed to be milliseconds', () => {
  assert.equal(parseDuration('10s'), 10_000);
  assert.equal(parseDuration('5s'), 5_000);
  assert.equal(parseDuration('1h'), 3_600_000);
  assert.equal(parseDuration('24h'), 86_400_000);
  assert.equal(parseDuration('250ms'), 250);
  assert.equal(parseDuration('15m'), 900_000);
  assert.equal(parseDuration('7d'), 604_800_000);
  for (const bad of ['', '10', 'soon', '10 s', '-5s', '1.5s', 'NaNs', '10sec']) {
    assert.throws(() => parseDuration(bad), ConfigError, JSON.stringify(bad));
  }
});

test('an unknown config version fails closed — DES-16', () => {
  const base = readFileSync(DEFAULT_PATH, 'utf8');
  assert.throws(() => parseConfig(base.replace('version: 1', 'version: 2')), ConfigError);
});

test('an unknown key is refused rather than ignored', () => {
  // Forward compatibility by ignoring unknown fields is right for configuration
  // the operator cannot get wrong. A witness key nobody reads is not that.
  assert.throws(() => parseConfig('version: 1\nstore: ./s\nwitnes: []\n'),
    /unknown key "witnes"/, 'and the error must name the key, not just fail');
});

test('a signer type outside kms | hsm | file is refused', () => {
  const ok = t => `version: 1\nstore: ./s\nsigner: { type: ${t}, key: k }\n`;
  for (const t of ['kms', 'hsm', 'file']) assert.doesNotThrow(() => parseConfig(ok(t)));
  assert.throws(() => parseConfig(ok('plaintext')), ConfigError);
});

test('quorum must be a positive integer no larger than the witness list', () => {
  const cfg = q => `version: 1\nstore: ./s\nquorum: ${q}\nwitnesses: [{ id: a, type: rfc3161, url: "https://x" }]\n`;
  assert.equal(parseConfig(cfg(1)).quorum, 1);
  for (const q of [0, -1, 1.5, 2]) assert.throws(() => parseConfig(cfg(q)), ConfigError, String(q));
});

test('a witness entry without an id or a type is refused', () => {
  assert.throws(() => parseConfig('version: 1\nstore: ./s\nwitnesses: [{ type: rfc3161 }]\n'), ConfigError);
  assert.throws(() => parseConfig('version: 1\nstore: ./s\nwitnesses: [{ id: a }]\n'), ConfigError);
  assert.throws(() => parseConfig('version: 1\nstore: ./s\nwitnesses: [{ id: a, type: rfc3161 }, { id: a, type: rfc3161 }]\n'),
    ConfigError, 'duplicate witness ids');
});

// SCOPE-15 — the roll-up anchor must be removable in one line.
test('SCOPE-15: the roll-up anchor can be removed, leaving a valid config', () => {
  const c = parseConfig(
    readFileSync(DEFAULT_PATH, 'utf8').replace(/^\s*- \{ id: ots.*$/m, ''));
  assert.deepEqual(c.witnesses.map(w => w.id), ['tsa']);
  assert.equal(c.quorum, 1);
});

test('defaults fill in only what the operator left out', () => {
  const c = parseConfig('version: 1\nstore: ./s\n');
  assert.equal(c.anchor_interval_ms, DEFAULTS.anchor_interval_ms);
  assert.equal(c.heartbeat_interval_ms, DEFAULTS.heartbeat_interval_ms);
  assert.equal(c.on_unavailable, 'mark_gap');
  assert.deepEqual(c.witnesses, []);
  const d = parseConfig('version: 1\nstore: ./s\nanchor_interval: 30s\n');
  assert.equal(d.anchor_interval_ms, 30_000);
  assert.equal(d.heartbeat_interval_ms, DEFAULTS.heartbeat_interval_ms);
});

test('loadConfig reads splitstick.yaml from a directory or a path', () => {
  const dir = mkdtempSync(join(tmpdir(), 'splitstick-cfg-'));
  const path = join(dir, 'splitstick.yaml');
  writeFileSync(path, readFileSync(DEFAULT_PATH));
  assert.equal(loadConfig(path).store, './splitstick');
  assert.equal(loadConfig(dir).store, './splitstick');
  assert.throws(() => loadConfig(join(dir, 'nope.yaml')), ConfigError);
});

test('the store path is resolved against the config file, not the cwd', () => {
  const dir = mkdtempSync(join(tmpdir(), 'splitstick-cfg-'));
  writeFileSync(join(dir, 'splitstick.yaml'), 'version: 1\nstore: ./evidence\n');
  assert.equal(loadConfig(dir).storePath, join(dir, 'evidence'));
});
