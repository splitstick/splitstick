// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * NFR-10 — @open-multi-agent/core 1.21.x.
 *
 * "Supported 1.21.x" is stated in three places that can drift apart: the
 * peerDependencies range that an installer enforces, the root pin that this
 * repository's own tests actually run against, and the prose in README.md that
 * a reader believes. Bump the root to 1.22 and nothing here would have failed:
 * the peer range would still say 1.21.x, the README would still say "tested
 * against 1.21.x", and the claim would be false with a green build behind it.
 *
 * So the three are checked against each other. The other half of the verify —
 * running the suite at both ENDS of the range rather than at one point inside
 * it — needs the registry and lives in the `oma-range` CI job; pinning one
 * patch and calling the minor line supported is a seam exercised once.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (/** @type {string} */ rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
const json = (/** @type {string} */ rel) => JSON.parse(read(rel));

const PKG = '@open-multi-agent/core';

/**
 * Does `version` satisfy `range`, for the `N.M.x` form only?
 *
 * Deliberately narrow. A general semver evaluator here would be a second
 * implementation of a solved problem, and — worse — one that silently returned
 * `true` for a range shape it did not really understand. Anything but `N.M.x`
 * is refused, so widening the declared range cannot quietly disable this test.
 * @param {string} version @param {string} range
 */
function satisfiesMinorRange(version, range) {
  const r = /^(\d+)\.(\d+)\.x$/.exec(range);
  assert.ok(r, `NFR-10's range is declared as ${JSON.stringify(range)}, which this check does not `
    + 'understand. It only evaluates the N.M.x form on purpose: a checker that guessed at a range '
    + 'shape would pass whatever it could not parse.');
  const v = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  assert.ok(v, `${JSON.stringify(version)} is not a version`);
  return v[1] === r[1] && v[2] === r[2];
}

test('NFR-10: the peer range, the root pin and the prose all say one thing', () => {
  const peer = json('../package.json').peerDependencies?.[PKG];
  assert.ok(peer, 'collect-oma declares no supported OMA range at all');

  // The root pin is what this repository's own suite runs against. If it left
  // the declared range, every "tested against" claim in the project would be
  // about a version nothing tests.
  const pin = json('../../../package.json').dependencies?.[PKG];
  assert.ok(pin, 'the root does not depend on OMA, so nothing here exercises it');
  assert.ok(satisfiesMinorRange(pin, peer),
    `the root pins ${pin}, outside the ${peer} that collect-oma declares supported`);

  // And the prose. A reader takes the claim from the README, not from a
  // package manifest.
  const readme = read('../../../README.md');
  assert.ok(readme.includes(peer),
    `README.md does not say ${peer}, so the documented claim and the enforced range can differ`);
});

test('NFR-10: the installed OMA is inside the supported range', () => {
  // The declarations can agree with each other and both be wrong about what is
  // actually on disk — which is what the suite really ran against.
  const peer = json('../package.json').peerDependencies?.[PKG];
  const installed = json(`../../../node_modules/${PKG}/package.json`).version;
  assert.ok(satisfiesMinorRange(installed, peer),
    `the suite ran against ${installed}, outside the declared ${peer}`);
});

test('NFR-10: CI exercises both ends of the range, not one point in it', () => {
  // The requirement is about a minor LINE. One pinned patch release passing
  // says nothing about the oldest 1.21 an installer may resolve, and
  // peerDependencies is a promise to whoever installs.
  const ci = read('../../../.github/workflows/ci.yml');
  assert.match(ci, /oma-range/, 'no CI job covers the declared OMA range');
  assert.match(ci, /NFR-10/, 'the job does not say which requirement it discharges');
  // Both ends named, so a job that quietly tested one version twice would fail
  // this rather than look like coverage.
  assert.match(ci, /lowest/i);
  assert.match(ci, /highest/i);
});
