import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

/**
 * DOC-05 as a check rather than a documentation review.
 *
 * "Publish the known information leaks and the attacks not covered" is only
 * worth something if the published list cannot drift from the measured one. So
 * every attack the red-team harness still declares undetected — after a
 * witness is configured, which is the strongest configuration this release
 * has — must appear in docs/known-limits.md by name.
 *
 * The failure this prevents is specific and likely: an attack stops being
 * closed, or a new uncovered one is added, and the document that an auditor
 * reads goes on describing the previous state.
 */
test('DOC-05: every attack still undetected is named in the published limits', async () => {
  const root = new URL('../../..', import.meta.url).pathname;
  const harness = readFileSync(`${root}/redteam/splitstick.mjs`, 'utf8');
  const limits = readFileSync(`${root}/docs/known-limits.md`, 'utf8');

  // Attack declarations, read from the harness's own table. `expect_witnessed`
  // is what remains open once a second party is configured; where it is absent
  // the local expectation stands.
  const open = [];
  for (const m of harness.matchAll(/id: '([A-Z0-9]+)',[^\n]*?expect: '(\w+)'(?:[^\n]*?expect_witnessed: '(\w+)')?/g)) {
    const [, id, expect, witnessed] = m;
    if ((witnessed ?? expect) === 'undetected') open.push(id);
  }
  assert.ok(open.length > 0, 'the harness declares at least one open attack, or this test is vacuous');

  for (const id of open) {
    assert.match(limits, new RegExp(`attack ${id}\\b`),
      `attack ${id} is still undetected and is not named in docs/known-limits.md`);
  }
});

test('DOC-05: the published leaks name the ones the requirements call out', () => {
  const root = new URL('../../..', import.meta.url).pathname;
  const limits = readFileSync(`${root}/docs/known-limits.md`, 'utf8');
  // Each of these is a leak a requirement says must be disclosed. A document
  // that stopped naming one would still read as a complete disclosure.
  for (const [what, pattern] of /** @type {const} */ ([
    ['the tree-size leak (PRIV-07)', /PRIV-07/],
    ['the anchor-cadence leak (PRIV-08)', /PRIV-08/],
    ['the coverage resolution an observer can read', /heartbeat interval is in the record/],
    ['the declared capture surface', /declared capture surface/i],
    ['that prevention is not the goal', /operator is the adversary/i],
  ])) {
    assert.match(limits, pattern, `the published limits no longer state ${what}`);
  }
});
