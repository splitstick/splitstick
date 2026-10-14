// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * LEG-12's lint, tested against claims it must refuse.
 *
 * A lint that passes the repository today tells you nothing about whether it
 * would catch the sentence somebody writes next year. So each rule is run
 * against text that breaks exactly that rule and is otherwise correct, and
 * against text that is correct and must NOT be flagged — a lint that fires on
 * honest prose gets switched off, which is the same outcome as not having one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { presumptionFindings } from '../tools/leg12.mjs';

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));

test('LEG-12: a claim that our witness carries the presumption is refused', () => {
  const bad = [
    "Splitstick's witness gives you the eIDAS Art. 41 presumption.",
    'Anchor to our witness and the Art. 41 presumption attaches.',
    'We provide the eIDAS presumption through the hosted witness.',
    'The presumption of integrity follows from our countersignature.',
  ];
  for (const text of bad) {
    const f = presumptionFindings(text);
    assert.ok(f.some(x => x.rule === 'R2'), `not refused: ${text}`);
  }
});

test('LEG-12: mentioning the presumption without its precondition is refused', () => {
  // R1. The sentence is true as far as it goes, and that is the problem: a
  // reader takes "the presumption attaches to anchored batches" and supplies
  // the missing condition themselves, generously.
  const f = presumptionFindings('Where a batch is anchored, the Art. 41 presumption attaches.');
  assert.ok(f.some(x => x.rule === 'R1'), 'an unqualified presumption claim was accepted');
});

test('LEG-12: the correct statements are NOT flagged', () => {
  // A lint that fires on honest prose gets switched off.
  const good = [
    'The eIDAS Art. 41 presumption attaches only when anchored to a qualified TSA, '
      + "and not via Splitstick's own witness.",
    'For the eIDAS Art. 41 presumption specifically you need a qualified TSA, which no '
      + 'witness this project operates can provide.',
    'Not a qualified trust service under eIDAS, so the Article 41 presumption does NOT '
      + 'attach to its timestamps.',
    'A qualified TSA states its traceability to UTC(k); the Art. 41 presumption rests on '
      + 'that status and on nothing we do.',
  ];
  for (const text of good) {
    assert.deepEqual(presumptionFindings(text), [], `wrongly flagged: ${text}`);
  }
});

test('LEG-12: a disclaimer in a LATER sentence does not rescue the claim', () => {
  // The SEC-17 lesson one level down. A precondition a page away is read
  // without it; so is a disclaimer a sentence away, because the reader has
  // already taken the claim and moved on.
  const text = 'Our witness gives you the Art. 41 presumption. '
    + 'Strictly speaking a qualified TSA is required.';
  const f = presumptionFindings(text);
  assert.ok(f.some(x => x.rule === 'R2'),
    'a claim followed by a correction was accepted as if corrected');
});

test('LEG-12: a mention of eIDAS that is not about the presumption is left alone', () => {
  // Scope. The requirement is about the presumption, and a page may reference
  // the regulation for other reasons; flagging those would make the lint noise.
  assert.deepEqual(
    presumptionFindings('eIDAS-qualified authorities can verify the same pack.'), []);
  assert.deepEqual(
    presumptionFindings('An auditor who accepts only eIDAS-qualified authorities supplies this.'), []);
});

test('LEG-12: the repository is clean under both rules', () => {
  // The same scan the lint runs, so a failure here names the file before the
  // build does.
  for (const rel of ['docs/splitstick-1.0-release-notes.md', 'docs/self-hosted-witness.md',
    'docs/witness-practice-statement.md', 'spec/witnesses.json', 'requirements/MATRIX.md']) {
    assert.deepEqual(presumptionFindings(readFileSync(join(REPO, rel), 'utf8')), [],
      `${rel} carries a LEG-12 finding`);
  }
});
