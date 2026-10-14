// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * Every scope guard, broken on purpose — SCOPE-01 to SCOPE-16, LEG-14 to
 * LEG-16, SEC-16, TRC-05.
 *
 * M7's rule, from docs/risk-assessment.md: a guard ships with a companion that
 * breaks it on purpose, against text violating exactly that guard and against
 * honest prose that must not fire. EACH GUARD, not a sample — and the coverage
 * assertion at the bottom fails if a guard is added without a companion here,
 * because the next guard is the one somebody adds in a hurry.
 *
 * Both halves matter and for different reasons. A guard that cannot fire lets
 * the overclaim ship with a green build. A guard that fires on honest prose
 * gets switched off, and then it guards nothing — this file's own development
 * produced four of those in a row against the real repository, and each one
 * was a sentence in which the project was refusing the very thing the guard
 * forbids.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GUARDS, TREE_GUARDS, violates } from '../tools/scope-guards.mjs';
import { sentences } from '../tools/claim-text.mjs';

/**
 * One case per guard: text that must fire, and honest text that must not.
 * Keyed by the guard's id exactly as the guard declares it.
 */
const CASES = {
  'SCOPE-02, SEC-16': {
    fires: [
      'Splitstick gives you a tamper-proof record of every agent action.',
      'The result is an immutable audit log.',
      'Once written, a record cannot be altered.',
      'Your evidence is unalterable.',
    ],
    passes: [
      'Splitstick is tamper-evident, not tamper-proof: it detects and attributes change.',
      'We do not claim an immutable audit log; the operator can still rewrite the file.',
      'An explicit, immutable record kind with its own record_seq and a commitment.',
      'Tampering is detected and attributed, which is a different and weaker claim.',
    ],
  },
  'LEG-14': {
    fires: [
      'Splitstick delivers EU AI Act conformity for your agent deployments.',
      'Deploy it and your system is AI Act compliant.',
    ],
    passes: [
      'Nothing here claims EU AI Act conformity; conformity is assessed by a body.',
      'The AI Act is cited for context and this is not legal advice.',
    ],
  },
  'LEG-15, SCOPE-03': {
    fires: [
      'Splitstick certifies your compliance with the regulation.',
      'Download your compliance certificate from the dashboard.',
      'It attests the customer\'s obligations have been met.',
    ],
    passes: [
      'Splitstick never certifies your compliance: the conclusion is yours and your counsel\'s.',
      'It produces evidence, and does not issue a certificate of compliance.',
    ],
  },
  'SCOPE-04': {
    fires: [
      'Splitstick replaces your SIEM and your tracing stack.',
      'Use it instead of dashboards for operational insight.',
    ],
    passes: [
      'It does not replace your SIEM; keep the observability you already need.',
      'This is an evidence recorder, not a replacement for traces or dashboards.',
    ],
  },
  'SCOPE-12': {
    fires: [
      'Running the collector in a TEE makes event suppression impossible.',
      'An enclave guarantees no action can be dropped.',
    ],
    passes: [
      'A TEE does not make suppression impossible: it cannot make a collector report '
        + 'an action it never observed.',
      'Attestation would narrow this, and a TEE is not a guarantee against omission.',
    ],
  },
  'SCOPE-14': {
    fires: [
      'Splitstick defeats 12 of 12 attacks in our suite.',
      'It blocks all attacks in the tamper classes.',
      'We stop 100% of tampers.',
    ],
    passes: [
      'The suite reports which classes are NOT closed rather than a score.',
      'We do not publish an N-of-N attacks-defeated metric; 9 of 12 tampers are detected '
        + 'and the other three are named.',
      '9 of 12 tampers are detected by splitstick verify from files alone.',
      // DOC-03's rejected-designs log names the metric this project refused.
      '| 3 | CUT | Verifiable delay function; the "*N* of *N* attacks defeated" metric. |',
      'An adversarial bounty was adopted in place of the self-scored metric.',
    ],
  },
  'SCOPE-01, SCOPE-16': {
    fires: [
      'Splitstick blocks the agent when a policy is violated.',
      'Enable fail-closed mode to halt the run.',
      'Configure the collector to block consequential calls.',
      'The proxy can deny a tool call that breaks policy.',
    ],
    passes: [
      'Splitstick never blocks an agent action; fail-open is a design constraint.',
      'A configuration that can stop an agent run is a configuration that will, at 3 a.m.',
      'There is no fail-closed option, and SCOPE-16 rejects one as a feature request.',
    ],
  },
  'SCOPE-11': {
    fires: [
      'A future release will add zero-knowledge compliance proofs.',
      'We are evaluating a zk-SNARK for selective disclosure.',
    ],
    passes: [
      '| 3 | CUT | Verifiable delay function; zero-knowledge compliance proofs; TEE-as-guarantee. |',
      'Zero-knowledge compliance proofs were considered and rejected, and are not on the roadmap.',
    ],
  },
  'SCOPE-10': {
    fires: [
      'A verifiable delay function gives an offline lower bound on elapsed time.',
      'The roadmap includes a VDF for time assurance.',
    ],
    passes: [
      '| 3 | CUT | Verifiable delay function. |',
      'A verifiable delay function was proposed as an offline lower bound and rejected.',
    ],
  },
  'SCOPE-13': {
    fires: [
      'The blockchain is the primary ledger for every record.',
      'Your ledger lives on chain.',
    ],
    passes: [
      'A public chain may serve only as the optional hard anchor, never as the ledger.',
      'We do not use a blockchain as the primary ledger.',
    ],
  },
  'DOC-04, TRC-04': {
    fires: [
      'Splitstick achieves p99 under 3 ms on the append path.',
      'Append overhead is measured at sub-millisecond.',
    ],
    passes: [
      'The p99 target is under 3 ms and no qualifying run exists yet, so it is a target.',
      'bench/append.mjs reports a regression metric, not an acceptance measurement.',
    ],
  },
};

test('M7: every prose guard fires on a violation', () => {
  for (const guard of GUARDS) {
    const c = /** @type {any} */ (CASES)[guard.id];
    assert.ok(c, `${guard.id} has no companion case`);
    for (const text of c.fires) {
      const hit = sentences(text).some(s => violates(guard, s));
      assert.ok(hit, `${guard.id} did NOT fire on: ${text}`);
    }
  }
});

test('M7: every prose guard leaves honest prose alone', () => {
  // The half that keeps a guard alive. Four of these were real false positives
  // against this repository, each one a sentence refusing the forbidden thing.
  for (const guard of GUARDS) {
    const c = /** @type {any} */ (CASES)[guard.id];
    for (const text of c.passes) {
      const hit = sentences(text).filter(s => violates(guard, s));
      assert.deepEqual(hit, [], `${guard.id} wrongly fired on: ${text}`);
    }
  }
});

test('M7: no guard fires on another guard\'s honest prose either', () => {
  // A guard is not allowed to be a false positive for somebody else's
  // correctly-written refusal, which is how a whole audit gets switched off.
  for (const [id, c] of Object.entries(CASES)) {
    for (const text of c.passes) {
      for (const guard of GUARDS) {
        const hit = sentences(text).filter(s => violates(guard, s));
        assert.deepEqual(hit, [],
          `${guard.id} fired on ${id}'s honest prose: ${text}`);
      }
    }
  }
});

test('M7: the companion list covers every guard, and names no guard that is gone', () => {
  // The guard on the guards. A guard added without a companion is the next one
  // somebody adds in a hurry, and it would ship untested and believed.
  assert.deepEqual([...GUARDS.map(g => g.id)].sort(), Object.keys(CASES).sort());
});

test('M7: every tree guard fires on what it forbids', () => {
  const FIRES = {
    'SCOPE-05': 'export function reviewerUI() {}',
    'SCOPE-06': 'import { samlStrategy } from "./sso.mjs";',
    'SCOPE-07': 'const RBAC = { roles: [] };',
    'SCOPE-08': 'const tenantId = req.headers["x-tenant"];',
    'SCOPE-09': 'const retentionTier = "cold";',
    'SCOPE-10': 'import { vdf } from "./VDF.mjs";',
    'SCOPE-11': 'import * as snarkjs from "snarkjs";',
    'SCOPE-13': 'import { ethers } from "ethers";',
  };
  for (const guard of TREE_GUARDS) {
    const src = /** @type {any} */ (FIRES)[guard.id];
    assert.ok(src, `${guard.id} has no tree companion`);
    assert.ok(guard.forbids.test(src), `${guard.id} did NOT fire on: ${src}`);
  }
  assert.deepEqual([...TREE_GUARDS.map(g => g.id)].sort(), Object.keys(FIRES).sort());
});

test('M7: the splitter keeps a table row whole and a wrapped sentence whole', () => {
  // Both of these were real bugs, found in this order against the repository.
  //
  // Splitting a row on `;` discarded the cells before the fragment, so the
  // `CUT` that makes the rejected-designs log honest was lost for every item
  // after the first.
  const row = '| 3 | CUT | Verifiable delay function; zero-knowledge compliance proofs. |';
  assert.deepEqual(sentences(row), [row], 'a table row was split apart');

  // Treating every newline as a boundary cut a sentence at its line wrap, and
  // the denial was on the next line — so the guard fired on honest prose.
  const wrapped = 'the verifier states whether the presumption attaches — computed from\n'
    + 'the proof type, so labelling our own witness qualified carries nothing.';
  assert.equal(sentences(wrapped).length, 1, 'a wrapped sentence was split at the newline');
  assert.match(sentences(wrapped)[0] ?? '', /carries nothing/);

  // And treating NO newline as a boundary merged neighbouring list items, which
  // hid a claim inside a run of unrelated prose.
  const bullets = '- Splitstick produces records whose integrity can be certified.\n'
    + '- The presumption attaches only to a qualified authority.';
  assert.equal(sentences(bullets).length, 2, 'two list items were merged into one');
});
