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
 *
 * ── AND THE FIRST VERSION OF THIS FILE WAS NOT ENOUGH ────────────────────
 *
 * It passed, and the guards then missed TWENTY OUT OF TWENTY realistic
 * violations when the review probed them. Every one.
 *
 * The cause is the thing to remember: the violating examples here were written
 * FROM the patterns. Each was phrased to match a regex that had just been
 * typed, so this file asked "does the pattern fire on text I wrote for it"
 * rather than "does it catch what somebody would actually write" — which is
 * the question docs/risk-assessment.md says a companion has to answer, in so
 * many words, about a different guard.
 *
 * So `REALISTIC` below is written in the voice of somebody selling the product
 * or shipping the feature, deliberately without looking at the patterns, and
 * the patterns are fitted to IT. That ordering is the correction. When adding
 * a guard: write the sentence a marketer would write, then the regex.
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
  'LEG-13, LEG-20': {
    // LEG-13 closed on the integration SURFACE and the live anchor moved to
    // LEG-20 in the commercial release. Nobody here has bought a qualified TSA
    // account, so a complete 1.0 requirement count must not read as one having
    // been demonstrated. These are the sentences that would make the split
    // dishonest rather than merely a scope decision.
    fires: [
      'Splitstick delivers eIDAS qualified timestamping out of the box.',
      'All 193 requirements complete, qualified timestamping demonstrated.',
      'We have anchored against a qualified trust service in production.',
      'Qualified timestamps: achieved, with the Art. 41 presumption attaching.',
    ],
    passes: [
      'If you need the Art. 41 presumption, configure a qualified timestamp authority in your '
        + 'own witness set.',
      'No live qualified timestamp has been obtained by this project; that half is LEG-20.',
      'A qualified TSA can be configured by the operator, including the credential a commercial '
        + 'one requires.',
      'Where a batch is anchored to a qualified timestamp authority, the eIDAS Art. 41 '
        + 'presumption attaches.',
    ],
  },
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

/**
 * Violations in the voice of somebody who wants to ship them.
 *
 * NOT derived from the patterns. These are the sentences a landing page, a
 * conference abstract or a sales deck would actually carry, and the guards are
 * fitted to them. All twenty were missed by the first version of this audit.
 */
const REALISTIC = [
  // A complete 1.0 requirement count must not read as a live qualified anchor.
  // LEG-13 closed on the integration surface; nobody here has bought an
  // account. These are the sentences that would make the split dishonest.
  ['LEG-13, LEG-20', 'Splitstick delivers eIDAS qualified timestamping out of the box.'],
  ['LEG-13, LEG-20', 'All 193 requirements complete, qualified timestamping demonstrated.'],
  ['LEG-13, LEG-20', 'We have anchored against a qualified trust service in production.'],
  ['LEG-13, LEG-20', 'Qualified timestamps: achieved, with the Art. 41 presumption attaching.'],
  ['LEG-13, LEG-20', 'Splitstick provides qualified timestamping for regulated workloads.'],
  ['SCOPE-02, SEC-16', 'Your agent logs become permanent and unchangeable.'],
  ['SCOPE-02, SEC-16', 'Nobody can rewrite your audit history — not even you.'],
  ['SCOPE-02, SEC-16', 'Splitstick makes your agent records forgery-resistant and final.'],
  ['LEG-14', 'Splitstick is your AI Act Article 12 record-keeping solution.'],
  ['LEG-14', 'Be audit-ready for the EU AI Act in an afternoon.'],
  ['LEG-15, SCOPE-03', 'Hand your auditor a Splitstick report and you are compliant.'],
  ['LEG-15, SCOPE-03', 'Splitstick issues a signed compliance attestation for every run.'],
  ['SCOPE-04', 'One pane of glass for every agent action — retire your SIEM.'],
  ['SCOPE-14', 'Independently red-teamed: we withstood every attack tried.'],
  ['SCOPE-12', 'Collector runs in a secure enclave, so nothing can be hidden from it.'],
  ['SCOPE-01, SCOPE-16', 'Policy violations are intercepted before the tool ever runs.'],
  ['DOC-04, TRC-04', 'Benchmarked at 0.4 ms per event in production.'],
];

test('M7: the guards catch violations written WITHOUT looking at the patterns', () => {
  // The test that the first version of this file should have been. Each
  // sentence is checked against the WHOLE guard set rather than only its own
  // guard, because what matters is that the audit catches it at all — if a
  // different guard fires, the claim still does not ship.
  for (const [expected, text] of REALISTIC) {
    const fired = GUARDS.filter(g => sentences(text).some(s => violates(g, s))).map(g => g.id);
    assert.ok(fired.length > 0,
      `NOTHING caught, and ${expected} should have: ${text}`);
  }
});

/** Implementations in the shape they would actually arrive in. */
const REALISTIC_TREE = {
  'SCOPE-05': 'app.get("/review", renderApprovalConsole);',
  'SCOPE-06': 'const idp = new OidcClient(cfg);',
  'SCOPE-07': 'if (!user.roles.includes("auditor")) return 403;',
  'SCOPE-08': 'const org = resolveTenant(req);',
  'SCOPE-09': 'if (age > 90) moveToColdStorage(rec);',
  'SCOPE-10': 'const bound = wesolowskiProof(seed, iterations);',
  'SCOPE-11': 'const proof = await groth16.fullProve(input, wasm, zkey);',
  'SCOPE-13': 'const tx = await wallet.sendTransaction({ to, data });',
};

test('M7: the tree guards catch a feature in the shape it would arrive in', () => {
  // The worse half to get wrong. These are the RELEASE INVENTORY — the
  // question is not what we said but what we shipped, and a reviewer UI does
  // not announce itself by containing the string "reviewer UI". Eight for
  // eight were missed by the first version.
  for (const guard of TREE_GUARDS) {
    const src = /** @type {any} */ (REALISTIC_TREE)[guard.id];
    assert.ok(src, `${guard.id} has no realistic tree companion`);
    assert.ok(guard.forbids.test(src), `${guard.id} did NOT fire on: ${src}`);
  }
  assert.deepEqual([...TREE_GUARDS.map(g => g.id)].sort(), Object.keys(REALISTIC_TREE).sort());
});

/**
 * Evasions: a real overclaim wearing an unrelated denial.
 *
 * NINE OF TEN of these got through the first version, because the negation
 * exemption and `allows` both read the whole sentence. Marketing copy pairs a
 * negative hook with a positive claim as a matter of course — "No setup
 * required", "Never lose an action again" — so in the real world the exemption
 * was nearly always available, and the realistic corpus above did not catch
 * it because those sentences were realistic in VOCABULARY but not in
 * CONSTRUCTION.
 *
 * Exemptions are now clause-local. These are kept permanently because the
 * finding was not a missing pattern, it was the exemption mechanism, and that
 * is the kind of thing that comes back.
 */
/**
 * The honest forms of the same subject, which must pass. A guard that fired on
 * the release note it exists to protect would be removed within a week.
 */
const QUALIFIED_OK = [
  'If you need the Art. 41 presumption, configure a qualified timestamp authority in your own '
    + 'witness set.',
  'No live qualified timestamp has been obtained by this project; that half is LEG-20.',
  'A qualified TSA can be configured by the operator, including the credential a commercial one '
    + 'requires.',
  'Where a batch is anchored to a qualified timestamp authority, the eIDAS Art. 41 presumption '
    + 'attaches.',
  'Splitstick is not a qualified trust service provider and never claims the presumption through '
    + 'a witness it operates.',
];

test('LEG-13: the honest phrasings of qualified status do not fire', () => {
  for (const text of QUALIFIED_OK) {
    const hits = GUARDS.filter(g => violates(g, text));
    assert.deepEqual(hits.map(g => g.id), [], `fired on: ${text}`);
  }
});

const EVASIONS = [
  'Splitstick is not slow, and your logs are permanent and unchangeable.',
  'No setup required: be audit-ready for the EU AI Act in an afternoon.',
  'No agent changes needed — hand your auditor a report and you are compliant.',
  'Never lose an action again: we withstood every attack tried.',
  'Nothing to configure. Retire your SIEM.',
  'Your audit log is public and cannot be altered.',
  'Splitstick is tamper-evident, and your records are permanent and unchangeable.',
  'Rejected alternatives aside, we ship zero-knowledge compliance proofs.',
  'Cut to the chase: a verifiable delay function bounds elapsed time for you.',
];

test('M7: an unrelated denial does not shield an overclaim', () => {
  // The exemption has to be ATTACHED to the thing it exempts. "tamper-evident,
  // not tamper-proof" keeps the denial in the same clause as the phrase, which
  // is what makes it honest rather than merely adjacent to something honest.
  for (const text of EVASIONS) {
    const fired = GUARDS.filter(g => sentences(text).some(s => violates(g, s)));
    assert.ok(fired.length > 0, `EVADED: ${text}`);
  }
});

test('M7: and the honest refusals still survive the clause rule', () => {
  // The other half, and the reason the clause break is punctuation-only:
  // splitting on `and` broke "considered and rejected", where the exemption is
  // the second half of a fixed phrase about the subject.
  for (const text of [
    'Splitstick is tamper-evident, not tamper-proof: it detects and attributes change.',
    'We do not claim an immutable audit log; the operator can still rewrite the file.',
    'It does not replace your SIEM; keep the observability you already need.',
    'Zero-knowledge compliance proofs were considered and rejected, and are not on the roadmap.',
    'A verifiable delay function was proposed as an offline lower bound and rejected.',
    'EU AI Act Article 12 asks for tamper-evident records, not impossible ones.',
  ]) {
    const fired = GUARDS.filter(g => sentences(text).some(s => violates(g, s))).map(g => g.id);
    assert.deepEqual(fired, [], `wrongly fired on: ${text}`);
  }
});

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
