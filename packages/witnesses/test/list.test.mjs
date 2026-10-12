import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WitnessConfigError, witnessesFromConfig } from '../src/index.mjs';
import { parseWitnessList, readWitnessList, describeWitnessList } from '../src/list.mjs';
import { runConformance, selfTest, formatConformance } from '../src/conformance.mjs';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { StatefulWitness } from '@splitstick/witness-self';

const LIST = new URL('../../../spec/witnesses.json', import.meta.url).pathname;

// ── FR-47: the list is data, and every entry states its terms ──────────────

test('FR-47: the published list parses, and every entry states its position', async () => {
  const list = readWitnessList(LIST);
  assert.ok(list.entries.length >= 3, 'a list of one is not a choice');
  for (const e of list.entries) {
    assert.ok(e.acceptable_use.length > 20, `${e.id} states no real acceptable-use position`);
    assert.ok(e.rate_limits.length > 5, `${e.id} states no rate limits`);
    assert.equal(typeof e.retains_publicly, 'boolean', `${e.id} does not answer retains_publicly`);
    assert.ok(Array.isArray(e.establishes) && e.establishes.length > 0);
  }
});

test('FR-47: an entry missing its position is REFUSED, not defaulted', async () => {
  // An absent position reads as "no restriction", which is the one reading
  // that is never safe: an operator choosing a witness is choosing who learns
  // their anchor cadence and under whose terms.
  const base = JSON.parse(readFileSync(LIST, 'utf8'));
  for (const field of ['acceptable_use', 'rate_limits', 'retains_publicly', 'operator',
    'operated_by_splitstick', 'id', 'type', 'endpoints', 'establishes']) {
    const broken = structuredClone(base);
    delete broken.entries[0][field];
    assert.throws(() => parseWitnessList(broken), WitnessConfigError, `missing ${field}`);
  }
  // Empty string is not a position either.
  const blank = structuredClone(base);
  blank.entries[0].acceptable_use = '';
  assert.throws(() => parseWitnessList(blank), WitnessConfigError);
});

test('GOV-09: a field expressing preference is refused', async () => {
  // This project does not vet, rank or charge for inclusion. A `recommended`
  // flag would be gatekeeping wearing a different name, and the refusal is in
  // the parser rather than in a review checklist because a review is a thing
  // somebody skips.
  const base = JSON.parse(readFileSync(LIST, 'utf8'));
  for (const field of ['recommended', 'rating', 'rank', 'score', 'preferred', 'endorsed',
    'verified', 'trusted', 'certified', 'quality', 'stars', 'grade']) {
    const ranked = structuredClone(base);
    ranked.entries[0][field] = true;
    assert.throws(() => parseWitnessList(ranked), WitnessConfigError, field);
  }
  // And an honest field containing a ranking word as a substring is NOT
  // refused: `retention_note` must survive a check for `note`-like names.
  const honest = structuredClone(base);
  honest.entries[0].retention_note = 'still fine';
  assert.doesNotThrow(() => parseWitnessList(honest));
});

test('GOV-09: the published list contains entries this project does not control', async () => {
  // GOV-09's own verify asks for this. A list that is all ours is a list
  // nobody else is in, whatever the policy says.
  const list = readWitnessList(LIST);
  const theirs = list.entries.filter(e => !e.operated_by_splitstick);
  assert.equal(theirs.length, list.entries.length,
    'every entry is operated by somebody else, which is the strongest form of the property');
  assert.ok(theirs.length >= 3);
  // Operators are distinct parties, not one party under several names.
  assert.ok(new Set(theirs.map(e => e.operator)).size >= 3);
});

test('GOV-09: nothing in the rendering ranks or recommends', async () => {
  const text = describeWitnessList(readWitnessList(LIST));
  assert.match(text, /not a ranking and not an endorsement/);
  assert.match(text, /in file order/);
  for (const word of [/\brecommend/i, /\bbest\b/i, /\bpreferred\b/i, /\btrusted\b/i]) {
    // The disclaimer itself says "not an endorsement", so the check is that no
    // entry is SINGLED OUT — asserted by the absence of ranking vocabulary
    // outside the header.
    const body = text.split('\n').slice(4).join('\n');
    assert.ok(!word.test(body), `the rendering uses ${word} about an entry`);
  }
});

test('FR-47: an unknown witness type is refused rather than skipped', async () => {
  // A silently shrunk list leaves an operator believing a witness is available
  // that this build cannot build.
  const base = JSON.parse(readFileSync(LIST, 'utf8'));
  const unknown = structuredClone(base);
  unknown.entries[0].type = 'notarize-o-matic';
  // A validator, not a third argument: assert.throws(fn, Class, /re/) passes
  // the regex as the failure MESSAGE and asserts nothing about the error.
  assert.throws(() => parseWitnessList(unknown),
    (/** @type {any} */ e) => e instanceof WitnessConfigError && /not one of/.test(e.message));
});

test('FR-47: a duplicate id and a stale version are refused', async () => {
  const base = JSON.parse(readFileSync(LIST, 'utf8'));
  const dup = structuredClone(base);
  dup.entries.push(structuredClone(dup.entries[0]));
  assert.throws(() => parseWitnessList(dup),
    (/** @type {any} */ e) => e instanceof WitnessConfigError && /appears twice/.test(e.message));

  const future = structuredClone(base);
  future.version = 2;
  assert.throws(() => parseWitnessList(future),
    (/** @type {any} */ e) => e instanceof WitnessConfigError
      && /refused rather than partially/.test(e.message));
});

test('FR-47: the collector consumes the list', async () => {
  // The requirement says the collector consumes it, so an entry has to be
  // buildable into a witness adapter — otherwise the list is a document, not
  // data.
  const list = readWitnessList(LIST);
  const buildable = list.entries.filter(e => e.type !== 'splitstick' && e.endpoints.length > 0);
  assert.ok(buildable.length >= 2);
  const built = witnessesFromConfig({
    witnesses: buildable.map(e => ({
      id: e.id, type: e.type, url: e.endpoints[0],
      ...(e.type === 'opentimestamps' ? { calendars: e.endpoints } : {}),
    })),
  });
  assert.equal(built.length, buildable.length);
  for (const w of built) assert.ok(typeof w.submit === 'function');

  // And the self-hosted entry is NOT buildable from config by design — it
  // needs a transport the operator chooses and a key they hold.
  assert.throws(() => witnessesFromConfig({ witnesses: [{ id: 'x', type: 'splitstick' }] }),
    (/** @type {any} */ e) => e instanceof WitnessConfigError
      && /construct it with @splitstick\/witness-self/.test(e.message));
});

// ── FR-46, GOV-06: the conformance suite ───────────────────────────────────

/** A reference witness, set up the way an implementer would wire their own. */
function reference(/** @type {any} */ signer, /** @type {any} */ witnessKey, /** @type {string[]} */ dirs) {
  return () => {
    const dir = mkdtempSync(join(tmpdir(), 'ss-conf-'));
    dirs.push(dir);
    const make = () => {
      const w = /** @type {any} */ (new StatefulWitness({ dir, signer: witnessKey }));
      try { w.enrol('conformance.test/log', signer.publicKey); } catch { /* already */ }
      return w;
    };
    const w = make();
    w.reopen = make;
    return w;
  };
}

test('FR-46: the suite runs green against the reference witness', async () => {
  const signer = await generateDevSigner('conformance.test/log');
  const witnessKey = await generateDevSigner('reference.witness');
  /** @type {string[]} */
  const dirs = [];
  const r = await runConformance({ makeWitness: reference(signer, witnessKey, dirs), signer });
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  assert.equal(r.passed, true, formatConformance(r));
  assert.deepEqual(r.results.map(x => x.id), ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7']);
});

test('FR-46: the suite CAN fail, and each break is caught by its own check', async () => {
  // A conformance suite nothing can fail certifies nothing. And a self-test
  // satisfied by ANY failure would pass on a suite whose checks all fired for
  // the wrong reason — so each broken witness is correct in every other way
  // and must be caught by the check for the property it breaks.
  const signer = await generateDevSigner('conformance.test/log');
  const witnessKey = await generateDevSigner('reference.witness');
  const st = await selfTest({ signer, witnessKey });
  assert.equal(st.passed, true, JSON.stringify(st.results, null, 1));
  assert.deepEqual(st.results.map(x => x.expect), ['C3', 'C7', 'C3']);
  for (const x of st.results) {
    assert.ok(x.by.includes(x.expect), `${x.broken} was not caught by ${x.expect}`);
  }
});

test('GOV-05, GOV-06: the suite needs nothing this project operates', async () => {
  // A suite requiring our infrastructure would be a gate, not a check. Run
  // with `fetch` replaced by something that throws, and with an empty
  // environment: no account, no token, no registry to reach.
  const signer = await generateDevSigner('conformance.test/log');
  const witnessKey = await generateDevSigner('reference.witness');
  /** @type {string[]} */
  const dirs = [];
  const realFetch = globalThis.fetch;
  const savedEnv = { ...process.env };
  /** @type {any} */ (globalThis).fetch = () => {
    throw new Error('the conformance suite reached the network');
  };
  for (const k of Object.keys(process.env)) delete process.env[k];
  try {
    const r = await runConformance({ makeWitness: reference(signer, witnessKey, dirs), signer });
    assert.equal(r.passed, true, formatConformance(r));
  } finally {
    globalThis.fetch = realFetch;
    Object.assign(process.env, savedEnv);
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }
});

test('FR-46: each case builds a FRESH witness, so no case depends on another', async () => {
  // A suite whose result depends on its own ordering is measuring itself.
  const signer = await generateDevSigner('conformance.test/log');
  const witnessKey = await generateDevSigner('reference.witness');
  /** @type {string[]} */
  const dirs = [];
  let made = 0;
  const make = reference(signer, witnessKey, dirs);
  const r = await runConformance({
    makeWitness: () => { made += 1; return make(); }, signer,
  });
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  assert.equal(r.passed, true);
  assert.equal(made, 7, 'one witness per case, not one shared across them');
});
