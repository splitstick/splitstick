import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  FAILURE_CODES, VERDICTS, finding, forward, validateFindings, FindingError,
} from '../src/findings.mjs';

const SPEC = JSON.parse(readFileSync(new URL('../../../spec/failure-codes.json', import.meta.url), 'utf8'));

test('the frozen vocabulary is exactly the specified vocabulary', () => {
  // The lint asserts this too. It is here as well because the lint is a build
  // step someone can skip and this is a test they cannot.
  assert.deepEqual([...FAILURE_CODES].sort(), SPEC.codes.map((/** @type {any} */ c) => c.code).sort());
  assert.equal(FAILURE_CODES.length, new Set(FAILURE_CODES).size, 'no duplicates');
  assert.throws(() => { /** @type {any} */ (FAILURE_CODES).push('X'); }, TypeError);
});

test('an undefined code cannot be constructed', () => {
  for (const code of ['', 'NOT_A_CODE', 'torn_write', 'TORN_WRITE ', undefined, null, 42]) {
    assert.throws(() => finding(/** @type {any} */ (code), 'fail', 'detail'),
      (/** @type {any} */ e) => e instanceof FindingError, JSON.stringify(code));
  }
});

test('a verdict outside DES-12 cannot be constructed, and neither can an empty detail', () => {
  assert.throws(() => finding('TORN_WRITE', /** @type {any} */ ('maybe'), 'd'), FindingError);
  assert.throws(() => finding('TORN_WRITE', /** @type {any} */ (undefined), 'd'), FindingError);
  // A code alone tells a reader nothing, which is the whole thesis of the
  // report format.
  assert.throws(() => finding('TORN_WRITE', 'fail', ''), FindingError);
  assert.deepEqual([...VERDICTS], ['ok', 'fail', 'inconclusive']);
});

test('a finding carries only the location fields it was given', () => {
  assert.deepEqual(finding('TORN_WRITE', 'inconclusive', 'd'),
    { code: 'TORN_WRITE', verdict: 'inconclusive', detail: 'd' });
  assert.deepEqual(finding('SEQ_BROKEN', 'fail', 'd', { record_seq: 4 }),
    { code: 'SEQ_BROKEN', verdict: 'fail', detail: 'd', record_seq: 4 });
});

test('forwarding checks the code it forwards, which is what the lint stopped being able to', () => {
  const ok = forward({ code: 'CHAIN_BROKEN', detail: 'broke', record_seq: 2 }, 'fail', 'checkpoint 3');
  assert.deepEqual(ok, {
    code: 'CHAIN_BROKEN', verdict: 'fail', detail: 'checkpoint 3: broke', record_seq: 2,
  });
  assert.throws(() => forward({ code: 'INVENTED', detail: 'x' }, 'fail'), FindingError);
});

test('validateFindings throws on an undefined code and names where it came from', () => {
  const good = [{ code: 'TORN_WRITE', verdict: 'inconclusive', detail: 'a' }];
  assert.equal(validateFindings(good, 'test'), good);
  assert.throws(
    () => validateFindings([{ code: 'MADE_UP', detail: 'a' }], 'someModule'),
    (/** @type {any} */ e) => e instanceof FindingError && /someModule/.test(e.message) && /MADE_UP/.test(e.message),
  );
  assert.throws(
    () => validateFindings([{ code: 'TORN_WRITE', verdict: 'probably', detail: 'a' }], 'someModule'),
    (/** @type {any} */ e) => e instanceof FindingError && /probably/.test(e.message),
  );
});

test('every module that produces findings validates them at its boundary', async () => {
  // The guarantee is "nothing leaves a module with an unknown code". That rests
  // on each boundary calling validateFindings, which is the kind of thing that
  // is true when written and quietly false a year later — so it is asserted
  // rather than trusted.
  const files = [
    '../src/chain.mjs', '../src/succession.mjs', '../src/envelope.mjs',
    '../../verify/src/verify.mjs',
  ];
  for (const f of files) {
    const text = readFileSync(new URL(f, import.meta.url), 'utf8');
    assert.match(text, /validateFindings\(/, `${f} returns findings without validating them`);
  }
});

test('every specified code is in a milestone the plan knows about', () => {
  const plan = JSON.parse(readFileSync(new URL('../../../requirements/milestones.json', import.meta.url), 'utf8'));
  const known = new Set(plan.milestones.map((/** @type {any} */ m) => m.id));
  for (const c of SPEC.codes) {
    assert.ok(known.has(c.milestone), `${c.code} names milestone ${c.milestone}, which is not in the plan`);
  }
  for (const m of SPEC.delivered_milestones) {
    assert.ok(known.has(m), `delivered_milestones names ${m}, which is not in the plan`);
  }
});
