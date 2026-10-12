import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recomputeChain, chainEntry, genesis } from '../src/chain.mjs';
import { newSalt } from '../src/leaf.mjs';

/**
 * A declared gap EXPLAINS a source_seq jump — FR-26, consumed.
 *
 * M3a built the gap record and never taught the verifier to read it, so a log
 * that correctly declared its own loss was reported as SEQ_BROKEN: the honest
 * collector was accused of the thing the declaration exists to disclose. Found
 * by a test asserting the chain still verified after the FR-61 reconciliation
 * wrote one.
 *
 * The declaration is not a licence. It accounts for EXACTLY the span it names,
 * and a jump wider than the declaration is still a break — otherwise "declare
 * a gap" would become a way to delete records.
 */

const base = (/** @type {number} */ rs, /** @type {object} */ over) => ({
  v: 1, ts: '2026-10-11T10:00:00.000Z', record_seq: rs, collector: 'host-1', ...over,
});
const action = (/** @type {number} */ rs, /** @type {number} */ ss) => base(rs, {
  kind: 'tool_call', run: 'r-1', source_seq: ss, tool: 't', consequential: true,
  args: { cid: `sha256:${'a'.repeat(64)}` },
  outcome: 'ok', attempt: 1, correlation: `c-${ss}`,
});
const gap = (/** @type {number} */ rs, /** @type {number} */ from, /** @type {number} */ to) =>
  base(rs, { kind: 'gap', run: null, source_seq: null, from_source_seq: from, to_source_seq: to });

/** @param {Record<string, unknown>[]} records */
function chain(records) {
  let prev = genesis();
  return records.map(r => {
    const e = chainEntry(r, newSalt(), prev);
    prev = e.head;
    return e;
  });
}

const codes = (/** @type {any} */ r) => r.findings.map((/** @type {any} */ f) => f.code);

test('a declared gap accounts for the jump it names', () => {
  const r = recomputeChain(chain([action(1, 1), gap(2, 2, 3), action(3, 4)]));
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings));
  assert.equal(r.ok, true);
});

test('a jump with no declaration is still SEQ_BROKEN', () => {
  const r = recomputeChain(chain([action(1, 1), action(2, 4)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'));
});

test('a declaration narrower than the jump does not cover it', () => {
  // Declaring 2-2 while 2 and 3 are missing leaves 3 unexplained. If a partial
  // declaration excused the whole jump, "declare a gap" would be a way to
  // delete records.
  const r = recomputeChain(chain([action(1, 1), gap(2, 2, 2), action(3, 4)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'), JSON.stringify(r.findings));
  assert.match(r.findings[0].detail, /declared 2-2|not account/i);
});

test('a declaration wider than the jump is reported, not silently accepted', () => {
  // Claiming to have lost more than the sequence shows is a contradiction in
  // the operator's own account, and it is the shape of someone covering for a
  // deletion they have not worked out how to hide.
  const r = recomputeChain(chain([action(1, 1), gap(2, 2, 9), action(3, 4)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'), JSON.stringify(r.findings));
});

test('a declaration for a span that did not happen is reported', () => {
  const r = recomputeChain(chain([action(1, 1), gap(2, 5, 7), action(3, 2)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'), JSON.stringify(r.findings));
});

test('several declarations each account for their own span', () => {
  const r = recomputeChain(chain([
    action(1, 1), gap(2, 2, 3), action(3, 4), gap(4, 5, 10), action(5, 11),
  ]));
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings));
});

test('a declaration does not carry forward to a later jump', () => {
  // One declaration, two jumps. The second is unexplained, and a declaration
  // that kept applying would make the first one a blanket excuse.
  const r = recomputeChain(chain([action(1, 1), gap(2, 2, 3), action(3, 4), action(4, 9)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'), JSON.stringify(r.findings));
});

test('a gap declared before any observation accounts for the opening span', () => {
  // A collector that crashed before its first write and reconciled on restart.
  const r = recomputeChain(chain([gap(1, 1, 3), action(2, 4)]));
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings));
});

test('gap_unknown does not account for any exact span', () => {
  // It declares that the counter did not survive, which is the opposite of
  // naming a span. Treating it as cover for a jump would let the weakest
  // declaration excuse the most.
  const unknown = base(2, {
    kind: 'gap_unknown', run: null, source_seq: null,
    from_ts: '2026-10-11T09:00:00.000Z', to_ts: '2026-10-11T10:00:00.000Z',
    last_checkpoint_source_seq: 1,
  });
  const r = recomputeChain(chain([action(1, 1), unknown, action(3, 4)]));
  assert.ok(codes(r).includes('SEQ_BROKEN'), JSON.stringify(r.findings));
});
