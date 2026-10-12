/**
 * The witness restore drill — OPS-06.
 *
 * A witness that loses its roots destroys the corroboration it exists to
 * provide, so "it is backed up" has to mean something checkable. This is a
 * SCRIPT rather than a description, because a described procedure is one nobody
 * has run.
 *
 * It does four things, in the order that matters:
 *
 * 1. Builds a witness holding a real history, and takes a copy — the backup.
 * 2. Advances the live witness past the copy, so the backup is genuinely stale.
 * 3. Destroys the live store and restores the copy.
 * 4. Replays a CONFLICTING submission and asserts the restored witness refuses
 *    it, then asserts the operator's honest resubmission is refused too — and
 *    explains why that second refusal is correct rather than a bug.
 *
 * Run with `npm run drill:restore`. It prints the measured recovery point and
 * exits non-zero if the restored witness accepts something it should not.
 */

import { cpSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { StatefulWitness, WitnessRefused } from '../src/witness.mjs';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { checkpointText, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, leafHash, consistencyProof } from '@splitstick/core/merkle';

const OPERATOR = 'splitstick.dev/treasury-host-1';
const fail = (/** @type {string} */ m) => { console.error(`\n  DRILL FAILED: ${m}\n`); process.exit(1); };
const say = (/** @type {string} */ m) => console.log(`  ${m}`);

const leaves = (/** @type {number} */ n, /** @type {string} */ tag) =>
  Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`${tag}-${i}`)));

const witnessKey = await generateDevSigner('audit.internal');
const operator = await generateDevSigner(OPERATOR);

/** @param {StatefulWitness} w @param {Buffer[]} history @param {number} oldSize */
async function submit(w, history, oldSize) {
  const text = checkpointText({
    origin: OPERATOR, tree_size: history.length, root: treeRoot(history), suite: 'SS1' });
  return w.addCheckpoint({
    note: encodeNote(text, [await signNote(text, operator)]),
    old_size: oldSize,
    consistency_proof: oldSize === 0
      ? []
      : consistencyProof(history, oldSize).map(b => b.toString('base64')),
  });
}

console.log('\nWitness restore drill — OPS-06\n');

// 1 — a witness with a real history, and a backup.
const live = mkdtempSync(join(tmpdir(), 'drill-live-'));
const w1 = new StatefulWitness({ dir: live, signer: witnessKey });
w1.enrol(OPERATOR, operator.publicKey);
const prefix = leaves(100, 'shared');
await submit(w1, prefix, 0);
say(`live witness holds height ${w1.state(OPERATOR).last_size}`);

const backup = mkdtempSync(join(tmpdir(), 'drill-backup-'));
cpSync(live, backup, { recursive: true });
const backedUpAt = w1.state(OPERATOR).last_size;
say(`backup taken at height ${backedUpAt}`);

// 2 — advance past the backup, so it is genuinely stale.
const extended = [...prefix, ...leaves(50, 'more')];
await submit(w1, extended, 100);
const lostHeight = w1.state(OPERATOR).last_size;
// Counted BEFORE the store is destroyed. The first version read it afterwards,
// when both handles pointed at the restored directory, so the figure was
// always zero — and that figure is the drill's entire output.
const liveRoots = w1.roots(OPERATOR).length;
say(`live witness advanced to height ${lostHeight}; the backup is now stale`);

// 3 — lose the live store, restore the copy.
rmSync(live, { recursive: true, force: true });
cpSync(backup, live, { recursive: true });
const w2 = new StatefulWitness({ dir: live, signer: witnessKey });
if (w2.state(OPERATOR).last_size !== backedUpAt) {
  fail(`the restored witness is at ${w2.state(OPERATOR).last_size}, not ${backedUpAt}`);
}
say(`restored; the witness is back at height ${backedUpAt}`);
const restoredRoots = w2.roots(OPERATOR).length;
say(`MEASURED RECOVERY POINT: ${lostHeight - backedUpAt} record(s) of witnessed history, `
  + `being ${liveRoots - restoredRoots} retained root(s) `
  + `(${liveRoots} held, ${restoredRoots} recovered)`);
if (liveRoots - restoredRoots < 1) {
  fail('the drill measured no loss, so it did not exercise a stale backup at all');
}

// 4a — a CONFLICTING submission must still be refused.
const forked = [...prefix.slice(0, 50), ...leaves(100, 'forked')];
const conflicting = await submit(w2, forked, 100).then(() => null, (e) => e);
if (!(conflicting instanceof WitnessRefused)) {
  fail('the restored witness accepted a submission that forks below the height it holds');
}
say(`a conflicting history is refused: ${conflicting.status}`);

// 4b — and the operator's HONEST resubmission is refused too, which is right.
const honest = await submit(w2, extended, 150).then(() => null, (e) => e);
if (!(honest instanceof WitnessRefused)) {
  fail('the restored witness accepted a proof from a height it does not remember');
}
say(`the operator's own next submission is refused: ${honest.status}`);
console.log(`
  That second refusal is the correct outcome and must not be read as tampering.
  The operator is at height ${lostHeight} and the restored witness remembers
  ${backedUpAt}, so a proof from ${lostHeight} is a proof from a height this
  witness never saw — and accepting one would let an operator choose their own
  starting point, which is the whole of the sequence guarantee.

  The operator resubmits from the height the witness reports in the 409 body.
  The gap between the two is the recovery point above, and the records inside it
  are unwitnessed from this witness's perspective until they are resubmitted.
`);

// And the recovery is real: resubmitting from the restored height works.
const resubmitted = await submit(w2, extended, backedUpAt);
if (resubmitted.status !== 200) fail('resubmission from the restored height was refused');
say(`resubmitting from height ${backedUpAt} succeeds: the witness is at `
  + `${w2.state(OPERATOR).last_size} again`);

for (const d of [live, backup]) if (existsSync(d)) rmSync(d, { recursive: true, force: true });
console.log('\n  DRILL PASSED\n');
