// Copyright 2026 prathish-ks
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The same tamper classes, against a Splitstick store instead of a bare OMA
 * journal — the M1 gate (AC-1, AC-2).
 *
 * redteam.mjs stays exactly as it is: it documents what OMA's own verifyRun()
 * does and fails if that moves, in either direction. This file is the other
 * half. The genuine OMA run is fed through @splitstick/collect-oma into a real
 * store, each tamper is applied to that store, and `splitstick verify` is asked
 * for a verdict.
 *
 * Every attack declares what we observe, and the process exits non-zero when an
 * observation changes. Four of them declare UNDETECTED, with the milestone that
 * closes each. An attack class this release cannot close is listed here rather
 * than omitted, because a suite that only contains its successes is marketing.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Collector } from '@splitstick/core/collector';
import { Store } from '@splitstick/core/store';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, checkpointText, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { leafDigest } from '@splitstick/core/leaf';
import { chainHead, genesis } from '@splitstick/core/chain';
import { treeRoot } from '@splitstick/core/merkle';
import { noteDigest } from '@splitstick/core/envelope';
import { Anchorer } from '@splitstick/core/anchor';
import { StatefulWitness } from '@splitstick/witness-self/witness';
import { SplitstickRunJournal } from '@splitstick/collect-oma';
import { verifyStore } from '@splitstick/verify';
import { evaluateGates, formatGates } from './gates.mjs';
import { JOURNAL_PATH } from './generate.mjs';

if (!fs.existsSync(JOURNAL_PATH)) {
  console.error(`No fixture at ${JOURNAL_PATH}. Run: npm run generate`);
  process.exit(1);
}

const ORIGIN = 'splitstick.dev/redteam';
const WITNESS = 'audit.internal';
const COLLECTOR = 'redteam';
const FORGED = 'OK: transferred EUR 25 to ACME-9931. ref=TX-77814';
const events = fs.readFileSync(JOURNAL_PATH, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

/** The fixture journal under a different run id, so two runs interleave. */
function asRun(id) {
  return events.map((e) => {
    const copy = JSON.parse(JSON.stringify(e));
    copy.runId = id;
    if (copy.call) copy.call.id = `${copy.call.id}-${id}`;
    if (copy.toolCallId) copy.toolCallId = `${copy.toolCallId}-${id}`;
    return copy;
  });
}

/**
 * Build a fresh store from the genuine OMA journal, checkpointed and signed.
 *
 * Two runs and three heartbeats, because that is the shape a real collector
 * writes: one chain per instance, concurrent runs interleaved, heartbeats
 * between them (FR-56). A single-action chain would also make the sequence and
 * truncation attacks below untestable, which would be a suite shaped around
 * what is convenient to prove.
 */
async function build() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'splitstick-redteam-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(root, COLLECTOR);
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const collector = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: COLLECTOR, origin: ORIGIN, now: () => new Date((t += 1000)),
  });
  const journal = new SplitstickRunJournal({ collector });
  collector.heartbeat();
  await journal.append(asRun('run-1'));
  collector.heartbeat();
  await journal.append(asRun('run-2'));
  collector.heartbeat();
  await journal.close();
  const checkpoint = await collector.checkpoint();
  return { root, store, signer, collector, checkpoint, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

/**
 * The same store, with a stateful witness (FR-17) having countersigned the
 * checkpoint — and the witness's retained root kept OUT of the store, where the
 * operator cannot reach it.
 *
 * That second part is the whole mechanism. A countersignature inside the
 * envelope is evidence only until the operator deletes the envelope; what they
 * cannot delete is what a second party retained and a counterparty already
 * holds. So the witnessed run hands the verifier the heights the witness
 * remembers (FR-54, SEC-26) exactly as an auditor polling the witness would,
 * and the attacks that survive THAT are the ones M3a genuinely does not close.
 */
async function buildWitnessed() {
  const ctx = await build();
  const wdir = fs.mkdtempSync(path.join(os.tmpdir(), 'splitstick-witness-'));
  const wkey = await generateDevSigner(WITNESS);
  const witness = new StatefulWitness({ dir: wdir, signer: wkey });
  witness.enrol(ORIGIN, ctx.signer.publicKey);

  const adapter = {
    id: WITNESS,
    proof_type: 'c2sp-note',
    establishes: ['sequence'],
    tier: 'anchor',
    async submit(note) {
      const res = await witness.addCheckpoint({ note, old_size: 0 });
      const lines = parseNoteLines(res.note);
      return { type: 'c2sp-note', issuer: WITNESS, covers: 'note', line: lines.at(-1) };
    },
  };
  const anchorer = new Anchorer({
    store: ctx.store, witnesses: [adapter], quorum: 1,
    acceptance: { [WITNESS]: wkey.publicKey },
  });
  // Every checkpoint, not only the first. Anchoring one exercises the easy half
  // of the witness protocol and hides the sequence path entirely — which is how
  // a missing consistency proof survived until a test wired the two together
  // across four batches.
  for (const { seq } of ctx.store.readCheckpoints()) {
    const r = await anchorer.anchor(seq);
    if (r.attached.length !== 1) {
      throw new Error(`the witnessed baseline did not anchor checkpoint ${seq}: ${JSON.stringify(r.failed)}`);
    }
  }
  // What the auditor independently holds, retained by the witness.
  const disclosed = witness.roots(ORIGIN).map((x) => ({ tree_size: x.tree_size, root: x.root }));
  const policy = {
    quorum: 1,
    witnesses: [{ id: WITNESS, establishes: ['sequence'], public_key: wkey.publicKey.toString('base64') }],
  };
  return { ...ctx, witness, wkey, disclosed, policy };
}

/** @param {string} blob */
function parseNoteLines(blob) {
  return blob.trimEnd().split('\n');
}

const chainPath = (root) => path.join(root, 'chain', `${COLLECTOR}.jsonl`);
const lines = (root) => fs.readFileSync(chainPath(root), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const write = (root, ls) => fs.writeFileSync(chainPath(root), ls.map((l) => JSON.stringify(l)).join('\n') + '\n');
const saltOf = (root, seq) => {
  const f = path.join(root, 'salts', `${COLLECTOR}.jsonl`);
  for (const l of fs.readFileSync(f, 'utf8').trim().split('\n')) {
    const e = JSON.parse(l);
    if (e.record_seq === seq) return Buffer.from(e.salt, 'hex');
  }
  return null;
};

/** Re-leaf and re-chain a tampered store from genesis — the AC-2 repair. */
function repairChain(root) {
  const ls = lines(root);
  let prev = genesis();
  for (const l of ls) {
    const salt = saltOf(root, l.record.record_seq);
    l.leaf = leafDigest(salt, l.record).toString('hex');
    l.prev = prev.toString('hex');
    l.head = chainHead(prev, Buffer.from(l.leaf, 'hex')).toString('hex');
    prev = Buffer.from(l.head, 'hex');
  }
  write(root, ls);
}

/**
 * Re-sign ONE checkpoint at its own committed size, leaving the others alone.
 * reSign() below rewrites it at the log's current size, which is a different
 * attack: this one keeps the note's claim and changes only who signed it.
 */
async function reSignAt(root, signer, seq) {
  const env = JSON.parse(
    fs.readFileSync(path.join(root, 'checkpoints', COLLECTOR, `${seq}.json`), 'utf8'));
  const { parseNote } = await import('@splitstick/core/note');
  const text = parseNote(env.note).text;
  writeCheckpointBlob(root, seq, encodeNote(text, [await signNote(text, signer)]));
}

/**
 * Replace a checkpoint's note, keeping the DES-20 envelope around it. The
 * attacker controls the directory, so they can do this; what they cannot do is
 * make the envelope's digest agree with a note they did not also rewrite.
 */
function writeCheckpointBlob(root, seq, blob) {
  const p = path.join(root, 'checkpoints', COLLECTOR, `${seq}.json`);
  // Attack D deletes the directory's contents first, so the envelope may be
  // gone. An attacker writing a fresh one is exactly as able as an attacker
  // editing one, and pretending otherwise would weaken the attack.
  const env = fs.existsSync(p)
    ? JSON.parse(fs.readFileSync(p, 'utf8'))
    : { note: blob, note_digest: '', countersignatures: [] };
  env.note = blob;
  env.note_digest = noteDigest(blob);
  fs.writeFileSync(p, JSON.stringify(env, null, 1) + '\n');
}

/** Re-sign the current log under the same key — the AC-3 escalation. */
async function reSign(root, signer, seq = 1) {
  const leaves = lines(root).map((l) => Buffer.from(l.leaf, 'hex'));
  const text = checkpointText({ origin: ORIGIN, tree_size: leaves.length, root: treeRoot(leaves) });
  writeCheckpointBlob(root, seq, encodeNote(text, [await signNote(text, signer)]));
}


const attacks = [
  {
    id: 'A1', gate: 'AC-1', expect: 'detected',
    name: 'edit the recorded arguments',
    note: 'EUR 2,000,000 -> EUR 25 in the record. The leaf no longer reproduces.',
    async apply({ root }) {
      const ls = lines(root);
      const target = ls.find((l) => l.record.tool === 'transfer_funds' && l.record.args);
      target.record.args.cid = 'sha256:' + 'ab'.repeat(32);
      write(root, ls);
    },
  },
  {
    id: 'A2', gate: 'AC-1', expect: 'detected',
    name: 'swap the stored payload, keep the pointer',
    note: 'The cid is a salted hash OF THE PLAINTEXT, so substitution moves it. This is the hole an external review found in an earlier draft of DES-13.',
    async apply({ root, store }) {
      const target = lines(root).find((l) => l.record.args);
      store.content.overwriteForTest(target.record.args.cid, Buffer.from('{"amount":25}'));
    },
  },
  {
    id: 'A3', gate: 'AC-1', expect: 'detected',
    name: 'edit the recorded result',
    note: 'The authoritative side-effect record. Attack A against OMA passes verifyRun() unchanged.',
    async apply({ root }) {
      const ls = lines(root);
      const target = ls.find((l) => l.record.result);
      target.record.result.ok = false;
      write(root, ls);
    },
  },
  {
    id: 'B', gate: 'AC-1', expect: 'detected',
    name: 'naive single-field edit',
    note: 'Must not regress: this is the one class OMA already catches.',
    async apply({ root }) {
      const ls = lines(root);
      const target = ls.find((l) => l.record.kind === 'tool_call');
      target.record.outcome = 'denied';
      write(root, ls);
    },
  },
  {
    id: 'C', gate: 'AC-2', expect: 'detected',
    name: 'consistent edit + repaired chain',
    note: 'Re-leaf the altered record and recompute every head from genesis. The chain is then internally perfect — and the signed checkpoint root is not the root of it.',
    async apply(ctx) {
      const ls = lines(ctx.root);
      const target = ls.find((l) => l.record.result);
      target.record.result.ok = false;
      write(ctx.root, ls);
      repairChain(ctx.root);
    },
  },
  {
    id: 'C2', gate: 'AC-3', expect: 'undetected', expect_witnessed: 'detected', closes: 'M2 (non-exportable custody) + M3a (countersignature)',
    name: 'consistent edit + repaired chain + re-signed checkpoint',
    note: 'The operator holds the signing key, so they can sign the rewritten history. Nothing local can refuse this. A countersignature over the original root is what contradicts it, which is why AC-3 is not an M1 gate.',
    async apply(ctx) {
      await attacks.find((a) => a.id === 'C').apply(ctx);
      await reSign(ctx.root, ctx.signer);
    },
  },
  {
    id: 'C3', gate: 'AC-3', expect: 'detected',
    name: 'rewrite history and re-sign only the older checkpoint with the current epoch key',
    note: 'What M2 actually buys, demonstrated. The operator rotated twice, so the retired keys are gone and they can only re-sign with today\'s. Doing it to one checkpoint leaves the epochs running backwards as the ordinals run forwards, which no honest sequence produces. Doing it to ALL of them — C2 — leaves the epochs equal and is still undetected locally.',
    async apply(ctx) {
      // Two rotations, with a checkpoint taken from the middle epoch, so the
      // re-signed note is attributable to an epoch LATER than the one after it.
      const second = await generateDevSigner(ORIGIN);
      await ctx.collector.rotate(second);
      ctx.collector.heartbeat();
      await ctx.collector.checkpoint();
      const third = await generateDevSigner(ORIGIN);
      await ctx.collector.rotate(third);
      await attacks.find((a) => a.id === 'C').apply(ctx);
      await reSignAt(ctx.root, third, 1);
    },
  },
  {
    id: 'D', gate: 'AC-4', expect: 'undetected', expect_witnessed: 'detected', closes: 'M3a (stateful witness) + DES-19 cross-pack comparison',
    name: 'truncate the tail and drop the checkpoints above it',
    note: 'A chain over a prefix is internally perfect. The attacker controls the directory, so the stale checkpoint goes too — leaving it behind is what makes D2 detectable, and nothing forces them to.',
    async apply(ctx) {
      const ls = lines(ctx.root);
      ls.pop();
      write(ctx.root, ls);
      const dir = path.join(ctx.root, 'checkpoints', COLLECTOR);
      for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f));
      await reSign(ctx.root, ctx.signer, 1);
    },
  },
  {
    id: 'D2', gate: 'AC-4', expect: 'detected',
    name: 'truncate but leave a checkpoint committing to more records',
    note: 'A checkpoint that commits to a tree size the log no longer reaches is a contradiction. This catches only the attacker who leaves their own evidence in place; what they cannot delete is a checkpoint already DISCLOSED to someone else, which is DES-19 mechanism 1 and arrives in M3a.',
    async apply({ root }) {
      const ls = lines(root);
      write(root, ls.slice(0, Math.max(1, ls.length - 1)));
    },
  },
  {
    id: 'E', gate: 'AC-1', expect: 'detected',
    name: 'duplicate a record_seq',
    note: 'Breaks the stream invariant, which is what the sequence check is for.',
    async apply({ root }) {
      const ls = lines(root);
      ls[ls.length - 1].record.record_seq = ls[0].record.record_seq;
      write(root, ls);
    },
  },
  {
    id: 'F', gate: 'AC-5', expect: 'detected',
    name: 'erase a record from the middle',
    note: 'Without a repair the sequence and the chain both contradict it.',
    async apply({ root }) {
      const ls = lines(root);
      ls.splice(1, 1);
      write(root, ls);
    },
  },
  {
    id: 'F2', gate: 'AC-5', expect: 'detected',
    name: 'erase a record and renumber record_seq only',
    note: 'There are two counters to repair, not one. Renumbering record_seq leaves a hole in source_seq, and observation gaps are read from consecutive persisted source_seq values independently of record_seq (DES-04 rule 2).',
    async apply(ctx) {
      erase(ctx.root, { renumberSource: false });
      repairChain(ctx.root);
      await reSign(ctx.root, ctx.signer);
    },
  },
  {
    id: 'F3', gate: 'AC-5', expect: 'undetected', expect_witnessed: 'detected', closes: 'M3a (countersignature) + DES-19 counterparty reconciliation',
    name: 'erase a record, renumber BOTH counters, repair and re-sign',
    note: 'The thorough version of F2. The action never appears at all and nothing internal remembers it did. Reconciliation from the counterparty side is the answer here, not cryptography.',
    async apply(ctx) {
      erase(ctx.root, { renumberSource: true });
      repairChain(ctx.root);
      await reSign(ctx.root, ctx.signer);
    },
  },
];

/**
 * Remove the second record and renumber what is left.
 *
 * Renumbering record_seq orphans the salts, which are keyed by it, so they are
 * rewritten in order. With renumberSource the observation counter is closed up
 * too, which is what an interested party who had read DES-04 would do.
 * @param {string} root
 * @param {{ renumberSource: boolean }} opts
 */
function erase(root, opts) {
  const ls = lines(root);
  const saltFile = path.join(root, 'salts', `${COLLECTOR}.jsonl`);
  const salts = fs.readFileSync(saltFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const bySeq = new Map(salts.map((e) => [e.record_seq, e.salt]));
  const kept = ls.filter((_, i) => i !== 1);
  const keptSalts = kept.map((l) => bySeq.get(l.record.record_seq));

  let source = 0;
  kept.forEach((l, i) => {
    l.record.record_seq = i + 1;
    if (opts.renumberSource && typeof l.record.source_seq === 'number') {
      l.record.source_seq = ++source;
    }
  });
  fs.writeFileSync(saltFile, kept.map((l, i) =>
    JSON.stringify({ record_seq: l.record.record_seq, salt: keptSalts[i] })).join('\n') + '\n');
  write(root, kept);
}

const baseline = await build();
const baseReport = await verifyStore(baseline.root, { collector: COLLECTOR, vkey: baseline.vkey });
console.log(`\nbaseline            ${baseReport.summary.failed === 0 ? 'VERIFIES' : 'BROKEN'}   ` +
  `(verdict ${baseReport.verdict.toUpperCase()}, ${baseReport.tree_size} records, ` +
  `${baseReport.summary.passed} checks passed, ${baseReport.summary.unanswered} unanswered)\n`);
if (baseReport.summary.failed !== 0) {
  console.error('Baseline does not verify. Findings:');
  console.error(JSON.stringify(baseReport.findings, null, 2));
  process.exit(1);
}

/**
 * The witnessed baseline, so the second run's "detected" means something: if
 * the witnessed configuration failed to verify on an untampered store, every
 * attack would read as detected for the wrong reason.
 */
const wBase = await buildWitnessed();
const wBaseReport = await verifyStore(wBase.root, {
  collector: COLLECTOR, vkey: wBase.vkey, policy: wBase.policy, disclosed: wBase.disclosed,
});
if (wBaseReport.summary.failed !== 0) {
  console.error('The WITNESSED baseline does not verify, so no witnessed result below means anything.');
  console.error(JSON.stringify(wBaseReport.findings, null, 2));
  process.exit(1);
}
console.log(`witnessed baseline  VERIFIES   (sequence quorum `
  + `${wBaseReport.quorum.observed.sequence}/${wBaseReport.quorum.required}, `
  + `${wBase.disclosed.length} height(s) independently retained)\n`);

let mismatches = 0;
/** @type {import('./gates.mjs').Observation[]} */
const observations = [];
const codesOf = (/** @type {any} */ report) =>
  [...new Set(report.findings.filter((/** @type {any} */ f) => f.verdict === 'fail')
    .map((/** @type {any} */ f) => f.code))].join(', ');

for (const attack of attacks) {
  // Run 1 — files alone. What a reader with the store and nothing else sees.
  const ctx = await build();
  await attack.apply(ctx);
  const report = await verifyStore(ctx.root, { collector: COLLECTOR, vkey: ctx.vkey });
  const observed = report.summary.failed > 0 ? 'detected' : 'undetected';
  const label = observed === 'detected' ? 'DETECTED    ' : 'UNDETECTED >>';
  const drift = observed === attack.expect ? '' : '   <-- CHANGED from expected: ' + attack.expect;
  if (observed !== attack.expect) mismatches += 1;

  // Run 2 — the same attack against a store a stateful witness countersigned,
  // verified by a reader holding the witness's retained heights.
  const wctx = await buildWitnessed();
  await attack.apply(wctx);
  const wReport = await verifyStore(wctx.root, {
    collector: COLLECTOR, vkey: wctx.vkey, policy: wctx.policy, disclosed: wctx.disclosed,
  });
  const wObserved = wReport.summary.failed > 0 ? 'detected' : 'undetected';
  const wExpect = attack.expect_witnessed ?? attack.expect;
  const wDrift = wObserved === wExpect ? '' : '   <-- CHANGED from expected: ' + wExpect;
  if (wObserved !== wExpect) mismatches += 1;

  observations.push({
    id: attack.id, gate: attack.gate, expect: attack.expect, observed,
    expect_witnessed: wExpect, observed_witnessed: wObserved,
  });

  console.log(`${label}  ${attack.id}. ${attack.name}   [${attack.gate}]${drift}`);
  console.log(`               ${attack.note}`);
  if (codesOf(report)) console.log(`               files alone:       ${codesOf(report)}`);
  console.log(`               with a witness:    ${wObserved.toUpperCase()}`
    + `${codesOf(wReport) ? '   ' + codesOf(wReport) : ''}${wDrift}`);
  if (attack.closes) console.log(`               closed by:         ${attack.closes}`);
  console.log();
}

const localDetected = observations.filter((o) => o.observed === 'detected');
const localOpen = observations.filter((o) => o.observed !== 'detected');
const witnessedOpen = observations.filter((o) => o.observed_witnessed !== 'detected');
console.log(`${localDetected.length} of ${attacks.length} tampers are detected from files alone.`);
console.log(`${localOpen.length} are not: ${localOpen.map((o) => o.id).join(', ')}.`);
console.log(`With a stateful witness configured and its retained heights in the reader's hands, `
  + `${attacks.length - witnessedOpen.length} of ${attacks.length} are detected.`);
if (witnessedOpen.length > 0) {
  console.log(`Still open even then: ${witnessedOpen.map((o) => o.id).join(', ')}.`);
}
console.log('That difference is the whole argument: none of it is new cryptography, all of it is a');
console.log('second party. A notary you supply to yourself is not a notary.\n');

// Which gates must hold is read from the plan, and whether they hold is read
// from what the attacks actually did — not from what they declare. Both were
// wrong in the first version: it listed the gates literally, and it treated a
// declaration of "detected" as a result. See redteam/gates.mjs.
const plan = JSON.parse(fs.readFileSync('requirements/milestones.json', 'utf8'));
const result = evaluateGates(plan, observations);
console.log(formatGates(result));
console.log();

if (result.unmet > 0) {
  console.error(`${result.unmet} attack class(es) claimed by a shipped milestone are not closed.`);
  process.exit(1);
}

if (mismatches > 0) {
  console.error(`${mismatches} observation(s) changed. Update this file, or fix what moved.`);
  process.exit(1);
}
