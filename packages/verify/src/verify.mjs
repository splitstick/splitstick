/**
 * splitstick verify — DES-12, FR-29.
 *
 * Three verdicts, not two, borrowed directly from OMA, which gets this right
 * and which our own red team confirmed: a log that lawfully erased content is
 * not the same as a log that contradicts itself, and conflating them either
 * cries wolf or hides a tamper.
 *
 *   ok            every check that could run, ran, and passed
 *   fail          the evidence contradicts itself
 *   inconclusive  a check could not be answered — absence of evidence, as such
 *
 * A single `fail` makes the whole run `fail`. `inconclusive` never upgrades to
 * `fail` and never downgrades to `ok`.
 *
 * Offline by construction (NFR-05, NFR-06): this opens files and does
 * arithmetic. No network call, no credential, no notion of an account. Trust
 * anchors arrive as an input, not from a registry — and a test asserts that no
 * module in this package imports a network module at all, because a comment
 * saying "offline" is not a check.
 *
 * M1 runs checks 1-6 of DES-12's ten. WITNESS, ROLLUP, COVERAGE and POLICY need
 * evidence M1 does not yet produce, so they are reported as inconclusive with a
 * reason rather than silently skipped — and the capability statement says in
 * plain words what this set of evidence cannot establish.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { recomputeChain } from '@splitstick/core/chain';
import { treeRoot, prefixRoots, consistencyProof, verifyConsistency } from '@splitstick/core/merkle';
import { parseNote, parseCheckpointText, parseVkey, SUITES } from '@splitstick/core/note';
import { verifyNoteSignature } from '@splitstick/core/signer';
import { successionReport } from '@splitstick/core/succession';
import { validateFindings, verdictFor } from '@splitstick/core/findings';
import { CAPABILITY_CLASSES } from '@splitstick/core/anchor';
import { verifyTimeStampToken } from '@splitstick/core/rfc3161';
import { describeOtsProof } from '@splitstick/core/opentimestamps';
import { parseEnvelope } from '@splitstick/core/envelope';
import { createHash as nodeCreateHash } from 'node:crypto';

/**
 * @typedef {object} WitnessEntry
 * @property {string} id
 * @property {string} type
 * @property {string} establishes
 * @property {boolean} accepted
 * @property {Verdict} verdict
 * @property {string} detail
 * @property {number} checkpoint_seq the checkpoint this proof sits on. Every
 *   detail string already began "checkpoint N:", so the attribution was in the
 *   prose and not in the data — and a caller asking "is THIS record anchored?"
 *   had no way to tell which of these entries spoke to it.
 * @property {number|null} tree_size the size that checkpoint committed to. A
 *   proof on a checkpoint whose tree reaches record N is evidence about record
 *   N; one on an earlier checkpoint is not, however well it verifies.
 * @property {string} [received_at] FR-39 — the witness's own clock
 * @property {'absent'|'witness-asserted, unsigned'|'signed by the TSA, inside the token'}
 *   [received_at_basis] what that value rests on. A C2SP note has nowhere
 *   inside it to carry a time, so the value sits beside the proof rather than
 *   under it, and the report says which.
 * @property {number} [unwitnessed_for_ms] how long the batch went unwitnessed
 * @property {number} [clock_disagreement] by how much the witness's clock is
 *   EARLIER than the batch's self-asserted ts
 */

/**
 * RFC 3339 with milliseconds and a Z, the same shape DES-01 requires of every
 * timestamp. Used for FR-39's receipt time because `Date.parse` is lenient: it
 * reads "12345" as the year 12345, which would produce a receipt time ten
 * thousand years out and an unwitnessed window to match.
 */
const RECEIPT_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

import { noteKeyId } from '@splitstick/core/note';

/** @typedef {'ok'|'fail'|'inconclusive'} Verdict */

/**
 * @typedef {object} Finding
 * @property {string} code
 * @property {Verdict} verdict
 * @property {number} [record_seq]
 * @property {string} detail what a reader may conclude — "verification failed" is useless alone
 */

/** @param {Verdict[]} vs @returns {Verdict} */
function combine(vs) {
  if (vs.includes('fail')) return 'fail';
  if (vs.includes('inconclusive')) return 'inconclusive';
  return 'ok';
}

/**
 * A memoised prefix-root lookup — NFR-04.
 *
 * `treeRoot(leaves.slice(0, n))` once per checkpoint is O(checkpoints · n) and
 * was the single largest cost in verification: 585 ms of a 2.3 s run over
 * 8,000 records, which extrapolates to about 59 s at the 100,000 NFR-04 names.
 * `prefixRoots` computes every requested prefix in one left-to-right pass.
 *
 * Lazy and batched: the first call collects nothing, so the sizes are gathered
 * up front by the caller. A root for a size beyond the leaves is undefined,
 * which the SIZE_REGRESSED check above handles before asking.
 *
 * @param {Buffer[]} leaves @param {number[]} sizes
 */
function rootsFor(leaves, sizes) {
  const map = prefixRoots(leaves, sizes.filter(n => n <= leaves.length));
  /** @param {number} n */
  return (n) => map.get(n) ?? treeRoot(leaves.slice(0, n));
}

/**
 * @param {string} root the store directory
 * @param {object} [opts]
 * @param {string} [opts.collector] the collector instance whose chain to read
 * @param {string} [opts.vkey] the pinned operator identity, as a note vkey
 * @param {{ quorum?: number, witnesses?: { id: string, public_key?: string,
 *   establishes?: string[], anchors?: string[], tier?: 'anchor'|'rollup',
 *   key_history?: { keys?: { public_key?: string }[], note?: string } }[] }} [opts.policy]
 *   FR-30 — the ACCEPTANCE POLICY,
 *   supplied by the reader. Not a hardcoded trust store: two readers with
 *   different trust must be able to reach different conclusions from one pack,
 *   and a verifier that only accepted witnesses we operate would make
 *   independence impossible to demonstrate (INT-02).
 * @param {{ tree_size: number, root: string, issuers?: string[] }[]} [opts.disclosed]
 *   FR-54, SEC-26 — heights already disclosed in another pack, for the
 *   cross-pack comparison
 * @returns {Promise<{
 *   verdict: Verdict, tree_size: number, anchored_tree_size: number,
 *   records: { tree_size: number, by_kind: Record<string, number>, padding: number, real: number },
 *   summary: { passed: number, unanswered: number, failed: number },
 *   checks: { name: string, verdict: Verdict, detail?: string }[],
 *   findings: Finding[],
 *   witnesses: WitnessEntry[],
 *   quorum: { required: number, observed: Record<string, number>, met: Record<string, boolean> },
 *   capability: { can: string[], cannot: string[] },
 *   trusting: string[],
 *   succession: ReturnType<typeof successionReport>|null,
 * }>}
 */
export async function verifyStore(root, opts = {}) {
  const probe = new Store(root, opts.collector ?? 'unknown');
  const available = probe.collectors();
  const collector = opts.collector ?? (available[0] ?? 'unknown');
  const store = opts.collector ? probe : new Store(root, collector);
  /** @type {Finding[]} */
  const findings = [];

  // A store may hold several collectors (FR-56 scopes a chain to an instance).
  // Picking the first and saying nothing would show a reader one chain while
  // another sat beside it unexamined.
  if (!opts.collector && available.length > 1) {
    findings.push({
      code: 'MULTIPLE_COLLECTORS', verdict: 'inconclusive',
      detail: `this store holds ${available.length} collector chains (${available.join(', ')}); `
        + `only ${collector} was verified. Name one explicitly to verify it.`,
    });
  }
  /** @type {{ name: string, verdict: Verdict, detail?: string }[]} */
  const checks = [];
  /** @param {string} name @param {Verdict} verdict @param {string} [detail] */
  const check = (name, verdict, detail) => { checks.push({ name, verdict, ...(detail ? { detail } : {}) }); };

  const stray = store.unattributedCheckpoints();
  if (stray.length > 0) {
    findings.push({
      code: 'CHECKPOINTS_UNATTRIBUTED', verdict: 'inconclusive',
      detail: `${stray.length} note(s) sit directly in checkpoints/ and belong to no collector `
        + `(${stray.join(', ')}); they were not checked against this chain, because a note that `
        + 'cannot be attributed cannot be evidence about a particular log',
    });
  }

  const { entries, torn, malformed } = store.readChainDetailed();

  // A crash during an append leaves a partial final line. That is the ordinary
  // consequence of a crash, so it is reported and the complete records before
  // it are still verified. Anywhere other than the end, a broken line means the
  // file was edited.
  if (torn) {
    findings.push({
      code: 'TORN_WRITE', verdict: 'inconclusive',
      detail: 'the last line of the chain is incomplete, which is what a crash during an append leaves behind; the records before it verify normally',
    });
  }
  for (const m of malformed) {
    findings.push({
      code: 'MALFORMED_RECORD', verdict: 'fail', record_seq: undefined,
      detail: `chain line ${m.line} is not a readable record and is not at the end of the file, so it was altered rather than half-written: ${m.reason}`,
    });
  }

  if (entries.length === 0) {
    findings.push({ code: 'NO_EVIDENCE', verdict: 'inconclusive', detail: `no chain for collector ${collector} under ${root}` });
    return report(0, 0, checks, findings, [], collector, opts.vkey);
  }

  // 1 FORMAT, 2 SEQUENCE, 3 CHAIN, 4 LEAF — recomputeChain runs these in order
  // and stops at an unreadable record rather than guessing (DES-16).
  const chain = recomputeChain(entries);
  for (const f of chain.findings) {
    findings.push({
      code: f.code,
      // From the specification, not from the code's name. The name heuristic
      // was right only by luck: TORN_WRITE is specified inconclusive and does
      // not end in _INCONCLUSIVE.
      verdict: verdictFor(f.code),
      ...(f.record_seq === undefined ? {} : { record_seq: f.record_seq }),
      detail: f.detail,
    });
  }
  const seqF = findings.filter(f => f.code === 'SEQ_BROKEN');
  const chainF = findings.filter(f => f.code === 'CHAIN_BROKEN');
  const leafF = findings.filter(f => f.code.startsWith('LEAF_'));
  const fmtF = findings.filter(f => f.code === 'FORMAT_UNSUPPORTED');
  check('FORMAT', fmtF.length ? 'fail' : 'ok');
  check('SEQUENCE', seqF.length ? 'fail' : 'ok');
  check('CHAIN', chainF.length ? 'fail' : 'ok');
  check('LEAF', combine(leafF.map(f => f.verdict)));

  // 4b CONTENT — the commitment is over the plaintext (FR-35), so a swapped
  // payload is a finding here. Missing content is inconclusive: shredded by
  // design, retained elsewhere, or lost, and the pack cannot tell them apart.
  /** @type {Verdict[]} */
  const contentVs = [];
  for (const e of entries) {
    for (const [field, c] of commitments(e.record)) {
      const r = store.content.reproduces(c);
      if (r === true) { contentVs.push('ok'); continue; }
      if (r === null) {
        contentVs.push('inconclusive');
        findings.push({
          code: 'CONTENT_ABSENT', verdict: 'inconclusive', record_seq: Number(e.record.record_seq),
          detail: `${field} is not in the store: shredded by design, retained elsewhere, or lost`,
        });
        continue;
      }
      contentVs.push('fail');
      findings.push({
        code: 'CONTENT_MISMATCH', verdict: 'fail', record_seq: Number(e.record.record_seq),
        detail: `the stored ${field} does not reproduce its commitment: the payload was substituted`,
      });
    }
  }
  check('CONTENT', contentVs.length ? combine(contentVs) : 'inconclusive',
    contentVs.length ? undefined : 'no commitments to reproduce');

  // 5 TREE, 6 OP-SIG — over the checkpoints on disk.
  const notes = store.readCheckpoints();
  /** @type {Verdict[]} */
  const treeVs = [];
  /** @type {Verdict[]} */
  const sigVs = [];
  /** @type {{ seq: number, epoch: number }[]} which epoch signed which checkpoint */
  const signedBy = [];
  /** @type {{ seq: number, env: ReturnType<typeof parseEnvelope> }[]} */
  const envelopes = [];
  const pinned = opts.vkey ? parseVkey(opts.vkey) : null;
  const leaves = entries.map(e => e.leaf);
  // Every prefix size anybody below will ask about, in one pass. Gathering
  // them up front is what turns O(checkpoints · n) into O(n log n).
  const rootAt = rootsFor(leaves, [
    ...store.readCheckpoints().map(({ blob }) => parseEnvelope(blob).tree_size ?? 0),
    ...(opts.disclosed ?? []).map(d => Number(d.tree_size)),
  ]);
  let anchored = 0;

  // FR-11 — the succession chain, walked from the pinned root before any
  // signature is checked, because it decides WHICH keys may sign at all.
  //
  // In M1 a verifier pinned one key and demanded every checkpoint carry its
  // signature. With a ratchet that is wrong: later checkpoints are signed by
  // later epoch keys, and the pinned root's job is to endorse a path to them
  // rather than to sign everything itself. One pinned key, every epoch
  // attributed — that is the property, and it is what makes rotation possible
  // without re-pinning.
  const succRaw = store.readSuccessionDetailed();
  /** @type {ReturnType<typeof successionReport>|null} */
  let succession = null;
  /** @type {Map<string, { epoch: number, publicKey: Buffer }>} keyId hex -> epoch */
  const epochKeys = new Map();
  if (succRaw.torn) {
    findings.push({
      code: 'TORN_WRITE', verdict: 'inconclusive',
      detail: 'the succession journal ends mid-entry, so the newest epoch it was recording is not readable',
    });
  }
  for (const line of succRaw.malformed) {
    findings.push({
      code: 'MALFORMED_RECORD', verdict: 'fail',
      detail: `succession journal line ${line} is not readable, so the epoch chain cannot be walked past it`,
    });
  }
  if (succRaw.entries.length === 0) {
    check('SUCCESSION', 'inconclusive',
      'no succession journal in this store: one epoch, or a store written before the ratchet (FR-11)');
  } else if (!pinned) {
    check('SUCCESSION', 'inconclusive',
      'a succession chain is present but no operator identity was pinned, so it is walked from nothing');
  } else {
    succession = successionReport(pinned.publicKey, succRaw.entries);
    for (const f of succession.findings) {
      findings.push({
        code: f.code,
        verdict: 'fail',
        detail: f.detail,
      });
    }
    check('SUCCESSION', succession.ok ? 'ok' : 'fail',
      succession.ok
        ? `${succession.epochs.length} epoch(s) attributed to the pinned root`
        : 'the epoch chain does not walk from the pinned root');
    if (succession.ok) {
      for (const e of succession.epochs) {
        const publicKey = Buffer.from(e.public_key, 'base64');
        epochKeys.set(noteKeyId(pinned.name, publicKey).toString('hex'), { epoch: e.epoch, publicKey });
      }
    }
  }

  if (notes.length === 0) {
    treeVs.push('inconclusive');
    sigVs.push('inconclusive');
    findings.push({ code: 'UNANCHORED', verdict: 'inconclusive', detail: 'no checkpoint on disk: nothing commits to a tree size' });
  }

  for (const { seq, blob, format, legacy_note } of notes) {
    /** @type {ReturnType<typeof parseNote>} */
    let note;
    /** @type {ReturnType<typeof parseCheckpointText>} */
    let cp;

    // DES-20 — the envelope is checked before the note inside it, because the
    // envelope is what says these countersignatures are over THESE bytes. A
    // wrong note_digest makes every entry vouch for something that is not here,
    // and reading the note first would verify the signature and miss that.
    const env = parseEnvelope(blob, legacy_note === undefined ? {} : { expectNote: legacy_note });
    for (const f of env.findings) {
      // The verdict comes from the specification, not from this call site. It
      // used to be a ternary whose branches were both 'fail' — which looked
      // like a decision and was not one — and that made a duplicated witness
      // retry fail the whole verification. A retry that landed twice is a
      // benign operational event the witness itself treats as idempotent.
      findings.push({
        code: f.code,
        verdict: verdictFor(f.code),
        detail: `checkpoint ${seq}: ${f.detail}`,
      });
    }
    if (!env.ok || env.note === null) {
      treeVs.push('fail');
      continue;
    }
    envelopes.push({ seq, env });

    try {
      note = parseNote(env.note);
      cp = parseCheckpointText(note.text);
    } catch (e) {
      treeVs.push('fail');
      findings.push({ code: 'FORMAT_UNSUPPORTED', verdict: 'fail', detail: `checkpoint ${seq}: ${e instanceof Error ? e.message : String(e)}` });
      continue;
    }

    // DES-16 — a verifier either knows a suite or refuses the batch. An absent
    // suite is inconclusive, not assumed to be the current one: a checkpoint
    // that does not say what it was signed under cannot be read years later.
    if (cp.suite === null) {
      findings.push({
        code: 'SUITE_UNDECLARED', verdict: 'inconclusive',
        detail: `checkpoint ${seq} declares no algorithm suite, so which primitives it was signed under is not recorded`,
      });
    } else if (!SUITES.includes(cp.suite)) {
      treeVs.push('fail');
      findings.push({
        code: 'FORMAT_UNSUPPORTED', verdict: 'fail',
        detail: `checkpoint ${seq} declares algorithm suite ${cp.suite}, which this verifier does not implement: it never guesses and never partially verifies`,
      });
      continue;
    }

    if (cp.tree_size > leaves.length) {
      treeVs.push('fail');
      findings.push({
        code: 'SIZE_REGRESSED', verdict: 'fail',
        detail: `checkpoint ${seq} commits to ${cp.tree_size} records but the log holds ${leaves.length}: the tail was removed below a size already committed`,
      });
    } else if (!rootAt(cp.tree_size).equals(cp.root)) {
      treeVs.push('fail');
      findings.push({
        code: 'TREE_MISMATCH', verdict: 'fail',
        detail: `checkpoint ${seq}'s root is not the root of this log's first ${cp.tree_size} records`,
      });
    } else {
      treeVs.push('ok');
      if (cp.tree_size > anchored) anchored = cp.tree_size;
    }

    if (!pinned) {
      sigVs.push('inconclusive');
      findings.push({
        code: 'OPSIG_UNCHECKED', verdict: 'inconclusive',
        detail: `checkpoint ${seq} is signed, but no operator identity was pinned, so the signature means nothing to this reader`,
      });
      continue;
    }
    if (cp.origin !== pinned.name) {
      sigVs.push('fail');
      findings.push({
        code: 'IDENTITY_UNPINNED', verdict: 'fail',
        detail: `checkpoint ${seq} declares origin ${cp.origin}; this reader pinned ${pinned.name}. Nothing prevents an operator keeping a second log — this is how you are told you are being shown another.`,
      });
      continue;
    }
    const sig = note.signatures.find(s => s.name === pinned.name);
    if (!sig) {
      sigVs.push('fail');
      findings.push({ code: 'OPSIG_INVALID', verdict: 'fail', detail: `checkpoint ${seq} carries no signature line for ${pinned.name}` });
      continue;
    }
    // Which key signed this note is read off the note's own key id, then
    // looked up in the walked chain. A signature by a key the chain does not
    // contain is not a weaker signature: it is an unattributable one.
    const attributed = epochKeys.size > 0
      ? epochKeys.get(sig.keyId.toString('hex'))
      : (sig.keyId.equals(pinned.keyId) ? { epoch: 0, publicKey: pinned.publicKey } : undefined);
    if (!attributed) {
      sigVs.push('fail');
      findings.push({
        code: 'OPSIG_INVALID', verdict: 'fail',
        detail: epochKeys.size > 0
          ? `checkpoint ${seq} is signed by a key that is not any epoch in the succession chain walked from the pinned root`
          : `checkpoint ${seq} is not signed by the operator identity it claims`,
      });
      continue;
    }
    if (await verifyNoteSignature(note.text, sig,
      { name: pinned.name, publicKey: attributed.publicKey, keyId: noteKeyId(pinned.name, attributed.publicKey) })) {
      sigVs.push('ok');
      signedBy.push({ seq, epoch: attributed.epoch });
    } else {
      sigVs.push('fail');
      findings.push({
        code: 'OPSIG_INVALID', verdict: 'fail',
        detail: `checkpoint ${seq} declares a key id from epoch ${attributed.epoch} but the signature does not verify under that epoch's key`,
      });
    }
  }

  // SEC-08 — epochs run forwards as ordinals do.
  //
  // A checkpoint re-signed with a later key is attributed to a later epoch
  // than one that comes after it, which no honest sequence produces: an epoch
  // is retired before its successor exists. Each signature is individually
  // valid, so only the ordering across them shows the rewrite.
  //
  // This catches a PARTIAL re-sign. It does not catch re-signing everything
  // with the live key, which leaves the epochs equal and is locally
  // indistinguishable from rotating without checkpointing in between. That gap
  // is AC-3, and it closes in M3a against a countersignature over the original
  // root — not here. The capability statement says so rather than leaving a
  // reader to assume this check reaches further than it does.
  signedBy.sort((a, b) => a.seq - b.seq);
  for (let i = 1; i < signedBy.length; i += 1) {
    const prev = /** @type {{ seq: number, epoch: number }} */ (signedBy[i - 1]);
    const cur = /** @type {{ seq: number, epoch: number }} */ (signedBy[i]);
    if (cur.epoch < prev.epoch) {
      findings.push({
        code: 'OPSIG_EPOCH_REGRESSED', verdict: 'fail',
        detail: `checkpoint ${cur.seq} is signed by epoch ${cur.epoch} but the earlier checkpoint ${prev.seq} is signed by epoch ${prev.epoch}: an epoch is retired before its successor exists, so signing order cannot run backwards unless a checkpoint was re-signed later`,
      });
    }
  }
  // Append-only is CHECKED, not assumed (DES-04 rule 4). Every checkpoint must
  // be a prefix of the next: a later one committing to fewer records, or to a
  // history that does not extend the earlier one, is a rollback. merkle.mjs had
  // implemented and tested consistency proofs that nothing called.
  const sized = notes
    .map(n => { try { return { seq: n.seq, cp: parseCheckpointText(parseNote(n.note).text) }; } catch { return null; } })
    .filter(x => x !== null)
    .sort((a, b) => a.seq - b.seq);
  for (let i = 1; i < sized.length; i++) {
    const prev = /** @type {{ seq: number, cp: ReturnType<typeof parseCheckpointText> }} */ (sized[i - 1]);
    const cur = /** @type {{ seq: number, cp: ReturnType<typeof parseCheckpointText> }} */ (sized[i]);
    if (cur.cp.tree_size < prev.cp.tree_size) {
      treeVs.push('fail');
      findings.push({
        code: 'CONSISTENCY_BROKEN', verdict: 'fail',
        detail: `checkpoint ${cur.seq} commits to ${cur.cp.tree_size} records after checkpoint ${prev.seq} committed to ${prev.cp.tree_size}: a log cannot shrink`,
      });
      continue;
    }
    if (cur.cp.tree_size > leaves.length) continue;   // already reported as SIZE_REGRESSED
    const proof = consistencyProof(leaves.slice(0, cur.cp.tree_size), prev.cp.tree_size);
    if (!verifyConsistency(prev.cp.tree_size, prev.cp.root, cur.cp.tree_size, cur.cp.root, proof)) {
      treeVs.push('fail');
      findings.push({
        code: 'CONSISTENCY_BROKEN', verdict: 'fail',
        detail: `checkpoint ${cur.seq} is not an extension of checkpoint ${prev.seq}: both are signed, so they are checkpoints of two different histories`,
      });
    }
  }

  if (anchored > 0 && anchored < leaves.length) {
    findings.push({
      code: 'UNANCHORED_TAIL', verdict: 'inconclusive',
      detail: `${leaves.length - anchored} record(s) above record_seq ${anchored} are committed to by no checkpoint, so nothing fixes where this log ends`,
    });
  }

  check('TREE', combine(treeVs));
  check('OP-SIG', combine(sigVs));

  // 7 WITNESS — DES-08, DES-20, FR-19, FR-30, FR-31, INT-02.
  // SEC-24 — declared key compromises, found by KIND rather than by sniffing
  // for optional fields, which is what makes "never silently bridged"
  // checkable. There is no cryptographic recovery from a compromised key:
  // records it produced are suspect from that point and nothing here changes
  // that. What the declaration buys is an honest discontinuity, and the
  // verifier's job is to refuse to carry trust across it.
  const discontinuities = entries
    .map((e, i) => ({ e, i }))
    .filter(({ e }) => /** @type {any} */ (e).record?.kind === 'discontinuity')
    .map(({ e }) => /** @type {any} */ (e).record);
  for (const d of discontinuities) {
    findings.push({
      code: 'DISCONTINUITY', verdict: 'inconclusive',
      detail: `the operator declared a key compromise at record_seq ${d.record_seq}: `
        + `"${d.reason}". They state epoch ${d.last_sound_epoch} was the last they believe sound, `
        + 'and name a new root key. Records this log produced after the compromise are suspect and '
        + 'no verification can change that — what this declaration establishes is that somebody '
        + 'said so, at a time a countersignature over the checkpoint above it can corroborate',
      record_seq: d.record_seq,
    });
  }

  const latestBatchTs = entries.length === 0
    ? null
    : (/** @type {any} */ (entries[entries.length - 1]).record?.ts ?? null);
  // FR-66 — the roll-up envelopes go in too, so a witness on the slower tier
  // is told apart from one that is absent. Read before the WITNESS check
  // rather than inside the ROLLUP check below, because the expectation is
  // about the witness set and not about whether the roll-ups check out.
  const rollupIssuers = store.readRollups().map(({ blob }) => ({
    issuers: parseEnvelope(blob).issuers,
  }));
  const wit = await verifyWitnesses({
    envelopes, policy: opts.policy, leaves, findings, anchored, latestBatchTs,
    rollups: rollupIssuers,
  });
  check('WITNESS', wit.verdict, wit.detail);

  // 8 ROLLUP — FR-53. The roll-up's leaves are the CHECKPOINT NOTES, so it is
  // checked against the notes on disk and not against the record log. A
  // verifier that compared it to the records would report a mismatch on a
  // perfectly good roll-up.
  const rollup = await verifyRollups({ store, notes, pinned, epochKeys, findings });
  check('ROLLUP', rollup.verdict, rollup.detail);
  check('COVERAGE', 'inconclusive', 'heartbeat continuity is not yet reconciled (DES-10 ships in M4)');
  check('POLICY', 'inconclusive', 'policy-change reconciliation ships with DES-09 enforcement');

  // SEC-26, FR-54 — the cross-pack comparison. Checked here rather than inside
  // verifyWitnesses because it is about a height disclosed ELSEWHERE, which is
  // the one thing a single pack cannot contradict on its own.
  for (const d of opts.disclosed ?? []) {
    if (d.tree_size > entries.length) {
      findings.push({
        code: 'TRUNCATED_BELOW_DISCLOSED', verdict: 'fail',
        detail: `a pack already disclosed holds a countersigned checkpoint at tree_size ${d.tree_size}, `
          + `but this record ends at ${entries.length}. Truncation, caught without a stateful witness: `
          + 'the operator cannot un-disclose what a counterparty already holds (DES-19)',
      });
      continue;
    }
    const here = rootAt(d.tree_size).toString('base64');
    if (here !== d.root) {
      findings.push({
        code: 'TREE_MISMATCH', verdict: 'fail',
        detail: `a pack already disclosed holds a different root at tree_size ${d.tree_size} than this `
          + 'one does: the two are forks of each other, and neither is preferred by this verifier',
      });
    }
  }

  // FR-34 rule 3, FR-69 — real and padding records counted SEPARATELY.
  //
  // Indistinguishable padding would make a disclosed tree size meaningless,
  // which is the whole reason padding is a typed record kind rather than a
  // bare leaf. Counted here from the records, so the numbers describe the
  // evidence rather than the operator's configuration.
  /** @type {Record<string, number>} */
  const census = {};
  for (const e of entries) {
    const k = String(e.record?.kind ?? 'unreadable');
    census[k] = (census[k] ?? 0) + 1;
  }
  return report(entries.length, anchored, checks, findings, notes, collector, opts.vkey,
    succession, wit, rollup, discontinuities, census);
}

/**
 * @param {number} tree_size
 * @param {number} anchored the highest tree size a valid checkpoint commits to
 * @param {{ name: string, verdict: Verdict, detail?: string }[]} checks
 * @param {Finding[]} findings
 * @param {{ seq: number, blob: string }[]} notes
 * @param {string} collector
 * @param {string} [vkey]
 * @param {ReturnType<typeof successionReport>|null} [succession]
 * @param {Awaited<ReturnType<typeof verifyWitnesses>>} [wit]
 * @param {Awaited<ReturnType<typeof verifyRollups>>} [rollup]
 * @param {any[]} [discontinuities]
 * @param {Record<string, number>} [census] records by kind — FR-34, FR-69
 */
function report(tree_size, anchored, checks, findings, notes, collector, vkey, succession = null, wit, rollup,
  /** @type {any[]} */ discontinuities = [], /** @type {Record<string, number>} */ census = {}) {
  const verdict = combine([...checks.map(c => c.verdict), ...findings.map(f => f.verdict)]);

  // DES-12's own shape: a verdict is reported with how many checks could and
  // could not be answered. In M1 a flawless store reads INCONCLUSIVE, because
  // WITNESS, ROLLUP, COVERAGE and ROLLUP's tier are not answerable from this
  // evidence — and a bare `ok` would imply more than was checked, which is
  // exactly what an external review pushed back on. `failed` is therefore the
  // number a red-team gate reads, not the verdict string.
  // FR-34, FR-69 — the counts a reader needs to make sense of `tree_size`.
  // PRIV-07: tree size is the count of ALL records and is not an action count,
  // which is only checkable if the kinds are reported beside it.
  const padding = census.padding ?? 0;
  const records = {
    tree_size,
    by_kind: census,
    padding,
    // Everything that is not padding. Named `real` rather than `actions`
    // because heartbeats, gaps and policy events are real records and are not
    // agent actions either — conflating the two is the misreading PRIV-07
    // exists to prevent.
    real: tree_size - padding,
  };
  const summary = {
    passed: checks.filter(c => c.verdict === 'ok').length,
    unanswered: checks.filter(c => c.verdict === 'inconclusive').length,
    // A finding may fail without its check being marked, so both are counted.
    failed: checks.filter(c => c.verdict === 'fail').length
      + findings.filter(f => f.verdict === 'fail' && !checks.some(c => c.verdict === 'fail')).length,
  };

  // FR-57 — derived from the proof types actually present, not from
  // configuration. A verifier reads evidence, and the operator's config is not
  // evidence. There are no countersignatures in M1, so the honest answer is a
  // short list of what this evidence cannot do.
  const witnesses = wit?.witnesses ?? [];
  const quorum = {
    required: wit?.quorum ?? 1,
    observed: wit?.observed ?? Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, 0])),
    met: wit?.met ?? Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, false])),
  };

  // An affirmative capability must rest on a check that actually passed. This
  // block used to assert chain integrity whenever any record existed, so a
  // verification that FAILED still printed "no record was altered" directly
  // under the word FAIL. For a project whose thesis is not claiming more than
  // the evidence supports, that was the worst possible place to overclaim.
  /** @param {string} name */
  const passed = name => checks.find(c => c.name === name)?.verdict === 'ok';

  const can = [];
  const cannot = [];
  if (summary.failed > 0) {
    cannot.push('this evidence contradicts itself, so it establishes nothing about the records it contains — the findings above say which checks failed');
  } else if (tree_size > 0 && passed('FORMAT') && passed('SEQUENCE') && passed('CHAIN') && passed('LEAF')) {
    can.push('ordering and content integrity of every record in this chain');
    can.push('that no record was altered, inserted, removed or reordered within it');
    if (passed('CONTENT')) can.push('that every retained payload still reproduces the commitment in its record');
  }
  if (summary.failed === 0 && notes.length && vkey && passed('OP-SIG') && passed('TREE')
    && discontinuities.length === 0) {
    // The PINNED identity, not the collector id. They are different things —
    // the collector scopes a chain within a store, the identity is what the
    // reader pinned out of band — and naming the wrong one in the one sentence
    // about identity is the sort of error a reader would reasonably rely on.
    can.push(
      `that the operator identity ${vkey.split('+')[0]} signed the tree size and root it claims`,
    );
    if (passed('SUCCESSION') && succession && succession.epochs.length > 1) {
      can.push(
        `that all ${succession.epochs.length} epochs of signing keys descend from the one root `
        + 'key you pinned, each endorsed by its predecessor (FR-11)',
      );
    }
  }

  if (rollup && rollup.verdict === 'ok' && summary.failed === 0) {
    can.push(
      `that ${rollup.covers} checkpoint${rollup.covers === 1 ? '' : 's'} `
      + `${rollup.covers === 1 ? 'is' : 'are'} covered by ${rollup.count} signed roll-up `
      + `summar${rollup.count === 1 ? 'y' : 'ies'}, so a single batch can be shown to be under one `
      + 'by an inclusion proof (FR-53)',
    );
  }

  // SEC-24 — prominently, and never silently bridged.
  if (discontinuities.length > 0) {
    const first = discontinuities[0];
    cannot.push(
      `this log contains ${discontinuities.length} declared key compromise(s) — a DISCONTINUITY. `
      + `Nothing this reader pinned reaches across it: the records after record_seq `
      + `${first.record_seq} are signed under a key the pinned root no longer vouches for, and a `
      + 'reader who wants to rely on them must re-pin the new root OUT OF BAND, from somewhere '
      + 'the operator cannot quietly change',
    );
    cannot.push(
      'the compromise declaration is signed by the key it disowns — the suspect key is the only '
      + 'one that exists at that moment, so the statement rests on it. A fresh key cannot sign a '
      + "statement about its predecessor's compromise without first being trusted, which is the "
      + 'thing in question',
    );
    cannot.push(
      `records written before the declaration are the ones in question: the operator states epoch `
      + `${first.last_sound_epoch} was the last they believe sound, and that is their assessment `
      + 'rather than anything this evidence establishes',
    );
  }

  // SEC-17 — the forward-secrecy claim and its precondition in the same place.
  //
  // Not in a document beside the report: a reader acting on the report is the
  // one who needs the precondition, and a claim whose caveat lives elsewhere
  // is read without it. So the claim carries both declarations it rests on, or
  // it is not made at all.
  if (succession && succession.ok && succession.epochs.length > 0) {
    const software = succession.epochs.filter(e => e.custody === 'software');
    const retired = succession.epochs.filter(e => e.retired);
    if (software.length > 0) {
      cannot.push(
        `forward secrecy is NOT claimed for this log: ${software.length === 1 ? 'epoch' : 'epochs'} `
        + `${software.map(e => e.epoch).join(', ')} ${software.length === 1 ? 'is' : 'are'} `
        + 'declared software-keyed, so the private key existed outside any module and may have been '
        + 'copied before rotation. One such epoch is enough: the question a reader asks is whether '
        + "yesterday's record can be re-signed with today's key, and for this log the answer is yes",
      );
    } else if (retired.length === 0) {
      cannot.push(
        'forward secrecy is NOT claimed: no epoch has been retired yet, and a key that is never '
        + 'rotated has no forward secrecy whatever its custody class',
      );
    } else {
      const classes = [...new Set(retired.map(e => e.custody))].join(' and ');
      can.push(
        `forward secrecy for ${retired.length} retired epoch(s), ONLY under its precondition: the `
        + `operator DECLARES ${classes} custody with non-exportable keys, and DECLARES each retired `
        + 'private key destroyed. Both are declarations. Key destruction is not externally '
        + 'verifiable by anyone, and this claim is exactly as strong as those declarations',
      );
    }
    cannot.push(
      'the custody class of every epoch here is operator-declared, not established: an HSM '
      + 'signature and a signature from a key file are byte-identical, and no provider attestation '
      + 'is present to check against (FR-70)',
    );
    // Conditional, because with an accepted countersignature over the original
    // note this gap is CLOSED: the operator can rewrite the note but not forge
    // the witness's signature over what the witness was shown. Printing the
    // unconditional version understated the evidence in a report that had the
    // countersignature listed four lines above — and red-team C2 is detected in
    // exactly this configuration.
    const sequenceWitnessed = witnesses.some(w => w.accepted && /sequence/.test(w.establishes));
    cannot.push(sequenceWitnessed
      ? 'a wholesale re-sign is detectable here only for the checkpoints a witness actually '
        + 'countersigned: above the highest countersigned height, re-signing everything with the '
        + 'current key leaves the epochs equal and nothing local contradicts it'
      : 'a wholesale re-sign — every checkpoint re-signed with the current key after rewriting the '
        + 'records — leaves the epochs equal and is NOT detectable from this evidence alone; a '
        + 'countersignature over the original root is what contradicts it, and there is none here');
  } else if (succession === null && vkey) {
    cannot.push(
      'no succession journal is present, so nothing here says whether the signing key was ever '
      + 'rotated; the epoch ratchet (FR-11) establishes no forward secrecy for this log',
    );
  }
  // FR-57 — what the OBSERVED witness set can and cannot establish, derived
  // from the proofs present rather than from configuration. The height is the
  // number a reader needs, and DES-12's own example prints it; without it,
  // DES-19's cross-pack comparison has nothing to key on.
  const hasSequence = (quorum.observed.sequence ?? 0) > 0 && quorum.met.sequence;
  if (hasSequence && anchored > 0) {
    can.push(
      `that truncation below record_seq ${anchored} is detectable: a witness maintaining sequence `
      + `state countersigned a checkpoint at that height, and it cannot be un-signed`,
    );
  }
  if (!hasSequence) {
    cannot.push(anchored > 0
      ? `no witness in this set maintains sequence state, so truncation above record_seq ${anchored} is NOT detectable from this evidence alone`
      : 'no checkpoint commits to any height here, so truncation anywhere in this log is NOT detectable from this evidence alone');
  }
  // FR-39 — the unwitnessed window, its size, and what the receipt time rests on.
  for (const w of witnesses.filter(x => x.accepted)) {
    if (w.clock_disagreement !== undefined) {
      cannot.push(
        `${w.id} says it received this root ${w.clock_disagreement} ms BEFORE the batch's own `
        + 'timestamp, so the two clocks disagree. Either the witness\'s is wrong or the '
        + "operator's is, and this verifier does not prefer one — the ts field is self-asserted "
        + 'and the receipt time is the witness\'s claim',
      );
    } else if (w.unwitnessed_for_ms !== undefined && w.unwitnessed_for_ms > 0) {
      const hours = w.unwitnessed_for_ms / 3_600_000;
      can.push(
        `that ${w.id} received this root at ${w.received_at}, which is `
        + `${hours >= 1 ? `${hours.toFixed(2)} hours` : `${w.unwitnessed_for_ms} ms`} after the `
        + 'batch claims to have been written',
      );
      cannot.push(
        `the batch was unwitnessed for ${hours >= 1 ? `${hours.toFixed(2)} hours` : `${w.unwitnessed_for_ms} ms`} `
        + `before ${w.id} saw it: anything that happened to the log inside that window is `
        + 'outside what this countersignature reaches',
      );
    }
    if (w.received_at_basis === 'absent') {
      cannot.push(
        `${w.id} supplied no receipt time, so WHEN it saw this root is not established — and it `
        + "is not assumed to be the batch's own timestamp",
      );
    } else if (w.received_at_basis === 'witness-asserted, unsigned') {
      cannot.push(
        `${w.id}'s receipt time is witness-asserted and UNSIGNED: a C2SP note has nowhere inside `
        + 'it to carry a time, so the value sits beside the proof rather than under it. It is '
        + "exactly as good as that witness's word",
      );
    }
  }

  if (witnesses.length > 0 && quorum.required > 0) {
    // Three numbers, never one. An aggregate figure would let an operator look
    // well-witnessed while being unable to detect truncation at all.
    cannot.push(
      'quorum is reported per capability class, not as one number: '
      + CAPABILITY_CLASSES.map(c => `${c} ${quorum.observed[c] ?? 0}/${quorum.required}`).join(', ')
      + '. Redundancy of time is not independence of sequence',
    );
  }
  if (witnesses.length > 0 && witnesses.every(w => !w.accepted)) {
    cannot.push(
      'the acceptance policy names no witness that signed this pack, so no countersignature here '
      + 'counts towards anything for this reader — which is a statement about the policy, not about '
      + 'whether anyone signed',
    );
  }
  if (witnesses.length > 0 && !witnesses.some(w => w.accepted) && quorum.required > 0
    && witnesses.every(w => w.establishes === '(not accepted)')) {
    cannot.push('this reader\'s acceptance policy names no witness at all');
  }
  const timeProofs = witnesses.filter(w => w.accepted && /time|existence/.test(w.establishes));
  if (timeProofs.length === 0) {
    // Distinguish "nobody countersigned" from "somebody did, and none of them
    // bears a clock". Saying the first when the second is true is false in the
    // report's own terms: the witnesses block above lists the countersignature
    // it is denying exists.
    cannot.push(witnesses.some(w => w.accepted)
      ? 'no accepted countersignature here establishes TIME: the witnesses above establish sequence '
        + 'or nothing, so nothing in this evidence says WHEN any record was written — the ts field '
        + 'is self-asserted'
      : 'no countersignature is present, so nothing here establishes WHEN any record was written — '
        + 'the ts field is self-asserted');
  } else {
    cannot.push(
      `${timeProofs.length} time-bearing proof(s) are present but NOT confirmed by this verifier: `
      + 'an RFC 3161 token needs the TSA certificate chain and an OpenTimestamps commitment needs a '
      + 'Bitcoin block header, and NFR-05 requires this verifier to retrieve neither. They are reported '
      + 'as claimed',
    );
  }
  cannot.push('an action that was never observed leaves no trace here; this evidence speaks to what was recorded');
  if (!vkey) cannot.push('no operator identity was pinned, so the signature on the checkpoint was not checked against anything');

  const trusting = ['the cryptographic primitives (SHA-256, Ed25519)'];
  if (vkey) trusting.push(`the operator identity ${vkey.split('+')[0]} to be the one you meant`);
  trusting.push('the operator for the completeness of what was captured, until a witness is configured');
  if (succession && succession.ok && succession.epochs.some(e => e.custody !== 'software')) {
    trusting.push(
      'the operator\'s declaration of key custody, and their declaration that retired private keys '
      + 'were destroyed — neither is verifiable from this evidence',
    );
  }

  return {
    verdict, summary, tree_size, anchored_tree_size: anchored, records,
    checks,
    // The last boundary before a reader. Everything forwarded from another
    // layer passes through here, so an unrecognised code cannot be printed to
    // someone deciding whether to rely on this evidence.
    findings: validateFindings(findings, 'verifyStore'),
    witnesses, quorum, capability: { can, cannot }, trusting, succession,
  };
}

/** @param {Record<string, unknown>} record @returns {[string, string][]} */
function commitments(record) {
  /** @type {[string, string][]} */
  const out = [];
  for (const f of ['agent', 'args', 'result']) {
    const c = /** @type {{cid?: unknown}|undefined} */ (record[f]);
    if (c && typeof c === 'object' && typeof c.cid === 'string') out.push([f, c.cid]);
  }
  const ap = /** @type {Record<string, {cid?: unknown}>|null} */ (record.approval);
  if (ap && typeof ap === 'object') {
    for (const f of ['reviewer', 'request']) {
      const c = ap[f];
      if (c && typeof c === 'object' && typeof c.cid === 'string') out.push([`approval.${f}`, c.cid]);
    }
  }
  return out;
}



/**
 * Check the countersignatures in every checkpoint envelope against the
 * reader's acceptance policy — FR-19, FR-30, FR-31, FR-57, INT-02, DES-20.
 *
 * Three things here are the whole point of the element:
 *
 * The policy is an INPUT. A verifier with a hardcoded trust store would make
 * independence undemonstrable: the reader who matters is an auditor who trusts
 * their own witness and not ours, and they must be able to say so and get a
 * different, internally consistent answer from the same bytes.
 *
 * Quorum is counted PER CAPABILITY CLASS. Two time-only witnesses buy
 * redundancy of time, not independence of sequence. A single aggregate number
 * would let an operator look well-witnessed while being unable to detect
 * truncation at all — DES-20's review named this, and it is the reason the
 * report prints three numbers rather than one.
 *
 * An entry this verifier cannot check is INCONCLUSIVE, never a pass and never
 * a failure. An RFC 3161 token needs CMS path validation and an OpenTimestamps
 * proof needs a Bitcoin header, and NFR-05 requires this verifier to be
 * offline by construction. So it reports what the proof claims and declines to
 * confirm it, rather than reaching for the network or treating a format it
 * cannot open as evidence of tampering.
 *
 * @param {object} o
 * @param {{ seq: number, env: ReturnType<typeof parseEnvelope> }[]} o.envelopes
 * @param {{ quorum?: number, witnesses?: { id: string, public_key?: string, establishes?: string[],
 *   anchors?: string[], tier?: 'anchor'|'rollup' }[] }} [o.policy]
 * @param {{ issuers: Set<string> }[]} [o.rollups] FR-66 — the roll-up
 *   envelopes, so a witness on the slower tier can be told apart from one that
 *   is simply absent
 * @param {Buffer[]} o.leaves
 * @param {Finding[]} o.findings appended to
 * @param {number} o.anchored
 * @param {string|null} [o.latestBatchTs] the newest record's self-asserted ts,
 *   for FR-39's gap. Self-asserted is the point: the gap between it and the
 *   witness's receipt time is the unwitnessed window.
 */
async function verifyWitnesses({ envelopes, policy, leaves, findings, anchored, latestBatchTs, rollups }) {
  /** @type {WitnessEntry[]} */
  const witnesses = [];
  /** @type {Record<string, number>} */
  const observed = Object.fromEntries(CAPABILITY_CLASSES.map(c => [c, 0]));
  const quorum = policy?.quorum ?? 1;
  const named = new Map((policy?.witnesses ?? []).map(w => [w.id, w]));
  /** @type {Set<string>} */
  const seen = new Set();
  /** @type {Map<string, Set<string>>} issuer -> capability classes accepted */
  const credited = new Map();

  for (const { seq, env } of envelopes) {
    /** @type {Omit<WitnessEntry, 'checkpoint_seq'|'tree_size'>[]} */
    const local = [];
    for (const cs of env.countersignatures) {
      seen.add(cs.issuer);
      const spec = named.get(cs.issuer);
      if (!spec) {
        // Present, reported, counted for nothing. Dropping it would hide
        // evidence a reader with a different policy could use.
        local.push({
          id: cs.issuer, type: cs.type, establishes: '(not accepted)', accepted: false,
          verdict: 'inconclusive',
          detail: `checkpoint ${seq}: this reader's acceptance policy does not name ${cs.issuer}, so `
            + 'its proof counts towards no quorum. It is in the pack, and a reader with a different '
            + 'policy could use it.',
        });
        continue;
      }
      const classes = spec.establishes ?? [];
      if (cs.verdict !== 'ok' || !cs.entry) {
        local.push({
          id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
          verdict: 'inconclusive', detail: `checkpoint ${seq}: ${cs.detail ?? 'the entry is not usable'}`,
        });
        continue;
      }

      // FR-39 — the witness's own clock, and how far it is from the batch's.
      const time = receiptTime(cs, latestBatchTs ?? null);

      if (cs.type === 'c2sp-note') {
        // The only type checkable offline, and therefore the only one that can
        // produce WITNESS_MISMATCH — the strongest finding available, because
        // the operator could rewrite the note but not forge the signature over
        // what the witness actually saw.
        const r = await checkNoteLine(env.note ?? '', cs.entry, spec);
        if (r === 'ok' || (typeof r === 'object' && 'via' in r)) {
          credit(credited, cs.issuer, classes);
          local.push({
            id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: true,
            verdict: 'ok',
            detail: `checkpoint ${seq}: countersigned by ${cs.issuer}`
              + `${r === 'ok' ? '' : ` using ${r.via}`}${time.detail}`,
            ...time.fields,
          });
          continue;
        }
        if (r === 'no-key') {
          local.push({
            id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
            verdict: 'inconclusive',
            detail: `checkpoint ${seq}: the acceptance policy names ${cs.issuer} but supplies no `
              + 'public key for it, so the signature was not checked against anything',
          });
          continue;
        }
        if (typeof r === 'object' && 'detail' in r) {
          // FR-51 — the history was supplied and could not be used, or the key
          // is not in it. Inconclusive either way: a witness this reader
          // cannot attribute is a witness this reader does not know, and
          // calling that tampering would make a rotation somebody forgot to
          // publish look like an attack.
          local.push({
            id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
            verdict: 'inconclusive', detail: `checkpoint ${seq}: ${r.detail}`,
          });
          continue;
        }
        findings.push({
          code: 'WITNESS_MISMATCH', verdict: 'fail',
          detail: `checkpoint ${seq}: ${cs.issuer}'s countersignature does not verify over this `
            + "checkpoint's note. A witness signs what it was shown; this is what it looks like when "
            + 'history was rewritten after the witness saw it, because the signature could not be forged',
        });
        local.push({
          id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
          verdict: 'fail', detail: `checkpoint ${seq}: the countersignature does not verify`,
        });
        continue;
      }

      if (cs.type === 'rfc3161') {
        // FR-16 — actually verified, offline, when the reader supplies the trust
        // anchors. Everything an RFC 3161 token needs is in the token plus an
        // anchor; nothing has to be retrieved, so declining to check it would have
        // been a choice rather than a constraint.
        const imprint = Buffer.from(String(env.note_digest).slice('sha256:'.length), 'hex');
        const r = await verifyTimeStampToken(
          Buffer.from(String(cs.entry.token ?? ''), 'base64'),
          { imprint, anchors: spec.anchors ?? [] },
        );
        if (r.ok) {
          credit(credited, cs.issuer, classes);
          local.push({
            id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: true,
            verdict: 'ok', detail: `checkpoint ${seq}: ${r.detail}`,
          });
          continue;
        }
        if (r.inconclusive) {
          // Two different inconclusives, and the difference decides a quorum.
          //
          // A token that PARSES and is internally valid, where the reader
          // simply named no anchor for this TSA, is credited: the operator did
          // obtain a third-party timestamp, and whether this reader accepts
          // that TSA is a statement about the policy rather than the token.
          //
          // A token that does not parse is credited with nothing. There is no
          // evidence any timestamp was obtained at all, and counting it would
          // let a quorum be met by submitting noise.
          if (!r.malformed) credit(credited, cs.issuer, classes);
          local.push({
            id: cs.issuer, type: cs.type, establishes: classes.join('+'),
            accepted: !r.malformed,
            verdict: 'inconclusive', detail: `checkpoint ${seq}: ${r.detail}`,
          });
          continue;
        }
        findings.push({
          code: 'WITNESS_MISMATCH', verdict: 'fail',
          detail: `checkpoint ${seq}: the RFC 3161 token from ${cs.issuer} does not verify — ${r.detail}`,
        });
        local.push({
          id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
          verdict: 'fail', detail: `checkpoint ${seq}: ${r.detail}`,
        });
        continue;
      }

      // opentimestamps — FR-22. The proof is WALKED, which is the part that can
      // be done offline: the operations are applied and the attestation read.
      // What cannot be done offline is confirming the block header, so the
      // result is a commitment reported rather than a fact confirmed.
      const imprint = Buffer.from(String(env.note_digest).slice('sha256:'.length), 'hex');
      const ots = describeOtsProof(Buffer.from(String(cs.entry.proof ?? ''), 'base64'), { imprint });
      if (!ots.inconclusive) {
        // Refuted: a valid proof about other bytes.
        findings.push({
          code: 'WITNESS_MISMATCH', verdict: 'fail',
          detail: `checkpoint ${seq}: the OpenTimestamps proof from ${cs.issuer} commits a different `
            + `digest — ${ots.detail}`,
        });
        local.push({
          id: cs.issuer, type: cs.type, establishes: classes.join('+'), accepted: false,
          verdict: 'fail', detail: `checkpoint ${seq}: ${ots.detail}`,
        });
        continue;
      }
      local.push({
        id: cs.issuer, type: cs.type, establishes: classes.join('+'),
        accepted: !ots.malformed,
        verdict: 'inconclusive', detail: `checkpoint ${seq}: ${ots.detail}`,
      });
      // A mangled proof is credited with nothing, for the same reason an
      // unparseable token is: there is no evidence anything was submitted.
      if (!ots.malformed) credit(credited, cs.issuer, classes);
    }

    // Attribute everything this envelope produced to the checkpoint it came
    // from. Collected locally and stamped on the way out, rather than repeated
    // at each of the push sites above, so a branch added later cannot omit it
    // — the type will not let it.
    for (const w of local) {
      witnesses.push({ ...w, checkpoint_seq: seq, tree_size: env.tree_size });
    }
  }

  for (const [, classes] of credited) {
    for (const c of classes) observed[c] = (observed[c] ?? 0) + 1;
  }

  // FR-66 — expected against present, and the tier is what makes the
  // comparison mean something.
  //
  // A witness on the slower ROLL-UP tier is not expected in a checkpoint pack
  // at all: its proofs live in the roll-up envelopes, so its absence from the
  // checkpoints says nothing. Reporting that as missing would put a permanent
  // inconclusive on every correctly configured log that has one, which is how
  // a finding stops being read.
  //
  // What absence still cannot establish, for a witness that WAS expected:
  // pending under fail-open, an unavailable witness, and a removed receipt are
  // indistinguishable from absence alone. Demonstrating removal takes an
  // earlier pack that contained it, which is FR-54's cross-pack comparison.
  /** @type {string[]} */
  const notYetExpected = [];
  const rollupIssuers = new Set((rollups ?? []).flatMap(r => [...r.issuers]));
  for (const [id, spec] of named) {
    if (seen.has(id)) continue;
    if (spec.tier === 'rollup' && !rollupIssuers.has(id)) {
      if ((rollups ?? []).length === 0) {
        // No roll-up has been produced yet, so nothing from this witness is
        // due. Not a finding: an expectation that has not come round yet is
        // not an expectation that went unmet.
        notYetExpected.push(id);
        continue;
      }
      findings.push({
        code: 'WITNESS_MISSING', verdict: 'inconclusive',
        detail: `the acceptance policy names ${id} on the roll-up tier and ${rollups?.length} `
          + 'roll-up(s) are present with no proof from it. That is consistent with a submission '
          + 'still pending under fail-open, with the witness having been unavailable, and with a '
          + 'receipt having been removed — nothing here distinguishes them, and demonstrating '
          + 'removal takes an earlier pack that held it',
      });
      continue;
    }
    if (spec.tier === 'rollup') { notYetExpected.push(id); continue; }
    findings.push({
      code: 'WITNESS_MISSING', verdict: 'inconclusive',
      detail: `the acceptance policy names ${id} but no proof from it is in this pack. That is `
        + 'consistent with a submission still pending under fail-open, with the witness having '
        + 'been unavailable, and with a receipt having been removed — nothing here distinguishes '
        + 'them, and demonstrating removal takes an earlier pack that held it',
    });
  }

  const met = Object.fromEntries(
    CAPABILITY_CLASSES.map(c => [c, (observed[c] ?? 0) >= quorum]),
  );

  if (named.size === 0) {
    return {
      verdict: /** @type {Verdict} */ ('inconclusive'),
      detail: envelopes.some(e => !e.env.unwitnessed)
        ? 'countersignatures are present but this reader named no witness to accept'
        : 'no countersignature in this store',
      witnesses, observed, met, quorum, not_yet_expected: notYetExpected,
    };
  }
  if (CAPABILITY_CLASSES.every(c => (observed[c] ?? 0) === 0)) {
    // Nothing counted. Whether that is a FAILURE depends on why: a proof this
    // reader could not attribute — an unpublished rotation, a witness they do
    // not know — is not evidence of tampering, and failing the whole check on
    // it would be the same false accusation this project keeps having to
    // design out. A proof that was REFUTED is already a finding of its own.
    const refuted = witnesses.some(w => w.verdict === 'fail');
    return {
      verdict: /** @type {Verdict} */ (refuted ? 'fail' : 'inconclusive'),
      detail: refuted
        ? 'a proof in this pack does not verify under the key the acceptance policy supplies'
        : 'no proof in this pack could be attributed to a witness the acceptance policy accepts, '
          + 'which is a statement about what this reader can check rather than about the evidence',
      witnesses, observed, met, quorum, not_yet_expected: notYetExpected,
    };
  }
  const short = CAPABILITY_CLASSES.filter(c => (observed[c] ?? 0) > 0 && !met[c]);
  if (short.length > 0) {
    findings.push({
      code: 'WITNESS_SHORT', verdict: 'fail',
      detail: `the acceptance policy requires a quorum of ${quorum}, and this pack holds `
        + short.map(c => `${observed[c]} ${c}`).join(', ')
        + '. A quorum short of its requirement is not a weaker quorum, it is an unmet one',
    });
    return {
      verdict: /** @type {Verdict} */ ('fail'),
      detail: `quorum of ${quorum} not met for ${short.join(', ')}`,
      witnesses, observed, met, quorum, not_yet_expected: notYetExpected,
    };
  }
  return {
    verdict: /** @type {Verdict} */ ('ok'),
    detail: CAPABILITY_CLASSES.filter(c => met[c]).map(c => `${c} quorum ${observed[c]}/${quorum}`).join(', '),
    witnesses, observed, met, quorum, not_yet_expected: notYetExpected,
  };
}

/**
 * @param {Map<string, Set<string>>} credited
 * @param {string} issuer
 * @param {string[]} classes
 */
function credit(credited, issuer, classes) {
  // One issuer, one vote per class, however many checkpoints it signed.
  const set = credited.get(issuer) ?? new Set();
  for (const c of classes) set.add(c);
  credited.set(issuer, set);
}

/**
 * @param {string} noteBlob
 * @param {import('@splitstick/core/envelope').Countersignature} cs
 * @param {{ id: string, public_key?: string,
 *           key_history?: { keys?: { public_key?: string }[], note?: string } }} spec
 * @returns {Promise<'ok'|'bad'|'no-key'|{ via: string }|{ detail: string }>}
 */
async function checkNoteLine(noteBlob, cs, spec) {
  if (!spec.public_key && !spec.key_history) return 'no-key';
  /** @type {string} */
  let text;
  /** @type {{ keyId: Buffer, signature: Buffer, name: string }|undefined} */
  let line;
  try {
    text = parseNote(noteBlob).text;
    line = parseNote(`${text}\n${cs.line}\n`).signatures.find(x => x.name === cs.issuer);
  } catch {
    return 'bad';
  }
  if (!line) return 'bad';
  const found = line;

  /** @param {Buffer} pub */
  const matches = async (pub) => {
    // Shape check first: a key id that does not match cannot be a signature by
    // this key, and saying "does not verify" would be vaguer.
    if (!found.keyId.equals(noteKeyId(cs.issuer, pub))) return false;
    return verifyNoteSignature(text, found, {
      name: cs.issuer, publicKey: pub, keyId: noteKeyId(cs.issuer, pub),
    });
  };

  // FR-51 — a published key history, if one was supplied. It is VALIDATED
  // before any key in it is used: a history nobody signed is a list, and one
  // signed by a key outside itself would let anybody assert whatever keys they
  // liked.
  if (spec.key_history) {
    const h = await validateKeyHistory(cs.issuer, spec.key_history);
    if (!h.ok) return { detail: h.detail };
    for (const [i, pub] of h.keys.entries()) {
      if (!await matches(pub)) continue;
      return {
        via: i === h.keys.length - 1
          ? `the current key (key ${i + 1} of ${h.keys.length} in the signed history)`
          : `a RETIRED key (key ${i + 1} of ${h.keys.length} in the signed history) — rotation is `
            + 'not an amnesty for anything signed before it',
      };
    }
    return {
      detail: `${cs.issuer}'s countersignature is not any key in its signed key history, so this `
        + 'reader cannot attribute it. That is a witness this reader does not know rather than '
        + 'evidence of tampering: a rotation nobody published looks exactly like this',
    };
  }

  if (!spec.public_key) return 'no-key';
  return await matches(Buffer.from(spec.public_key, 'base64')) ? 'ok' : 'bad';
}

/**
 * Validate a witness's published key history — FR-51.
 *
 * The current key signs a note over a digest of the whole list, so three
 * things must hold before any key in it may attribute a countersignature: the
 * note exists, its signature verifies under a key that is ITSELF in the list,
 * and the digest signed is the digest of the list as presented.
 *
 * Without the third the signature covers nothing — a key could be appended
 * after signing and the note would still check out.
 *
 * @param {string} issuer
 * @param {{ keys?: { public_key?: string }[], note?: string }} history
 * One shape rather than a discriminated union: TypeScript does not preserve a
 * boolean literal discriminant written in JSDoc, so `if (!h.ok)` narrows
 * nothing. `detail` is empty on success — the same lesson as trustpath.mjs.
 * @returns {Promise<{ ok: boolean, keys: Buffer[], detail: string }>}
 */
async function validateKeyHistory(issuer, history) {
  const keys = Array.isArray(history.keys) ? history.keys : [];
  if (keys.length === 0) return { ok: false, keys: [], detail: `${issuer}'s key history is empty` };
  if (typeof history.note !== 'string' || history.note === '') {
    return {
      ok: false, keys: [],
      detail: `${issuer}'s key history is UNSIGNED. A key history nobody signed is a list, and a `
        + 'list cannot say which keys a witness held',
    };
  }
  /** @type {Buffer[]} */
  const raw = [];
  for (const k of keys) {
    if (typeof k?.public_key !== 'string') {
      return { ok: false, keys: [], detail: `${issuer}'s key history has an entry with no public_key` };
    }
    const b = Buffer.from(k.public_key, 'base64');
    if (b.length !== 32) {
      return { ok: false, keys: [], detail: `${issuer}'s key history has an entry that is not a 32-byte key` };
    }
    raw.push(b);
  }

  /** @type {ReturnType<typeof parseNote>} */
  let note;
  /** @type {ReturnType<typeof parseCheckpointText>} */
  let cp;
  try {
    note = parseNote(history.note);
    cp = parseCheckpointText(note.text);
  } catch (e) {
    return {
      ok: false, keys: [],
      detail: `${issuer}'s key history note does not parse: ${
        e instanceof Error ? e.message : String(e)}`,
    };
  }
  const expected = nodeCreateHash('sha256').update(JSON.stringify(keys)).digest();
  if (!expected.equals(cp.root)) {
    return {
      ok: false, keys: [],
      detail: `${issuer}'s key history note signs a digest that does not cover the key list as `
        + 'presented, so a key could have been added after it was signed and the signature would '
        + 'still check out',
    };
  }
  const sig = note.signatures.find(x => x.name === issuer);
  if (!sig) {
    return { ok: false, keys: [], detail: `${issuer}'s key history note carries no signature for ${issuer}` };
  }
  for (const pub of raw) {
    if (!sig.keyId.equals(noteKeyId(issuer, pub))) continue;
    if (await verifyNoteSignature(note.text, sig, {
      name: issuer, publicKey: pub, keyId: noteKeyId(issuer, pub),
    })) {
      return { ok: true, keys: raw, detail: '' };
    }
  }
  return {
    ok: false, keys: [],
    detail: `${issuer}'s key history is signed by a key that is not in the history itself, so `
      + 'anybody could publish a history asserting whatever keys they liked',
  };
}


/**
 * Check the roll-up summaries — FR-53.
 *
 * A roll-up commits to a tree of CHECKPOINT NOTES, so it is verified against
 * the notes on disk rather than against the record log. Getting that wrong
 * would make a verifier report TREE_MISMATCH on a perfectly good roll-up, which
 * is worse than not checking it: a false accusation from the component whose
 * only product is credibility.
 *
 * Its origin carries a `/rollup` suffix for the same reason, and the suffix is
 * CHECKED here rather than assumed — a roll-up presented under a different
 * origin is a different log's summary, and FR-63 says a reader who pinned an
 * identity is told when they are shown another.
 *
 * @param {object} o
 * @param {import('@splitstick/core/store').Store} o.store
 * @param {{ seq: number, note: string }[]} o.notes the checkpoints on disk
 * @param {ReturnType<typeof parseVkey>|null} o.pinned
 * @param {Map<string, { epoch: number, publicKey: Buffer }>} o.epochKeys
 * @param {Finding[]} o.findings appended to
 */
async function verifyRollups({ store, notes, pinned, epochKeys, findings }) {
  const rollups = store.readRollups();
  if (rollups.length === 0) {
    return {
      verdict: /** @type {Verdict} */ ('inconclusive'),
      detail: 'no roll-up in this store (FR-53); nothing here is anchored to a party that cannot '
        + 'withdraw it',
      count: 0,
      covers: 0,
    };
  }
  const leaves = notes
    .slice()
    .sort((a, b) => a.seq - b.seq)
    .map(n => Buffer.from(n.note, 'utf8'));

  /** @type {Verdict[]} */
  const vs = [];
  let covers = 0;
  for (const { seq, blob } of rollups) {
    const env = parseEnvelope(blob);
    if (!env.ok || env.note === null) {
      for (const f of env.findings) {
        findings.push({ code: f.code, verdict: 'fail', detail: `roll-up ${seq}: ${f.detail}` });
      }
      vs.push('fail');
      continue;
    }
    /** @type {ReturnType<typeof parseCheckpointText>} */
    let cp;
    /** @type {ReturnType<typeof parseNote>} */
    let note;
    try {
      note = parseNote(env.note);
      cp = parseCheckpointText(note.text);
    } catch (e) {
      findings.push({
        code: 'FORMAT_UNSUPPORTED', verdict: 'fail',
        detail: `roll-up ${seq}: ${e instanceof Error ? e.message : String(e)}`,
      });
      vs.push('fail');
      continue;
    }

    if (pinned && cp.origin !== `${pinned.name}/rollup`) {
      findings.push({
        code: 'IDENTITY_UNPINNED', verdict: 'fail',
        detail: `roll-up ${seq} declares origin ${cp.origin}; this reader pinned ${pinned.name}, `
          + `so the roll-up should be ${pinned.name}/rollup. A summary of a log you did not pin is `
          + 'a summary of another log',
      });
      vs.push('fail');
      continue;
    }
    if (cp.tree_size > leaves.length) {
      findings.push({
        code: 'SIZE_REGRESSED', verdict: 'fail',
        detail: `roll-up ${seq} covers ${cp.tree_size} checkpoints but ${leaves.length} are on disk: `
          + 'checkpoints have been removed below a count already summarised',
      });
      vs.push('fail');
      continue;
    }
    if (!treeRoot(leaves.slice(0, cp.tree_size)).equals(cp.root)) {
      findings.push({
        code: 'TREE_MISMATCH', verdict: 'fail',
        detail: `roll-up ${seq}'s root is not the root of this store's first ${cp.tree_size} `
          + 'checkpoint notes, so it summarises a different set of batches',
      });
      vs.push('fail');
      continue;
    }

    if (!pinned) {
      vs.push('inconclusive');
      findings.push({
        code: 'OPSIG_UNCHECKED', verdict: 'inconclusive',
        detail: `roll-up ${seq} is signed, but no operator identity was pinned`,
      });
      continue;
    }
    // The signature line's NAME is the operator's key identity, which is not
    // the roll-up's origin: a C2SP note's origin and its signers are separate,
    // and here the origin carries a `/rollup` suffix that the key does not.
    // Looking the line up by origin found nothing and reported an unsigned
    // roll-up — a false accusation from a lookup bug.
    const sig = note.signatures.find(x => x.name === pinned.name);
    const attributed = sig
      ? (epochKeys.size > 0
        ? [...epochKeys.values()].find(e => noteKeyId(pinned.name, e.publicKey).equals(sig.keyId))
        : (noteKeyId(pinned.name, pinned.publicKey).equals(sig.keyId)
          ? { epoch: 0, publicKey: pinned.publicKey }
          : undefined))
      : undefined;
    if (!sig || !attributed) {
      findings.push({
        code: 'OPSIG_INVALID', verdict: 'fail',
        detail: `roll-up ${seq} is not signed by a key in the succession chain walked from the `
          + 'pinned root',
      });
      vs.push('fail');
      continue;
    }
    if (!await verifyNoteSignature(note.text, sig,
      { name: pinned.name, publicKey: attributed.publicKey, keyId: noteKeyId(pinned.name, attributed.publicKey) })) {
      findings.push({
        code: 'OPSIG_INVALID', verdict: 'fail',
        detail: `roll-up ${seq} declares a key id from epoch ${attributed.epoch} but the signature `
          + "does not verify under that epoch's key",
      });
      vs.push('fail');
      continue;
    }
    vs.push('ok');
    if (cp.tree_size > covers) covers = cp.tree_size;
  }

  const verdict = combine(vs);
  const failed = vs.filter(v => v === 'fail').length;
  return {
    verdict,
    // Three branches, not two. With one roll-up present and no identity pinned
    // the verdict is inconclusive and nothing failed, and the two-branch
    // version printed "0 roll-up(s) do not check out" — a sentence that is both
    // false and meaningless.
    detail: verdict === 'ok'
      ? `${rollups.length} roll-up(s) covering ${covers} checkpoint(s)`
      : failed > 0
        ? `${failed} of ${rollups.length} roll-up(s) do not check out`
        : `${rollups.length} roll-up(s) present, but not checkable by this reader`,
    count: rollups.length,
    covers,
  };
}

/**
 * What the witness says about when it received the root — FR-39.
 *
 * A retroactive countersignature must record the witness's ACTUAL receipt time,
 * not the batch's claimed time: backdating it to the batch would turn the one
 * independent clock in the system into an echo of the operator's. The gap
 * between the two IS the unwitnessed window, and a reader needs its size.
 *
 * The basis is reported, not just the value. A `c2sp-note` has nowhere inside
 * it to put a time, so `received_at` is a bare claim sitting in the envelope;
 * an `rfc3161` token carries its genTime under the signature. Reporting the
 * first as though it were the second would be the most useful-looking lie
 * available here.
 *
 * A receipt time EARLIER than the batch's is reported and not preferred. Either
 * the witness's clock is wrong or the operator's is, and choosing between them
 * is deciding whose account to believe — the one thing a verifier must not do.
 *
 * @param {import('@splitstick/core/envelope').ParsedCountersignature} cs
 * @param {string|null} batchTs
 */
function receiptTime(cs, batchTs) {
  const raw = cs.entry?.received_at;
  // Strict RFC 3339, the same shape DES-01 requires of `ts`. Date.parse is
  // lenient: it reads "12345" as the year 12345, which would have produced a
  // receipt time ten thousand years out and an unwitnessed window to match.
  const at = typeof raw === 'string' && RECEIPT_TIME.test(raw) ? Date.parse(raw) : NaN;
  if (Number.isNaN(at)) {
    return {
      detail: '',
      fields: { received_at_basis: /** @type {const} */ ('absent') },
    };
  }
  const basis = cs.type === 'rfc3161'
    ? /** @type {const} */ ('signed by the TSA, inside the token')
    : /** @type {const} */ ('witness-asserted, unsigned');
  const batch = batchTs === null ? NaN : Date.parse(batchTs);
  if (Number.isNaN(batch)) {
    return { detail: ` at ${raw}`, fields: { received_at: raw, received_at_basis: basis } };
  }
  const delta = at - batch;
  if (delta < 0) {
    return {
      detail: ` at ${raw}, which is BEFORE the batch's own timestamp`,
      fields: {
        received_at: raw,
        received_at_basis: basis,
        clock_disagreement: Math.abs(delta),
      },
    };
  }
  return {
    detail: ` at ${raw}, ${delta} ms after the batch`,
    fields: { received_at: raw, received_at_basis: basis, unwitnessed_for_ms: delta },
  };
}
