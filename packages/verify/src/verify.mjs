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
import { treeRoot, consistencyProof, verifyConsistency } from '@splitstick/core/merkle';
import { parseNote, parseCheckpointText, parseVkey, SUITES } from '@splitstick/core/note';
import { verifyNoteSignature } from '@splitstick/core/signer';
import { successionReport } from '@splitstick/core/succession';
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
 * @param {string} root the store directory
 * @param {object} [opts]
 * @param {string} [opts.collector] the collector instance whose chain to read
 * @param {string} [opts.vkey] the pinned operator identity, as a note vkey
 * @returns {Promise<{
 *   verdict: Verdict, tree_size: number, anchored_tree_size: number,
 *   summary: { passed: number, unanswered: number, failed: number },
 *   checks: { name: string, verdict: Verdict, detail?: string }[],
 *   findings: Finding[],
 *   witnesses: { id: string, type: string, establishes: string }[],
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
      verdict: f.code.endsWith('_INCONCLUSIVE') ? 'inconclusive' : 'fail',
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
  const pinned = opts.vkey ? parseVkey(opts.vkey) : null;
  const leaves = entries.map(e => e.leaf);
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

  for (const { seq, blob } of notes) {
    /** @type {ReturnType<typeof parseNote>} */
    let note;
    /** @type {ReturnType<typeof parseCheckpointText>} */
    let cp;
    try {
      note = parseNote(blob);
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
    } else if (!treeRoot(leaves.slice(0, cp.tree_size)).equals(cp.root)) {
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
    .map(n => { try { return { seq: n.seq, cp: parseCheckpointText(parseNote(n.blob).text) }; } catch { return null; } })
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

  // 7-10 need evidence M1 does not produce. Reported, not skipped.
  check('WITNESS', 'inconclusive', 'no countersignature in this store (DES-08 ships in M3a)');
  check('ROLLUP', 'inconclusive', 'no roll-up checkpoint in this store (FR-53 ships in M3a)');
  check('COVERAGE', 'inconclusive', 'heartbeat continuity is not yet reconciled (DES-10 ships in M4)');
  check('POLICY', 'inconclusive', 'policy-change reconciliation ships with DES-09 enforcement');

  return report(entries.length, anchored, checks, findings, notes, collector, opts.vkey, succession);
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
 */
function report(tree_size, anchored, checks, findings, notes, collector, vkey, succession = null) {
  const verdict = combine([...checks.map(c => c.verdict), ...findings.map(f => f.verdict)]);

  // DES-12's own shape: a verdict is reported with how many checks could and
  // could not be answered. In M1 a flawless store reads INCONCLUSIVE, because
  // WITNESS, ROLLUP, COVERAGE and ROLLUP's tier are not answerable from this
  // evidence — and a bare `ok` would imply more than was checked, which is
  // exactly what an external review pushed back on. `failed` is therefore the
  // number a red-team gate reads, not the verdict string.
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
  /** @type {{ id: string, type: string, establishes: string }[]} */
  const witnesses = [];

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
  if (summary.failed === 0 && notes.length && vkey && passed('OP-SIG') && passed('TREE')) {
    can.push(`that the operator identity ${collector} signed the tree size and root it claims`);
    if (passed('SUCCESSION') && succession && succession.epochs.length > 1) {
      can.push(
        `that all ${succession.epochs.length} epochs of signing keys descend from the one root `
        + 'key you pinned, each endorsed by its predecessor (FR-11)',
      );
    }
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
        + `${software.map(e => `epoch ${e.epoch}`).join(', ')} ${software.length === 1 ? 'is' : 'are'} `
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
    cannot.push(
      'a wholesale re-sign — every checkpoint re-signed with the current key after rewriting the '
      + 'records — leaves the epochs equal and is NOT detectable from this evidence alone; a '
      + 'countersignature over the original root is what contradicts it, and there is none here',
    );
  } else if (succession === null && vkey) {
    cannot.push(
      'no succession journal is present, so nothing here says whether the signing key was ever '
      + 'rotated; the epoch ratchet (FR-11) establishes no forward secrecy for this log',
    );
  }
  // The height is the number a reader needs, and DES-12's own example prints
  // it. Without it, DES-19's cross-pack comparison has nothing to key on.
  cannot.push(anchored > 0
    ? `no witness in this set maintains sequence state, so truncation above record_seq ${anchored} is NOT detectable from this evidence alone`
    : 'no checkpoint commits to any height here, so truncation anywhere in this log is NOT detectable from this evidence alone');
  cannot.push('no countersignature is present, so nothing here establishes WHEN any record was written — the ts field is self-asserted');
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
    verdict, summary, tree_size, anchored_tree_size: anchored,
    checks, findings, witnesses, capability: { can, cannot }, trusting, succession,
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


