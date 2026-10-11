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

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { recomputeChain } from '@splitstick/core/chain';
import { treeRoot } from '@splitstick/core/merkle';
import { parseNote, parseCheckpointText, parseVkey, SUITES } from '@splitstick/core/note';
import { verifyNoteSignature } from '@splitstick/core/signer';

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
 *   verdict: Verdict, tree_size: number,
 *   summary: { passed: number, unanswered: number, failed: number },
 *   checks: { name: string, verdict: Verdict, detail?: string }[],
 *   findings: Finding[],
 *   witnesses: { id: string, type: string, establishes: string }[],
 *   capability: { can: string[], cannot: string[] },
 *   trusting: string[],
 * }>}
 */
export async function verifyStore(root, opts = {}) {
  const collector = opts.collector ?? inferCollector(root);
  const store = new Store(root, collector);
  /** @type {Finding[]} */
  const findings = [];
  /** @type {{ name: string, verdict: Verdict, detail?: string }[]} */
  const checks = [];
  /** @param {string} name @param {Verdict} verdict @param {string} [detail] */
  const check = (name, verdict, detail) => { checks.push({ name, verdict, ...(detail ? { detail } : {}) }); };

  const entries = store.readChain();
  if (entries.length === 0) {
    findings.push({ code: 'NO_EVIDENCE', verdict: 'inconclusive', detail: `no chain for collector ${collector} under ${root}` });
    return report(0, checks, findings, [], collector, opts.vkey);
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
  const notes = readCheckpoints(root);
  /** @type {Verdict[]} */
  const treeVs = [];
  /** @type {Verdict[]} */
  const sigVs = [];
  const pinned = opts.vkey ? parseVkey(opts.vkey) : null;
  const leaves = entries.map(e => e.leaf);

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
    } else if (await verifyNoteSignature(note.text, sig, { name: pinned.name, publicKey: pinned.publicKey, keyId: pinned.keyId })) {
      sigVs.push('ok');
    } else {
      sigVs.push('fail');
      findings.push({
        code: 'OPSIG_INVALID', verdict: 'fail',
        detail: `checkpoint ${seq} is not signed by the operator identity it claims`,
      });
    }
  }
  check('TREE', combine(treeVs));
  check('OP-SIG', combine(sigVs));

  // 7-10 need evidence M1 does not produce. Reported, not skipped.
  check('WITNESS', 'inconclusive', 'no countersignature in this store (DES-08 ships in M3a)');
  check('ROLLUP', 'inconclusive', 'no roll-up checkpoint in this store (FR-53 ships in M3a)');
  check('COVERAGE', 'inconclusive', 'heartbeat continuity is not yet reconciled (DES-10 ships in M4)');
  check('POLICY', 'inconclusive', 'policy-change reconciliation ships with DES-09 enforcement');

  return report(entries.length, checks, findings, notes, collector, opts.vkey);
}

/**
 * @param {number} tree_size
 * @param {{ name: string, verdict: Verdict, detail?: string }[]} checks
 * @param {Finding[]} findings
 * @param {{ seq: number, blob: string }[]} notes
 * @param {string} collector
 * @param {string} [vkey]
 */
function report(tree_size, checks, findings, notes, collector, vkey) {
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
    failed: checks.filter(c => c.verdict === 'fail').length,
  };

  // FR-57 — derived from the proof types actually present, not from
  // configuration. A verifier reads evidence, and the operator's config is not
  // evidence. There are no countersignatures in M1, so the honest answer is a
  // short list of what this evidence cannot do.
  /** @type {{ id: string, type: string, establishes: string }[]} */
  const witnesses = [];

  const can = [];
  const cannot = [];
  if (tree_size > 0) {
    can.push('ordering and content integrity of every record in this chain');
    can.push('that no record was altered, inserted, removed or reordered within it');
  }
  if (notes.length && vkey) {
    can.push(`that the operator identity ${collector} signed the tree size and root it claims`);
  }
  cannot.push('no witness in this set maintains sequence state, so truncation of the tail is NOT detectable from this evidence alone');
  cannot.push('no countersignature is present, so nothing here establishes WHEN any record was written — the ts field is self-asserted');
  cannot.push('an action that was never observed leaves no trace here; this evidence speaks to what was recorded');
  if (!vkey) cannot.push('no operator identity was pinned, so the signature on the checkpoint was not checked against anything');

  const trusting = ['the cryptographic primitives (SHA-256, Ed25519)'];
  if (vkey) trusting.push(`the operator identity ${vkey.split('+')[0]} to be the one you meant`);
  trusting.push('the operator for the completeness of what was captured, until a witness is configured');

  return { verdict, summary, tree_size, checks, findings, witnesses, capability: { can, cannot }, trusting };
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

/** @param {string} root @returns {{ seq: number, blob: string }[]} */
function readCheckpoints(root) {
  const dir = join(root, 'checkpoints');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .map(f => ({ m: /^([0-9]+)\.note$/.exec(f), f }))
    .filter(x => x.m)
    .map(x => ({ seq: Number(/** @type {RegExpExecArray} */ (x.m)[1]), blob: readFileSync(join(dir, x.f), 'utf8') }))
    .sort((a, b) => a.seq - b.seq);
}

/** @param {string} root */
function inferCollector(root) {
  const dir = join(root, 'chain');
  if (!existsSync(dir)) return 'unknown';
  const f = readdirSync(dir).find(n => n.endsWith('.jsonl'));
  return f ? f.replace(/\.jsonl$/, '') : 'unknown';
}
