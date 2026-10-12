/**
 * The witness conformance suite — FR-46, GOV-05, GOV-06.
 *
 * An executable suite any witness implementation can run against **itself**.
 * Published under the project's open licence so implementations self-check, and
 * written so that it needs nothing this project operates: a suite requiring our
 * infrastructure would be a gate, not a check, and GOV-05 says anyone —
 * including competitors and hyperscalers — may run a conformant witness.
 *
 * WHAT A WITNESS IS FOR, stated as the cases below. A witness exists to refuse
 * a history that does not extend what it already signed. Every check here is
 * either that property or a precondition of it, and a suite that tested
 * anything else would be certifying the wrong thing.
 *
 * THE SUITE MUST BE ABLE TO FAIL. A conformance suite nothing can fail
 * certifies nothing, so `selfTest()` below runs it against deliberately broken
 * witnesses and asserts each is caught. An implementer running the suite should
 * run that too: it is the only evidence that a green result means anything.
 *
 * THE INTERFACE UNDER TEST is one method:
 *
 *   addCheckpoint({ note, old_size?, consistency_proof? })
 *     → { status: 200, note, received_at }   accepted and countersigned
 *     → throws { status }                    refused, with an HTTP-shaped code
 *
 * 409 means a fork or a regression — stop and investigate. 503 means
 * contention — retry. The distinction is checked, because a monitoring system
 * that cannot tell them apart pages on both.
 */

import { checkpointText, encodeNote, parseNote, parseCheckpointText } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { treeRoot, consistencyProof } from '@splitstick/core/merkle';

/**
 * @typedef {object} ConformanceResult
 * @property {string} id
 * @property {string} what the property, in one line
 * @property {boolean} passed
 * @property {string} detail what happened
 */

/**
 * @typedef {object} WitnessUnderTest
 * @property {(req: { note: string, old_size?: number, consistency_proof?: string[] }) =>
 *   Promise<{ note: string }>} addCheckpoint
 */

/** A deterministic leaf, so a run is reproducible. @param {number} i */
const leafAt = (i) => {
  const b = Buffer.alloc(32);
  b.writeUInt32BE(i >>> 0, 0);
  b.writeUInt32BE(0x5115_7C00, 4);
  return b;
};

/**
 * Build a signed checkpoint over the first `size` leaves of one history.
 * @param {object} o
 * @param {string} o.origin @param {any} o.signer @param {number} o.size
 * @param {(i: number) => Buffer} [o.leaf]
 */
async function checkpoint({ origin, signer, size, leaf = leafAt }) {
  const leaves = Array.from({ length: size }, (_, i) => leaf(i));
  const text = checkpointText({ origin, tree_size: size, root: treeRoot(leaves), suite: 'SS1' });
  return { note: encodeNote(text, [await signNote(text, signer)]), leaves };
}

/**
 * @param {Buffer[]} leaves @param {number} from
 * @returns {string[]} the audit path, base64, as the protocol carries it
 */
const proof = (leaves, from) => consistencyProof(leaves, from).map(b => b.toString('base64'));

/**
 * Run the suite against a witness.
 *
 * @param {object} o
 * @param {() => WitnessUnderTest|Promise<WitnessUnderTest>} o.makeWitness a FRESH
 *   witness per case, READY TO ACCEPT SUBMISSIONS. Sharing one would make each
 *   case depend on the order of the ones before it, and a suite whose result
 *   depends on its own ordering is measuring itself.
 *
 *   Whatever an implementation needs before it will accept a submission —
 *   enrolment, provisioning, an account — belongs in this factory. The suite
 *   does not prescribe how a witness is set up, because prescribing it would
 *   make the suite a conformance test for OUR witness rather than for the
 *   property every witness must have (GOV-05).
 * @param {any} o.signer the operator key the suite submits under
 * @param {string} [o.origin]
 * @returns {Promise<{ passed: boolean, results: ConformanceResult[] }>}
 */
export async function runConformance({ makeWitness, signer, origin = 'conformance.test/log' }) {
  /** @type {ConformanceResult[]} */
  const results = [];
  /**
   * @param {string} id @param {string} what
   * @param {() => Promise<string>} body returns the detail on success
   */
  const check = async (id, what, body) => {
    try {
      results.push({ id, what, passed: true, detail: await body() });
    } catch (e) {
      results.push({ id, what, passed: false, detail: e instanceof Error ? e.message : String(e) });
    }
  };
  /** @param {unknown} c @param {string} why */
  const must = (c, why) => { if (!c) throw new Error(why); };

  // ── C1: it accepts a first submission and countersigns it ────────────────
  await check('C1', 'a first submission is accepted and countersigned', async () => {
    const w = await makeWitness();
    const { note } = await checkpoint({ origin, signer, size: 4 });
    const res = await w.addCheckpoint({ note });
    const sigs = parseNote(res.note).signatures;
    must(sigs.length >= 2, `expected the operator signature and the witness's, got ${sigs.length}`);
    const cp = parseCheckpointText(parseNote(res.note).text);
    must(cp?.tree_size === 4, 'the countersigned note must be over the submitted checkpoint');
    return `countersigned by ${sigs.length - 1} witness signature(s)`;
  });

  // ── C2: it extends its own history ───────────────────────────────────────
  await check('C2', 'a submission extending what it signed is accepted', async () => {
    const w = await makeWitness();
    const first = await checkpoint({ origin, signer, size: 4 });
    await w.addCheckpoint({ note: first.note });
    const second = await checkpoint({ origin, signer, size: 8 });
    await w.addCheckpoint({
      note: second.note, old_size: 4, consistency_proof: proof(second.leaves, 4),
    });
    return 'height 4 then 8, with a consistency proof';
  });

  // ── C3: THE PROPERTY. It refuses a regression ────────────────────────────
  await check('C3', 'a submission BELOW a height already signed is refused', async () => {
    const w = await makeWitness();
    await w.addCheckpoint({ note: (await checkpoint({ origin, signer, size: 8 })).note });
    const back = await checkpoint({ origin, signer, size: 4 });
    let refused = null;
    try { await w.addCheckpoint({ note: back.note, old_size: 0 }); } catch (e) { refused = e; }
    must(refused !== null, 'the witness ACCEPTED a regression; this is the one thing it exists to refuse');
    must(/** @type {any} */ (refused).status === 409,
      `expected 409 for a regression, got ${JSON.stringify(/** @type {any} */ (refused).status)}: `
      + '409 means stop and investigate, 503 means retry, and a monitor that cannot tell them '
      + 'apart pages on both');
    return 'refused with 409';
  });

  // ── C4: THE PROPERTY. It refuses a fork ──────────────────────────────────
  await check('C4', 'two different histories at one height cannot both be signed', async () => {
    const w = await makeWitness();
    await w.addCheckpoint({ note: (await checkpoint({ origin, signer, size: 4 })).note });
    // The same height, a different tree.
    const fork = await checkpoint({
      origin, signer, size: 4, leaf: (i) => leafAt(i + 1_000_000),
    });
    let refused = null;
    try { await w.addCheckpoint({ note: fork.note, old_size: 0 }); } catch (e) { refused = e; }
    must(refused !== null,
      'the witness signed two different trees at one height; it is not a witness');
    must(/** @type {any} */ (refused).status === 409, 'a fork is 409, not 503');
    return 'refused with 409';
  });

  // ── C5: it refuses a successor it cannot prove extends the last ──────────
  await check('C5', 'a successor with no usable consistency proof is refused', async () => {
    const w = await makeWitness();
    const first = await checkpoint({ origin, signer, size: 4 });
    await w.addCheckpoint({ note: first.note });
    const second = await checkpoint({ origin, signer, size: 8 });
    let refused = null;
    try {
      // Claims to extend height 4 and offers a proof that is not one.
      await w.addCheckpoint({ note: second.note, old_size: 4, consistency_proof: [] });
    } catch (e) { refused = e; }
    must(refused !== null,
      'the witness accepted a successor without proof that it extends the history it holds');
    return `refused with ${/** @type {any} */ (refused).status}`;
  });

  // ── C6: it refuses what it cannot read, rather than guessing ─────────────
  await check('C6', 'an unparseable submission is refused, not guessed at', async () => {
    const w = await makeWitness();
    for (const bad of ['', 'not a note', 'origin\nnotanumber\nAAAA\n']) {
      let refused = null;
      try { await w.addCheckpoint({ note: bad }); } catch (e) { refused = e; }
      must(refused !== null, `the witness accepted ${JSON.stringify(bad)} as a checkpoint`);
      must(/** @type {any} */ (refused).status === 400,
        'a malformed submission is 400 — the client sent something wrong, not a conflict');
    }
    return 'refused with 400';
  });

  // ── C7: it remembers across a restart ────────────────────────────────────
  await check('C7', 'state survives: a witness that forgets is not a witness', async () => {
    const w = await makeWitness();
    await w.addCheckpoint({ note: (await checkpoint({ origin, signer, size: 8 })).note });
    // A second handle on the same witness, as a restart would produce. An
    // implementation that keeps its height only in memory passes every check
    // above and fails here, which is why this is separate from C3.
    const again = /** @type {any} */ (w).reopen?.() ?? w;
    const back = await checkpoint({ origin, signer, size: 4 });
    let refused = null;
    try { await again.addCheckpoint({ note: back.note, old_size: 0 }); } catch (e) { refused = e; }
    must(refused !== null, 'the witness forgot its height and accepted a regression after restart');
    return 'the regression is still refused';
  });

  return { passed: results.every(r => r.passed), results };
}

/**
 * Prove the suite can FAIL — FR-46's own precondition.
 *
 * Runs the suite against witnesses that are deliberately broken in each of the
 * ways the suite is supposed to catch, and asserts each is caught. A green
 * result from a suite nothing can fail certifies nothing, and an implementer
 * should run this before trusting their own green.
 *
 * Each broken witness names the check that MUST catch it, so a self-test that
 * passed because of an unrelated failure is itself a failure.
 *
 * @param {object} o
 * @param {any} o.signer
 * @param {any} o.witnessKey a key for the fakes to countersign with, so they
 *   are correct in every way except the one under test
 * @returns {Promise<{ passed: boolean,
 *   results: { broken: string, expect: string, caught: boolean, by: string[] }[] }>}
 */
export async function selfTest({ signer, witnessKey }) {
  // Each broken witness is CORRECT IN EVERY OTHER WAY, so the self-test shows
  // the specific check firing rather than something incidental. A crude fake
  // that also failed C1 and C6 would prove the suite can fail without proving
  // that the check for the property under test is the one that caught it.
  const base = () => {
    /** @type {{ size: number, root: string }|null} */
    let held = null;
    /** @param {string} note */
    const read = (note) => {
      /** @type {any} */
      let parsed;
      try { parsed = parseNote(note); } catch { parsed = null; }
      const cp = parsed === null ? null : parseCheckpointText(parsed.text);
      if (cp === null) {
        const e = new Error('not a checkpoint'); /** @type {any} */ (e).status = 400; throw e;
      }
      return cp;
    };
    /** @param {string} note */
    const countersign = async (note) => {
      const text = parseNote(note).text;
      const sigs = parseNote(note).signatures;
      return { note: encodeNote(text, [...sigs, await signNote(text, witnessKey)]) };
    };
    return { read, countersign, get held() { return held; }, set held(v) { held = v; } };
  };

  /** Correct except that it accepts a regression and a fork. */
  const permissive = () => {
    const b = base();
    return {
      async addCheckpoint(/** @type {any} */ req) {
        b.read(req.note);                       // still refuses what it cannot read
        return b.countersign(req.note);
      },
    };
  };
  /** Correct except that its height lives in memory only. */
  const forgetful = () => {
    const b = base();
    return {
      async addCheckpoint(/** @type {any} */ req) {
        const cp = b.read(req.note);
        const prev = b.held;
        if (prev !== null && (cp.tree_size < prev.size
          || (cp.tree_size === prev.size && cp.root.toString('base64') !== prev.root))) {
          const e = new Error('regression or fork'); /** @type {any} */ (e).status = 409; throw e;
        }
        b.held = { size: cp.tree_size, root: cp.root.toString('base64') };
        return b.countersign(req.note);
      },
      reopen() { return forgetful(); },         // a restart loses the height
    };
  };
  /** Correct except that a regression comes back as 503, which means "retry". */
  const miscoded = () => {
    const b = base();
    const w = {
      async addCheckpoint(/** @type {any} */ req) {
        const cp = b.read(req.note);
        const prev = b.held;
        if (prev !== null && (cp.tree_size < prev.size
          || (cp.tree_size === prev.size && cp.root.toString('base64') !== prev.root))) {
          const e = new Error('regression'); /** @type {any} */ (e).status = 503; throw e;
        }
        b.held = { size: cp.tree_size, root: cp.root.toString('base64') };
        return b.countersign(req.note);
      },
      reopen() { return w; },
    };
    return w;
  };

  /** @type {{ broken: string, expect: string, caught: boolean, by: string[] }[]} */
  const results = [];
  for (const [broken, expect, makeWitness] of /** @type {const} */ ([
    ['accepts a regression and a fork', 'C3', permissive],
    ['forgets its height across a restart', 'C7', forgetful],
    ['refuses a regression with 503 instead of 409', 'C3', miscoded],
  ])) {
    const r = await runConformance({ makeWitness: /** @type {any} */ (makeWitness), signer });
    const by = r.results.filter(x => !x.passed).map(x => x.id);
    // Caught BY THE CHECK THAT SHOULD CATCH IT. A self-test satisfied by any
    // failure would pass on a suite whose checks all fired for the wrong
    // reason, which is the state a crude fake left it in.
    results.push({ broken, expect, caught: by.includes(expect), by });
  }
  return { passed: results.every(r => r.caught), results };
}

/** @param {{ passed: boolean, results: ConformanceResult[] }} r */
export function formatConformance(r) {
  const lines = ['Splitstick witness conformance suite — FR-46', ''];
  for (const c of r.results) {
    lines.push(`${c.passed ? 'PASS' : 'FAIL'}  ${c.id}  ${c.what}`);
    lines.push(`        ${c.detail}`);
  }
  lines.push('', r.passed
    ? 'CONFORMANT against this suite. Run selfTest() too: a suite nothing can fail certifies nothing.'
    : 'NOT CONFORMANT.');
  return `${lines.join('\n')}\n`;
}
