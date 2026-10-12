/**
 * The operator-hosted stateful witness — FR-17, FR-42, FR-43, FR-44, FR-50, FR-51.
 *
 * This is the adapter that actually closes attack classes 4 and 5. A TSA signs
 * your hash and forgets you; OpenTimestamps proves a hash existed before a
 * block but offers no index of your submissions. Neither can tell you that a
 * checkpoint it signed last week is missing from the log you are showing it
 * today. Only a party that REMEMBERS YOUR SEQUENCE can, and that is all this
 * is: `(operator_id, last_size, last_root)` plus a signature.
 *
 * It is called operator-hosted because the operator stands it up. It must not
 * be run by the same function that runs the collector — see docs/key-custody.md
 * — and nothing here can enforce that. What it can do is refuse to be a
 * signature oracle: enrolment is required, the submitted note must be signed by
 * the enrolled key, and sequence state is only ever advanced by a submission
 * that proves consistency with what the witness already holds.
 *
 * The state is a file, not a database, because a witness that is hard to run
 * does not get run, and the guarantee is worth nothing if there is no second
 * party.
 *
 * ## Why one writer is enforced, not just serialised
 *
 * An earlier version serialised submissions on a private promise chain and
 * wrote state.json with an atomic rename. That is correct for one instance and
 * worthless across two. Two processes sharing a state directory both read the
 * same prior root, both validated against it, both signed, and both wrote —
 * and the witness ended up retaining TWO DISTINCT ROOTS AT THE SAME HEIGHT.
 * It countersigned two conflicting histories, which is the one thing it exists
 * to prevent. It reproduced six times out of six once the two processes were
 * made to enter the critical section at the same instant; without that barrier
 * the first simply finished before the second began, which is how it looked
 * safe.
 *
 * Atomic replacement stops a half-written file. It does not make
 * read-validate-write atomic, and that sequence is the whole protocol.
 *
 * So the critical section is held under an exclusive cross-process lock — the
 * same `WriteLock` the collector uses for its journals, for the same reason and
 * with the same crash behaviour: a lock naming a process that is gone is taken
 * over rather than left to wedge the witness, because a witness that needs
 * manual recovery after a crash is a witness an operator stops running, and
 * then there is no second party at all.
 *
 * The lock covers ENROLMENT as well as checkpoint transitions. Enrolment
 * decides whose successor a submission is, so two processes enrolling
 * concurrently could disagree about that.
 *
 * ## Why a crash is reconciled, not assumed away
 *
 * A submission commits in two writes: append the root to `roots.jsonl`, then
 * advance `state.json`. A crash between them used to leave the retained
 * history AHEAD of the active state, and after restart the witness would accept
 * a different valid successor at the same height — so the retained history
 * ended up holding two conflicting roots at one height even though the locking
 * was working perfectly. An earlier comment here called a retained root with an
 * unadvanced state harmless; that is true only if recovery reconciles, and it
 * did not.
 *
 * The two writes are not merged into one. Keeping the full root history inside
 * the atomically-rewritten state file would rewrite every retained root on
 * every submission, which is the O(n²) shape DES-13 rejects for the salt
 * journal and for the same reason — at a ten-second cadence that is 8,640
 * entries a day. Instead the order is load-bearing and recovery closes the
 * window:
 *
 * - **Append, then advance.** The append happens only after every check has
 *   passed, so a retained root is one this witness DID accept. The only thing
 *   lost in the window is whether the operator received their signature, and a
 *   retry is idempotent.
 * - **On load and inside the critical section, reconcile.** A retained root
 *   above the active state is adopted. The window becomes a recoverable state
 *   rather than a silent fork.
 * - **Two different roots at one height fails CLOSED.** If that is already on
 *   disk — an older build, a restored backup — the witness cannot tell which it
 *   accepted, and continuing to serve would rest every later signature on a
 *   guess.
 * - **The newline is the commit marker**, as it is for the collector's
 *   journals. A crash mid-append leaves a partial line; it is dropped, because
 *   parsing half of it would invent a root. Damage in the MIDDLE is not a torn
 *   tail and is refused, or one corrupted byte would delete a retained root.
 */

import {
  mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, appendFileSync, truncateSync,
} from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseNote, parseCheckpointText, encodeNote, checkpointText } from '@splitstick/core/note';
import { signNote, verifyNoteSignature, publicKeyFromRaw } from '@splitstick/core/signer';
import { noteKeyId } from '@splitstick/core/note';
import { verifyConsistency } from '@splitstick/core/merkle';
import { WriteLock, StoreBusy } from '@splitstick/core/writelock';

/**
 * A refusal, carrying the protocol status so a client can tell a regression
 * (400) from a fork (409) from an identity problem (403) without parsing prose.
 */
export class WitnessRefused extends Error {
  /** @param {number} status @param {string} message @param {Record<string, unknown>} [body] */
  constructor(status, message, body = {}) {
    super(message);
    this.name = 'WitnessRefused';
    this.status = status;
    this.body = body;
  }
}

/** @typedef {{ last_size: number, last_root: string, received_at: string }} SeqState */

/** @typedef {{ enrolled: Record<string, string>, seq: Record<string, SeqState> }} WitnessState */

export class StatefulWitness {
  /**
   * @param {object} o
   * @param {string} o.dir where state is kept
   * @param {import('@splitstick/core/signer').Signer} o.signer the WITNESS's key —
   *   which the operator must not hold, and which nothing here can check
   * @param {() => Date} [o.now] injected so tests are not clock-dependent
   */
  constructor({ dir, signer, now }) {
    this.dir = dir;
    this.signer = signer;
    this.now = now ?? (() => new Date());
    mkdirSync(dir, { recursive: true });
    this.statePath = join(dir, 'state.json');
    this.rootsPath = join(dir, 'roots.jsonl');
    this.keysPath = join(dir, 'keys.jsonl');
    /**
     * Every submission the witness has been handed, kept in memory for the
     * egress assertion. The check has to be on the traffic rather than on a
     * reviewer's reading of the adapter, so the adapter records the traffic.
     * @type {unknown[]}
     */
    this.receivedForTesting = [];
    /**
     * Exclusive, cross-process, for the whole read-validate-write sequence.
     * The in-process promise chain below is kept as well: the lock refuses a
     * second claim from the same process (StoreBusy), so without the chain two
     * concurrent calls on ONE instance would turn into a spurious conflict
     * rather than queueing.
     */
    this.lock = new WriteLock(join(dir, '.lock'));
    this.#queue = Promise.resolve();
    if (!existsSync(this.keysPath)) {
      this.#appendKey(signer);
    }
    // Refuse to start on an unreadable history. A witness whose retained roots
    // cannot be read has no sequence memory, and every guarantee it offers is
    // void — so it must not come up looking healthy to a monitor while being
    // useless. A torn TAIL is tolerated here; it is the ordinary consequence of
    // a crash. Damage in the middle is not.
    this.#readRoots();
  }

  /** @type {Promise<unknown>} */
  #queue;

  /**
   * Retained roots, tolerating a torn tail and refusing damage in the middle.
   *
   * `roots()` used to parse every line eagerly, so a crash during an append —
   * which leaves a partial line — made the witness unable to read its own
   * retained history at all, and it needed a hand edit before it would run.
   * @returns {{ entries: { operator: string, tree_size: number, root: string, at: string }[],
   *             torn: boolean }}
   */
  #readRoots() {
    if (!existsSync(this.rootsPath)) return { entries: [], torn: false };
    const raw = readFileSync(this.rootsPath, 'utf8');
    const torn = raw.length > 0 && !raw.endsWith('\n');
    const lines = raw.split('\n');
    if (torn) lines.pop();
    /** @type {{ operator: string, tree_size: number, root: string, at: string }[]} */
    const entries = [];
    lines.forEach((line, i) => {
      if (line === '') return;
      /** @type {unknown} */
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        throw new Error(
          `${this.rootsPath} line ${i + 1} is unreadable, and it is not the last line. A torn tail `
          + 'is the ordinary consequence of a crash; damage in the middle is not, and skipping it '
          + 'would let one corrupted byte delete a retained root.',
        );
      }
      // Shape as strictly as syntax. Being strict about JSON and lax about
      // shape was the worst combination available: reconciliation used to skip
      // an entry whose tree_size was the STRING "20", so a retained root
      // vanished from the check and a conflicting root at that height was
      // accepted. The lax half is where the bypass lived.
      entries.push(this.#validateRootEntry(parsed, i + 1));
    });
    return { entries, torn };
  }

  /**
   * One retained entry, or an error naming what is wrong with it.
   *
   * Refused rather than skipped. A retained root is evidence; an entry that
   * cannot be read as one must stop the witness, not quietly disappear from
   * the reconciliation that depends on it.
   *
   * @param {unknown} parsed @param {number} line
   * @returns {{ operator: string, tree_size: number, root: string, at: string }}
   */
  #validateRootEntry(parsed, line) {
    /** @param {string} why @returns {never} */
    const bad = (why) => {
      throw new Error(
        `${this.rootsPath} line ${line} is not a usable retained root: ${why}. It is refused `
        + 'rather than skipped, because an entry that disappears from reconciliation lets a '
        + 'conflicting root at the same height through.',
      );
    };
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return bad('it is not a JSON object');
    }
    const r = /** @type {Record<string, unknown>} */ (parsed);
    if (typeof r.operator !== 'string' || r.operator === '') {
      return bad(`operator is ${JSON.stringify(r.operator)}`);
    }
    if (!Number.isSafeInteger(r.tree_size) || /** @type {number} */ (r.tree_size) < 1) {
      return bad(`tree_size is ${JSON.stringify(r.tree_size)}, not a positive integer`);
    }
    if (typeof r.root !== 'string') return bad(`root is ${JSON.stringify(r.root)}`);
    const root = decodeRoot(r.root);
    if (!root) {
      return bad('root is not 32 base64-encoded bytes, which is what a SHA-256 tree root is');
    }
    if (typeof r.at !== 'string' || r.at === '') return bad(`at is ${JSON.stringify(r.at)}`);
    return {
      operator: r.operator,
      tree_size: /** @type {number} */ (r.tree_size),
      root: r.root,
      at: r.at,
    };
  }

  /**
   * Remove a torn trailing line, under the lock, before anything is appended.
   *
   * Tolerating it on read was not enough. `appendFileSync` writes AFTER the
   * partial bytes, so the next submission produced one malformed line that was
   * newline-terminated — damage in the middle, which fails closed. A
   * recoverable crash therefore became permanent corruption through ordinary
   * operation, and the submission that corrupted the journal was accepted and
   * signed first: the operator held a countersignature for a height the witness
   * could no longer read.
   *
   * Truncating to the last newline removes only the incomplete line. A
   * complete entry always ends in one.
   */
  #repairTornTail() {
    if (!existsSync(this.rootsPath)) return;
    const raw = readFileSync(this.rootsPath, 'utf8');
    if (raw.length === 0 || raw.endsWith('\n')) return;
    const keep = raw.lastIndexOf('\n') + 1;
    truncateSync(this.rootsPath, Buffer.byteLength(raw.slice(0, keep), 'utf8'));
  }

  /**
   * Bring the active state up to the retained history — the crash window.
   *
   * @param {WitnessState} s
   * @returns {{ state: WitnessState, adopted: string[], ambiguous: Map<string, number> }}
   */
  #reconcile(s) {
    // Every entry is already validated by #readRoots, so there is nothing to
    // skip here. The filter that used to live at this line is where a
    // wrong-typed tree_size disappeared from the check.
    const { entries } = this.#readRoots();
    /** @type {Map<string, Map<number, Set<string>>>} */
    const byOperator = new Map();
    for (const r of entries) {
      const heights = byOperator.get(r.operator) ?? new Map();
      const roots = heights.get(r.tree_size) ?? new Set();
      roots.add(r.root);
      heights.set(r.tree_size, roots);
      byOperator.set(r.operator, heights);
    }

    /** @type {string[]} */
    const adopted = [];
    /** @type {Map<string, number>} */
    const ambiguous = new Map();
    for (const [operator, heights] of byOperator) {
      for (const [height, roots] of heights) {
        if (roots.size > 1) ambiguous.set(operator, height);
      }
      if (ambiguous.has(operator)) continue;
      let highest = 0;
      for (const h of heights.keys()) if (h > highest) highest = h;
      const current = s.seq[operator]?.last_size ?? 0;
      if (highest <= current) continue;
      const root = [...(heights.get(highest) ?? [])][0];
      if (root === undefined) continue;
      const kept = entries.filter(r => r.operator === operator && r.tree_size === highest);
      s.seq[operator] = {
        last_size: highest,
        last_root: root,
        received_at: kept[kept.length - 1]?.at ?? this.now().toISOString(),
      };
      adopted.push(operator);
    }
    return { state: s, adopted, ambiguous };
  }

  /** @returns {WitnessState} */
  #read() {
    if (!existsSync(this.statePath)) return { enrolled: {}, seq: {} };
    try {
      const d = JSON.parse(readFileSync(this.statePath, 'utf8'));
      return { enrolled: d.enrolled ?? {}, seq: d.seq ?? {} };
    } catch {
      // A witness that silently starts fresh after a damaged state file has
      // forgotten the sequence, which is the one thing it is for.
      throw new Error(`${this.statePath} is unreadable; a witness must not resume without its state`);
    }
  }

  /** @param {WitnessState} s */
  #write(s) {
    // Atomic: the state and the signature it authorises must land together, or
    // a crash between them leaves a countersignature the witness does not
    // remember issuing.
    const tmp = `${this.statePath}.${randomBytes(6).toString('hex')}`;
    writeFileSync(tmp, JSON.stringify(s, null, 1), { mode: 0o600 });
    renameSync(tmp, this.statePath);
  }

  /** @param {import('@splitstick/core/signer').Signer} signer */
  #appendKey(signer) {
    appendFileSync(this.keysPath, JSON.stringify({
      public_key: signer.publicKey.toString('base64'),
      key_id: signer.keyId.toString('hex'),
      from: this.now().toISOString(),
    }) + '\n', { mode: 0o600 });
  }

  /**
   * Register an operator identity and its public key — FR-42.
   *
   * A precondition of sequence state: without an identity the witness cannot
   * know whose successor a submission is. Re-enrolling under a different key is
   * refused, because it would silently reset the sequence.
   *
   * @param {string} operator @param {Uint8Array} publicKey raw 32 bytes
   */
  enrol(operator, publicKey) {
    if (typeof operator !== 'string' || !operator) throw new TypeError('an operator identity is a string');
    if (publicKey?.length !== 32) throw new TypeError('an Ed25519 public key is 32 bytes');
    // Under the lock: enrolment decides whose successor a submission is, so two
    // processes enrolling at once could disagree about that.
    return this.#exclusively(() => {
      const s = this.#read();
      const b64 = Buffer.from(publicKey).toString('base64');
      const existing = s.enrolled[operator];
      if (existing !== undefined && existing !== b64) {
        throw new Error(
          `${operator} is already enrolled under a different key; re-enrolling would reset the `
          + 'sequence state this witness exists to keep. Enrol a new identity instead.',
        );
      }
      if (existing === b64) return;
      s.enrolled[operator] = b64;
      this.#write(s);
    });
  }

  /**
   * Run `fn` holding the exclusive lock, and release it however `fn` ends.
   *
   * A contended lock surfaces as 503, not 409. They are different events and
   * an operator's response differs: 503 means retry, 409 means a history has
   * forked and somebody should stop and look. Reporting contention as a fork
   * would send them hunting for an attacker that is not there.
   *
   * @template T @param {() => T} fn @returns {T}
   */
  #exclusively(fn) {
    this.#claim();
    try {
      return fn();
    } finally {
      this.lock.release();
    }
  }

  /**
   * Claim the exclusive lock, translating contention into a protocol status.
   *
   * 503, not 409. They are different events and an operator's response
   * differs: 503 means retry, 409 means a history has forked and somebody
   * should stop and look. Reporting contention as a fork would send them
   * hunting for an attacker that is not there.
   */
  #claim() {
    try {
      this.lock.claim();
    } catch (e) {
      if (e instanceof StoreBusy) {
        throw new WitnessRefused(503,
          'another witness process holds this state directory. The read-validate-write sequence '
          + 'must be exclusive, or two processes can countersign conflicting histories at the same '
          + 'height. Retry.',
          { retry: true });
      }
      throw e;
    }
  }

  /**
   * The sequence position, reconciled.
   *
   * Read-only: it reports the position a submission would be validated
   * against, including a root retained in a crash window. Reporting the raw
   * file would show a reader 10 while the witness is about to validate against
   * 20.
   * @param {string} operator @returns {SeqState}
   */
  state(operator) {
    const { state } = this.#reconcile(this.#read());
    return state.seq[operator] ?? { last_size: 0, last_root: '', received_at: '' };
  }

  /** @param {string} operator @returns {{ tree_size: number, root: string, at: string }[]} */
  roots(operator) {
    return this.#readRoots().entries
      .filter(r => r.operator === operator)
      .map(({ tree_size, root, at }) => ({ tree_size, root, at }));
  }

  /**
   * `POST /add-checkpoint` — FR-43.
   *
   * Accepts when BOTH hold: `tree_size >= last_size`, and an RFC 6962
   * consistency proof from `last_size` to `tree_size` verifies against
   * `last_root`. Truncation detection is stronger this way than a
   * successor-only rule would be: a truncated or forked tree fails the proof at
   * ANY size, so the witness refuses without needing to know how many records
   * should have arrived.
   *
   * @param {{ note: string, old_size?: number, consistency_proof?: string[] }} req
   * @returns {Promise<{ status: 200, note: string }>}
   */
  async addCheckpoint(req) {
    // Two layers, because they answer different questions. The promise chain
    // queues concurrent calls on THIS instance; the exclusive lock inside
    // #addCheckpoint stops a second PROCESS interleaving its own
    // read-validate-write with ours.
    const run = this.#queue.then(() => this.#addCheckpoint(req), () => this.#addCheckpoint(req));
    this.#queue = run.catch(() => {});
    return run;
  }

  /** @param {{ note: string, old_size?: number, consistency_proof?: string[] }} req */
  async #addCheckpoint(req) {
    this.receivedForTesting.push(req);
    if (req === null || typeof req !== 'object' || typeof req.note !== 'string') {
      throw new WitnessRefused(400, 'a submission carries a note');
    }
    /** @type {ReturnType<typeof parseNote>} */
    let note;
    /** @type {ReturnType<typeof parseCheckpointText>} */
    let cp;
    try {
      note = parseNote(req.note);
      cp = parseCheckpointText(note.text);
    } catch (e) {
      throw new WitnessRefused(400, `the note is not a parseable checkpoint: ${e instanceof Error ? e.message : String(e)}`);
    }

    // Everything from here to the signature is one critical section. Reading
    // the prior root, validating against it, retaining the new one and
    // advancing the state cannot be interleaved by another process, or both
    // processes countersign conflicting histories at the same height.
    this.#claim();
    try {
      return await this.#commit(req, note, cp);
    } finally {
      this.lock.release();
    }
  }

  /**
   * The critical section. Called only with the exclusive lock held.
   * @param {{ note: string, old_size?: number, consistency_proof?: string[] }} req
   * @param {ReturnType<typeof parseNote>} note
   * @param {ReturnType<typeof parseCheckpointText>} cp
   * @returns {Promise<{ status: 200, note: string }>}
   */
  async #commit(req, note, cp) {
    // Under the lock, before anything is validated: another process may have
    // crashed in the window between its append and its state write, and
    // validating against a state that is behind the retained history is how a
    // conflicting successor gets accepted.
    // Under the lock: repair first, so reconciliation and the append that
    // follows both see a journal whose every line is complete.
    this.#repairTornTail();
    const { state: s, adopted, ambiguous } = this.#reconcile(this.#read());
    const ambiguousAt = ambiguous.get(cp.origin);
    if (ambiguousAt !== undefined) {
      throw new WitnessRefused(409,
        `this witness holds two different roots at height ${ambiguousAt} for ${cp.origin} and `
        + 'cannot tell which it accepted, so it will not sign anything further for that operator. '
        + 'Continuing would rest every later signature on a guess. Reconcile the retained history '
        + 'against the operator\'s checkpoints and remove the root that was never issued.',
        { last_size: ambiguousAt });
    }
    if (adopted.includes(cp.origin)) {
      // Durable, because we hold the lock. Otherwise every submission would
      // redo the same recovery and `state()` would disagree with the file.
      this.#write(s);
    }
    const enrolled = s.enrolled[cp.origin];
    if (enrolled === undefined) {
      throw new WitnessRefused(403,
        `${cp.origin} is not enrolled with this witness. Enrolment is a precondition of sequence `
        + 'state: without an identity there is no "whose successor is this" to answer.');
    }
    // A witness that signs whatever is presented to it is a signature oracle,
    // and its countersignature then establishes nothing about who wrote the log.
    const opPub = Buffer.from(enrolled, 'base64');
    const sig = note.signatures.find(x => x.name === cp.origin);
    if (!sig || !sig.keyId.equals(noteKeyId(cp.origin, opPub))
      || !await verifyNoteSignature(note.text, sig, {
        name: cp.origin, publicKey: opPub, keyId: noteKeyId(cp.origin, opPub),
      })) {
      throw new WitnessRefused(403,
        `the note is not signed by the key enrolled for ${cp.origin}`);
    }

    const prev = s.seq[cp.origin];
    const last_size = prev?.last_size ?? 0;
    const last_root = prev?.last_root ?? '';
    const root_b64 = cp.root.toString('base64');

    if (cp.tree_size < last_size) {
      throw new WitnessRefused(400,
        `tree_size ${cp.tree_size} regresses below the ${last_size} this witness already signed`,
        { last_size, last_root });
    }
    if (cp.tree_size === last_size) {
      if (root_b64 !== last_root) {
        throw new WitnessRefused(409,
          `a fork at height ${last_size}: this witness holds a different root at that size`,
          { last_size, last_root });
      }
      // Idempotent. A retry after a dropped response is not an attack, and must
      // not produce a second distinct signature over the same subject.
      return { status: /** @type {200} */ (200), note: await this.#countersign(note.text, req.note) };
    }
    if (last_size > 0) {
      if (req.old_size !== last_size) {
        throw new WitnessRefused(409,
          `old_size ${req.old_size} is not the ${last_size} this witness remembers; a proof from a `
          + 'size it never saw proves consistency with something else',
          { last_size, last_root });
      }
      const proof = (req.consistency_proof ?? []).map(b => Buffer.from(b, 'base64'));
      if (proof.length === 0 || !verifyConsistency(
        last_size, Buffer.from(last_root, 'base64'), cp.tree_size, cp.root, proof,
      )) {
        throw new WitnessRefused(409,
          `the consistency proof from ${last_size} to ${cp.tree_size} does not verify against the `
          + 'root this witness holds: the history has forked or been rewritten below that height',
          { last_size, last_root });
      }
    }

    const at = this.now().toISOString();
    // Retain first, then advance. A retained root for a submission that failed
    // to commit is harmless; an advanced state with no retained root is not.
    appendFileSync(this.rootsPath, JSON.stringify({
      operator: cp.origin, tree_size: cp.tree_size, root: root_b64, at,
    }) + '\n', { mode: 0o600 });
    s.seq[cp.origin] = { last_size: cp.tree_size, last_root: root_b64, received_at: at };
    this.#write(s);
    return { status: /** @type {200} */ (200), note: await this.#countersign(note.text, req.note) };
  }

  /**
   * Append the witness's signature line to the note. The signed subject is the
   * note TEXT, unaltered — a witness that rewrites what it signs is signing its
   * own statement rather than the operator's.
   * @param {string} text @param {string} blob
   */
  async #countersign(text, blob) {
    const existing = parseNote(blob).signatures.filter(s => s.name !== this.signer.name);
    return encodeNote(text, [...existing, await signNote(text, this.signer)]);
  }

  /**
   * The witness's own signed tree head for an operator — FR-50.
   *
   * Published so the operator or any third party can poll it. A witness serving
   * an earlier head than one previously observed is the witness's own
   * misbehaviour, and this is what makes it detectable rather than suspected.
   * @param {string} operator @returns {Promise<string>}
   */
  async treeHead(operator) {
    const st = this.state(operator);
    const text = checkpointText({
      origin: `${this.signer.name}/head/${operator}`,
      tree_size: st.last_size,
      root: st.last_root ? Buffer.from(st.last_root, 'base64') : Buffer.alloc(32),
      suite: 'SS1',
    });
    return encodeNote(text, [await signNote(text, this.signer)]);
  }

  /**
   * The witness's signed key history — FR-51. Countersignatures from retired
   * keys stay verifiable indefinitely; rotation is not an amnesty.
   * @returns {Promise<{ keys: { public_key: string, key_id: string, from: string }[], note: string }>}
   */
  async keyHistory() {
    const keys = existsSync(this.keysPath)
      ? readFileSync(this.keysPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
      : [];
    // Signed by the CURRENT key over a digest of the whole history, so a reader
    // who trusts today's key can attribute every earlier one.
    const { createHash } = await import('node:crypto');
    const digest = createHash('sha256').update(JSON.stringify(keys)).digest();
    const text = checkpointText({
      origin: `${this.signer.name}/keys`, tree_size: keys.length, root: digest, suite: 'SS1',
    });
    return { keys, note: encodeNote(text, [await signNote(text, this.signer)]) };
  }

  /** @param {import('@splitstick/core/signer').Signer} next */
  async rotate(next) {
    if (next.name !== this.signer.name) {
      throw new Error('rotating the witness identity is becoming a different witness');
    }
    this.#appendKey(next);
    this.signer = next;
  }
}

/**
 * Strict base64 for a 32-byte tree root. `Buffer.from` is lenient and would
 * accept rubbish, silently producing a shorter root.
 * @param {string} v @returns {Buffer|null}
 */
function decodeRoot(v) {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(v)) return null;
  const b = Buffer.from(v, 'base64');
  return b.length === 32 ? b : null;
}

export { publicKeyFromRaw };

/**
 * The state file's shape, so a test or an operator's tooling can read it
 * without this module offering a way to MOVE the sequence backwards.
 *
 * `rollbackForTesting()` used to live on the class. It was named so that every
 * call site said what it was, which is not the same as not existing: a method
 * that rewinds sequence state is a method that undoes the only guarantee this
 * witness provides, and shipping it in the package that provides that guarantee
 * is an invitation. The rollback-detection test writes the file instead, which
 * is exactly what a dishonest operator would have to do.
 */
export const STATE_FILE = 'state.json';
