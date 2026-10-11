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
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, appendFileSync } from 'node:fs';
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
  }

  /** @type {Promise<unknown>} */
  #queue;

  /** @returns {{ enrolled: Record<string, string>, seq: Record<string, SeqState> }} */
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

  /** @param {{ enrolled: Record<string, string>, seq: Record<string, SeqState> }} s */
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

  /** @param {string} operator @returns {SeqState} */
  state(operator) {
    return this.#read().seq[operator] ?? { last_size: 0, last_root: '', received_at: '' };
  }

  /** @param {string} operator @returns {{ tree_size: number, root: string, at: string }[]} */
  roots(operator) {
    if (!existsSync(this.rootsPath)) return [];
    return readFileSync(this.rootsPath, 'utf8').split('\n').filter(Boolean)
      .map(l => JSON.parse(l))
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
    const s = this.#read();
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
