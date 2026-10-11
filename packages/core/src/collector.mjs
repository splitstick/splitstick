/**
 * The collector — DES-14, FR-56, FR-62.
 *
 * One core, thin adapters. This is the core: an adapter notices that something
 * happened, builds nothing cryptographic, and hands plaintext here. The record
 * format is therefore adapter-independent, so a verifier never needs to know
 * which collector wrote a pack — and adding a collector cannot introduce an
 * integrity bug.
 *
 * Plaintext goes in; a commitment goes into the record. That ordering is what
 * makes PRIV-02 structural rather than a rule someone has to remember: there is
 * no API here that accepts a payload and puts it in a record.
 *
 * One chain per collector instance, not per run (FR-56). Concurrent runs
 * interleave; heartbeats carry no run at all.
 */

import { randomBytes } from 'node:crypto';
import { chainEntry, genesis } from './chain.mjs';
import { newSalt } from './leaf.mjs';
import { treeRoot } from './merkle.mjs';
import { checkpointText, encodeNote } from './note.mjs';
import { signNote } from './signer.mjs';
import { extractRefs } from './content.mjs';
import { SCHEMA_VERSION } from './record.mjs';

/** @param {unknown} v @returns {v is Uint8Array} */
const isBytes = v => v instanceof Uint8Array;

export class Collector {
  /**
   * @param {object} o
   * @param {import('./store.mjs').Store} o.store
   * @param {import('./config.mjs').Config} o.config
   * @param {import('./signer.mjs').Signer} o.signer a signing function, never a key — SEC-14
   * @param {string} o.collector the instance identity that scopes the chain
   * @param {string} [o.origin] the log origin; defaults to the signer name
   * @param {() => Date} [o.now] injected so tests are not clock-dependent
   * @param {string} [o.build] the build digest a heartbeat attests — SEC-22
   */
  constructor({ store, config, signer, collector, origin, now, build }) {
    this.store = store;
    this.config = config;
    this.signer = signer;
    this.collector = collector;
    this.origin = origin ?? signer.name;
    this.now = now ?? (() => new Date());
    this.build = build ?? 'sha256:unattested';

    const tip = store.tip();
    this.recordSeq = tip.record_seq;
    this.sourceSeq = tip.source_seq;
    this.head = tip.record_seq === 0 ? genesis() : tip.head;
    this.checkpointSeq = store.lastCheckpointSeq();
  }

  /** The log's tree size — the record count, always equal to record_seq. */
  get tree_size() { return this.recordSeq; }

  /**
   * Consume a source_seq for an observed attempt.
   *
   * Public because the counter advances on every consequential attempt
   * **observed**, written or not. When a write is dropped, the number is spent
   * and the hole is what a verifier sees — an unwritten attempt must leave a
   * mark rather than vanish.
   * @returns {number}
   */
  observe() { return ++this.sourceSeq; }

  /** @returns {string} an opaque random correlation id — DES-13 requires it carry nothing. */
  static newCorrelation() { return randomBytes(12).toString('hex'); }

  /**
   * Externalise a payload and return its commitment.
   * @param {Uint8Array} plaintext
   * @param {{ index?: boolean }} [opts]
   * @returns {{ cid: string, bytes: number }}
   */
  #commit(plaintext, opts = {}) {
    if (!isBytes(plaintext)) {
      throw new TypeError('payloads are handed over as bytes; the collector never records a value');
    }
    return this.store.content.put(plaintext, opts.index ? { refs: extractRefs(plaintext) } : {});
  }

  /**
   * @param {Record<string, unknown>} record
   * @returns {import('./chain.mjs').ChainEntry}
   */
  #write(record) {
    const salt = newSalt();
    const e = chainEntry(record, salt, this.head);
    this.store.append(e);
    this.head = e.head;
    return e;
  }

  /** @param {Partial<Record<string, unknown>>} [extra] */
  #envelope(extra = {}) {
    return {
      v: SCHEMA_VERSION,
      collector: this.collector,
      record_seq: ++this.recordSeq,
      ts: this.now().toISOString().replace(/\.(\d{3})\d*Z$/, '.$1Z'),
      ...extra,
    };
  }

  /**
   * Record a tool call or an approval — FR-05, FR-06, FR-07, FR-62.
   * @param {object} a
   * @param {string} a.tool
   * @param {boolean} [a.consequential] as the tool declared it
   * @param {string|null} [a.run]
   * @param {Uint8Array} [a.agent]
   * @param {Uint8Array} [a.args]
   * @param {Uint8Array} [a.result]
   * @param {'ok'|'error'|'timeout'|'denied'} [a.outcome]
   * @param {number} [a.attempt]
   * @param {string} [a.correlation]
   * @param {{ decision: 'approve'|'deny', reviewer?: Uint8Array, request?: Uint8Array }|null} [a.approval]
   * @param {'tool_call'|'approval'} [a.kind]
   * @returns {import('./chain.mjs').ChainEntry}
   */
  action(a) {
    const record = this.#envelope({
      run: a.run ?? null,
      source_seq: this.observe(),
      kind: a.kind ?? 'tool_call',
      tool: a.tool,
      consequential: a.consequential ?? true,
      ...(a.agent ? { agent: this.#commit(a.agent) } : {}),
      ...(a.args ? { args: this.#commit(a.args) } : {}),
      // FR-55 — only the result is scanned for counterparty references; an
      // argument is what we asked for, a result is what they issued.
      ...(a.result ? { result: this.#commit(a.result, { index: true }) } : {}),
      approval: a.approval
        ? {
          decision: a.approval.decision,
          ...(a.approval.reviewer ? { reviewer: this.#commit(a.approval.reviewer) } : {}),
          ...(a.approval.request ? { request: this.#commit(a.approval.request) } : {}),
        }
        : null,
      outcome: a.outcome ?? 'ok',
      attempt: a.attempt ?? 1,
      correlation: a.correlation ?? Collector.newCorrelation(),
    });
    return this.#write(record);
  }

  /**
   * A liveness record — FR-24's resolution. No run, no source_seq: a heartbeat
   * is not an observation, and `null` says so checkably where a repeated value
   * would be indistinguishable from a second observation.
   * @param {{ policy?: string }} [o]
   */
  heartbeat(o = {}) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'heartbeat',
      build: this.build, policy: o.policy ?? 'sha256:unset',
    }));
  }

  /**
   * A declared observation gap — DES-10. Carries the span it lost.
   * @param {{ from_source_seq: number, to_source_seq: number, reason?: string }} o
   */
  gap(o) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'gap',
      from_source_seq: o.from_source_seq, to_source_seq: o.to_source_seq,
      ...(o.reason ? { reason: o.reason } : {}),
    }));
  }

  /**
   * An interval the collector cannot characterise — FR-60. It never carries a
   * span: inventing one would assert what was lost along with the counter.
   * A verifier reports this as inconclusive, never ok.
   * @param {{ from_ts?: string, to_ts?: string, last_checkpoint_source_seq: number }} o
   */
  gapUnknown(o) {
    const ts = this.now().toISOString().replace(/\.(\d{3})\d*Z$/, '.$1Z');
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'gap_unknown',
      from_ts: o.from_ts ?? ts, to_ts: o.to_ts ?? ts,
      last_checkpoint_source_seq: o.last_checkpoint_source_seq,
    }));
  }

  /**
   * A padding leaf — FR-69, off by default. An explicit record kind with its own
   * record_seq, so record_seq == tree_size still holds; dummy leaves without
   * records would break exactly that.
   */
  padding() {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'padding',
      pad: randomBytes(16).toString('hex'),
    }));
  }

  /**
   * A policy change — FR-23, SEC-12. Chained and anchored like anything else,
   * which is what closes the downgrade attack: weakening the policy and then
   * tampering leaves a countersigned record of the weakening.
   * @param {{ previous: string, next: string }} o digests of the effective policies
   */
  policy(o) {
    return this.#write(this.#envelope({
      run: null, source_seq: null, kind: 'policy',
      previous_policy: o.previous, next_policy: o.next,
    }));
  }

  /**
   * Close the batch: compute the RFC 6962 root over the whole log, sign the
   * note, write it. The root is over every leaf so far, not over this batch —
   * a checkpoint says "this log now has tree_size entries", which is what makes
   * tree_size monotonic and a rollback detectable (DES-05).
   *
   * @returns {Promise<{ checkpoint_seq: number, tree_size: number, root: Buffer, note: string }>}
   */
  async checkpoint() {
    const leaves = this.store.readChain().map(e => e.leaf);
    if (leaves.length === 0) throw new Error('nothing to checkpoint: the log is empty');
    const root = treeRoot(leaves);
    const text = checkpointText({ origin: this.origin, tree_size: leaves.length, root });
    const note = encodeNote(text, [await signNote(text, this.signer)]);
    const checkpoint_seq = ++this.checkpointSeq;
    this.store.writeCheckpoint(checkpoint_seq, note);
    return { checkpoint_seq, tree_size: leaves.length, root, note };
  }
}
