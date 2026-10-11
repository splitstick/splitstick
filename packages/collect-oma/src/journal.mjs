/**
 * @splitstick/collect-oma — FR-01, FR-02, INT-04, INT-07.
 *
 * A thin adapter, by design (DES-14). It knows how to notice that something
 * happened and hands a plaintext payload to core; it touches no cryptography
 * at all, and a test asserts that by scanning this directory. That is what
 * keeps the record format adapter-independent — a verifier never needs to know
 * which collector wrote a pack — and it means adding a collector cannot
 * introduce an integrity bug.
 *
 * Additive, never a fork (INT-04): this implements OMA's own RunJournal
 * interface against the unmodified package. No patch, no vendored copy, no
 * upstream pull request, and nothing that breaks when OMA releases.
 *
 * Fail-open, never fail-closed (SCOPE-16). The journal contract already says a
 * failed append is surfaced to the caller and never fails the run it observes;
 * a collector that can stop an agent run is one that will, at 3 a.m.
 */

/**
 * @typedef {object} Pending
 * @property {string} tool
 * @property {Uint8Array|undefined} args
 * @property {string} correlation
 * @property {number} attempt
 * @property {string|null} run
 * @property {boolean} [consequential]
 */

/** @param {any} result @returns {string|undefined} */
function resultText(result) {
  if (!result) return undefined;
  const parts = result.content;
  if (!Array.isArray(parts)) return undefined;
  const text = parts.filter(p => p && p.type === 'text').map(p => p.text).join('');
  return text.length ? text : undefined;
}

/** @param {any} content @returns {string} */
function toolOf(content) {
  if (content && typeof content.toolName === 'string') return content.toolName;
  return (content && content.kind) || 'approval';
}

export class SplitstickRunJournal {
  /**
   * @param {object} o
   * @param {any} o.collector
   * @param {any} [o.journal] OMA's own journal to pass through to. Retention is its job.
   * @param {(e: unknown) => void} [o.onError]
   */
  constructor({ collector, journal, onError }) {
    this.collector = collector;
    this.inner = journal;
    this.onError = onError || (() => {});
    /** @type {Map<string, Pending>} */
    this.pendingCalls = new Map();
    /** @type {Map<string, { tool: string, request: Uint8Array, run: string|null, correlation: string, consequential: boolean }>} */
    this.pendingApprovals = new Map();
  }

  /**
   * OMA's contract, satisfied exactly: the events go to the inner journal
   * untouched, and a Splitstick record is derived alongside.
   * @param {readonly any[]} events
   */
  async append(events) {
    for (const e of events) {
      try {
        this.#observe(e);
      } catch (err) {
        // Surfaced, never thrown onward. Losing the audit trail is bad; failing
        // the agent run because the audit trail failed is worse (SCOPE-16).
        this.onError(err);
      }
    }
    if (this.inner) await this.inner.append(events);
  }

  /** @param {any} e */
  #observe(e) {
    if (e.type === 'tool/call') {
      const input = e.call && e.call.input;
      const args = input === undefined ? undefined : Buffer.from(JSON.stringify(input));
      const name = (e.call && e.call.name) || 'unknown';
      const { correlation, attempt } = this.collector.correlate(name, args);
      this.pendingCalls.set(e.call && e.call.id, {
        tool: name, args, correlation, attempt, run: e.runId || null,
      });
      return;
    }
    if (e.type === 'tool/result') {
      const p = this.pendingCalls.get(e.toolCallId);
      this.pendingCalls.delete(e.toolCallId);
      const text = resultText(e.result);
      this.collector.action({
        run: (p && p.run) || e.runId || null,
        tool: (p && p.tool) || 'unknown',
        ...(p && p.args ? { args: p.args } : {}),
        ...(text === undefined ? {} : { result: Buffer.from(text) }),
        outcome: e.result && e.result.isError ? 'error' : 'ok',
        attempt: (p && p.attempt) || 1,
        correlation: (p && p.correlation) || this.collector.correlate(e.toolCallId, undefined).correlation,
      });
      return;
    }
    if (e.type === 'approval/request') {
      const r = e.request;
      this.pendingApprovals.set(r.id, {
        tool: toolOf(r.content),
        request: Buffer.from(JSON.stringify(r.content)),
        run: r.runId || null,
        correlation: this.collector.correlate('approval', Buffer.from(r.id)).correlation,
        // DES-01 wants the tool's own declaration, and OMA's tool-call approval
        // content carries it. Taking it from there beats assuming true.
        consequential: typeof (r.content && r.content.consequential) === 'boolean'
          ? r.content.consequential : true,
      });
      return;
    }
    if (e.type === 'approval/decision') {
      this.#writeDecision(e.decision);
      return;
    }
    if (e.type === 'run/end') {
      this.#settleOutstanding();
      return;
    }
    // Every other RunEvent is execution state OMA already keeps. Recording a
    // turn boundary in the chain would add a leaf and no accountability.
  }

  /** @param {any} decision */
  #writeDecision(decision) {
    const p = this.pendingApprovals.get(decision.requestId);
    this.pendingApprovals.delete(decision.requestId);
    const approved = decision.decision === 'approved';
    const reviewer = decision.reviewer && decision.reviewer.id;
    this.collector.action({
      kind: 'approval',
      run: (p && p.run) || decision.runId || null,
      tool: (p && p.tool) || 'unknown',
      ...(p && p.request ? { args: p.request } : {}),
      consequential: p && typeof p.consequential === 'boolean' ? p.consequential : true,
      approval: {
        decision: approved ? 'approve' : 'deny',
        ...(reviewer ? { reviewer: Buffer.from(String(reviewer)) } : {}),
        ...(p && p.request ? { request: p.request } : {}),
      },
      outcome: approved ? 'ok' : 'denied',
      attempt: 1,
      correlation: (p && p.correlation)
        || this.collector.correlate('approval', Buffer.from(String(decision.requestId))).correlation,
    });
  }

  /**
   * Record anything still outstanding as a timeout.
   *
   * A call that never returned may already have caused an external side effect,
   * so it stays independently accountable (FR-62). Dropping it would make the
   * one case that matters most the one case with no record.
   */
  #settleOutstanding() {
    for (const [id, p] of [...this.pendingCalls]) {
      this.pendingCalls.delete(id);
      try {
        this.collector.action({
          run: p.run, tool: p.tool, ...(p.args ? { args: p.args } : {}),
          outcome: 'timeout', attempt: p.attempt, correlation: p.correlation,
        });
      } catch (err) { this.onError(err); }
    }
    for (const [id, p] of [...this.pendingApprovals]) {
      this.pendingApprovals.delete(id);
      try {
        this.collector.action({
          kind: 'approval', run: p.run, tool: p.tool, args: p.request,
          approval: null, outcome: 'timeout', attempt: 1, correlation: p.correlation,
        });
      } catch (err) { this.onError(err); }
    }
  }

  /** @param {number} seq */
  async readFrom(seq) {
    return this.inner ? this.inner.readFrom(seq) : [];
  }

  async close() {
    this.#settleOutstanding();
    if (this.inner) await this.inner.close();
  }

  /** The journalRef pointer OMA records in a v5 checkpoint. */
  describe() {
    return {
      kind: 'splitstick',
      ...(this.inner && this.inner.describe ? { inner: this.inner.describe() } : {}),
    };
  }
}

/**
 * The approval store — FR-02.
 *
 * OMA's DurableApprovalLedger is driven by a MemoryStore, so the additive
 * integration is a store that passes every operation through and records the
 * approval rows it sees on the way past. The ledger keeps its atomicity,
 * because compareAndSet is forwarded rather than reimplemented.
 */
export class SplitstickApprovalStore {
  /**
   * @param {object} o
   * @param {any} o.store the operator's own MemoryStore
   * @param {any} o.collector
   * @param {(e: unknown) => void} [o.onError]
   */
  constructor({ store, collector, onError }) {
    this.store = store;
    this.journal = new SplitstickRunJournal({ collector, onError });
    this.onError = onError || (() => {});
    if (typeof store.compareAndSet === 'function') {
      this.compareAndSet = async (
        /** @type {string} */ k, /** @type {string|null} */ expected,
        /** @type {string} */ v, /** @type {Record<string, unknown>|undefined} */ m,
      ) => {
        const won = await this.store.compareAndSet(k, expected, v, m);
        if (won) this.#notice(v);
        return won;
      };
    }
    if (typeof store.setWithExpiry === 'function') {
      this.setWithExpiry = (
        /** @type {string} */ k, /** @type {string} */ v,
        /** @type {number} */ t, /** @type {Record<string, unknown>|undefined} */ m,
      ) => this.store.setWithExpiry(k, v, t, m);
    }
  }

  /** @param {string} value a serialised approval row */
  #notice(value) {
    try {
      const row = JSON.parse(value);
      if (row && row.request && row.request.id) {
        this.journal.append([{ type: 'approval/request', request: row.request }]);
      }
      if (row && row.decision && row.decision.requestId) {
        this.journal.append([{ type: 'approval/decision', decision: row.decision }]);
      }
    } catch (err) {
      this.onError(err);
    }
  }

  /** @param {string} k */
  async get(k) { return this.store.get(k); }
  /** @param {string} k @param {string} v @param {Record<string, unknown>} [m] */
  async set(k, v, m) { await this.store.set(k, v, m); this.#notice(v); }
  async list() { return this.store.list(); }
  /** @param {string} k */
  async delete(k) { return this.store.delete(k); }
  async clear() { return this.store.clear(); }
}
