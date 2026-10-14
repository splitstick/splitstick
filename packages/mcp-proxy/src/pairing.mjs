/**
 * Pairing MCP requests with their results — FR-03, FR-04, DES-14.
 *
 * Transport-independent on purpose: stdio and HTTP differ in how bytes arrive
 * and not at all in what a tool call is, so this is the only place that decides
 * what gets recorded. Two transports with two pairing implementations would
 * eventually disagree about what a call is, and a verifier cannot tell which
 * transport wrote a pack — the record format is adapter-independent (DES-14),
 * so the disagreement would surface as evidence that is subtly wrong rather
 * than as a bug anybody notices.
 *
 * THE RULES THAT ARE EASY TO GET WRONG, and why:
 *
 * A response is matched to a request by its JSON-RPC `id` and by nothing else.
 * Not by arrival order — MCP allows concurrent requests, so the second response
 * is routinely for the first request. An implementation that paired by order
 * would attribute one tool's result to another tool's call, which is a false
 * record rather than a missing one.
 *
 * An `id` nobody sent is REPORTED, never matched to the nearest request. The
 * nearest request is a guess, and a guess here fabricates a tool result.
 *
 * An error IS a result. A call that failed happened; recording it as an absence
 * would make a failed transfer indistinguishable from one that was never
 * attempted.
 *
 * Nothing here forwards or alters bytes. The transports do that, and they
 * forward the ORIGINAL bytes — this sees a parsed copy.
 */

/** MCP's method for invoking a tool. */
export const TOOL_CALL = 'tools/call';

/**
 * @typedef {object} PendingCall
 * @property {string|number} id the JSON-RPC id
 * @property {string} tool
 * @property {Uint8Array} args the arguments as they were sent
 * @property {boolean} verbatim whether `args` is the wire bytes or a re-encoding
 * @property {string} [ambiguousKey] the id key this call was detached from, when
 *   two outstanding calls shared one id
 * @property {string} correlation
 * @property {number} at when the request was seen, for a timeout
 */

/**
 * @typedef {object} Observation
 * @property {'call'|'unmatched'|'unparsed'|'timeout'|'unverbatim'|'notification'
 *   |'ambiguous'|'unattributable'} what
 * @property {string} [tool]
 * @property {Uint8Array} [args]
 * @property {Uint8Array} [result]
 * @property {'ok'|'error'|'timeout'} [outcome]
 * @property {string} [correlation]
 * @property {string} [detail]
 */

export class Pairing {
  /** @type {Map<string, PendingCall>} */
  #pending = new Map();

  /** Counts id-less tools/call messages, so each gets a distinct pending key. */
  #notifications = 0;

  /** Counts calls moved off a colliding id, so each keeps its own pending key. */
  #detached = 0;

  /**
   * Ids two outstanding calls have used, mapped to the instant their
   * QUARANTINE ends — `Infinity` while any of those calls is still pending.
   *
   * A set that was never emptied stood here, and an id that collided once was
   * unusable for the lifetime of the proxy: every later call on it was
   * detached and every response unattributable, long after the ambiguity had
   * ended. Conservative handling of a real collision is right; permanent
   * handling of a finished one degrades the record it was protecting.
   *
   * The window is the same `ms` the sweep uses to decide a call is unanswered.
   * Past it, a response to one of the collided calls is a response the proxy
   * has ALREADY declared never-arriving, so there is nothing left for a late
   * one to be confused with — and before it there genuinely is, because a
   * response carries nothing but the id.
   * @type {Map<string, number>}
   */
  #ambiguous = new Map();

  /**
   * @param {object} o
   * @param {() => string} o.newCorrelation an opaque random identifier — DES-13
   *   requires it to carry nothing, so it is supplied rather than derived here
   * @param {() => number} [o.now] injected so a timeout is testable
   */
  constructor({ newCorrelation, now = () => Date.now() }) {
    this.newCorrelation = newCorrelation;
    this.now = now;
  }

  /** How many calls are awaiting a result. */
  get outstanding() { return this.#pending.size; }

  /**
   * A message travelling agent → server.
   *
   * Returns an observation only when something is worth recording at this
   * point; a tool call is recorded when its RESULT arrives, so that the call
   * and the result are one record (FR-01's shape, which DES-01 keeps).
   *
   * @param {Uint8Array} bytes the exact bytes, for recording
   * @returns {Observation|null}
   */
  request(bytes) {
    const msg = parse(bytes);
    if (msg === null) {
      // Unparsed, and still forwarded by the transport. A proxy that repaired
      // traffic would be altering what it records; one that refused it would be
      // deciding what the agent may send.
      return {
        what: 'unparsed',
        detail: 'a request crossing the proxy is not valid JSON-RPC; it was forwarded unchanged '
          + 'and is recorded as unparsed rather than repaired or refused',
      };
    }
    if (msg.method !== TOOL_CALL) return null;
    if (msg.id === undefined || msg.id === null) {
      // A `tools/call` sent as a JSON-RPC NOTIFICATION. It is not conformant —
      // tools/call is a request — but the proxy exists because the agent is
      // not trusted to report its own actions, and this used to return null:
      // the call was forwarded, many servers dispatch on `method` without
      // looking for an id and would execute it, and NOTHING was recorded. A
      // consequential action crossing the boundary invisibly is the one
      // outcome this collector may not have.
      //
      // So it is pended like any other call, under a key no response can
      // produce — `idKey` is always `string:` or `number:` — and therefore
      // settles as a timeout at expiry or shutdown. `timeout` is the honest
      // value available: observed, and no result was ever received. That it
      // was never going to receive one is in the out-of-band report, because
      // the record vocabulary has no value for it (see docs/m6-follow-ups.md).
      this.#notifications += 1;
      const { args, verbatim } = argsBytes(bytes, msg);
      const tool = typeof msg.params?.name === 'string' ? msg.params.name : 'unknown';
      this.#pending.set(`notification:#${this.#notifications}`, {
        id: `notification:#${this.#notifications}`, tool, args, verbatim,
        correlation: this.newCorrelation(), at: this.now(),
      });
      return {
        what: 'notification',
        detail: `a tools/call for ${JSON.stringify(tool)} arrived with no JSON-RPC id, so it can `
          + 'never receive a result. It was forwarded unchanged and is recorded as an attempt '
          + 'with no result rather than passed over: a consequential call that left no trace is '
          + 'the one thing this proxy exists to prevent',
      };
    }
    const tool = typeof msg.params?.name === 'string' ? msg.params.name : 'unknown';
    // The ARGUMENTS as sent, by span out of the original bytes. A
    // re-serialisation would commit to bytes the server never saw, so the
    // record would attest to a request that was never made.
    const { args, verbatim } = argsBytes(bytes, msg);
    const key = idKey(msg.id);

    this.#retireQuarantine(key);
    const clash = this.#pending.get(key);
    if (clash !== undefined || this.#ambiguous.has(key)) {
      // TWO OUTSTANDING CALLS ON ONE ID. `set()` used to overwrite, so the
      // first invocation was erased: forwarded, executed, and gone from the
      // record with no timeout behind it, while the response that arrived was
      // attributed to whichever call happened to be in the map. A transfer
      // observed crossing this boundary left no trace at all.
      //
      // Reusing an outstanding id breaks JSON-RPC, but a proxy that exists
      // because the agent is not trusted to report its own actions cannot
      // answer misbehaviour by discarding what it saw.
      //
      // So both attempts are kept, each under a key no response can produce,
      // and the id is marked ambiguous. Neither can be paired: a response
      // bearing that id answers one of them and nothing here can say which,
      // and this module's rule is that a guess invents a tool result. Both
      // settle as attempts with no result, each keeping its own arguments and
      // correlation.
      // Infinity while anything is outstanding: the quarantine clock starts
      // when the last collided call settles, not when the collision happened.
      this.#ambiguous.set(key, Infinity);
      if (clash !== undefined) {
        this.#pending.delete(key);
        this.#detached += 1;
        this.#pending.set(`ambiguous:#${this.#detached}`, { ...clash, ambiguousKey: key });
      }
      this.#detached += 1;
      this.#pending.set(`ambiguous:#${this.#detached}`, {
        id: msg.id, tool, args, verbatim, ambiguousKey: key,
        correlation: this.newCorrelation(), at: this.now(),
      });
      return {
        what: 'ambiguous',
        detail: `a second tools/call for ${JSON.stringify(tool)} reused the outstanding JSON-RPC `
          + `id ${JSON.stringify(msg.id)}. Both attempts are kept and both settle with no result: `
          + 'a response carrying that id answers one of them and nothing here can say which, and '
          + 'attributing it would invent a tool result. Neither invocation is discarded',
      };
    }

    this.#pending.set(key, {
      id: msg.id, tool, args, verbatim, correlation: this.newCorrelation(), at: this.now(),
    });
    return verbatim ? null : {
      what: 'unverbatim',
      detail: `the arguments of a call to ${JSON.stringify(tool)} could not be taken verbatim `
        + 'from the request bytes, so the commitment is over a re-encoding of them. It is '
        + 'reported because a reader told "these are the arguments as sent" would otherwise be '
        + 'told something this proxy cannot establish',
    };
  }

  /**
   * A message travelling server → agent.
   * @param {Uint8Array} bytes
   * @returns {Observation|null}
   */
  response(bytes) {
    const msg = parse(bytes);
    if (msg === null) {
      return {
        what: 'unparsed',
        detail: 'a response crossing the proxy is not valid JSON-RPC; it was forwarded unchanged '
          + 'and is recorded as unparsed',
      };
    }
    if (msg.id === undefined || msg.id === null) return null;     // a notification
    const key = idKey(msg.id);
    this.#retireQuarantine(key);
    if (this.#ambiguous.has(key)) {
      // The id had two outstanding calls. Reported, never attributed: this
      // response answers one of them and nothing here can say which.
      return {
        what: 'unattributable',
        detail: `a response arrived with id ${JSON.stringify(msg.id)}, which two outstanding `
          + 'calls used. It is reported rather than attributed to either, because attributing it '
          + 'would record a result against an invocation that may not have produced it. Both '
          + 'attempts are accounted for as attempts with no result',
      };
    }
    const call = this.#pending.get(key);
    if (call === undefined) {
      // An id nobody sent. Reported, never matched to the nearest request: the
      // nearest request is a guess, and a guess here fabricates a tool result.
      return {
        what: 'unmatched',
        detail: `a response arrived with id ${JSON.stringify(msg.id)} and no request used that `
          + 'id. It is reported rather than attributed to the nearest call, because the nearest '
          + 'call is a guess and a guess here invents a tool result',
      };
    }
    this.#pending.delete(key);
    return {
      what: 'call',
      tool: call.tool,
      args: call.args,
      result: bytes,
      // An error IS a result: a call that failed happened, and recording it as
      // an absence would make a failed transfer indistinguishable from one
      // never attempted.
      outcome: msg.error === undefined ? 'ok' : 'error',
      correlation: call.correlation,
    };
  }

  /**
   * Calls still outstanding after `ms`, as timeouts — inventory row 5.
   *
   * A call whose result never arrives is recorded as a timeout rather than
   * dropped. Dropping it would make a server that stopped answering look like
   * an agent that stopped asking.
   * @param {number} ms
   * @returns {Observation[]}
   */
  expire(ms) {
    /** @type {Observation[]} */
    const out = [];
    const now = this.now();
    const cutoff = now - ms;
    /** @type {Set<string>} */
    const touched = new Set();
    for (const [key, call] of [...this.#pending]) {
      if (call.at > cutoff) continue;
      this.#pending.delete(key);
      if (call.ambiguousKey !== undefined) touched.add(call.ambiguousKey);
      out.push({
        what: 'timeout', tool: call.tool, args: call.args,
        outcome: 'timeout', correlation: call.correlation,
      });
    }

    // Start the quarantine for any id whose LAST collided call just settled.
    // Until then the deadline stays Infinity, because a response could still
    // be answering a call that is genuinely outstanding.
    for (const key of touched) {
      const stillPending = [...this.#pending.values()].some(c => c.ambiguousKey === key);
      if (!stillPending) this.#ambiguous.set(key, now + Math.max(0, ms));
    }
    // And let go of the ones whose window has passed, so an id that collided
    // once does not cost memory or accuracy forever.
    for (const [key, until] of [...this.#ambiguous]) {
      if (now >= until) this.#ambiguous.delete(key);
    }
    return out;
  }

  /**
   * Drop an id's quarantine if its window has passed.
   *
   * Called on the read paths as well as from `expire`, so an id becomes usable
   * again at the moment it is safe rather than at the next sweep — a proxy
   * with no sweep configured would otherwise keep the id poisoned.
   * @param {string} key
   */
  #retireQuarantine(key) {
    const until = this.#ambiguous.get(key);
    if (until !== undefined && this.now() >= until) this.#ambiguous.delete(key);
  }

  /** Ids currently quarantined after a collision. For tests and diagnostics. */
  get ambiguous() { return this.#ambiguous.size; }

  /** Every outstanding call, as a timeout. For shutdown — nothing is dropped. */
  closeAll() { return this.expire(-Infinity); }
}

/**
 * The pending-map key for a JSON-RPC id.
 *
 * The TYPE is part of the key. `String(id)` collapsed `1` and `"1"`, which
 * JSON-RPC treats as different ids — so an upstream answering `"1"` to a
 * request made with `1` was matched, and its result was attributed to a call
 * that never received it. This module refuses to match a response to the
 * nearest request because "a guess here invents a tool result"; a type
 * coercion invents one just as effectively, and from the side of the boundary
 * that is not trusted.
 * @param {string|number} id
 */
const idKey = (id) => `${typeof id}:${id}`;

/**
 * @param {Uint8Array} bytes
 * @returns {{ id?: string|number, method?: string, params?: any, error?: any }|null}
 */
function parse(bytes) {
  try {
    const v = JSON.parse(Buffer.from(bytes).toString('utf8'));
    // A JSON array is a JSON-RPC batch, which MCP does not use; treating it as
    // a message would read `id` off an array and match nothing.
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
    return v;
  } catch { return null; }
}

/**
 * The arguments as the agent sent them — the ORIGINAL BYTES, by span.
 *
 * Only the `arguments` subtree, which is the smallest thing that can be said
 * to be "what was asked". Committing to the whole envelope would put the
 * JSON-RPC id in the record, and ids are a per-connection counter that says
 * nothing about the action.
 *
 * This used to be `JSON.stringify(msg.params.arguments)` under a comment
 * saying it was not re-serialised. It was: `{"amount": 1.50,"big":1e2,"note":
 * "caf\u00e9"}` on the wire became `{"amount":1.5,"big":100,"note":"café"}` in
 * the commitment. Self-consistent, verifiable, and not the bytes the agent
 * sent — so a reader told "these are the arguments as sent" was being told
 * something false about the one field most likely to be argued over. The
 * number of a transfer is exactly where `1.50` versus `1.5` stops being
 * cosmetic.
 *
 * Falls back to re-serialising ONLY when the span cannot be located, and says
 * so in the return value so the caller is never left believing a
 * re-serialisation is the wire bytes.
 *
 * @param {Uint8Array} bytes @param {any} msg
 * @returns {{ args: Buffer, verbatim: boolean }}
 */
function argsBytes(bytes, msg) {
  const a = msg.params?.arguments;
  if (a === undefined) return { args: Buffer.alloc(0), verbatim: true };
  const span = argumentsSpan(bytes);
  if (span !== null) {
    return { args: Buffer.from(bytes.subarray(span[0], span[1])), verbatim: true };
  }
  return { args: Buffer.from(JSON.stringify(a), 'utf8'), verbatim: false };
}

/**
 * Locate the `"arguments"` value inside `params` in the raw bytes.
 *
 * A scanner rather than a regular expression, because the value is a balanced
 * structure that may contain the key's own spelling inside a string. It walks
 * the text once, tracking string state and escapes, and returns the half-open
 * byte range of the value — or null, which the caller treats as "cannot claim
 * verbatim" rather than as "no arguments".
 *
 * Only a top-level-of-`params` `"arguments"` is accepted: a nested one belongs
 * to the payload, and committing to it would be committing to a fragment of
 * what was asked while calling it the whole.
 * @param {Uint8Array} bytes
 * @returns {[number, number]|null}
 */
function argumentsSpan(bytes) {
  const t = Buffer.from(bytes).toString('utf8');
  // Byte offsets and string offsets diverge under multi-byte UTF-8, so the
  // scan is done on the string and the result is converted back through the
  // same encoder. Slicing the Buffer at a string index would cut a character
  // in half and produce a commitment to invalid UTF-8.
  let i = 0;
  let depth = 0;
  let inStr = false;
  let esc = false;
  /** Depth at which `params`'s object sits, once seen. */
  let paramsDepth = -1;
  /** @type {string|null} the key most recently completed at this depth */
  let pendingKey = null;
  let keyStart = -1;

  for (; i < t.length; i += 1) {
    const ch = t[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === '"') {
        inStr = false;
        pendingKey = t.slice(keyStart + 1, i);
      }
      continue;
    }
    if (ch === '"') { inStr = true; keyStart = i; continue; }
    if (ch === '{' || ch === '[') {
      if (pendingKey === 'params' && paramsDepth === -1) paramsDepth = depth;
      if (pendingKey === 'arguments' && depth === paramsDepth + 1) {
        const start = i;
        const end = balancedEnd(t, i);
        if (end === -1) return null;
        return [Buffer.byteLength(t.slice(0, start), 'utf8'),
          Buffer.byteLength(t.slice(0, end), 'utf8')];
      }
      depth += 1;
      pendingKey = null;
      continue;
    }
    if (ch === '}' || ch === ']') { depth -= 1; pendingKey = null; continue; }
    if (ch === ',') { pendingKey = null; continue; }
  }
  return null;
}

/**
 * The index just past the structure opening at `open`.
 * @param {string} t @param {number} open @returns {number}
 */
function balancedEnd(t, open) {
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = open; i < t.length; i += 1) {
    const ch = t[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '{' || ch === '[') { depth += 1; continue; }
    if (ch === '}' || ch === ']') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}
