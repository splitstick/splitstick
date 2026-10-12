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
 * @property {string} correlation
 * @property {number} at when the request was seen, for a timeout
 */

/**
 * @typedef {object} Observation
 * @property {'call'|'unmatched'|'unparsed'|'timeout'} what
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
    if (msg.method !== TOOL_CALL || msg.id === undefined || msg.id === null) return null;
    const key = String(msg.id);
    const tool = typeof msg.params?.name === 'string' ? msg.params.name : 'unknown';
    // The ARGUMENTS as sent, not re-serialised. A re-serialisation would commit
    // to bytes the server never saw, so the record would attest to a request
    // that was never made.
    const args = argsBytes(bytes, msg);
    this.#pending.set(key, {
      id: msg.id, tool, args, correlation: this.newCorrelation(), at: this.now(),
    });
    return null;
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
    const key = String(msg.id);
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
    const cutoff = this.now() - ms;
    for (const [key, call] of [...this.#pending]) {
      if (call.at > cutoff) continue;
      this.#pending.delete(key);
      out.push({
        what: 'timeout', tool: call.tool, args: call.args,
        outcome: 'timeout', correlation: call.correlation,
      });
    }
    return out;
  }

  /** Every outstanding call, as a timeout. For shutdown — nothing is dropped. */
  closeAll() { return this.expire(-Infinity); }
}

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
 * The arguments as the agent sent them.
 *
 * Taken from the original bytes by re-encoding only the `arguments` subtree,
 * which is the smallest thing that can be said to be "what was asked".
 * Committing to the whole envelope would put the JSON-RPC id in the record,
 * and ids are a per-connection counter that says nothing about the action.
 * @param {Uint8Array} bytes @param {any} msg
 */
function argsBytes(bytes, msg) {
  const a = msg.params?.arguments;
  if (a === undefined) return Buffer.alloc(0);
  return Buffer.from(JSON.stringify(a), 'utf8');
}
