# DES-02 — Canonical encoding

**Milestone:** M1 · **Covers:** FR-52, SEC-07

> The highest-risk element in the project relative to its size. A canonical encoding that
> silently omits a field makes every downstream guarantee hollow while every test still passes.
> This was demonstrated during design: a replacer-array `JSON.stringify` dropped the nested
> `args` object, and changing EUR 2,000,000 to EUR 25 produced an identical digest.

## Decision

**Adopt RFC 8785, the JSON Canonicalization Scheme (JCS).** Do not write a bespoke
canonicaliser.

JCS specifies exactly the things a hand-rolled version gets wrong:

- **Number serialisation.** The hard part. JCS mandates ECMAScript `Number::toString` semantics,
  so `2000000`, `2.0e6` and `2000000.0` all serialise identically. A naive canonicaliser lets an
  attacker change the bytes without changing the value, or the value without changing the bytes.
- **Property ordering** by UTF-16 code unit, recursively, at every depth.
- **String escaping** — the minimal, deterministic form.
- **No insignificant whitespace.**
- **Array order preserved**, because order is semantic.

## Rules

1. The canonical form of a record is JCS over the record object **with no fields removed**.
2. Every field at every nesting depth contributes. There is no allowlist, no denylist, and no
   replacer.
3. Floating-point values are **coerced, never rejected**. A float is encoded as its canonical
   decimal string and the record is flagged `"coerced": ["args.amount"]`, which is itself part of
   the canonical form and therefore digested.

   **A validation rule must never cause an action to go unrecorded.** Dropping or refusing a
   record because its arguments displease the canonicaliser would manufacture exactly the omission
   DES-10 names as its residual risk — self-inflicted, by an integrity feature. Capture always
   wins; the flag tells an auditor the value was reshaped and how.

   Tool authors are still advised to use integers or strings for monetary and quantity arguments,
   because a coerced record is weaker evidence than a clean one. Advice, not a gate.
4. The canonical form is a byte string. It is hashed by DES-03 and never stored separately.

## Test obligation — FR-52

A property test enumerates **every leaf path** in a representative record, including nested
`args` keys, and mutates each in turn. Every mutation must change the digest. The test derives
its paths by walking the object, so a newly added field is covered automatically rather than
when someone remembers to extend a list.

A second test asserts number equivalence: `{"a":2000000}` and `{"a":2.0e6}` must produce the
same canonical bytes, and `{"a":2000000}` versus `{"a":2000001}` must not.

## Consequences

- Rejecting floats is a visible constraint on tool authors. It is the right trade: a tool
  returning `0.1 + 0.2` should not be able to produce two different digests for one value.
- JCS is a dependency decision. If no acceptable implementation exists, implement RFC 8785
  directly against its test vectors — never an approximation of it.
