# M6 failure-mode inventory

Written **before** the code, as M1's through M5's were. Each row is a test; rows
marked **adv** are written before the happy path. **risk** names the shape from
[the risk assessment](risk-assessment.md); **bdy** the direction of the trust
boundary the row guards.

M6 is the ecosystem milestone: capture for any runtime speaking MCP, a
conformance suite anybody can run against their own witness, a witness list
nobody gatekeeps, and a deployment that sends nothing anywhere.

## The boundary M6 introduces, which is new in kind

The MCP proxy is a **man-in-the-middle by design**. Every boundary before it
either read something already written or handed something over; this one sits in
the live path of an agent doing work, and it carries **two obligations at once**:

- **Transparency.** It must not alter what crosses it. A proxy that reorders,
  drops, re-encodes or delays traffic has changed the thing it was recording,
  and the record is then evidence about the proxy rather than about the agent.
- **Capture.** It must record what crossed it. A proxy that forwards
  faithfully and records nothing is worse than no proxy, because the deployment
  believes it is covered.

And NFR-12 is absolute above both: **the collector must never be able to stop an
agent run.** Where transparency and capture conflict — a record that cannot be
written — availability wins and the gap is declared. That ordering is not a
preference; a collector that can halt production is one an operator will
rightly disable.

| | Too much crosses | Too little crosses |
|---|---|---|
| **agent → server** | the proxy rewrites a request | the proxy drops or stalls a request |
| **server → agent** | the proxy alters a result | the proxy truncates a result |
| **into the record** | the proxy records a payload the operator excluded | the proxy records nothing and the deployment believes it is covered |

## The MCP proxy — FR-03, FR-04, NFR-11, INT-05, INT-07

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 1 | an agent calls a tool over stdio | the call and its result are one record, and the bytes the server saw are byte-identical to the bytes the agent sent | 4 | both | |
| 2 | the same over HTTP | identical records from a different transport; a verifier cannot tell which was used, because the record format is adapter-independent | 4 | both | |
| 3 | the proxy cannot write a record | the traffic still flows and the loss is declared. NFR-12 is absolute: a collector that can stop a run is one an operator disables | 7 | out | ✓ |
| 4 | the upstream server returns an error | the error is the result, recorded as an outcome. An error is an outcome, not an absence | 1 | in | ✓ |
| 5 | the upstream server never answers | the call is recorded as a timeout at close, never dropped | 1 | in | ✓ |
| 6 | a request is not valid JSON-RPC | forwarded unchanged and recorded as unparsed. A proxy that repaired traffic would be altering it, and a proxy that refused it would be deciding what the agent may send | 1 | both | ✓ |
| 7 | two calls are in flight at once | both are recorded, each with its own correlation, and neither result is attributed to the other request | 4 | in | ✓ |
| 8 | a response arrives with an id no request used | recorded and reported, never matched to the nearest request | 4 | in | ✓ |
| 9 | the agent's source is compared before and after integration | byte-identical. INT-07 is verified literally, not by inspection | 3 | — | ✓ |
| 10 | a runtime that is not OMA speaks MCP | captured identically. INT-05's whole point is that the proxy does not know what is upstream of it | — | both | |
| 11 | the stream carries a payload larger than memory | streamed through rather than buffered whole, or refused loudly at a stated limit — never silently truncated | 1 | both | ✓ |

## The conformance suite — FR-46, GOV-05, GOV-06

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 12 | a third party runs the suite against their own witness | it passes or fails on their witness's behaviour alone, with no dependency on anything we operate | 3 | out | |
| 13 | a witness accepts a regression | the suite fails. That is the one property a witness exists for | 5 | out | ✓ |
| 14 | a witness accepts two different histories at one height | the suite fails | 5 | out | ✓ |
| 15 | a witness returns a signature that does not verify | the suite fails and says the signature, not the protocol | 1 | out | ✓ |
| 16 | the suite passes against the reference witness | it does, and a test asserts the suite can FAIL — a conformance suite nothing can fail certifies nothing | 5 | out | ✓ |
| 17 | the suite is run with no network | it works against a local witness. A suite needing our infrastructure is a gate, not a check | 3 | out | ✓ |

## The witness list — FR-47, GOV-08, GOV-09

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 18 | the list is parsed | machine-readable, and every entry states acceptable use, rate limits, and whether entries are retained publicly | 1 | in | |
| 19 | an entry omits its acceptable-use position | refused at parse. The field exists so an operator chooses on informed grounds, and an absent one reads as "no restriction" | 1 | in | ✓ |
| 20 | an entry is added by pull request | the documented path, exercised by a test that adds one | — | out | |
| 21 | the list is consulted for a ranking | there is none. GOV-09: no vetting, no ranking, no charging, and a test asserts no field expresses preference | 2 | out | ✓ |
| 22 | the list contains only entries we control | the test fails. GOV-09's own verify asks for entries not controlled by us | 5 | out | ✓ |
| 23 | the collector is given the list | it consumes it, and an unknown witness type is refused rather than skipped | 1 | in | ✓ |

## Zero egress, and the deployment — OPS-05, OPS-03, LEG-12, LEG-13

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 24 | a fully self-hosted deployment runs | nothing leaves the perimeter: no account, no enrolment, no telemetry, no default witness reaching outward | 3 | out | ✓ |
| 25 | the default configuration is used | it does NOT silently reach a public calendar. A default that egresses is a default that violates OPS-05 for anybody who did not read it | 7 | out | ✓ |
| 26 | an operator configures a qualified TSA | it works, and the report says the eIDAS presumption attaches to that anchor and not to our own witness | 2 | out | ✓ |
| 27 | any surface implies the presumption attaches via our witness | the claims lint fails. LEG-12 is checked, not reviewed | 3 | out | ✓ |

## The pairing boundary, after PR #11's review

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 31 | two outstanding calls reuse one JSON-RPC id | both stay accountable and neither is paired. A response bearing that id answers one of them and nothing can say which, so attributing it would invent a tool result | 8 | in | ✓ |
| 32 | a response arrives for an id two calls used | reported, never attributed. Both attempts settle with their own arguments and correlation | 6 | in | ✓ |
| 33 | a call is never answered and the proxy keeps running | it becomes a durable timeout record within the settle interval, not at shutdown | 8 | out | ✓ |
| 34 | the proxy is sent SIGTERM with calls outstanding | they settle before the process exits | 5 | out | |
| 35 | the proxy is SIGKILLed with calls outstanding | the loss is bounded by the settle interval, as FR-61 bounds the observation counter. Stated, not claimed away | 6 | out | ✓ |
| 36 | settlement itself fails to record | the traffic is unaffected and the failure is out of band. A throw from a timer callback would terminate the process — the collector stopping the run | 7 | out | ✓ |

## The CLI contract — FR-49

| # | What happens if… | Expected | risk | bdy | adv |
|---|---|---|---|---|---|
| 28 | every documented invocation is run verbatim | it works. FR-49's test executes the strings from the documentation, so documentation drift is a failing test | 3 | out | ✓ |
| 29 | a documented flag is renamed | the contract test fails before anybody ships it | 5 | out | ✓ |
| 30 | the documentation shows a flag no entry point has | the contract test fails. A manual that names a flag which does not exist is worse than one that omits it | 3 | out | ✓ |
