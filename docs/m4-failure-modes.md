# M4 failure-mode inventory

Written **before** the code, as M1's through M3b's were. Each row is a test.
Rows marked **adv** are written before the happy path. The **risk** column names
which shape from [the risk assessment](risk-assessment.md) the row guards, so
the inventory and the instrument are not two separate exercises.

M4 is the differentiated claim: every comparable tool can say what was logged is
unaltered, none can say everything was logged. Proving absence is strictly
harder than proving presence, and the whole milestone turns on **composing an
assurance that says exactly what the evidence supports and no more** — risk
shape 2, which produced four defects in M3b's 200-line anchoring command. The
coverage report is a much larger surface of the same kind.

## Heartbeat liveness — FR-24, FR-25, SEC-11

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 1 | the collector is stopped mid-window and restarted | the missing heartbeats are an undeclared gap in the coverage report, located to the interval | 2 | ✓ |
| 2 | the collector is stopped during an interval with **no agent run** | identical treatment. A heartbeat stream inside a run proves nothing about the gap between runs, which is exactly the window an operator would choose | 2 | ✓ |
| 3 | heartbeats are emitted but the clock jumps backwards | reported, not reordered. `record_seq` is the order; `ts` is self-asserted and a backwards jump is evidence about the clock | 1 | ✓ |
| 4 | a heartbeat carries a `ts` that is not a real instant | refused at validation, as any record is | 1 | ✓ |
| 5 | the heartbeat interval is longer than the suppression being looked for | the report states its own resolution and never implies finer. A 60s heartbeat cannot speak to a 50s suppression and must not appear to | 2 | ✓ |
| 6 | `heartbeat_interval` is zero, negative or absent from config | refused at config load. A zero interval makes continuity meaningless rather than perfect | 1 | ✓ |
| 7 | the collector runs with no agent activity at all for the whole window | continuity is 100% and actions are zero. An idle collector is not a stopped one, and the report must distinguish them | 2 | |
| 8 | a window contains heartbeats from two different builds | both are reported, with the point of change. One build is the ordinary case, not an assumption | 4 | ✓ |

## The limits, pinned by tests rather than prose — SEC-11, FR-25, FR-64, DOC-10

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 9 | a patched collector reports the **original** build digest while suppressing actions | **NOT flagged.** A self-reported digest is not remote attestation. The test asserts the absence of a signal — and in the same test asserts a *changed* digest IS reported, so the mechanism is proved live rather than merely silent | M4 | ✓ |
| 10 | an execution path is created entirely outside the collector | **NO signal.** Nothing inside Splitstick observes it. Same construction: the declared-change case must fire in the same test | M4 | ✓ |
| 11 | the coverage report is generated for any window at all | the collector-patch limit appears in the **output**, not only in the design docs. The report is the surface an auditor acts on | 2 | ✓ |
| 12 | any output or doc surface implies patch detection | the claims lint fails. DOC-10 is checked by `lint-claims`, not by reading | 3 | ✓ |
| 13 | the report says "100% captured" | it says 100% **of what the collector reported**, in that phrasing, never softened into a footnote | 2 | ✓ |

## Self-reported capture configuration — FR-64, FR-23, SEC-12

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 14 | a declared upstream is added or removed | the attested configuration digest changes and a `policy` record is emitted | 4 | |
| 15 | the witness set is weakened before tampering | a countersigned `policy` record appears in the chain **before** the next batch. The downgrade is visible in the record, which is all SEC-12 claims | 2 | ✓ |
| 16 | the quorum is lowered | same: a recorded, countersigned event. A policy that changed without a record is the attack | 2 | ✓ |
| 17 | the policy record is written but the change is applied first | refused: the record is written before the new policy takes effect, or the change does not happen | 7 | ✓ |
| 18 | two policy changes land in one window | both appear, in order. Collapsing them to the latest would hide the interval the weaker policy was live | 4 | ✓ |
| 19 | the configuration digest is computed over a serialisation with unstable key order | refused — JCS, as everything else here. A digest that changes without the configuration changing is an alarm that trains people to ignore alarms | 1 | ✓ |

## Coverage report — FR-28, FR-40

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 20 | one action spans several attempts | attempts and logical actions are counted **separately** and differ under retry. One number would make a retried action look like several, or several like one | 4 | ✓ |
| 21 | an action is suppressed before the collector ever saw it | it does not appear, **and the report does not imply completeness**. This is the central honesty of FR-28 | 2 | ✓ |
| 22 | a gap was declared in the window | it appears exactly, with its span, reason and whether it was countersigned | 2 | |
| 23 | a window was anchored late | reported as a coverage gap with the delay. An eleven-minute mutability window is honestly weaker evidence, not silently absent | 2 | ✓ |
| 24 | the requested range has no records at all | `inconclusive`, never `COMPLETE`. An empty window is not a clean one | 7 | ✓ |
| 25 | the range starts before the chain does | the report states the chain's actual start and does not claim coverage of time that predates it | 2 | ✓ |
| 26 | the range is reversed, or the dates are not real dates | refused at argument parsing | 1 | ✓ |
| 27 | records fall outside the range by `ts` but inside by `record_seq` | the range is applied by `ts` and the report says so — and says `ts` is self-asserted | 2 | ✓ |
| 28 | the chain has an undeclared sequence break in the window | the report refuses to issue a completeness claim across it | 7 | ✓ |
| 29 | the store holds several collectors | one is reported and the others are named, never silently picked | 1 | ✓ |
| 30 | the report is asked for a window the heartbeat interval cannot resolve | it states the resolution rather than rounding to something it cannot support | 2 | ✓ |

## Expected witnesses versus proofs present — FR-66

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 31 | a proof is removed from a pack | `WITNESS_MISSING`, **inconclusive** — never reported as deletion. Pending under fail-open, an unavailable witness and a removed receipt are indistinguishable from absence alone | 2 | ✓ |
| 32 | a witness on a slower roll-up tier has no proof yet | reported as **not yet expected**, which is different from missing | 4 | ✓ |
| 33 | a pack pair is supplied where the earlier holds a proof the later does not | removal, demonstrated by cross-pack comparison. This is the only way absence becomes deletion | 2 | |
| 34 | a checkpoint records an expected witness that is not in the acceptance policy | reported, counted towards nothing | 1 | |

## The gates — AC-6, AC-7

| # | What happens if… | Expected | Risk | adv |
|---|---|---|---|---|
| 35 | red-team family **G** stops or patches the collector, then claims quiet | the stop is detected; the patch is **not**, and the gate holds only if every attack assigned to it behaves as declared — detection for the stop, documented non-detection for the patch | M4 | ✓ |
| 36 | red-team family **H** weakens the anchoring policy, then tampers | the policy event is in the record before the tampering, and the tampering is caught by the ordinary chain checks | 2 | ✓ |
| 37 | an attack assigned to AC-6 or AC-7 goes undetected without being declared non-covered | the gate is NOT MET. A gate that passes while an assigned attack succeeds is worse than no gate | 5 | ✓ |
