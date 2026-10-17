# FR-15 — interoperability with transparency-dev/witness

`../test/tlog.test.mjs` drives the adapter against a server built from
`@splitstick/witness-self`. That covers the adapter's logic and cannot, even in
principle, establish interoperability: **a client and a server written against
one reading of one document agree with each other whether or not the reading is
right.**

`probe.mjs` is the thing that can. It runs the real Go implementation, enrols
this project's operator key through the witness's own config path, and anchors
four successive checkpoints, each carrying a real consistency proof from the
size the witness last cosigned.

## Reproducing

No Xcode needed — `transparency-dev/witness` uses `modernc.org/sqlite`, which is
pure Go, so `CGO_ENABLED=0` builds it.

```bash
git clone --depth 1 https://github.com/transparency-dev/witness.git
cd witness && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o /tmp/fr15-omniwitness ./cmd/omniwitness
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o /tmp/fr15-genkeys ./cmd/generate_keys
```

```bash
mkdir -p /tmp/fr15/run
/tmp/fr15-genkeys --origin fr15.witness.local --print > /tmp/fr15/run/witness-keys.txt
FR15_DIR=/tmp/fr15/ node packages/witness-tlog/interop/probe.mjs
```

The probe writes `results/fr-15-interop.json`, which is the requirement's
evidence. It is not in `npm run test:unit`: CI has no Go toolchain, and a test
that silently skips is worse than one that is absent.

## What it found on its first run

Four defects, every one invisible to a suite where we wrote both sides. The
request framing and the 200-response line format — the places
`docs/m6-follow-ups.md` predicted trouble — were already correct.

**1. A witness cosignature is not a plain note signature.** It uses algorithm
byte `0x04` (`algEd25519CosignatureV1`), its blob is 76 bytes
(`keyId ‖ timestamp ‖ signature`) rather than 68, and it signs
`cosignature/v1\ntime <unix>\n<note text>` rather than the note text. Three
consequences, each sufficient on its own to reject a valid signature:

| | real | ours |
|---|---|---|
| key id | `sha256(name ‖ "\n" ‖ 0x04 ‖ key)` → `070e9861` | computed with `0x01` → `2f117086` |
| blob | 76 bytes | `parseNote` **threw** on anything but 68 |
| signed bytes | `cosignature/v1\ntime …\n…` | the bare note text |

The parse failure is the worst of the three: it surfaced through the Anchorer's
`catch` as *"the countersignature does not verify"* — a parse error wearing a
cryptographic verdict's clothes.

**2. The cosignature carries a signed timestamp.** The adapter stated the
opposite (*"the protocol gives the witness nowhere to put one"*) and declared
`establishes: ['sequence']`. The witness's observation time is signed over the
same message as the root, by the key the reader's policy names. It is now
recorded as `received_at`, and the adapter claims `['sequence', 'time']`. Our
clock is still never substituted when a line carries no timestamp.

**3. The 409 body is `<size>\n` and carries no root.** The adapter parsed
`<size>\n<root>\n` and silently kept `root` as `''`. The second line exists only
in *our* witness, which is exactly where the assumption came from. `root` is now
`null`.

**4. The status map was wrong in four places.** Read out of `witness/http.go`:

| status | real meaning | the adapter before |
|---|---|---|
| 404 | `ErrUnknownLog` — not enrolled | fell through to a generic error |
| 403 | `ErrNoValidSignature` — the operator's own signature failed | carried the "enrol your key" message |
| 422 | `ErrInvalidProof` / `ErrRootMismatch` — **the witness refusing** | generic error |
| 429 | `ErrPushback` — the only transient one | generic error |

403 and 404 had their diagnoses crossed: an operator whose signature had failed
was told to enrol a key that was already enrolled. And 422 is the one signal
this entire witness class exists to produce — a history that does not extend
what was already signed — folded into "returned HTTP 422".

## Two traps worth knowing

Both cost real time, and both produced failures that looked like interop bugs.

- **A stray witness on a fixed port.** An earlier run's process still held the
  port; the new one failed to bind, the readiness check got a cheerful answer
  from the stale process, and its older enrolled key returned a 403
  indistinguishable from a genuine failure. The probe now uses a per-run port
  and refuses to talk to anything it did not start.
- **A deleted SQLite file is not a deleted database.** Removing `chkpts.db` and
  leaving `chkpts.db-wal` lets SQLite recover the previous run's state,
  resurrecting an old enrolled key. The probe uses a fresh directory per run.

## Still open

`@splitstick/witness-self` signs plain note signatures (algorithm `0x01`), not
`cosignature/v1`. It therefore does **not** speak the protocol it serves, even
though it is now known what the protocol says. Readers verify it through a
different path than a real tlog-witness — which works, because the algorithm
comes from the reader's acceptance policy, but it means our own witness is not
something a conforming client could necessarily use. Tracked separately; FR-15
is about the adapter being able to use a real witness, and it now can.
