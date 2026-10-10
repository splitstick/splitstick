# DES-07 — Checkpoint format

**Milestone:** M3a · **Covers:** FR-12, FR-45, INT-01, SEC-25

## Decision

**Adopt the C2SP `tlog-checkpoint` signed-note format.** Not a bespoke envelope — this is the
format Sigstore and the Go checksum database already depend on, which means existing witnesses
can countersign our checkpoints without special-casing us, and that is the entire point of
INT-01.

```
splitstick.example/treasury-agent
4812
3ba3f74c546447627be1c2dfb309e63f8c1d4e7a9b2f5c8d0e3a6b9c2d5f8a1b=

— operator.treasury 7f3a9c2e MEUCIQD…
— audit.internal    5d1e8a3b MEQCIBc…
```

Only signers implementing the C2SP witness protocol appear as note lines. **An RFC 3161 TSA
cannot** — it produces a DER `TimeStampToken`, and an OpenTimestamps proof is not a signature at
all. Those live in the typed envelope beside the note (`DES-20`), each declaring the bytes it
covers.

Lines are: origin (a unique identifier for this log), tree size, base64 root hash, blank line,
then one `— <key name> <key hint> <base64 signature>` line per signer.

**Multiple signature lines on one note is why this format was chosen.** The operator signs, then
each C2SP-protocol witness appends. Quorum (FR-19) counts acceptable proofs across the note lines
*and* the envelope (`DES-20`), and is reported per capability class rather than as one number —
two time-only witnesses are not two independent sequence witnesses.

## The time assertion — FR-45, SEC-25

The witness's countersignature carries **its own clock**, never the operator's. The operator's
`ts` (DES-01) is self-asserted and worth nothing; all trustworthy time in the system enters here.

Which makes the clock behind it load-bearing. **SEC-25** requires the witness to declare its time
source and discipline, and the verifier to surface that declaration — because a countersignature
is only as good as the clock that produced it, and a wrong or manipulable clock invalidates every
timestamp it ever issued.

For an RFC 3161 TSA the declaration comes from its own practice statement. For a self-hosted
witness it is the operator's to state (DES-18). Either way the verifier prints it rather than
leaving a reader to assume NTP.

## Rules

1. The origin string is stable for the life of a log and is derived from the collector identity
   (FR-56). Changing it forks the log, which a verifier reports as `ORIGIN_CHANGED` — and
   cross-pack comparison (DES-19) keys on the operator key as well as the origin, so a fork
   cannot be used to escape a previously disclosed height.
2. Tree size is monotonic. A checkpoint with a smaller size than one already seen is a rollback
   (DES-08's tree-head check).
3. The note is the only thing signed. Nothing about the records' content appears in it — which is
   why only 32 bytes of root ever leave the host (PRIV-01).

## Consequences

- A text format is slightly larger than binary and enormously easier to debug, archive and
  reimplement. For an artifact meant to be verifiable in 2031, legibility is a feature.
- Conformance (FR-46) is testable against C2SP's own vectors rather than only against ourselves.
