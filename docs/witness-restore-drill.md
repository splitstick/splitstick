# Witness restore drill

**Covers:** OPS-06 · **Related:** FR-43, FR-44, LEG-04, §5 of the
[Witness Practice Statement](witness-practice-statement.md),
[witness outages](witness-outages.md)

```bash
npm run drill:restore
```

A witness that loses its roots destroys the corroboration it exists to provide,
so "it is backed up" has to mean something checkable. This drill is a script
rather than a description, because a described procedure is one nobody has run.

## What it does

1. Builds a witness holding a real history, and copies the store — the backup.
2. Advances the live witness past the copy, so the backup is genuinely stale.
3. Destroys the live store and restores the copy.
4. Replays a **conflicting** submission and asserts the restored witness refuses
   it; then replays the operator's **honest** next submission and asserts that
   is refused too.
5. Resubmits from the height the restored witness reports, and asserts recovery.

It prints the measured recovery point and exits non-zero if the restored witness
accepts anything it should not — including if it measures no loss at all, which
would mean the drill never exercised a stale backup.

## The recovery point objective

**One submission.** The witness commits a retained root before advancing its
sequence state, so the most an unclean shutdown can lose is the receipt of a
submission the operator never got a signature for — and that submission is
idempotent on retry.

That is the RPO for a *crash*. The RPO for a *restore* is whatever the backup
interval is, and the drill measures it rather than assuming it: in the run
above, a backup taken 50 records before the failure cost 50 records of witnessed
history and one retained root.

## The refusal that is not a bug

After a restore, the operator's own next submission **fails** with `409`, and
this is correct.

The operator is at height 150; the restored witness remembers 100. A proof from
150 is a proof from a height this witness never saw, and accepting one would let
an operator choose their own starting point — which is the entirety of the
sequence guarantee. The witness refuses and reports the height it holds in the
`409` body.

**The operator resubmits from that height.** The gap between the two is the
recovery point, and the records inside it are unwitnessed from this witness's
perspective until they are resubmitted. A monitoring system that pages on `409`
will page here; it should be configured to distinguish this from a fork, which
carries the same status and a different meaning. That is a real ergonomic cost
of the design and it is better than the alternative, which is a witness that
accepts whatever height it is handed after a restore.

## What the drill does not establish

**That any particular deployment performs it.** A drill that meets an RPO on one
machine says the procedure works. Nothing in the software can check that an
operator takes backups, that the copy is off-host, or that anybody has run this
since the day it was written.

**That the backup is independent of the operator.** If the witness store is
backed up to infrastructure the operator controls, the backup is as
compromisable as the witness — and the whole point of the witness is that it is
a different party. Where the backup lives is a deployment decision this drill
cannot see.

**Replication.** OPS-06 asks for the store to be replicated. The drill
exercises restore-from-copy, which is the recovery half. Replication is a
deployment concern — a second witness host, or a filesystem that replicates —
and the honest position is that this project specifies the requirement and the
recovery procedure, and does not implement replication itself.
