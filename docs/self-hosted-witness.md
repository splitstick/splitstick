# Running the witness yourself

OPS-03. You run the witness inside your own perimeter, internal audit holds its key, and
nothing leaves. This is the deployment the release notes call *two parties, one company*.

Read [the practice statement](witness-practice-statement.md) for what a witness undertakes,
[witness outages](witness-outages.md) for what recovers on its own, and
[the restore drill](witness-restore-drill.md) for the rehearsal you should have done before
you need it.

## What the separation is actually for

A countersignature is worth exactly the independence of whoever made it. The operator signs
a checkpoint; the witness signs that it saw that checkpoint at that height and never a
conflicting one. If the same team holds both keys, the second signature establishes nothing
the first did not — it is the same party agreeing with itself, and no amount of process
documentation changes the arithmetic.

So the only load-bearing requirement in this guide is this one:

> **The witness key is held by a party who does not operate the collector, and who cannot be
> directed by the team that does.** Internal audit, risk, or a compliance function with its
> own reporting line. Not a service account engineering can assume. Not a key in the same
> vault, under the same policy, with the same administrators.

Everything below is mechanics. This is the part that decides whether the mechanics mean
anything.

## What it establishes, and what it does not

A self-hosted witness establishes **sequence**: that your log has one history, that it did
not fork, and that it did not retract a height it had already attested. That is what detects
the operator rewriting their own past, which is the attack the whole system exists for.

It does **not** establish **time**. A witness inside your perimeter attests when *it* saw a
checkpoint, by a clock your organisation controls, so an auditor who distrusts your
organisation has no reason to accept the timestamp. `verify` says so: a deployment with one
sequence-only witness reports `inconclusive`, not `ok`, with the time checks unanswered.
That is the honest verdict and not a shortfall to be configured away.

If you need time that survives distrusting you, anchor to a witness outside your perimeter
as well — see [the witness list](../spec/witnesses.json) — and for the eIDAS Art. 41
presumption specifically, a **qualified** TSA, which no self-hosted witness and no witness
this project operates can provide.

A qualified TSA goes in the witness set beside your own (LEG-13):

```yaml
witnesses:
  - id: audit.internal
    type: splitstick
  - id: qtsa.example
    type: rfc3161
    url: https://tsa.example/tsr
    qualified: true
```

`qualified: true` is **your declaration**, recorded so the deployment can be described and
audited. It is not a verification and cannot be: qualified status lives in the EU trusted
list, which verification does not consult and by NFR-05 never will. What the verifier
reports rests on the *reader's* acceptance policy, where the same flag appears — because
the presumption is a conclusion the reader draws, and a reader who has not checked the
trusted list themselves has no business drawing it. A policy that labels a C2SP note
witness `qualified` still gets nothing: the report computes this from the proof type, so
mislabelling our own witness cannot produce the claim.

## Standing it up

The witness is a library plus a directory. It holds its state on disk and signs with a key
you give it; it has no listener of its own, so audit chooses the transport — in-process in a
single-host deployment, or an HTTP service they run and engineering cannot deploy to.

```js
import { mkdirSync } from 'node:fs';
import { StatefulWitness } from '@splitstick/witness-self';
import { generateDevSigner } from '@splitstick/core/signer-file';

// Audit's directory, audit's key. `generateDevSigner` is for a drill; in
// production this is a KMS or HSM handle audit holds — see docs/key-custody.md.
mkdirSync('./witness-state', { recursive: true });
const witnessKey = await generateDevSigner('audit.internal');
const witness = new StatefulWitness({ dir: './witness-state', signer: witnessKey });

// Enrolment is audit admitting one operator identity and pinning its public
// key. A witness that accepted any key would countersign anybody's history.
witness.enrol('splitstick.dev/host-1', operatorPublicKey);
```

Engineering wires the collector to it through an adapter and an `Anchorer`. The `acceptance`
map is the reader's side of the same pin: a countersignature from a key you did not expect
is not a countersignature.

```js
import { Anchorer } from '@splitstick/core/anchor';
import { parseNote } from '@splitstick/core/note';

const adapter = {
  id: 'audit.internal',
  proof_type: 'c2sp-note',
  establishes: ['sequence'],
  tier: 'anchor',
  async submit(note, ctx) {
    const res = await witness.addCheckpoint({
      note, old_size: ctx.old_size, consistency_proof: ctx.consistency_proof,
    });
    return {
      type: 'c2sp-note', issuer: 'audit.internal', covers: 'note',
      line: res.note.trimEnd().split('\n').at(-1),
    };
  },
};

const anchorer = new Anchorer({
  store, witnesses: [adapter], quorum: 1,
  acceptance: { 'audit.internal': witnessKey.publicKey },
});
```

Then every checkpoint goes to it:

```js
const cp = await collector.checkpoint();
const result = await anchorer.anchor(cp.checkpoint_seq);
```

`result.attached` carries the countersignatures that verified. `result.failed` carries the
ones that did not, and an empty `attached` is not an error the collector raises — NFR-12 is
absolute, so losing the witness never stops the agent. It shows up where it belongs: in the
coverage report, as records that fall under no verified checkpoint.

## Keys, and what audit has to hold

See [key custody](key-custody.md) for the full treatment. The deployment-specific points:

- **The witness key never goes near the collector host.** If it is reachable from the machine
  that writes the log, the separation is notional.
- **Back up `./witness-state`, not just the key.** The key alone cannot reconstruct what
  heights the witness has already attested, and a witness that forgets will countersign a
  height it previously refused — which is indistinguishable, to a reader, from the witness
  having been complicit. [The restore drill](witness-restore-drill.md) rehearses exactly this.
- **Rotation is succession, not replacement.** A new witness key signed over by the old one
  keeps the chain of acceptance intact; a key swapped in silently makes every prior
  countersignature unverifiable against the key you now publish.

## Checking that it is real

Two things to run, neither of which needs us:

```bash
npm run conformance     # the witness behaves like a witness: C1–C7, offline
npm run drill:restore   # it survives losing its state, and says so when it has
```

And the reader's side, which is the only check that matters to somebody who does not trust
you: give them the store and your acceptance policy, and let them run
`splitstick-verify` themselves. If audit's countersignature does not verify against the
public key audit publishes, nothing in this guide was true.
