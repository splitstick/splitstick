# Splitstick 0.9.0

**A pre-1.0 release. It claims no requirement release, and that is deliberate.**

The requirement backlog for 1.0 is complete — 193 of 193 — and the release gate
would let a `v1.0.0` tag through. This is 0.9.0 anyway, because two things are
true at once: every requirement has evidence behind it, and none of that
evidence has yet met an operator who did not write it.

A `1.0.0` on a registry says "this is finished" more loudly than any README can
qualify. 0.9.0 says what is actually true: the mechanisms are built, measured
and guarded, and the first people to run them in anger will find things.

## What is in it

The whole of the 1.0 backlog. [The 1.0 release notes](splitstick-1.0-release-notes.md)
describe the claim set in full, including the figures table and what each figure
rests on. Nothing in this release is weaker than that document says; the
difference is the version number, not the contents.

## What has NOT been established

Read this part first if you are evaluating Splitstick.

- **No live qualified timestamp.** LEG-13 closed on the integration *surface*:
  an operator can configure a qualified TSA, credential included, and the
  verifier reports the eIDAS presumption from the operator's declaration about
  it. Nobody here has bought an account and anchored against one. **A complete
  requirement count is not evidence that qualified timestamping has been
  demonstrated in a live deployment.**
- **No independent custody of a witness.** The practice statement is anchored
  against a real transparency-dev/witness instance, which is an independent
  *implementation* — and this project operates it. A third party's RFC 3161
  token is in the same anchor and cannot be confirmed offline by design.
- **Performance figures come from one laptop.** The append and verification
  numbers are measured, attributed and carry the conditions they were taken
  under. They are not from a dedicated reference host, and they say so.
- **Interoperability is proven against one other implementation.** The tlog
  adapter talks to transparency-dev's Go witness. That is one external reading
  of one document, not a conformance programme.
- **No accreditation, no hosted witness, no certification mark.** Unchanged
  from the 1.0 notes, and structural rather than temporary.

## What would move this to 1.0

Operators finding the things an author cannot. Specifically: somebody anchoring
against a qualified TSA they pay for (LEG-20), somebody running a witness this
project does not operate, and performance figures from a host chosen by
somebody with no stake in the result.

## Installing

```
npm install @splitstick/core @splitstick/verify
```

The verifier is the piece to start with: it reads a store and tells you what
the evidence does and does not establish, including a `trusting` list naming
every assumption it could not discharge.

## Reporting

Security issues: see [SECURITY.md](../SECURITY.md). Novel tamper classes found
against the mechanisms are recognised under [the bounty terms](bounty.md); there
is no money in it and the terms say so plainly.

## Not legal advice

**Not legal advice.** eIDAS is named above only to say where an engineering
property stops: specifically, that the Article 41 presumption attaches through a
**qualified** trust service and never through a witness this project operates,
and that nothing in this release establishes it. Nothing here is legal advice,
no conclusion about your obligations is offered, and nothing here certifies
anything about your deployment. Consult your counsel.
