# Security policy

## Reporting

Open a [GitHub security advisory](https://github.com/splitstick/splitstick/security/advisories/new)
on this repository. If that is not available to you, email **sriyapaka@gmail.com** with
`SPLITSTICK` in the subject.

Receipt is acknowledged within five working days, with the received-at timestamp that fixes
first-reporter order under the bounty terms.

## What happens next

The full intake, completeness, triage and disclosure process is in
[docs/bounty.md](docs/bounty.md) — SEC-19. In summary:

- **Disclosure within 90 days of receipt, or on fix, whichever is sooner** (SEC-20).
- **Findings are published either way, including when there is no mitigation** (SEC-21). A
  finding withheld because it is embarrassing is a finding the next operator meets alone.
- **Recognition, not cash, while the project is unfunded** (GOV-13, GOV-17). No figure is
  advertised as available, because none is held.

## Scope

[docs/threat-model.md](docs/threat-model.md) is the scope, and it binds **both** ways: the
published out-of-scope list is what it is, and exclusions are not added after a report
arrives. The attack must survive the shipped default, pinned by digest in the bounty terms.

## Supported versions

Pre-1.0. The `main` branch is what is supported; there are no maintained release branches
yet, and saying otherwise would be a support commitment this project cannot keep.
