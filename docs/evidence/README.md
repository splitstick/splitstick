# Evidence

Committed results from runs that close a requirement, so a reader can check the
claim against the measurement rather than against prose about it.

| file | requirement | what it is |
|---|---|---|
| `leg-09-wps-anchor.json` | LEG-09 | the Witness Practice Statement's checkpoint, anchored and verified |

Benchmark evidence lives in `bench/results/`, and the FR-15 interoperability
probe's output in `packages/witness-tlog/interop/results/`.

## Reproducing LEG-09

The statement is recorded by this repository and anchored by witnesses an
operator supplies. Recording and anchoring are separate runs on purpose: a
statement recorded before any witness existed is anchored later against the
checkpoint it already falls under.

Build the Go witness (see `packages/witness-tlog/interop/README.md` — no Xcode
needed, `transparency-dev/witness` uses pure-Go sqlite):

```bash
/tmp/fr15-genkeys --origin wps-witness.local --print > /tmp/leg09/witness-keys.txt
sed -n 1p /tmp/leg09/witness-keys.txt > /tmp/leg09/witness.key
```

Enrol this log with it. The origin and public key come from
`npm run anchor-wps` with no arguments, which prints the identity:

```yaml
# /tmp/leg09/additional-logs.yaml
Logs:
  - Origin: splitstick.dev/wps
    PublicKey: splitstick.dev/wps+4340035c+AXpFr51FJ7QrrzjajffNU2GZy6O2dzwz9PnhVeqV6se+
```

```bash
/tmp/fr15-omniwitness --listen 127.0.0.1:8099 --metrics_listen 127.0.0.1:8100 \
  --private_key_path /tmp/leg09/witness.key \
  --additional_logs /tmp/leg09/additional-logs.yaml --db_file "$(mktemp -d)/c.db"
```

Then the witness set and the acceptance policy. The witness's key is given as a
**vkey**, which carries its algorithm byte — a cosignature/v1 witness signs with
algorithm `0x04` and a bare base64 key would be read as algorithm `0x01`:

```yaml
# witnesses.yaml
version: 1
store: ./s
witnesses:
  - { id: wps-witness.local, type: tlog-witness, url: "http://127.0.0.1:8099" }
  - { id: freetsa.org,       type: rfc3161,      url: "https://freetsa.org/tsr" }
quorum: 1
```

```json
{ "quorum": 1, "witnesses": [
  { "id": "wps-witness.local", "public_key": "wps-witness.local+…", "establishes": ["sequence", "time"] },
  { "id": "freetsa.org", "establishes": ["time"], "qualified": false } ] }
```

```bash
npm run anchor-wps -- --config witnesses.yaml --policy acceptance.json
node packages/verify/src/cli.mjs out/wps-anchor --collector wps \
  --key "splitstick.dev/wps+4340035c+…" --policy acceptance.json
```

## What the LEG-09 anchor establishes, and what it does not

- **Mechanism parity.** The statement is chained, checkpointed and anchored by
  the same path as any action record, and verified by the ordinary CLI. There
  is no special case for it, which is the requirement.
- **An independent implementation.** The cosignature comes from
  transparency-dev's Go witness, not from `@splitstick/witness-self`, so it is
  not this project agreeing with itself.
- **NOT independent custody**, for that witness. We run it. A reader who wants
  custody independence names a witness they trust in their own acceptance
  policy — the policy is an input precisely so that two readers can reach
  different conclusions from the same bytes.
- **Independent custody, unconfirmable offline**, for the TSA. `freetsa.org` is
  a third party and its token is real; NFR-05 forbids this verifier from
  fetching a certificate chain, so it is reported `inconclusive` — recorded as
  claimed, not confirmed.
- **No eIDAS presumption.** Neither witness is a qualified trust service, and
  the report says so. That is LEG-13, and it is procurement rather than code.

Rekor was deliberately not used. FR-48 keeps a public transparency log opt-in
rather than the shipped default; a one-off statement anchor would not breach
its acceptable use, but a local witness plus a TSA already gives both
capability classes without spending a public good's capacity or publishing
permanently.

## Not legal advice

**Not legal advice.** eIDAS is named above only to say which engineering
property is relevant to it and where that stops — specifically, that nothing in
this evidence establishes the Article 41 presumption. Nothing here is legal
advice, no conclusion about your obligations is offered, and nothing here
certifies anything about your deployment. Consult your counsel.
