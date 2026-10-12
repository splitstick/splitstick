# RFC 3161 fixtures

A **genuine** TimeStampToken, produced by LibreSSL 2.8.3's `openssl ts` against
a throwaway two-certificate chain generated for this purpose. It is committed
rather than generated at test time for two reasons: a test that builds its own
token with the code under test proves only self-consistency, and `openssl ts` is
not present on every machine that runs these tests.

| File | What it is |
|---|---|
| `token.b64` | base64 of the DER `TimeStampToken` (a CMS `SignedData` over `TSTInfo`) |
| `root.pem` | the throwaway root CA, which is the trust anchor a test supplies |
| `tsa.pem` | the TSA signing certificate, `extendedKeyUsage = timeStamping` |
| `imprint.hex` | SHA-256 of `note.txt`, which is what the `MessageImprint` covers |
| `note.txt` | the bytes that were timestamped |

`openssl ts -verify -digest <imprint> -in resp.tsr -CAfile root.pem -untrusted
tsa.pem` reports `Verification: OK` on the response this token came from, so
"our parser agrees with OpenSSL" is a claim about an independent
implementation's output rather than about our own.

**The keys are throwaway and the chain is worthless.** It exists to be parsed.
Nothing in it is trusted by any default, and the trust anchor has to be passed
in explicitly by whoever is verifying — which is FR-30's point.
