import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tsaWitness, TsaError } from '../src/index.mjs';

const FIX = new URL('../../core/test/fixtures/rfc3161/', import.meta.url);
const fix = (/** @type {string} */ n) => readFileSync(new URL(n, FIX));
const note = fix('checkpoint.note').toString('utf8');
const token = Buffer.from(fix('checkpoint-token.b64').toString('utf8').trim(), 'base64');
const root = fix('root.pem').toString('utf8');

/** @param {(body: Buffer) => { status?: number, body: Buffer }} handler */
function tsa(handler) {
  /** @type {{ url: string, body: Buffer, headers: any, redirect?: string }[]} */
  const seen = [];
  /** @type {any} */
  const fetchImpl = async (/** @type {string} */ url, /** @type {any} */ init) => {
    seen.push({ url, body: Buffer.from(init.body), headers: init.headers, redirect: init.redirect });
    const r = handler(Buffer.from(init.body));
    return {
      ok: (r.status ?? 200) < 400,
      status: r.status ?? 200,
      async arrayBuffer() { return r.body; },
    };
  };
  return { seen, fetchImpl };
}

test('a bare TimeStampToken response is accepted and carried as an envelope entry', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(cs.type, 'rfc3161');
  assert.equal(cs.issuer, 'tsa.example');
  assert.equal(cs.covers, 'note_digest');
  assert.equal(Buffer.from(String(cs.token), 'base64').toString('hex'), token.toString('hex'));
  assert.deepEqual(w.establishes, ['time']);
});

test('PRIV-01: the request carries the digest and nothing else', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl });
  await w.submit(note, { old_size: 0, consistency_proof: [] });
  const body = t.seen[0].body;
  const digest = createHash('sha256').update(Buffer.from(note, 'utf8')).digest();
  assert.ok(body.includes(digest), 'the digest must be in the request');
  // Everything a note contains, and the fixture strings besides. The check is
  // on the bytes that left, not on a reading of the adapter.
  for (const secret of ['splitstick.example', 'SS1', 'transfer_funds', '2000000', 'TX-77814']) {
    assert.ok(!body.includes(Buffer.from(secret)), `${secret} must not leave the host`);
  }
  assert.ok(body.length < 128, `a timestamp request is small; this one is ${body.length} bytes`);
  assert.equal(t.seen[0].headers['content-type'], 'application/timestamp-query');
});

test('a TimeStampResp wrapper is unwrapped', async () => {
  // SEQUENCE { SEQUENCE { INTEGER 0 }, <token> } — the granted form.
  const statusInfo = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  const inner = Buffer.concat([statusInfo, token]);
  const len = Buffer.from([0x82, (inner.length >> 8) & 0xff, inner.length & 0xff]);
  const resp = Buffer.concat([Buffer.from([0x30]), len, inner]);
  const t = tsa(() => ({ body: resp }));
  const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(Buffer.from(String(cs.token), 'base64').toString('hex'), token.toString('hex'));
});

test('a declined request surfaces the PKIStatus rather than collapsing to "failed"', async () => {
  // PKIStatus 2 = rejection.
  const resp = Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);
  const t = tsa(() => ({ body: resp }));
  const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TsaError && /rejection/.test(e.message));
});

test('a token over a DIFFERENT digest is refused at submission, not stored', async () => {
  // The adapter holds the imprint it just sent, so it is the only place that
  // can catch this. Storing it would put a proof in the evidence that fails an
  // auditor's check months later, which is the worst place to find out.
  const t = tsa(() => ({ body: Buffer.from(fix('token.b64').toString('utf8').trim(), 'base64') }));
  const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TsaError && /does not verify|something else/.test(e.message));
});

test('an unreachable or erroring TSA is an error the collector can treat as fail-open', async () => {
  const dead = tsaWitness({
    id: 'tsa.example', url: 'https://tsa.example/t',
    fetchImpl: async () => { throw new Error('ECONNREFUSED'); },
  });
  await assert.rejects(() => dead.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TsaError && /unreachable/.test(e.message));

  const t = tsa(() => ({ status: 503, body: Buffer.alloc(0) }));
  const down = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl });
  await assert.rejects(() => down.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TsaError && /503/.test(e.message));
});

test('garbage in the response is an error, not a stored proof', async () => {
  for (const body of [Buffer.alloc(0), Buffer.from('nope'), Buffer.from([0x30, 0x00])]) {
    const t = tsa(() => ({ body }));
    const w = tsaWitness({ id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl });
    await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }), TsaError);
  }
});

test('a bad configuration is refused at construction', () => {
  assert.throws(() => tsaWitness({ id: '', url: 'https://x/' }), TsaError);
  assert.throws(() => tsaWitness({ id: 'x', url: 'ftp://x/' }), TsaError);
  assert.throws(() => tsaWitness({ id: 'x', url: /** @type {any} */ (undefined) }), TsaError);
});

test('no test here makes a network call: fetch is injected', () => {
  // The adapter is the one module in this package that may touch the network,
  // and its tests must not. If this file ever uses the global fetch, the
  // suite's behaviour starts depending on someone else's server.
  const text = readFileSync(new URL('./tsa.test.mjs', import.meta.url), 'utf8');
  assert.ok(!/[^.]\bfetch\s*\(/.test(text.replace(/fetchImpl/g, '')), 'tests must inject fetch');
});

// ── LEG-13: the integration surface for a qualified TSA ─────────────────────

/**
 * LEG-13's statement is that an operator CAN configure a qualified TSA. They
 * could not: the request's headers were hardcoded and the config builder passed
 * only id, url and qualified, so an operator with a commercial account had no
 * way to present a credential. Every qualified trust service is audited and
 * billable, so every provider meters it behind one.
 *
 * The configuration names WHERE the secret is. It never holds it.
 */
const withEnv = async (/** @type {Record<string,string|undefined>} */ vars, /** @type {() => any} */ fn) => {
  const saved = Object.keys(vars).map(k => /** @type {const} */ ([k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  try { return await fn(); } finally {
    for (const [k, v] of saved) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
};

test('LEG-13: a bearer credential is read from the environment and sent', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_TOKEN: 'super-secret-value' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
      fetchImpl: t.fetchImpl, auth: { scheme: 'bearer', env: 'SS_TSA_TOKEN' },
    });
    const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(t.seen[0].headers.authorization, 'Bearer super-secret-value');
    // And the content type is still right: auth must not displace it.
    assert.equal(t.seen[0].headers['content-type'], 'application/timestamp-query');
    // THE SECRET MUST NOT REACH THE PROOF. A countersignature is stored,
    // shipped in evidence packs and read by auditors.
    assert.ok(!JSON.stringify(cs).includes('super-secret-value'),
      'the credential appeared in the countersignature');
  });
});

test('LEG-13: basic auth encodes user:password, and refuses a value it cannot split', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_BASIC: 'alice:hunter2' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
      fetchImpl: t.fetchImpl, auth: { scheme: 'basic', env: 'SS_TSA_BASIC' },
    });
    await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(t.seen[0].headers.authorization,
      `Basic ${Buffer.from('alice:hunter2').toString('base64')}`);
  });
  await withEnv({ SS_TSA_BASIC: 'no-colon-here' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: tsa(() => ({ body: token })).fetchImpl,
      auth: { scheme: 'basic', env: 'SS_TSA_BASIC' },
    });
    await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
      /must hold "user:password"/);
  });
});

test('LEG-13: a custom header carries the key, and the header name is validated', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_KEY: 'k-123' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
      fetchImpl: t.fetchImpl, auth: { scheme: 'header', env: 'SS_TSA_KEY', header: 'X-Api-Key' },
    });
    await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(t.seen[0].headers['x-api-key'], 'k-123');

    // A header name is not a place to accept arbitrary bytes: a newline here
    // is request splitting.
    const bad = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl,
      auth: { scheme: 'header', env: 'SS_TSA_KEY', header: 'X-Bad\r\nInjected: 1' },
    });
    await assert.rejects(() => bad.submit(note, { old_size: 0, consistency_proof: [] }),
      /not a valid header token/);
  });
});

test('LEG-13: a missing credential fails by NAME, and never submits anonymously', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_ABSENT: undefined }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
      fetchImpl: t.fetchImpl, auth: { scheme: 'bearer', env: 'SS_TSA_ABSENT' },
    });
    await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
      (/** @type {any} */ e) => e instanceof TsaError
        && /SS_TSA_ABSENT, and it is\s+not set/.test(e.message)
        && !/was unreachable/.test(e.message));
    assert.equal(t.seen.length, 0,
      'a request was made without the credential it was configured to present');
  });
});

test('LEG-13: an unknown auth scheme is refused, not dropped', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({
    id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl,
    auth: /** @type {any} */ ({ scheme: 'magic', env: 'SS_TSA_KEY' }),
  });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TsaError
      && /does not know/.test(e.message)
      // NOT reported as unreachable: the credential is resolved before the
      // fetch, so a configuration error keeps its own diagnosis.
      && !/was unreachable/.test(e.message));
  assert.equal(t.seen.length, 0, 'silently dropping a credential looks like a bad credential');
});

/**
 * The footgun this is for. Of nine free public RFC 3161 endpoints surveyed,
 * none was qualified while five belonged to companies that ARE qualified trust
 * service providers — Certum runs a free basic endpoint next to its commercial
 * qualified service. So `qualified: true` pointed at a free endpoint is the
 * expected mistake, and the verifier reports the Art. 41 presumption on the
 * strength of that flag.
 */
test('LEG-13: declaring qualified records what the certificate actually carries', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({
    id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
    fetchImpl: t.fetchImpl, qualified: true,
  });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  const q = /** @type {any} */ (cs).qualified_statements;
  assert.ok(q, 'a qualified declaration must be accompanied by what was seen');
  assert.equal(typeof q.qc_qtst, 'boolean');
  // The fixture is an ordinary test TSA, so it carries no qualified statements.
  assert.equal(q.qc_qtst, false);
  assert.equal(q.qc_compliance, false);
});

test('LEG-13: an ordinary TSA is not annotated, because the absence is unremarkable', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({
    id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl,
  });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(/** @type {any} */ (cs).qualified_statements, undefined);
});

// ── PR #20 review: structural QCStatements, not a byte search ───────────────

import { qcStatements } from '../src/index.mjs';
import { encodeTlv, encodeOidValue, TAG } from '@splitstick/core/der';

const oid = (/** @type {string} */ d) => encodeTlv(TAG.OID, encodeOidValue(d));
const seq = (/** @type {Buffer[]} */ parts) => encodeTlv(TAG.SEQUENCE, Buffer.concat(parts));

/**
 * A certificate carrying the extensions given. Only the shape the parser walks
 * is real — TBSCertificate with an [3] EXPLICIT Extensions — which is the
 * point: the parser must find the statements STRUCTURALLY and not by stumbling
 * over bytes.
 * @param {Buffer[]} extensions
 * @param {Buffer} [serial] bytes placed in the serial number
 */
function certWith(extensions, serial = Buffer.from([0x01])) {
  const tbs = seq([
    encodeTlv(TAG.INTEGER, serial),
    seq([oid('1.2.840.113549.1.1.11')]),
    ...(extensions.length ? [encodeTlv(0xa3, seq(extensions))] : []),
  ]);
  return seq([tbs, seq([oid('1.2.840.113549.1.1.11')]), encodeTlv(TAG.BIT_STRING, Buffer.from([0]))]);
}

/** @param {Buffer[]} statements */
const qcExt = (statements) => seq([
  oid('1.3.6.1.5.5.7.1.3'),
  encodeTlv(TAG.OCTET_STRING, seq(statements)),
]);

const QC_COMPLIANCE = seq([oid('0.4.0.1862.1.1')]);
const QC_TYPE_QTST = seq([oid('0.4.0.1862.1.6'), seq([oid('0.4.0.1862.1.6.3')])]);
const QC_TYPE_ESEAL = seq([oid('0.4.0.1862.1.6'), seq([oid('0.4.0.1862.1.6.2')])]);

test('QCStatements: a qualified timestamp certificate is read as one', () => {
  const r = qcStatements(certWith([qcExt([QC_COMPLIANCE, QC_TYPE_QTST])]));
  assert.deepEqual(r, { compliance: true, qtst: true });
});

test('QCStatements: QcCompliance without the qtst TYPE is not a qualified timestamp', () => {
  // A qualified certificate for e-seals is QcCompliance too. Treating that as
  // a qualified TIMESTAMP service would be the mistake this check exists for.
  assert.deepEqual(qcStatements(certWith([qcExt([QC_COMPLIANCE, QC_TYPE_ESEAL])])),
    { compliance: true, qtst: false });
  assert.deepEqual(qcStatements(certWith([qcExt([QC_COMPLIANCE])])),
    { compliance: true, qtst: false });
});

test('QCStatements: no extension at all is a definite absence', () => {
  assert.deepEqual(qcStatements(certWith([])), { compliance: false, qtst: false });
  assert.deepEqual(qcStatements(certWith([seq([oid('2.5.29.19'), encodeTlv(TAG.OCTET_STRING, seq([]))])])),
    { compliance: false, qtst: false });
});

/**
 * THE DEFECT THE REVIEW FOUND. The first version searched the certificate's raw
 * DER for the OID byte sequences, which establishes only that the bytes occur
 * SOMEWHERE in the encoding. Here they occur in the serial number and in an
 * unrelated extension, and the certificate makes no qualified statement at all.
 */
test('QCStatements: the OID bytes elsewhere in the certificate prove nothing', () => {
  const qtstBytes = encodeOidValue('0.4.0.1862.1.6.3');
  const complianceBytes = encodeOidValue('0.4.0.1862.1.1');

  // In the serial number, and inside a different extension's value.
  const cert = certWith(
    [seq([oid('2.5.29.17'), encodeTlv(TAG.OCTET_STRING, Buffer.concat([qtstBytes, complianceBytes]))])],
    Buffer.concat([Buffer.from([0x7f]), qtstBytes]),
  );

  // A raw search finds them...
  assert.ok(cert.includes(qtstBytes), 'the fixture must actually contain the bytes');
  // ...and the structural parse correctly reports no qualified statement.
  assert.deepEqual(qcStatements(cert), { compliance: false, qtst: false });
});

test('QCStatements: an unparseable certificate is UNKNOWN, not absent', () => {
  assert.equal(qcStatements(Buffer.from('not a certificate')), null);
  assert.equal(qcStatements(Buffer.alloc(0)), null);
});

test('QCStatements: the adapter reports the basis, so the field cannot be over-read', async () => {
  const t = tsa(() => ({ body: token }));
  const w = tsaWitness({
    id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root],
    fetchImpl: t.fetchImpl, qualified: true,
  });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  const q = /** @type {any} */ (cs).qualified_statements;
  assert.match(q.basis, /self-asserted, NOT checked against an EU Trusted List/);
  assert.match(q.basis, /RFC 3739/);
});

// ── PR #20 review, P1 and P2 ────────────────────────────────────────────────

test('P1: a credential is REFUSED against a plain-HTTP endpoint, before any request', () => {
  // Basic auth is base64, which is an encoding and not encryption, and a
  // bearer token in the clear is readable by anything on the path.
  for (const scheme of /** @type {const} */ (['bearer', 'basic', 'header'])) {
    assert.throws(() => tsaWitness({
      id: 'tsa.example', url: 'http://tsa.example/t',
      auth: { scheme, env: 'SS_TSA_KEY', ...(scheme === 'header' ? { header: 'X-Api-Key' } : {}) },
    }), (/** @type {any} */ e) => e instanceof TsaError && /plain-HTTP endpoint/.test(e.message), scheme);
  }
  // Anonymous submission over HTTP is unchanged: the request carries a version,
  // an algorithm identifier and 32 bytes of hash, and nothing worth protecting.
  assert.doesNotThrow(() => tsaWitness({ id: 'tsa.example', url: 'http://tsa.example/t' }));
});

test('P1: loopback is the exception, and it is matched by HOST not by prefix', () => {
  for (const url of ['http://127.0.0.1:8080/t', 'http://localhost:8080/t', 'http://[::1]:8080/t']) {
    assert.doesNotThrow(() => tsaWitness({
      id: 'tsa.example', url, auth: { scheme: 'bearer', env: 'SS_TSA_KEY' },
    }), url);
  }
  // A hostname that merely STARTS with a loopback address is not loopback.
  for (const url of ['http://127.0.0.1.evil.example/t', 'http://localhost.evil.example/t']) {
    assert.throws(() => tsaWitness({
      id: 'tsa.example', url, auth: { scheme: 'bearer', env: 'SS_TSA_KEY' },
    }), /plain-HTTP endpoint/, url);
  }
});

test('P2: a custom auth header may not displace the RFC 3161 request headers', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_KEY: 'k-123' }, async () => {
    for (const header of ['Content-Type', 'content-type', 'Accept', 'Authorization', 'Host']) {
      const w = tsaWitness({
        id: 'tsa.example', url: 'https://tsa.example/t', fetchImpl: t.fetchImpl,
        auth: { scheme: 'header', env: 'SS_TSA_KEY', header },
      });
      await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
        (/** @type {any} */ e) => e instanceof TsaError
          && /may not be/.test(e.message) && !/was unreachable/.test(e.message), header);
    }
    assert.equal(t.seen.length, 0, 'no request may be made with a displaced protocol header');
  });
});

test('P2: the protocol headers survive a legitimate custom auth header', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_KEY: 'k-123' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl,
      auth: { scheme: 'header', env: 'SS_TSA_KEY', header: 'X-Api-Key' },
    });
    await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(t.seen[0].headers['content-type'], 'application/timestamp-query');
    assert.equal(t.seen[0].headers.accept, 'application/timestamp-reply');
    assert.equal(t.seen[0].headers['x-api-key'], 'k-123');
  });
});

test('P2: a credentialled request refuses to follow a redirect', async () => {
  const t = tsa(() => ({ body: token }));
  await withEnv({ SS_TSA_KEY: 'k-123' }, async () => {
    const w = tsaWitness({
      id: 'tsa.example', url: 'https://tsa.example/t', anchors: [root], fetchImpl: t.fetchImpl,
      auth: { scheme: 'header', env: 'SS_TSA_KEY', header: 'X-Api-Key' },
    });
    await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(t.seen[0].redirect, 'error',
      'fetch strips authorization across origins but not a custom header, so a redirect could collect the key');
  });
});

/**
 * The qcStatements tests above exercise the PARSER. Nothing asserted that the
 * adapter calls it — reverting the adapter to a raw byte search over the
 * certificate failed none of them, so the structural parse could have been
 * undone without a single test noticing. A guard whose subject can be swapped
 * out from under it is not guarding.
 *
 * Checked at the source, and the check fails loudly naming what it could not
 * find rather than passing over nothing.
 */
test('the adapter resolves qualified statements through the structural parser', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/index.mjs', import.meta.url), 'utf8');

  const call = src.indexOf('qcStatements(');
  assert.ok(call !== -1,
    'the adapter no longer calls qcStatements — this check cannot locate its subject and must be '
    + 'repaired, not skipped');

  // And it must not reach for a byte search over the certificate again. The
  // OID content bytes, in any of the forms the first version used.
  for (const shape of [/\.includes\(\s*QC_/, /includes\(Buffer\.from\(\[\s*0x04,\s*0x00,\s*0x8e/i,
    /includes\(Buffer\.from\(\[\s*4\s*,\s*0\s*,\s*142/]) {
    assert.doesNotMatch(src, shape,
      'the adapter searches raw certificate bytes for an OID again: finding a needle somewhere in '
      + 'a certificate is not the certificate making a statement');
  }
});
