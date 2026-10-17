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
  /** @type {{ url: string, body: Buffer, headers: any }[]} */
  const seen = [];
  /** @type {any} */
  const fetchImpl = async (/** @type {string} */ url, /** @type {any} */ init) => {
    seen.push({ url, body: Buffer.from(init.body), headers: init.headers });
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
