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
