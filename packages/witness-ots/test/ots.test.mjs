import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { otsWitness, OtsWitnessError } from '../src/index.mjs';
import { parseOtsProof } from '@splitstick/core/opentimestamps';

const note = 'splitstick.dev/host-1\n7\nAAAA\nsuite SS1\n\n— splitstick.dev/host-1 AAAAAAAA AA==\n';
const digest = createHash('sha256').update(Buffer.from(note, 'utf8')).digest();

const varuint = (/** @type {number} */ n) => {
  const out = [];
  for (;;) { if (n < 0x80) { out.push(n); break; } out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  return Buffer.from(out);
};
const varbytes = (/** @type {Buffer} */ b) => Buffer.concat([varuint(b.length), b]);
const PENDING = Buffer.from('83dfe30d2e906c6e', 'hex');
/** A bare timestamp, as a calendar returns: one pending attestation. */
const calendarReply = (uri = 'https://a.calendar.example') => Buffer.concat([
  Buffer.from([0x00]), PENDING, varbytes(varbytes(Buffer.from(uri, 'utf8'))),
]);

/** @param {(url: string, body: Buffer) => { status?: number, body: Buffer }} handler */
function calendar(handler) {
  /** @type {{ url: string, body: Buffer }[]} */
  const seen = [];
  /** @type {any} */
  const fetchImpl = async (/** @type {string} */ url, /** @type {any} */ init) => {
    seen.push({ url, body: Buffer.from(init.body) });
    const r = handler(url, Buffer.from(init.body));
    return { ok: (r.status ?? 200) < 400, status: r.status ?? 200, async arrayBuffer() { return r.body; } };
  };
  return { seen, fetchImpl };
}

test('a pending proof is stored: it is the receipt that the submission happened', async () => {
  const c = calendar(() => ({ body: calendarReply() }));
  const w = otsWitness({ calendars: ['https://a.calendar.example'], fetchImpl: c.fetchImpl });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(cs.type, 'opentimestamps');
  assert.equal(cs.issuer, 'bitcoin');
  assert.equal(cs.covers, 'note_digest');
  const p = parseOtsProof(Buffer.from(String(cs.proof), 'base64'), { expectDigest: digest });
  assert.equal(p.attestations[0].chain, 'pending');
  // The hard tier is the slow tier, by design: a calendar submission every ten
  // seconds is not acceptable use of a public good.
  assert.equal(w.tier, 'rollup');
  assert.deepEqual(w.establishes, ['existence']);
});

test('PRIV-01: 32 bytes leave the host, and nothing else', async () => {
  const c = calendar(() => ({ body: calendarReply() }));
  const w = otsWitness({ calendars: ['https://a.calendar.example'], fetchImpl: c.fetchImpl });
  await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(c.seen[0].body.length, 32);
  assert.equal(c.seen[0].body.toString('hex'), digest.toString('hex'));
  // A calendar never learns the note, the origin, or that Splitstick exists.
  for (const s of ['splitstick', 'host-1', 'SS1']) {
    assert.ok(!c.seen[0].body.includes(Buffer.from(s)), s);
  }
  assert.match(c.seen[0].url, /\/digest$/);
});

test('calendars are tried in order and the first usable reply wins', async () => {
  const c = calendar((url) => (url.includes('down')
    ? { status: 502, body: Buffer.alloc(0) }
    : { body: calendarReply('https://b.calendar.example') }));
  const w = otsWitness({
    calendars: ['https://down.calendar.example', 'https://b.calendar.example'],
    fetchImpl: c.fetchImpl,
  });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(c.seen.length, 2);
  const p = parseOtsProof(Buffer.from(String(cs.proof), 'base64'), { expectDigest: digest });
  assert.equal(p.attestations[0].uri, 'https://b.calendar.example');
});

test('every calendar failing is an error the collector treats as fail-open', async () => {
  const c = calendar(() => ({ status: 503, body: Buffer.alloc(0) }));
  const w = otsWitness({
    calendars: ['https://a.example', 'https://b.example'], fetchImpl: c.fetchImpl,
  });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof OtsWitnessError && /503/.test(e.message));
  // Both named, so an operator reading the log knows it was not one calendar.
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => /a\.example.*b\.example/s.test(e.message));
});

test('a reply that does not parse is never stored as though it were evidence', async () => {
  const c = calendar(() => ({ body: Buffer.from('not a timestamp') }));
  const w = otsWitness({ calendars: ['https://a.example'], fetchImpl: c.fetchImpl });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    OtsWitnessError);
});

test('a bad configuration is refused at construction', () => {
  assert.throws(() => otsWitness({ calendars: [] }), OtsWitnessError);
  assert.throws(() => otsWitness({ calendars: ['ftp://x/'] }), OtsWitnessError);
  assert.throws(() => otsWitness({ calendars: /** @type {any} */ (undefined) }), OtsWitnessError);
});
