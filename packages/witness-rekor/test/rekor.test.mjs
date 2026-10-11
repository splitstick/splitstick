import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rekorWitness, RekorError } from '../src/index.mjs';

const note = 'splitstick.dev/host-1\n7\nAAAA\nsuite SS1\n\n— splitstick.dev/host-1 AAAAAAAA AA==\n';
// A C2SP signature line is '— <name> <base64(keyId‖signature)>' — two fields,
// not three. My first fixture had three and the search correctly rejected it.
const LINE = `— rekor ${Buffer.concat([Buffer.alloc(4, 7), Buffer.alloc(64, 9)]).toString('base64')}`;

/** @param {(url: string, body: any) => { status?: number, json?: any }} handler */
function rekor(handler) {
  /** @type {{ url: string, body: any }[]} */
  const seen = [];
  /** @type {any} */
  const fetchImpl = async (/** @type {string} */ url, /** @type {any} */ init) => {
    const body = JSON.parse(String(init.body));
    seen.push({ url, body });
    const r = handler(url, body);
    return {
      ok: (r.status ?? 200) < 400, status: r.status ?? 200,
      async json() { return r.json ?? {}; },
    };
  };
  return { seen, fetchImpl };
}

test('an entry returning a signed note line becomes a countersignature', async () => {
  const r = rekor(() => ({ json: { uuid: 'abc', verification: { signedEntryTimestamp: LINE } } }));
  const w = rekorWitness({ url: 'https://rekor.internal.example', fetchImpl: r.fetchImpl });
  const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(cs.type, 'c2sp-note');
  assert.equal(cs.issuer, 'rekor');
  assert.equal(cs.covers, 'note');
  assert.equal(cs.line, LINE);
});

test('the signed line is found wherever in the response it arrives', async () => {
  // Rekor's shape varies by version and entry type. Guessing one and failing on
  // the others would look like an unreachable log.
  for (const json of [
    { verification: { signedEntryTimestamp: LINE } },
    { entries: [{ nested: { deep: { line: LINE } } }] },
    { a: { b: { c: [[{ d: LINE }]] } } },
  ]) {
    const r = rekor(() => ({ json }));
    const w = rekorWitness({ url: 'https://rekor.internal.example', fetchImpl: r.fetchImpl });
    const cs = await w.submit(note, { old_size: 0, consistency_proof: [] });
    assert.equal(cs.line, LINE);
  }
});

test('a response with no checkable line is an error, not a stored entry', async () => {
  const r = rekor(() => ({ json: { uuid: 'abc', logIndex: 42 } }));
  const w = rekorWitness({ url: 'https://rekor.internal.example', fetchImpl: r.fetchImpl });
  await assert.rejects(() => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof RekorError && /nobody can check/.test(e.message));
});

test('FR-47: a public instance is refused on the per-batch tier', () => {
  // 8,640 entries a day per collector at the default cadence. "The operator can
  // configure it badly" is not an answer when the cost lands on someone else's
  // infrastructure.
  assert.throws(() => rekorWitness({ url: 'https://rekor.sigstore.dev', tier: 'anchor' }),
    (/** @type {any} */ e) => e instanceof RekorError && /8,640/.test(e.message));
  // The roll-up tier is fine, and so is a self-hosted instance.
  assert.doesNotThrow(() => rekorWitness({ url: 'https://rekor.sigstore.dev' }));
  assert.doesNotThrow(() => rekorWitness({
    url: 'https://rekor.sigstore.dev', tier: 'anchor', selfHosted: true,
  }));
});

test('FR-48: the default tier is roll-up, so an operator has to opt INTO per-batch', () => {
  const w = rekorWitness({ url: 'https://rekor.internal.example' });
  assert.equal(w.tier, 'rollup');
});

test('it establishes existence, never sequence', () => {
  const w = rekorWitness({ url: 'https://rekor.internal.example' });
  // Rekor accepts any entry offered and does not know what these heights ought
  // to be, so it cannot refuse a rewritten history at submission time the way a
  // stateful witness can. Declaring `sequence` here would make the verifier's
  // capability statement a lie by configuration.
  assert.deepEqual(w.establishes, ['existence']);
});

test('PRIV-01: the request carries the note and its digest, and no payload', async () => {
  const r = rekor(() => ({ json: { verification: { signedEntryTimestamp: LINE } } }));
  const w = rekorWitness({ url: 'https://rekor.internal.example', fetchImpl: r.fetchImpl });
  await w.submit(note, { old_size: 0, consistency_proof: [] });
  const sent = JSON.stringify(r.seen[0].body);
  assert.ok(sent.includes('suite SS1'), 'the note itself is the entry');
  for (const secret of ['transfer_funds', '2000000', 'TX-77814']) {
    assert.ok(!sent.includes(secret), secret);
  }
});

test('an unreachable log or an error response is an error the collector can fail open on', async () => {
  const dead = rekorWitness({
    url: 'https://rekor.internal.example',
    fetchImpl: async () => { throw new Error('ENOTFOUND'); },
  });
  await assert.rejects(() => dead.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof RekorError && /unreachable/.test(e.message));

  const r = rekor(() => ({ status: 429 }));
  const limited = rekorWitness({ url: 'https://rekor.internal.example', fetchImpl: r.fetchImpl });
  await assert.rejects(() => limited.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => /429/.test(e.message));
});

test('a bad URL is refused at construction', () => {
  assert.throws(() => rekorWitness({ url: 'not a url' }), RekorError);
  assert.throws(() => rekorWitness({ url: /** @type {any} */ (undefined) }), RekorError);
});
