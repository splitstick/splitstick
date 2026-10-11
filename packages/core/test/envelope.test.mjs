import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateDevSigner } from '../src/signer-file.mjs';
import { checkpointText, encodeNote, formatVkey } from '../src/note.mjs';
import { signNote } from '../src/signer.mjs';
import {
  buildEnvelope, parseEnvelope, noteDigest, addCountersignature,
  EnvelopeError, COUNTERSIGNATURE_TYPES,
} from '../src/envelope.mjs';

const ORIGIN = 'splitstick.example/treasury-host-1';

async function note(tree_size = 4812) {
  const signer = await generateDevSigner(ORIGIN);
  const text = checkpointText({
    origin: ORIGIN, tree_size, root: Buffer.alloc(32, 0x3b), suite: 'SS1',
  });
  return { signer, blob: encodeNote(text, [await signNote(text, signer)]) };
}

test('an envelope carries the note bytes and their digest, and nothing else is required', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  assert.equal(env.note, blob);
  assert.equal(env.note_digest, 'sha256:' + createHash('sha256').update(blob).digest('hex'));
  // Row 7 — the common case. An unwitnessed checkpoint is not damage.
  assert.deepEqual(env.countersignatures, []);
  const parsed = parseEnvelope(JSON.stringify(env));
  assert.deepEqual(parsed.findings, []);
  assert.equal(parsed.unwitnessed, true);
});

// ── Row 1 — the digest binds everything else ─────────────────────────────────

test('row 1: a note_digest that is not the digest of the note is refused', async () => {
  const { blob } = await note();
  const env = { ...buildEnvelope(blob), note_digest: 'sha256:' + 'ab'.repeat(32) };
  const parsed = parseEnvelope(JSON.stringify(env));
  assert.equal(parsed.ok, false);
  assert.ok(parsed.findings.some(f => f.code === 'ENVELOPE_DIGEST_MISMATCH'));
  // And nothing in it is treated as verified: every countersignature `covers`
  // that digest, so a wrong one makes them all vouch for bytes nobody has.
  assert.deepEqual(parsed.countersignatures, []);
});

test('row 1: a missing or malformed note_digest is refused, not recomputed', async () => {
  const { blob } = await note();
  for (const d of [undefined, null, '', 'sha256:short', 'deadbeef', 'sha512:' + 'a'.repeat(128), 42]) {
    const env = { ...buildEnvelope(blob), note_digest: d };
    const parsed = parseEnvelope(JSON.stringify(env));
    assert.equal(parsed.ok, false, `${JSON.stringify(d)} should be refused`);
  }
  // Recomputing a missing digest would make the field decorative: the point of
  // storing it is that a countersignature names it rather than the bytes.
});

// ── Rows 2, 3 — covers and unknown types ─────────────────────────────────────

test('row 2: a countersignature covering something absent is inconclusive, not valid', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  env.countersignatures.push(
    /** @type {any} */ ({ type: 'rfc3161', issuer: 'tsa.example', covers: 'something_else', token: 'AAAA' }),
    /** @type {any} */ ({ type: 'rfc3161', issuer: 'tsa.example', token: 'AAAA' }),
  );
  const parsed = parseEnvelope(JSON.stringify(env));
  assert.equal(parsed.countersignatures.length, 2);
  for (const cs of parsed.countersignatures) {
    assert.equal(cs.verdict, 'inconclusive');
    assert.match(String(cs.detail), /covers/);
  }
  // Inconclusive, so the envelope is not failed by it — an unverifiable entry
  // is not evidence of tampering.
  assert.equal(parsed.ok, true);
});

test('row 3: an unimplemented type is inconclusive, never a failure', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  env.countersignatures.push({
    type: 'post-quantum-notary-2031', issuer: 'future.example',
    covers: 'note_digest', proof: 'AAAA',
  });
  const parsed = parseEnvelope(JSON.stringify(env));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.countersignatures[0].verdict, 'inconclusive');
  assert.match(String(parsed.countersignatures[0].detail), /does not implement/);
  // The three types this verifier does implement, stated so a reader of the
  // report knows what the inconclusive verdict means.
  assert.deepEqual([...COUNTERSIGNATURE_TYPES], ['c2sp-note', 'rfc3161', 'opentimestamps']);
});

test('an entry that is not an object, or has no type, is a finding not a crash', async () => {
  const { blob } = await note();
  for (const bad of [null, 'string', 42, [], {}, { issuer: 'x' }, { type: 42 }]) {
    const env = buildEnvelope(blob);
    env.countersignatures.push(/** @type {any} */ (bad));
    const parsed = parseEnvelope(JSON.stringify(env));
    assert.ok(parsed.findings.length > 0 || parsed.countersignatures[0]?.verdict === 'inconclusive',
      `${JSON.stringify(bad)} should produce a finding`);
  }
});

// ── Row 4 — one issuer, one vote ─────────────────────────────────────────────

test('row 4: the same issuer twice counts once', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  /** @type {import('../src/envelope.mjs').Countersignature} */
  const entry = { type: 'rfc3161', issuer: 'tsa.example', covers: 'note_digest', token: 'AAAA' };
  env.countersignatures.push({ ...entry }, { ...entry });
  const parsed = parseEnvelope(JSON.stringify(env));
  // Both entries are reported — hiding one would hide a duplicate submission —
  // but the issuer set, which is what a quorum counts, holds one.
  assert.equal(parsed.countersignatures.length, 2);
  assert.deepEqual([...parsed.issuers], ['tsa.example']);
  assert.ok(parsed.findings.some(f => f.code === 'ENVELOPE_DUPLICATE_ISSUER'));
});

// ── Row 5 — the envelope's note must be the note on disk ─────────────────────

test('row 5: an envelope whose note is not the note it is checked against is refused', async () => {
  const { blob } = await note(4812);
  const other = await note(9999);
  const env = buildEnvelope(blob);
  const parsed = parseEnvelope(JSON.stringify(env), { expectNote: other.blob });
  assert.equal(parsed.ok, false);
  assert.ok(parsed.findings.some(f => f.code === 'ENVELOPE_NOTE_MISMATCH'));
});

// ── Row 6 — malformed input ──────────────────────────────────────────────────

test('row 6: bytes that are not an envelope are a finding, not a throw', () => {
  for (const raw of ['', 'not json', '[]', 'null', '42', '"a string"', '{"note":42}', '{}']) {
    const parsed = parseEnvelope(raw);
    assert.equal(parsed.ok, false, `${JSON.stringify(raw)} should be refused`);
    assert.ok(parsed.findings.length > 0);
  }
});

test('an envelope whose note is not a parseable checkpoint is refused', () => {
  const env = buildEnvelope('this is not a signed note');
  const parsed = parseEnvelope(JSON.stringify(env));
  assert.equal(parsed.ok, false);
  assert.ok(parsed.findings.some(f => f.code === 'FORMAT_UNSUPPORTED'));
});

// ── addCountersignature ──────────────────────────────────────────────────────

test('adding a countersignature keeps the note and digest untouched', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  const next = addCountersignature(env, {
    type: 'c2sp-note', issuer: 'audit.internal', covers: 'note', line: '— audit.internal AAAAAAAA AA==',
  });
  assert.equal(next.note, env.note);
  assert.equal(next.note_digest, env.note_digest);
  assert.equal(next.countersignatures.length, 1);
  // Immutable: the envelope handed in is not mutated, so a failed write cannot
  // leave the in-memory copy ahead of the file.
  assert.equal(env.countersignatures.length, 0);
});

test('addCountersignature refuses an entry with no covers, type or issuer', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  for (const bad of [
    {}, { type: 'c2sp-note' }, { type: 'c2sp-note', issuer: 'a' },
    { issuer: 'a', covers: 'note' }, { type: 'c2sp-note', issuer: 'a', covers: 'nothing' },
  ]) {
    assert.throws(() => addCountersignature(env, /** @type {any} */ (bad)),
      (/** @type {any} */ e) => e instanceof EnvelopeError, JSON.stringify(bad));
  }
});

test('a c2sp-note entry must cover the note, and a token entry the digest', async () => {
  const { blob } = await note();
  const env = buildEnvelope(blob);
  // A signed-note line is over the note TEXT; an RFC 3161 token is over a
  // MessageImprint of the digest. Allowing either to claim the other's subject
  // is how a verifier ends up checking a signature against bytes nobody signed.
  assert.throws(() => addCountersignature(env, {
    type: 'c2sp-note', issuer: 'a', covers: 'note_digest', line: '— a AAAAAAAA AA==',
  }), /c2sp-note/);
  assert.throws(() => addCountersignature(env, {
    type: 'rfc3161', issuer: 'a', covers: 'note', token: 'AAAA',
  }), /rfc3161/);
});

test('noteDigest is over the exact bytes, including the trailing newline', async () => {
  const { blob } = await note();
  assert.notEqual(noteDigest(blob), noteDigest(blob.trimEnd()));
  assert.equal(noteDigest(blob), 'sha256:' + createHash('sha256').update(blob).digest('hex'));
});
