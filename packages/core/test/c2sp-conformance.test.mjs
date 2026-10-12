import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  checkpointText, parseCheckpointText, encodeNote, parseNote, formatVkey, parseVkey, noteKeyId,
  NoteError, ALG_ED25519,
} from '../src/note.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { signNote, verifyNoteSignature } from '../src/signer.mjs';

/**
 * INT-01 — conformance to the C2SP `tlog-checkpoint` and signed-note formats.
 *
 * This is the requirement that makes INT-02 possible at all: an existing C2SP
 * witness can only countersign our checkpoints if our checkpoints are C2SP
 * notes. An earlier draft of DES-06 had the operator signing a custom preimage,
 * and an external review pointed out that no existing witness could then have
 * signed the same bytes. There is one signed subject in this system, not two,
 * and these assertions are what keep it that way.
 *
 * The assertions are against the SPEC as written, deliberately spelled out
 * rather than expressed in terms of our own helpers — a test that says
 * `parseNote(encodeNote(x)) === x` conforms to itself.
 */

const ORIGIN = 'splitstick.example/treasury-host-1';
const ROOT = Buffer.from('3ba3f74c'.repeat(8), 'hex');

test('the checkpoint body is origin, size, base64 root, each on its own line', () => {
  const text = checkpointText({ origin: ORIGIN, tree_size: 4812, root: ROOT });
  const lines = text.split('\n');
  assert.equal(lines[0], ORIGIN);
  assert.equal(lines[1], '4812');
  assert.equal(lines[2], ROOT.toString('base64'));
  assert.equal(text.endsWith('\n'), true, 'the body is newline-terminated');
});

test('an extension line follows the three required ones, and is optional', () => {
  const withSuite = checkpointText({ origin: ORIGIN, tree_size: 1, root: ROOT, suite: 'SS1' });
  assert.equal(withSuite.split('\n')[3], 'suite SS1');
  // The spec allows extension lines after the first three and requires a
  // reader to tolerate ones it does not know.
  const unknown = `${ORIGIN}\n1\n${ROOT.toString('base64')}\nsomething else\nsuite SS1\n`;
  const cp = parseCheckpointText(unknown);
  assert.equal(cp.tree_size, 1);
  assert.equal(cp.suite, 'SS1');
});

test('a note is body, blank line, then signature lines', () => {
  const text = checkpointText({ origin: ORIGIN, tree_size: 7, root: ROOT, suite: 'SS1' });
  const blob = encodeNote(text, [{
    name: ORIGIN, keyId: Buffer.alloc(4, 1), signature: Buffer.alloc(64, 2),
  }]);
  assert.equal(blob, `${text}\n— ${ORIGIN} ${Buffer.concat([Buffer.alloc(4, 1), Buffer.alloc(64, 2)]).toString('base64')}\n`);
  // The separator is a blank line, which is what lets a verifier find the end
  // of the signed bytes without parsing the body.
  assert.ok(blob.includes(`${ROOT.toString('base64')}\nsuite SS1\n\n—`));
});

test('a signature line is an em dash, a space, the name, a space, and base64', () => {
  const blob = encodeNote(`${ORIGIN}\n1\n${ROOT.toString('base64')}\n`, [{
    name: 'audit.internal', keyId: Buffer.alloc(4, 9), signature: Buffer.alloc(64, 8),
  }]);
  const line = blob.trimEnd().split('\n').at(-1) ?? '';
  assert.match(line, /^— \S+ [A-Za-z0-9+/]+={0,2}$/);
  assert.equal(line.charCodeAt(0), 0x2014, 'U+2014 EM DASH, not a hyphen');
  assert.equal(line[1], ' ');
});

test('the signature blob is a 4-byte key id followed by the signature', () => {
  const keyId = Buffer.from('deadbeef', 'hex');
  const sig = Buffer.alloc(64, 3);
  const blob = encodeNote(`${ORIGIN}\n1\n${ROOT.toString('base64')}\n`, [
    { name: ORIGIN, keyId, signature: sig },
  ]);
  const b64 = (blob.trimEnd().split(' ').at(-1)) ?? '';
  const raw = Buffer.from(b64, 'base64');
  assert.equal(raw.length, 68);
  assert.equal(raw.subarray(0, 4).toString('hex'), 'deadbeef');
  assert.equal(raw.subarray(4).toString('hex'), sig.toString('hex'));
});

test('the key id is the first 4 bytes of SHA-256 over name, newline, alg, key', () => {
  // The spec's own construction, reproduced here independently of our helper.
  const signerName = 'audit.internal';
  const publicKey = Buffer.alloc(32, 5);
  const expected = createHash('sha256')
    .update(Buffer.concat([
      Buffer.from(`${signerName}\n`, 'utf8'),
      Buffer.from([ALG_ED25519]),
      publicKey,
    ]))
    .digest()
    .subarray(0, 4);
  assert.equal(noteKeyId(signerName, publicKey).toString('hex'), expected.toString('hex'));
  assert.equal(ALG_ED25519, 1, 'Ed25519 is algorithm 1 in the signed-note registry');
});

test('a vkey is name+alg+base64(key), and round-trips', () => {
  const publicKey = Buffer.alloc(32, 6);
  const vkey = formatVkey('audit.internal', publicKey);
  assert.match(vkey, /^audit\.internal\+[0-9a-f]{8}\+[A-Za-z0-9+/]+={0,2}$/);
  const parsed = parseVkey(vkey);
  assert.equal(parsed.name, 'audit.internal');
  assert.equal(parsed.publicKey.toString('hex'), publicKey.toString('hex'));
  assert.equal(parsed.keyId.toString('hex'), noteKeyId('audit.internal', publicKey).toString('hex'));
});

test('what is signed is the body INCLUDING its trailing newline, and not the separator', async () => {
  // The single most important conformance property: if we sign a byte more or
  // fewer than the spec says, no existing C2SP witness can countersign the
  // same bytes and INT-02 is unreachable.
  const signer = await generateDevSigner(ORIGIN);
  const text = checkpointText({ origin: ORIGIN, tree_size: 9, root: ROOT, suite: 'SS1' });
  const sig = await signNote(text, signer);
  const { verify, createPublicKey } = await import('node:crypto');
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), signer.publicKey]),
    format: 'der', type: 'spki',
  });
  assert.equal(verify(null, Buffer.from(text, 'utf8'), key, sig.signature), true);
  // And NOT over the body plus the blank-line separator.
  assert.equal(verify(null, Buffer.from(`${text}\n`, 'utf8'), key, sig.signature), false);
  // Nor over the body with its trailing newline stripped.
  assert.equal(verify(null, Buffer.from(text.trimEnd(), 'utf8'), key, sig.signature), false);
});

test('a second signature line is appended without touching the first or the body', async () => {
  // This is what a witness does, and the reason the note is the signed subject:
  // countersigning must not change what the operator signed.
  const operator = await generateDevSigner(ORIGIN);
  const witness = await generateDevSigner('audit.internal');
  const text = checkpointText({ origin: ORIGIN, tree_size: 3, root: ROOT, suite: 'SS1' });
  const one = encodeNote(text, [await signNote(text, operator)]);
  const two = encodeNote(text, [await signNote(text, operator), await signNote(text, witness)]);
  assert.equal(parseNote(two).text, parseNote(one).text);
  assert.ok(two.startsWith(one.slice(0, one.lastIndexOf('\n') + 1)));
  const sigs = parseNote(two).signatures;
  assert.equal(sigs.length, 2);
  assert.equal(await verifyNoteSignature(text, sigs[0], operator.verifier()), true);
  assert.equal(await verifyNoteSignature(text, sigs[1], witness.verifier()), true);
});

test('a note with no signature, or a malformed line, is refused', () => {
  const text = `${ORIGIN}\n1\n${ROOT.toString('base64')}\n`;
  assert.throws(() => parseNote(`${text}\n`), NoteError);
  assert.throws(() => parseNote(`${text}\n- ${ORIGIN} AAAA\n`), NoteError, 'a hyphen is not an em dash');
  assert.throws(() => parseNote(`${text}\n— ${ORIGIN}\n`), NoteError, 'no blob');
  assert.throws(() => parseNote(text), NoteError, 'no separator');
  assert.throws(() => encodeNote(text, []), NoteError);
});

test('a tree size that is not a non-negative decimal integer is refused', () => {
  const b64 = ROOT.toString('base64');
  for (const size of ['-1', '1.5', '0x10', '', ' 1', '1 ', '01']) {
    assert.throws(() => parseCheckpointText(`${ORIGIN}\n${size}\n${b64}\n`), NoteError, size);
  }
  // Zero is valid: a log with no entries has a well-defined root.
  assert.equal(parseCheckpointText(`${ORIGIN}\n0\n${b64}\n`).tree_size, 0);
});

test('a root that is not 32 base64 bytes is refused', () => {
  for (const root of ['', 'AAAA', Buffer.alloc(31).toString('base64'), Buffer.alloc(33).toString('base64'), '!!!']) {
    assert.throws(() => parseCheckpointText(`${ORIGIN}\n1\n${root}\n`), NoteError, root);
  }
});
