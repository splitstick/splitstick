import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  noteKeyId, formatVkey, parseVkey, checkpointText, parseCheckpointText,
  encodeNote, parseNote, NoteError,
} from '../src/note.mjs';
import { generateDevSigner } from '../src/signer-file.mjs';
import { signNote, verifyNoteSignature } from '../src/signer.mjs';
import { treeRoot } from '../src/merkle.mjs';

const V = JSON.parse(readFileSync(new URL('../../../spec/vectors/note.json', import.meta.url), 'utf8'));

// The externally anchored half of the format: this key id comes from a published
// verifier key, so the derivation is checked against someone else's bytes.
test('key-id derivation reproduces a published C2SP verifier key id', () => {
  for (const v of V.keyid) {
    const pub = Buffer.from(v.public_key_b64, 'base64');
    assert.equal(noteKeyId(v.name, pub).toString('hex'), v.expect_keyid);
    assert.equal(formatVkey(v.name, pub), v.vkey);
    const parsed = parseVkey(v.vkey);
    assert.equal(parsed.name, v.name);
    assert.equal(parsed.algorithm, 1);
    assert.equal(parsed.publicKey.toString('base64'), v.public_key_b64);
  }
});

test('a vkey whose key id does not match its key is refused', () => {
  const v = V.keyid[0];
  assert.throws(() => parseVkey(v.vkey.replace('c74f20a3', 'deadbeef')), NoteError);
});

// DES-07's text — origin, tree_size, base64 root, each line newline-terminated.
test('checkpoint text is origin, tree_size and base64 root, in that order', () => {
  const root = treeRoot([Buffer.from('a'), Buffer.from('b')]);
  const text = checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 2, root });
  assert.equal(text, `splitstick.dev/host-1\n2\n${root.toString('base64')}\n`);
  const back = parseCheckpointText(text);
  assert.equal(back.origin, 'splitstick.dev/host-1');
  assert.equal(back.tree_size, 2);
  assert.equal(back.root.toString('hex'), root.toString('hex'));
});

test('a checkpoint with a non-integer or negative tree_size is refused', () => {
  const root = treeRoot([]);
  for (const bad of [-1, 1.5, NaN]) {
    assert.throws(() => checkpointText({ origin: 'o', tree_size: bad, root }), NoteError);
  }
  assert.throws(() => checkpointText(
    { origin: 'o', tree_size: /** @type {never} */ ('2'), root }), NoteError,
    'a numeric string is not an integer');
  assert.throws(() => parseCheckpointText('o\nnot-a-number\nAAAA\n'), NoteError);
  assert.throws(() => parseCheckpointText('o\n2\n'), NoteError, 'a truncated note is not a note');
});

test('an origin containing a newline cannot smuggle a second line', () => {
  assert.throws(() => checkpointText({ origin: 'a\n9999', tree_size: 1, root: treeRoot([]) }), NoteError);
});

test('note round trip: text plus signature lines', async () => {
  const signer = await generateDevSigner('splitstick.dev/host-1');
  const text = checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 4, root: treeRoot([Buffer.from('x')]) });
  const sig = await signNote(text, signer);
  const blob = encodeNote(text, [sig]);
  assert.match(blob, /\n\n— splitstick\.dev\/host-1 [A-Za-z0-9+/=]+\n$/);
  const parsed = parseNote(blob);
  assert.equal(parsed.text, text);
  assert.equal(parsed.signatures.length, 1);
  assert.equal(parsed.signatures[0].name, 'splitstick.dev/host-1');
  assert.equal(await verifyNoteSignature(parsed.text, parsed.signatures[0], signer.verifier()), true);
});

// DES-06: the signed subject is the note, which is what lets an existing C2SP
// witness countersign the same bytes. One subject in this system, not two.
test('a second signature line is added over the same bytes', async () => {
  const op = await generateDevSigner('splitstick.dev/host-1');
  const witness = await generateDevSigner('witness.audit.internal');
  const text = checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 9, root: treeRoot([Buffer.from('y')]) });

  const blob = encodeNote(text, [await signNote(text, op), await signNote(text, witness)]);
  const parsed = parseNote(blob);
  assert.equal(parsed.signatures.length, 2);
  assert.equal(parsed.text, text, 'countersigning must not alter the subject');
  assert.equal(await verifyNoteSignature(parsed.text, parsed.signatures[0], op.verifier()), true);
  assert.equal(await verifyNoteSignature(parsed.text, parsed.signatures[1], witness.verifier()), true);
  // And neither signature validates under the other identity.
  assert.equal(await verifyNoteSignature(parsed.text, parsed.signatures[1], op.verifier()), false);
});

test('OPSIG_INVALID: a changed root, size or origin breaks the signature', async () => {
  const op = await generateDevSigner('splitstick.dev/host-1');
  const root = treeRoot([Buffer.from('y')]);
  const text = checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 9, root });
  const sig = await signNote(text, op);

  const tampered = [
    checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 8, root }),
    checkpointText({ origin: 'splitstick.dev/host-2', tree_size: 9, root }),
    checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 9, root: createHash('sha256').update('z').digest() }),
  ];
  for (const t of tampered) {
    assert.equal(await verifyNoteSignature(t, sig, op.verifier()), false);
  }
});

test('a signature line whose key id does not match the verifier is rejected, not verified', async () => {
  const op = await generateDevSigner('splitstick.dev/host-1');
  const other = await generateDevSigner('splitstick.dev/host-1');  // same name, different key
  const text = checkpointText({ origin: 'splitstick.dev/host-1', tree_size: 1, root: treeRoot([]) });
  const sig = await signNote(text, op);
  assert.equal(await verifyNoteSignature(text, sig, other.verifier()), false,
    'the same origin under a different key must not pass — FR-63');
});

test('a malformed note is refused rather than partially parsed', () => {
  for (const bad of ['', 'no trailing newline', 'text\n', 'text\n\nnot a sig line\n',
                     'text\n\n— name\n', 'text\n\n— name !!!notbase64!!!\n']) {
    assert.throws(() => parseNote(bad), NoteError, JSON.stringify(bad));
  }
});
