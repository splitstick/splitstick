// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * LEG-12 and LEG-13 — the eIDAS Art. 41 presumption, in the report.
 *
 * LEG-12 is also a lint over the prose (tools/leg12.mjs). This is the other
 * half: what the verifier is allowed to SAY, which no amount of careful
 * documentation controls once the report is generated.
 *
 * The gate is the READER's acceptance policy, not the operator's config. An
 * operator declaring their own TSA qualified is self-assertion; the presumption
 * is a conclusion the reader draws, and FR-30 already says the reader's trust
 * is an input. And it is computed from the proof TYPE rather than the issuer's
 * name, because a policy that labels our own C2SP witness "qualified" must
 * still not produce the claim.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { parseEnvelope, addCountersignature } from '@splitstick/core/envelope';
import { verifyStore } from '../src/index.mjs';

const FIX = new URL('../../core/test/fixtures/rfc3161/', import.meta.url);
const fix = (/** @type {string} */ n) => readFileSync(new URL(n, FIX));
const ORIGIN = 'splitstick.dev/host-1';

/** A store whose one checkpoint is countersigned by our own C2SP witness. */
async function ours() {
  const root = mkdtempSync(join(tmpdir(), 'ss-presume-'));
  const signer = await generateDevSigner(ORIGIN);
  const wk = await generateDevSigner('audit.internal');
  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  for (let i = 0; i < 3; i += 1) {
    c.action({ tool: 't', args: Buffer.from('{}'), result: Buffer.from('ok'), correlation: `c-${i}` });
  }
  const cp = await c.checkpoint();
  const raw = /** @type {string} */ (store.readCheckpointEnvelope(cp.checkpoint_seq));
  const text = parseNote(/** @type {string} */ (parseEnvelope(raw).note)).text;
  const line = encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1);
  store.writeCheckpointEnvelope(cp.checkpoint_seq, addCountersignature(JSON.parse(raw), {
    type: 'c2sp-note', issuer: 'audit.internal', covers: 'note',
    line: /** @type {string} */ (line), received_at: new Date(t).toISOString(),
  }));
  store.close();
  return {
    root,
    vkey: formatVkey(ORIGIN, signer.publicKey),
    pk: Buffer.from(wk.publicKey).toString('base64'),
  };
}

/** The same store, with a REAL RFC 3161 token from the interop fixture. */
async function tsa() {
  const { root } = await ours();
  const s = new Store(root, 'host-1');
  s.writeCheckpointEnvelope(1, {
    note: fix('checkpoint.note').toString('utf8'),
    note_digest: fix('checkpoint.digest').toString('utf8').trim(),
    countersignatures: [{
      type: 'rfc3161', issuer: 'tsa.example', covers: 'note_digest',
      token: fix('checkpoint-token.b64').toString('utf8').trim(),
    }],
  });
  s.close();
  return { root, vkey: fix('checkpoint.vkey').toString('utf8').trim() };
}

test('LEG-13: a qualified TSA the reader declares carries the presumption', async () => {
  const { root, vkey } = await tsa();
  const r = await verifyStore(root, {
    collector: 'host-1', vkey,
    policy: {
      quorum: 1,
      witnesses: [{
        id: 'tsa.example', establishes: ['time'], qualified: true,
        anchors: [fix('root.pem').toString('utf8')],
      }],
    },
  });
  assert.equal(r.presumption.attaches, true, r.presumption.detail);
  assert.deepEqual(r.presumption.issuers, ['tsa.example']);
  // And it says whose declaration it rests on. A report that simply announced
  // the presumption would be stating a legal conclusion it has no way to
  // reach: qualified status lives in the EU trusted list, which verification
  // cannot consult and by NFR-05 never will.
  assert.match(r.presumption.detail, /YOUR POLICY declares/);
  assert.match(r.presumption.detail, /does not and cannot establish qualified status/);
  assert.ok(r.capability.cannot.some(c => /rests on your own declaration/.test(c)),
    'the limit is not in the list a reader is shown');
});

test('LEG-12: a policy declaring OUR OWN witness qualified still carries nothing', async () => {
  // The adversarial case, and the reason this is computed from the proof type.
  // A reader — or an operator writing the reader's policy for them — can put
  // `qualified: true` beside any issuer they like. A C2SP note is not a
  // qualified timestamp whatever it is labelled.
  const { root, vkey, pk } = await ours();
  const r = await verifyStore(root, {
    collector: 'host-1', vkey,
    policy: {
      quorum: 1,
      witnesses: [{
        id: 'audit.internal', public_key: pk, establishes: ['sequence'], qualified: true,
      }],
    },
  });
  // The countersignature itself is fine — this is not a story about a bad
  // witness, which is what makes the refusal meaningful.
  assert.equal(r.witnesses.find(w => w.id === 'audit.internal')?.verdict, 'ok');
  assert.equal(r.presumption.attaches, false);
  assert.match(r.presumption.detail, /not an RFC 3161 token from a trust service/);
  assert.match(r.presumption.detail, /LEG-12/);
});

test('LEG-12: with no declaration the report says the presumption is not addressed', async () => {
  // Silence would be read as "probably fine" by a reader hoping for it, so the
  // absence is stated rather than left out.
  const { root, vkey, pk } = await ours();
  const r = await verifyStore(root, {
    collector: 'host-1', vkey,
    policy: { quorum: 1, witnesses: [{ id: 'audit.internal', public_key: pk, establishes: ['sequence'] }] },
  });
  assert.equal(r.presumption.attaches, false);
  assert.deepEqual(r.presumption.issuers, []);
  assert.match(r.presumption.detail, /never through a witness this project operates/);
  assert.ok(r.capability.cannot.includes('nothing here establishes the eIDAS Art. 41 presumption'));
});

test('LEG-13: a declared TSA whose token does NOT verify carries nothing', async () => {
  // Declared qualified, right proof type, and the anchor withheld so the token
  // cannot be attributed. "Qualified" is a statement about the authority; it
  // is not a substitute for the signature checking out.
  const { root, vkey } = await tsa();
  const r = await verifyStore(root, {
    collector: 'host-1', vkey,
    policy: {
      quorum: 1,
      witnesses: [{
        id: 'tsa.example', establishes: ['time'], qualified: true,
        anchors: [fix('impostor.pem').toString('utf8')],
      }],
    },
  });
  assert.equal(r.presumption.attaches, false, r.presumption.detail);
  assert.match(r.presumption.detail, /did NOT verify here/);
});

test('LEG-13: the operator can configure a qualified TSA in the witness set', async () => {
  // LEG-13's literal ask. The config path has to accept it, and the two
  // allowed-key lists that used to disagree now come from one table.
  const { parseConfig: pc } = await import('@splitstick/core/config');
  const cfg = pc('version: 1\nstore: ./s\n'
    + 'witnesses:\n  - id: qtsa.example\n    type: rfc3161\n'
    + '    url: https://tsa.example/tsr\n    qualified: true\n', '/tmp');
  assert.equal(cfg.witnesses[0]?.qualified, true);

  const { witnessesFromConfig } = await import('@splitstick/witnesses');
  const [w] = witnessesFromConfig(cfg);
  assert.equal(/** @type {any} */ (w).qualified, true,
    'the adapter does not carry the declaration, so a deployment cannot be described');
  assert.equal(w?.proof_type, 'rfc3161');

  // And a non-boolean is refused rather than coerced: `qualified: "yes"` is
  // truthy, and a string that silently became a legal claim is the whole
  // reason this is validated.
  assert.throws(() => pc('version: 1\nstore: ./s\n'
    + 'witnesses:\n  - id: q\n    type: rfc3161\n    url: https://x/\n    qualified: maybe\n', '/tmp'),
  (/** @type {any} */ e) => /qualified on q is a boolean/.test(e.message));
});

test('the witness key table is the only one, so the parser and the builder cannot disagree', async () => {
  // They DID disagree: the parser allowed five keys while the builder read
  // `calendars` and `self_hosted`, so an operator could not configure a knob
  // the code supports. Every key the builder reads must be declared.
  const { witnessKeysFor } = await import('@splitstick/core/config');
  const src = readFileSync(new URL('../../witnesses/src/index.mjs', import.meta.url), 'utf8');
  const read = new Set([...src.matchAll(/\bw\.([a-z_]+)\b/g)].map(m => String(m[1])));
  for (const key of read) {
    const declared = ['rfc3161', 'opentimestamps', 'rekor', 'splitstick']
      .some(t => witnessKeysFor(t).includes(key))
      // `establishes` and `proof_type` are the adapter's own output, not config.
      || ['establishes', 'proof_type'].includes(key);
    assert.ok(declared,
      `witnessesFromConfig reads w.${key}, which no witness type declares — `
      + 'parseConfig will refuse it and the operator cannot set it');
  }
});

test('LEG-12: the RENDERED report states it either way', async () => {
  // A field in the JSON that the human-readable report omits is a field most
  // readers never see, and this is the one most likely to be quoted at
  // somebody outside the room.
  const { execFile } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const { root, vkey } = await ours();
  const r = await new Promise((resolve) => {
    execFile(process.execPath, [CLI, root, '--collector', 'host-1', '--key', vkey],
      (err, stdout) => resolve(stdout));
  });
  assert.match(String(r), /eIDAS\s+no Art\. 41 presumption/);
  assert.match(String(r), /never\s+through a witness this project operates \(LEG-12\)/);
});
