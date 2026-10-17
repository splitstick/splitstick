// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * FR-15 — the tlog-witness adapter, against a local instance.
 *
 * The server here is REAL in the part that matters: its state, its consistency
 * checking and its refusals come from @splitstick/witness-self, whose
 * semantics the published conformance suite checks independently (C1–C7). What
 * the server adds is the HTTP shape of the C2SP tlog-witness protocol.
 *
 * What that cannot establish is wire compatibility with transparency-dev's Go
 * implementation: a client and a server written against one reading of one
 * document agree with each other whether or not the reading is right. Said
 * plainly in the adapter and carried in docs/m6-follow-ups.md.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { Anchorer } from '@splitstick/core/anchor';
import { StatefulWitness } from '@splitstick/witness-self';
import { tlogWitness, TlogWitnessError, TlogConflict } from '../src/index.mjs';

const ORIGIN = 'splitstick.dev/host-1';

/** Serve one StatefulWitness over the tlog-witness protocol. */
async function serve(witness) {
  /** @type {{ body: string }[]} */
  const seen = [];
  const server = createServer((req, res) => {
    if (req.url !== '/add-checkpoint' || req.method !== 'POST') {
      res.writeHead(404).end(); return;
    }
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', async () => {
      seen.push({ body });
      // `old <n>\n` then zero or more base64 proof hashes, then a blank line,
      // then the note. Parsed strictly: a body this server could not read is
      // a protocol error and not something to guess at.
      const i = body.indexOf('\n\n');
      if (i === -1) { res.writeHead(400).end('no blank line before the note'); return; }
      const head = body.slice(0, i).split('\n');
      const note = body.slice(i + 2);
      const first = head[0] ?? '';
      if (!/^old \d+$/.test(first)) { res.writeHead(400).end('first line is not `old <size>`'); return; }
      const old_size = Number(first.slice(4));
      const consistency_proof = head.slice(1).filter(l => l !== '');
      try {
        const r = await witness.addCheckpoint({ note, old_size, consistency_proof });
        res.writeHead(200, { 'content-type': 'text/plain' })
          .end(`${r.note.trimEnd().split('\n').at(-1)}\n`);
      } catch (e) {
        const status = /** @type {any} */ (e)?.status ?? 500;
        if (status === 409 || status === 400) {
          const st = witness.state(ORIGIN);
          res.writeHead(409, { 'content-type': 'text/plain' })
            .end(`${st.last_size}\n${st.last_root ?? ''}\n`);
          return;
        }
        res.writeHead(status === 403 ? 403 : 500).end(String(/** @type {any} */ (e)?.message ?? e));
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(undefined)));
  const { port } = /** @type {any} */ (server.address());
  return { url: `http://127.0.0.1:${port}`, seen, close: () => server.close() };
}

/** A collector anchored to a tlog witness over HTTP. */
async function wired() {
  const root = mkdtempSync(join(tmpdir(), 'ss-tlog-'));
  const wdir = mkdtempSync(join(tmpdir(), 'ss-tlog-w-'));
  const signer = await generateDevSigner(ORIGIN);
  const wkey = await generateDevSigner('witness.example');
  const witness = new StatefulWitness({ dir: wdir, signer: wkey });
  witness.enrol(ORIGIN, signer.publicKey);
  const http = await serve(witness);

  const store = new Store(root, 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', root), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  const adapter = tlogWitness({ id: 'witness.example', url: http.url });
  const anchorer = new Anchorer({
    store, witnesses: [adapter], quorum: 1,
    acceptance: { 'witness.example': wkey.publicKey },
  });
  return {
    store, c, anchorer, adapter, witness, http,
    cleanup: () => {
      http.close(); store.close();
      rmSync(root, { recursive: true, force: true });
      rmSync(wdir, { recursive: true, force: true });
    },
  };
}

test('FR-15: successive checkpoints anchor against a local tlog-witness over HTTP', async () => {
  // Four batches, not one. A seam exercised once looks like a seam that works,
  // and the consistency proof only appears from the second submission on —
  // which is precisely where the Anchorer was once broken for a stateful
  // witness and nothing caught it.
  const w = await wired();
  try {
    /** @type {number[]} */
    const sizes = [];
    for (let batch = 0; batch < 4; batch += 1) {
      for (let i = 0; i < 3; i += 1) {
        w.c.action({
          run: 'r-1', tool: 'transfer_funds', consequential: true,
          args: Buffer.from(`{"amount":${batch}${i}00}`), result: Buffer.from('OK'),
          outcome: 'ok', attempt: 1, correlation: `c-${batch}-${i}`,
        });
      }
      const cp = await w.c.checkpoint();
      const r = await w.anchorer.anchor(cp.checkpoint_seq);
      assert.deepEqual(r.failed, [], `batch ${batch}: ${JSON.stringify(r.failed)}`);
      assert.equal(r.attached.length, 1, `batch ${batch} did not anchor`);
      assert.equal(r.attached[0]?.verified, true, 'the cosignature does not verify');
      sizes.push(cp.tree_size);
    }
    assert.deepEqual(sizes, [3, 6, 9, 12]);
    assert.equal(w.witness.state(ORIGIN).last_size, 12);

    // The wire format, asserted rather than assumed: `old <n>`, then the proof
    // hashes, then a blank line, then the note.
    const bodies = w.http.seen.map(s => s.body);
    assert.match(String(bodies[0]), /^old 0\n\n/);
    assert.match(String(bodies[1]), /^old 3\n[A-Za-z0-9+/=]+\n/);
    for (const b of bodies) {
      const i = String(b).indexOf('\n\n');
      assert.ok(i > 0, 'no blank line separates the head from the note');
      assert.match(String(b).slice(i + 2), /^splitstick\.dev\/host-1\n\d+\n/);
    }
  } finally {
    w.cleanup();
  }
});

test('FR-15: a rewritten history is REFUSED, and the refusal is a conflict', async () => {
  // The reason this witness type exists. A TSA or Rekor would stamp the
  // replacement without complaint; this one remembers and says no.
  const w = await wired();
  try {
    for (let i = 0; i < 3; i += 1) {
      w.c.action({ tool: 't', args: Buffer.from('{}'), result: Buffer.from('ok'), correlation: `a-${i}` });
    }
    const first = await w.c.checkpoint();
    await w.anchorer.anchor(first.checkpoint_seq);
    assert.equal(w.witness.state(ORIGIN).last_size, 3);

    // Submit a SHORTER tree, proving from 0 — what a rewind looks like on the
    // wire.
    const note = /** @type {any} */ (w.witness.roots(ORIGIN));
    await assert.rejects(
      () => w.adapter.submit(`${ORIGIN}\n2\nAAAA\n\n— ${ORIGIN} AAAA\n`,
        { old_size: 0, consistency_proof: [] }),
      (/** @type {any} */ e) => {
        assert.ok(e instanceof TlogConflict, `expected a conflict, got ${e?.name}: ${e?.message}`);
        assert.equal(e.size, 3, 'the conflict does not carry the size the witness remembers');
        assert.match(e.message, /refusing a rewritten history/);
        return true;
      });
    assert.ok(note);
  } finally {
    w.cleanup();
  }
});

test('FR-15: the operator\'s own signature is never returned as a countersignature', async () => {
  // The defect this project has already had twice: presence counted as
  // anchoring. A witness whose reply echoed the note back would otherwise make
  // the operator their own witness, and the note already contains their line.
  const signer = await generateDevSigner(ORIGIN);
  const note = `${ORIGIN}\n3\ncm9vdA==\n\n— ${ORIGIN} AAAAAAAA\n`;
  const echo = tlogWitness({
    id: 'echo.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response(note, { status: 200 }),
  });
  await assert.rejects(
    () => echo.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /would make the operator\s+their own witness/.test(e.message));
  assert.ok(signer);
});

/**
 * The real status map, read out of transparency-dev/witness rather than
 * inferred. This test asserted 403 for the unenrolled case; 403 is
 * ErrNoValidSignature and 404 is ErrUnknownLog, so the adapter was telling an
 * operator whose SIGNATURE had failed to go and enrol a key that was already
 * enrolled. Both are permanent, and they are different diagnoses.
 */
test('FR-15: an unenrolled log is 404, and a permanent refusal', async () => {
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('', { status: 404 }),
  });
  await assert.rejects(
    () => w.submit('x\n1\nr\n\n— x s\n', { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /does not know this log \(HTTP 404\)/.test(e.message)
      && /retrying will not fix it/.test(e.message));
});

test('FR-15: 403 is the operator\'s own signature failing, not an enrolment problem', async () => {
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('', { status: 403 }),
  });
  await assert.rejects(
    () => w.submit('x\n1\nr\n\n— x s\n', { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /rejected the operator's signature/.test(e.message));
});

/**
 * 422 is ErrInvalidProof or ErrRootMismatch — the witness REFUSING, which is
 * the one signal this witness class exists to produce. It used to fall through
 * to a generic "returned HTTP 422".
 */
test('FR-15: 422 is the witness refusing a history, not an outage', async () => {
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('', { status: 422 }),
  });
  await assert.rejects(
    () => w.submit('x\n1\nr\n\n— x s\n', { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /REFUSED this checkpoint \(HTTP 422\)/.test(e.message)
      && /must not be read as the witness being unavailable/.test(e.message));
});

test('FR-15: 429 is the only transient refusal, and says so', async () => {
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('', { status: 429 }),
  });
  await assert.rejects(
    () => w.submit('x\n1\nr\n\n— x s\n', { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /rate-limiting/.test(e.message) && /transient/.test(e.message));
});

/** The 409 body is `<size>\n` and carries no root. */
test('FR-15: a conflict carries the size and does not invent a root', async () => {
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('42\n', { status: 409 }),
  });
  await assert.rejects(
    () => w.submit('x\n1\nr\n\n— x s\n', { old_size: 7, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogConflict && e.size === 42 && e.root === null);
});

/**
 * This test asserted that a cosignature carries no time, on the reasoning that
 * claiming `time` would make the verifier's capability statement a lie. The
 * reasoning was sound and the premise was wrong: a cosignature/v1 signature
 * covers `cosignature/v1\ntime <unix>\n<text>`, so the witness's observation
 * time is signed over the same message as the root. Running the real
 * implementation is what established it (FR-15).
 *
 * What still holds is the other half: our clock is never substituted. A line
 * carrying no timestamp yields no received_at.
 */
test('FR-15: it claims SEQUENCE and TIME, because a cosignature signs one', async () => {
  const w = tlogWitness({ id: 'w.example', url: 'http://w.example/' });
  assert.deepEqual(w.establishes, ['sequence', 'time']);
  assert.equal(w.proof_type, 'c2sp-note');
});

test('FR-15: the recorded time is the witness\'s signed one, not ours', async () => {
  // A cosignature/v1 blob: 4-byte key id, 8-byte big-endian timestamp, 64-byte
  // signature. The timestamp here is 1792224330 = 2026-10-17T08:05:30Z.
  const blob = Buffer.concat([
    Buffer.from([0x07, 0x0e, 0x98, 0x61]),
    (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(1792224330n); return b; })(),
    Buffer.alloc(64, 7),
  ]);
  const t = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response(`— w.example ${blob.toString('base64')}\n`, { status: 200 }),
  });
  const cs = await t.submit('o\n1\nr\n\n— o s\n', { old_size: 0, consistency_proof: [] });
  assert.equal(/** @type {any} */ (cs).received_at, '2026-10-17T08:05:30.000Z');
});

test('FR-15: a plain signature line yields no time, because it asserts none', async () => {
  const t = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response(
      `— w.example ${Buffer.alloc(68, 3).toString('base64')}\n`, { status: 200 }),
  });
  const cs = await t.submit('o\n1\nr\n\n— o s\n', { old_size: 0, consistency_proof: [] });
  assert.equal(/** @type {any} */ (cs).received_at, undefined,
    'our clock must never stand in for a time the witness did not assert');
});

test('FR-15: it is reachable from configuration, as a type like any other', async () => {
  const { witnessesFromConfig, WITNESS_TYPES } = await import('@splitstick/witnesses');
  assert.ok(WITNESS_TYPES.includes('tlog-witness'));
  const [a] = witnessesFromConfig({
    witnesses: [{ id: 'w.example', type: 'tlog-witness', url: 'http://w.example/' }],
  });
  assert.equal(a?.id, 'w.example');
  assert.deepEqual(a?.establishes, ['sequence', 'time']);
});

// ── Review findings: what the adapter CLAIMS about what it hands over ──────

test('FR-15: a cosignature signed under another name is refused, not relabelled', async () => {
  // It was returned as `issuer: id` regardless of who signed the line, so a
  // bad or hostile witness response travelled into the envelope labelled with
  // an identity it was not signed by. Every reader then checked it against
  // that identity's key, failed, and got a mismatch finding whose stated
  // meaning is "the operator re-signed history" — a false tampering signal
  // caused by a misbehaving witness.
  const note = 'o\n1\ncm9vdA==\n\n— o AAAA\n';
  const w = tlogWitness({
    id: 'expected.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('— someone.else SIG\n', { status: 200 }),
  });
  await assert.rejects(
    () => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /signed under the name "someone\.else"/.test(e.message)
      && /reads as the operator having rewritten history/.test(e.message));

  // The name matching IS accepted — the check is about mislabelling, not about
  // authenticating the witness, which is the reader's policy's job (FR-30).
  const ok = tlogWitness({
    id: 'expected.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('— expected.example SIG\n', { status: 200 }),
  });
  const cs = await ok.submit(note, { old_size: 0, consistency_proof: [] });
  assert.equal(cs.issuer, 'expected.example');
  assert.equal(cs.line, '— expected.example SIG');
});

test('FR-15: several cosignature lines are refused rather than one being chosen', async () => {
  // `.at(-1)` kept the last and dropped the rest in silence. Nothing makes the
  // last line authoritative, and a witness cosigning under two keys during a
  // rotation is a real case — losing one quietly is losing evidence.
  const note = 'o\n1\ncm9vdA==\n\n— o AAAA\n';
  const w = tlogWitness({
    id: 'w.example', url: 'http://127.0.0.1:1',
    fetchImpl: async () => new Response('— w.example FIRST\n— w.example SECOND\n', { status: 200 }),
  });
  await assert.rejects(
    () => w.submit(note, { old_size: 0, consistency_proof: [] }),
    (/** @type {any} */ e) => e instanceof TlogWitnessError
      && /will not choose between them/.test(e.message)
      && /FIRST/.test(e.message) && /SECOND/.test(e.message));
});
