// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * OPS-05 — a fully self-hosted deployment, with nothing leaving the perimeter.
 *
 * "No traffic leaves" is a claim about ABSENCE, and absence is the easiest
 * thing in the world to prove vacuously: a capture that sees no egress because
 * the code path never ran proves only that the test did nothing. So this is
 * three things, and the third is what makes the second mean anything:
 *
 *   static    no package that must stay offline even IMPORTS a network module
 *   dynamic   a complete lifecycle — record, checkpoint, anchor, verify,
 *             report, disclose, verify the pack — runs with every outbound
 *             primitive trapped, and the trap stays empty while the work
 *             demonstrably happens
 *   control   a deliberate egress through each trapped primitive IS caught,
 *             so an empty trap is evidence and not an artefact of a trap that
 *             does not work
 *
 * The environment is emptied too: OPS-05 is "no account, no enrolment with us",
 * and a deployment that silently depends on a credential in the environment has
 * an enrolment whatever the documentation says.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import dgram from 'node:dgram';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote } from '@splitstick/core/note';
import { Anchorer } from '@splitstick/core/anchor';
import { StatefulWitness } from '@splitstick/witness-self';
import { verifyStore } from '@splitstick/verify';
import { runCoverage } from '@splitstick/verify/coverage-cli';
import { runDisclose } from '@splitstick/verify/disclose-cli';

const REPO = join(fileURLToPath(import.meta.url), '..', '..');
const ORIGIN = 'splitstick.dev/host-1';

/** The packages that must work with no network at all. mcp-proxy is excluded: an
 *  HTTP transport that could not open a socket would not be a transport. */
const OFFLINE = ['core', 'verify', 'witness-self', 'collect-oma', 'witnesses'];

/** @param {string} dir @returns {string[]} */
function sources(dir) {
  /** @type {string[]} */
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (name.endsWith('.mjs')) out.push(p);
  }
  return out;
}

/** Network modules, however they are spelled. */
const NET = 'net|http|https|dns|tls|dgram|http2|inspector|quic';

/**
 * The static rules, each with the message it fails under.
 *
 * Written out rather than crammed into one alternation because the first
 * version was one regex and it MISSED `await import('node:net')` — in a
 * repository where `await import('node:crypto')` is an established idiom in
 * these very packages, so a dynamic network import would have read as
 * ordinary style and passed. It also missed `globalThis.fetch(...)`. A guard
 * on the highest-risk requirement in the milestone that quietly covered two
 * of the four ways to reach the network is the kind of check that makes a
 * build green and stops anybody looking.
 *
 * Each rule is exercised against text that breaks it, below.
 */
const RULES = [
  {
    re: new RegExp(`from\\s+['"]node:(${NET})['"]`),
    why: 'statically imports a network module',
  },
  {
    re: new RegExp(`require\\(\\s*['"]node:(${NET})['"]\\s*\\)`),
    why: 'requires a network module',
  },
  {
    re: new RegExp(`import\\(\\s*['"]node:(${NET})['"]\\s*\\)`),
    why: 'dynamically imports a network module',
  },
  {
    // The CALL, not the name. Requiring the open paren matters: the first
    // version matched `@param {{ fetchImpl?: typeof globalThis.fetch }}` — a
    // JSDoc type annotation in the package that passes a fetch implementation
    // through to the adapters and never calls one itself. A guard that fires
    // on a type reference gets switched off, and then it guards nothing.
    re: /(^|[^.\w])fetch\s*\(|\b(?:globalThis|global|window|self)\s*\.\s*fetch\s*\(/,
    why: 'calls fetch',
  },
  {
    // The evasion the three rules above cannot see. A non-literal specifier
    // makes the static layer decorative, so it is refused outright: every
    // dynamic import in these packages names its module directly, and one
    // that does not is either an evasion or a pattern that needs a different
    // guard.
    re: /import\(\s*(?!['"])/,
    why: 'dynamically imports a module named by an expression, which no static check can read',
  },
];

test('OPS-05: nothing that must stay offline can reach the network', () => {
  // The static half. A trap can be bypassed by a primitive nobody thought to
  // patch; an import that is not there cannot be called by any route.
  for (const pkg of OFFLINE) {
    for (const f of sources(join(REPO, 'packages', pkg, 'src'))) {
      const src = readFileSync(f, 'utf8');
      for (const rule of RULES) {
        assert.ok(!rule.re.test(src),
          `${f.slice(REPO.length + 1)} ${rule.why}, and ${pkg} must not reach the network`);
      }
    }
  }
});

test('OPS-05: each static rule catches what it is for', () => {
  // A rule that cannot fire is worse than no rule. Every way in is checked
  // against the rule meant to stop it, and against text that must NOT fire —
  // a guard that flags `node:crypto` would be switched off within a week.
  const caught = (/** @type {string} */ src) => RULES.some(r => r.re.test(src));
  for (const src of [
    "import net from 'node:net';",
    'import https from "node:https";',
    "const { connect } = require('node:net');",
    "const net = await import('node:net');",
    'await import("node:dns");',
    'await fetch(url);',
    'globalThis.fetch(url);',
    'const r = await self.fetch(u);',
    'const m = pick(); await import(m);',
  ]) {
    assert.ok(caught(src), `not caught: ${src}`);
  }
  for (const src of [
    "const { createHash } = await import('node:crypto');",
    "import { readFileSync } from 'node:fs';",
    '// the fetchImpl is injected so the suite never depends on a network',
    'const prefetch = (x) => x;',
    'obj.fetch(url);',
    '@param {{ fetchImpl?: typeof globalThis.fetch }} [opts]',
  ]) {
    assert.ok(!caught(src), `wrongly caught: ${src}`);
  }
});

/**
 * Trap every outbound primitive. Returns the list attempts land in, and a
 * restore function.
 */
function trapEgress() {
  /** @type {string[]} */
  const attempts = [];
  /** @type {(() => void)[]} */
  const restore = [];
  /** @param {any} obj @param {string} key */
  const trap = (obj, key, label) => {
    const original = obj[key];
    if (typeof original !== 'function') return;
    restore.push(() => { obj[key] = original; });
    obj[key] = (/** @type {any[]} */ ...args) => {
      // EVERY argument, not the first: `net.connect(443, 'host')` puts the
      // port first, so recording args[0] alone would log a capture that
      // cannot say what was reached.
      const where = args.map(a => (typeof a === 'function' ? 'fn' : JSON.stringify(a) ?? '?')).join(', ');
      attempts.push(`${label}(${where})`);
      throw new Error(`EGRESS: ${label} was called`);
    };
  };
  trap(globalThis, 'fetch', 'fetch');
  for (const k of ['connect', 'createConnection']) trap(net, k, `net.${k}`);
  trap(tls, 'connect', 'tls.connect');
  for (const k of ['request', 'get']) trap(http, k, `http.${k}`);
  for (const k of ['request', 'get']) trap(https, k, `https.${k}`);
  for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6']) trap(dns, k, `dns.${k}`);
  for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6']) trap(dns.promises, k, `dns.promises.${k}`);
  trap(dgram, 'createSocket', 'dgram.createSocket');
  return { attempts, restore: () => { for (const r of restore) r(); } };
}

test('OPS-05: a full self-hosted lifecycle runs with no egress and no environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ss-egress-'));
  const wdir = mkdtempSync(join(tmpdir(), 'ss-egress-w-'));
  const { attempts, restore } = trapEgress();
  const savedEnv = { ...process.env };
  for (const k of Object.keys(process.env)) delete process.env[k];

  /** What the deployment actually produced. An empty trap beside an empty
   *  list of these would be a test of nothing. */
  let did = {
    records: 0, anchored: 0, verdict: '', failed: -1, witness: '',
    coverage: -1, pack: '', packVerdict: -1,
  };
  try {
    const signer = await generateDevSigner(ORIGIN);
    const wkey = await generateDevSigner('audit.internal');
    const store = new Store(join(dir, 'evidence'), 'host-1');
    let t = Date.parse('2026-10-11T10:00:00.000Z');
    const c = new Collector({
      store, config: parseConfig('version: 1\nstore: ./s\n', dir), signer,
      collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
    });

    // The witness is the operator's own, on their own disk, under their own
    // key — OPS-03's deployment, which is what makes zero egress possible at
    // all rather than merely configured.
    const witness = new StatefulWitness({ dir: wdir, signer: wkey });
    witness.enrol(ORIGIN, signer.publicKey);
    const adapter = {
      id: 'audit.internal', proof_type: /** @type {const} */ ('c2sp-note'),
      establishes: ['sequence'], tier: /** @type {const} */ ('anchor'),
      async submit(/** @type {string} */ note, /** @type {any} */ ctx) {
        const res = await witness.addCheckpoint({
          note, old_size: ctx.old_size, consistency_proof: ctx.consistency_proof,
        });
        return {
          type: /** @type {const} */ ('c2sp-note'), issuer: 'audit.internal',
          covers: /** @type {const} */ ('note'),
          line: /** @type {string} */ (res.note.trimEnd().split('\n').at(-1)),
        };
      },
    };
    const anchorer = new Anchorer({
      store, witnesses: [adapter], quorum: 1,
      acceptance: { 'audit.internal': wkey.publicKey },
    });

    c.heartbeat();
    for (let i = 1; i <= 6; i += 1) {
      c.action({
        run: 'r-1', tool: 'transfer_funds', consequential: true,
        args: Buffer.from(`{"amount":${i}00}`), result: Buffer.from(`OK c-${i}`),
        outcome: 'ok', attempt: 1, correlation: `c-${i}`,
      });
      did.records += 1;
    }
    const cp = await c.checkpoint();
    const r = await anchorer.anchor(cp.checkpoint_seq);
    did.anchored = r.attached.length;
    store.close();

    const vkey = formatVkey(ORIGIN, signer.publicKey);
    const policy = {
      quorum: 1,
      witnesses: [{
        id: 'audit.internal',
        public_key: Buffer.from(wkey.publicKey).toString('base64'),
        establishes: ['sequence'],
      }],
    };
    const report = await verifyStore(join(dir, 'evidence'),
      { collector: 'host-1', vkey, policy });
    did.verdict = report.verdict;
    did.failed = report.summary.failed;
    did.witness = report.witnesses.map((/** @type {any} */ w) => `${w.id}:${w.verdict}`).join(',');

    const { readFileSync: rf, writeFileSync: wf } = await import('node:fs');
    wf(join(dir, 'policy.json'), JSON.stringify(policy));
    did.coverage = (await runCoverage([join(dir, 'evidence'),
      '--from', '2026-10-01', '--to', '2026-10-31', '--collector', 'host-1',
      '--policy', join(dir, 'policy.json')])).exit;

    const built = await runDisclose([join(dir, 'evidence'), '--event', '3',
      '--collector', 'host-1', '--out', join(dir, 'pack.json')]);
    did.pack = built.exit === 0 ? rf(join(dir, 'pack.json'), 'utf8') : '';
    did.packVerdict = (await runDisclose(['--verify', join(dir, 'pack.json'),
      '--key', vkey, '--policy', join(dir, 'policy.json')])).exit;
  } finally {
    restore();
    Object.assign(process.env, savedEnv);
    rmSync(dir, { recursive: true, force: true });
    rmSync(wdir, { recursive: true, force: true });
  }

  // Nothing left.
  assert.deepEqual(attempts, [], `the deployment attempted egress: ${attempts.join(', ')}`);

  // And the deployment is not empty, so the empty trap above is about a system
  // that ran rather than one that never started.
  assert.equal(did.records, 6);
  assert.equal(did.anchored, 1, 'the checkpoint was countersigned by the operator\'s own witness');
  assert.equal(did.failed, 0, 'nothing failed');
  assert.equal(did.witness, 'audit.internal:ok',
    'and the operator\'s own witness countersignature VERIFIES against the reader\'s policy');
  // `inconclusive`, not `ok`, and that is the honest answer rather than a
  // shortfall: one witness establishing `sequence` says nothing about WHEN,
  // so the time checks stay unanswered. A deployment inside one perimeter
  // buys independence of sequence, not of clock — which is exactly what
  // OPS-03 has to tell an operator.
  assert.equal(did.verdict, 'inconclusive');
  assert.ok([0, 1, 2].includes(did.coverage), 'coverage produced a verdict');
  assert.ok(did.pack.includes('"proof"') && did.pack.includes('"manifest"'),
    `a disclosure pack was built: ${did.pack.slice(0, 200)}`);
  assert.equal(did.packVerdict, 0, 'and verifies, offline, against nothing but the files');
});

test('OPS-05: the capture catches egress, so an empty capture is evidence', async () => {
  // The control. Without this, "no attempts were recorded" is equally
  // consistent with a trap that does not trap.
  const { attempts, restore } = trapEgress();
  try {
    for (const attempt of [
      () => globalThis.fetch('https://calendar.example/anchor'),
      () => net.connect(443, 'calendar.example'),
      () => tls.connect(443, 'calendar.example'),
      () => http.request('http://calendar.example/'),
      () => https.request('https://calendar.example/'),
      () => dns.lookup('calendar.example', () => {}),
      () => dgram.createSocket('udp4'),
    ]) {
      assert.throws(attempt, /EGRESS/, 'a primitive escaped the capture');
    }
  } finally {
    restore();
  }
  assert.equal(attempts.length, 7, `only ${attempts.length} of 7 primitives were seen`);
  assert.ok(attempts.every(a => /calendar\.example|udp4/.test(a)),
    `the capture recorded WHAT was reached, not merely that something was: ${attempts.join(', ')}`);
});

test('OPS-05: the shipped default configuration names no witness at all', () => {
  // The highest-risk row in M6's inventory. A default that anchors to a public
  // calendar is a default that violates OPS-05 for everybody who did not read
  // the documentation — and "did not read the documentation" is the condition
  // a default exists to serve.
  const cfg = parseConfig('version: 1\nstore: ./s\n', '/tmp');
  assert.deepEqual(cfg.witnesses, [],
    'the default witness set must be empty: anchoring is a choice an operator makes');
});
