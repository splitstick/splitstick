// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * FR-49 — the documented CLI contract.
 *
 * The invocations are not written here. They are READ OUT OF README.md and
 * executed verbatim, because a test holding its own copy of the commands is a
 * test of the copy: rename `--event` to `--record` in the CLI and in the test
 * and the README still says `--event`, still fails for a user, and still
 * passes here. Extracting them is what makes documentation drift a failing
 * test (inventory rows 28–30).
 *
 * So the only thing this file knows is WHERE the contract is written, and what
 * FR-49 obliges it to contain.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { generateDevSigner } from '@splitstick/core/signer-file';
import { formatVkey, parseNote, encodeNote } from '@splitstick/core/note';
import { signNote } from '@splitstick/core/signer';
import { parseEnvelope, addCountersignature } from '@splitstick/core/envelope';

const REPO = dirname(dirname(fileURLToPath(import.meta.url)));
const README = join(REPO, 'README.md');
const BIN = join(REPO, 'node_modules', '.bin');
const ORIGIN = 'splitstick.dev/host-1';

/**
 * FR-49's statement, as the obligation it is. Execution alone cannot catch a
 * flag silently DROPPED from the documentation — the remaining commands still
 * run — so what the requirement names is checked for presence separately.
 */
const REQUIRED = {
  'collect-oma': [],
  'mcp-proxy': ['--upstream', '--out'],
  verify: ['--policy'],
  coverage: ['--from', '--to'],
  disclose: ['--event', '--out'],
};

/**
 * Every fenced block under `## Getting started`, with its language tag.
 * @returns {{ lang: string, body: string }[]}
 */
function documentedBlocks() {
  const md = readFileSync(README, 'utf8');
  const start = md.indexOf('\n## Getting started\n');
  assert.notEqual(start, -1, 'README.md has no "Getting started" section — FR-49 has no contract');
  const after = md.indexOf('\n## ', start + 1);
  const section = md.slice(start, after === -1 ? md.length : after);
  const blocks = [];
  const re = /```(\w+)\n([\s\S]*?)```/g;
  for (let m = re.exec(section); m !== null; m = re.exec(section)) {
    blocks.push({ lang: String(m[1]), body: String(m[2]) });
  }
  assert.ok(blocks.length > 0, 'the section documents no invocation at all');
  return blocks;
}

/** The shell lines, in document order. Order matters: disclose builds the pack it then verifies. */
const shellLines = () => documentedBlocks()
  .filter(b => b.lang === 'bash')
  .flatMap(b => b.body.split('\n'))
  .map(l => l.trim())
  .filter(l => l !== '' && !l.startsWith('#'));

/** A store, a policy, an upstream MCP server and a key — the state the documentation assumes. */
async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'ss-contract-'));
  const signer = await generateDevSigner(ORIGIN);
  const store = new Store(join(dir, 'evidence'), 'host-1');
  let t = Date.parse('2026-10-11T10:00:00.000Z');
  const c = new Collector({
    store, config: parseConfig('version: 1\nstore: ./s\n', dir), signer,
    collector: 'host-1', origin: ORIGIN, now: () => new Date(t += 1000),
  });
  for (let i = 0; i < 4; i += 1) {
    c.action({
      tool: 'transfer_funds', args: Buffer.from(`{"amount":${i}}`),
      result: Buffer.from(`OK ref=TX-${i}`), correlation: `c-${i}`,
    });
  }
  const cp = await c.checkpoint();

  // Countersigned, because the documented disclose line REFUSES otherwise:
  // FR-33 will not hand over a pack whose only backing is the operator's own
  // arithmetic. A fixture without a witness would have made the documented
  // flow untestable, which is the same thing as not documenting it.
  const wk = await generateDevSigner('audit.internal');
  const raw = /** @type {string} */ (store.readCheckpointEnvelope(cp.checkpoint_seq));
  const text = parseNote(/** @type {string} */ (parseEnvelope(raw).note)).text;
  const line = encodeNote(text, [await signNote(text, wk)]).trim().split('\n').at(-1);
  store.writeCheckpointEnvelope(cp.checkpoint_seq, addCountersignature(JSON.parse(raw), {
    type: 'c2sp-note', issuer: 'audit.internal', covers: 'note',
    line: /** @type {string} */ (line), received_at: new Date(t).toISOString(),
  }));
  store.close();

  writeFileSync(join(dir, 'policy.json'), JSON.stringify({
    quorum: 1,
    witnesses: [{
      id: 'audit.internal',
      public_key: Buffer.from(wk.publicKey).toString('base64'),
      establishes: ['sequence'],
    }],
  }));

  // The upstream the documented proxy line names. A real MCP server: one
  // JSON-RPC request in, one response out, newline-delimited over stdio.
  writeFileSync(join(dir, 'my-mcp-server.mjs'), `
let buf = '';
process.stdin.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\\n')) !== -1) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    const req = JSON.parse(line);
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: 'OK ref=TX-9' }] },
    }) + '\\n');
  }
});
`);
  return { dir, vkey: formatVkey(ORIGIN, signer.publicKey) };
}

/**
 * Run one documented line in a shell, in the fixture directory.
 *
 * A shell, because these are shell commands: running them any other way would
 * be testing a transcription of the contract rather than the contract.
 *
 * `stdin` and `settle` exist for the one documented command that does not
 * terminate on its own. Launching a proxy and killing it would prove only that
 * it starts, so it is given a request and killed after it answers — the line
 * still runs exactly as written.
 */
function runLine(line, { dir, vkey }, { stdin = '', settle = 0 } = {}) {
  return new Promise((resolve) => {
    const p = spawn(line, {
      shell: true, cwd: dir,
      env: { ...process.env, PATH: `${BIN}:${process.env.PATH}`, SPLITSTICK_KEY: vkey },
    });
    let out = '';
    let err = '';
    let timer = null;
    p.stdout.on('data', (d) => {
      out += d;
      if (settle > 0 && timer === null) timer = setTimeout(() => p.kill('SIGTERM'), settle);
    });
    p.stderr.on('data', (d) => { err += d; });
    if (stdin) p.stdin.write(stdin);
    else p.stdin.end();
    p.on('close', (code, signal) => {
      if (timer !== null) clearTimeout(timer);
      resolve({ code, signal, out, err, line });
    });
  });
}

const isProxy = (/** @type {string} */ l) => l.includes('mcp-proxy');

test('FR-49: every documented invocation runs verbatim', async () => {
  const f = await fixture();
  const lines = shellLines();
  assert.equal(lines.length, 5, 'five documented commands, one per entry point plus pack verification');
  try {
    for (const line of lines) {
      const r = isProxy(line)
        ? await runLine(line, f, {
          stdin: `${JSON.stringify({
            jsonrpc: '2.0', id: 1, method: 'tools/call',
            params: { name: 'transfer_funds', arguments: { amount: 200000 } },
          })}\n`,
          settle: 300,
        })
        : await runLine(line, f);

      // What is asserted is that the line is a VALID INVOCATION, not that the
      // evidence it reports on is good. 0/1/2 are verdicts — a store with no
      // countersignature is honestly inconclusive and that is not a
      // documentation defect. 3 is REFUSAL across all four entry points, and
      // refusal is exactly what documentation drift produces: a flag the
      // entry point does not have, a renamed one, a missing required one.
      assert.notEqual(r.code, 127, `${line} — no such command`);
      assert.notEqual(r.code, 3, `${line} — refused as an invocation:\n${r.err}`);
      assert.ok(!/not a flag this reads|needs a value|is required/.test(`${r.err}${r.out}`),
        `a documented line is not a valid invocation:\n  ${line}\n  ${r.err.split('\n')[0]}`);
      if (isProxy(line)) {
        assert.match(r.out, /TX-9/, `${line} — the proxy did not pass the call through`);
      }
    }
    // Not just "it ran": the documented disclose line names an output file, so
    // the file the reader is told they will get has to be there.
    assert.ok(existsSync(join(f.dir, 'disclosure.json')),
      'the documented --out file was not written');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('FR-49: the documentation names every entry point and flag the requirement obliges', () => {
  // Execution cannot catch a flag quietly removed from the documentation: the
  // shorter command still runs. This is the half of the contract that has to
  // be asserted rather than exercised.
  const section = documentedBlocks().map(b => b.body).join('\n');
  for (const [entry, flags] of Object.entries(REQUIRED)) {
    const name = entry === 'collect-oma' ? 'collect-oma' : `splitstick-${entry}`;
    assert.ok(section.includes(name) || section.includes('@splitstick/collect-oma'),
      `FR-49 names ${entry} and the documentation does not invoke it`);
    for (const flag of flags) {
      assert.ok(new RegExp(`\\s${flag}(\\s|$)`, 'm').test(section),
        `FR-49 names ${entry} ${flag} and the documentation does not pass it`);
    }
  }
});

test('FR-49: a documented flag that no entry point has is caught', async () => {
  // The guard on the guard. If a misspelled flag were accepted and ignored,
  // the contract test above would pass over a manual that lies — so the
  // detection is proven against a line the documentation does not contain.
  const f = await fixture();
  try {
    const r = await runLine('splitstick-verify ./evidence --polcy ./policy.json', f);
    assert.match(r.err, /not a flag this reads/);
    assert.equal(r.code, 3);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('FR-49: the documented library snippet is the real API', async () => {
  // `collect-oma` is the one entry point that is not a command, so the way to
  // run it verbatim is to run it. It was wrong when first written — the
  // constructor takes a Collector, not a store path — which is the whole
  // argument for executing documentation rather than reviewing it.
  const js = documentedBlocks().filter(b => b.lang === 'js').map(b => b.body).join('\n');
  assert.ok(js.includes('SplitstickRunJournal'), 'no library snippet is documented');
  // Inside the repo, not the system temp dir: the snippet imports
  // `@splitstick/core` by name, and Node resolves that by walking UP from the
  // importing file. A temp dir elsewhere would fail for a reason that says
  // nothing about whether the documented API is real.
  const dir = mkdtempSync(join(REPO, '.contract-js-'));
  try {
    writeFileSync(join(dir, 'snippet.mjs'), js);
    const r = await runLine(`node ${JSON.stringify(join(dir, 'snippet.mjs'))}`,
      { dir, vkey: '' });
    assert.equal(r.code, 0, `the documented snippet does not run:\n${r.err}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
