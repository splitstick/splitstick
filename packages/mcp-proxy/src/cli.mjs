// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * `splitstick mcp-proxy` — FR-03, FR-04, FR-49.
 *
 * Two modes, one per transport:
 *
 *   --upstream <cmd> [args…]   stdio: spawn the server and sit between it and
 *                              this process's stdin/stdout
 *   --upstream <url>           HTTP: listen and forward to the URL
 *
 * `--out` is the store. Nothing else is required, and nothing reaches a
 * network that the operator did not name — OPS-05.
 *
 * Unknown flags are REFUSED rather than ignored, which is the third time this
 * project has written that sentence and the first time it was free.
 */

import { spawn } from 'node:child_process';
import { Store } from '@splitstick/core/store';
import { Collector } from '@splitstick/core/collector';
import { parseConfig } from '@splitstick/core/config';
import { stdioProxy } from './stdio.mjs';
import { httpProxy } from './http.mjs';

const USAGE = `splitstick-mcp-proxy --upstream <command|url> --out <store> [--collector <name>]
                       [--config <file>] [--run <id>] [--listen <port>]

  --upstream   an MCP server to sit in front of. A command runs it over stdio;
               an http(s) URL proxies to it over HTTP.
  --out        the evidence store to write into.
  --collector  the collector instance identity that scopes the chain (FR-56).
  --config     splitstick.yaml, for intervals, witnesses and padding.
  --run        a run identifier to record against, when the deployment has one.
  --listen     the port to listen on in HTTP mode. 0 picks one.
`;

/**
 * Parse the arguments. Separated from running so the contract can be tested
 * without spawning anything.
 * ONE FLAT SHAPE, not a discriminated union. JSDoc does not preserve a
 * boolean-literal discriminant, so `{ok: true, ...} | {ok: false, ...}` does
 * not narrow and every field reads as possibly-absent. This project has now
 * learned that three times — in trustpath.mjs, in validateKeyHistory, and
 * here — so the shape is flat and `err` being non-empty is the signal.
 *
 * @param {string[]} argv
 * @returns {{ err: string, exit: number, flags: Record<string, string>, rest: string[] }}
 */
export function parseArgs(argv) {
  const FLAGS = new Set(['upstream', 'out', 'collector', 'config', 'run', 'listen']);
  /** @type {Record<string, string>} */
  const flags = {};
  /** @type {string[]} */
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = String(argv[i]);
    if (a === '--help' || a === '-h') return { err: USAGE, exit: 0, flags: {}, rest: [] };
    if (a === '--') { rest.push(...argv.slice(i + 1).map(String)); break; }
    if (!a.startsWith('--')) { rest.push(a); continue; }
    const name = a.slice(2);
    if (!FLAGS.has(name)) {
      return {
        exit: 2, flags: {}, rest: [],
        err: `${a} is not a flag this reads. Refused rather than ignored: a misspelled flag that `
          + `silently proxied somewhere else would be read as proxying here.\n\n${USAGE}`,
      };
    }
    const v = argv[i + 1];
    if (v === undefined || String(v).startsWith('--')) {
      return { exit: 2, flags: {}, rest: [], err: `${a} needs a value\n\n${USAGE}` };
    }
    if (flags[name] !== undefined) {
      // Given twice. Taking the last silently is the same defect as accepting
      // a flag nobody reads: the operator stated two evidence stores, or two
      // upstreams, and one of them was discarded without a word. `--out /a
      // --out /b` wrote to /b while the operator had every reason to look in
      // /a for the record.
      return {
        exit: 2, flags: {}, rest: [],
        err: `${a} was given twice, as ${JSON.stringify(flags[name])} and ${JSON.stringify(String(v))}. `
          + 'Refused rather than taking the last: a value silently discarded here is an evidence '
          + `store, or a server, that somebody is expecting.\n\n${USAGE}`,
      };
    }
    flags[name] = String(v);
    i += 1;
  }
  for (const required of ['upstream', 'out']) {
    if (flags[required] === undefined) {
      return { exit: 2, flags: {}, rest: [], err: `--${required} is required\n\n${USAGE}` };
    }
  }

  // A flag the chosen mode does not read is refused, not ignored. `--listen`
  // with a command upstream used to be accepted and dropped, so an operator
  // who believed they were serving HTTP on a port had nothing listening on it
  // and no indication why. This project has shipped that shape three times
  // already — `--vkey`, `padding`, `retention` — and each time the cost was
  // the tool answering a question nobody asked.
  const http = isUrl(/** @type {string} */ (flags.upstream));
  if (!http && flags.listen !== undefined) {
    return {
      exit: 2, flags: {}, rest: [],
      err: `--listen only applies when --upstream is an http(s) URL. ${JSON.stringify(flags.upstream)} `
        + 'is a command, which is proxied over stdio and listens on no port. Refused rather than '
        + `ignored: nothing would have been listening on it.\n\n${USAGE}`,
    };
  }
  if (http && rest.length > 0) {
    return {
      exit: 2, flags: {}, rest: [],
      err: `${JSON.stringify(rest.join(' '))} was given as extra arguments, and an http(s) upstream `
        + 'takes none — they are the arguments of a command, and this upstream is a URL. Refused '
        + `rather than dropped.\n\n${USAGE}`,
    };
  }
  return { err: '', exit: 0, flags, rest };
}

/**
 * Whether an upstream is a URL (HTTP mode) or a command (stdio mode).
 *
 * Case-insensitive: a scheme is case-insensitive in the URL grammar, and
 * `HTTP://x` taken for a command produces an ENOENT about a program nobody
 * meant to run.
 */
export const isUrl = (/** @type {string} */ u) => /^https?:\/\//i.test(u);

/**
 * Split an upstream command into a program and its arguments.
 *
 * `--upstream` is documented as taking a command, and a command with no
 * arguments is the rare case — `node ./server.mjs`, `uvx some-mcp-server`,
 * `docker run ...`. It used to be handed to spawn() whole as the program
 * NAME, so every documented form failed with ENOENT.
 *
 * Quotes are honoured because a path with a space in it is not an exotic
 * case, and an UNTERMINATED quote is refused rather than closed for the
 * caller: guessing where the operator meant the argument to end is guessing
 * what process to run.
 *
 * @param {string} s
 * @returns {{ argv: string[], err: string }}
 */
export function tokenizeCommand(s) {
  /** @type {string[]} */
  const argv = [];
  let cur = '';
  let quote = '';
  let started = false;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s.charAt(i);
    if (quote === '' && (ch === ' ' || ch === '\t')) {
      if (started) { argv.push(cur); cur = ''; started = false; }
    } else if (ch === '\\' && quote !== "'" && i + 1 < s.length) {
      i += 1; cur += s.charAt(i); started = true;
    } else if (quote === '' && (ch === "'" || ch === '"')) {
      quote = ch; started = true;
    } else if (quote !== '' && ch === quote) {
      quote = '';
    } else {
      cur += ch; started = true;
    }
  }
  if (quote !== '') {
    return { argv: [], err: `--upstream has an unterminated ${quote} quote: ${s}\n` };
  }
  if (started) argv.push(cur);
  if (argv.length === 0) return { argv: [], err: '--upstream is empty\n' };
  return { argv, err: '' };
}

/**
 * @param {string[]} argv
 * @param {{ signer: any, stdin?: any, stdout?: any }} o
 */
export async function runProxy(argv, o) {
  const parsed = parseArgs(argv);
  if (parsed.err !== '') {
    // `--help` is an answer to a question, not a complaint about one. The flat
    // shape carries both in `err`, so the exit code is what separates them:
    // asking for help and getting it on stderr means `--help > help.txt`
    // writes an empty file.
    return parsed.exit === 0
      ? { exit: 0, out: parsed.err, err: '' }
      : { exit: parsed.exit, err: parsed.err, out: '' };
  }
  const { rest } = parsed;
  // parseArgs has already refused a missing --upstream or --out, so these are
  // strings by the time execution reaches here; the cast says so once rather
  // than at every use.
  const flags = /** @type {Record<string, string> & { upstream: string, out: string }} */
    (parsed.flags);

  const collectorName = flags.collector ?? 'mcp-proxy';
  const store = new Store(flags.out, collectorName);
  const config = parseConfig(
    flags.config === undefined
      ? 'version: 1\nstore: ./s\n'
      : (await import('node:fs')).readFileSync(flags.config, 'utf8'),
    flags.out,
  );
  const collector = new Collector({
    store, config, signer: o.signer, collector: collectorName, origin: o.signer.name,
  });
  const newCorrelation = () => Collector.newCorrelation();
  const onUnrecordable = (/** @type {{detail: string}} */ e) => {
    // Out of band — stderr, never the data path, and never into the log whose
    // integrity is the thing in question.
    process.stderr.write(`splitstick: ${e.detail}\n`);
  };

  if (isUrl(flags.upstream)) {
    const proxy = httpProxy({
      upstream: flags.upstream, collector, newCorrelation, onUnrecordable,
      ...(flags.run ? { run: flags.run } : {}),
    });
    const addr = /** @type {any} */ (await proxy.listen(Number(flags.listen ?? 0)));
    return {
      exit: 0, err: '', out: `listening on http://127.0.0.1:${addr.port} → ${flags.upstream}\n`,
      proxy, store,
    };
  }

  const { argv: upstreamArgv, err: tokenErr } = tokenizeCommand(flags.upstream);
  if (tokenErr !== '') {
    store.close();
    return { exit: 2, err: tokenErr, out: '' };
  }
  const [program, ...programArgs] = upstreamArgv;
  const child = spawn(/** @type {string} */ (program), [...programArgs, ...rest],
    { stdio: ['pipe', 'pipe', 'inherit'] });
  const proxy = stdioProxy({
    agentIn: o.stdin ?? process.stdin,
    agentOut: o.stdout ?? process.stdout,
    upstreamIn: child.stdin,
    upstreamOut: child.stdout,
    collector, newCorrelation, onUnrecordable,
    ...(flags.run ? { run: flags.run } : {}),
  });
  // An upstream that cannot be started is not a background warning. Node's
  // default for an unhandled 'error' event is to throw a raw stack trace out
  // of the event loop, which left the process exiting 0: a recorder that
  // never recorded anything, reporting success.
  child.on('error', (e) => {
    process.stderr.write(`splitstick: cannot start the upstream \`${flags.upstream}\`: ${e.message}\n`);
    proxy.close();
    store.close();
    process.exitCode = 4;
  });
  // The child's exit is the proxy's: a collector that outlived the thing it
  // was recording would keep a store open for nothing.
  child.on('exit', () => { proxy.close(); store.close(); });
  return { exit: 0, err: '', out: '', proxy, store, child };
}
