#!/usr/bin/env node
// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/** `npm run mcp-proxy -- --upstream <command|url> --out <store>` — FR-03, FR-04. */
import { generateDevSigner } from '@splitstick/core/signer-file';
import { runProxy } from './cli.mjs';

const signer = await generateDevSigner('splitstick.local/mcp-proxy');
const r = await runProxy(process.argv.slice(2), { signer });
if (r.out) process.stdout.write(r.out);
if (r.err) process.stderr.write(r.err);
if (r.exit !== 0) process.exit(r.exit);

/**
 * Settle on the way out.
 *
 * A proxy told to stop still holds whatever calls were outstanding, and those
 * are observed invocations. Exiting without settling them loses exactly the
 * records this collector exists to write — so `close()` runs first, which
 * turns each one into an attempt with no result, and only then does the
 * process go.
 *
 * SIGKILL cannot be caught and the loss there is bounded by the settle
 * interval instead. See the note in settle.mjs.
 */
if (r.proxy !== undefined) {
  let closing = false;
  for (const sig of /** @type {const} */ (['SIGINT', 'SIGTERM', 'SIGHUP'])) {
    process.on(sig, () => {
      // Once. A second signal during the flush must not re-enter it and
      // double-record, and a user pressing ctrl-c twice is the ordinary case.
      if (closing) { process.exit(130); }
      closing = true;
      Promise.resolve(/** @type {any} */ (r.proxy).close())
        .catch(() => {})
        .finally(() => {
          /** @type {any} */ (r.store)?.close?.();
          process.exit(sig === 'SIGINT' ? 130 : 143);
        });
    });
  }
}
