#!/usr/bin/env node
/** `npm run mcp-proxy -- --upstream <command|url> --out <store>` — FR-03, FR-04. */
import { generateDevSigner } from '@splitstick/core/signer-file';
import { runProxy } from './cli.mjs';

const signer = await generateDevSigner('splitstick.local/mcp-proxy');
const r = await runProxy(process.argv.slice(2), { signer });
if (r.out) process.stdout.write(r.out);
if (r.err) process.stderr.write(r.err);
if (r.exit !== 0) process.exit(r.exit);
