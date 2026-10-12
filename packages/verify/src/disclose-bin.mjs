#!/usr/bin/env node
/** `npm run disclose -- <store> --record <seq>` — FR-32. */
import { runDisclose } from './disclose-cli.mjs';

const { exit, out, err } = await runDisclose(process.argv.slice(2));
if (out) process.stdout.write(out);
if (err) process.stderr.write(err);
process.exit(exit);
