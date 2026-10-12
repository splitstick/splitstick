#!/usr/bin/env node
/** `npm run coverage -- <store> --from <date> --to <date>` — FR-28. */
import { runCoverage } from './coverage-cli.mjs';

const { exit, out } = runCoverage(process.argv.slice(2));
process.stdout.write(out);
process.exit(exit);
