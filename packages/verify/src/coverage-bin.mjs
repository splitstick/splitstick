#!/usr/bin/env node
// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/** `npm run coverage -- <store> --from <date> --to <date>` — FR-28. */
import { runCoverage } from './coverage-cli.mjs';

const { exit, out, err } = await runCoverage(process.argv.slice(2));
// The report goes to stdout and a REFUSAL goes to stderr. They used to share
// stdout, so `splitstick-coverage ... > report.txt` on a typo wrote the usage
// text into report.txt and printed nothing to the terminal.
if (out) process.stdout.write(out);
if (err) process.stderr.write(err);
process.exit(exit);
