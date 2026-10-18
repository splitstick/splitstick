#!/usr/bin/env node
// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/** `npm run disclose -- <store> --event <seq>` — FR-32. */
import { runDisclose } from './disclose-cli.mjs';

const { exit, out, err } = await runDisclose(process.argv.slice(2));
if (out) process.stdout.write(out);
if (err) process.stderr.write(err);
process.exit(exit);
