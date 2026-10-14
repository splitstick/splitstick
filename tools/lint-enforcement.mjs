// Copyright 2026 prathish-ks
// SPDX-License-Identifier: Apache-2.0

/**
 * No enforcement path exists — SCOPE-01 and SCOPE-16.
 *
 * Their verifies are not claims audits. SCOPE-01 says "code review; no
 * enforcement path exists" and SCOPE-16 says "config schema review; no
 * enforcement path exists; rejected as a feature request by policy". The prose
 * guard in scope-guards.mjs catches a marketing offer of blocking; this
 * catches the capability.
 *
 * WHY THIS IS NOT A VOCABULARY CHECK. The obvious design — forbid `block`,
 * `deny`, `veto` in the capture path — was calibrated against the real source
 * and would have been almost entirely false positives: `block` is a Bitcoin
 * block in the OpenTimestamps adapter, `denied` is an approval OUTCOME in the
 * record schema, `allowlist` is the schema's field list, `reject` is a Promise.
 * Recording that a human denied an action is the product; deciding to deny one
 * is forbidden, and no word distinguishes them. A guard built on that word list
 * would have fired nine times on correct code and been switched off, which is
 * the row-2 failure this milestone is most at risk of.
 *
 * So three things that are actually structural:
 *
 *   1. the config admits exactly ONE `on_unavailable` value, and it is not an
 *      enforcement value. SCOPE-16 names config schema review.
 *   2. no config key is an enforcement switch.
 *   3. THE ORDERING, ON BOTH LEGS. In both transports the traffic is forwarded
 *      before anything on the recording side runs, so there is no point at
 *      which a recording outcome could gate it. The HTTP transport is checked
 *      twice — outbound and inbound — because the first version of this guard
 *      checked only the response, and a change that recorded before calling
 *      the upstream would have passed it while putting a recording outcome
 *      between the agent and its tool on the way in. That is a property of the source and
 *      it is checked in the source, because it is the one an edit would break
 *      silently — a reordering that put `observe` first would pass every test
 *      that only asserts traffic eventually arrives.
 *
 * The behavioural half — that traffic flows when the collector is degraded,
 * when recording throws, and when no witness is configured — lives in
 * test/enforcement.test.mjs, because that is a question about running code.
 */

import { readFileSync } from 'node:fs';
import { code } from './code-text.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const read = (/** @type {string} */ rel) => readFileSync(`${ROOT}${rel}`, 'utf8');

/** @type {string[]} */
const findings = [];

// ── 1. the config admits exactly one on_unavailable value ─────────────────
const config = code(read('packages/core/src/config.mjs'));
const values = /ON_UNAVAILABLE_VALUES\s*=\s*Object\.freeze\(\[([^\]]*)\]/.exec(config);
if (values === null) {
  findings.push('packages/core/src/config.mjs no longer declares ON_UNAVAILABLE_VALUES as a '
    + 'frozen list, so the single-value guarantee SCOPE-16 rests on cannot be read');
} else {
  const admitted = String(values[1]).split(',').map(v => v.trim().replace(/^['"]|['"]$/g, ''))
    .filter(v => v !== '');
  if (admitted.length !== 1 || admitted[0] !== 'mark_gap') {
    findings.push(`on_unavailable admits ${JSON.stringify(admitted)}. SCOPE-16: fail-open is a `
      + 'design constraint and not a setting, so there is exactly one value and it is mark_gap. '
      + 'A second value is the enforcement path, whatever it is called');
  }
}

// ── 2. no config key is an enforcement switch ─────────────────────────────
const known = /KNOWN\s*=\s*new Set\(\[([\s\S]*?)\]\)/.exec(config);
if (known === null) {
  // A guard that cannot find what it checks must SAY SO rather than pass. The
  // first version of this looked for `Object.freeze([…])` while the source
  // declares `new Set([…])`, so it found nothing, checked nothing, and
  // reported success — the exact shape M7 exists to catch, in M7's own tool.
  findings.push('packages/core/src/config.mjs: the known-key list could not be located, so the '
    + 'enforcement-key check ran against nothing. Update this guard deliberately rather than '
    + 'leaving it silently inert');
} else {
  const keys = String(known[1]).split(',').map(k => k.trim().replace(/^['"]|['"]$/g, ''))
    .filter(k => k !== '');
  const ENFORCEMENT_KEY = /^(?:block|deny|enforce|gate|halt|veto|fail_closed|blocking|enforcement)/i;
  for (const k of keys.filter(k => ENFORCEMENT_KEY.test(k))) {
    findings.push(`the config accepts a key named ${JSON.stringify(k)}, which reads as an `
      + 'enforcement switch. SCOPE-16 rejects one as a feature request by policy');
  }
}

// ── 3. the ordering: forward first, record after ──────────────────────────
/**
 * Each entry names a function, the call that forwards the traffic, and the
 * call that begins recording. The forward must come first IN THE SOURCE.
 *
 * A test that only checks the traffic arrives would pass either ordering, so
 * this is the half a reordering would break silently.
 */
const ORDERINGS = [
  {
    file: 'packages/mcp-proxy/src/stdio.mjs',
    within: /const deliver = [\s\S]*?\n {4}\};/,
    forward: /to\.write\(/,
    record: /observe\(/,
    why: 'the stdio proxy must write the message onward before it parses a copy for recording',
  },
  {
    file: 'packages/mcp-proxy/src/http.mjs',
    within: /res\.writeHead\(upstreamRes\.status[\s\S]*?pairing\.response\(/,
    forward: /res\.end\(out\)/,
    record: /pairing\.request\(body\)/,
    why: 'the HTTP proxy must return the upstream\'s answer before it records anything',
  },
  {
    // THE REQUEST PATH, which the review found unguarded. The entry above
    // covers only the RESPONSE: that the agent gets its answer before anything
    // is recorded. It says nothing about the outbound leg, so a change that
    // moved recording ahead of the upstream call would put a recording outcome
    // between the agent and its tool on the way IN — an availability
    // dependency of exactly the kind SCOPE-01 forbids — and would have passed
    // this lint.
    //
    // The region deliberately ENDS at the first recording call, so the check
    // is simply that the forward is inside it. If recording moved earlier the
    // region shortens, `fetchImpl` falls outside, and the missing-forward
    // branch reports it.
    file: 'packages/mcp-proxy/src/http.mjs',
    within: /async function handle\([\s\S]*?pairing\.request\(body\)/,
    forward: /await fetchImpl\(target/,
    record: /pairing\.request\(body\)/,
    why: 'the HTTP proxy must send the request upstream before it records anything about it',
  },
];

for (const o of ORDERINGS) {
  const src = code(read(o.file));
  const region = o.within.exec(src);
  if (region === null) {
    findings.push(`${o.file}: the forwarding region could not be located, so the ordering `
      + 'SCOPE-01 depends on is no longer checkable. If the shape changed, update this guard '
      + 'deliberately rather than deleting it');
    continue;
  }
  const text = region[0];
  const f = text.search(o.forward);
  const r = text.search(o.record);
  if (f === -1) {
    findings.push(`${o.file}: the forwarding call is gone from the region. ${o.why}`);
  } else if (r !== -1 && r < f) {
    findings.push(`${o.file}: recording now runs BEFORE forwarding. ${o.why} — otherwise a `
      + 'recording outcome sits between the agent and its tool, which is the enforcement path '
      + 'SCOPE-01 forbids');
  }
}

if (findings.length > 0) {
  console.error('\nENFORCEMENT LINT FAILED — SCOPE-01, SCOPE-16\n');
  for (const f of findings) console.error(`  - ${f}\n`);
  console.error(`  ${findings.length} finding(s).\n`);
  process.exit(1);
}

console.log('\n  enforcement: one on_unavailable value, no enforcement key, and both transports');
console.log('               forward before they record (SCOPE-01, SCOPE-16)\n');
