// Copyright 2026 prathish-ks
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Six tampers against a genuine OMA run journal, each checked with OMA's own
 * `verifyRun()`.
 *
 * Every attack declares the outcome we currently observe. The process exits
 * non-zero when an observation changes, which makes this file a regression
 * canary in both directions: it fails if upstream closes a gap (good news,
 * worth knowing immediately) and it fails if something that used to be caught
 * stops being caught.
 */
import { verifyRun, canonicalContentHash } from '@open-multi-agent/core';
import fs from 'node:fs';
import { JOURNAL_PATH } from './generate.mjs';

if (!fs.existsSync(JOURNAL_PATH)) {
  console.error(`No fixture at ${JOURNAL_PATH}. Run: npm run generate`);
  process.exit(1);
}

const baseline = fs.readFileSync(JOURNAL_PATH, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const clone = () => JSON.parse(JSON.stringify(baseline));
const at = (events, seq) => events.find((e) => e.seq === seq);
const FORGED = 'OK: transferred EUR 25 to ACME-9931. ref=TX-77814';

/** Renumber a journal into a contiguous stream, remapping every reference. */
function renumber(events) {
  const map = new Map();
  events.forEach((e, i) => map.set(e.seq, i + 1));
  const remap = (seqs) => seqs.map((s) => map.get(s)).filter((s) => s !== undefined);
  for (const e of events) {
    if (Array.isArray(e.sourceEventSeqs)) e.sourceEventSeqs = remap(e.sourceEventSeqs);
    if (Array.isArray(e.blocks)) {
      for (const b of e.blocks) {
        if (Array.isArray(b.sourceEventSeqs)) b.sourceEventSeqs = remap(b.sourceEventSeqs);
      }
    }
    e.seq = map.get(e.seq);
  }
  return events;
}

const attacks = [
  {
    id: 'A',
    name: 'edit tool/result only',
    expect: 'undetected',
    note: 'EUR 2,000,000 -> EUR 25 in the authoritative side-effect record. No contentHash covers this event.',
    build() {
      const events = clone();
      const e = at(events, 7);
      e.result.content = FORGED;
      e.record.output = FORGED;
      e.record.input.amount = 25;
      return events;
    },
  },
  {
    id: 'B',
    name: 'naive edit of model-visible block',
    expect: 'detected',
    note: 'The citing llm/request still names the original bytes, so the journal contradicts itself.',
    build() {
      const events = clone();
      at(events, 8).message.content[0].content = FORGED;
      return events;
    },
  },
  {
    id: 'C',
    name: 'consistent edit + recomputed hash',
    expect: 'undetected',
    note: "One extra line, using OMA's own exported canonicalContentHash().",
    build() {
      const events = clone();
      at(events, 7).result.content = FORGED;
      at(events, 7).record.output = FORGED;
      at(events, 7).record.input.amount = 25;
      at(events, 8).message.content[0].content = FORGED;
      const descriptor = at(events, 11).blocks.find(
        (b) => b.blockType === 'tool_result' && b.sourceEventSeqs?.includes(8),
      );
      descriptor.contentHash = canonicalContentHash(at(events, 8).message.content[0]);
      return events;
    },
  },
  {
    id: 'D',
    name: 'truncate the tail',
    expect: 'undetected',
    note: 'A monotonic prefix is still a valid stream. The confirmation turn and run/end are simply gone.',
    build: () => clone().filter((e) => e.seq <= 9),
  },
  {
    id: 'E',
    name: 'duplicate a sequence number',
    expect: 'detected',
    note: 'Breaks the stream invariant, which is exactly what the sequence check is for.',
    build() {
      const events = clone();
      at(events, 12).seq = 11;
      return events;
    },
  },
  {
    id: 'F',
    name: 'erase the tool call entirely',
    expect: 'undetected',
    note: 'The transfer never appears in the record at all.',
    build() {
      const events = clone().filter((e) => ![6, 7, 8].includes(e.seq));
      const request = at(events, 11);
      request.blocks = request.blocks.filter(
        (b) => !(b.sourceEventSeqs ?? []).some((s) => [5, 6, 7, 8].includes(s)),
      );
      return renumber(events);
    },
  },
];

const base = await verifyRun({ events: clone() });
console.log(`\nbaseline            ${base.ok ? 'VERIFIES OK' : 'BROKEN'}   (${base.stats.blocksChecked} blocks, ${base.stats.events} events)\n`);
if (!base.ok) {
  console.error('Baseline does not verify. Regenerate the fixture.');
  process.exit(1);
}

let mismatches = 0;
for (const attack of attacks) {
  const verdict = await verifyRun({ events: attack.build() });
  const observed = verdict.ok ? 'undetected' : 'detected';
  const codes = [...new Set(verdict.failures.map((f) => `${f.code}/${f.reason}`))].join(', ');
  const label = observed === 'detected' ? 'DETECTED    ' : 'UNDETECTED >>';
  const drift = observed === attack.expect ? '' : '   <-- CHANGED from expected: ' + attack.expect;
  if (observed !== attack.expect) mismatches += 1;

  console.log(`${label}  ${attack.id}. ${attack.name}${drift}`);
  console.log(`               ${attack.note}`);
  if (codes) console.log(`               verifier: ${codes}`);
  console.log();
}

const undetected = attacks.filter((a) => a.expect === 'undetected').length;
console.log(`${undetected} of ${attacks.length} tampers pass verifyRun() unchanged.`);

if (mismatches > 0) {
  console.error(`\n${mismatches} observation(s) changed. Upstream behaviour has moved — update this file.`);
  process.exit(1);
}
