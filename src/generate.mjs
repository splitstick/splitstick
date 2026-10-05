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
 * Produce a genuine OMA run journal to use as a tamper fixture.
 *
 * The LLM adapter is scripted, so the run is deterministic, needs no API key
 * and makes no network request — but every journal event is written by OMA's
 * real runtime, not hand-authored. That matters: a synthetic fixture would
 * prove nothing about the shipped verifier.
 *
 * The agent performs one consequential tool call (a funds transfer), which is
 * the kind of action an audit actually asks about.
 */
import { OpenMultiAgent, JsonlRunJournal, defineTool, verifyRun } from '@open-multi-agent/core';
import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';

export const JOURNAL_PATH = path.join('out', 'journal.jsonl');

const transferFunds = defineTool({
  name: 'transfer_funds',
  description: 'Transfer funds to a counterparty account.',
  consequential: true,
  inputSchema: z.object({
    amount: z.number(),
    currency: z.string(),
    to: z.string(),
  }),
  async execute(input) {
    return { data: `OK: transferred ${input.currency} ${input.amount} to ${input.to}. ref=TX-77814` };
  },
});

/** Turn 1 calls the tool; turn 2 confirms. No credentials, no egress. */
function scriptedAdapter() {
  let call = 0;
  return {
    name: 'scripted',
    async chat() {
      call += 1;
      if (call === 1) {
        return {
          id: 'msg_1',
          model: 'scripted-1',
          stop_reason: 'tool_use',
          usage: { input_tokens: 100, output_tokens: 20 },
          content: [{
            type: 'tool_use',
            id: 'call_1',
            name: 'transfer_funds',
            input: { amount: 2000000, currency: 'EUR', to: 'ACME-9931' },
          }],
        };
      }
      return {
        id: 'msg_2',
        model: 'scripted-1',
        stop_reason: 'end_turn',
        usage: { input_tokens: 180, output_tokens: 25 },
        content: [{ type: 'text', text: 'Transfer of EUR 2,000,000 to ACME-9931 is complete (ref TX-77814).' }],
      };
    },
    async *stream() { throw new Error('stream() is not exercised by this fixture'); },
  };
}

export async function generate() {
  fs.mkdirSync('out', { recursive: true });
  fs.rmSync(JOURNAL_PATH, { force: true });

  const journal = new JsonlRunJournal(JOURNAL_PATH, { flushIntervalMs: 1 });
  const oma = new OpenMultiAgent({ journal });

  const result = await oma.runAgent(
    {
      name: 'treasury-agent',
      adapter: scriptedAdapter(),
      model: 'scripted-1',
      systemPrompt: 'You are a treasury operations agent.',
      customTools: [transferFunds],
      tools: ['transfer_funds'],
      maxTurns: 4,
    },
    'Pay invoice 4471: EUR 2,000,000 to ACME-9931.',
    { journal },
  );

  await journal.close();
  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await generate();
  const events = fs.readFileSync(JOURNAL_PATH, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const verdict = await verifyRun({ events });

  console.log(`run status : ${JSON.stringify(result.status)}`);
  console.log(`journal    : ${JOURNAL_PATH} (${events.length} events)`);
  console.log(`sequence   : ${events.map((e) => `${e.seq}:${e.type}`).join('  ')}`);
  console.log(`verifyRun  : ${verdict.ok ? 'OK' : 'FAIL'} (${verdict.stats.blocksChecked} blocks checked)`);

  if (!verdict.ok) {
    console.error('\nBaseline journal does not verify. The fixture is wrong, not the verifier.');
    process.exit(1);
  }
}
