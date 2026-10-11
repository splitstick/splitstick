/**
 * An "agent", as the customer writes it — INT-07's subject.
 *
 * This file is hashed before and after integration by the test beside it.
 * Nothing in it mentions Splitstick: the agent is a name, an adapter, a model,
 * a prompt and its tools. Wiring a collector is a change to how the
 * orchestrator is CONSTRUCTED, which is the application's configuration, not a
 * change to this.
 */
import { defineTool } from '@open-multi-agent/core';
import { z } from 'zod';

export const transferFunds = defineTool({
  name: 'transfer_funds',
  description: 'Transfer funds to a counterparty account.',
  consequential: true,
  inputSchema: z.object({ amount: z.number(), currency: z.string(), to: z.string() }),
  async execute(input) {
    return { data: `OK: transferred ${input.currency} ${input.amount} to ${input.to}. ref=TX-77814` };
  },
});

/** @returns {any} a deterministic stand-in for a provider; the only stub here */
export function scriptedAdapter() {
  let call = 0;
  return {
    name: 'scripted',
    async chat() {
      call += 1;
      if (call === 1) {
        return {
          id: 'msg_1', model: 'scripted-1', stop_reason: 'tool_use',
          usage: { input_tokens: 100, output_tokens: 20 },
          content: [{ type: 'tool_use', id: 'call_1', name: 'transfer_funds',
            input: { amount: 2000000, currency: 'EUR', to: 'ACME-9931' } }],
        };
      }
      return {
        id: 'msg_2', model: 'scripted-1', stop_reason: 'end_turn',
        usage: { input_tokens: 180, output_tokens: 25 },
        content: [{ type: 'text', text: 'Transfer complete (ref TX-77814).' }],
      };
    },
    async *stream() { throw new Error('stream() is not exercised by this fixture'); },
  };
}

export const agent = {
  name: 'treasury-agent',
  model: 'scripted-1',
  systemPrompt: 'You are a treasury operations agent.',
  customTools: [transferFunds],
  tools: ['transfer_funds'],
  maxTurns: 4,
};

export const goal = 'Pay invoice 4471: EUR 2,000,000 to ACME-9931.';
