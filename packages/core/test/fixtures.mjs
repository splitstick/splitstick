/** Shared record fixtures. The walkthrough record from the release notes. */

export const action = (over = {}) => ({
  v: 1, collector: 'host-1', run: 'r-1', record_seq: 1, source_seq: 1,
  ts: '2026-10-11T10:00:00.000Z', kind: 'tool_call', tool: 'transfer_funds',
  agent: { cid: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
  args: { cid: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', bytes: 61 },
  result: { cid: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', bytes: 54, ok: true },
  approval: null, consequential: true,
  outcome: 'ok', attempt: 1, correlation: 'c-0001',
  ...over,
});

export const heartbeat = (over = {}) => ({
  v: 1, collector: 'host-1', run: null, record_seq: 2, source_seq: null,
  ts: '2026-10-11T10:00:05.000Z', kind: 'heartbeat',
  build: 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', policy: 'sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface',
  ...over,
});
