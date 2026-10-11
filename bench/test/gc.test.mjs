import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PerformanceObserver } from 'node:perf_hooks';
import { gcRecorder, gcOverlap, selfCheck } from '../gc.mjs';

const storm = () => {
  let sink = [];
  for (let i = 0; i < 300_000; i++) {
    sink.push(Buffer.alloc(200, i % 256));
    if (sink.length > 2000) sink = [];
  }
};

test('the recorder observes real collections', async () => {
  const gc = gcRecorder();
  gc.start();
  storm();
  const run = await gc.stop();
  assert.ok(run.count > 0, 'an allocation storm must produce pauses the recorder sees');
  assert.ok(run.totalMs > 0);
  assert.equal(run.windows.length, run.count);
});

/**
 * The bug this module exists because of: observer callbacks are asynchronous,
 * so disconnecting straight after a synchronous loop loses every entry. The
 * benchmark did exactly that and reported zero pauses, and I then "verified"
 * the recorder with a flush the benchmark did not have.
 */
test('disconnecting without draining loses the entries — which is why stop() awaits', async () => {
  let immediate = 0;
  const obs = new PerformanceObserver((list) => { immediate += list.getEntries().length; });
  obs.observe({ entryTypes: ['gc'] });
  storm();
  obs.disconnect();

  const gc = gcRecorder();
  gc.start();
  storm();
  const drained = await gc.stop();

  assert.equal(immediate, 0, 'the undrained observer sees nothing');
  assert.ok(drained.count > 0, 'the drained one sees the same collections');
});

test('selfCheck reports verified, so a zero elsewhere can be trusted', async () => {
  const result = await selfCheck();
  assert.equal(result.verified, true);
  assert.ok(result.count > 0);
});

test('a quiet run legitimately records no pauses', async () => {
  const gc = gcRecorder();
  gc.start();
  const run = await gc.stop();
  assert.equal(run.count, 0, 'and that is a real zero, not a lost one');
  assert.equal(gcOverlap([{ at: 0, ms: 1 }], run.windows), 0);
});

test('overlap is computed against the sample window, not its start alone', () => {
  const windows = /** @type {[number, number][]} */ ([[100, 105]]);
  assert.equal(gcOverlap([{ at: 101, ms: 0.1 }], windows), 1, 'inside');
  assert.equal(gcOverlap([{ at: 98, ms: 4 }], windows), 1, 'starts before, overlaps');
  assert.equal(gcOverlap([{ at: 104, ms: 10 }], windows), 1, 'starts inside, runs past');
  assert.equal(gcOverlap([{ at: 50, ms: 1 }], windows), 0, 'well before');
  assert.equal(gcOverlap([{ at: 200, ms: 1 }], windows), 0, 'well after');
  assert.equal(gcOverlap([], windows), 0, 'nothing to compare');
});
