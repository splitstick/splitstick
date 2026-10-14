import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PerformanceObserver } from 'node:perf_hooks';
import { gcRecorder, gcOverlap, selfCheck } from '../gc.mjs';

/** Allocation the optimiser cannot elide: the objects stay reachable. */
const storm = () => {
  let keep = [];
  for (let i = 0; i < 400_000; i++) {
    keep.push({ i, buf: Buffer.alloc(256, i % 256) });
    if (keep.length > 5000) keep = keep.slice(2500);
  }
  return keep.length;
};

test('the recorder observes real collections', async () => {
  // Retried, because the drain waits for quiescence rather than a fixed delay
  // and a loaded machine can push the first collection past one attempt. An
  // instrument check that fails randomly is no more use than one that cannot
  // fail, so it gets the same budget the benchmark's own self-check gets.
  let run = { count: 0, totalMs: 0, windows: /** @type {[number, number][]} */ ([]) };
  for (let attempt = 0; attempt < 3 && run.count === 0; attempt++) {
    const gc = gcRecorder();
    gc.start();
    storm();
    run = await gc.stop();
  }
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
  assert.equal(immediate, 0, 'the undrained observer sees nothing');

  const drained = await selfCheck();
  assert.equal(drained.verified, true, 'the drained one sees the same collections');
});

test('selfCheck reports verified, so a zero elsewhere can be trusted', async () => {
  const result = await selfCheck();
  assert.equal(result.verified, true);
  assert.ok(result.count > 0);
});

test('a quiet run records only pauses that really happened', async () => {
  // The property is that the recorder does not FABRICATE pauses, and that an
  // empty window yields a real zero rather than a lost one — which is why the
  // `selfCheck` test above, proving it records when pauses do occur, is the
  // other half of this pair.
  //
  // It used to assert `count === 0` outright. A recorder cannot stop the
  // garbage collector from running in its window, and under the full suite one
  // sometimes does: the test failed once in a 936-test run and passed three
  // times in isolation. That is the same shape as M6's write-lock contention
  // test, which asserted "exactly one winner" — a load-sensitive proxy for the
  // property, rather than the property.
  const gc = gcRecorder();
  gc.start();
  const run = await gc.stop();

  assert.equal(run.count, run.windows.length,
    'the count and the recorded windows disagree, so one of them is invented');
  assert.ok(run.count >= 0);
  for (const [from, to] of run.windows) {
    assert.ok(to >= from, `a recorded pause ends before it starts: ${from}..${to}`);
  }
  // A sample at time 0 cannot overlap a pause observed during this window,
  // because `performance` timestamps here are well past process start. This is
  // the deterministic half and it does not depend on whether a GC fired.
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
