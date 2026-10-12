/**
 * The operator's side of the witness protocol, and the check that makes a
 * witness's own misbehaviour visible — FR-50.
 */

import { parseNote, parseCheckpointText } from '@splitstick/core/note';

/**
 * Compare a tree head observed earlier against one served now.
 *
 * This is the whole mechanism behind "detected rather than suspected". A
 * witness that serves an earlier head than one a party already holds has
 * either lost its state or is colluding, and either way the two signed heads
 * contradict each other in a way nobody can talk their way out of — which is
 * why the earlier head must be RETAINED by whoever polled it.
 *
 * @param {string} observed a head retained from an earlier poll
 * @param {string} now the head served now
 * @returns {{ rolledBack: boolean, detail: string, observed_size: number, now_size: number }}
 */
export function detectRollback(observed, now) {
  const a = parseCheckpointText(parseNote(observed).text);
  const b = parseCheckpointText(parseNote(now).text);
  if (a.origin !== b.origin) {
    return {
      rolledBack: false,
      detail: `these are heads for different origins (${a.origin} and ${b.origin}), so they say nothing about each other`,
      observed_size: a.tree_size,
      now_size: b.tree_size,
    };
  }
  if (b.tree_size < a.tree_size) {
    return {
      rolledBack: true,
      detail: `the witness now serves tree_size ${b.tree_size} but previously signed ${a.tree_size}: `
        + 'two signed heads from the same key contradict each other',
      observed_size: a.tree_size,
      now_size: b.tree_size,
    };
  }
  if (b.tree_size === a.tree_size && !a.root.equals(b.root)) {
    return {
      rolledBack: true,
      detail: `the witness serves a different root at height ${a.tree_size} than it previously signed`,
      observed_size: a.tree_size,
      now_size: b.tree_size,
    };
  }
  return {
    rolledBack: false,
    detail: `the witness has advanced from ${a.tree_size} to ${b.tree_size}`,
    observed_size: a.tree_size,
    now_size: b.tree_size,
  };
}
