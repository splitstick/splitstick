/**
 * Source with comments and string literals removed, for checks that scan code.
 *
 * This exists because the same mistake has now been made four times in this
 * repository, by four different instruments:
 *
 * - `tools/lint-failure-codes.mjs` read `@property {string} code` in a typedef
 *   as a computed failure code.
 * - `tools/lint-claims.mjs` read a paragraph explaining a limit as a claim.
 * - the NFR-05 offline scan failed on the word `fetch` in a comment saying this
 *   verifier does not fetch.
 * - a review regression test, written to assert that three dead branches had
 *   been removed, matched the comments that described removing them.
 *
 * Every one of them was a check reading its own documentation as code. The
 * lesson had been learned three times and written down twice, and the fourth
 * instrument still made it — which is the argument for one shared helper
 * rather than a habit.
 *
 * `code()` strips comments. `codeOnly()` also strips string and template
 * literals, for checks where a pattern appearing inside a user-facing message
 * is a false positive — that happened too, with `fetch (NFR-05)` in a
 * capability sentence.
 */

/** @param {string} text @returns {string} */
export function code(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    // Not preceded by a colon, so a `https://` inside a string survives as
    // string content for codeOnly() to remove, rather than eating the line.
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/** @param {string} text @returns {string} */
export function codeOnly(text) {
  return code(text)
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}
