/**
 * Splitstick's MCP collector — FR-03, FR-04, NFR-11, INT-05.
 *
 * Framework-agnostic by construction: the proxy does not know what is upstream
 * of it or what is downstream, which is what makes capture work for any
 * runtime speaking MCP, including ones with no journal of their own.
 */

export { Pairing, TOOL_CALL } from './pairing.mjs';
export { recorder } from './record.mjs';
export { stdioProxy } from './stdio.mjs';
export { httpProxy } from './http.mjs';
