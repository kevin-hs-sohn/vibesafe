/**
 * CLI Check Command
 * Run security check on a PermissionRequest (stdin)
 */

import { runHook } from '../hook.js';

/**
 * Run security check from stdin
 */
export async function check(): Promise<void> {
  await runHook();
}
