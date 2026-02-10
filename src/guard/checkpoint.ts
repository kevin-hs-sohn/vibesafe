/**
 * Checkpoint Detection - Identify commands that need security review
 */

import { CHECKPOINT_PATTERNS } from '../config/patterns.js';
import { containsUrlShortener } from '../config/domains.js';
import type { SecurityCheckpoint } from '../types.js';

export type { SecurityCheckpoint };

/**
 * Detect if a command triggers a security checkpoint
 * Returns the checkpoint info if triggered, null otherwise
 */
export function detectCheckpoint(command: string): SecurityCheckpoint | null {
  // Empty or whitespace-only commands don't trigger checkpoints
  if (!command || !command.trim()) {
    return null;
  }

  // Check for URL shorteners first - they can redirect to malicious sites
  const shortenerCheck = containsUrlShortener(command);
  if (shortenerCheck.found) {
    return {
      type: 'url_shortener',
      command,
      description: `URL shortener detected: ${shortenerCheck.shortenerUrls.join(', ')} - could redirect to malicious site`,
    };
  }

  for (const { pattern, type, description } of CHECKPOINT_PATTERNS) {
    if (pattern.test(command)) {
      return {
        type,
        command,
        description,
      };
    }
  }

  return null;
}
