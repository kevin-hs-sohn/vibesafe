/**
 * High Risk Detection - Detect dangerous patterns and warn user
 * Instead of blocking, we warn the user and let them decide
 */

import { INSTANT_BLOCK_PATTERNS } from '../config/patterns.js';

export interface HighRiskResult {
  detected: boolean;
  patternName?: string | undefined;
  severity?: 'critical' | 'high' | 'medium' | undefined;
  description?: string | undefined;
  risk?: string | undefined;
  legitimateUses?: string[] | undefined;
}

/**
 * Check if a command matches any high-risk pattern
 * Returns warning info instead of blocking
 */
export function checkHighRiskPatterns(command: string): HighRiskResult {
  // Empty or whitespace-only commands are safe
  if (!command || !command.trim()) {
    return { detected: false };
  }

  for (const pattern of INSTANT_BLOCK_PATTERNS) {
    if (pattern.pattern.test(command)) {
      return {
        detected: true,
        patternName: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        risk: pattern.risk,
        legitimateUses: pattern.legitimateUses,
      };
    }
  }

  return { detected: false };
}

