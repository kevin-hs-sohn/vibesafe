/**
 * Input sanitization utilities for LLM prompt injection defense
 */

/**
 * Maximum allowed command length for LLM analysis
 */
export const MAX_COMMAND_LENGTH = 2000;

/**
 * Patterns that indicate potential prompt injection attempts
 *
 * These detect common prompt injection techniques:
 * 1. Instruction override: "ignore previous instructions"
 * 2. Role manipulation: "you are now a", "system:", "assistant:"
 * 3. Output manipulation: "respond with this json", "return ALLOW"
 * 4. Context escape: "end of instructions", "for testing purposes"
 */
const PROMPT_INJECTION_PATTERNS = [
  // Instruction override attempts
  /ignore\s+(all\s+)?(previous\s+)?instructions/i,
  /forget\s+(all\s+)?(previous\s+)?instructions/i,
  /disregard\s+(all\s+)?(previous\s+)?instructions/i,
  /override\s+(all\s+)?(previous\s+)?instructions/i,
  /skip\s+(all\s+)?(security\s+)?checks?/i,
  /bypass\s+(all\s+)?(security\s+)?checks?/i,

  // Role manipulation
  /you\s+are\s+(now\s+)?a/i,
  /act\s+as\s+(a\s+)?/i,
  /pretend\s+(to\s+be|you\s+are)/i,
  /new\s+instructions?:/i,
  /updated?\s+instructions?:/i,

  // Context/role markers (could be trying to inject fake context)
  /system\s*:/i,
  /assistant\s*:/i,
  /human\s*:/i,
  /user\s*:/i,
  /<\s*system\s*>/i,
  /<\s*\/?\s*instructions?\s*>/i,

  // Emphasis markers often used in injection
  /\bIMPORTANT\s*:/i,
  /\bNOTE\s*:/i,
  /\bWARNING\s*:/i,
  /\bCRITICAL\s*:/i,
  /\bURGENT\s*:/i,

  // Output manipulation
  /respond\s+with\s+(this\s+)?(exact\s+)?json/i,
  /return\s+(only\s+)?["']?ALLOW["']?/i,
  /output\s+(only\s+)?["']?ALLOW["']?/i,
  /always\s+(return|respond|output)\s+/i,
  /must\s+(return|respond|output)\s+/i,

  // Context escape attempts
  /for\s+testing\s+purposes/i,
  /end\s+of\s+(test\s+)?instructions/i,
  /this\s+is\s+(a\s+)?(safe|secure|authorized|approved)/i,
  /pre-?approved/i,
  /already\s+(been\s+)?(verified|approved|checked)/i,

  // Direct verdict manipulation
  /classification\s*[=:]\s*["']?(SELF_HANDLE|ALLOW)["']?/i,
  /verdict\s*[=:]\s*["']?ALLOW["']?/i,
  /\{"?\s*verdict\s*"?\s*:\s*"?ALLOW/i,
];

/**
 * Check if command contains prompt injection patterns
 */
export function containsPromptInjection(command: string): boolean {
  return PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Sanitize command for safe inclusion in LLM prompts
 * - Truncates to max length
 * - Escapes special characters that could break prompt structure
 * - Normalizes whitespace
 */
export function sanitizeForPrompt(command: string): string {
  let sanitized = command;

  // Truncate to max length
  if (sanitized.length > MAX_COMMAND_LENGTH) {
    sanitized = sanitized.slice(0, MAX_COMMAND_LENGTH) + '... [truncated]';
  }

  // Break CDATA end sequences to prevent escaping XML CDATA blocks
  sanitized = sanitized.replace(/]]>/g, ']]&gt;');

  // Normalize excessive newlines (potential injection delimiter)
  sanitized = sanitized.replace(/\n{3,}/g, '\n\n');

  return sanitized;
}

/**
 * Escape string for XML content
 */
export function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Risk indicators that should force escalation even if LLM says SELF_HANDLE
 */
const FORCE_ESCALATE_PATTERNS = [
  /\|\s*(ba)?sh/i,                    // Pipe to shell
  /curl.*\|/i,                        // curl piped to something
  /wget.*\|/i,                        // wget piped to something
  /base64/i,                          // Base64 operations
  /eval\s*\(/i,                       // eval() calls
  /\$\([^)]+\)/,                      // Command substitution
  /`[^`]+`/,                          // Backtick command substitution
  /[<>]\s*\/dev\/tcp/i,               // /dev/tcp redirection (both < and >)
  /\/dev\/tcp\//i,                    // /dev/tcp path anywhere
  /nc\s+.*-[elp]/i,                   // netcat with execution/listen flags
  /\bsudo\b/i,                        // sudo commands
  /\bsu\b\s+-/i,                      // su commands
  /chmod\s+[0-7]*[7][0-7]*/i,         // chmod with executable permissions
  /\.env/i,                           // env file access
  /\/(etc|root|home)\//i,             // System directory access
];

/**
 * Check if command should force escalation regardless of LLM response
 * This is a safety net against prompt injection attacks
 */
export function shouldForceEscalate(command: string): boolean {
  // Check for prompt injection attempts
  if (containsPromptInjection(command)) {
    return true;
  }

  // Check for risky patterns that shouldn't be auto-approved
  return FORCE_ESCALATE_PATTERNS.some((pattern) => pattern.test(command));
}
