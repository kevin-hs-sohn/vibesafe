/**
 * Instant Allow - Immediately allow known safe patterns
 * No LLM call needed for these safe commands
 */

export interface InstantAllowResult {
  allowed: boolean;
  reason?: string;
  patternName?: string;
}

/**
 * Safe git commands that can be instantly allowed
 * These are local operations that don't affect remote or cause data loss
 */
const SAFE_GIT_COMMANDS = [
  'status',
  'log',
  'diff',
  'add',
  'commit',
  'branch',
  'checkout',
  'stash',
  'fetch',
  'pull',
  'merge',
  'rebase',
  'show',
  'blame',
  'remote',
  'tag',
  'cherry-pick',
  'reflog',
  'shortlog',
  'describe',
  'rev-parse',
  'ls-files',
  'ls-tree',
];

/**
 * Dangerous git commands that should NOT be instantly allowed
 * These can cause data loss or affect remote repositories
 */
const DANGEROUS_GIT_PATTERNS = [
  /git\s+push/i,
  /git\s+reset\s+--hard/i,
  /git\s+clean\s+-[a-z]*f/i,  // git clean with -f flag
  /git\s+.*--force/i,
  /git\s+.*-f\b/i,  // short force flag (but not in branch names like -feature)
];

/**
 * Check if a command is a pure git command (not chained with other commands)
 */
function isPureGitCommand(command: string): boolean {
  const trimmed = command.trim();

  // Check for command chaining (;, &&, ||, |, backticks, $())
  if (/[;&|`]|\$\(/.test(trimmed)) {
    return false;
  }

  // Must start with 'git '
  return /^git\s+/i.test(trimmed);
}

/**
 * Check if a command matches any dangerous git pattern
 */
function isDangerousGitCommand(command: string): boolean {
  for (const pattern of DANGEROUS_GIT_PATTERNS) {
    if (pattern.test(command)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a command is a safe git subcommand
 */
function isSafeGitSubcommand(command: string): boolean {
  const match = command.match(/^git\s+(\S+)/i);
  if (!match) return false;

  const subcommand = match[1].toLowerCase();
  return SAFE_GIT_COMMANDS.includes(subcommand);
}

/**
 * Check if a command should be instantly allowed (skip LLM review)
 * Returns immediately without any LLM call
 */
export function checkInstantAllow(command: string): InstantAllowResult {
  // Empty or whitespace-only commands are not allowed
  if (!command || !command.trim()) {
    return { allowed: false };
  }

  // Must be a pure git command (no chaining)
  if (!isPureGitCommand(command)) {
    return { allowed: false };
  }

  // Check for dangerous git patterns first
  if (isDangerousGitCommand(command)) {
    return { allowed: false };
  }

  // Check if it's a safe git subcommand
  if (isSafeGitSubcommand(command)) {
    const match = command.match(/^git\s+(\S+)/i);
    const subcommand = match?.[1] || 'git';
    return {
      allowed: true,
      reason: `Safe git command: git ${subcommand}`,
      patternName: `git_${subcommand}`,
    };
  }

  return { allowed: false };
}
