/**
 * Security checks for file-based tools (Write, Edit, Read)
 *
 * These tools can bypass Bash command security if not checked:
 * - Write: Can create ~/.ssh/authorized_keys, ~/.bashrc, crontabs
 * - Edit: Can inject code into existing files
 * - Read: Can exfiltrate ~/.aws/credentials, ~/.ssh/id_rsa, .env
 */

export type FileToolAction = 'write' | 'edit' | 'read';

export interface FileCheckResult {
  blocked: boolean;
  reason?: string;
  severity?: 'critical' | 'high' | 'medium';
}

/**
 * Sensitive paths that should be blocked for write/edit operations
 */
const WRITE_BLOCKED_PATHS: Array<{ pattern: RegExp; description: string; severity: 'critical' | 'high' }> = [
  // SSH - Critical (persistent access)
  { pattern: /^~?\/?\.ssh\//i, description: 'SSH directory', severity: 'critical' },
  { pattern: /\.ssh\/authorized_keys$/i, description: 'SSH authorized_keys', severity: 'critical' },
  { pattern: /\.ssh\/config$/i, description: 'SSH config', severity: 'critical' },

  // Cloud credentials - Critical
  { pattern: /^~?\/?\.aws\//i, description: 'AWS credentials directory', severity: 'critical' },
  { pattern: /^~?\/?\.azure\//i, description: 'Azure credentials directory', severity: 'critical' },
  { pattern: /^~?\/?\.gcloud\//i, description: 'GCloud credentials directory', severity: 'critical' },
  { pattern: /^~?\/?\.config\/gcloud\//i, description: 'GCloud config directory', severity: 'critical' },

  // GPG/Crypto - Critical
  { pattern: /^~?\/?\.gnupg\//i, description: 'GPG directory', severity: 'critical' },

  // System config - Critical
  { pattern: /^\/etc\//i, description: 'System /etc directory', severity: 'critical' },
  { pattern: /^\/usr\//i, description: 'System /usr directory', severity: 'critical' },
  { pattern: /^\/bin\//i, description: 'System /bin directory', severity: 'critical' },
  { pattern: /^\/sbin\//i, description: 'System /sbin directory', severity: 'critical' },

  // Shell startup files - High (code execution on shell start)
  { pattern: /^~?\/?\.bashrc$/i, description: 'Bash startup file', severity: 'high' },
  { pattern: /^~?\/?\.bash_profile$/i, description: 'Bash profile', severity: 'high' },
  { pattern: /^~?\/?\.zshrc$/i, description: 'Zsh startup file', severity: 'high' },
  { pattern: /^~?\/?\.zprofile$/i, description: 'Zsh profile', severity: 'high' },
  { pattern: /^~?\/?\.profile$/i, description: 'Shell profile', severity: 'high' },
  { pattern: /^~?\/?\.bash_logout$/i, description: 'Bash logout script', severity: 'high' },
  { pattern: /^~?\/?\.zlogout$/i, description: 'Zsh logout script', severity: 'high' },

  // Cron - High (scheduled code execution)
  { pattern: /crontab/i, description: 'Crontab file', severity: 'high' },
  { pattern: /^\/var\/spool\/cron\//i, description: 'Cron spool directory', severity: 'high' },

  // Git hooks - High (code execution on git operations)
  { pattern: /\.git\/hooks\//i, description: 'Git hooks directory', severity: 'high' },

  // Package managers config (supply chain risk)
  { pattern: /^~?\/?\.npmrc$/i, description: 'NPM config (may contain tokens)', severity: 'high' },
  { pattern: /^~?\/?\.pypirc$/i, description: 'PyPI config (may contain tokens)', severity: 'high' },

  // Claude Code config - High (could disable security)
  { pattern: /CLAUDE\.md$/i, description: 'Claude instructions file', severity: 'high' },
  { pattern: /^~?\/?\.claude\//i, description: 'Claude config directory', severity: 'high' },
];

/**
 * Sensitive paths that should be blocked for read operations
 * More restrictive than write - includes secrets that shouldn't be exfiltrated
 */
const READ_BLOCKED_PATHS: Array<{ pattern: RegExp; description: string; severity: 'critical' | 'high' }> = [
  // Private keys - Critical
  { pattern: /\.ssh\/id_rsa$/i, description: 'SSH private key (RSA)', severity: 'critical' },
  { pattern: /\.ssh\/id_ed25519$/i, description: 'SSH private key (Ed25519)', severity: 'critical' },
  { pattern: /\.ssh\/id_ecdsa$/i, description: 'SSH private key (ECDSA)', severity: 'critical' },
  { pattern: /\.ssh\/id_dsa$/i, description: 'SSH private key (DSA)', severity: 'critical' },
  { pattern: /\.pem$/i, description: 'PEM private key', severity: 'critical' },
  { pattern: /\.key$/i, description: 'Private key file', severity: 'critical' },

  // Cloud credentials - Critical
  { pattern: /\.aws\/credentials$/i, description: 'AWS credentials', severity: 'critical' },
  { pattern: /\.azure\/credentials$/i, description: 'Azure credentials', severity: 'critical' },

  // Environment files - High
  { pattern: /\.env$/i, description: 'Environment file', severity: 'high' },
  { pattern: /\.env\.local$/i, description: 'Local environment file', severity: 'high' },
  { pattern: /\.env\.production$/i, description: 'Production environment file', severity: 'high' },
  { pattern: /\.env\.development$/i, description: 'Development environment file', severity: 'high' },

  // Password/credential files - Critical
  { pattern: /^\/etc\/shadow$/i, description: 'System shadow file', severity: 'critical' },
  { pattern: /^\/etc\/passwd$/i, description: 'System passwd file', severity: 'high' },

  // Browser/app credentials
  { pattern: /\.netrc$/i, description: 'Netrc credentials', severity: 'critical' },
  { pattern: /\.docker\/config\.json$/i, description: 'Docker config (may contain tokens)', severity: 'high' },

  // Keychain/secret stores
  { pattern: /\.gnupg\/private-keys/i, description: 'GPG private keys', severity: 'critical' },
];

/**
 * Normalize file path for consistent matching
 */
function normalizePath(filePath: string): string {
  // Expand environment variables
  let normalized = filePath
    .replace(/\$HOME/g, '~')
    .replace(/\$\{HOME\}/g, '~');

  // Normalize multiple slashes
  normalized = normalized.replace(/\/+/g, '/');

  return normalized;
}

/**
 * Check if a file path is sensitive for a given action
 */
export function checkFilePath(filePath: string, action: FileToolAction): FileCheckResult {
  const normalized = normalizePath(filePath);

  if (action === 'read') {
    // Check read-blocked paths
    for (const { pattern, description, severity } of READ_BLOCKED_PATHS) {
      if (pattern.test(normalized)) {
        return {
          blocked: true,
          reason: `Blocked: Reading ${description} (${normalized})`,
          severity,
        };
      }
    }
  } else {
    // Write or Edit
    for (const { pattern, description, severity } of WRITE_BLOCKED_PATHS) {
      if (pattern.test(normalized)) {
        return {
          blocked: true,
          reason: `Blocked: ${action === 'write' ? 'Writing to' : 'Editing'} ${description} (${normalized})`,
          severity,
        };
      }
    }
  }

  return { blocked: false };
}

/**
 * Check file tool input and return security result
 */
export function checkFileTool(
  toolName: string,
  toolInput: Record<string, unknown>
): FileCheckResult {
  const filePath = toolInput.file_path as string | undefined;

  if (!filePath) {
    return { blocked: false };
  }

  switch (toolName) {
    case 'Write':
      return checkFilePath(filePath, 'write');
    case 'Edit':
      return checkFilePath(filePath, 'edit');
    case 'Read':
      return checkFilePath(filePath, 'read');
    default:
      return { blocked: false };
  }
}
