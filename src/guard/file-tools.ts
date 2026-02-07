/**
 * Security checks for file-based tools (Write, Edit, Read)
 *
 * These tools can bypass Bash command security if not checked:
 * - Write: Can create ~/.ssh/authorized_keys, ~/.bashrc, crontabs
 * - Edit: Can inject code into existing files
 * - Read: Can exfiltrate ~/.aws/credentials, ~/.ssh/id_rsa, .env
 *
 * Instead of blocking, we warn users and let them decide.
 */

export type FileToolAction = 'write' | 'edit' | 'read';

export interface FileCheckResult {
  blocked: boolean;
  reason?: string | undefined;
  severity?: 'critical' | 'high' | 'medium' | undefined;
  risk?: string | undefined;
  legitimateUses?: string[] | undefined;
}

interface SensitivePath {
  pattern: RegExp;
  description: string;
  severity: 'critical' | 'high';
  risk: string;
  legitimateUses: string[];
}

/**
 * Sensitive paths for write/edit operations
 */
const WRITE_SENSITIVE_PATHS: SensitivePath[] = [
  // SSH - Critical (persistent access)
  { pattern: /^~?\/?\.ssh\//i, description: 'SSH directory', severity: 'critical',
    risk: 'Attacker can add their key for persistent remote access',
    legitimateUses: ['Adding new SSH keys', 'Configuring SSH'] },
  { pattern: /\.ssh\/authorized_keys$/i, description: 'SSH authorized_keys', severity: 'critical',
    risk: 'Attacker gains persistent SSH access to your machine',
    legitimateUses: ['Adding authorized keys for remote access'] },
  { pattern: /\.ssh\/config$/i, description: 'SSH config', severity: 'critical',
    risk: 'Can redirect SSH connections to attacker-controlled servers',
    legitimateUses: ['Configuring SSH hosts and options'] },

  // Cloud credentials - Critical
  { pattern: /^~?\/?\.aws\//i, description: 'AWS credentials directory', severity: 'critical',
    risk: 'Attacker gains access to your AWS account',
    legitimateUses: ['Configuring AWS CLI', 'Setting up AWS profiles'] },
  { pattern: /^~?\/?\.azure\//i, description: 'Azure credentials directory', severity: 'critical',
    risk: 'Attacker gains access to your Azure account',
    legitimateUses: ['Configuring Azure CLI'] },
  { pattern: /^~?\/?\.gcloud\//i, description: 'GCloud credentials directory', severity: 'critical',
    risk: 'Attacker gains access to your Google Cloud account',
    legitimateUses: ['Configuring gcloud CLI'] },
  { pattern: /^~?\/?\.config\/gcloud\//i, description: 'GCloud config directory', severity: 'critical',
    risk: 'Attacker gains access to your Google Cloud account',
    legitimateUses: ['Configuring gcloud CLI'] },

  // GPG/Crypto - Critical
  { pattern: /^~?\/?\.gnupg\//i, description: 'GPG directory', severity: 'critical',
    risk: 'Attacker can sign/encrypt as you or steal your keys',
    legitimateUses: ['Managing GPG keys', 'Configuring GPG'] },

  // System config - Critical
  { pattern: /^\/etc\//i, description: 'System /etc directory', severity: 'critical',
    risk: 'Can modify system configuration, add users, change permissions',
    legitimateUses: ['System administration', 'Server configuration'] },
  { pattern: /^\/usr\//i, description: 'System /usr directory', severity: 'critical',
    risk: 'Can replace system binaries with malicious versions',
    legitimateUses: ['Installing software', 'System administration'] },
  { pattern: /^\/bin\//i, description: 'System /bin directory', severity: 'critical',
    risk: 'Can replace core system commands',
    legitimateUses: ['System administration'] },
  { pattern: /^\/sbin\//i, description: 'System /sbin directory', severity: 'critical',
    risk: 'Can replace system administration commands',
    legitimateUses: ['System administration'] },

  // Shell startup files - High (code execution on shell start)
  { pattern: /^~?\/?\.bashrc$/i, description: 'Bash startup file', severity: 'high',
    risk: 'Code runs every time you open a terminal',
    legitimateUses: ['Adding aliases', 'Setting environment variables', 'Shell customization'] },
  { pattern: /^~?\/?\.bash_profile$/i, description: 'Bash profile', severity: 'high',
    risk: 'Code runs on login shell startup',
    legitimateUses: ['Login shell configuration'] },
  { pattern: /^~?\/?\.zshrc$/i, description: 'Zsh startup file', severity: 'high',
    risk: 'Code runs every time you open a terminal',
    legitimateUses: ['Adding aliases', 'Setting environment variables', 'Shell customization'] },
  { pattern: /^~?\/?\.zprofile$/i, description: 'Zsh profile', severity: 'high',
    risk: 'Code runs on login shell startup',
    legitimateUses: ['Login shell configuration'] },
  { pattern: /^~?\/?\.profile$/i, description: 'Shell profile', severity: 'high',
    risk: 'Code runs on shell startup',
    legitimateUses: ['Shell configuration'] },
  { pattern: /^~?\/?\.bash_logout$/i, description: 'Bash logout script', severity: 'high',
    risk: 'Code runs when you close terminal',
    legitimateUses: ['Cleanup scripts'] },
  { pattern: /^~?\/?\.zlogout$/i, description: 'Zsh logout script', severity: 'high',
    risk: 'Code runs when you close terminal',
    legitimateUses: ['Cleanup scripts'] },

  // Cron - High (scheduled code execution)
  { pattern: /crontab/i, description: 'Crontab file', severity: 'high',
    risk: 'Can schedule malicious code to run periodically',
    legitimateUses: ['Setting up scheduled tasks', 'Automation'] },
  { pattern: /^\/var\/spool\/cron\//i, description: 'Cron spool directory', severity: 'high',
    risk: 'Can schedule malicious code to run periodically',
    legitimateUses: ['System cron job management'] },

  // Git hooks - High (code execution on git operations)
  { pattern: /\.git\/hooks\//i, description: 'Git hooks directory', severity: 'high',
    risk: 'Code runs automatically on git operations (commit, push, etc.)',
    legitimateUses: ['Setting up pre-commit hooks', 'CI/CD integration', 'Code formatting'] },

  // Package managers config (supply chain risk)
  { pattern: /^~?\/?\.npmrc$/i, description: 'NPM config (may contain tokens)', severity: 'high',
    risk: 'Can steal npm tokens or redirect package installs',
    legitimateUses: ['Configuring npm registry', 'Setting up private packages'] },
  { pattern: /^~?\/?\.pypirc$/i, description: 'PyPI config (may contain tokens)', severity: 'high',
    risk: 'Can steal PyPI tokens or redirect package installs',
    legitimateUses: ['Configuring PyPI', 'Publishing packages'] },

  // Claude Code config - Critical (could disable security)
  { pattern: /CLAUDE\.md$/i, description: 'Claude instructions file', severity: 'critical',
    risk: 'Can modify AI behavior and disable security rules',
    legitimateUses: ['Updating project instructions', 'Configuring Claude behavior'] },
  { pattern: /^~?\/?\.claude\//i, description: 'Claude config directory', severity: 'critical',
    risk: 'Can modify Claude Code settings and disable security hooks',
    legitimateUses: ['Configuring Claude Code'] },
  { pattern: /\.claude\/settings\.json$/i, description: 'Claude Code settings', severity: 'critical',
    risk: 'Can disable vibesafu security hook - potential prompt injection attack',
    legitimateUses: ['Manually configuring Claude Code'] },

  // vibesafu self-protection - Critical
  { pattern: /vibesafu?\//i, description: 'vibesafu directory', severity: 'critical',
    risk: 'Modifying security tool could disable protection - potential prompt injection attack',
    legitimateUses: ['vibesafu development', 'Legitimate updates'] },
];

/**
 * Sensitive paths for read operations
 * Includes secrets that could be exfiltrated
 */
const READ_SENSITIVE_PATHS: SensitivePath[] = [
  // Private keys - Critical
  { pattern: /\.ssh\/id_rsa$/i, description: 'SSH private key (RSA)', severity: 'critical',
    risk: 'Private key can be used to access all your SSH-protected servers',
    legitimateUses: ['Backing up keys', 'Key migration'] },
  { pattern: /\.ssh\/id_ed25519$/i, description: 'SSH private key (Ed25519)', severity: 'critical',
    risk: 'Private key can be used to access all your SSH-protected servers',
    legitimateUses: ['Backing up keys', 'Key migration'] },
  { pattern: /\.ssh\/id_ecdsa$/i, description: 'SSH private key (ECDSA)', severity: 'critical',
    risk: 'Private key can be used to access all your SSH-protected servers',
    legitimateUses: ['Backing up keys', 'Key migration'] },
  { pattern: /\.ssh\/id_dsa$/i, description: 'SSH private key (DSA)', severity: 'critical',
    risk: 'Private key can be used to access all your SSH-protected servers',
    legitimateUses: ['Backing up keys', 'Key migration'] },
  { pattern: /\.pem$/i, description: 'PEM private key', severity: 'critical',
    risk: 'Private key file - could grant access to servers or services',
    legitimateUses: ['Certificate management', 'Server configuration'] },
  { pattern: /\.key$/i, description: 'Private key file', severity: 'critical',
    risk: 'Private key file - could grant access to servers or services',
    legitimateUses: ['Certificate management', 'SSL configuration'] },

  // Cloud credentials - Critical
  { pattern: /\.aws\/credentials$/i, description: 'AWS credentials', severity: 'critical',
    risk: 'Full access to your AWS account - can create resources, access data',
    legitimateUses: ['Credential rotation', 'Backup'] },
  { pattern: /\.azure\/credentials$/i, description: 'Azure credentials', severity: 'critical',
    risk: 'Full access to your Azure account',
    legitimateUses: ['Credential rotation', 'Backup'] },

  // Environment files - High
  { pattern: /\.env$/i, description: 'Environment file', severity: 'high',
    risk: 'Contains API keys, database passwords, and other secrets',
    legitimateUses: ['Debugging', 'Environment setup', 'Configuration review'] },
  { pattern: /\.env\.local$/i, description: 'Local environment file', severity: 'high',
    risk: 'Contains local development secrets',
    legitimateUses: ['Debugging', 'Local development'] },
  { pattern: /\.env\.production$/i, description: 'Production environment file', severity: 'high',
    risk: 'Contains production secrets - highest value target',
    legitimateUses: ['Deployment configuration', 'Debugging production issues'] },
  { pattern: /\.env\.development$/i, description: 'Development environment file', severity: 'high',
    risk: 'Contains development secrets',
    legitimateUses: ['Development setup'] },

  // Password/credential files - Critical
  { pattern: /^\/etc\/shadow$/i, description: 'System shadow file', severity: 'critical',
    risk: 'Contains hashed passwords for all system users',
    legitimateUses: ['System administration', 'Security auditing'] },
  { pattern: /^\/etc\/passwd$/i, description: 'System passwd file', severity: 'high',
    risk: 'Contains user account information',
    legitimateUses: ['System administration', 'User management'] },

  // Browser/app credentials
  { pattern: /\.netrc$/i, description: 'Netrc credentials', severity: 'critical',
    risk: 'Contains plaintext passwords for FTP/HTTP authentication',
    legitimateUses: ['Credential management'] },
  { pattern: /\.docker\/config\.json$/i, description: 'Docker config (may contain tokens)', severity: 'high',
    risk: 'May contain registry authentication tokens',
    legitimateUses: ['Docker configuration', 'Registry setup'] },

  // Keychain/secret stores
  { pattern: /\.gnupg\/private-keys/i, description: 'GPG private keys', severity: 'critical',
    risk: 'Can decrypt messages and sign as you',
    legitimateUses: ['Key backup', 'Key migration'] },
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
 * Returns warning info instead of blocking
 */
export function checkFilePath(filePath: string, action: FileToolAction): FileCheckResult {
  const normalized = normalizePath(filePath);

  if (action === 'read') {
    for (const { pattern, description, severity, risk, legitimateUses } of READ_SENSITIVE_PATHS) {
      if (pattern.test(normalized)) {
        return {
          blocked: true,
          reason: `Reading ${description} (${normalized})`,
          severity,
          risk,
          legitimateUses,
        };
      }
    }
  } else {
    // Write or Edit
    for (const { pattern, description, severity, risk, legitimateUses } of WRITE_SENSITIVE_PATHS) {
      if (pattern.test(normalized)) {
        return {
          blocked: true,
          reason: `${action === 'write' ? 'Writing to' : 'Editing'} ${description} (${normalized})`,
          severity,
          risk,
          legitimateUses,
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
