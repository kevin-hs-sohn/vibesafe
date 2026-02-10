/**
 * Security patterns for instant block and checkpoint detection
 */

import type { BlockPattern } from '../types.js';

// =============================================================================
// Instant Block Patterns - Always block without LLM
// =============================================================================

const REVERSE_SHELL_RISK = 'Remote attacker gains complete control of your system';
const REVERSE_SHELL_LEGIT = ['Penetration testing', 'CTF challenges', 'Security research'];

export const REVERSE_SHELL_PATTERNS: BlockPattern[] = [
  // Bash variants
  {
    name: 'bash_reverse_shell',
    pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Bash reverse shell via /dev/tcp',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'sh_reverse_shell',
    pattern: /\bsh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'sh reverse shell via /dev/tcp',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'zsh_reverse_shell',
    pattern: /zsh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Zsh reverse shell via /dev/tcp',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'ksh_reverse_shell',
    pattern: /ksh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Ksh reverse shell via /dev/tcp',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'dash_reverse_shell',
    pattern: /dash\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Dash reverse shell via /dev/tcp',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Generic /dev/tcp pattern (catches variable expansion bypasses)
  {
    name: 'dev_tcp_redirect',
    pattern: />\s*&?\s*\/dev\/tcp\//i,
    severity: 'critical',
    description: 'Redirection to /dev/tcp (reverse shell indicator)',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Netcat variants
  {
    name: 'netcat_reverse_shell',
    pattern: /nc\s+.*-e\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Netcat reverse shell with -e flag',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'netcat_c_flag',
    pattern: /nc\s+.*-c\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Netcat reverse shell with -c flag',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'ncat_reverse_shell',
    pattern: /ncat\s+.*-e\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Ncat reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Python reverse shells
  {
    name: 'python_reverse_shell',
    pattern: /python[23]?\s+.*-c\s+.*socket.*connect/i,
    severity: 'critical',
    description: 'Python socket-based reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'python_pty_shell',
    pattern: /python[23]?\s+.*-c\s+.*pty\.spawn/i,
    severity: 'critical',
    description: 'Python PTY spawn (shell upgrade)',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Perl reverse shell
  {
    name: 'perl_reverse_shell',
    pattern: /perl\s+.*(-e\s+.*)?(['"])?use\s+Socket/i,
    severity: 'critical',
    description: 'Perl socket-based reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Ruby reverse shell
  {
    name: 'ruby_reverse_shell',
    pattern: /ruby\s+.*-rsocket\s+-e/i,
    severity: 'critical',
    description: 'Ruby socket-based reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  {
    name: 'ruby_socket_reverse',
    pattern: /ruby\s+.*-e\s+.*TCPSocket/i,
    severity: 'critical',
    description: 'Ruby TCPSocket reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // PHP reverse shell
  {
    name: 'php_reverse_shell',
    pattern: /php\s+.*-r\s+.*fsockopen/i,
    severity: 'critical',
    description: 'PHP fsockopen reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Socat
  {
    name: 'socat_reverse_shell',
    pattern: /socat\s+.*exec.*sh/i,
    severity: 'critical',
    description: 'Socat reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
  // Telnet reverse shell
  {
    name: 'telnet_reverse_shell',
    pattern: /telnet\s+.*\|\s*\/bin\/(ba)?sh/i,
    severity: 'critical',
    description: 'Telnet-based reverse shell',
    risk: REVERSE_SHELL_RISK,
    legitimateUses: REVERSE_SHELL_LEGIT,
  },
];

const DATA_EXFIL_RISK = 'Sensitive data (API keys, secrets, credentials) sent to external server';
const DATA_EXFIL_LEGIT = ['Sending auth headers to your own API', 'Debugging with trusted services'];

export const DATA_EXFIL_PATTERNS: BlockPattern[] = [
  // Environment variable exfiltration via curl
  {
    name: 'curl_api_key',
    pattern: /curl.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'curl with API key environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'curl_secret',
    pattern: /curl.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'curl with secret environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'curl_token',
    pattern: /curl.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'curl with token environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'curl_password',
    pattern: /curl.*\$\{?[A-Z_]*PASSWORD/i,
    severity: 'critical',
    description: 'curl with password environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'curl_credential',
    pattern: /curl.*\$\{?[A-Z_]*CREDENTIAL/i,
    severity: 'critical',
    description: 'curl with credential environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  // Environment variable exfiltration via wget
  {
    name: 'wget_key',
    pattern: /wget.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'wget with API key environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'wget_secret',
    pattern: /wget.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'wget with secret environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'wget_token',
    pattern: /wget.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'wget with token environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  // POST data with env vars
  {
    name: 'curl_data_env',
    pattern: /curl\s+.*(-d|--data|--data-raw)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl POST with environment variable in data',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'curl_header_env',
    pattern: /curl\s+.*(-H|--header)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl with environment variable in header',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'wget_post_env',
    pattern: /wget\s+.*--post-data.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'wget POST with environment variable',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  {
    name: 'wget_header_env',
    pattern: /wget\s+.*--header.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'wget with environment variable in header',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  // Full environment dump
  {
    name: 'env_pipe_curl',
    pattern: /\benv\b.*\|\s*curl/i,
    severity: 'critical',
    description: 'Environment dump piped to curl',
    risk: 'All environment variables (including secrets) sent to external server',
    legitimateUses: ['Debugging in controlled environment'],
  },
  {
    name: 'printenv_pipe',
    pattern: /printenv.*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'Printenv piped to network command',
    risk: 'All environment variables sent to external server',
    legitimateUses: ['Debugging in controlled environment'],
  },
  {
    name: 'env_pipe_nc',
    pattern: /\benv\b.*\|\s*nc\b/i,
    severity: 'critical',
    description: 'Environment dump piped to netcat',
    risk: 'All environment variables sent to external server',
    legitimateUses: ['Debugging in controlled environment'],
  },
  // Sensitive file exfiltration
  {
    name: 'ssh_key_exfil',
    pattern: /cat\s+.*\.ssh\/(id_rsa|id_ed25519|id_dsa).*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'SSH private key exfiltration',
    risk: 'SSH private key sent to external server - attacker can access your servers',
    legitimateUses: ['Backing up keys to your own secure storage'],
  },
  {
    name: 'aws_creds_exfil',
    pattern: /cat\s+.*\.aws\/(credentials|config).*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'AWS credentials exfiltration',
    risk: 'AWS credentials sent to external server - attacker gains cloud access',
    legitimateUses: ['Backing up config to your own secure storage'],
  },
  {
    name: 'file_stdin_curl',
    pattern: /curl\s+.*-d\s*@-/i,
    severity: 'high',
    description: 'curl reading from stdin (potential data exfil)',
    risk: 'Piped data sent to external server',
    legitimateUses: ['Uploading files to your own API', 'CI/CD pipelines'],
  },
  // Reverse copy tools
  {
    name: 'scp_outbound',
    pattern: /scp\s+.*[^@]+@[^:]+:/i,
    severity: 'high',
    description: 'scp to remote host (potential data exfil)',
    risk: 'Files copied to remote server',
    legitimateUses: ['Deploying to your servers', 'Backup operations'],
  },
  {
    name: 'rsync_outbound',
    pattern: /rsync\s+.*[^@]+@/i,
    severity: 'high',
    description: 'rsync to remote host (potential data exfil)',
    risk: 'Files synced to remote server',
    legitimateUses: ['Deploying to your servers', 'Backup operations'],
  },
  // Backtick command substitution with env vars
  {
    name: 'backtick_env_exfil',
    pattern: /curl.*`.*\$[A-Z_]+.*`/i,
    severity: 'critical',
    description: 'curl with backtick command substitution containing env var',
    risk: DATA_EXFIL_RISK,
    legitimateUses: DATA_EXFIL_LEGIT,
  },
  // DNS tunneling patterns
  {
    name: 'dns_tunnel_dig',
    pattern: /dig\s+.*\$[A-Z_]/i,
    severity: 'high',
    description: 'DNS query with environment variable (potential DNS tunnel)',
    risk: 'Data exfiltration via DNS queries - bypasses firewalls',
    legitimateUses: ['Dynamic DNS lookups', 'DNS debugging'],
  },
  {
    name: 'dns_tunnel_nslookup',
    pattern: /nslookup\s+.*\$[A-Z_]/i,
    severity: 'high',
    description: 'nslookup with environment variable (potential DNS tunnel)',
    risk: 'Data exfiltration via DNS queries - bypasses firewalls',
    legitimateUses: ['Dynamic DNS lookups', 'DNS debugging'],
  },
];

const CRYPTO_RISK = 'Uses your CPU/GPU for cryptocurrency mining, slowing system and increasing power costs';
const CRYPTO_LEGIT = ['Intentional mining on your own hardware', 'Mining pool testing'];

export const CRYPTO_MINING_PATTERNS: BlockPattern[] = [
  {
    name: 'xmrig',
    pattern: /xmrig/i,
    severity: 'critical',
    description: 'XMRig cryptocurrency miner',
    risk: CRYPTO_RISK,
    legitimateUses: CRYPTO_LEGIT,
  },
  {
    name: 'minerd',
    pattern: /minerd/i,
    severity: 'critical',
    description: 'Minerd cryptocurrency miner',
    risk: CRYPTO_RISK,
    legitimateUses: CRYPTO_LEGIT,
  },
  {
    name: 'cgminer',
    pattern: /cgminer/i,
    severity: 'critical',
    description: 'CGMiner cryptocurrency miner',
    risk: CRYPTO_RISK,
    legitimateUses: CRYPTO_LEGIT,
  },
  {
    name: 'bfgminer',
    pattern: /bfgminer/i,
    severity: 'critical',
    description: 'BFGMiner cryptocurrency miner',
    risk: CRYPTO_RISK,
    legitimateUses: CRYPTO_LEGIT,
  },
  {
    name: 'stratum_protocol',
    pattern: /stratum\+tcp/i,
    severity: 'critical',
    description: 'Stratum mining protocol',
    risk: CRYPTO_RISK,
    legitimateUses: CRYPTO_LEGIT,
  },
];

const OBFUSCATED_RISK = 'Hidden/encoded commands executed - content cannot be reviewed before running';
const OBFUSCATED_LEGIT = ['Running encoded payloads in security testing', 'Decoding legitimate scripts'];

export const OBFUSCATED_EXEC_PATTERNS: BlockPattern[] = [
  {
    name: 'base64_pipe_bash',
    pattern: /\|\s*base64\s+-d\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode piped to shell',
    risk: OBFUSCATED_RISK,
    legitimateUses: OBFUSCATED_LEGIT,
  },
  {
    name: 'base64_decode_bash',
    pattern: /base64\s+(-d|--decode)\s+\S+\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode from file piped to shell',
    risk: OBFUSCATED_RISK,
    legitimateUses: OBFUSCATED_LEGIT,
  },
  {
    name: 'eval_base64_decode',
    pattern: /eval\s*\(\s*base64_decode/i,
    severity: 'critical',
    description: 'PHP-style eval with base64 decode',
    risk: OBFUSCATED_RISK,
    legitimateUses: OBFUSCATED_LEGIT,
  },
  // Bypass techniques
  {
    name: 'eval_curl',
    pattern: /eval\s+.*\$\(.*curl/i,
    severity: 'critical',
    description: 'eval with curl command substitution',
    risk: 'Remote code downloaded and executed immediately',
    legitimateUses: ['Running installer scripts you trust'],
  },
  {
    name: 'eval_wget',
    pattern: /eval\s+.*\$\(.*wget/i,
    severity: 'critical',
    description: 'eval with wget command substitution',
    risk: 'Remote code downloaded and executed immediately',
    legitimateUses: ['Running installer scripts you trust'],
  },
  {
    name: 'bash_herestring_curl',
    pattern: /bash\s+<<<\s*.*\$\(.*curl/i,
    severity: 'critical',
    description: 'bash here-string with curl',
    risk: 'Remote code downloaded and executed via here-string',
    legitimateUses: ['Running installer scripts you trust'],
  },
  {
    name: 'bash_process_sub',
    pattern: /bash\s+<\(.*curl/i,
    severity: 'critical',
    description: 'bash process substitution with curl',
    risk: 'Remote code downloaded and executed via process substitution',
    legitimateUses: ['Running installer scripts you trust'],
  },
  {
    name: 'bash_process_sub_wget',
    pattern: /bash\s+<\(.*wget/i,
    severity: 'critical',
    description: 'bash process substitution with wget',
    risk: 'Remote code downloaded and executed via process substitution',
    legitimateUses: ['Running installer scripts you trust'],
  },
];

export const DESTRUCTIVE_PATTERNS: BlockPattern[] = [
  {
    name: 'rm_rf_root',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*.*\s+\/(\s|$|;|&)/i,
    severity: 'critical',
    description: 'rm -rf on root directory',
    risk: 'Deletes entire filesystem - complete data loss, unbootable system',
    legitimateUses: ['Wiping a system intentionally before reinstall'],
  },
  {
    name: 'rm_rf_home',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*.*\s+(~|\/home|\$HOME)/i,
    severity: 'critical',
    description: 'rm -rf on home directory',
    risk: 'Deletes all user files - documents, configs, ssh keys, everything',
    legitimateUses: ['Cleaning up a user account before deletion'],
  },
  {
    name: 'rm_rf_star',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*\s+\*/i,
    severity: 'critical',
    description: 'rm -rf with wildcard',
    risk: 'Deletes all files in current directory recursively',
    legitimateUses: ['Cleaning build artifacts', 'Resetting test environment'],
  },
  {
    name: 'mkfs_format',
    pattern: /mkfs(\.[a-z0-9]+)?\s+\/dev\//i,
    severity: 'critical',
    description: 'mkfs filesystem format on device',
    risk: 'Formats disk - all data on device will be permanently lost',
    legitimateUses: ['Setting up new disk', 'Creating bootable drives'],
  },
  {
    name: 'dd_destructive',
    pattern: /dd\s+.*of=\/dev\/[hs]d/i,
    severity: 'critical',
    description: 'dd write to disk device',
    risk: 'Overwrites disk directly - data loss, potential boot failure',
    legitimateUses: ['Creating bootable USB', 'Disk imaging'],
  },
  {
    name: 'dd_zero_device',
    pattern: /dd\s+.*if=\/dev\/(zero|urandom).*of=\/dev\//i,
    severity: 'critical',
    description: 'dd zero/random write to device',
    risk: 'Wipes disk with zeros/random data - complete, unrecoverable data loss',
    legitimateUses: ['Secure disk wiping', 'Preparing disk for disposal'],
  },
  {
    name: 'fork_bomb',
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/,
    severity: 'critical',
    description: 'Fork bomb',
    risk: 'Creates infinite processes - system freeze, requires hard reboot',
    legitimateUses: ['Testing system limits', 'Security demonstrations'],
  },
  {
    name: 'fork_bomb_variant',
    pattern: /\w+\(\)\s*\{\s*\w+\s*\|\s*\w+\s*&\s*\}\s*;?\s*\w+/,
    severity: 'critical',
    description: 'Fork bomb variant',
    risk: 'Creates infinite processes - system freeze, requires hard reboot',
    legitimateUses: ['Testing system limits', 'Security demonstrations'],
  },
  {
    name: 'chmod_recursive_777',
    pattern: /chmod\s+(-R|--recursive)\s+777\s+\//i,
    severity: 'critical',
    description: 'chmod 777 recursive on system directories',
    risk: 'Makes all system files world-writable - severe security vulnerability',
    legitimateUses: ['Almost never legitimate on system directories'],
  },
  {
    name: 'chown_recursive_root',
    pattern: /chown\s+(-R|--recursive)\s+.*\s+\/(\s|$)/i,
    severity: 'critical',
    description: 'chown recursive on root',
    risk: 'Changes ownership of all system files - can break system',
    legitimateUses: ['System recovery operations'],
  },
];

const SELF_PROTECTION_RISK = 'Attempting to disable security monitoring - this could be a prompt injection attack';
const SELF_PROTECTION_LEGIT = ['Intentionally uninstalling vibesafu via CLI'];

export const SELF_PROTECTION_PATTERNS: BlockPattern[] = [
  // Match vibesafu uninstall at command start or after separator (;, &&, ||, |)
  // Excludes matches inside heredocs/echo/strings
  {
    name: 'vibesafu_uninstall',
    pattern: /(?:^|[;&|]\s*)vibesafu?\s+uninstall/i,
    severity: 'critical',
    description: 'Attempting to uninstall vibesafu security hook',
    risk: SELF_PROTECTION_RISK,
    legitimateUses: SELF_PROTECTION_LEGIT,
  },
  // rm command specifically targeting vibesafu
  {
    name: 'vibesafu_rm',
    pattern: /(?:^|[;&|]\s*)rm\s+(-[rf]+\s+)?.*vibesafu/i,
    severity: 'critical',
    description: 'Attempting to delete vibesafu files',
    risk: SELF_PROTECTION_RISK,
    legitimateUses: SELF_PROTECTION_LEGIT,
  },
  // Direct file operations on claude settings (cat >, >, echo >)
  {
    name: 'claude_settings_write',
    pattern: /(?:^|[;&|]\s*)(?:cat|echo|printf)\s+.*>\s*~?\/?.claude\/settings\.json/i,
    severity: 'critical',
    description: 'Attempting to overwrite Claude Code settings',
    risk: SELF_PROTECTION_RISK,
    legitimateUses: ['Manually configuring Claude Code settings'],
  },
  // sed/awk editing claude settings
  {
    name: 'claude_settings_edit',
    pattern: /(?:^|[;&|]\s*)(?:sed|awk)\s+.*\.claude\/settings\.json/i,
    severity: 'critical',
    description: 'Attempting to edit Claude Code settings',
    risk: SELF_PROTECTION_RISK,
    legitimateUses: ['Manually configuring Claude Code settings'],
  },
  // kill/pkill targeting vibesafu
  {
    name: 'vibesafu_kill',
    pattern: /(?:^|[;&|]\s*)(?:kill|pkill|killall)\s+.*vibesafu/i,
    severity: 'critical',
    description: 'Attempting to kill vibesafu process',
    risk: SELF_PROTECTION_RISK,
    legitimateUses: SELF_PROTECTION_LEGIT,
  },
];

// All instant block patterns combined
export const INSTANT_BLOCK_PATTERNS: BlockPattern[] = [
  ...REVERSE_SHELL_PATTERNS,
  ...DATA_EXFIL_PATTERNS,
  ...CRYPTO_MINING_PATTERNS,
  ...OBFUSCATED_EXEC_PATTERNS,
  ...DESTRUCTIVE_PATTERNS,
  ...SELF_PROTECTION_PATTERNS,
];

// =============================================================================
// Checkpoint Patterns - Trigger security review
// =============================================================================

export interface CheckpointPattern {
  pattern: RegExp;
  type: 'network' | 'package_install' | 'git_operation' | 'file_sensitive' | 'script_execution' | 'env_modification';
  description: string;
}

export const CHECKPOINT_PATTERNS: CheckpointPattern[] = [
  // Script execution
  { pattern: /curl\s+.*\|\s*(ba)?sh/i, type: 'script_execution', description: 'curl piped to shell' },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i, type: 'script_execution', description: 'wget piped to shell' },
  { pattern: /curl\s+.*-o\s*-\s*\|/i, type: 'script_execution', description: 'curl output piped' },
  { pattern: /chmod\s+\+x/i, type: 'script_execution', description: 'Making file executable' },
  { pattern: /\.\/[^\s]+\.sh/i, type: 'script_execution', description: 'Running shell script' },
  { pattern: /bash\s+[^\s]+\.sh/i, type: 'script_execution', description: 'Running shell script with bash' },
  { pattern: /npm\s+run\b/i, type: 'script_execution', description: 'npm run (executes package.json scripts)' },
  { pattern: /\bmake\b/i, type: 'script_execution', description: 'make (executes Makefile)' },

  // Network operations
  { pattern: /curl\s+.*?(https?:\/\/[^\s"']+)/i, type: 'network', description: 'curl HTTP request' },
  { pattern: /wget\s+.*?(https?:\/\/[^\s"']+)/i, type: 'network', description: 'wget HTTP request' },

  // Package installations
  { pattern: /npm\s+install\s+(?!-[dDgG])/i, type: 'package_install', description: 'npm install' },
  { pattern: /pnpm\s+(add|install)/i, type: 'package_install', description: 'pnpm add/install' },
  { pattern: /yarn\s+add/i, type: 'package_install', description: 'yarn add' },
  { pattern: /pip\s+install/i, type: 'package_install', description: 'pip install' },
  { pattern: /apt(-get)?\s+install/i, type: 'package_install', description: 'apt install' },
  { pattern: /brew\s+install/i, type: 'package_install', description: 'brew install' },

  // Git operations - commands that can trigger hooks or affect remote/state
  // SECURITY: git hooks (.git/hooks/) can execute arbitrary code
  // Read-only commands (status, log, diff, show, blame) are handled by instant-allow
  { pattern: /git\s+push/i, type: 'git_operation', description: 'git push' },
  { pattern: /git\s+commit/i, type: 'git_operation', description: 'git commit (triggers pre-commit, commit-msg hooks)' },
  { pattern: /git\s+checkout/i, type: 'git_operation', description: 'git checkout (triggers post-checkout hook)' },
  { pattern: /git\s+switch/i, type: 'git_operation', description: 'git switch (triggers post-checkout hook)' },
  { pattern: /git\s+merge/i, type: 'git_operation', description: 'git merge (triggers pre-merge-commit, post-merge hooks)' },
  { pattern: /git\s+rebase/i, type: 'git_operation', description: 'git rebase (triggers pre-rebase hook)' },
  { pattern: /git\s+pull/i, type: 'git_operation', description: 'git pull (triggers post-merge hook)' },
  { pattern: /git\s+fetch/i, type: 'git_operation', description: 'git fetch' },
  { pattern: /git\s+reset\s+--hard/i, type: 'git_operation', description: 'git reset --hard' },
  { pattern: /git\s+.*--force/i, type: 'git_operation', description: 'git force operation' },
  { pattern: /git\s+clean\s+-[a-z]*f/i, type: 'git_operation', description: 'git clean with force' },
  { pattern: /git\s+stash/i, type: 'git_operation', description: 'git stash' },
  { pattern: /git\s+cherry-pick/i, type: 'git_operation', description: 'git cherry-pick' },
  { pattern: /git\s+add/i, type: 'git_operation', description: 'git add' },

  // Environment files
  { pattern: /\.env(?:\.local|\.production|\.development)?(?:\s|$|["'])/i, type: 'env_modification', description: '.env file access' },

  // Sensitive files
  { pattern: /\.ssh/i, type: 'file_sensitive', description: 'SSH directory access' },
  { pattern: /\.aws/i, type: 'file_sensitive', description: 'AWS credentials access' },
  { pattern: /credentials/i, type: 'file_sensitive', description: 'Credentials file access' },

  // Sensitive file copy/move (indirect path bypass)
  { pattern: /(cp|mv)\s+.*\.ssh\//i, type: 'file_sensitive', description: 'Copying/moving SSH files' },
  { pattern: /(cp|mv)\s+.*\.aws\//i, type: 'file_sensitive', description: 'Copying/moving AWS credentials' },
  { pattern: /(cp|mv)\s+.*\.env(\s|$)/i, type: 'file_sensitive', description: 'Copying/moving .env file' },
];
