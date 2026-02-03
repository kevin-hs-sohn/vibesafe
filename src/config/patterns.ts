/**
 * Security patterns for instant block and checkpoint detection
 */

import type { BlockPattern } from '../types.js';

// =============================================================================
// Instant Block Patterns - Always block without LLM
// =============================================================================

export const REVERSE_SHELL_PATTERNS: BlockPattern[] = [
  // Bash variants
  {
    name: 'bash_reverse_shell',
    pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Bash reverse shell via /dev/tcp',
  },
  {
    name: 'sh_reverse_shell',
    pattern: /\bsh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'sh reverse shell via /dev/tcp',
  },
  {
    name: 'zsh_reverse_shell',
    pattern: /zsh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Zsh reverse shell via /dev/tcp',
  },
  {
    name: 'ksh_reverse_shell',
    pattern: /ksh\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Ksh reverse shell via /dev/tcp',
  },
  {
    name: 'dash_reverse_shell',
    pattern: /dash\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Dash reverse shell via /dev/tcp',
  },
  // Generic /dev/tcp pattern (catches variable expansion bypasses)
  {
    name: 'dev_tcp_redirect',
    pattern: />\s*&?\s*\/dev\/tcp\//i,
    severity: 'critical',
    description: 'Redirection to /dev/tcp (reverse shell indicator)',
  },
  // Netcat variants
  {
    name: 'netcat_reverse_shell',
    pattern: /nc\s+.*-e\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Netcat reverse shell with -e flag',
  },
  {
    name: 'netcat_c_flag',
    pattern: /nc\s+.*-c\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Netcat reverse shell with -c flag',
  },
  {
    name: 'ncat_reverse_shell',
    pattern: /ncat\s+.*-e\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Ncat reverse shell',
  },
  // Python reverse shells
  {
    name: 'python_reverse_shell',
    pattern: /python[23]?\s+.*-c\s+.*socket.*connect/i,
    severity: 'critical',
    description: 'Python socket-based reverse shell',
  },
  {
    name: 'python_pty_shell',
    pattern: /python[23]?\s+.*-c\s+.*pty\.spawn/i,
    severity: 'critical',
    description: 'Python PTY spawn (shell upgrade)',
  },
  // Perl reverse shell
  {
    name: 'perl_reverse_shell',
    pattern: /perl\s+.*(-e\s+.*)?(['"])?use\s+Socket/i,
    severity: 'critical',
    description: 'Perl socket-based reverse shell',
  },
  // Ruby reverse shell
  {
    name: 'ruby_reverse_shell',
    pattern: /ruby\s+.*-rsocket\s+-e/i,
    severity: 'critical',
    description: 'Ruby socket-based reverse shell',
  },
  {
    name: 'ruby_socket_reverse',
    pattern: /ruby\s+.*-e\s+.*TCPSocket/i,
    severity: 'critical',
    description: 'Ruby TCPSocket reverse shell',
  },
  // PHP reverse shell
  {
    name: 'php_reverse_shell',
    pattern: /php\s+.*-r\s+.*fsockopen/i,
    severity: 'critical',
    description: 'PHP fsockopen reverse shell',
  },
  // Socat
  {
    name: 'socat_reverse_shell',
    pattern: /socat\s+.*exec.*sh/i,
    severity: 'critical',
    description: 'Socat reverse shell',
  },
  // Telnet reverse shell
  {
    name: 'telnet_reverse_shell',
    pattern: /telnet\s+.*\|\s*\/bin\/(ba)?sh/i,
    severity: 'critical',
    description: 'Telnet-based reverse shell',
  },
];

export const DATA_EXFIL_PATTERNS: BlockPattern[] = [
  // Environment variable exfiltration via curl
  {
    name: 'curl_api_key',
    pattern: /curl.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'curl with API key environment variable',
  },
  {
    name: 'curl_secret',
    pattern: /curl.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'curl with secret environment variable',
  },
  {
    name: 'curl_token',
    pattern: /curl.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'curl with token environment variable',
  },
  {
    name: 'curl_password',
    pattern: /curl.*\$\{?[A-Z_]*PASSWORD/i,
    severity: 'critical',
    description: 'curl with password environment variable',
  },
  {
    name: 'curl_credential',
    pattern: /curl.*\$\{?[A-Z_]*CREDENTIAL/i,
    severity: 'critical',
    description: 'curl with credential environment variable',
  },
  // Environment variable exfiltration via wget
  {
    name: 'wget_key',
    pattern: /wget.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'wget with API key environment variable',
  },
  {
    name: 'wget_secret',
    pattern: /wget.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'wget with secret environment variable',
  },
  {
    name: 'wget_token',
    pattern: /wget.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'wget with token environment variable',
  },
  // POST data with env vars
  {
    name: 'curl_data_env',
    pattern: /curl\s+.*(-d|--data|--data-raw)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl POST with environment variable in data',
  },
  {
    name: 'curl_header_env',
    pattern: /curl\s+.*(-H|--header)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl with environment variable in header',
  },
  {
    name: 'wget_post_env',
    pattern: /wget\s+.*--post-data.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'wget POST with environment variable',
  },
  {
    name: 'wget_header_env',
    pattern: /wget\s+.*--header.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'wget with environment variable in header',
  },
  // Full environment dump
  {
    name: 'env_pipe_curl',
    pattern: /\benv\b.*\|\s*curl/i,
    severity: 'critical',
    description: 'Environment dump piped to curl',
  },
  {
    name: 'printenv_pipe',
    pattern: /printenv.*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'Printenv piped to network command',
  },
  {
    name: 'env_pipe_nc',
    pattern: /\benv\b.*\|\s*nc\b/i,
    severity: 'critical',
    description: 'Environment dump piped to netcat',
  },
  // Sensitive file exfiltration
  {
    name: 'ssh_key_exfil',
    pattern: /cat\s+.*\.ssh\/(id_rsa|id_ed25519|id_dsa).*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'SSH private key exfiltration',
  },
  {
    name: 'aws_creds_exfil',
    pattern: /cat\s+.*\.aws\/(credentials|config).*\|\s*(curl|nc|wget)/i,
    severity: 'critical',
    description: 'AWS credentials exfiltration',
  },
  {
    name: 'file_stdin_curl',
    pattern: /curl\s+.*-d\s*@-/i,
    severity: 'high',
    description: 'curl reading from stdin (potential data exfil)',
  },
  // Reverse copy tools
  {
    name: 'scp_outbound',
    pattern: /scp\s+.*[^@]+@[^:]+:/i,
    severity: 'high',
    description: 'scp to remote host (potential data exfil)',
  },
  {
    name: 'rsync_outbound',
    pattern: /rsync\s+.*[^@]+@/i,
    severity: 'high',
    description: 'rsync to remote host (potential data exfil)',
  },
  // Backtick command substitution with env vars
  {
    name: 'backtick_env_exfil',
    pattern: /curl.*`.*\$[A-Z_]+.*`/i,
    severity: 'critical',
    description: 'curl with backtick command substitution containing env var',
  },
  // DNS tunneling patterns
  {
    name: 'dns_tunnel_dig',
    pattern: /dig\s+.*\$[A-Z_]/i,
    severity: 'high',
    description: 'DNS query with environment variable (potential DNS tunnel)',
  },
  {
    name: 'dns_tunnel_nslookup',
    pattern: /nslookup\s+.*\$[A-Z_]/i,
    severity: 'high',
    description: 'nslookup with environment variable (potential DNS tunnel)',
  },
];

export const CRYPTO_MINING_PATTERNS: BlockPattern[] = [
  {
    name: 'xmrig',
    pattern: /xmrig/i,
    severity: 'critical',
    description: 'XMRig cryptocurrency miner',
  },
  {
    name: 'minerd',
    pattern: /minerd/i,
    severity: 'critical',
    description: 'Minerd cryptocurrency miner',
  },
  {
    name: 'cgminer',
    pattern: /cgminer/i,
    severity: 'critical',
    description: 'CGMiner cryptocurrency miner',
  },
  {
    name: 'bfgminer',
    pattern: /bfgminer/i,
    severity: 'critical',
    description: 'BFGMiner cryptocurrency miner',
  },
  {
    name: 'stratum_protocol',
    pattern: /stratum\+tcp/i,
    severity: 'critical',
    description: 'Stratum mining protocol',
  },
];

export const OBFUSCATED_EXEC_PATTERNS: BlockPattern[] = [
  {
    name: 'base64_pipe_bash',
    pattern: /\|\s*base64\s+-d\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode piped to shell',
  },
  {
    name: 'base64_decode_bash',
    pattern: /base64\s+(-d|--decode)\s+\S+\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode from file piped to shell',
  },
  {
    name: 'eval_base64_decode',
    pattern: /eval\s*\(\s*base64_decode/i,
    severity: 'critical',
    description: 'PHP-style eval with base64 decode',
  },
  // Bypass techniques
  {
    name: 'eval_curl',
    pattern: /eval\s+.*\$\(.*curl/i,
    severity: 'critical',
    description: 'eval with curl command substitution',
  },
  {
    name: 'eval_wget',
    pattern: /eval\s+.*\$\(.*wget/i,
    severity: 'critical',
    description: 'eval with wget command substitution',
  },
  {
    name: 'bash_herestring_curl',
    pattern: /bash\s+<<<\s*.*\$\(.*curl/i,
    severity: 'critical',
    description: 'bash here-string with curl',
  },
  {
    name: 'bash_process_sub',
    pattern: /bash\s+<\(.*curl/i,
    severity: 'critical',
    description: 'bash process substitution with curl',
  },
  {
    name: 'bash_process_sub_wget',
    pattern: /bash\s+<\(.*wget/i,
    severity: 'critical',
    description: 'bash process substitution with wget',
  },
];

export const DESTRUCTIVE_PATTERNS: BlockPattern[] = [
  {
    name: 'rm_rf_root',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*.*\s+\/(\s|$|;|&)/i,
    severity: 'critical',
    description: 'rm -rf on root directory',
  },
  {
    name: 'rm_rf_home',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*.*\s+(~|\/home|\$HOME)/i,
    severity: 'critical',
    description: 'rm -rf on home directory',
  },
  {
    name: 'rm_rf_star',
    pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*\s+\*/i,
    severity: 'critical',
    description: 'rm -rf with wildcard',
  },
  {
    name: 'mkfs_format',
    pattern: /mkfs(\.[a-z0-9]+)?\s+\/dev\//i,
    severity: 'critical',
    description: 'mkfs filesystem format on device',
  },
  {
    name: 'dd_destructive',
    pattern: /dd\s+.*of=\/dev\/[hs]d/i,
    severity: 'critical',
    description: 'dd write to disk device',
  },
  {
    name: 'dd_zero_device',
    pattern: /dd\s+.*if=\/dev\/(zero|urandom).*of=\/dev\//i,
    severity: 'critical',
    description: 'dd zero/random write to device',
  },
  {
    name: 'fork_bomb',
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/,
    severity: 'critical',
    description: 'Fork bomb',
  },
  {
    name: 'fork_bomb_variant',
    pattern: /\w+\(\)\s*\{\s*\w+\s*\|\s*\w+\s*&\s*\}\s*;?\s*\w+/,
    severity: 'critical',
    description: 'Fork bomb variant',
  },
  {
    name: 'chmod_recursive_777',
    pattern: /chmod\s+(-R|--recursive)\s+777\s+\//i,
    severity: 'critical',
    description: 'chmod 777 recursive on system directories',
  },
  {
    name: 'chown_recursive_root',
    pattern: /chown\s+(-R|--recursive)\s+.*\s+\/(\s|$)/i,
    severity: 'critical',
    description: 'chown recursive on root',
  },
];

// All instant block patterns combined
export const INSTANT_BLOCK_PATTERNS: BlockPattern[] = [
  ...REVERSE_SHELL_PATTERNS,
  ...DATA_EXFIL_PATTERNS,
  ...CRYPTO_MINING_PATTERNS,
  ...OBFUSCATED_EXEC_PATTERNS,
  ...DESTRUCTIVE_PATTERNS,
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

  // Git operations (only dangerous ones - safe git commands handled by instant-allow)
  { pattern: /git\s+push/i, type: 'git_operation', description: 'git push' },
  { pattern: /git\s+reset\s+--hard/i, type: 'git_operation', description: 'git reset --hard' },
  { pattern: /git\s+.*--force/i, type: 'git_operation', description: 'git force operation' },
  { pattern: /git\s+clean\s+-[a-z]*f/i, type: 'git_operation', description: 'git clean with force' },

  // Environment files
  { pattern: /\.env(?:\.local|\.production|\.development)?(?:\s|$|["'])/i, type: 'env_modification', description: '.env file access' },

  // Sensitive files
  { pattern: /\.ssh/i, type: 'file_sensitive', description: 'SSH directory access' },
  { pattern: /\.aws/i, type: 'file_sensitive', description: 'AWS credentials access' },
  { pattern: /credentials/i, type: 'file_sensitive', description: 'Credentials file access' },
  { pattern: /CLAUDE\.md/i, type: 'file_sensitive', description: 'CLAUDE.md modification' },
];
