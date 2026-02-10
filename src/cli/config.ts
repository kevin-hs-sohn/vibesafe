/**
 * CLI Config Command
 * Configure vibesafu settings (API key, etc.)
 */

import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { vibesafuConfig } from '../types.js';

const CONFIG_DIR = join(homedir(), '.vibesafu');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

const DEFAULT_CONFIG: vibesafuConfig = {
  anthropic: {
    apiKey: '',
  },
  models: {
    triage: 'claude-haiku-4-20250514',
    review: 'claude-sonnet-4-20250514',
  },
  trustedDomains: [],
  customPatterns: {
    block: [],
    allow: [],
  },
  allowedMCPTools: [],
};

/**
 * Deep merge user config over defaults (2 levels deep)
 */
function mergeConfig(defaults: vibesafuConfig, user: Partial<vibesafuConfig>): vibesafuConfig {
  return {
    anthropic: { ...defaults.anthropic, ...user.anthropic },
    models: { ...defaults.models, ...user.models },
    trustedDomains: user.trustedDomains ?? defaults.trustedDomains,
    customPatterns: { ...defaults.customPatterns, ...user.customPatterns },
    allowedMCPTools: user.allowedMCPTools ?? defaults.allowedMCPTools,
  };
}

/**
 * Read vibesafu config
 */
export async function readConfig(): Promise<vibesafuConfig> {
  try {
    const content = await readFile(CONFIG_PATH, 'utf-8');
    return mergeConfig(DEFAULT_CONFIG, JSON.parse(content));
  } catch (error) {
    // File not found is expected on first run - no warning needed
    if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
      return DEFAULT_CONFIG;
    }
    // Other errors (permission denied, invalid JSON) should be surfaced
    const msg = error instanceof Error ? error.message : 'Unknown error';
    process.stderr.write(`[vibesafu] Warning: Failed to read config (${CONFIG_PATH}): ${msg}. Using defaults.\n`);
    return DEFAULT_CONFIG;
  }
}

/**
 * Write vibesafu config
 */
export async function writeConfig(config: vibesafuConfig): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
  // Restrict file permissions since config may contain API keys
  await chmod(CONFIG_PATH, 0o600);
}

/**
 * Prompt user for input
 */
function prompt(question: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Configure vibesafu
 */
export async function config(): Promise<void> {
  console.log('vibesafu Configuration');
  console.log('======================');
  console.log('');

  const currentConfig = await readConfig();

  // Show current status
  const hasApiKey = currentConfig.anthropic.apiKey.length > 0;
  console.log(`Current API Key: ${hasApiKey ? '***configured***' : '(not set)'}`);
  console.log(`Triage Model: ${currentConfig.models.triage}`);
  console.log(`Review Model: ${currentConfig.models.review}`);
  console.log('');

  // Prompt for API key
  const apiKey = await prompt('Enter Anthropic API Key (leave blank to keep current): ');

  if (apiKey.trim()) {
    if (!apiKey.startsWith('sk-ant-')) {
      console.log('Warning: API key should start with "sk-ant-"');
    }
    currentConfig.anthropic.apiKey = apiKey.trim();
  }

  await writeConfig(currentConfig);

  console.log('');
  console.log('Configuration saved!');
  console.log(`Config file: ${CONFIG_PATH}`);
}

