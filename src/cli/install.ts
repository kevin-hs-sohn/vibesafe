/**
 * CLI Install Command
 * Installs VibeSafe hook to Claude Code settings
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CLAUDE_SETTINGS_PATH = join(homedir(), '.claude', 'settings.json');

interface ClaudeSettings {
  hooks?: {
    PermissionRequest?: Array<{
      matcher: string;
      hooks: Array<{
        type: string;
        command: string;
      }>;
    }>;
  };
  [key: string]: unknown;
}

const VIBESAFE_HOOK = {
  matcher: '*',
  hooks: [
    {
      type: 'command',
      command: 'npx vibesafe check',
    },
  ],
};

/**
 * Read Claude settings file
 */
async function readClaudeSettings(): Promise<ClaudeSettings> {
  try {
    const content = await readFile(CLAUDE_SETTINGS_PATH, 'utf-8');
    return JSON.parse(content) as ClaudeSettings;
  } catch {
    // File doesn't exist or is invalid, return empty settings
    return {};
  }
}

/**
 * Write Claude settings file
 */
async function writeClaudeSettings(settings: ClaudeSettings): Promise<void> {
  const dir = join(homedir(), '.claude');
  await mkdir(dir, { recursive: true });
  await writeFile(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2));
}

/**
 * Check if VibeSafe hook is already installed
 */
function isHookInstalled(settings: ClaudeSettings): boolean {
  const hooks = settings.hooks?.PermissionRequest ?? [];
  return hooks.some((h) =>
    h.hooks.some((hook) => hook.command.includes('vibesafe'))
  );
}

/**
 * Install VibeSafe hook
 */
export async function install(): Promise<void> {
  console.log('Installing VibeSafe hook...');

  const settings = await readClaudeSettings();

  if (isHookInstalled(settings)) {
    console.log('VibeSafe hook is already installed.');
    return;
  }

  // Initialize hooks structure if needed
  if (!settings.hooks) {
    settings.hooks = {};
  }
  if (!settings.hooks.PermissionRequest) {
    settings.hooks.PermissionRequest = [];
  }

  // Add VibeSafe hook
  settings.hooks.PermissionRequest.push(VIBESAFE_HOOK);

  await writeClaudeSettings(settings);

  console.log('VibeSafe hook installed successfully!');
  console.log(`Settings file: ${CLAUDE_SETTINGS_PATH}`);
  console.log('');
  console.log('Next steps:');
  console.log('  1. Run "vibesafe config" to set up your Anthropic API key');
  console.log('  2. Restart Claude Code to activate the hook');
}

/**
 * Uninstall VibeSafe hook
 */
export async function uninstall(): Promise<void> {
  console.log('Uninstalling VibeSafe hook...');

  const settings = await readClaudeSettings();

  if (!isHookInstalled(settings)) {
    console.log('VibeSafe hook is not installed.');
    return;
  }

  // Remove VibeSafe hooks
  if (settings.hooks?.PermissionRequest) {
    settings.hooks.PermissionRequest = settings.hooks.PermissionRequest.filter(
      (h) => !h.hooks.some((hook) => hook.command.includes('vibesafe'))
    );

    // Clean up empty arrays
    if (settings.hooks.PermissionRequest.length === 0) {
      delete settings.hooks.PermissionRequest;
    }
    if (Object.keys(settings.hooks).length === 0) {
      delete settings.hooks;
    }
  }

  await writeClaudeSettings(settings);

  console.log('VibeSafe hook uninstalled successfully!');
}
