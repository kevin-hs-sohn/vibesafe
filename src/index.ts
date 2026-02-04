#!/usr/bin/env node

/**
 * VibeSafu CLI - Claude Code Security Guard
 *
 * Commands:
 *   install   - Install hook to ~/.claude/settings.json
 *   uninstall - Remove hook from settings
 *   check     - Run security check (stdin: PermissionRequest JSON)
 *   config    - Configure API key and settings
 */

import { parseArgs } from 'node:util';
import { install, uninstall } from './cli/install.js';
import { config } from './cli/config.js';
import { check } from './cli/check.js';

const COMMANDS = ['install', 'uninstall', 'check', 'config'] as const;
type Command = (typeof COMMANDS)[number];

async function main(): Promise<void> {
  const { positionals } = parseArgs({
    allowPositionals: true,
    strict: false,
  });

  const command = positionals[0] as Command | undefined;

  if (!command || !COMMANDS.includes(command)) {
    console.error('VibeSafu - Claude Code Security Guard');
    console.error('');
    console.error(`Usage: vibesafu <${COMMANDS.join('|')}>`);
    console.error('');
    console.error('Commands:');
    console.error('  install   - Install security hook to Claude Code');
    console.error('  uninstall - Remove security hook');
    console.error('  check     - Run security check (stdin: PermissionRequest JSON)');
    console.error('  config    - Configure API key and settings');
    process.exit(1);
  }

  switch (command) {
    case 'install':
      await install();
      break;
    case 'uninstall':
      await uninstall();
      break;
    case 'check':
      await check();
      break;
    case 'config':
      await config();
      break;
  }
}

main().catch((error: Error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
