/**
 * VibeSafe Hook Handler
 * Main entry point for processing PermissionRequest events
 */

import type {
  PermissionRequestInput,
  PermissionRequestOutput,
  SecurityCheckpoint,
} from './types.js';
import { checkInstantBlock } from './guard/instant-block.js';
import { detectCheckpoint } from './guard/checkpoint.js';
import { checkTrustedDomains } from './guard/trusted-domain.js';

export type HookDecision = 'allow' | 'deny' | 'needs-review';
export type DecisionSource =
  | 'instant-block'
  | 'trusted-domain'
  | 'no-checkpoint'
  | 'checkpoint'
  | 'non-bash-tool';

export interface ProcessResult {
  decision: HookDecision;
  reason: string;
  source: DecisionSource;
  checkpoint?: SecurityCheckpoint;
}

/**
 * Process a PermissionRequest and determine if it should be allowed
 *
 * Flow:
 * 1. Non-Bash tools → Allow (only analyze Bash commands)
 * 2. Instant Block → Deny immediately
 * 3. No Checkpoint → Allow (safe command)
 * 4. Trusted Domain → Allow (script from trusted source)
 * 5. Checkpoint Triggered → Needs LLM review
 */
export async function processPermissionRequest(
  input: PermissionRequestInput
): Promise<ProcessResult> {
  // Step 1: Only analyze Bash commands
  if (input.tool_name !== 'Bash') {
    return {
      decision: 'allow',
      reason: `Tool ${input.tool_name} is not Bash, allowing`,
      source: 'non-bash-tool',
    };
  }

  const command = input.tool_input.command as string;

  // Step 2: Check for instant block patterns
  const blockResult = checkInstantBlock(command);
  if (blockResult.blocked) {
    return {
      decision: 'deny',
      reason: blockResult.reason ?? 'Blocked by instant block',
      source: 'instant-block',
    };
  }

  // Step 3: Check if command triggers a checkpoint
  const checkpoint = detectCheckpoint(command);
  if (!checkpoint) {
    return {
      decision: 'allow',
      reason: 'No security checkpoint triggered',
      source: 'no-checkpoint',
    };
  }

  // Step 4: For script execution or network, check trusted domains
  if (checkpoint.type === 'script_execution' || checkpoint.type === 'network') {
    const domainResult = checkTrustedDomains(command);
    if (domainResult.allTrusted && domainResult.urls.length > 0) {
      return {
        decision: 'allow',
        reason: `All URLs from trusted domains: ${domainResult.trustedUrls.join(', ')}`,
        source: 'trusted-domain',
      };
    }
  }

  // Step 5: Checkpoint triggered, needs LLM review
  // Without LLM integration, return needs-review
  return {
    decision: 'needs-review',
    reason: `Checkpoint triggered: ${checkpoint.type} - ${checkpoint.description}`,
    source: 'checkpoint',
    checkpoint,
  };
}

/**
 * Create the hook output in the expected format
 */
export function createHookOutput(
  decision: 'allow' | 'deny',
  message?: string
): PermissionRequestOutput {
  const output: PermissionRequestOutput = {
    hookSpecificOutput: {
      hookEventName: 'PermissionRequest',
      decision: {
        behavior: decision,
      },
    },
  };

  if (message !== undefined) {
    output.hookSpecificOutput.decision.message = message;
  }

  return output;
}

/**
 * Main hook handler - reads from stdin, writes to stdout
 */
export async function runHook(): Promise<void> {
  // Read input from stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const inputJson = Buffer.concat(chunks).toString('utf-8');

  let input: PermissionRequestInput;
  try {
    input = JSON.parse(inputJson) as PermissionRequestInput;
  } catch {
    // Invalid JSON, deny for safety
    const output = createHookOutput('deny', 'Invalid JSON input');
    console.log(JSON.stringify(output));
    return;
  }

  // Process the request
  const result = await processPermissionRequest(input);

  // Convert result to hook output
  let output: PermissionRequestOutput;

  if (result.decision === 'deny') {
    output = createHookOutput('deny', result.reason);
  } else if (result.decision === 'needs-review') {
    // Without LLM, we need to be cautious - deny with explanation
    // In future, this will call Haiku/Sonnet for analysis
    output = createHookOutput(
      'deny',
      `Security review required: ${result.reason}. Configure API key with 'vibesafe config' to enable LLM analysis.`
    );
  } else {
    output = createHookOutput('allow');
  }

  console.log(JSON.stringify(output));
}
