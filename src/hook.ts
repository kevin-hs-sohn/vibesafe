/**
 * VibeSafu Hook Handler
 * Main entry point for processing PermissionRequest events
 */

import Anthropic from '@anthropic-ai/sdk';
import type {
  PermissionRequestInput,
  PermissionRequestOutput,
  SecurityCheckpoint,
} from './types.js';
import { checkHighRiskPatterns } from './guard/instant-block.js';
import { checkInstantAllow } from './guard/instant-allow.js';
import { detectCheckpoint } from './guard/checkpoint.js';
import { checkTrustedDomains } from './guard/trusted-domain.js';
import { checkFileTool } from './guard/file-tools.js';
import { triageWithHaiku } from './guard/haiku-triage.js';
import { reviewWithSonnet } from './guard/sonnet-review.js';
import { getApiKey } from './cli/config.js';

/** Timeout in seconds before auto-denying risky commands */
const TIMEOUT_SECONDS = 3;

export type HookDecision = 'allow' | 'deny' | 'needs-review';
export type DecisionSource =
  | 'instant-allow'
  | 'instant-block'
  | 'high-risk'
  | 'trusted-domain'
  | 'no-checkpoint'
  | 'checkpoint'
  | 'non-bash-tool'
  | 'haiku'
  | 'sonnet';

export interface ProcessResult {
  decision: HookDecision;
  reason: string;
  source: DecisionSource;
  checkpoint?: SecurityCheckpoint;
  userMessage?: string;
}

/**
 * Process a PermissionRequest and determine if it should be allowed
 *
 * Flow:
 * 1. File Tools (Write/Edit/Read) → Check sensitive paths
 * 2. Non-Bash tools → Allow (only analyze Bash commands)
 * 3. Instant Allow → Allow safe patterns (e.g., git status) without LLM
 * 4. Instant Block → Deny immediately
 * 5. No Checkpoint → Allow (safe command)
 * 6. Trusted Domain → Allow for network-only (NOT script execution)
 * 7. Checkpoint Triggered → LLM review (Haiku → Sonnet if escalated)
 */
export async function processPermissionRequest(
  input: PermissionRequestInput,
  anthropicClient?: Anthropic
): Promise<ProcessResult> {
  // Step 1: Check file tools for sensitive path access
  if (input.tool_name === 'Write' || input.tool_name === 'Edit' || input.tool_name === 'Read') {
    const fileCheck = checkFileTool(input.tool_name, input.tool_input);
    if (fileCheck.blocked) {
      const severityLabel = fileCheck.severity === 'critical' ? 'SENSITIVE FILE' : 'CAUTION';
      const legitimateUsesText = fileCheck.legitimateUses?.length
        ? `\nCommon uses: ${fileCheck.legitimateUses.join(', ')}`
        : '';

      return {
        decision: 'needs-review',
        reason: `[${severityLabel}] ${fileCheck.reason}`,
        source: 'high-risk',
        userMessage: `[${severityLabel}] ${fileCheck.reason} (Auto-reject in ${TIMEOUT_SECONDS}s)\n\nPotential risk: ${fileCheck.risk}${legitimateUsesText}\n\nOnly proceed if you know what you're doing.`,
      };
    }
    // File tool with safe path - allow
    return {
      decision: 'allow',
      reason: `File tool ${input.tool_name} with safe path`,
      source: 'non-bash-tool',
    };
  }

  // Step 2: Other non-Bash tools → Allow
  if (input.tool_name !== 'Bash') {
    return {
      decision: 'allow',
      reason: `Tool ${input.tool_name} is not Bash, allowing`,
      source: 'non-bash-tool',
    };
  }

  const command = input.tool_input.command as string;

  // Step 3: Check for instant allow patterns (safe commands that skip LLM)
  const allowResult = checkInstantAllow(command);
  if (allowResult.allowed) {
    return {
      decision: 'allow',
      reason: allowResult.reason ?? 'Safe command pattern',
      source: 'instant-allow',
    };
  }

  // Step 4: Check for high-risk patterns (warn instead of block)
  const highRisk = checkHighRiskPatterns(command);
  if (highRisk.detected) {
    const severityLabel = highRisk.severity === 'critical' ? 'HIGH RISK' : 'CAUTION';
    const legitimateUsesText = highRisk.legitimateUses?.length
      ? `\nCommon uses: ${highRisk.legitimateUses.join(', ')}`
      : '';

    return {
      decision: 'needs-review',
      reason: `[${severityLabel}] ${highRisk.description}`,
      source: 'high-risk',
      userMessage: `[${severityLabel}] ${highRisk.description} (Auto-reject in ${TIMEOUT_SECONDS}s)\n\nPotential risk: ${highRisk.risk}${legitimateUsesText}\n\nOnly proceed if you know what you're doing.`,
    };
  }

  // Step 5: Check if command triggers a checkpoint
  const checkpoint = detectCheckpoint(command);
  if (!checkpoint) {
    return {
      decision: 'allow',
      reason: 'No security checkpoint triggered',
      source: 'no-checkpoint',
    };
  }

  // Step 6: For network operations (not script execution), check trusted domains
  // SECURITY: script_execution (curl | bash) is NEVER auto-approved, even from trusted domains
  // because anyone can upload malicious scripts to GitHub/npm/etc.
  if (checkpoint.type === 'network') {
    const domainResult = checkTrustedDomains(command);
    if (domainResult.allTrusted && domainResult.urls.length > 0) {
      return {
        decision: 'allow',
        reason: `All URLs from trusted domains: ${domainResult.trustedUrls.join(', ')}`,
        source: 'trusted-domain',
      };
    }
  }

  // Step 7: LLM review if API key is available
  if (!anthropicClient) {
    return {
      decision: 'needs-review',
      reason: `Checkpoint triggered: ${checkpoint.type} - ${checkpoint.description}`,
      source: 'checkpoint',
      checkpoint,
    };
  }

  // Progress indicator to stderr (doesn't interfere with JSON output on stdout)
  process.stderr.write('\x1b[90m[VibeSafu] Assessing security risks...\x1b[0m\n');

  // Step 5a: Haiku triage
  const triage = await triageWithHaiku(anthropicClient, checkpoint);

  if (triage.classification === 'BLOCK') {
    return {
      decision: 'deny',
      reason: `Blocked by Haiku: ${triage.reason}`,
      source: 'haiku',
    };
  }

  if (triage.classification === 'SELF_HANDLE') {
    return {
      decision: 'allow',
      reason: `Approved by Haiku: ${triage.reason}`,
      source: 'haiku',
    };
  }

  // Step 5b: Escalate to Sonnet for deeper review
  process.stderr.write('\x1b[90m[VibeSafu] Escalating to deep analysis...\x1b[0m\n');
  const review = await reviewWithSonnet(anthropicClient, checkpoint, triage);

  if (review.verdict === 'BLOCK') {
    const result: ProcessResult = {
      decision: 'deny',
      reason: `Blocked by Sonnet: ${review.reason}`,
      source: 'sonnet',
    };
    if (review.userMessage) {
      result.userMessage = review.userMessage;
    }
    return result;
  }

  if (review.verdict === 'ALLOW') {
    return {
      decision: 'allow',
      reason: `Approved by Sonnet: ${review.reason}`,
      source: 'sonnet',
    };
  }

  // ASK_USER - return as needs-review with user message
  const result: ProcessResult = {
    decision: 'needs-review',
    reason: review.reason,
    source: 'sonnet',
    checkpoint,
  };
  if (review.userMessage) {
    result.userMessage = review.userMessage;
  }
  return result;
}

/**
 * Create the hook output in the expected format
 */
export function createHookOutput(
  decision: 'allow' | 'deny' | 'ask',
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

  // Try to get API key and create Anthropic client
  let anthropicClient: Anthropic | undefined;
  const apiKey = await getApiKey();
  if (apiKey) {
    anthropicClient = new Anthropic({ apiKey });
  }

  // Process the request
  const result = await processPermissionRequest(input, anthropicClient);

  // Convert result to hook output
  let output: PermissionRequestOutput;

  if (result.decision === 'allow') {
    output = createHookOutput('allow');
    console.log(JSON.stringify(output));
    return;
  }

  const warningMessage = result.userMessage ?? result.reason;

  // Both 'deny' and 'needs-review': wait for timeout, then deny
  // During this time, user can click "Allow" in Claude Code's override dialog
  await new Promise((resolve) => setTimeout(resolve, TIMEOUT_SECONDS * 1000));

  // Still here after timeout = user didn't allow, auto-deny
  const denyMessage = `🛡️ [VibeSafu] Auto-denied (no response in ${TIMEOUT_SECONDS}s)\n\n` +
    `Reason: ${warningMessage}\n\n` +
    `If this was intentional, re-run the command and click "Allow" within ${TIMEOUT_SECONDS} seconds.`;

  output = createHookOutput('deny', denyMessage);
  console.log(JSON.stringify(output));
}
