/**
 * Claude Code Hook Types for VibeSafu
 */

// Hook Input (stdin)
export interface PermissionRequestInput {
  session_id: string;
  transcript_path: string;
  cwd: string;
  permission_mode: string;
  hook_event_name: 'PermissionRequest';
  tool_name: string;
  tool_input: Record<string, unknown>;
  permission_suggestions?: Array<{
    type: string;
    tool: string;
  }>;
}

// Hook Output (stdout)
export interface PermissionRequestOutput {
  hookSpecificOutput: {
    hookEventName: 'PermissionRequest';
    decision: {
      behavior: 'allow' | 'deny' | 'ask';
      message?: string;
      updatedInput?: Record<string, unknown>;
    };
  };
}

// Security Decision
export type SecurityVerdict = 'ALLOW' | 'DENY' | 'ASK_USER';

export interface SecurityDecision {
  verdict: SecurityVerdict;
  reason: string;
  source: 'instant-block' | 'trusted-domain' | 'haiku' | 'sonnet';
}

// Haiku Triage Response
export type HaikuDecision = 'SELF_HANDLE' | 'ESCALATE' | 'BLOCK';

export interface HaikuTriageResult {
  decision: HaikuDecision;
  reasoning: string;
  verdict?: SecurityVerdict; // for SELF_HANDLE
  reason?: string; // for SELF_HANDLE or BLOCK
}

// Sonnet Review Response
export interface SonnetReviewResult {
  verdict: SecurityVerdict;
  analysis: string;
  recommendations?: string[];
}

// Config
export interface VibeSafuConfig {
  anthropic: {
    apiKey: string;
  };
  models: {
    triage: string;
    review: string;
  };
  trustedDomains: string[];
  customPatterns: {
    block: string[];
    allow: string[];
  };
  logging: {
    enabled: boolean;
    path: string;
  };
}

// Pattern Definition
export interface BlockPattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  risk: string;  // What could go wrong
  legitimateUses?: string[];  // When this might be intentional
}

// Security Checkpoint
export interface SecurityCheckpoint {
  type: 'network' | 'package_install' | 'git_operation' | 'file_sensitive' | 'script_execution' | 'env_modification' | 'url_shortener';
  command: string;
  description: string;
}
