/**
 * Common LLM API call utility
 *
 * Extracts shared patterns from haiku-triage.ts and sonnet-review.ts:
 * - AbortController timeout management
 * - Response text extraction
 * - JSON parsing with extractJsonFromText
 * - Error handling (timeout vs general)
 */

import type Anthropic from '@anthropic-ai/sdk';
import { extractJsonFromText } from './sanitize.js';

export interface LLMCallOptions {
  client: Anthropic;
  model: string;
  systemPrompt: string;
  userPrompt: string;
  maxTokens: number;
  timeoutMs: number;
}

export type LLMCallResult =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; error: 'empty_response' | 'parse_error' | 'timeout' | 'api_error'; message: string };

/**
 * Make an LLM API call with timeout, response extraction, and JSON parsing.
 * Returns a discriminated union for clean error handling by callers.
 */
export async function callLLM(options: LLMCallOptions): Promise<LLMCallResult> {
  const { client, model, systemPrompt, userPrompt, maxTokens, timeoutMs } = options;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const response = await client.messages.create(
      {
        model,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      },
      { signal: controller.signal }
    );

    clearTimeout(timeoutId);

    const text = response.content[0]?.type === 'text' ? response.content[0].text : '';

    if (!text) {
      return { ok: false, error: 'empty_response', message: 'Empty response from LLM' };
    }

    const extracted = extractJsonFromText(text);
    if (!extracted) {
      return { ok: false, error: 'parse_error', message: 'Could not parse JSON response' };
    }

    return { ok: true, data: extracted };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    if (errorMessage.includes('abort') || errorMessage.includes('timeout')) {
      return { ok: false, error: 'timeout', message: 'API timeout' };
    }

    return { ok: false, error: 'api_error', message: errorMessage };
  }
}
