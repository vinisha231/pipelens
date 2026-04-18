/**
 * AI client wrapper for pipelens.
 *
 * Wraps the Anthropic SDK with:
 *   - Retry logic with exponential backoff (3 attempts by default)
 *   - Rate-limit handling (429 responses trigger a longer backoff)
 *   - Prompt caching via cache_control: { type: "ephemeral" } on the system prompt
 *   - Graceful degradation: if the API is unavailable, audits still complete
 *     without AI suggestions
 *
 * IMPORTANT: This module never logs API keys or request/response content.
 *
 * Usage:
 *   const client = new PipelensAIClient();
 *   const narrative = await client.analyzeFindings(findings, fileContent, 'dockerfile');
 */

import Anthropic from '@anthropic-ai/sdk';
import type { AuditFinding, AnalyzerType } from '../types/index.js';
import {
  AI_MODEL,
  AI_MAX_TOKENS,
  AI_RETRY_ATTEMPTS,
  AI_RETRY_BASE_DELAY,
} from '../constants/index.js';
import { buildNarrativePrompt, buildFixPrompt } from './prompts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Result of an AI analysis call.
 * `success: false` means the AI was unavailable — callers should degrade gracefully.
 */
export type AIResult =
  | { success: true; content: string }
  | { success: false; error: string };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Sleeps for the given number of milliseconds.
 * Used between retry attempts.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculates the backoff delay for a given attempt number.
 * Uses full jitter to avoid thundering herd: delay = random(0, base * 2^attempt)
 */
function backoffDelay(attempt: number): number {
  const maxDelay = AI_RETRY_BASE_DELAY * Math.pow(2, attempt);
  return Math.floor(Math.random() * maxDelay);
}

/**
 * Returns true if an error is retryable (network issues, server errors, rate limits).
 */
function isRetryable(error: unknown): boolean {
  if (error instanceof Anthropic.APIError) {
    // 429 = rate limit, 500/502/503/529 = server errors — all retryable
    return error.status === 429 || error.status >= 500;
  }
  // Network errors (ECONNRESET, ETIMEDOUT, etc.) are retryable
  if (error instanceof Error) {
    return (
      error.message.includes('ECONNRESET') ||
      error.message.includes('ETIMEDOUT') ||
      error.message.includes('fetch failed') ||
      error.message.includes('network')
    );
  }
  return false;
}

// ---------------------------------------------------------------------------
// PipelensAIClient
// ---------------------------------------------------------------------------

/**
 * Wraps the Anthropic SDK to provide AI-powered analysis for pipelens.
 *
 * Instantiation is lightweight — the API key is read from ANTHROPIC_API_KEY
 * environment variable by the SDK automatically.
 */
export class PipelensAIClient {
  private client: Anthropic;

  constructor() {
    // The Anthropic SDK automatically reads ANTHROPIC_API_KEY from the environment.
    // Passing an explicit key here would risk logging it accidentally.
    this.client = new Anthropic();
  }

  /**
   * Checks whether the AI client is likely usable (API key is present).
   * Does not make a network call — just checks for the env variable.
   */
  isAvailable(): boolean {
    return Boolean(process.env['ANTHROPIC_API_KEY']);
  }

  /**
   * Core retry wrapper for Anthropic API calls.
   *
   * @param fn          The async function to call (should return a string response)
   * @param context     Human-readable context for error messages
   * @returns           AIResult — success with content or failure with error
   */
  private async withRetry(
    fn: () => Promise<string>,
    context: string,
  ): Promise<AIResult> {
    let lastError: unknown;

    for (let attempt = 0; attempt < AI_RETRY_ATTEMPTS; attempt++) {
      try {
        const content = await fn();
        return { success: true, content };
      } catch (error) {
        lastError = error;

        // Don't retry auth errors — they won't succeed on retry
        if (error instanceof Anthropic.AuthenticationError) {
          return {
            success: false,
            error: 'AI authentication failed. Check your ANTHROPIC_API_KEY.',
          };
        }

        if (!isRetryable(error)) {
          break;
        }

        // Wait before retrying
        const delay = backoffDelay(attempt);
        await sleep(delay);
      }
    }

    // All retries exhausted
    const errorMessage =
      lastError instanceof Error ? lastError.message : String(lastError);

    return {
      success: false,
      error: `AI request failed after ${AI_RETRY_ATTEMPTS} attempts (${context}): ${errorMessage}`,
    };
  }

  /**
   * Generates a narrative summary and recommendations for a set of findings.
   *
   * Uses prompt caching on the system prompt to reduce cost when called
   * multiple times in the same audit session.
   *
   * @param findings      All findings from the analyzer
   * @param fileContent   Original file content (provides context for the AI)
   * @param analyzerType  Which analyzer produced these findings
   * @returns             AIResult with a markdown narrative
   */
  async analyzeFindings(
    findings: AuditFinding[],
    fileContent: string,
    analyzerType: AnalyzerType,
  ): Promise<AIResult> {
    if (!this.isAvailable()) {
      return { success: false, error: 'ANTHROPIC_API_KEY not set' };
    }

    if (findings.length === 0) {
      return { success: true, content: 'No findings to analyze — the configuration looks clean!' };
    }

    const { systemPrompt, userPrompt } = buildNarrativePrompt(
      findings,
      fileContent,
      analyzerType,
    );

    return this.withRetry(async () => {
      const response = await this.client.messages.create({
        model: AI_MODEL,
        max_tokens: AI_MAX_TOKENS,
        system: [
          {
            type: 'text',
            text: systemPrompt,
            // Cache the system prompt — it rarely changes between calls in a session,
            // so this significantly reduces token costs for multi-file audits.
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [
          {
            role: 'user',
            content: userPrompt,
          },
        ],
      });

      // Extract text from the response content blocks
      const textBlock = response.content.find((b) => b.type === 'text');
      if (!textBlock || textBlock.type !== 'text') {
        throw new Error('AI returned no text content');
      }
      return textBlock.text;
    }, `analyzeFindings(${analyzerType})`);
  }

  /**
   * Generates a specific, actionable fix suggestion for a single finding.
   *
   * This provides more detailed guidance than the deterministic `fix` field
   * on the finding — the AI can tailor advice to the specific evidence context.
   *
   * @param finding   The finding to get a fix for
   * @param context   The surrounding file content for context
   * @returns         AIResult with a fix suggestion
   */
  async suggestFix(
    finding: AuditFinding,
    context: string,
  ): Promise<AIResult> {
    if (!this.isAvailable()) {
      return { success: false, error: 'ANTHROPIC_API_KEY not set' };
    }

    const { systemPrompt, userPrompt } = buildFixPrompt(finding, context);

    return this.withRetry(async () => {
      const response = await this.client.messages.create({
        model: AI_MODEL,
        max_tokens: 512, // Fix suggestions should be concise
        system: [
          {
            type: 'text',
            text: systemPrompt,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [
          {
            role: 'user',
            content: userPrompt,
          },
        ],
      });

      const textBlock = response.content.find((b) => b.type === 'text');
      if (!textBlock || textBlock.type !== 'text') {
        throw new Error('AI returned no text content');
      }
      return textBlock.text;
    }, `suggestFix(${finding.id})`);
  }
}
