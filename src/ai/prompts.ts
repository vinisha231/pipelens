/**
 * Prompt templates for AI-powered analysis.
 *
 * Centralizes all prompt construction so that:
 *   1. Prompts are easy to review and improve without touching business logic
 *   2. The system prompt (which is cached) stays stable across calls
 *   3. User prompts are minimal and token-efficient
 *
 * System prompts are designed for prompt caching — they are long, stable,
 * and describe the AI's role. User prompts contain the variable data.
 */

import type { AuditFinding, AnalyzerType } from '../types/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PromptPair {
  systemPrompt: string;
  userPrompt: string;
}

// ---------------------------------------------------------------------------
// Shared system prompt base (cached — do not make this dynamic)
// ---------------------------------------------------------------------------

/**
 * Base system prompt shared across all analysis types.
 * This text is stable between calls and benefits from prompt caching.
 */
const BASE_SYSTEM_PROMPT = `You are a senior DevSecOps engineer and security auditor specializing in container security and CI/CD pipeline hardening. You help development teams understand and remediate security vulnerabilities and configuration issues found by automated analysis tools.

Your responses should be:
- Concise and actionable (developers need to fix things, not read essays)
- Technically accurate and specific to the finding context
- Prioritized by risk (address critical issues first)
- Written for an audience that knows DevOps but may not be security specialists
- Free of unnecessary hedging or vague advice

When reviewing findings:
- Focus on the practical impact and exploitation scenario
- Explain WHY something is risky, not just THAT it is risky
- Give specific code examples for fixes when possible
- Mention any edge cases or tradeoffs in the recommended fix
- If a finding might be a false positive, acknowledge it

Format your response in clean markdown. Use code blocks for code examples.`;

// ---------------------------------------------------------------------------
// Narrative prompt (multi-finding analysis)
// ---------------------------------------------------------------------------

/**
 * Formats findings into a concise summary string for inclusion in prompts.
 * Avoids sending full file content when findings alone are sufficient.
 */
function formatFindingsSummary(findings: AuditFinding[]): string {
  return findings
    .map(
      (f) =>
        `[${f.severity.toUpperCase()}] ${f.id}: ${f.title}` +
        (f.line ? ` (line ${f.line})` : '') +
        (f.evidence ? `\n  Evidence: ${f.evidence}` : ''),
    )
    .join('\n');
}

/**
 * Analyzer-specific context for the narrative prompt.
 */
const ANALYZER_CONTEXT: Record<AnalyzerType, string> = {
  dockerfile:
    'This is a Dockerfile used to build a container image. ' +
    'Consider the full container security context: image attack surface, runtime privileges, secrets management, and build reproducibility.',
  'github-actions':
    'This is a GitHub Actions workflow file (.yml). ' +
    'Consider the CI/CD security context: supply chain attacks, secret exposure, GITHUB_TOKEN permissions, and repository write access.',
  'gitlab-ci':
    'This is a GitLab CI configuration file (.gitlab-ci.yml). ' +
    'Consider the CI/CD security context: privileged runners, secret variable exposure, and pipeline performance.',
};

/**
 * Builds the prompt pair for the multi-finding narrative analysis.
 *
 * @param findings      All findings to analyze
 * @param fileContent   Original file content (truncated if very long)
 * @param analyzerType  Type of file being analyzed
 */
export function buildNarrativePrompt(
  findings: AuditFinding[],
  fileContent: string,
  analyzerType: AnalyzerType,
): PromptPair {
  const systemPrompt = `${BASE_SYSTEM_PROMPT}

Context: ${ANALYZER_CONTEXT[analyzerType]}`;

  // Truncate very long file content to avoid token limits
  const maxFileLength = 3000;
  const truncatedContent =
    fileContent.length > maxFileLength
      ? fileContent.slice(0, maxFileLength) + '\n... [truncated]'
      : fileContent;

  const criticalAndHigh = findings.filter(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  const others = findings.filter(
    (f) => f.severity !== 'critical' && f.severity !== 'high',
  );

  const userPrompt = `I have run an automated security audit on the following ${analyzerType} configuration and found ${findings.length} issue(s).

## File Content
\`\`\`
${truncatedContent}
\`\`\`

## Findings Summary
${formatFindingsSummary(findings)}

## Task
Please provide:
1. **Overall assessment** (2-3 sentences): How serious is the overall security posture?
2. **Top priorities** (bulleted list): The ${criticalAndHigh.length > 0 ? criticalAndHigh.length : 3} most important issues to fix first, with a one-sentence explanation of the real-world risk for each.
3. **Quick wins** (if any): Are there any findings in this list that are easy 1-line fixes?
4. **Systemic issues** (if applicable): Do these findings suggest a deeper cultural or process problem (e.g., secrets management not established, no image pinning policy)?

Keep the total response under 400 words.`;

  return { systemPrompt, userPrompt };
}

// ---------------------------------------------------------------------------
// Fix suggestion prompt (single finding)
// ---------------------------------------------------------------------------

/**
 * Builds the prompt pair for a single-finding fix suggestion.
 *
 * @param finding   The specific finding to get a fix for
 * @param context   Surrounding file content for context
 */
export function buildFixPrompt(
  finding: AuditFinding,
  context: string,
): PromptPair {
  const systemPrompt = `${BASE_SYSTEM_PROMPT}

Your task is to provide a specific, actionable fix for a single security finding. Be concise — developers want to fix the issue and move on. Provide the corrected code snippet when possible.`;

  // Truncate context to relevant surrounding lines
  const maxContextLength = 1500;
  const truncatedContext =
    context.length > maxContextLength
      ? context.slice(0, maxContextLength) + '\n... [truncated]'
      : context;

  const userPrompt = `Fix the following security finding:

**Finding ID**: ${finding.id}
**Severity**: ${finding.severity.toUpperCase()}
**Title**: ${finding.title}
**Description**: ${finding.description}
${finding.evidence ? `**Offending code**:\n\`\`\`\n${finding.evidence}\n\`\`\`` : ''}
${finding.fix ? `**Suggested fix** (from static analysis):\n${finding.fix}` : ''}

## Surrounding context
\`\`\`
${truncatedContext}
\`\`\`

Provide a corrected code snippet and a 1-2 sentence explanation of why the fix works. If there are multiple valid approaches, mention the tradeoffs briefly.`;

  return { systemPrompt, userPrompt };
}
