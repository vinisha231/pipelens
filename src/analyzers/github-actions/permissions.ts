/**
 * GitHub Actions permissions analyzer.
 *
 * Checks for overly broad or missing permissions declarations in workflows.
 *
 * Rules implemented:
 *   GHA-PERM-001: Overly broad `write-all` or `contents: write` at workflow level
 *   GHA-PERM-002: Missing `permissions:` block (relies on inherited repo defaults)
 *
 * Background:
 *   GitHub Actions workflows have an associated GITHUB_TOKEN that is used for
 *   API calls. By default (without a permissions block), the token has "permissive"
 *   defaults that grant write access to most resources. Explicit permissions blocks
 *   following the principle of least privilege are strongly recommended.
 *
 *   Reference:
 *   https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
 */

import type { AuditFinding } from '../../types/index.js';
import type { GHAWorkflow, GHAJob } from '../../types/ast.js';
import { RULE_IDS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Permission scopes where `write` access is considered high-risk when granted
 * at the workflow level without justification.
 */
const HIGH_RISK_WRITE_SCOPES = new Set([
  'contents',    // Can push commits, delete branches, create releases
  'packages',    // Can push/delete packages
  'id-token',    // Can request OIDC tokens (used for cloud auth)
  'deployments', // Can create/delete deployments
  'actions',     // Can manage Actions (create self-hosted runners, etc.)
  'security-events', // Can submit code scanning alerts
]);

/**
 * Triggers that commonly need write permissions and where workflow-level
 * write access is more understandable (but should still be explicit).
 */
const WRITE_WORKFLOW_TRIGGERS = new Set([
  'release',
  'push',
  'workflow_dispatch',
]);

// ---------------------------------------------------------------------------
// GHA-PERM-001: Overly broad permissions
// ---------------------------------------------------------------------------

/**
 * Checks a permissions block for overly broad grants.
 *
 * Red flags:
 *   - `permissions: write-all` — every scope has write access
 *   - `contents: write` at workflow level on untrusted triggers
 *   - Multiple write scopes without clear justification
 */
function checkOverboadPermissions(
  permissions: Record<string, string>,
  context: string,
  line?: number,
  triggers?: Set<string>,
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Check for write-all shorthand
  if ((permissions as Record<string, unknown>)['write-all'] ||
      Object.values(permissions).includes('write-all')) {
    findings.push({
      id: RULE_IDS.GHA_PERM_001,
      title: `Overly broad permissions: write-all in ${context}`,
      description:
        'The workflow or job uses `permissions: write-all` which grants write access ' +
        'to ALL permission scopes. This violates the principle of least privilege. ' +
        'If a workflow step is compromised (e.g. via a malicious action), the attacker ' +
        'has write access to your entire repository, packages, and secrets.',
      severity: 'high',
      line,
      evidence: 'permissions: write-all',
      fix:
        'Replace write-all with explicit minimal permissions. Example for a release workflow:\n' +
        'permissions:\n' +
        '  contents: write\n' +
        '  packages: write\n' +
        '  id-token: write',
      references: [
        'https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token',
      ],
    });
    return findings; // Don't double-report if write-all is set
  }

  // Check each high-risk write scope
  const writeScopes = Object.entries(permissions).filter(
    ([scope, access]) => access === 'write' && HIGH_RISK_WRITE_SCOPES.has(scope),
  );

  for (const [scope, _access] of writeScopes) {
    // contents: write on PR-triggered workflows is particularly dangerous
    if (
      scope === 'contents' &&
      triggers &&
      (triggers.has('pull_request') || triggers.has('pull_request_target'))
    ) {
      findings.push({
        id: RULE_IDS.GHA_PERM_001,
        title: `contents: write permission on pull_request trigger in ${context}`,
        description:
          'Granting `contents: write` to a workflow triggered by pull requests ' +
          'is dangerous. An attacker can fork your repo, open a PR, and use the ' +
          'write permission to push malicious commits if any step runs untrusted code.',
        severity: 'high',
        line,
        evidence: `permissions:\n  contents: write\n# on: pull_request`,
        fix:
          'Set `contents: read` for PR-triggered workflows. Only grant write permissions ' +
          'in a separate workflow triggered by `push` to protected branches.',
        references: [
          'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GHA-PERM-002: Missing permissions block
// ---------------------------------------------------------------------------

/**
 * Checks whether a workflow or job is missing an explicit permissions block.
 *
 * Without an explicit `permissions:` block, the GITHUB_TOKEN defaults to
 * whatever the repository's "Actions permissions" setting is — often permissive.
 * Explicit permissions make the workflow's intent clear and limit blast radius.
 */
function checkMissingPermissions(
  hasWorkflowPermissions: boolean,
  jobs: GHAJob[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // If every job has its own permissions block, the workflow-level one is optional
  const everyJobHasPermissions = jobs.every((j) => j.permissions !== undefined);

  if (!hasWorkflowPermissions && !everyJobHasPermissions) {
    findings.push({
      id: RULE_IDS.GHA_PERM_002,
      title: 'Missing explicit permissions block in workflow',
      description:
        'The workflow does not define a `permissions:` block. Without it, ' +
        'the GITHUB_TOKEN receives the repository\'s default permissions, which are ' +
        'often permissive (read/write to contents, issues, pull-requests, etc.). ' +
        'Explicit permissions follow the principle of least privilege and make ' +
        'the workflow\'s needs auditable.',
      severity: 'medium',
      fix:
        'Add a permissions block at the workflow level (or per-job):\n' +
        'permissions:\n' +
        '  contents: read\n' +
        '  # Add only the scopes your workflow actually needs',
      references: [
        'https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token',
        'https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions',
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Analyzes a GitHub Actions workflow for permission configuration issues.
 *
 * @param workflow  Parsed GHAWorkflow
 * @returns         Array of findings
 */
export function analyzeGHAPermissions(workflow: GHAWorkflow): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const triggers = new Set(Object.keys(workflow.on));

  // Check workflow-level permissions
  if (workflow.permissions) {
    findings.push(
      ...checkOverboadPermissions(
        workflow.permissions,
        'workflow',
        undefined,
        triggers,
      ),
    );
  }

  // Check missing permissions
  findings.push(
    ...checkMissingPermissions(
      workflow.permissions !== undefined,
      workflow.jobs,
    ),
  );

  // Check per-job permissions
  for (const job of workflow.jobs) {
    if (job.permissions) {
      findings.push(
        ...checkOverboadPermissions(
          job.permissions,
          `job "${job.id}"`,
          job.line,
          triggers,
        ),
      );
    }
  }

  return findings;
}
