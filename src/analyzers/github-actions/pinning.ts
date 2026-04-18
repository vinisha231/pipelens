/**
 * GitHub Actions dependency pinning checker.
 *
 * Checks that all `uses:` action references are pinned to a full commit SHA
 * rather than a mutable tag or branch reference.
 *
 * Rule implemented:
 *   GHA-PIN-001: Action pinned to a tag or branch instead of a full commit SHA
 *
 * Background:
 *   GitHub Actions referenced as `actions/checkout@v4` can be silently
 *   updated by the action author (by moving the v4 tag to a new commit).
 *   If an action repository is compromised, your workflow will immediately
 *   run the attacker's code.
 *
 *   Full SHA pinning (actions/checkout@sha256:abc123...) guarantees you always
 *   run the exact code you audited.
 *
 *   Reference:
 *   https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
 */

import type { AuditFinding } from '../../types/index.js';
import type { GHAWorkflow, GHAStep } from '../../types/ast.js';
import { RULE_IDS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parses a `uses:` reference into its parts.
 *
 * Formats:
 *   owner/repo@ref           → { owner: 'owner', repo: 'repo', ref: 'ref' }
 *   owner/repo/path@ref      → same (subdirectory action)
 *   docker://image:tag        → local docker action (skip)
 *   ./local/action            → local action (skip)
 */
interface ActionRef {
  owner: string;
  repo: string;
  ref: string;
  full: string;
}

function parseActionRef(uses: string): ActionRef | null {
  // Skip local actions and Docker actions
  if (uses.startsWith('./') || uses.startsWith('docker://')) return null;

  // owner/repo@ref  or  owner/repo/subdir@ref
  const atIdx = uses.lastIndexOf('@');
  if (atIdx === -1) return null;

  const ref = uses.slice(atIdx + 1);
  const fullName = uses.slice(0, atIdx);

  // Extract owner and repo from the path
  const pathParts = fullName.split('/');
  const owner = pathParts[0] ?? '';
  const repo = pathParts[1] ?? '';

  return { owner, repo, ref, full: uses };
}

/**
 * Returns true if the ref looks like a full Git commit SHA (40 hex chars).
 */
function isFullSha(ref: string): boolean {
  return /^[0-9a-f]{40}$/i.test(ref);
}

/**
 * Returns true if the ref looks like a short SHA (7-39 hex chars).
 * Short SHAs are better than tags but not fully safe (collision risk).
 */
function isShortSha(ref: string): boolean {
  return /^[0-9a-f]{7,39}$/i.test(ref);
}

/**
 * Returns true if the ref looks like a semver tag (v1, v1.2, v1.2.3).
 */
function isSemverTag(ref: string): boolean {
  return /^v?\d+(\.\d+){0,2}$/.test(ref);
}

// ---------------------------------------------------------------------------
// GHA-PIN-001: Unpinned action
// ---------------------------------------------------------------------------

/**
 * Checks a single step's `uses:` reference for pinning issues.
 */
function checkActionPinning(step: GHAStep, jobId: string): AuditFinding | null {
  if (!step.uses) return null;

  const ref = parseActionRef(step.uses);
  if (!ref) return null; // local or docker action — skip

  // Full SHA: perfect
  if (isFullSha(ref.ref)) return null;

  // Short SHA: acceptable but mention upgrade
  if (isShortSha(ref.ref)) {
    return {
      id: RULE_IDS.GHA_PIN_001,
      title: `Action ${ref.owner}/${ref.repo} pinned to short SHA`,
      description:
        `"${step.uses}" uses a short (abbreviated) SHA. While better than a tag, ` +
        'short SHAs have a (small) collision risk and make it harder to verify what ' +
        'code you are running. Pin to the full 40-character SHA.',
      severity: 'low',
      line: step.line,
      evidence: `uses: ${step.uses}`,
      fix: `uses: ${ref.owner}/${ref.repo}@<full-40-char-sha>  # ${ref.ref} (abbreviated)`,
    };
  }

  // Semver tag (v1, v2.1, etc.) — common but mutable
  if (isSemverTag(ref.ref)) {
    const isMinorOrPatch = /^v?\d+\.\d/.test(ref.ref);
    return {
      id: RULE_IDS.GHA_PIN_001,
      title: `Action ${ref.owner}/${ref.repo}@${ref.ref} uses mutable tag`,
      description:
        `"${step.uses}" is pinned to a semantic version tag. ` +
        `Tags like "${ref.ref}" can be moved to a different commit by the action author, ` +
        'meaning your workflow may start running different code without any change to the ' +
        'workflow file. Supply-chain attacks often compromise popular actions by moving tags.',
      severity: isMinorOrPatch ? 'medium' : 'high',
      line: step.line,
      evidence: `uses: ${step.uses}`,
      fix:
        `Pin to the full commit SHA corresponding to ${ref.ref}:\n` +
        `# 1. Find the SHA: git ls-remote https://github.com/${ref.owner}/${ref.repo} ${ref.ref}\n` +
        `# 2. Or use: https://github.com/${ref.owner}/${ref.repo}/releases/tag/${ref.ref}\n` +
        `uses: ${ref.owner}/${ref.repo}@<sha>  # ${ref.ref}`,
      references: [
        'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions',
        'https://blog.step.security.io/harden-runner-release-identify-download-tampering-in-actions-runner-and-detect-outbound-network-calls/',
      ],
    };
  }

  // Branch reference (main, master, develop, etc.) — worst case
  return {
    id: RULE_IDS.GHA_PIN_001,
    title: `Action ${ref.owner}/${ref.repo} pinned to branch "${ref.ref}"`,
    description:
      `"${step.uses}" references a branch name. Any push to the ${ref.ref} branch ` +
      'of that action repository will immediately change the code your workflow runs. ' +
      'This is the most dangerous form of unpinned action — a single compromised commit ' +
      'to that branch affects every workflow that references it.',
    severity: 'high',
    line: step.line,
    evidence: `uses: ${step.uses}`,
    fix:
      `Pin to the full commit SHA for the current HEAD of ${ref.ref}:\n` +
      `git ls-remote https://github.com/${ref.owner}/${ref.repo} refs/heads/${ref.ref}`,
    references: [
      'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions',
    ],
  };
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Analyzes a GitHub Actions workflow for action dependency pinning issues.
 *
 * @param workflow  Parsed GHAWorkflow
 * @returns         Array of findings
 */
export function analyzeGHAPinning(workflow: GHAWorkflow): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const job of workflow.jobs) {
    for (const step of job.steps) {
      const finding = checkActionPinning(step, job.id);
      if (finding) findings.push(finding);
    }
  }

  return findings;
}
