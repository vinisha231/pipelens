/**
 * Audit orchestrator — coordinates all parsers, analyzers, and AI.
 *
 * This is the central coordination module. It:
 *   1. Discovers Dockerfile and CI/CD files from a given path
 *   2. Routes each file to the appropriate parser
 *   3. Runs all relevant analyzers on each parsed file
 *   4. Optionally enriches findings with AI suggestions
 *   5. Assembles the final AuditReport
 *
 * All async work is done with structured concurrency — file analyses run
 * sequentially (to avoid hammering the AI API), but within each file,
 * all synchronous analyzers run together.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { AuditReport, AuditResult, AuditFinding, PipelensConfig } from '../types/index.js';
import { PIPELENS_VERSION } from '../constants/index.js';
import { parseDockerfile } from '../parsers/dockerfile.js';
import { parseGitHubActionsWorkflow } from '../parsers/github-actions.js';
import { parseGitLabCI } from '../parsers/gitlab-ci.js';
import { analyzeDockerfileSecurity } from '../analyzers/dockerfile/security.js';
import { analyzeDockerfileLayers } from '../analyzers/dockerfile/layers.js';
import { analyzeDockerfileBestPractices } from '../analyzers/dockerfile/best-practices.js';
import { analyzeImagePinning } from '../analyzers/dockerfile/image-pinning.js';
import { analyzeGHASecrets } from '../analyzers/github-actions/secrets.js';
import { analyzeGHAPermissions } from '../analyzers/github-actions/permissions.js';
import { analyzeGHAPinning } from '../analyzers/github-actions/pinning.js';
import { analyzeGHACaching } from '../analyzers/github-actions/caching.js';
import { analyzeGitLabCI } from '../analyzers/gitlab-ci/analyzer.js';
import { PipelensAIClient } from '../ai/client.js';
import { calculateScore, calculateSummary, sortFindings } from '../scoring/engine.js';

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/**
 * Recursively finds all files under a directory, up to a depth limit.
 * Returns absolute paths.
 */
function findFiles(dir: string, maxDepth = 4, currentDepth = 0): string[] {
  if (currentDepth > maxDepth) return [];

  let results: string[] = [];
  let entries: fs.Dirent[];

  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const entry of entries) {
    // Skip common noise directories
    if (
      entry.name === 'node_modules' ||
      entry.name === '.git' ||
      entry.name === 'dist' ||
      entry.name === 'vendor' ||
      entry.name === '__pycache__'
    ) {
      continue;
    }

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(findFiles(fullPath, maxDepth, currentDepth + 1));
    } else {
      results.push(fullPath);
    }
  }

  return results;
}

/**
 * Determines the type of a file based on its name and path.
 * Returns 'dockerfile', 'github-actions', 'gitlab-ci', or null.
 */
function classifyFile(
  filePath: string,
): 'dockerfile' | 'github-actions' | 'gitlab-ci' | null {
  const basename = path.basename(filePath).toLowerCase();
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

  // Dockerfile detection
  if (
    basename === 'dockerfile' ||
    basename.startsWith('dockerfile.') ||
    basename.endsWith('.dockerfile')
  ) {
    return 'dockerfile';
  }

  // GitHub Actions detection (.github/workflows/*.yml)
  if (
    normalizedPath.includes('.github/workflows/') &&
    (basename.endsWith('.yml') || basename.endsWith('.yaml'))
  ) {
    return 'github-actions';
  }

  // GitLab CI detection
  if (basename === '.gitlab-ci.yml' || basename === '.gitlab-ci.yaml') {
    return 'gitlab-ci';
  }

  return null;
}

/**
 * Discovers all auditable files under the given path.
 * If `targetPath` is a file, returns just that file.
 * If it's a directory, recursively searches for Dockerfiles and CI configs.
 */
export function discoverFiles(
  targetPath: string,
): Array<{ path: string; type: 'dockerfile' | 'github-actions' | 'gitlab-ci' }> {
  const stat = fs.statSync(targetPath);

  if (stat.isFile()) {
    const type = classifyFile(targetPath);
    if (!type) return [];
    return [{ path: targetPath, type }];
  }

  const allFiles = findFiles(targetPath);
  const results: Array<{ path: string; type: 'dockerfile' | 'github-actions' | 'gitlab-ci' }> = [];

  for (const filePath of allFiles) {
    const type = classifyFile(filePath);
    if (type) {
      results.push({ path: filePath, type });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Per-file analysis
// ---------------------------------------------------------------------------

/**
 * Runs all applicable analyzers on a single Dockerfile.
 */
function analyzeDockerfile(content: string, filePath: string): AuditFinding[] {
  const ast = parseDockerfile(content, filePath);
  return [
    ...analyzeDockerfileSecurity(ast),
    ...analyzeDockerfileLayers(ast),
    ...analyzeDockerfileBestPractices(ast),
    ...analyzeImagePinning(ast),
  ];
}

/**
 * Runs all applicable analyzers on a single GitHub Actions workflow.
 */
function analyzeGitHubActions(content: string, filePath: string): AuditFinding[] {
  const workflow = parseGitHubActionsWorkflow(content, filePath);
  return [
    ...analyzeGHASecrets(workflow),
    ...analyzeGHAPermissions(workflow),
    ...analyzeGHAPinning(workflow),
    ...analyzeGHACaching(workflow),
  ];
}

/**
 * Runs all applicable analyzers on a single GitLab CI config.
 */
function analyzeGitLabCIFile(content: string, filePath: string): AuditFinding[] {
  const config = parseGitLabCI(content, filePath);
  return analyzeGitLabCI(config);
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/**
 * Filters findings based on the user's config (ignored rule IDs and min severity).
 */
function filterFindings(
  findings: AuditFinding[],
  config: PipelensConfig,
): AuditFinding[] {
  const ignoredIds = new Set(config.ignore ?? []);
  const minSeverityOrder = getSeverityOrder(config.severity ?? 'info');

  return findings.filter((f) => {
    if (ignoredIds.has(f.id)) return false;
    if (getSeverityOrder(f.severity) > minSeverityOrder) return false;
    return true;
  });
}

function getSeverityOrder(severity: string): number {
  const order: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return order[severity] ?? 4;
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

/**
 * Options for running an audit.
 */
export interface AuditOptions {
  /** Path to audit (file or directory) */
  targetPath: string;

  /** Optional explicit Dockerfile path (overrides discovery) */
  dockerfilePath?: string;

  /** Optional explicit workflow directory/file path */
  workflowPath?: string;

  /** Audit configuration */
  config: PipelensConfig;

  /** Callback for progress updates (called before each file is analyzed) */
  onProgress?: (message: string) => void;
}

/**
 * Runs the full audit pipeline and returns a complete AuditReport.
 *
 * This is the main entry point for the pipelens library.
 * The CLI calls this function and then passes the result to a reporter.
 *
 * @param options  Audit configuration and targets
 * @returns        Complete AuditReport ready for reporting
 */
export async function runAudit(options: AuditOptions): Promise<AuditReport> {
  const { targetPath, dockerfilePath, workflowPath, config, onProgress } = options;
  const aiClient = new PipelensAIClient();

  // Step 1: Discover files
  const filesToAudit: Array<{
    path: string;
    type: 'dockerfile' | 'github-actions' | 'gitlab-ci';
  }> = [];

  // If explicit paths were given, use those instead of discovery
  if (dockerfilePath) {
    filesToAudit.push({ path: dockerfilePath, type: 'dockerfile' });
  }
  if (workflowPath) {
    const stat = fs.statSync(workflowPath);
    if (stat.isFile()) {
      filesToAudit.push({ path: workflowPath, type: 'github-actions' });
    } else {
      // Treat as workflow directory
      const discovered = discoverFiles(workflowPath).filter(
        (f) => f.type === 'github-actions',
      );
      filesToAudit.push(...discovered);
    }
  }

  // If no explicit targets, discover from the base path
  if (!dockerfilePath && !workflowPath) {
    filesToAudit.push(...discoverFiles(targetPath));
  }

  // Step 2: Analyze each file
  const results: AuditResult[] = [];

  for (const file of filesToAudit) {
    onProgress?.(`Analyzing ${file.path}...`);
    const startTime = Date.now();

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch (err) {
      onProgress?.(`Warning: Could not read ${file.path} — skipping`);
      continue;
    }

    let rawFindings: AuditFinding[] = [];

    try {
      switch (file.type) {
        case 'dockerfile':
          rawFindings = analyzeDockerfile(content, file.path);
          break;
        case 'github-actions':
          rawFindings = analyzeGitHubActions(content, file.path);
          break;
        case 'gitlab-ci':
          rawFindings = analyzeGitLabCIFile(content, file.path);
          break;
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      onProgress?.(`Warning: Analysis failed for ${file.path}: ${errMsg}`);
      continue;
    }

    // Apply filters (ignored rules, min severity)
    const findings = sortFindings(filterFindings(rawFindings, config));

    // Step 3: AI enrichment for critical/high findings
    if (config.ai !== false && aiClient.isAvailable()) {
      onProgress?.(`Running AI analysis for ${path.basename(file.path)}...`);

      const topFindings = findings
        .filter((f) => f.severity === 'critical' || f.severity === 'high')
        .slice(0, 5); // Limit to top 5 to control API cost

      for (const finding of topFindings) {
        const aiResult = await aiClient.suggestFix(finding, content);
        if (aiResult.success) {
          finding.aiSuggestion = aiResult.content;
        }
      }
    }

    results.push({
      target: file.path,
      analyzerType: file.type,
      findings,
      score: calculateScore(findings),
      duration: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    });
  }

  // Step 4: Generate AI narrative (one call for the whole report)
  let aiNarrative: string | undefined;

  if (config.ai !== false && aiClient.isAvailable() && results.length > 0) {
    const allFindings = results.flatMap((r) => r.findings);
    if (allFindings.length > 0) {
      onProgress?.('Generating AI narrative...');

      // Use the first result's type for context (usually the most important file)
      const primaryType = results[0]?.analyzerType ?? 'dockerfile';
      const primaryContent = fs.existsSync(results[0]?.target ?? '') ?
        fs.readFileSync(results[0]?.target ?? '', 'utf-8') : '';

      const narrativeResult = await aiClient.analyzeFindings(
        allFindings,
        primaryContent,
        primaryType,
      );

      if (narrativeResult.success) {
        aiNarrative = narrativeResult.content;
      }
    }
  }

  // Step 5: Assemble report
  return {
    version: PIPELENS_VERSION,
    results,
    summary: calculateSummary(results),
    aiNarrative,
  };
}
