/**
 * pipelens public library exports.
 *
 * When pipelens is used as a library (rather than a CLI tool),
 * consumers can import from 'pipelens' directly:
 *
 *   import { runAudit, renderTerminalReport } from 'pipelens';
 *
 * All types are also exported for TypeScript consumers.
 */

// Core types
export type {
  Severity,
  AnalyzerType,
  ReportFormat,
  AuditFinding,
  AuditResult,
  AuditReport,
  ReportSummary,
  PipelensConfig,
  Analyzer,
} from './types/index.js';

// AST types
export type {
  DockerfileAST,
  DockerfileInstruction,
  DockerfileInstructionType,
  FromDetails,
  GHAWorkflow,
  GHAJob,
  GHAStep,
  GitLabCIConfig,
  GitLabJob,
} from './types/ast.js';

// Parsers
export { parseDockerfile, tokenizeDockerfile } from './parsers/dockerfile.js';
export { parseGitHubActionsWorkflow } from './parsers/github-actions.js';
export { parseGitLabCI } from './parsers/gitlab-ci.js';

// Analyzers
export { analyzeDockerfileSecurity } from './analyzers/dockerfile/security.js';
export { analyzeDockerfileLayers } from './analyzers/dockerfile/layers.js';
export { analyzeDockerfileBestPractices } from './analyzers/dockerfile/best-practices.js';
export { analyzeImagePinning } from './analyzers/dockerfile/image-pinning.js';
export { analyzeGHASecrets } from './analyzers/github-actions/secrets.js';
export { analyzeGHAPermissions } from './analyzers/github-actions/permissions.js';
export { analyzeGHAPinning } from './analyzers/github-actions/pinning.js';
export { analyzeGHACaching } from './analyzers/github-actions/caching.js';
export { analyzeGitLabCI } from './analyzers/gitlab-ci/analyzer.js';

// Scoring
export { calculateScore, calculateSummary, sortFindings, getScoreBand, renderScoreBar } from './scoring/engine.js';

// Orchestrator
export { runAudit, discoverFiles } from './orchestrator/index.js';
export type { AuditOptions } from './orchestrator/index.js';

// Reporters
export { renderTerminalReport } from './reporters/terminal.js';
export { renderJSONReport, parseJSONReport, getExitCode } from './reporters/json.js';
export { renderHTMLReport } from './reporters/html.js';

// Constants
export { PIPELENS_VERSION, RULE_IDS, SEVERITY_WEIGHTS, DEFAULT_CONFIG } from './constants/index.js';
