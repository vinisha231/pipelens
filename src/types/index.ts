/**
 * Core type definitions for pipelens audit system.
 *
 * These interfaces define the data contracts used throughout the entire
 * pipeline: parsers produce structured data, analyzers consume it and
 * produce AuditFindings, the orchestrator bundles findings into AuditResults,
 * and reporters consume AuditReports.
 */

// ---------------------------------------------------------------------------
// Primitive types
// ---------------------------------------------------------------------------

/**
 * Severity levels ordered from most to least critical.
 * Used for filtering, sorting, and color-coding output.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Which kind of file/config system the analyzer targets.
 */
export type AnalyzerType = 'dockerfile' | 'github-actions' | 'gitlab-ci';

/**
 * Available output formats for reports.
 */
export type ReportFormat = 'terminal' | 'json' | 'html';

// ---------------------------------------------------------------------------
// Finding — one discrete security / quality issue discovered in a file
// ---------------------------------------------------------------------------

/**
 * A single finding produced by an analyzer.
 *
 * Rule IDs follow the pattern: <PREFIX>-<CATEGORY>-<NNN>
 *   DF-SEC-001  = Dockerfile, Security, rule 1
 *   GHA-PERM-002 = GitHub Actions, Permissions, rule 2
 *   GL-OPT-001  = GitLab CI, Optimization, rule 1
 */
export interface AuditFinding {
  /** Unique rule identifier, e.g. "DF-SEC-001" */
  id: string;

  /** Short human-readable title for the finding */
  title: string;

  /** Longer explanation of why this is a problem */
  description: string;

  /** How severe this finding is */
  severity: Severity;

  /** 1-based line number where the issue was found (optional) */
  line?: number;

  /** 1-based column number (optional) */
  column?: number;

  /** The offending code snippet as it appears in the file */
  evidence?: string;

  /** A suggested fix (deterministic, from the rule logic) */
  fix?: string;

  /** Links to relevant documentation, CVEs, or best-practice guides */
  references?: string[];

  /** AI-generated contextual fix suggestion (filled in by the AI module) */
  aiSuggestion?: string;
}

// ---------------------------------------------------------------------------
// AuditResult — findings for a single file
// ---------------------------------------------------------------------------

/**
 * The complete audit result for one target file.
 */
export interface AuditResult {
  /** Absolute or relative path to the analyzed file */
  target: string;

  /** Which analyzer produced this result */
  analyzerType: AnalyzerType;

  /** All findings discovered in this file, sorted by severity */
  findings: AuditFinding[];

  /**
   * Health score from 0 to 100 (higher = better).
   * Calculated by the scoring engine based on finding severities.
   */
  score: number;

  /** Wall-clock time taken to analyze this file, in milliseconds */
  duration: number;

  /** ISO 8601 timestamp of when the analysis ran */
  timestamp: string;
}

// ---------------------------------------------------------------------------
// AuditReport — the top-level document returned to reporters
// ---------------------------------------------------------------------------

/**
 * The complete report produced by the orchestrator.
 * This is the object serialized to JSON or rendered to HTML/terminal.
 */
export interface AuditReport {
  /** pipelens version that produced this report */
  version: string;

  /** Per-file results */
  results: AuditResult[];

  /** Aggregated statistics across all results */
  summary: ReportSummary;

  /**
   * Optional AI-generated narrative covering the overall security posture.
   * Only present when AI is enabled and the API call succeeds.
   */
  aiNarrative?: string;
}

// ---------------------------------------------------------------------------
// ReportSummary — aggregate counts across all results
// ---------------------------------------------------------------------------

/**
 * Aggregate statistics displayed in the report header/footer.
 */
export interface ReportSummary {
  /** Total number of findings across all files */
  totalFindings: number;

  /** Count of CRITICAL severity findings */
  critical: number;

  /** Count of HIGH severity findings */
  high: number;

  /** Count of MEDIUM severity findings */
  medium: number;

  /** Count of LOW severity findings */
  low: number;

  /** Count of INFO severity findings */
  info: number;

  /**
   * Weighted average score across all analyzed files (0–100).
   * Higher is better.
   */
  overallScore: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * User-facing configuration loaded from pipelens.config.json
 * or passed via CLI flags.
 */
export interface PipelensConfig {
  /**
   * List of rule IDs to skip entirely.
   * Example: ["DF-BP-003", "GHA-CACHE-001"]
   */
  ignore?: string[];

  /**
   * Minimum severity to include in the report.
   * Findings below this threshold are silently dropped.
   * Default: "info" (show everything)
   */
  severity?: Severity;

  /**
   * Whether to call the AI for contextual suggestions.
   * Requires ANTHROPIC_API_KEY to be set.
   * Default: true
   */
  ai?: boolean;

  /**
   * Default output format when --format is not specified.
   * Default: "terminal"
   */
  format?: ReportFormat;

  /**
   * If set, write the report to this file path in addition to (or instead of) stdout.
   */
  output?: string;
}

// ---------------------------------------------------------------------------
// Analyzer interface — implemented by every analyzer module
// ---------------------------------------------------------------------------

/**
 * Contract that every analyzer must implement.
 * Analyzers are pure functions from file content → findings.
 */
export interface Analyzer<TInput> {
  /**
   * Run the analysis on the parsed input.
   * @param input   Parsed representation of the file
   * @param raw     Original raw file content (for evidence snippets)
   * @returns       Array of findings (may be empty)
   */
  analyze(input: TInput, raw: string): AuditFinding[];
}
