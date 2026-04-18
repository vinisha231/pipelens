/**
 * Severity scoring engine for pipelens.
 *
 * Calculates a 0–100 "health score" for each audited file based on
 * the severity and quantity of findings. Higher scores = better security.
 *
 * Scoring model:
 *   1. Start at 100 (perfect score)
 *   2. Subtract weighted penalties for each finding
 *   3. Apply diminishing returns — the 5th critical finding doesn't hurt as much
 *      as the 1st (you can't score below 0, and findings have compounding context)
 *   4. Clamp the result to [0, 100]
 *
 * This is inspired by CVSS but intentionally simpler and focused on
 * actionable feedback rather than precise risk quantification.
 */

import type { AuditFinding, AuditResult, ReportSummary, Severity } from '../types/index.js';
import { SEVERITY_WEIGHTS, SEVERITY_ORDER } from '../constants/index.js';

// ---------------------------------------------------------------------------
// Scoring constants
// ---------------------------------------------------------------------------

/**
 * Diminishing returns factor.
 * Each additional finding of the same severity adds less penalty than the previous.
 * penalty(n) = weight * diminishingFactor^(n-1)
 *
 * With factor 0.85:
 *   1st critical:  40.0 pts
 *   2nd critical:  34.0 pts
 *   3rd critical:  28.9 pts
 *   ... (converges, never goes below 0)
 */
const DIMINISHING_FACTOR = 0.85;

// ---------------------------------------------------------------------------
// Score calculation
// ---------------------------------------------------------------------------

/**
 * Calculates the health score for a list of findings.
 *
 * @param findings  All findings for a single file
 * @returns         Score from 0 (worst) to 100 (best)
 */
export function calculateScore(findings: AuditFinding[]): number {
  if (findings.length === 0) return 100;

  // Count findings per severity level
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  // Calculate penalty with diminishing returns per severity level
  let totalPenalty = 0;

  for (const severity of Object.keys(SEVERITY_WEIGHTS) as Severity[]) {
    const count = counts[severity];
    const weight = SEVERITY_WEIGHTS[severity];

    // Geometric series: sum = weight * (1 - r^n) / (1 - r)
    // This avoids looping and handles large counts efficiently
    if (count > 0) {
      const penalty = weight * (1 - Math.pow(DIMINISHING_FACTOR, count)) / (1 - DIMINISHING_FACTOR);
      totalPenalty += penalty;
    }
  }

  // Clamp to [0, 100]
  return Math.max(0, Math.min(100, Math.round(100 - totalPenalty)));
}

// ---------------------------------------------------------------------------
// Summary calculation
// ---------------------------------------------------------------------------

/**
 * Builds a ReportSummary from multiple AuditResults.
 *
 * @param results  All per-file audit results
 * @returns        Aggregated summary
 */
export function calculateSummary(results: AuditResult[]): ReportSummary {
  const summary: ReportSummary = {
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    overallScore: 100,
  };

  if (results.length === 0) return summary;

  // Aggregate findings across all results
  for (const result of results) {
    for (const finding of result.findings) {
      summary.totalFindings++;
      summary[finding.severity]++;
    }
  }

  // Overall score: weighted average of per-file scores
  // Weight each file equally (could be weighted by finding count in future)
  const avgScore =
    results.reduce((sum, r) => sum + r.score, 0) / results.length;
  summary.overallScore = Math.round(avgScore);

  return summary;
}

// ---------------------------------------------------------------------------
// Finding sorting
// ---------------------------------------------------------------------------

/**
 * Sorts findings by severity (critical first) then by line number.
 * Returns a new array — does not mutate the input.
 *
 * @param findings  Findings to sort
 * @returns         Sorted copy
 */
export function sortFindings(findings: AuditFinding[]): AuditFinding[] {
  return [...findings].sort((a, b) => {
    // Primary sort: severity (critical = 0, info = 4)
    const severityDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDiff !== 0) return severityDiff;

    // Secondary sort: line number (ascending), undefined lines go to the end
    const lineA = a.line ?? Infinity;
    const lineB = b.line ?? Infinity;
    return lineA - lineB;
  });
}

// ---------------------------------------------------------------------------
// Score band utility (used by reporters)
// ---------------------------------------------------------------------------

/**
 * Returns a human-readable label for a given score.
 */
export function getScoreBand(score: number): {
  label: string;
  color: string;
} {
  if (score >= 90) return { label: 'EXCELLENT', color: 'green' };
  if (score >= 75) return { label: 'GOOD', color: 'cyan' };
  if (score >= 50) return { label: 'FAIR', color: 'yellow' };
  if (score >= 25) return { label: 'POOR', color: 'redBright' };
  return { label: 'CRITICAL', color: 'red' };
}

/**
 * Renders a score as a Unicode block progress bar.
 *
 * Example output for score=65, width=20:
 *   "█████████████░░░░░░░"
 *
 * @param score  0–100
 * @param width  Total number of characters in the bar (default 20)
 */
export function renderScoreBar(score: number, width = 20): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  return '█'.repeat(filled) + '░'.repeat(empty);
}
