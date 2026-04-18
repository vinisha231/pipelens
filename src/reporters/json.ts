/**
 * JSON reporter for pipelens.
 *
 * Produces a structured JSON report suitable for:
 *   - CI/CD pipeline integration (parse results to fail the build on critical findings)
 *   - Tool integrations (import into dashboards, ticket systems, etc.)
 *   - Archiving audit history
 *
 * The JSON output is the AuditReport interface directly serialized,
 * with no transformations — what you see in the types is what you get.
 */

import type { AuditReport } from '../types/index.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Serializes an AuditReport to a pretty-printed JSON string.
 *
 * The output is intentionally pretty-printed (2-space indent) rather than
 * minified — JSON reports are often read by humans in addition to machines.
 *
 * @param report  The audit report to serialize
 * @returns       Pretty-printed JSON string
 */
export function renderJSONReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Parses a JSON report string back into an AuditReport.
 * Useful for the `pipelens report` command which re-renders from a saved file.
 *
 * @param json  The JSON string to parse
 * @returns     Parsed AuditReport
 * @throws      SyntaxError if the JSON is invalid
 */
export function parseJSONReport(json: string): AuditReport {
  return JSON.parse(json) as AuditReport;
}

/**
 * Returns the appropriate exit code for a CI/CD pipeline based on the report.
 *
 * Exit code semantics:
 *   0 = No critical or high findings → pipeline passes
 *   1 = Critical or high findings found → pipeline should fail
 *
 * This lets users do:
 *   pipelens audit --format json | jq .summary.critical
 * or simply check the process exit code.
 *
 * @param report        The audit report
 * @param failOnSeverity  Minimum severity that triggers exit code 1 (default: 'high')
 */
export function getExitCode(
  report: AuditReport,
  failOnSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'high',
): number {
  const { summary } = report;

  const severityCounts: Record<string, number> = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info,
  };

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const failIdx = severityOrder.indexOf(failOnSeverity);

  for (let i = 0; i <= failIdx; i++) {
    const sev = severityOrder[i];
    if (sev && (severityCounts[sev] ?? 0) > 0) {
      return 1;
    }
  }

  return 0;
}
