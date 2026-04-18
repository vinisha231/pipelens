/**
 * Rich terminal reporter for pipelens.
 *
 * Produces beautiful, colored terminal output using:
 *   - chalk: text colors and styles
 *   - boxen: bordered boxes for sections
 *
 * Output structure:
 *   1. Header box (pipelens banner + version)
 *   2. Per-file sections:
 *      - File path + score bar
 *      - Finding cards (severity badge + title + evidence + fix)
 *      - AI suggestions (if available)
 *   3. Summary table (severity counts)
 *   4. Overall score with progress bar
 *   5. AI narrative (if available)
 */

import chalk from 'chalk';
import boxen from 'boxen';
import type { AuditReport, AuditResult, AuditFinding, Severity } from '../types/index.js';
import { renderScoreBar, getScoreBand } from '../scoring/engine.js';
import { PIPELENS_VERSION } from '../constants/index.js';

// ---------------------------------------------------------------------------
// Color helpers
// ---------------------------------------------------------------------------

/**
 * Returns a chalk-colored severity badge string.
 * The badge is padded to a fixed width so finding lists align correctly.
 */
function severityBadge(severity: Severity): string {
  const labels: Record<Severity, string> = {
    critical: chalk.bgRed.white.bold(' CRITICAL '),
    high:     chalk.bgRedBright.black.bold('  HIGH    '),
    medium:   chalk.bgYellow.black.bold('  MEDIUM  '),
    low:      chalk.bgBlue.white.bold('   LOW    '),
    info:     chalk.bgGray.white.bold('   INFO   '),
  };
  return labels[severity];
}

/**
 * Colors a score number based on the score band.
 */
function coloredScore(score: number): string {
  const { color } = getScoreBand(score);
  const chalkColor = chalk[color as keyof typeof chalk] as (s: string) => string;
  return chalkColor(score.toString());
}

/**
 * Returns a colored score bar.
 */
function coloredScoreBar(score: number, width = 20): string {
  const bar = renderScoreBar(score, width);
  const { color } = getScoreBand(score);
  const chalkColor = chalk[color as keyof typeof chalk] as (s: string) => string;
  return chalkColor(bar);
}

// ---------------------------------------------------------------------------
// Finding card
// ---------------------------------------------------------------------------

/**
 * Renders a single finding as a formatted text block.
 */
function renderFinding(finding: AuditFinding, index: number): string {
  const lines: string[] = [];

  // Title line: [badge] [ID] Title
  const locationStr = finding.line ? chalk.dim(` (line ${finding.line})`) : '';
  lines.push(
    `  ${severityBadge(finding.severity)} ${chalk.bold(finding.id)}${locationStr}`,
  );
  lines.push(`  ${chalk.white.bold(finding.title)}`);
  lines.push('');

  // Description (word-wrapped at 80 chars)
  const desc = finding.description.replace(/\s+/g, ' ').trim();
  lines.push(`  ${chalk.dim(desc)}`);

  // Evidence
  if (finding.evidence) {
    lines.push('');
    lines.push(chalk.dim('  Evidence:'));
    const evidenceLines = finding.evidence.split('\n').slice(0, 5); // max 5 lines
    for (const line of evidenceLines) {
      lines.push(`  ${chalk.redBright('  ' + line)}`);
    }
    if (finding.evidence.split('\n').length > 5) {
      lines.push(chalk.dim('  ... (truncated)'));
    }
  }

  // Deterministic fix suggestion
  if (finding.fix) {
    lines.push('');
    lines.push(chalk.dim('  Fix:'));
    const fixLines = finding.fix.split('\n').slice(0, 8);
    for (const line of fixLines) {
      lines.push(`  ${chalk.green('  ' + line)}`);
    }
  }

  // AI suggestion (if available)
  if (finding.aiSuggestion) {
    lines.push('');
    lines.push(`  ${chalk.cyan.bold('✦ AI Suggestion:')}`);
    // Take first 3 lines of AI suggestion to keep output manageable
    const aiLines = finding.aiSuggestion.trim().split('\n').slice(0, 6);
    for (const line of aiLines) {
      lines.push(`  ${chalk.cyan('  ' + line)}`);
    }
    if (finding.aiSuggestion.split('\n').length > 6) {
      lines.push(chalk.dim('  ... (see full report for complete AI suggestion)'));
    }
  }

  // References
  if (finding.references && finding.references.length > 0) {
    lines.push('');
    lines.push(chalk.dim('  References: ') + chalk.dim(finding.references[0]));
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// File section
// ---------------------------------------------------------------------------

/**
 * Renders the section for one analyzed file.
 */
function renderFileSection(result: AuditResult): string {
  const lines: string[] = [];
  const { label } = getScoreBand(result.score);

  // Section header
  const relPath = result.target.replace(process.cwd(), '.');
  lines.push(chalk.white.bold(`\n┌─ ${relPath} `).padEnd(72, '─') + '┐');
  lines.push(
    `│  Score: ${coloredScore(result.score)}/100  ${coloredScoreBar(result.score)} ${chalk.bold(label)}`,
  );
  lines.push(
    `│  ${chalk.dim(`${result.findings.length} finding(s) · ${result.analyzerType} · ${result.duration}ms`)}`,
  );
  lines.push(chalk.white('└' + '─'.repeat(71) + '┘'));

  if (result.findings.length === 0) {
    lines.push(chalk.green('  No findings — this file looks clean!'));
    return lines.join('\n');
  }

  // Findings
  for (let i = 0; i < result.findings.length; i++) {
    const finding = result.findings[i];
    if (finding) {
      lines.push('');
      lines.push(renderFinding(finding, i));
      if (i < result.findings.length - 1) {
        lines.push(chalk.dim('  ' + '─'.repeat(68)));
      }
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

/**
 * Renders the summary table showing finding counts by severity.
 */
function renderSummary(report: AuditReport): string {
  const { summary } = report;
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.white.bold('  Summary'));
  lines.push(chalk.dim('  ' + '─'.repeat(40)));

  const rows: Array<[string, number]> = [
    [severityBadge('critical'), summary.critical],
    [severityBadge('high'), summary.high],
    [severityBadge('medium'), summary.medium],
    [severityBadge('low'), summary.low],
    [severityBadge('info'), summary.info],
  ];

  for (const [badge, count] of rows) {
    const countStr = count === 0 ? chalk.dim('0') : chalk.bold(count.toString());
    lines.push(`  ${badge}  ${countStr} finding(s)`);
  }

  lines.push(chalk.dim('  ' + '─'.repeat(40)));
  lines.push(
    `  Total: ${chalk.bold(summary.totalFindings.toString())} finding(s) across ${chalk.bold(report.results.length.toString())} file(s)`,
  );

  // Overall score bar
  lines.push('');
  const { label } = getScoreBand(summary.overallScore);
  lines.push(
    `  Overall Score: ${coloredScore(summary.overallScore)}/100  ${coloredScoreBar(summary.overallScore, 30)} ${chalk.bold(label)}`,
  );

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/**
 * Renders the pipelens ASCII header with version info.
 */
function renderHeader(): string {
  const header = [
    chalk.cyan.bold('  ██████╗ ██╗██████╗ ███████╗██╗     ███████╗███╗   ██╗███████╗'),
    chalk.cyan.bold('  ██╔══██╗██║██╔══██╗██╔════╝██║     ██╔════╝████╗  ██║██╔════╝'),
    chalk.cyan.bold('  ██████╔╝██║██████╔╝█████╗  ██║     █████╗  ██╔██╗ ██║███████╗'),
    chalk.cyan.bold('  ██╔═══╝ ██║██╔═══╝ ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║╚════██║'),
    chalk.cyan.bold('  ██║     ██║██║     ███████╗███████╗███████╗██║ ╚████║███████║'),
    chalk.cyan.bold('  ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝'),
    '',
    chalk.dim(`  AI-powered Dockerfile & CI/CD pipeline security auditor  v${PIPELENS_VERSION}`),
  ].join('\n');

  return boxen(header, {
    padding: { top: 1, bottom: 1, left: 2, right: 2 },
    margin: { top: 0, bottom: 0, left: 0, right: 0 },
    borderStyle: 'round',
    borderColor: 'cyan',
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Renders a complete AuditReport to a string for terminal output.
 *
 * @param report  The report produced by the orchestrator
 * @returns       A formatted string ready to print with console.log
 */
export function renderTerminalReport(report: AuditReport): string {
  const sections: string[] = [];

  // Header
  sections.push(renderHeader());
  sections.push('');

  // No files found
  if (report.results.length === 0) {
    sections.push(
      boxen(
        chalk.yellow('  No auditable files found.\n') +
        chalk.dim('  Pipelens looks for Dockerfiles, .github/workflows/*.yml,\n') +
        chalk.dim('  and .gitlab-ci.yml files.'),
        { padding: 1, borderStyle: 'round', borderColor: 'yellow' },
      ),
    );
    return sections.join('\n');
  }

  // Per-file sections
  for (const result of report.results) {
    sections.push(renderFileSection(result));
  }

  // Summary
  sections.push(renderSummary(report));

  // AI narrative
  if (report.aiNarrative) {
    sections.push('');
    sections.push(
      boxen(
        chalk.cyan.bold('  AI Analysis\n\n') +
        report.aiNarrative
          .split('\n')
          .map((line) => '  ' + line)
          .join('\n'),
        {
          padding: 1,
          borderStyle: 'round',
          borderColor: 'cyan',
          title: 'AI Insights',
          titleAlignment: 'left',
        },
      ),
    );
  }

  sections.push('');
  return sections.join('\n');
}
