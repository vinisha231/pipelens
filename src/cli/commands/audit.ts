/**
 * `pipelens audit` command implementation.
 *
 * Orchestrates the full audit workflow:
 *   1. Load configuration (file + CLI flag overrides)
 *   2. Start progress spinner
 *   3. Call the audit orchestrator
 *   4. Pass results to the appropriate reporter
 *   5. Write output (stdout or file)
 *   6. Exit with appropriate code
 */

import * as fs from 'fs';
import * as path from 'path';
import ora from 'ora';
import type { PipelensConfig, ReportFormat, Severity } from '../../types/index.js';
import { loadConfig } from '../config.js';
import { runAudit } from '../../orchestrator/index.js';
import { renderTerminalReport } from '../../reporters/terminal.js';
import { renderJSONReport, getExitCode } from '../../reporters/json.js';
import { renderHTMLReport } from '../../reporters/html.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * CLI options for the `audit` command, parsed by commander.
 */
export interface AuditCommandOptions {
  dockerfile?: string;
  workflow?: string;
  format?: ReportFormat;
  output?: string;
  ai?: boolean;
  severity?: Severity;
  config?: string;
  failOn?: Severity;
}

// ---------------------------------------------------------------------------
// Main command handler
// ---------------------------------------------------------------------------

/**
 * Handles the `pipelens audit [path]` command.
 *
 * @param targetPath  Path to audit (defaults to current directory)
 * @param options     CLI options
 */
export async function runAuditCommand(
  targetPath: string,
  options: AuditCommandOptions,
): Promise<void> {
  // Resolve the target path to absolute
  const resolvedTarget = path.resolve(targetPath);

  // Load config from file, then override with CLI flags
  const fileConfig = await loadConfig(options.config);
  const config: PipelensConfig = {
    ...fileConfig,
    ...(options.format !== undefined && { format: options.format }),
    ...(options.output !== undefined && { output: options.output }),
    ...(options.ai === false && { ai: false }),
    ...(options.severity !== undefined && { severity: options.severity }),
  };

  const format = config.format ?? 'terminal';
  const spinner = ora({
    text: 'Starting audit...',
    color: 'cyan',
    // Disable spinner in non-terminal environments (CI logs)
    isSilent: format === 'json',
  }).start();

  try {
    const report = await runAudit({
      targetPath: resolvedTarget,
      dockerfilePath: options.dockerfile
        ? path.resolve(options.dockerfile)
        : undefined,
      workflowPath: options.workflow
        ? path.resolve(options.workflow)
        : undefined,
      config,
      onProgress: (msg) => {
        spinner.text = msg;
      },
    });

    spinner.stop();

    // Render the report in the requested format
    let output: string;
    switch (format) {
      case 'json':
        output = renderJSONReport(report);
        break;
      case 'html':
        output = renderHTMLReport(report);
        break;
      default:
        output = renderTerminalReport(report);
    }

    // Write to file or stdout
    if (config.output) {
      fs.writeFileSync(config.output, output, 'utf-8');
      // Always print a summary to stdout even when writing to file
      if (format !== 'terminal') {
        const terminalSummary = renderTerminalReport(report);
        process.stdout.write(terminalSummary);
      }
      process.stdout.write(
        `\nReport written to: ${config.output}\n`,
      );
    } else {
      process.stdout.write(output + '\n');
    }

    // Save last audit for `pipelens report` command
    const lastAuditPath = path.join(process.cwd(), 'pipelens-last-audit.json');
    fs.writeFileSync(lastAuditPath, renderJSONReport(report), 'utf-8');

    // Set exit code based on findings severity
    const failOn = options.failOn ?? 'high';
    const exitCode = getExitCode(report, failOn);
    process.exit(exitCode);
  } catch (error) {
    spinner.fail('Audit failed');
    const errMsg = error instanceof Error ? error.message : String(error);
    process.stderr.write(`Error: ${errMsg}\n`);
    process.exit(2);
  }
}
