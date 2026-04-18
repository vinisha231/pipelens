/**
 * `pipelens report` command implementation.
 *
 * Re-renders a report from the last saved audit (pipelens-last-audit.json)
 * or a specified JSON file in a different format.
 *
 * This is useful when you want to:
 *   - Re-render a JSON report as HTML after the fact
 *   - Share a report in a different format without re-running the audit
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ReportFormat } from '../../types/index.js';
import { parseJSONReport } from '../../reporters/json.js';
import { renderTerminalReport } from '../../reporters/terminal.js';
import { renderJSONReport } from '../../reporters/json.js';
import { renderHTMLReport } from '../../reporters/html.js';

export interface ReportCommandOptions {
  input?: string;
  format?: ReportFormat;
  output?: string;
}

/**
 * Handles the `pipelens report` command.
 *
 * @param options  CLI options
 */
export async function runReportCommand(options: ReportCommandOptions): Promise<void> {
  const inputPath = options.input
    ? path.resolve(options.input)
    : path.join(process.cwd(), 'pipelens-last-audit.json');

  if (!fs.existsSync(inputPath)) {
    process.stderr.write(
      `Error: No audit report found at ${inputPath}\n` +
        'Run `pipelens audit` first to generate a report.\n',
    );
    process.exit(1);
  }

  let reportJson: string;
  try {
    reportJson = fs.readFileSync(inputPath, 'utf-8');
  } catch (err) {
    process.stderr.write(`Error reading ${inputPath}: ${err}\n`);
    process.exit(1);
  }

  const report = parseJSONReport(reportJson);
  const format = options.format ?? 'terminal';

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

  if (options.output) {
    fs.writeFileSync(options.output, output, 'utf-8');
    process.stdout.write(`Report written to: ${options.output}\n`);
  } else {
    process.stdout.write(output + '\n');
  }
}
