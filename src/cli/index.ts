#!/usr/bin/env node
/**
 * Main CLI entry point for pipelens.
 *
 * Wires up all commands using commander:
 *   pipelens audit [path] [options]
 *   pipelens report [options]
 *   pipelens init
 *
 * This file is the value of the "bin.pipelens" field in package.json,
 * so it must start with the `#!/usr/bin/env node` shebang line.
 */

import { Command, Option } from 'commander';
import { PIPELENS_VERSION } from '../constants/index.js';
import { runAuditCommand } from './commands/audit.js';
import { runReportCommand } from './commands/report.js';
import { runInitCommand } from './commands/init.js';

// ---------------------------------------------------------------------------
// Root program
// ---------------------------------------------------------------------------

const program = new Command();

program
  .name('pipelens')
  .description('AI-powered Dockerfile and CI/CD pipeline security auditor')
  .version(PIPELENS_VERSION);

// ---------------------------------------------------------------------------
// `pipelens audit [path]`
// ---------------------------------------------------------------------------

program
  .command('audit [path]')
  .description('Audit Dockerfiles and CI/CD configurations at the given path')
  .option('--dockerfile <path>', 'Path to a specific Dockerfile to audit')
  .option('--workflow <path>', 'Path to a workflow file or directory to audit')
  .addOption(
    new Option('--format <format>', 'Output report format')
      .choices(['terminal', 'json', 'html'])
      .default('terminal'),
  )
  .option('--output <file>', 'Write report to file (in addition to stdout)')
  .option('--no-ai', 'Disable AI-powered suggestions')
  .addOption(
    new Option(
      '--severity <level>',
      'Minimum severity to report (filter out lower severities)',
    )
      .choices(['critical', 'high', 'medium', 'low', 'info'])
      .default('info'),
  )
  .addOption(
    new Option(
      '--fail-on <level>',
      'Exit with code 1 if any findings at or above this severity are found',
    )
      .choices(['critical', 'high', 'medium', 'low', 'info'])
      .default('high'),
  )
  .option('--config <path>', 'Path to pipelens.config.json')
  .action(async (targetPath: string | undefined, options: Record<string, unknown>) => {
    await runAuditCommand(targetPath ?? process.cwd(), {
      dockerfile: options['dockerfile'] as string | undefined,
      workflow: options['workflow'] as string | undefined,
      format: options['format'] as 'terminal' | 'json' | 'html' | undefined,
      output: options['output'] as string | undefined,
      ai: options['ai'] !== false,
      severity: options['severity'] as 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined,
      failOn: options['failOn'] as 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined,
      config: options['config'] as string | undefined,
    });
  });

// ---------------------------------------------------------------------------
// `pipelens report`
// ---------------------------------------------------------------------------

program
  .command('report')
  .description('Re-render a report from a saved audit JSON file')
  .option('--input <file>', 'Path to audit JSON file (default: pipelens-last-audit.json)')
  .addOption(
    new Option('--format <format>', 'Output format')
      .choices(['terminal', 'json', 'html'])
      .default('terminal'),
  )
  .option('--output <file>', 'Write rendered report to file')
  .action(async (options: Record<string, unknown>) => {
    await runReportCommand({
      input: options['input'] as string | undefined,
      format: options['format'] as 'terminal' | 'json' | 'html' | undefined,
      output: options['output'] as string | undefined,
    });
  });

// ---------------------------------------------------------------------------
// `pipelens init`
// ---------------------------------------------------------------------------

program
  .command('init')
  .description('Create a pipelens.config.json file in the current directory')
  .action(() => {
    runInitCommand();
  });

// ---------------------------------------------------------------------------
// Parse and run
// ---------------------------------------------------------------------------

program.parse(process.argv);
