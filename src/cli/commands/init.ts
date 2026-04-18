/**
 * `pipelens init` command implementation.
 *
 * Creates a default pipelens.config.json in the current directory,
 * or updates an existing one interactively.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { PipelensConfig } from '../../types/index.js';
import { DEFAULT_CONFIG } from '../../constants/index.js';

/**
 * Default config content written by `pipelens init`.
 */
const DEFAULT_CONFIG_CONTENT: PipelensConfig = {
  ignore: [],
  severity: DEFAULT_CONFIG.severity,
  ai: DEFAULT_CONFIG.ai,
  format: DEFAULT_CONFIG.format,
  output: undefined,
};

/**
 * Handles the `pipelens init` command.
 * Creates pipelens.config.json in the current directory.
 */
export function runInitCommand(): void {
  const configPath = path.join(process.cwd(), 'pipelens.config.json');

  if (fs.existsSync(configPath)) {
    process.stdout.write(
      `Config file already exists at ${configPath}\n` +
        'Delete it first if you want to recreate it.\n',
    );
    return;
  }

  const configContent = JSON.stringify(
    {
      ...DEFAULT_CONFIG_CONTENT,
      $schema:
        'https://raw.githubusercontent.com/vinisha231/pipelens/main/schema/config.json',
      // Helpful comments as a separate description field
      _comment:
        'pipelens configuration. See https://github.com/vinisha231/pipelens#configuration for docs.',
    },
    null,
    2,
  );

  fs.writeFileSync(configPath, configContent, 'utf-8');

  process.stdout.write(`Created ${configPath}\n\n`);
  process.stdout.write('Configuration options:\n');
  process.stdout.write(
    '  ignore   — Array of rule IDs to skip (e.g. ["DF-BP-003"])\n',
  );
  process.stdout.write(
    '  severity — Minimum severity to report (critical/high/medium/low/info)\n',
  );
  process.stdout.write(
    '  ai       — Enable AI suggestions (requires ANTHROPIC_API_KEY)\n',
  );
  process.stdout.write(
    '  format   — Default output format (terminal/json/html)\n',
  );
  process.stdout.write(
    '  output   — Write report to this file path\n',
  );
  process.stdout.write(
    '\nSet ANTHROPIC_API_KEY environment variable to enable AI suggestions.\n',
  );
}
