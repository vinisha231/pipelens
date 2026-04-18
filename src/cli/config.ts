/**
 * Configuration file loader for pipelens.
 *
 * Loads pipelens.config.json from:
 *   1. An explicit path (--config flag)
 *   2. The current working directory
 *   3. Falls back to default config if no file found
 *
 * Config files are validated after loading — invalid fields produce
 * clear error messages rather than cryptic failures downstream.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { PipelensConfig, Severity, ReportFormat } from '../types/index.js';
import { DEFAULT_CONFIG } from '../constants/index.js';

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_FORMATS: ReportFormat[] = ['terminal', 'json', 'html'];

/**
 * Validates and normalizes a raw config object.
 * Returns validated config + array of validation error messages.
 */
function validateConfig(
  raw: unknown,
): { config: PipelensConfig; errors: string[] } {
  const errors: string[] = [];
  const config: PipelensConfig = { ...DEFAULT_CONFIG };

  if (raw === null || typeof raw !== 'object') {
    return { config, errors: ['Config file must be a JSON object'] };
  }

  const obj = raw as Record<string, unknown>;

  // ignore: string[]
  if ('ignore' in obj) {
    if (!Array.isArray(obj['ignore']) || !obj['ignore'].every((x) => typeof x === 'string')) {
      errors.push('Config "ignore" must be an array of strings');
    } else {
      config.ignore = obj['ignore'] as string[];
    }
  }

  // severity: Severity
  if ('severity' in obj) {
    if (!VALID_SEVERITIES.includes(obj['severity'] as Severity)) {
      errors.push(
        `Config "severity" must be one of: ${VALID_SEVERITIES.join(', ')}`,
      );
    } else {
      config.severity = obj['severity'] as Severity;
    }
  }

  // ai: boolean
  if ('ai' in obj) {
    if (typeof obj['ai'] !== 'boolean') {
      errors.push('Config "ai" must be a boolean');
    } else {
      config.ai = obj['ai'];
    }
  }

  // format: ReportFormat
  if ('format' in obj) {
    if (!VALID_FORMATS.includes(obj['format'] as ReportFormat)) {
      errors.push(
        `Config "format" must be one of: ${VALID_FORMATS.join(', ')}`,
      );
    } else {
      config.format = obj['format'] as ReportFormat;
    }
  }

  // output: string | undefined
  if ('output' in obj && obj['output'] !== null && obj['output'] !== undefined) {
    if (typeof obj['output'] !== 'string') {
      errors.push('Config "output" must be a string path');
    } else {
      config.output = obj['output'];
    }
  }

  return { config, errors };
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/**
 * Loads pipelens configuration from a JSON file.
 *
 * @param explicitPath  If provided, loads from this path instead of auto-discovering
 * @returns             Validated PipelensConfig (defaults applied for missing fields)
 */
export async function loadConfig(explicitPath?: string): Promise<PipelensConfig> {
  // Determine config file path
  let configPath: string | null = null;

  if (explicitPath) {
    configPath = path.resolve(explicitPath);
    if (!fs.existsSync(configPath)) {
      process.stderr.write(
        `Warning: Config file not found at ${configPath} — using defaults\n`,
      );
      return { ...DEFAULT_CONFIG };
    }
  } else {
    // Auto-discover in current directory
    const candidates = [
      path.join(process.cwd(), 'pipelens.config.json'),
      path.join(process.cwd(), '.pipelens.json'),
    ];
    configPath = candidates.find((p) => fs.existsSync(p)) ?? null;
  }

  // No config file found — use defaults silently
  if (!configPath) {
    return { ...DEFAULT_CONFIG };
  }

  // Load and parse the config file
  let rawText: string;
  try {
    rawText = fs.readFileSync(configPath, 'utf-8');
  } catch (err) {
    process.stderr.write(
      `Warning: Could not read config file ${configPath}: ${err}\n`,
    );
    return { ...DEFAULT_CONFIG };
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(rawText);
  } catch (err) {
    process.stderr.write(
      `Warning: Config file ${configPath} is not valid JSON: ${err}\n`,
    );
    return { ...DEFAULT_CONFIG };
  }

  const { config, errors } = validateConfig(rawJson);

  if (errors.length > 0) {
    process.stderr.write(
      `Warning: Config validation errors in ${configPath}:\n` +
        errors.map((e) => `  - ${e}`).join('\n') +
        '\nUsing defaults for invalid fields.\n',
    );
  }

  return config;
}
