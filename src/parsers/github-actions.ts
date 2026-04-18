/**
 * GitHub Actions workflow YAML parser.
 *
 * Converts a raw .yml/.yaml workflow file into a typed GHAWorkflow AST
 * that analyzers can traverse without dealing with raw YAML objects.
 *
 * Approach:
 *   1. Parse YAML with js-yaml (throws on syntax errors)
 *   2. Walk the parsed object and map fields to our typed interfaces
 *   3. Normalise quirks in the GHA schema (e.g. `on` can be a string,
 *      array, or object; `runs-on` can be a string or array)
 *
 * The parser is intentionally lenient — unknown/unexpected fields are
 * ignored rather than causing failures, because real-world workflow files
 * are extremely varied.
 */

import yaml from 'js-yaml';
import type { GHAWorkflow, GHAJob, GHAStep } from '../types/ast.js';

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/**
 * Safely cast an unknown value to a Record<string, unknown>.
 * Returns an empty object if the value is not an object or is null/undefined.
 */
function asRecord(val: unknown): Record<string, unknown> {
  if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
    return val as Record<string, unknown>;
  }
  return {};
}

/**
 * Safely cast an unknown value to a string.
 * Returns empty string for non-string / undefined values.
 */
function asString(val: unknown): string {
  return typeof val === 'string' ? val : '';
}

/**
 * Safely cast an unknown value to string[].
 * Handles both a single string and an array of strings.
 */
function asStringArray(val: unknown): string[] {
  if (typeof val === 'string') return [val];
  if (Array.isArray(val)) return val.map(String);
  return [];
}

/**
 * Converts a Record<string, unknown> where all values are expected to be
 * strings into a Record<string, string>.
 * Non-string values are coerced with String().
 */
function toStringRecord(obj: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = String(value);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Step parser
// ---------------------------------------------------------------------------

/**
 * Parses a single step object from the YAML into a GHAStep.
 *
 * Handles both `uses:` steps (action references) and `run:` steps (shell).
 */
function parseStep(raw: unknown, index: number): GHAStep {
  const obj = asRecord(raw);

  const step: GHAStep = {};

  if (obj['id']) step.id = asString(obj['id']);
  if (obj['name']) step.name = asString(obj['name']);
  if (obj['uses']) step.uses = asString(obj['uses']);
  if (obj['run']) step.run = asString(obj['run']);
  if (obj['if']) step.if = asString(obj['if']);

  // Parse env block if present
  if (obj['env']) {
    step.env = toStringRecord(asRecord(obj['env']));
  }

  // js-yaml doesn't give us line numbers directly.
  // We use the step index as a proxy; callers can override if needed.
  step.line = index + 1;

  return step;
}

// ---------------------------------------------------------------------------
// Job parser
// ---------------------------------------------------------------------------

/**
 * Parses a single job object from the YAML into a GHAJob.
 *
 * @param id     The key name of this job in the `jobs:` map
 * @param raw    The raw YAML object for this job
 */
function parseJob(id: string, raw: unknown): GHAJob {
  const obj = asRecord(raw);

  // `runs-on` can be a string or array
  const runsOn: string | string[] = Array.isArray(obj['runs-on'])
    ? asStringArray(obj['runs-on'])
    : asString(obj['runs-on']) || 'ubuntu-latest';

  const steps: GHAStep[] = [];
  if (Array.isArray(obj['steps'])) {
    obj['steps'].forEach((s, idx) => {
      steps.push(parseStep(s, idx));
    });
  }

  const job: GHAJob = {
    id,
    runsOn,
    steps,
  };

  if (obj['name']) job.name = asString(obj['name']);
  if (obj['env']) job.env = toStringRecord(asRecord(obj['env']));
  if (obj['permissions']) {
    job.permissions = toStringRecord(asRecord(obj['permissions']));
  }
  if (obj['needs']) {
    job.needs = asStringArray(obj['needs']);
  }

  return job;
}

// ---------------------------------------------------------------------------
// Workflow-level `on:` trigger normaliser
// ---------------------------------------------------------------------------

/**
 * Normalises the `on:` field which can appear in three forms:
 *
 *   on: push                          → { push: {} }
 *   on: [push, pull_request]          → { push: {}, pull_request: {} }
 *   on:                               → { push: { branches: ['main'] }, ... }
 *     push:
 *       branches: [main]
 */
function normaliseOn(onField: unknown): Record<string, unknown> {
  if (typeof onField === 'string') {
    return { [onField]: {} };
  }
  if (Array.isArray(onField)) {
    const result: Record<string, unknown> = {};
    for (const event of onField) {
      result[String(event)] = {};
    }
    return result;
  }
  return asRecord(onField);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses a raw GitHub Actions workflow YAML string into a GHAWorkflow AST.
 *
 * @param content  Raw YAML text (contents of the .yml file)
 * @param source   File path used in the AST's `source` field
 * @returns        Typed GHAWorkflow structure
 * @throws         If the YAML is syntactically invalid
 *
 * @example
 * const wf = parseGitHubActionsWorkflow(
 *   fs.readFileSync('.github/workflows/ci.yml', 'utf-8'),
 *   '.github/workflows/ci.yml'
 * );
 */
export function parseGitHubActionsWorkflow(
  content: string,
  source = 'workflow.yml',
): GHAWorkflow {
  // js-yaml.load returns unknown; we assert it's an object after checking
  const doc = yaml.load(content);
  const obj = asRecord(doc);

  // Parse all jobs
  const jobs: GHAJob[] = [];
  const jobsObj = asRecord(obj['jobs']);
  for (const [jobId, jobData] of Object.entries(jobsObj)) {
    jobs.push(parseJob(jobId, jobData));
  }

  const workflow: GHAWorkflow = {
    source,
    on: normaliseOn(obj['on']),
    jobs,
  };

  if (obj['name']) workflow.name = asString(obj['name']);
  if (obj['env']) workflow.env = toStringRecord(asRecord(obj['env']));
  if (obj['permissions']) {
    workflow.permissions = toStringRecord(asRecord(obj['permissions']));
  }

  return workflow;
}
