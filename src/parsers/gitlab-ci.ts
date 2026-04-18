/**
 * GitLab CI configuration parser (.gitlab-ci.yml).
 *
 * Converts a raw YAML string into a typed GitLabCIConfig AST.
 *
 * GitLab CI YAML has a flat structure: every top-level key that isn't
 * a reserved keyword (stages, variables, image, cache, etc.) is a job.
 * This parser separates the two groups and maps them to typed interfaces.
 *
 * Reserved top-level keys (not treated as jobs):
 *   stages, variables, image, services, cache, before_script, after_script,
 *   workflow, include, default, pages (special job)
 */

import yaml from 'js-yaml';
import type { GitLabCIConfig, GitLabJob, GitLabCache } from '../types/ast.js';

// ---------------------------------------------------------------------------
// Reserved top-level keywords that are NOT job definitions
// ---------------------------------------------------------------------------

/**
 * These keys appear at the top level of .gitlab-ci.yml but are not jobs.
 * Anything else at the top level is treated as a job definition.
 */
const GITLAB_RESERVED_KEYS = new Set([
  'stages',
  'variables',
  'image',
  'services',
  'cache',
  'before_script',
  'after_script',
  'workflow',
  'include',
  'default',
]);

// ---------------------------------------------------------------------------
// Helper utilities (same pattern as github-actions parser)
// ---------------------------------------------------------------------------

function asRecord(val: unknown): Record<string, unknown> {
  if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
    return val as Record<string, unknown>;
  }
  return {};
}

function asString(val: unknown): string {
  return typeof val === 'string' ? val : '';
}

function asStringArray(val: unknown): string[] {
  if (typeof val === 'string') return [val];
  if (Array.isArray(val)) return val.map(String);
  return [];
}

function toStringRecord(obj: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    result[k] = String(v);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Cache parser
// ---------------------------------------------------------------------------

/**
 * Parses the `cache:` block which can appear at the global level or per-job.
 */
function parseCache(raw: unknown): GitLabCache | undefined {
  if (!raw) return undefined;
  const obj = asRecord(raw);
  const cache: GitLabCache = {};

  if (obj['paths']) cache.paths = asStringArray(obj['paths']);
  if (obj['key']) {
    cache.key = typeof obj['key'] === 'string'
      ? obj['key']
      : asRecord(obj['key']) as Record<string, unknown>;
  }
  if (obj['policy']) {
    const policy = asString(obj['policy']);
    if (policy === 'pull' || policy === 'push' || policy === 'pull-push') {
      cache.policy = policy;
    }
  }

  return Object.keys(cache).length > 0 ? cache : undefined;
}

// ---------------------------------------------------------------------------
// Job parser
// ---------------------------------------------------------------------------

/**
 * Parses a single GitLab CI job definition.
 *
 * @param name  The job's key name in the YAML
 * @param raw   The raw YAML object for this job
 */
function parseGitLabJob(name: string, raw: unknown): GitLabJob {
  const obj = asRecord(raw);

  // `script` is required in a valid job; we default to [] if absent
  const script = asStringArray(obj['script']);

  const job: GitLabJob = {
    name,
    script,
  };

  // Image: can be a string "node:18" or an object { name: ..., entrypoint: [...] }
  if (obj['image']) {
    if (typeof obj['image'] === 'string') {
      job.image = obj['image'];
    } else {
      const imgObj = asRecord(obj['image']);
      job.image = {
        name: asString(imgObj['name']),
        entrypoint: imgObj['entrypoint']
          ? asStringArray(imgObj['entrypoint'])
          : undefined,
      };
    }
  }

  if (obj['before_script']) job.beforeScript = asStringArray(obj['before_script']);
  if (obj['after_script']) job.afterScript = asStringArray(obj['after_script']);
  if (obj['stage']) job.stage = asString(obj['stage']);
  if (obj['variables']) job.variables = toStringRecord(asRecord(obj['variables']));
  if (obj['cache']) job.cache = parseCache(obj['cache']);
  if (obj['artifacts']) job.artifacts = asRecord(obj['artifacts']);
  if (obj['tags']) job.tags = asStringArray(obj['tags']);

  // Detect privileged mode — commonly set for Docker-in-Docker setups
  if (typeof obj['privileged'] === 'boolean') {
    job.privileged = obj['privileged'];
  } else if (obj['services']) {
    // If `docker:dind` is listed as a service, the runner likely needs privileged
    const services = asStringArray(obj['services']);
    job.privileged = services.some((s) => s.includes('docker:dind') || s.includes('docker:20'));
  }

  return job;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses a raw .gitlab-ci.yml string into a GitLabCIConfig AST.
 *
 * @param content  Raw YAML text
 * @param source   File path for the AST's `source` field
 * @returns        Typed GitLabCIConfig structure
 * @throws         If the YAML is syntactically invalid
 *
 * @example
 * const config = parseGitLabCI(
 *   fs.readFileSync('.gitlab-ci.yml', 'utf-8'),
 *   '.gitlab-ci.yml'
 * );
 */
export function parseGitLabCI(
  content: string,
  source = '.gitlab-ci.yml',
): GitLabCIConfig {
  const doc = yaml.load(content);
  const obj = asRecord(doc);

  const config: GitLabCIConfig = {
    source,
    jobs: [],
  };

  // Global-level fields
  if (obj['image']) config.image = asString(obj['image']);
  if (obj['stages']) config.stages = asStringArray(obj['stages']);
  if (obj['variables']) config.variables = toStringRecord(asRecord(obj['variables']));
  if (obj['cache']) config.cache = parseCache(obj['cache']);
  if (obj['before_script']) config.beforeScript = asStringArray(obj['before_script']);
  if (obj['after_script']) config.afterScript = asStringArray(obj['after_script']);

  // Everything that isn't a reserved key is a job
  for (const [key, value] of Object.entries(obj)) {
    if (GITLAB_RESERVED_KEYS.has(key)) continue;

    // Skip non-object values at the top level (e.g. anchors/aliases resolved by yaml)
    if (typeof value !== 'object' || value === null || Array.isArray(value)) continue;

    // Jobs that start with `.` are hidden/template jobs — still worth auditing
    config.jobs.push(parseGitLabJob(key, value));
  }

  return config;
}
