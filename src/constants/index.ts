/**
 * Central constants for pipelens.
 *
 * Keeping magic numbers and strings here (rather than scattered across
 * analyzer files) makes it easy to tune the scoring model, add new rules,
 * and keep rule IDs consistent across the entire codebase.
 */

import type { Severity } from '../types/index.js';

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/** Current pipelens version — keep in sync with package.json */
export const PIPELENS_VERSION = '0.1.0';

// ---------------------------------------------------------------------------
// Severity weights
// ---------------------------------------------------------------------------

/**
 * Numeric penalty weights for each severity level.
 *
 * These are used by the scoring engine to calculate a 0–100 health score.
 * The values are loosely inspired by the CVSS scoring system:
 *   - CRITICAL issues heavily penalize the score (like CVSS 9-10)
 *   - HIGH issues are significant but not catastrophic
 *   - Lower severities contribute minor penalties
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40, // One critical finding can cut score by 40 points
  high: 20,     // One high finding cuts by 20 points
  medium: 10,   // Medium findings deduct 10 points each
  low: 5,       // Low findings deduct 5 points each
  info: 1,      // Info findings are nearly free (just informational)
};

/**
 * Human-readable labels for each severity level, used in reports.
 */
export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

/**
 * Sort order for severities (lower number = displayed first).
 */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ---------------------------------------------------------------------------
// Rule IDs — Dockerfile
// ---------------------------------------------------------------------------

/**
 * Dockerfile security rule IDs.
 * Format: DF-SEC-NNN
 */
export const RULE_IDS = {
  // Dockerfile security
  DF_SEC_001: 'DF-SEC-001', // Running as root
  DF_SEC_002: 'DF-SEC-002', // Secrets in ENV
  DF_SEC_003: 'DF-SEC-003', // Dangerous RUN (curl|sh)
  DF_SEC_004: 'DF-SEC-004', // Sensitive port exposed

  // Dockerfile layer optimization
  DF_LAYER_001: 'DF-LAYER-001', // Package cache not cleared
  DF_LAYER_002: 'DF-LAYER-002', // Multiple RUN commands (could be chained)
  DF_LAYER_003: 'DF-LAYER-003', // Source copied before deps (breaks caching)
  DF_LAYER_004: 'DF-LAYER-004', // package.json not isolated before npm install

  // Dockerfile best practices
  DF_BP_001: 'DF-BP-001', // Unpinned :latest tag
  DF_BP_002: 'DF-BP-002', // ADD instead of COPY
  DF_BP_003: 'DF-BP-003', // No HEALTHCHECK
  DF_BP_004: 'DF-BP-004', // Large image — alpine alternative
  DF_BP_005: 'DF-BP-005', // No WORKDIR set

  // GitHub Actions security
  GHA_SEC_001: 'GHA-SEC-001', // Hardcoded secret
  GHA_SEC_002: 'GHA-SEC-002', // Secret echoed to log
  GHA_SEC_003: 'GHA-SEC-003', // Script injection via untrusted input

  // GitHub Actions permissions
  GHA_PERM_001: 'GHA-PERM-001', // Overly broad write permissions
  GHA_PERM_002: 'GHA-PERM-002', // Missing permissions block

  // GitHub Actions dependency pinning
  GHA_PIN_001: 'GHA-PIN-001', // Action pinned to branch, not SHA

  // GitHub Actions caching
  GHA_CACHE_001: 'GHA-CACHE-001', // Missing dependency cache

  // GitLab CI security
  GL_SEC_001: 'GL-SEC-001', // Secret in logs
  GL_SEC_002: 'GL-SEC-002', // Privileged mode without justification

  // GitLab CI optimization
  GL_OPT_001: 'GL-OPT-001', // Missing cache
  GL_OPT_002: 'GL-OPT-002', // No stages defined (all jobs run in parallel)
} as const;

// ---------------------------------------------------------------------------
// Sensitive port numbers
// ---------------------------------------------------------------------------

/**
 * Port numbers that are considered sensitive when EXPOSEd in a Dockerfile.
 * These are common services that shouldn't be exposed in production containers
 * without a documented reason.
 */
export const SENSITIVE_PORTS: Record<number, string> = {
  22: 'SSH — exposing SSH in a container is a security risk',
  23: 'Telnet — cleartext protocol, never expose',
  3306: 'MySQL — database should not be directly exposed',
  5432: 'PostgreSQL — database should not be directly exposed',
  6379: 'Redis — should not be publicly accessible',
  27017: 'MongoDB — database should not be directly exposed',
  9200: 'Elasticsearch — should not be publicly accessible',
  2375: 'Docker daemon (unencrypted) — critical security risk',
  2376: 'Docker daemon — should not be exposed from container',
};

// ---------------------------------------------------------------------------
// Secret-like patterns for ENV var value detection
// ---------------------------------------------------------------------------

/**
 * Regex patterns for ENV var keys that suggest the value is a secret.
 * These are used by the Dockerfile security analyzer to flag ENV instructions
 * that appear to contain credentials.
 */
export const SECRET_KEY_PATTERNS: RegExp[] = [
  /password/i,
  /passwd/i,
  /secret/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /access[_-]?token/i,
  /auth[_-]?token/i,
  /bearer[_-]?token/i,
  /credentials?/i,
  /connection[_-]?string/i,
  /database[_-]?url/i,
  /db[_-]?pass/i,
  /db[_-]?password/i,
];

/**
 * Regex patterns for inline secret values (not just key names).
 * Detects things like "password=hunter2" or "token=ghp_..." in RUN commands.
 */
export const SECRET_VALUE_PATTERNS: RegExp[] = [
  /password\s*=\s*\S+/i,
  /secret\s*=\s*\S+/i,
  /api[_-]?key\s*=\s*\S+/i,
  /ghp_[A-Za-z0-9]{36}/, // GitHub personal access token
  /ghs_[A-Za-z0-9]{36}/, // GitHub Actions token
  /AKIA[0-9A-Z]{16}/,     // AWS Access Key ID
  /sk-[A-Za-z0-9]{48}/,   // OpenAI key pattern
];

// ---------------------------------------------------------------------------
// Large base images that have known alpine alternatives
// ---------------------------------------------------------------------------

/**
 * Base images where an alpine or slim variant is available and recommended.
 * Maps image name → suggested alternative.
 */
export const LARGE_IMAGE_ALTERNATIVES: Record<string, string> = {
  ubuntu: 'alpine or ubuntu:22.04-slim',
  debian: 'debian:bookworm-slim or alpine',
  centos: 'alpine (CentOS is EOL)',
  fedora: 'alpine',
  node: 'node:lts-alpine',
  python: 'python:3.12-alpine',
  ruby: 'ruby:3.3-alpine',
  golang: 'golang:1.22-alpine (build stage) + scratch/alpine (final stage)',
  java: 'eclipse-temurin:21-jre-alpine or amazoncorretto:21-alpine',
  openjdk: 'eclipse-temurin:21-jre-alpine',
  maven: 'maven:3.9-eclipse-temurin-21-alpine',
};

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

/**
 * Default values for PipelensConfig fields.
 * Applied when a user's config file is absent or a field is not set.
 */
export const DEFAULT_CONFIG = {
  ignore: [] as string[],
  severity: 'info' as Severity,
  ai: true,
  format: 'terminal' as const,
  output: undefined as string | undefined,
};

// ---------------------------------------------------------------------------
// AI model settings
// ---------------------------------------------------------------------------

/**
 * The AI model identifier used for analysis.
 * Only change this in the constants file — never hard-code it elsewhere.
 */
export const AI_MODEL = 'claude-sonnet-4-6';

/**
 * Maximum tokens to request from the AI for narrative responses.
 */
export const AI_MAX_TOKENS = 1024;

/**
 * Number of retry attempts when AI API calls fail.
 */
export const AI_RETRY_ATTEMPTS = 3;

/**
 * Base delay (ms) for exponential backoff on AI retries.
 * Actual delay = AI_RETRY_BASE_DELAY * 2^(attempt)
 */
export const AI_RETRY_BASE_DELAY = 500;

// ---------------------------------------------------------------------------
// Scoring thresholds
// ---------------------------------------------------------------------------

/**
 * Score bands for the health score (0–100).
 * Used by reporters to choose color/label.
 */
export const SCORE_BANDS = {
  excellent: { min: 90, label: 'EXCELLENT', color: 'green' },
  good: { min: 75, label: 'GOOD', color: 'cyan' },
  fair: { min: 50, label: 'FAIR', color: 'yellow' },
  poor: { min: 25, label: 'POOR', color: 'redBright' },
  critical: { min: 0, label: 'CRITICAL', color: 'red' },
} as const;
