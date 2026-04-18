/**
 * GitLab CI security and optimization analyzer.
 *
 * Analyzes .gitlab-ci.yml configurations for:
 *
 *   GL-SEC-001: Secret/credential variables exposed in logs
 *   GL-SEC-002: Privileged Docker-in-Docker without clear justification
 *   GL-OPT-001: Missing cache configuration for build artifacts
 *   GL-OPT-002: No stages defined (all jobs run in the same implicit stage)
 *
 * Reference:
 *   https://docs.gitlab.com/ee/ci/yaml/
 *   https://docs.gitlab.com/ee/ci/environments/deployment_safety.html
 */

import type { AuditFinding } from '../../types/index.js';
import type { GitLabCIConfig, GitLabJob } from '../../types/ast.js';
import { RULE_IDS, SECRET_KEY_PATTERNS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// GL-SEC-001: Secret variables in logs
// ---------------------------------------------------------------------------

/**
 * Patterns for printing variable values to stdout in shell scripts.
 */
const ECHO_PATTERNS = [
  /\becho\s+.*\$[A-Z_]{3,}/,     // echo $MY_SECRET
  /\bprintenv\b/,                  // printenv dumps all env vars
  /\benv\b\s*$/m,                  // bare `env` command
  /\bset\s+-x\b/,                  // set -x traces all commands including secret expansions
];

/**
 * Checks job scripts for secret variable exposure.
 *
 * GL-SEC-001 covers two scenarios:
 *  1. A variable with a secret-sounding key name is echoed to stdout
 *  2. `printenv` or bare `env` dumps all environment variables (including secrets)
 */
function checkSecretExposure(job: GitLabJob): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Collect all script lines (before_script + script + after_script)
  const allScripts = [
    ...(job.beforeScript ?? []),
    ...job.script,
    ...(job.afterScript ?? []),
  ];

  for (const line of allScripts) {
    // Check for printenv / bare env (dumps everything)
    if (/\bprintenv\b/.test(line) || /\benv\b\s*$/.test(line)) {
      findings.push({
        id: RULE_IDS.GL_SEC_001,
        title: `All environment variables may be dumped to log in job "${job.name}"`,
        description:
          `The script in job "${job.name}" uses \`${line.trim()}\` which prints ALL ` +
          'environment variables to the log, including any secret variables configured ' +
          'in GitLab CI settings. This exposes credentials in job logs.',
        severity: 'high',
        line: job.line,
        evidence: line.trim(),
        fix: 'Remove printenv/env commands from scripts. If debugging, use `env | grep -v SECRET` and remove before merging.',
        references: [
          'https://docs.gitlab.com/ee/ci/variables/#cicd-variable-security',
        ],
      });
      continue;
    }

    // Check set -x (traces all commands, expanding variables)
    if (/\bset\s+-x\b/.test(line) || /\bset\s+-[a-zA-Z]*x/.test(line)) {
      findings.push({
        id: RULE_IDS.GL_SEC_001,
        title: `set -x in job "${job.name}" may expose secrets in trace output`,
        description:
          '`set -x` enables shell command tracing which prints every command with ' +
          'expanded variable values before executing it. This will print secret variable ' +
          'values to the job log.',
        severity: 'medium',
        line: job.line,
        evidence: line.trim(),
        fix: 'Remove `set -x` from scripts, or unset it before commands that use secrets: `set +x`',
      });
      continue;
    }

    // Check for echo of specific secret-named variables
    for (const pattern of ECHO_PATTERNS.slice(0, 1)) {
      if (pattern.test(line)) {
        // Extract the variable name to check if it sounds like a secret
        const varMatch = line.match(/\$([A-Z_]{3,})/);
        if (varMatch) {
          const varName = varMatch[1] ?? '';
          const isSensitive = SECRET_KEY_PATTERNS.some((p) => p.test(varName));
          if (isSensitive) {
            findings.push({
              id: RULE_IDS.GL_SEC_001,
              title: `Possible secret variable "${varName}" echoed to log in job "${job.name}"`,
              description:
                `The variable $${varName} appears to be echoed to the log in job "${job.name}". ` +
                'If this is a masked variable, GitLab may redact it, but relying on masking ' +
                'is fragile. Secrets should never be intentionally logged.',
              severity: 'high',
              line: job.line,
              evidence: line.trim(),
              fix: 'Remove the echo statement. If debugging, check the value without logging it.',
            });
          }
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GL-SEC-002: Privileged mode
// ---------------------------------------------------------------------------

/**
 * Checks for Docker-in-Docker (DinD) usage with privileged mode.
 *
 * Docker-in-Docker requires privileged: true to work, which gives the container
 * nearly unrestricted access to the host. There are alternatives (rootless Docker,
 * kaniko, buildah) that don't require privileged mode.
 */
function checkPrivilegedMode(job: GitLabJob): AuditFinding | null {
  if (!job.privileged) return null;

  return {
    id: RULE_IDS.GL_SEC_002,
    title: `Job "${job.name}" runs in privileged mode`,
    description:
      `Job "${job.name}" uses privileged: true, which gives the container nearly ` +
      'unrestricted access to the host machine. This is commonly needed for ' +
      'Docker-in-Docker (DinD) builds but significantly increases the security risk. ' +
      'If a build script is compromised, it can escape the container.',
    severity: 'medium',
    line: job.line,
    evidence: 'privileged: true',
    fix:
      'Consider alternatives that do not require privileged mode:\n' +
      '  - kaniko: https://github.com/GoogleContainerTools/kaniko\n' +
      '  - buildah: https://buildah.io/\n' +
      '  - img: https://github.com/genuinetools/img\n' +
      'If privileged mode is required, scope it to specific jobs and use protected runners.',
    references: [
      'https://docs.gitlab.com/ee/ci/docker/using_docker_build.html#use-rootless-dockerind',
    ],
  };
}

// ---------------------------------------------------------------------------
// GL-OPT-001: Missing cache configuration
// ---------------------------------------------------------------------------

/**
 * Patterns for detecting package manager install commands in scripts.
 */
const INSTALL_PATTERNS: Array<{ pattern: RegExp; name: string; cacheDir: string }> = [
  { pattern: /\bnpm\s+(install|ci)\b/, name: 'npm', cacheDir: '~/.npm' },
  { pattern: /\byarn\s+(install)?\b/, name: 'yarn', cacheDir: '~/.yarn/cache or .yarn/cache' },
  { pattern: /\bpnpm\s+install\b/, name: 'pnpm', cacheDir: '~/.local/share/pnpm/store' },
  { pattern: /\bpip\d*\s+install\b/, name: 'pip', cacheDir: '~/.cache/pip' },
  { pattern: /\bpoetry\s+install\b/, name: 'poetry', cacheDir: '~/.cache/pypoetry' },
  { pattern: /\bmvn\b/, name: 'Maven', cacheDir: '~/.m2/repository' },
  { pattern: /\bcomposer\s+install\b/, name: 'Composer', cacheDir: '~/.composer/cache' },
  { pattern: /\bbundle\s+install\b/, name: 'Bundler', cacheDir: 'vendor/bundle' },
  { pattern: /\bcargo\s+(build|fetch)\b/, name: 'Cargo', cacheDir: '.cargo/registry' },
];

/**
 * Checks whether a job that installs dependencies has caching configured.
 */
function checkMissingCache(
  job: GitLabJob,
  globalCacheExists: boolean,
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // If global cache is configured, jobs inherit it (unless they override with cache: [])
  if (globalCacheExists && job.cache === undefined) return findings;

  const allScripts = [
    ...(job.beforeScript ?? []),
    ...job.script,
  ];

  for (const { pattern, name, cacheDir } of INSTALL_PATTERNS) {
    const installsPackages = allScripts.some((line) => pattern.test(line));
    if (!installsPackages) continue;

    const hasCacheConfig = job.cache !== undefined;
    if (!hasCacheConfig) {
      findings.push({
        id: RULE_IDS.GL_OPT_001,
        title: `${name} install without cache in job "${job.name}"`,
        description:
          `Job "${job.name}" installs ${name} dependencies on every run without configuring ` +
          'a GitLab CI cache. This slows down pipelines by re-downloading packages every time. ' +
          'GitLab CI caches can be shared between pipeline runs and branches.',
        severity: 'low',
        line: job.line,
        fix:
          `Add a cache block to job "${job.name}":\n` +
          `cache:\n` +
          `  key:\n` +
          `    files:\n` +
          `      - package-lock.json  # Change to your lockfile\n` +
          `  paths:\n` +
          `    - ${cacheDir}`,
        references: [
          'https://docs.gitlab.com/ee/ci/caching/',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// GL-OPT-002: No stages defined
// ---------------------------------------------------------------------------

/**
 * Checks whether stages are defined.
 *
 * Without explicit stages, all jobs run in the single implicit "test" stage,
 * which means they all run in parallel with no dependency ordering.
 * For non-trivial pipelines, explicit stages improve readability and control.
 */
function checkNoStages(config: GitLabCIConfig): AuditFinding | null {
  // Only flag if there are multiple jobs — single-job pipelines don't need stages
  if (config.jobs.length <= 1) return null;
  if (config.stages && config.stages.length > 0) return null;

  return {
    id: RULE_IDS.GL_OPT_002,
    title: 'No stages defined — all jobs run in parallel',
    description:
      `The .gitlab-ci.yml has ${config.jobs.length} jobs but no \`stages:\` block. ` +
      'Without stages, all jobs run concurrently in the implicit "test" stage. ' +
      'This prevents build → test → deploy ordering and can cause flaky pipelines ' +
      'if jobs have implicit dependencies.',
    severity: 'low',
    fix:
      'Add a stages block:\nstages:\n  - build\n  - test\n  - deploy\n\n' +
      'Then add `stage: build`, `stage: test`, etc. to each job.',
    references: [
      'https://docs.gitlab.com/ee/ci/yaml/#stages',
    ],
  };
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Runs all GitLab CI checks on a parsed config.
 *
 * @param config  Parsed GitLabCIConfig
 * @returns       Array of findings
 */
export function analyzeGitLabCI(config: GitLabCIConfig): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const globalCacheExists = config.cache !== undefined;

  for (const job of config.jobs) {
    findings.push(...checkSecretExposure(job));

    const privFinding = checkPrivilegedMode(job);
    if (privFinding) findings.push(privFinding);

    findings.push(...checkMissingCache(job, globalCacheExists));
  }

  const stagesFinding = checkNoStages(config);
  if (stagesFinding) findings.push(stagesFinding);

  return findings;
}
