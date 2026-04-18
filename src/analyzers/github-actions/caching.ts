/**
 * GitHub Actions caching opportunities detector.
 *
 * Finds jobs that install dependencies but don't use the `actions/cache`
 * action or the built-in cache support of setup actions, leading to slow
 * workflows that re-download the same packages on every run.
 *
 * Rule implemented:
 *   GHA-CACHE-001: Dependency installation detected without caching
 *
 * Supported ecosystems:
 *   - Node.js (npm, yarn, pnpm)
 *   - Python (pip, pip3, poetry, pipenv)
 *   - Java (Maven, Gradle)
 *   - Ruby (bundle install, gem install)
 *   - Go (go mod download)
 *   - Rust (cargo build, cargo fetch)
 *   - PHP (composer install)
 */

import type { AuditFinding } from '../../types/index.js';
import type { GHAWorkflow, GHAJob, GHAStep } from '../../types/ast.js';
import { RULE_IDS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// Ecosystem detection
// ---------------------------------------------------------------------------

/**
 * An ecosystem entry describes a package manager and how to detect/fix it.
 */
interface Ecosystem {
  name: string;
  /** Patterns in `run:` steps that indicate this ecosystem is in use */
  installPatterns: RegExp[];
  /**
   * Patterns in `uses:` steps that indicate caching is already set up
   * (either via setup action with cache option or explicit cache action)
   */
  cachePatterns: RegExp[];
  /** A recommended caching approach for the fix message */
  fixHint: string;
}

const ECOSYSTEMS: Ecosystem[] = [
  {
    name: 'Node.js (npm/yarn/pnpm)',
    installPatterns: [
      /\bnpm\s+(install|ci)\b/,
      /\byarn\s+(install)?\b/,
      /\bpnpm\s+install\b/,
    ],
    cachePatterns: [
      /actions\/cache/,
      /actions\/setup-node/,   // setup-node has built-in cache: npm|yarn|pnpm
    ],
    fixHint:
      'Use the built-in cache option in actions/setup-node:\n' +
      '- uses: actions/setup-node@v4\n' +
      '  with:\n' +
      '    node-version: "20"\n' +
      '    cache: "npm"  # or yarn/pnpm',
  },
  {
    name: 'Python (pip/poetry/pipenv)',
    installPatterns: [
      /\bpip\d*\s+install\b/,
      /\bpoetry\s+install\b/,
      /\bpipenv\s+install\b/,
    ],
    cachePatterns: [
      /actions\/cache/,
      /actions\/setup-python/,  // setup-python has built-in pip cache
    ],
    fixHint:
      'Use the built-in cache option in actions/setup-python:\n' +
      '- uses: actions/setup-python@v5\n' +
      '  with:\n' +
      '    python-version: "3.12"\n' +
      '    cache: "pip"\n' +
      'Or use actions/cache with key: ${{ hashFiles(\'**/requirements*.txt\') }}',
  },
  {
    name: 'Java (Maven)',
    installPatterns: [/\bmvn\b/, /\bmaven\b/],
    cachePatterns: [/actions\/cache/, /actions\/setup-java/],
    fixHint:
      'Use the built-in Maven cache in actions/setup-java:\n' +
      '- uses: actions/setup-java@v4\n' +
      '  with:\n' +
      '    distribution: temurin\n' +
      '    java-version: "21"\n' +
      '    cache: "maven"',
  },
  {
    name: 'Java (Gradle)',
    installPatterns: [/\bgradle\b/, /gradlew/],
    cachePatterns: [/actions\/cache/, /actions\/setup-java/, /gradle-build-action/, /setup-gradle/],
    fixHint:
      'Use the built-in Gradle cache in actions/setup-java:\n' +
      '- uses: actions/setup-java@v4\n' +
      '  with:\n' +
      '    distribution: temurin\n' +
      '    java-version: "21"\n' +
      '    cache: "gradle"',
  },
  {
    name: 'Ruby (Bundler)',
    installPatterns: [/\bbundle\s+install\b/, /\bgem\s+install\b/],
    cachePatterns: [/actions\/cache/, /ruby\/setup-ruby/],
    fixHint:
      'Use ruby/setup-ruby with bundler-cache: true:\n' +
      '- uses: ruby/setup-ruby@v1\n' +
      '  with:\n' +
      '    ruby-version: "3.3"\n' +
      '    bundler-cache: true',
  },
  {
    name: 'Go (modules)',
    installPatterns: [/\bgo\s+mod\s+download\b/, /\bgo\s+get\b/, /\bgo\s+build\b/],
    cachePatterns: [/actions\/cache/, /actions\/setup-go/],
    fixHint:
      'Use the built-in Go module cache in actions/setup-go:\n' +
      '- uses: actions/setup-go@v5\n' +
      '  with:\n' +
      '    go-version: "1.22"\n' +
      '    cache: true',
  },
  {
    name: 'Rust (Cargo)',
    installPatterns: [/\bcargo\s+(build|fetch|install)\b/],
    cachePatterns: [/actions\/cache/, /Swatinem\/rust-cache/, /dtolnay\/rust-toolchain/],
    fixHint:
      'Use Swatinem/rust-cache for Rust dependency caching:\n' +
      '- uses: Swatinem/rust-cache@v2',
  },
  {
    name: 'PHP (Composer)',
    installPatterns: [/\bcomposer\s+install\b/],
    cachePatterns: [/actions\/cache/, /shivammathur\/setup-php/],
    fixHint:
      'Cache Composer dependencies with actions/cache:\n' +
      '- uses: actions/cache@v4\n' +
      '  with:\n' +
      '    path: ~/.composer/cache\n' +
      '    key: composer-${{ hashFiles(\'**/composer.lock\') }}',
  },
];

// ---------------------------------------------------------------------------
// GHA-CACHE-001: Missing dependency cache
// ---------------------------------------------------------------------------

/**
 * Checks a single job for dependency installs without caching.
 */
function checkJobCaching(job: GHAJob): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Collect all `uses:` values and `run:` scripts in this job
  const usesRefs: string[] = [];
  const runScripts: string[] = [];

  for (const step of job.steps) {
    if (step.uses) usesRefs.push(step.uses);
    if (step.run) runScripts.push(step.run);
  }

  for (const ecosystem of ECOSYSTEMS) {
    // Check if this job uses this ecosystem's package manager
    const usesEcosystem = ecosystem.installPatterns.some((pattern) =>
      runScripts.some((script) => pattern.test(script)),
    );

    if (!usesEcosystem) continue;

    // Check if caching is already configured
    const hasCaching =
      ecosystem.cachePatterns.some((pattern) =>
        usesRefs.some((ref) => pattern.test(ref)),
      ) ||
      // Also check run scripts for cache-restore commands
      runScripts.some((script) => /actions\/cache|restore-keys/i.test(script));

    if (!hasCaching) {
      // Find the line number of the first install step for this ecosystem
      const installStep = job.steps.find((step) =>
        step.run
          ? ecosystem.installPatterns.some((p) => p.test(step.run ?? ''))
          : false,
      ) as GHAStep | undefined;

      findings.push({
        id: RULE_IDS.GHA_CACHE_001,
        title: `${ecosystem.name} dependency install without caching in job "${job.id}"`,
        description:
          `Job "${job.id}" installs ${ecosystem.name} dependencies on every run without ` +
          'using a dependency cache. This means packages are re-downloaded from the internet ' +
          'on every workflow run, slowing down CI by minutes and increasing bandwidth costs. ' +
          'Caching can reduce install time by 80-95% for unchanged dependencies.',
        severity: 'low',
        line: installStep?.line,
        evidence: installStep?.run?.split('\n')[0],
        fix: ecosystem.fixHint,
        references: [
          'https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Analyzes a GitHub Actions workflow for missing dependency caches.
 *
 * @param workflow  Parsed GHAWorkflow
 * @returns         Array of findings
 */
export function analyzeGHACaching(workflow: GHAWorkflow): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const job of workflow.jobs) {
    findings.push(...checkJobCaching(job));
  }

  return findings;
}
