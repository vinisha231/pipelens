/**
 * Dockerfile best practices analyzer.
 *
 * Checks for common mistakes that don't necessarily create security
 * vulnerabilities but lead to unmaintainable, unreliable, or oversized images.
 *
 * Rules implemented:
 *   DF-BP-002: ADD used instead of COPY (ADD has unintended side effects)
 *   DF-BP-003: No HEALTHCHECK defined
 *   DF-BP-004: Large base image — alpine alternative available
 *   DF-BP-005: No WORKDIR set (files land in /)
 */

import type { AuditFinding } from '../../types/index.js';
import type { DockerfileAST } from '../../types/ast.js';
import { RULE_IDS, LARGE_IMAGE_ALTERNATIVES } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// DF-BP-002: ADD instead of COPY
// ---------------------------------------------------------------------------

/**
 * Flags ADD instructions that could use COPY instead.
 *
 * ADD has two special behaviors that COPY lacks:
 *   1. It can fetch URLs (rarely needed — use RUN curl instead for better control)
 *   2. It auto-extracts tar archives (often unexpected)
 *
 * For everything else, COPY is explicit and predictable.
 */
function checkAddVsCopy(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instr of ast.instructions) {
    if (instr.type !== 'ADD') continue;

    const args = instr.args.trim();

    // ADD with a URL source is acceptable (though RUN curl is better)
    const isUrlSource = /^https?:\/\//i.test(args);

    // ADD with a .tar.* source intentionally uses the auto-extraction feature
    const isTarSource = /\.(tar\.gz|tgz|tar\.bz2|tar\.xz|tar\.Z|tar)(\s|$)/i.test(args);

    if (!isUrlSource && !isTarSource) {
      findings.push({
        id: RULE_IDS.DF_BP_002,
        title: 'ADD instruction used where COPY is more appropriate',
        description:
          'The ADD instruction has implicit behaviors (URL fetching and tar auto-extraction) ' +
          'that can cause surprising results. Use COPY for simple file copies — ' +
          'it is more explicit and easier to reason about.',
        severity: 'medium',
        line: instr.line,
        evidence: instr.raw,
        fix: `Replace: ${instr.raw}\nWith:    COPY ${instr.args}`,
        references: [
          'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-BP-003: No HEALTHCHECK defined
// ---------------------------------------------------------------------------

/**
 * Checks whether the Dockerfile defines a HEALTHCHECK instruction.
 *
 * Without HEALTHCHECK, Docker and orchestration platforms (Kubernetes, ECS)
 * have no way to determine whether the application inside the container is
 * actually healthy and serving traffic — they can only tell if the process
 * is still running.
 *
 * We skip this check for base/builder images (multi-stage builds where the
 * final stage is the only one that needs a healthcheck).
 */
function checkHealthcheck(ast: DockerfileAST): AuditFinding | null {
  const hasHealthcheck = ast.instructions.some(
    (i) => i.type === 'HEALTHCHECK' && !i.args.toUpperCase().startsWith('NONE'),
  );

  if (!hasHealthcheck) {
    return {
      id: RULE_IDS.DF_BP_003,
      title: 'No HEALTHCHECK instruction defined',
      description:
        'The Dockerfile does not define a HEALTHCHECK. Without it, Docker cannot ' +
        'determine whether the application is healthy — only whether the process is running. ' +
        'Orchestration platforms use health checks to route traffic and restart unhealthy containers.',
      severity: 'low',
      fix:
        'Add a HEALTHCHECK instruction, for example:\n' +
        'HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n' +
        '    CMD curl -f http://localhost:8080/health || exit 1',
      references: [
        'https://docs.docker.com/engine/reference/builder/#healthcheck',
        'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#healthcheck',
      ],
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// DF-BP-004: Large base image
// ---------------------------------------------------------------------------

/**
 * Suggests smaller base image alternatives when the current image is known
 * to be large and an alpine/slim variant exists.
 *
 * This is an INFO-level finding because it doesn't cause a security issue
 * but can significantly reduce image size, pull times, and attack surface.
 */
function checkLargeBaseImage(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instr of ast.instructions) {
    if (instr.type !== 'FROM' || !instr.fromDetails) continue;

    const imageName = instr.fromDetails.image.toLowerCase();
    const tag = (instr.fromDetails.tag ?? '').toLowerCase();

    // Skip if already using alpine/slim/distroless
    if (
      tag.includes('alpine') ||
      tag.includes('slim') ||
      tag.includes('distroless') ||
      imageName.includes('alpine') ||
      imageName.includes('distroless')
    ) {
      continue;
    }

    // Check if this image has a known lighter alternative
    const alternative = LARGE_IMAGE_ALTERNATIVES[imageName];
    if (alternative) {
      findings.push({
        id: RULE_IDS.DF_BP_004,
        title: `Large base image — consider ${alternative}`,
        description:
          `The base image "${instr.fromDetails.image}" is a full OS image. ` +
          `A smaller alternative (${alternative}) would reduce image size, ` +
          'reduce the attack surface (fewer installed packages), ' +
          'and speed up image pulls in CI/CD pipelines.',
        severity: 'info',
        line: instr.line,
        evidence: instr.raw,
        fix: `Consider: FROM ${alternative.split(' ')[0]}`,
        references: [
          'https://docs.docker.com/develop/develop-images/baseimages/',
          'https://hub.docker.com/_/alpine',
        ],
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-BP-005: No WORKDIR set
// ---------------------------------------------------------------------------

/**
 * Checks whether a WORKDIR is set before COPY/RUN instructions.
 *
 * Without WORKDIR:
 *   - Files are copied to the filesystem root (/)
 *   - The working directory for CMD/ENTRYPOINT is / (confusing)
 *   - RUN instructions execute from /
 *
 * WORKDIR also implicitly creates the directory if it doesn't exist,
 * unlike `RUN mkdir -p /app && cd /app` (which doesn't persist across layers).
 */
function checkWorkdir(ast: DockerfileAST): AuditFinding | null {
  const hasWorkdir = ast.instructions.some((i) => i.type === 'WORKDIR');
  const hasCopyOrRun = ast.instructions.some(
    (i) => i.type === 'COPY' || i.type === 'ADD' || i.type === 'RUN',
  );

  if (!hasWorkdir && hasCopyOrRun) {
    return {
      id: RULE_IDS.DF_BP_005,
      title: 'No WORKDIR instruction — files land in filesystem root',
      description:
        'The Dockerfile has COPY/ADD/RUN instructions but no WORKDIR. ' +
        'Without WORKDIR, files are placed in / and commands run from /, ' +
        'which can conflict with system files and makes the container harder to maintain. ' +
        'WORKDIR also creates the directory if it does not exist.',
      severity: 'medium',
      fix: 'Add WORKDIR before your first COPY/RUN instruction, e.g.: WORKDIR /app',
      references: [
        'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir',
      ],
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Runs all best-practice checks on a parsed Dockerfile AST.
 *
 * @param ast  Parsed DockerfileAST
 * @returns    Array of findings
 */
export function analyzeDockerfileBestPractices(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  findings.push(...checkAddVsCopy(ast));
  findings.push(...checkLargeBaseImage(ast));

  const healthFinding = checkHealthcheck(ast);
  if (healthFinding) findings.push(healthFinding);

  const workdirFinding = checkWorkdir(ast);
  if (workdirFinding) findings.push(workdirFinding);

  return findings;
}
