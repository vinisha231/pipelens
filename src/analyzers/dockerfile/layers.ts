/**
 * Dockerfile layer ordering and caching optimizer.
 *
 * Docker builds images layer by layer — each instruction creates a new layer.
 * When a layer changes, all subsequent layers are invalidated and rebuilt.
 * This analyzer finds common mistakes that break Docker's layer cache,
 * leading to unnecessarily slow builds.
 *
 * Rules implemented:
 *   DF-LAYER-001: Package manager cache not cleared (apt/yum/apk)
 *   DF-LAYER-002: Multiple consecutive RUN commands (could be chained)
 *   DF-LAYER-003: Source code COPY before dependency install (breaks caching)
 *   DF-LAYER-004: package.json not isolated (npm install cache busted by src changes)
 */

import type { AuditFinding } from '../../types/index.js';
import type { DockerfileAST, DockerfileInstruction } from '../../types/ast.js';
import { RULE_IDS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// DF-LAYER-001: Package manager cache not cleared
// ---------------------------------------------------------------------------

/**
 * Patterns that indicate a package manager install command without
 * cleaning up the package cache afterward.
 *
 * Not cleaning the cache means the cache files end up baked into the
 * image layer, increasing image size unnecessarily.
 */
const APT_WITHOUT_CLEAN = /apt-get\s+install/;
const APT_HAS_CLEAN = /rm\s+-rf\s+\/var\/lib\/apt|apt-get\s+clean/;
const APT_NO_RECOMMENDS = /--no-install-recommends/;

const YUM_WITHOUT_CLEAN = /yum\s+install/;
const YUM_HAS_CLEAN = /yum\s+clean\s+all/;

const APK_WITHOUT_PURGE = /apk\s+add/;
const APK_HAS_PURGE = /--no-cache|apk\s+cache\s+clean/;

/**
 * Checks a single RUN instruction for package manager cache issues.
 */
function checkPackageManagerCache(
  instruction: DockerfileInstruction,
): AuditFinding | null {
  const cmd = instruction.args;

  // apt-get install without cleanup
  if (APT_WITHOUT_CLEAN.test(cmd)) {
    const hasClean = APT_HAS_CLEAN.test(cmd);
    const hasNoRecommends = APT_NO_RECOMMENDS.test(cmd);

    if (!hasClean) {
      return {
        id: RULE_IDS.DF_LAYER_001,
        title: 'apt-get cache not cleared in same RUN layer',
        description:
          'Running apt-get install without cleaning up creates unnecessarily large layers. ' +
          'The package lists and cached .deb files remain in the layer permanently. ' +
          'Always run `rm -rf /var/lib/apt/lists/*` in the same RUN instruction.',
        severity: 'medium',
        line: instruction.line,
        evidence: instruction.raw,
        fix:
          'Chain the cleanup in the same RUN instruction:\n' +
          'RUN apt-get update && apt-get install -y --no-install-recommends <packages> \\\n' +
          '    && rm -rf /var/lib/apt/lists/*',
        references: [
          'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run',
          'https://docs.docker.com/develop/dev-best-practices/',
        ],
      };
    }

    // Warn about --no-install-recommends separately (lower severity)
    if (hasClean && !hasNoRecommends) {
      return {
        id: RULE_IDS.DF_LAYER_001,
        title: 'apt-get install without --no-install-recommends',
        description:
          'Not using --no-install-recommends causes apt to install optional recommended packages, ' +
          'bloating the image with software you likely do not need.',
        severity: 'low',
        line: instruction.line,
        evidence: instruction.raw,
        fix: 'Add --no-install-recommends: apt-get install -y --no-install-recommends <packages>',
      };
    }
  }

  // yum install without yum clean all
  if (YUM_WITHOUT_CLEAN.test(cmd) && !YUM_HAS_CLEAN.test(cmd)) {
    return {
      id: RULE_IDS.DF_LAYER_001,
      title: 'yum cache not cleared in same RUN layer',
      description:
        'Running yum install without `yum clean all` leaves package manager cache ' +
        'baked into the layer, increasing image size.',
      severity: 'medium',
      line: instruction.line,
      evidence: instruction.raw,
      fix: 'Chain cleanup: RUN yum install -y <packages> && yum clean all && rm -rf /var/cache/yum',
    };
  }

  // apk add without --no-cache
  if (APK_WITHOUT_PURGE.test(cmd) && !APK_HAS_PURGE.test(cmd)) {
    return {
      id: RULE_IDS.DF_LAYER_001,
      title: 'apk add without --no-cache flag',
      description:
        'Running `apk add` without `--no-cache` caches the package index in the layer. ' +
        'Use `apk add --no-cache` to avoid this.',
      severity: 'low',
      line: instruction.line,
      evidence: instruction.raw,
      fix: 'Use: apk add --no-cache <packages>',
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// DF-LAYER-002: Multiple consecutive RUN commands
// ---------------------------------------------------------------------------

/**
 * Finds groups of consecutive RUN instructions that could be combined.
 *
 * Each RUN instruction creates a separate layer. Chaining commands with &&
 * keeps everything in one layer, reducing image size and build time.
 *
 * We flag groups of 3+ consecutive RUN instructions as this is a clear
 * pattern of missed optimization (2 consecutive RUNs is sometimes intentional).
 */
function checkConsecutiveRunCommands(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  let runStart = -1;
  let runCount = 0;

  for (let i = 0; i <= instructions.length; i++) {
    const instr = instructions[i];
    const isRun = instr?.type === 'RUN';

    if (isRun) {
      if (runCount === 0) runStart = i;
      runCount++;
    } else {
      // Check if we just ended a run of 3+ consecutive RUN instructions
      if (runCount >= 3 && runStart >= 0) {
        const firstRun = instructions[runStart];
        findings.push({
          id: RULE_IDS.DF_LAYER_002,
          title: `${runCount} consecutive RUN instructions can be merged`,
          description:
            `Found ${runCount} consecutive RUN instructions (lines ${firstRun?.line}–${instructions[runStart + runCount - 1]?.line}). ` +
            'Each RUN creates a separate image layer. Merging them with && ' +
            'reduces the number of layers and the final image size.',
          severity: 'low',
          line: firstRun?.line,
          evidence: instructions
            .slice(runStart, runStart + Math.min(runCount, 3))
            .map((i) => i.raw)
            .join('\n') + (runCount > 3 ? '\n...' : ''),
          fix: 'Chain commands with &&:\nRUN command1 \\\n    && command2 \\\n    && command3',
        });
      }
      runCount = 0;
      runStart = -1;
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-LAYER-003: Source code COPY before dependency install
// ---------------------------------------------------------------------------

/**
 * Checks whether source code is copied before dependencies are installed.
 *
 * The optimal Dockerfile pattern for Node.js apps:
 *   COPY package.json package-lock.json ./   ← only these files
 *   RUN npm install                           ← install deps (cached unless package.json changes)
 *   COPY . .                                  ← copy source (invalidates only later layers)
 *
 * If `COPY . .` (or similar broad copy) appears BEFORE `npm install` / `pip install`,
 * ANY source file change will invalidate the dependency install layer.
 */
function checkSourceBeforeDeps(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Broad copy patterns that suggest copying source code
  const broadCopyPattern = /^\.(\s+\.)?$|^src\s|^app\s|^\.\s+\/app/;

  // Dependency install patterns
  const depInstallPattern =
    /npm\s+(install|ci)|yarn\s+(install)?|pip\s+install|composer\s+install|bundle\s+install|cargo\s+build|go\s+mod\s+download/;

  let broadCopyLine: number | null = null;
  let broadCopyRaw = '';

  for (const instr of instructions) {
    if (instr.type === 'COPY' || instr.type === 'ADD') {
      if (broadCopyPattern.test(instr.args.trim())) {
        if (broadCopyLine === null) {
          broadCopyLine = instr.line;
          broadCopyRaw = instr.raw;
        }
      }
    }

    if (instr.type === 'RUN' && depInstallPattern.test(instr.args)) {
      // If we saw a broad copy BEFORE this dep install, that's a cache-busting issue
      if (broadCopyLine !== null && broadCopyLine < instr.line) {
        findings.push({
          id: RULE_IDS.DF_LAYER_003,
          title: 'Source code copied before dependency install breaks layer caching',
          description:
            `A broad COPY instruction (line ${broadCopyLine}) copies source files before ` +
            `the dependency install (line ${instr.line}). This means every source code change ` +
            'invalidates the dependency cache, causing slow rebuilds.',
          severity: 'medium',
          line: broadCopyLine,
          evidence: broadCopyRaw + '\n...\n' + instr.raw,
          fix:
            'Restructure: copy only your dependency manifest first, run install, then copy source:\n' +
            'COPY package.json package-lock.json ./\n' +
            'RUN npm ci\n' +
            'COPY . .',
          references: [
            'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#leverage-build-cache',
          ],
        });
        // Only report once per stage
        broadCopyLine = null;
        broadCopyRaw = '';
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-LAYER-004: package.json not isolated before npm install
// ---------------------------------------------------------------------------

/**
 * Checks whether package.json is copied in isolation before npm/yarn install.
 *
 * This is a more specific version of DF-LAYER-003 targeting Node.js projects.
 * If we detect an npm/yarn install but don't see an isolated `COPY package.json`
 * step before it, flag it.
 */
function checkPackageJsonIsolation(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  const npmInstallPattern = /npm\s+(install|ci)|yarn\s+(install)?$/;
  const packageJsonCopyPattern = /package(-lock)?\.json|yarn\.lock/;

  for (let i = 0; i < instructions.length; i++) {
    const instr = instructions[i];
    if (instr.type !== 'RUN' || !npmInstallPattern.test(instr.args)) continue;

    // Look backward for a COPY that mentions package.json
    const hasIsolatedCopy = instructions
      .slice(0, i)
      .some(
        (prev) =>
          (prev.type === 'COPY' || prev.type === 'ADD') &&
          packageJsonCopyPattern.test(prev.args),
      );

    if (!hasIsolatedCopy) {
      findings.push({
        id: RULE_IDS.DF_LAYER_004,
        title: 'npm/yarn install without isolated package.json COPY',
        description:
          'No COPY instruction for package.json found before the npm/yarn install. ' +
          'Without first copying package.json in isolation, Docker cannot cache the ' +
          'node_modules layer between builds when source changes.',
        severity: 'medium',
        line: instr.line,
        evidence: instr.raw,
        fix:
          'Add before your npm install:\n' +
          'COPY package.json package-lock.json ./\n' +
          'RUN npm ci\n' +
          'COPY . .',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Runs all layer optimization checks on a parsed Dockerfile AST.
 *
 * @param ast  Parsed DockerfileAST
 * @returns    Array of findings (may be empty if the Dockerfile is optimal)
 */
export function analyzeDockerfileLayers(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instruction of ast.instructions) {
    if (instruction.type === 'RUN') {
      const finding = checkPackageManagerCache(instruction);
      if (finding) findings.push(finding);
    }
  }

  findings.push(...checkConsecutiveRunCommands(ast.instructions));
  findings.push(...checkSourceBeforeDeps(ast.instructions));
  findings.push(...checkPackageJsonIsolation(ast.instructions));

  return findings;
}
