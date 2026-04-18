/**
 * Dockerfile image pinning analyzer.
 *
 * Detects base images that are not pinned to a specific version,
 * which makes builds non-reproducible and vulnerable to supply-chain attacks.
 *
 * Rule implemented:
 *   DF-BP-001: Unpinned base image (using :latest or no tag)
 *
 * What "pinned" means:
 *   - Pinned to digest (best):   FROM node@sha256:abc123...
 *   - Pinned to specific tag:    FROM node:20.11.1-alpine3.18
 *   - NOT pinned:                FROM node:latest  or  FROM node
 *   - Partially pinned (warn):   FROM node:lts  (tag is a moving alias)
 */

import type { AuditFinding } from '../../types/index.js';
import type { DockerfileAST } from '../../types/ast.js';
import { RULE_IDS } from '../../constants/index.js';

// ---------------------------------------------------------------------------
// Moving tags that look specific but aren't
// ---------------------------------------------------------------------------

/**
 * These tags are commonly used as if they're pinned but are actually moving
 * aliases that point to different digests over time.
 */
const MOVING_TAGS = new Set([
  'latest',
  'stable',
  'current',
  'mainline',
  'edge',
  'nightly',
  'dev',
  'development',
  'beta',
  'alpha',
  'rc',
  'canary',
  'lts',          // "lts" moves when a new LTS is released
  'lts-alpine',   // same
  'slim',         // "slim" without version is a moving target
  'alpine',       // "alpine" without version is a moving target
  'buster',       // Debian codenames without a version number
  'bullseye',
  'bookworm',
  'trixie',
  'jammy',        // Ubuntu codenames without a version number
  'focal',
  'noble',
]);

/**
 * Returns true if a tag looks like a specific semantic version.
 * Examples: "20.11.1", "3.12", "22.04", "3.12-alpine3.18"
 */
function isSpecificVersion(tag: string): boolean {
  // Must start with a digit to be a version number
  if (!/^\d/.test(tag)) return false;

  // Check for typical SemVer or date-version patterns
  // e.g. "20.11.1", "3.12.0", "22.04", "7.2.3-alpine3.18"
  return /^\d+(\.\d+)+/.test(tag);
}

/**
 * Returns true if a tag contains a moving alias as a component.
 * E.g. "lts-alpine3.18" still contains "lts" which is moving.
 */
function containsMovingAlias(tag: string): boolean {
  const components = tag.toLowerCase().split(/[-_]/);
  return components.some((c) => MOVING_TAGS.has(c));
}

// ---------------------------------------------------------------------------
// Main check
// ---------------------------------------------------------------------------

/**
 * Analyzes all FROM instructions for unpinned or loosely-pinned images.
 *
 * Produces findings at three severity levels:
 *   - CRITICAL: :latest tag or no tag (guaranteed non-reproducible)
 *   - HIGH:     Moving alias tag (lts, stable, etc.)
 *   - MEDIUM:   Major-only version (e.g. node:20 which rolls through patch releases)
 *
 * Multi-stage build references (FROM builder AS final) are skipped because
 * they reference a stage name, not a registry image.
 */
function checkImagePinning(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Collect stage aliases so we can skip them in FROM references
  const stageAliases = new Set<string>();
  for (const instr of ast.instructions) {
    if (instr.type === 'FROM' && instr.fromDetails?.alias) {
      stageAliases.add(instr.fromDetails.alias.toLowerCase());
    }
  }

  for (const instr of ast.instructions) {
    if (instr.type !== 'FROM' || !instr.fromDetails) continue;

    const { image, tag, digest, isMultiStage } = instr.fromDetails;

    // Skip multi-stage references like `FROM builder` or `FROM compile-stage`
    if (isMultiStage && stageAliases.has(image.toLowerCase())) continue;
    if (image === 'scratch') continue; // scratch is always reproducible

    // If pinned to a digest, it's perfectly reproducible — no finding
    if (digest) continue;

    // No tag at all (defaults to :latest)
    if (!tag) {
      findings.push({
        id: RULE_IDS.DF_BP_001,
        title: `Unpinned base image: ${image} (defaults to :latest)`,
        description:
          `The FROM instruction uses "${image}" without a tag, which defaults to :latest. ` +
          'This makes the build non-reproducible: a build today may produce a different ' +
          'image than a build next month if the upstream image is updated. ' +
          'Supply-chain attacks can also inject malicious code via tag poisoning.',
        severity: 'high',
        line: instr.line,
        evidence: instr.raw,
        fix:
          `Pin to a specific version and ideally a digest:\n` +
          `FROM ${image}:X.Y.Z@sha256:...\n` +
          `Use \`docker pull ${image}:X.Y.Z && docker inspect --format='{{index .RepoDigests 0}}' ${image}:X.Y.Z\` to get the digest.`,
        references: [
          'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from',
          'https://docs.snyk.io/products/snyk-container/getting-around-the-snyk-container-ui/base-image-detection',
        ],
      });
      continue;
    }

    // :latest tag
    if (tag.toLowerCase() === 'latest') {
      findings.push({
        id: RULE_IDS.DF_BP_001,
        title: `Unpinned base image: ${image}:latest`,
        description:
          `The FROM instruction uses "${image}:latest". The :latest tag is a moving pointer ` +
          'and provides no reproducibility guarantee. It changes whenever the image maintainer ' +
          'pushes a new version, which can silently break your builds.',
        severity: 'high',
        line: instr.line,
        evidence: instr.raw,
        fix:
          `Replace :latest with a specific version:\nFROM ${image}:X.Y.Z\n` +
          'Or pin by digest for full reproducibility.',
        references: [
          'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from',
        ],
      });
      continue;
    }

    // Moving alias tags (lts, stable, etc.)
    if (MOVING_TAGS.has(tag.toLowerCase()) || containsMovingAlias(tag)) {
      findings.push({
        id: RULE_IDS.DF_BP_001,
        title: `Loosely-pinned base image: ${image}:${tag} (moving tag)`,
        description:
          `The tag "${tag}" is a moving alias that points to different image digests over time. ` +
          'While it avoids the :latest pitfall, it still makes builds non-reproducible.',
        severity: 'medium',
        line: instr.line,
        evidence: instr.raw,
        fix: `Use a specific version number instead of the alias "${tag}".`,
        references: [
          'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from',
        ],
      });
      continue;
    }

    // Major-only version (e.g. "20" for node, "3" for python) — rolls through minors
    if (/^\d+$/.test(tag)) {
      findings.push({
        id: RULE_IDS.DF_BP_001,
        title: `Base image ${image}:${tag} uses major-only version pin`,
        description:
          `"${image}:${tag}" pins only the major version. Minor and patch updates ` +
          'will be pulled automatically, which can introduce breaking changes.',
        severity: 'low',
        line: instr.line,
        evidence: instr.raw,
        fix: `Use a full version pin, e.g. ${image}:${tag}.X.Y`,
      });
    }

    // If we reach here, the tag looks like a specific version (semver) — OK
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Analyzes Dockerfile FROM instructions for image pinning issues.
 *
 * @param ast  Parsed DockerfileAST
 * @returns    Array of findings
 */
export function analyzeImagePinning(ast: DockerfileAST): AuditFinding[] {
  return checkImagePinning(ast);
}
