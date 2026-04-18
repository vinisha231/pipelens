/**
 * Dockerfile security analyzer.
 *
 * Checks for the most impactful security issues in Dockerfiles:
 *
 *   DF-SEC-001: Container runs as root (no USER instruction, or USER root)
 *   DF-SEC-002: Secrets/credentials in ENV variables
 *   DF-SEC-003: Dangerous command execution patterns (curl|sh, wget|bash, etc.)
 *   DF-SEC-004: Sensitive ports exposed (SSH, databases, etc.)
 *
 * Security philosophy: prefer false positives over false negatives.
 * It is better to flag something safe than to miss a real vulnerability.
 */

import type { AuditFinding } from '../../types/index.js';
import type { DockerfileAST, DockerfileInstruction } from '../../types/ast.js';
import {
  RULE_IDS,
  SENSITIVE_PORTS,
  SECRET_KEY_PATTERNS,
  SECRET_VALUE_PATTERNS,
} from '../../constants/index.js';

// ---------------------------------------------------------------------------
// DF-SEC-001: Running as root
// ---------------------------------------------------------------------------

/**
 * Checks whether the final stage of the Dockerfile specifies a non-root user.
 *
 * Containers that run as root have full access to the host system if they
 * escape their sandbox. Always run containers as a least-privilege user.
 *
 * Logic:
 *  - Scan all USER instructions in document order
 *  - Track the last USER instruction seen
 *  - If the last USER is root/0 or no USER exists at all → finding
 */
function checkRootUser(ast: DockerfileAST): AuditFinding | null {
  const userInstructions = ast.instructions.filter((i) => i.type === 'USER');

  if (userInstructions.length === 0) {
    // No USER instruction at all — runs as root by default
    return {
      id: RULE_IDS.DF_SEC_001,
      title: 'Container runs as root — no USER instruction found',
      description:
        'The Dockerfile has no USER instruction. By default, Docker containers ' +
        'run as root (uid=0). If an attacker gains code execution inside the container, ' +
        'they will have root privileges, making container escape much easier.',
      severity: 'critical',
      fix:
        'Add a non-root user before the final ENTRYPOINT/CMD:\n' +
        'RUN groupadd --gid 1001 appgroup && useradd --uid 1001 --gid appgroup appuser\n' +
        'USER appuser',
      references: [
        'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user',
        'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
      ],
    };
  }

  // Find the effective USER for the last stage
  const lastUser = userInstructions[userInstructions.length - 1];
  if (!lastUser) return null;

  const userArg = lastUser.args.trim().toLowerCase();
  const isRoot =
    userArg === 'root' ||
    userArg === '0' ||
    userArg === '0:0' ||
    userArg === 'root:root';

  if (isRoot) {
    return {
      id: RULE_IDS.DF_SEC_001,
      title: 'Container explicitly runs as root user',
      description:
        `The Dockerfile sets "USER ${lastUser.args}" which runs the container as root. ` +
        'This grants unnecessary privileges and violates the principle of least privilege.',
      severity: 'critical',
      line: lastUser.line,
      evidence: lastUser.raw,
      fix: 'Change to a non-root user: USER nonroot (create the user first if needed)',
      references: [
        'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user',
      ],
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// DF-SEC-002: Secrets in ENV variables
// ---------------------------------------------------------------------------

/**
 * Scans ENV instructions for keys that look like credentials.
 *
 * Hard-coded secrets in Dockerfiles get baked into image layers permanently —
 * even if you overwrite them in a later ENV instruction, the secret is still
 * visible in the layer history. Never put secrets in Dockerfiles.
 */
function checkSecretsInEnv(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instr of instructions) {
    if (instr.type !== 'ENV' || !instr.envPairs) continue;

    for (const pair of instr.envPairs) {
      const keyMatches = SECRET_KEY_PATTERNS.some((pattern) =>
        pattern.test(pair.key),
      );

      const valueMatches = SECRET_VALUE_PATTERNS.some((pattern) =>
        pattern.test(pair.value),
      );

      // Check if the value looks like it's a real secret (not a placeholder)
      const isPlaceholder =
        pair.value === '' ||
        pair.value.startsWith('${') || // references another env var
        pair.value === 'changeme' ||
        pair.value === 'placeholder' ||
        pair.value.toLowerCase().includes('example');

      if ((keyMatches || valueMatches) && !isPlaceholder) {
        findings.push({
          id: RULE_IDS.DF_SEC_002,
          title: `Possible secret in ENV variable: ${pair.key}`,
          description:
            `The ENV variable "${pair.key}" appears to contain a secret or credential. ` +
            'Secrets in Dockerfile ENV instructions are baked into image layers and ' +
            'visible via `docker history` or `docker inspect`. ' +
            'Even if the image is private, layer metadata can leak credentials.',
          severity: 'high',
          line: instr.line,
          evidence: `ENV ${pair.key}=***`,  // Redact value in the finding
          fix:
            'Use Docker secrets, environment variables at runtime, or a secrets manager instead:\n' +
            '  - Pass at runtime: docker run -e MY_SECRET=$MY_SECRET ...\n' +
            '  - Use Docker BuildKit secrets: RUN --mount=type=secret,...\n' +
            '  - Use a .env file with docker-compose (gitignored)',
          references: [
            'https://docs.docker.com/engine/swarm/secrets/',
            'https://docs.docker.com/build/buildkit/secrets/',
          ],
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-SEC-003: Dangerous command execution patterns
// ---------------------------------------------------------------------------

/**
 * Patterns for dangerous shell pipe executions.
 *
 * Piping curl/wget output directly into a shell is dangerous because:
 *   1. You cannot verify the integrity of what you're executing
 *   2. If the remote server is compromised, you run attacker code
 *   3. The downloaded script is never saved for review
 */
const DANGEROUS_RUN_PATTERNS: Array<{
  pattern: RegExp;
  description: string;
  fix: string;
}> = [
  {
    pattern: /curl[^|]*\|\s*(ba)?sh/,
    description:
      'curl piped directly into bash executes remote code without verification. ' +
      'If the remote server is compromised or the URL changes, your build executes malicious code.',
    fix:
      'Download the file first, verify its checksum, then execute:\n' +
      'RUN curl -fsSL https://example.com/install.sh -o install.sh \\\n' +
      '    && echo "expected-sha256  install.sh" | sha256sum -c \\\n' +
      '    && bash install.sh \\\n' +
      '    && rm install.sh',
  },
  {
    pattern: /wget[^|]*\|\s*(ba)?sh/,
    description:
      'wget piped directly into bash executes remote code without verification.',
    fix: 'Download the file first, verify its checksum, then execute it explicitly.',
  },
  {
    pattern: /curl[^|]*\|\s*python/,
    description: 'curl piped into Python executes remote code without verification.',
    fix: 'Download the script, verify its checksum, then run it explicitly.',
  },
  {
    pattern: /curl[^|]*\|\s*ruby/,
    description: 'curl piped into Ruby executes remote code without verification.',
    fix: 'Download the script, verify its checksum, then run it explicitly.',
  },
  {
    pattern: /chmod\s+777/,
    description:
      'chmod 777 grants full read/write/execute permissions to all users. ' +
      'This is almost never the right permission set and violates least privilege.',
    fix: 'Use the minimum necessary permissions, e.g. chmod 755 for executables or chmod 644 for files.',
  },
  {
    pattern: /--privileged/,
    description:
      'Running with --privileged grants nearly unrestricted access to the host system. ' +
      'This should not appear in a Dockerfile RUN instruction.',
    fix: 'Remove --privileged. If you need specific capabilities, use --cap-add with the minimum required capabilities.',
  },
];

/**
 * Checks RUN instructions for dangerous command patterns.
 */
function checkDangerousRunCommands(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instr of instructions) {
    if (instr.type !== 'RUN') continue;

    for (const { pattern, description, fix } of DANGEROUS_RUN_PATTERNS) {
      if (pattern.test(instr.args)) {
        findings.push({
          id: RULE_IDS.DF_SEC_003,
          title: `Dangerous RUN command pattern: ${pattern.source.slice(0, 40)}...`,
          description,
          severity: 'high',
          line: instr.line,
          evidence: instr.raw,
          fix,
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
          ],
        });
        // One finding per instruction per match pattern
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// DF-SEC-004: Sensitive ports exposed
// ---------------------------------------------------------------------------

/**
 * Checks EXPOSE instructions for ports that are considered sensitive
 * (databases, SSH, admin UIs, etc.) when exposed in production containers.
 */
function checkSensitivePorts(
  instructions: DockerfileInstruction[],
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const instr of instructions) {
    if (instr.type !== 'EXPOSE' || !instr.exposedPorts) continue;

    for (const { port } of instr.exposedPorts) {
      const reason = SENSITIVE_PORTS[port];
      if (reason) {
        findings.push({
          id: RULE_IDS.DF_SEC_004,
          title: `Sensitive port ${port} exposed`,
          description:
            `Port ${port} is being exposed. ${reason}. ` +
            'Exposing this port increases the attack surface of the container. ' +
            'If this port must be accessible, restrict it to internal networks.',
          severity: port === 2375 ? 'critical' : 'medium',
          line: instr.line,
          evidence: instr.raw,
          fix:
            port === 22
              ? 'Remove EXPOSE 22. Use `docker exec` or kubectl exec for shell access instead of SSH.'
              : `Remove EXPOSE ${port} if not required. Access databases from application containers on internal networks.`,
          references: [
            'https://docs.docker.com/engine/reference/builder/#expose',
            'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
          ],
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public analyzer entry point
// ---------------------------------------------------------------------------

/**
 * Runs all security checks on a parsed Dockerfile AST.
 *
 * @param ast  Parsed DockerfileAST from parseDockerfile()
 * @returns    Array of security findings, sorted by severity
 */
export function analyzeDockerfileSecurity(ast: DockerfileAST): AuditFinding[] {
  const findings: AuditFinding[] = [];

  // Root user check (operates on full AST for cross-instruction analysis)
  const rootFinding = checkRootUser(ast);
  if (rootFinding) findings.push(rootFinding);

  // Instruction-level checks
  findings.push(...checkSecretsInEnv(ast.instructions));
  findings.push(...checkDangerousRunCommands(ast.instructions));
  findings.push(...checkSensitivePorts(ast.instructions));

  return findings;
}
