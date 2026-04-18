/**
 * Unit tests for the Dockerfile security analyzer.
 *
 * Tests cover all four security rules:
 *   DF-SEC-001: Root user detection
 *   DF-SEC-002: Secrets in ENV variables
 *   DF-SEC-003: Dangerous RUN commands
 *   DF-SEC-004: Sensitive ports
 */

import { describe, it, expect } from 'vitest';
import { parseDockerfile } from '../../src/parsers/dockerfile.js';
import { analyzeDockerfileSecurity } from '../../src/analyzers/dockerfile/security.js';
import { RULE_IDS } from '../../src/constants/index.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function analyze(dockerfileContent: string) {
  const ast = parseDockerfile(dockerfileContent, 'test.Dockerfile');
  return analyzeDockerfileSecurity(ast);
}

function findById(findings: ReturnType<typeof analyze>, id: string) {
  return findings.find((f) => f.id === id);
}

// ---------------------------------------------------------------------------
// DF-SEC-001: Root user
// ---------------------------------------------------------------------------

describe('DF-SEC-001 — Root user', () => {
  it('flags Dockerfile with no USER instruction', () => {
    const findings = analyze('FROM ubuntu:22.04\nRUN echo hello');
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('flags Dockerfile with explicit USER root', () => {
    const findings = analyze('FROM ubuntu:22.04\nUSER root');
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('flags USER 0 (numeric root)', () => {
    const findings = analyze('FROM ubuntu:22.04\nUSER 0');
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeDefined();
  });

  it('does NOT flag Dockerfile with non-root USER', () => {
    const findings = analyze('FROM ubuntu:22.04\nRUN useradd -u 1001 appuser\nUSER appuser');
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeUndefined();
  });

  it('does NOT flag USER 1001', () => {
    const findings = analyze('FROM ubuntu:22.04\nUSER 1001');
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeUndefined();
  });

  it('uses the LAST USER instruction (handles multi-stage)', () => {
    // Final stage runs as root — should flag
    const content = [
      'FROM node:20 AS builder',
      'USER nonroot',
      'RUN npm build',
      'FROM nginx:alpine',
      // No USER in final stage
    ].join('\n');
    const findings = analyze(content);
    const finding = findById(findings, RULE_IDS.DF_SEC_001);
    expect(finding).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// DF-SEC-002: Secrets in ENV
// ---------------------------------------------------------------------------

describe('DF-SEC-002 — Secrets in ENV', () => {
  it('flags ENV with PASSWORD key', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV DB_PASSWORD=supersecret123\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('flags ENV with API_KEY pattern', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV API_KEY=abc123xyz\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    expect(finding).toBeDefined();
  });

  it('flags ENV with SECRET in name', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV GITHUB_SECRET=abc123\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    expect(finding).toBeDefined();
  });

  it('does NOT flag ENV with placeholder values', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV DB_PASSWORD=${DB_PASSWORD}\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    expect(finding).toBeUndefined();
  });

  it('does NOT flag innocuous ENV variables', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV NODE_ENV=production PORT=3000\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    expect(finding).toBeUndefined();
  });

  it('redacts the secret value in finding evidence', () => {
    const findings = analyze('FROM ubuntu:22.04\nENV DB_PASSWORD=hunter2\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_002);
    // Evidence should NOT contain the actual secret value
    expect(finding?.evidence).not.toContain('hunter2');
    expect(finding?.evidence).toContain('***');
  });
});

// ---------------------------------------------------------------------------
// DF-SEC-003: Dangerous RUN commands
// ---------------------------------------------------------------------------

describe('DF-SEC-003 — Dangerous RUN commands', () => {
  it('flags curl|bash pattern', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN curl https://install.example.com | bash\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('flags curl|sh pattern', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN curl -fsSL https://get.docker.com | sh\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeDefined();
  });

  it('flags wget|bash pattern', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN wget -O - https://example.com/install | bash\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeDefined();
  });

  it('flags chmod 777', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN chmod 777 /app/secret\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeDefined();
  });

  it('does NOT flag safe curl usage', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/file.tar.gz -o file.tar.gz\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeUndefined();
  });

  it('does NOT flag normal apt-get', () => {
    const findings = analyze(
      'FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\nUSER app',
    );
    const finding = findById(findings, RULE_IDS.DF_SEC_003);
    expect(finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// DF-SEC-004: Sensitive ports
// ---------------------------------------------------------------------------

describe('DF-SEC-004 — Sensitive ports', () => {
  it('flags SSH port 22', () => {
    const findings = analyze('FROM ubuntu:22.04\nEXPOSE 22\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('flags MySQL port 3306', () => {
    const findings = analyze('FROM mysql:8\nEXPOSE 3306\nUSER mysql');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeDefined();
  });

  it('flags PostgreSQL port 5432', () => {
    const findings = analyze('FROM postgres:16\nEXPOSE 5432\nUSER postgres');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeDefined();
  });

  it('flags Docker daemon port 2375 as CRITICAL', () => {
    const findings = analyze('FROM ubuntu:22.04\nEXPOSE 2375\nUSER app');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('does NOT flag standard web ports', () => {
    const findings = analyze('FROM nginx:alpine\nEXPOSE 80 443\nUSER nginx');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeUndefined();
  });

  it('does NOT flag application ports', () => {
    const findings = analyze('FROM node:20\nEXPOSE 3000 8080\nUSER node');
    const finding = findById(findings, RULE_IDS.DF_SEC_004);
    expect(finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Integration: multiple findings
// ---------------------------------------------------------------------------

describe('Security analyzer integration', () => {
  it('returns multiple findings for a badly-configured Dockerfile', () => {
    const content = [
      'FROM ubuntu:latest',
      'ENV DB_PASSWORD=secret123',
      'RUN curl https://get.docker.com | sh',
      'EXPOSE 22 3306',
      // No USER instruction
    ].join('\n');

    const findings = analyze(content);
    // Should have: root user, secret in env, dangerous run, x2 sensitive ports
    expect(findings.length).toBeGreaterThanOrEqual(4);
  });

  it('returns no security findings for a clean Dockerfile', () => {
    const content = [
      'FROM node:20.11.1-alpine3.18',
      'WORKDIR /app',
      'COPY package.json package-lock.json ./',
      'RUN npm ci --only=production',
      'COPY src/ ./src/',
      'EXPOSE 3000',
      'RUN addgroup -S appgroup && adduser -S appuser -G appgroup',
      'USER appuser',
      'HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1',
      'CMD ["node", "src/index.js"]',
    ].join('\n');

    const findings = analyze(content);
    const securityFindings = findings.filter(
      (f) => f.id.startsWith('DF-SEC'),
    );
    expect(securityFindings).toHaveLength(0);
  });
});
