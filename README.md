# pipelens

[![npm version](https://badge.fury.io/js/pipelens.svg)](https://badge.fury.io/js/pipelens)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/vinisha231/pipelens/actions/workflows/ci.yml/badge.svg)](https://github.com/vinisha231/pipelens/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org/)

> AI-powered Dockerfile and CI/CD pipeline security auditor — find vulnerabilities, bad practices, and optimization opportunities in seconds.

---

## Features

- **Dockerfile Analysis** — Security issues, layer optimization, best practices, image pinning
- **GitHub Actions Auditing** — Secrets exposure, permission misconfigurations, dependency pinning, caching gaps
- **GitLab CI Auditing** — Security and optimization analysis for `.gitlab-ci.yml`
- **AI-Powered Suggestions** — Contextual, intelligent fix recommendations using AI
- **Multiple Output Formats** — Beautiful terminal output, JSON for CI/CD integration, HTML for sharing
- **Configurable** — Skip rules, set severity thresholds, disable AI

---

## Installation

```bash
# Install globally
npm install -g pipelens

# Or run directly with npx
npx pipelens audit
```

---

## Quick Start

```bash
# Audit the current directory (auto-detects Dockerfiles + workflow files)
pipelens audit

# Audit a specific Dockerfile
pipelens audit --dockerfile ./Dockerfile

# Audit GitHub Actions workflows
pipelens audit --workflow .github/workflows/

# Audit everything in a path
pipelens audit ./my-project

# Get a JSON report
pipelens audit --format json --output report.json

# Get an HTML report
pipelens audit --format html --output report.html
```

---

## CLI Reference

### `pipelens audit [path]`

Audits Dockerfiles and CI/CD configuration files at the given path (defaults to current directory).

| Flag | Description | Default |
|------|-------------|---------|
| `--dockerfile <path>` | Path to a specific Dockerfile | auto-detect |
| `--workflow <path>` | Path to workflow file or directory | auto-detect |
| `--format <type>` | Output format: `terminal`, `json`, `html` | `terminal` |
| `--output <file>` | Write report to file | stdout |
| `--no-ai` | Disable AI suggestions | AI enabled |
| `--severity <level>` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | `info` |
| `--config <path>` | Path to config file | `./pipelens.config.json` |

### `pipelens init`

Creates a `pipelens.config.json` configuration file in the current directory.

### `pipelens report`

Regenerates a report from the last audit results.

---

## Configuration

Create a `pipelens.config.json` file (or run `pipelens init`):

```json
{
  "ignore": ["DF-BP-003", "GHA-CACHE-001"],
  "severity": "medium",
  "ai": true,
  "format": "terminal",
  "output": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ignore` | `string[]` | Rule IDs to skip |
| `severity` | `string` | Minimum severity level to report |
| `ai` | `boolean` | Enable/disable AI suggestions |
| `format` | `string` | Default output format |
| `output` | `string \| null` | Default output file path |

---

## Environment Variables

```bash
# Required for AI suggestions
export ANTHROPIC_API_KEY=your_api_key_here
```

---

## Rule Reference

### Dockerfile Rules

| ID | Severity | Description |
|----|----------|-------------|
| `DF-SEC-001` | CRITICAL | Running as root user |
| `DF-SEC-002` | HIGH | Secrets detected in ENV variables |
| `DF-SEC-003` | HIGH | Dangerous command execution (curl\|sh) |
| `DF-SEC-004` | MEDIUM | Sensitive port exposed (22, 3306, etc.) |
| `DF-LAYER-001` | MEDIUM | Package manager cache not cleared |
| `DF-LAYER-002` | LOW | Multiple RUN commands should be chained |
| `DF-LAYER-003` | MEDIUM | Source code copied before dependencies (breaks caching) |
| `DF-BP-001` | HIGH | Unpinned base image (using :latest tag) |
| `DF-BP-002` | MEDIUM | ADD used instead of COPY |
| `DF-BP-003` | LOW | No HEALTHCHECK defined |
| `DF-BP-004` | INFO | Large base image — alpine alternative available |

### GitHub Actions Rules

| ID | Severity | Description |
|----|----------|-------------|
| `GHA-SEC-001` | CRITICAL | Hardcoded secret/token in workflow |
| `GHA-SEC-002` | HIGH | Secret printed to logs |
| `GHA-SEC-003` | HIGH | Untrusted input in run step (script injection) |
| `GHA-PERM-001` | HIGH | Overly broad write permissions |
| `GHA-PERM-002` | MEDIUM | Missing explicit permissions block |
| `GHA-PIN-001` | HIGH | Unpinned action (using branch ref instead of SHA) |
| `GHA-CACHE-001` | LOW | Missing dependency cache (npm/pip/maven detected) |

### GitLab CI Rules

| ID | Severity | Description |
|----|----------|-------------|
| `GL-SEC-001` | HIGH | Secret variable exposed in log |
| `GL-SEC-002` | MEDIUM | Privileged Docker-in-Docker without justification |
| `GL-OPT-001` | LOW | Missing cache configuration for build artifacts |

---

## Examples

### Audit with AI suggestions (terminal output)

```
$ pipelens audit ./my-app

╔══════════════════════════════════════════════════════╗
║              pipelens v0.1.0                         ║
║     AI-powered pipeline security auditor             ║
╚══════════════════════════════════════════════════════╝

 Analyzing ./my-app/Dockerfile...
 Analyzing .github/workflows/deploy.yml...
 Running AI analysis...

┌─ Dockerfile ────────────────────────────────────────┐
│  Score: 42/100  ████████░░░░░░░░░░░░ POOR           │
└─────────────────────────────────────────────────────┘

  [CRITICAL] DF-SEC-001 — Running as root user
  Line 1: FROM ubuntu:latest
  No USER instruction found. Container runs as root by default.
  Fix: Add "USER nonroot" after creating a non-root user.

  [HIGH] DF-BP-001 — Unpinned base image
  Line 1: FROM ubuntu:latest
  Using :latest tag makes builds non-reproducible.
  Fix: Pin to a specific digest: FROM ubuntu:22.04@sha256:...

Summary: 3 critical, 2 high, 4 medium, 1 low
Overall score: 51/100
```

---

## Development

```bash
# Clone the repository
git clone https://github.com/vinisha231/pipelens.git
cd pipelens

# Install dependencies
npm install

# Run in development mode
npm run dev -- audit --dockerfile examples/dockerfiles/bad.Dockerfile

# Run tests
npm test

# Build
npm run build
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Run `npm test` and `npm run lint`
5. Submit a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.
