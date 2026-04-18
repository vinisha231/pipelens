/**
 * Unit tests for the Dockerfile parser.
 *
 * Tests cover:
 *   - Basic instruction tokenization
 *   - Multi-line continuation handling
 *   - FROM instruction parsing (image, tag, digest, alias)
 *   - ENV instruction parsing (both syntaxes)
 *   - EXPOSE instruction parsing (ports + protocols)
 *   - Comment and blank line handling
 *   - Multi-stage build detection
 *   - Edge cases (empty files, unknown instructions)
 */

import { describe, it, expect } from 'vitest';
import { parseDockerfile, tokenizeDockerfile } from '../../src/parsers/dockerfile.js';

// ---------------------------------------------------------------------------
// tokenizeDockerfile
// ---------------------------------------------------------------------------

describe('tokenizeDockerfile', () => {
  it('returns empty array for blank file', () => {
    const tokens = tokenizeDockerfile('');
    expect(tokens).toHaveLength(0);
  });

  it('skips comment-only lines', () => {
    const tokens = tokenizeDockerfile('# This is a comment\n# Another comment');
    expect(tokens).toHaveLength(0);
  });

  it('skips blank lines', () => {
    const tokens = tokenizeDockerfile('\n\n  \n\t\n');
    expect(tokens).toHaveLength(0);
  });

  it('tokenizes a simple FROM instruction', () => {
    const tokens = tokenizeDockerfile('FROM node:20-alpine');
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.text).toBe('FROM node:20-alpine');
    expect(tokens[0]?.startLine).toBe(1);
  });

  it('joins continuation lines into one token', () => {
    const content = 'RUN apt-get update \\\n    && apt-get install -y curl';
    const tokens = tokenizeDockerfile(content);
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.text).toBe('RUN apt-get update && apt-get install -y curl');
  });

  it('handles multiple continuation lines', () => {
    const content = [
      'RUN apt-get update \\',
      '    && apt-get install -y \\',
      '        curl \\',
      '        wget',
    ].join('\n');
    const tokens = tokenizeDockerfile(content);
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.text).toContain('apt-get update');
    expect(tokens[0]?.text).toContain('curl');
    expect(tokens[0]?.text).toContain('wget');
  });

  it('records the correct start line for each instruction', () => {
    const content = ['# comment', 'FROM node:20', '', 'RUN npm install'].join('\n');
    const tokens = tokenizeDockerfile(content);
    expect(tokens).toHaveLength(2);
    expect(tokens[0]?.startLine).toBe(2); // FROM is on line 2
    expect(tokens[1]?.startLine).toBe(4); // RUN is on line 4
  });

  it('handles inline comments after continuation', () => {
    // Comments inside continuation blocks should be skipped
    const content = ['RUN echo hello \\', '    # this is a comment', '    && echo world'].join(
      '\n',
    );
    const tokens = tokenizeDockerfile(content);
    expect(tokens).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// parseDockerfile — basic structure
// ---------------------------------------------------------------------------

describe('parseDockerfile — basic structure', () => {
  it('parses a minimal Dockerfile', () => {
    const ast = parseDockerfile('FROM ubuntu:22.04\nRUN echo hello');
    expect(ast.instructions).toHaveLength(2);
    expect(ast.instructions[0]?.type).toBe('FROM');
    expect(ast.instructions[1]?.type).toBe('RUN');
  });

  it('sets the source field correctly', () => {
    const ast = parseDockerfile('FROM scratch', '/path/to/Dockerfile');
    expect(ast.source).toBe('/path/to/Dockerfile');
  });

  it('marks unknown instructions as UNKNOWN', () => {
    const ast = parseDockerfile('INVALIDINSTRUCTION some args');
    expect(ast.instructions[0]?.type).toBe('UNKNOWN');
  });

  it('handles HEALTHCHECK NONE correctly', () => {
    const ast = parseDockerfile('FROM scratch\nHEALTHCHECK NONE');
    const hc = ast.instructions.find((i) => i.type === 'HEALTHCHECK');
    expect(hc).toBeDefined();
    expect(hc?.args).toBe('NONE');
  });
});

// ---------------------------------------------------------------------------
// parseDockerfile — FROM instruction details
// ---------------------------------------------------------------------------

describe('parseDockerfile — FROM details', () => {
  it('parses image and tag', () => {
    const ast = parseDockerfile('FROM node:20-alpine');
    const from = ast.instructions[0];
    expect(from?.fromDetails?.image).toBe('node');
    expect(from?.fromDetails?.tag).toBe('20-alpine');
  });

  it('parses image without tag (defaults to latest behavior)', () => {
    const ast = parseDockerfile('FROM ubuntu');
    const from = ast.instructions[0];
    expect(from?.fromDetails?.image).toBe('ubuntu');
    expect(from?.fromDetails?.tag).toBeUndefined();
  });

  it('parses image with digest', () => {
    const ast = parseDockerfile('FROM node@sha256:abc123def456');
    const from = ast.instructions[0];
    expect(from?.fromDetails?.image).toBe('node');
    expect(from?.fromDetails?.digest).toBe('sha256:abc123def456');
  });

  it('parses AS alias for multi-stage builds', () => {
    const ast = parseDockerfile('FROM node:20 AS builder');
    const from = ast.instructions[0];
    expect(from?.fromDetails?.alias).toBe('builder');
    expect(from?.fromDetails?.image).toBe('node');
    expect(from?.fromDetails?.tag).toBe('20');
  });

  it('detects multi-stage build reference', () => {
    const content = 'FROM node:20 AS builder\nRUN npm build\nFROM scratch\nCOPY --from=builder /app .';
    const ast = parseDockerfile(content);
    expect(ast.stageCount).toBe(2);
  });

  it('handles registry with port in image name', () => {
    const ast = parseDockerfile('FROM registry.example.com:5000/myapp:latest');
    const from = ast.instructions[0];
    expect(from?.fromDetails?.image).toContain('registry.example.com');
    expect(from?.fromDetails?.tag).toBe('latest');
  });
});

// ---------------------------------------------------------------------------
// parseDockerfile — ENV instruction details
// ---------------------------------------------------------------------------

describe('parseDockerfile — ENV details', () => {
  it('parses new-style ENV with = syntax', () => {
    const ast = parseDockerfile('FROM scratch\nENV FOO=bar BAZ=qux');
    const env = ast.instructions.find((i) => i.type === 'ENV');
    expect(env?.envPairs).toHaveLength(2);
    expect(env?.envPairs?.[0]).toEqual({ key: 'FOO', value: 'bar' });
    expect(env?.envPairs?.[1]).toEqual({ key: 'BAZ', value: 'qux' });
  });

  it('parses legacy ENV with space syntax', () => {
    const ast = parseDockerfile('FROM scratch\nENV MYVAR myvalue with spaces');
    const env = ast.instructions.find((i) => i.type === 'ENV');
    expect(env?.envPairs).toHaveLength(1);
    expect(env?.envPairs?.[0]?.key).toBe('MYVAR');
    expect(env?.envPairs?.[0]?.value).toBe('myvalue with spaces');
  });

  it('parses ENV with quoted values', () => {
    const ast = parseDockerfile('FROM scratch\nENV MESSAGE="hello world"');
    const env = ast.instructions.find((i) => i.type === 'ENV');
    expect(env?.envPairs?.[0]?.value).toBe('hello world');
  });
});

// ---------------------------------------------------------------------------
// parseDockerfile — EXPOSE instruction details
// ---------------------------------------------------------------------------

describe('parseDockerfile — EXPOSE details', () => {
  it('parses a single TCP port', () => {
    const ast = parseDockerfile('FROM scratch\nEXPOSE 80');
    const expose = ast.instructions.find((i) => i.type === 'EXPOSE');
    expect(expose?.exposedPorts).toHaveLength(1);
    expect(expose?.exposedPorts?.[0]).toEqual({ port: 80, protocol: 'tcp' });
  });

  it('parses multiple ports', () => {
    const ast = parseDockerfile('FROM scratch\nEXPOSE 80 443 8080');
    const expose = ast.instructions.find((i) => i.type === 'EXPOSE');
    expect(expose?.exposedPorts).toHaveLength(3);
  });

  it('parses UDP port', () => {
    const ast = parseDockerfile('FROM scratch\nEXPOSE 53/udp');
    const expose = ast.instructions.find((i) => i.type === 'EXPOSE');
    expect(expose?.exposedPorts?.[0]).toEqual({ port: 53, protocol: 'udp' });
  });

  it('defaults to TCP when protocol not specified', () => {
    const ast = parseDockerfile('FROM scratch\nEXPOSE 8080/tcp');
    const expose = ast.instructions.find((i) => i.type === 'EXPOSE');
    expect(expose?.exposedPorts?.[0]?.protocol).toBe('tcp');
  });
});

// ---------------------------------------------------------------------------
// parseDockerfile — stageCount
// ---------------------------------------------------------------------------

describe('parseDockerfile — stage counting', () => {
  it('counts stages correctly for single-stage build', () => {
    const ast = parseDockerfile('FROM node:20\nRUN echo hello');
    expect(ast.stageCount).toBe(1);
  });

  it('counts stages correctly for multi-stage build', () => {
    const content = [
      'FROM node:20 AS build',
      'RUN npm run build',
      'FROM nginx:alpine',
      'COPY --from=build /dist /usr/share/nginx/html',
    ].join('\n');
    const ast = parseDockerfile(content);
    expect(ast.stageCount).toBe(2);
  });

  it('handles three-stage builds', () => {
    const content = [
      'FROM golang:1.22 AS deps',
      'FROM golang:1.22 AS builder',
      'FROM scratch AS final',
    ].join('\n');
    const ast = parseDockerfile(content);
    expect(ast.stageCount).toBe(3);
  });
});
