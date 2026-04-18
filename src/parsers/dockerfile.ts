/**
 * Dockerfile parser — lexer + AST builder.
 *
 * Implements a two-phase approach:
 *   1. Lexer (tokenizeDockerfile): Splits raw text into logical lines,
 *      handling line continuations (backslash at end of line) and comments.
 *   2. Parser (parseDockerfile): Converts logical lines into DockerfileInstruction
 *      objects with structured metadata (fromDetails, envPairs, exposedPorts).
 *
 * The parser intentionally does not fail on unknown instructions — it marks
 * them as type 'UNKNOWN' so analyzers can still process the rest of the file.
 */

import type {
  DockerfileAST,
  DockerfileInstruction,
  DockerfileInstructionType,
  FromDetails,
} from '../types/ast.js';

// ---------------------------------------------------------------------------
// Token — represents one logical line after continuation processing
// ---------------------------------------------------------------------------

/**
 * A single logical line produced by the lexer.
 * "Logical" means continuation lines have been joined into one entry.
 */
interface Token {
  /** The full text of the logical line (continuation lines joined with space) */
  text: string;

  /** 1-based line number where this logical line starts in the source */
  startLine: number;
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

/**
 * Tokenizes a raw Dockerfile string into logical lines.
 *
 * Rules applied:
 * - Lines starting with `#` are comments → skipped
 * - Empty lines → skipped
 * - Lines ending with `\` continue onto the next line (backslash-continuation)
 * - The continuation character and surrounding whitespace are collapsed to a
 *   single space so the resulting `args` is easy to process
 *
 * @param content  Raw Dockerfile text
 * @returns        Array of logical-line tokens with their start line numbers
 */
export function tokenizeDockerfile(content: string): Token[] {
  const rawLines = content.split('\n');
  const tokens: Token[] = [];

  let i = 0;
  while (i < rawLines.length) {
    const rawLine = rawLines[i] ?? '';
    const trimmed = rawLine.trim();

    // Skip comments and blank lines
    if (trimmed === '' || trimmed.startsWith('#')) {
      i++;
      continue;
    }

    // Detect the escape character directive (# escape=`) at top of file.
    // For simplicity we only support `\` (the default). A future enhancement
    // could parse the parser directive and adjust accordingly.

    const startLine = i + 1; // 1-based
    let logical = trimmed;

    // Handle line continuation: lines ending with `\` join with next line
    while (logical.endsWith('\\')) {
      // Remove trailing backslash + optional whitespace
      logical = logical.slice(0, -1).trimEnd();
      i++;
      if (i >= rawLines.length) break;

      const nextTrimmed = (rawLines[i] ?? '').trim();
      // Skip comment-only continuation lines (rare but valid)
      if (nextTrimmed.startsWith('#')) {
        i++;
        continue;
      }
      // Join with a space — normalizes `RUN apt-get update \` + `    && apt-get install`
      logical = logical + ' ' + nextTrimmed;
    }

    tokens.push({ text: logical, startLine });
    i++;
  }

  return tokens;
}

// ---------------------------------------------------------------------------
// Helpers for specific instruction types
// ---------------------------------------------------------------------------

/**
 * Parses a FROM argument string into its component parts.
 *
 * Examples:
 *   "ubuntu:22.04"                  → { image: 'ubuntu', tag: '22.04' }
 *   "node:lts-alpine AS builder"    → { image: 'node', tag: 'lts-alpine', alias: 'builder' }
 *   "ubuntu@sha256:abc123"          → { image: 'ubuntu', digest: 'sha256:abc123' }
 *   "builder"                       → { image: 'builder', isMultiStage: true }
 */
function parseFromArgs(args: string): FromDetails {
  // Strip optional AS <name> suffix (case-insensitive per spec)
  let rest = args;
  let alias: string | undefined;

  const asMatch = rest.match(/^(.+?)\s+AS\s+(\S+)$/i);
  if (asMatch) {
    rest = (asMatch[1] ?? '').trim();
    alias = asMatch[2];
  }

  // Split image reference from digest (@sha256:...)
  const digestIdx = rest.indexOf('@');
  let imageRef = rest;
  let digest: string | undefined;

  if (digestIdx !== -1) {
    imageRef = rest.slice(0, digestIdx);
    digest = rest.slice(digestIdx + 1);
  }

  // Split image name from tag (:tag)
  // Be careful with registry hostnames that contain colons (host:port/image)
  const parts = imageRef.split('/');
  const lastPart = parts[parts.length - 1] ?? '';
  const colonIdx = lastPart.indexOf(':');

  let image: string;
  let tag: string | undefined;

  if (colonIdx !== -1) {
    // Reconstruct image path without the tag
    parts[parts.length - 1] = lastPart.slice(0, colonIdx);
    image = parts.join('/');
    tag = lastPart.slice(colonIdx + 1);
  } else {
    image = imageRef;
  }

  return {
    image,
    tag,
    digest,
    alias,
    // Heuristic: if image looks like a stage name (no slash, no registry chars)
    // and matches the pattern of a previous AS alias, mark as multi-stage.
    // The parser sets this; the analyzer cross-references against declared aliases.
    isMultiStage: !tag && !digest && !image.includes('/') && !image.includes('.'),
  };
}

/**
 * Parses ENV instruction arguments into key-value pairs.
 *
 * Handles both syntaxes:
 *   - Multi-var: `KEY1=value1 KEY2="value two"` → array of pairs
 *   - Legacy:    `KEY value`                     → single pair
 */
function parseEnvArgs(args: string): Array<{ key: string; value: string }> {
  const pairs: Array<{ key: string; value: string }> = [];

  // Check if this uses the key=value syntax (new-style)
  if (args.includes('=')) {
    // Tokenize respecting quoted values
    // e.g. KEY1=val1 KEY2="hello world" KEY3='it'"'"'s fine'
    const regex = /(\w+)=("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S*)/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(args)) !== null) {
      const key = match[1] ?? '';
      let value = match[2] ?? '';
      // Strip surrounding quotes
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      pairs.push({ key, value });
    }
  } else {
    // Legacy syntax: `ENV KEY value` — everything after first whitespace is the value
    const spaceIdx = args.search(/\s/);
    if (spaceIdx !== -1) {
      pairs.push({
        key: args.slice(0, spaceIdx),
        value: args.slice(spaceIdx + 1).trim(),
      });
    }
  }

  return pairs;
}

/**
 * Parses EXPOSE instruction arguments into port/protocol pairs.
 *
 * Examples:
 *   "80"          → [{ port: 80, protocol: 'tcp' }]
 *   "80/tcp 443"  → [{ port: 80, protocol: 'tcp' }, { port: 443, protocol: 'tcp' }]
 *   "53/udp"      → [{ port: 53, protocol: 'udp' }]
 */
function parseExposeArgs(args: string): Array<{ port: number; protocol: 'tcp' | 'udp' }> {
  return args
    .split(/\s+/)
    .filter(Boolean)
    .map((token) => {
      const [portStr, proto] = token.split('/');
      const port = parseInt(portStr ?? '', 10);
      const protocol: 'tcp' | 'udp' =
        (proto ?? 'tcp').toLowerCase() === 'udp' ? 'udp' : 'tcp';
      return { port: isNaN(port) ? 0 : port, protocol };
    })
    .filter((p) => p.port > 0);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parses a list of lexer tokens into a DockerfileAST.
 *
 * @param tokens   Output from tokenizeDockerfile()
 * @param source   File path for the DockerfileAST.source field
 */
function tokensToAST(tokens: Token[], source: string): DockerfileAST {
  const instructions: DockerfileInstruction[] = [];
  let stageCount = 0;

  for (const token of tokens) {
    // The instruction keyword is the first whitespace-delimited word (upper-cased)
    const spaceIdx = token.text.search(/\s/);
    let keyword: string;
    let args: string;

    if (spaceIdx === -1) {
      // Instruction with no arguments (e.g., standalone HEALTHCHECK NONE)
      keyword = token.text.toUpperCase();
      args = '';
    } else {
      keyword = token.text.slice(0, spaceIdx).toUpperCase();
      args = token.text.slice(spaceIdx + 1).trim();
    }

    // Map the keyword to our known instruction types
    const knownTypes: Set<string> = new Set([
      'FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY',
      'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD',
      'STOPSIGNAL', 'HEALTHCHECK', 'SHELL',
    ]);
    const type: DockerfileInstructionType = knownTypes.has(keyword)
      ? (keyword as DockerfileInstructionType)
      : 'UNKNOWN';

    const instruction: DockerfileInstruction = {
      type,
      args,
      line: token.startLine,
      raw: token.text,
    };

    // Enrich specific instruction types with parsed details
    if (type === 'FROM') {
      stageCount++;
      instruction.fromDetails = parseFromArgs(args);
    } else if (type === 'ENV') {
      instruction.envPairs = parseEnvArgs(args);
    } else if (type === 'EXPOSE') {
      instruction.exposedPorts = parseExposeArgs(args);
    }

    instructions.push(instruction);
  }

  return { instructions, stageCount, source };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses a raw Dockerfile string into a structured AST.
 *
 * This is the main entry point for the Dockerfile parser.
 * Combines the lexer and AST-builder phases.
 *
 * @param content  Raw text content of the Dockerfile
 * @param source   File path (used in error messages and the AST)
 * @returns        Structured DockerfileAST
 *
 * @example
 * const ast = parseDockerfile(fs.readFileSync('Dockerfile', 'utf-8'), 'Dockerfile');
 * ast.instructions.forEach(i => console.log(i.type, i.line));
 */
export function parseDockerfile(content: string, source = 'Dockerfile'): DockerfileAST {
  const tokens = tokenizeDockerfile(content);
  return tokensToAST(tokens, source);
}
