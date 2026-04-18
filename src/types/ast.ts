/**
 * AST (Abstract Syntax Tree) node type definitions.
 *
 * These types represent the structured form of parsed configuration files.
 * Each parser produces one of these trees, which analyzers then traverse
 * to find issues.
 *
 * Design principle: keep AST nodes minimal — only what analyzers need.
 * Every node carries its source line number for accurate error reporting.
 */

// ===========================================================================
// Dockerfile AST
// ===========================================================================

/**
 * All Dockerfile instruction keywords we recognize.
 * The parser will tag each instruction with one of these discriminants.
 */
export type DockerfileInstructionType =
  | 'FROM'
  | 'RUN'
  | 'CMD'
  | 'LABEL'
  | 'EXPOSE'
  | 'ENV'
  | 'ADD'
  | 'COPY'
  | 'ENTRYPOINT'
  | 'VOLUME'
  | 'USER'
  | 'WORKDIR'
  | 'ARG'
  | 'ONBUILD'
  | 'STOPSIGNAL'
  | 'HEALTHCHECK'
  | 'SHELL'
  | 'UNKNOWN';

/**
 * A single Dockerfile instruction with its arguments and source location.
 *
 * For example, `RUN apt-get update && apt-get install -y curl` becomes:
 * {
 *   type: 'RUN',
 *   args: 'apt-get update && apt-get install -y curl',
 *   line: 5,
 *   raw: 'RUN apt-get update && apt-get install -y curl'
 * }
 */
export interface DockerfileInstruction {
  /** The instruction keyword (upper-cased) */
  type: DockerfileInstructionType;

  /** Everything after the instruction keyword, with continuation lines joined */
  args: string;

  /** 1-based line number of the first line of this instruction */
  line: number;

  /** The raw text of the instruction (possibly multi-line, as written) */
  raw: string;

  /**
   * For FROM instructions, the parsed image reference:
   * { image: 'ubuntu', tag: 'latest', digest: undefined }
   */
  fromDetails?: FromDetails;

  /**
   * For ENV instructions, the parsed key-value pairs.
   * Handles both `ENV KEY=value` and legacy `ENV KEY value` syntax.
   */
  envPairs?: Array<{ key: string; value: string }>;

  /**
   * For EXPOSE instructions, the list of ports with optional protocol.
   */
  exposedPorts?: Array<{ port: number; protocol: 'tcp' | 'udp' }>;
}

/**
 * Parsed details from a FROM instruction.
 */
export interface FromDetails {
  /** The registry + image name, e.g. "ubuntu", "node", "gcr.io/foo/bar" */
  image: string;

  /** The tag portion, e.g. "latest", "22.04", "alpine3.18" */
  tag?: string;

  /** The digest pin, e.g. "sha256:abc123..." */
  digest?: string;

  /** The AS alias for multi-stage builds, e.g. "builder" */
  alias?: string;

  /** True if this is a multi-stage build reference (FROM builder AS ...) */
  isMultiStage?: boolean;
}

/**
 * The top-level Dockerfile AST — an ordered list of instructions.
 */
export interface DockerfileAST {
  /** All instructions in document order */
  instructions: DockerfileInstruction[];

  /** Number of distinct FROM instructions (>1 means multi-stage build) */
  stageCount: number;

  /** Source file path for error messages */
  source: string;
}

// ===========================================================================
// GitHub Actions AST
// ===========================================================================

/**
 * A single step within a GitHub Actions job.
 */
export interface GHAStep {
  /** Step id (optional, user-defined) */
  id?: string;

  /** Human-readable step name */
  name?: string;

  /** For `uses:` steps — the action reference, e.g. "actions/checkout@v4" */
  uses?: string;

  /** For `run:` steps — the shell script content */
  run?: string;

  /** Environment variables scoped to this step */
  env?: Record<string, string>;

  /** Step-level `if` condition */
  if?: string;

  /** 1-based line number in the workflow file */
  line?: number;
}

/**
 * A single job within a GitHub Actions workflow.
 */
export interface GHAJob {
  /** The job's key in the `jobs:` map */
  id: string;

  /** Human-readable job name */
  name?: string;

  /** Runner label, e.g. "ubuntu-latest" */
  runsOn: string | string[];

  /** Ordered list of steps */
  steps: GHAStep[];

  /** Job-level environment variables */
  env?: Record<string, string>;

  /**
   * Job-level permissions block.
   * Keys are permission scopes (contents, packages, etc.),
   * values are "read", "write", or "none".
   */
  permissions?: Record<string, string>;

  /** Job dependencies via `needs:` */
  needs?: string[];

  /** 1-based line number of the job definition */
  line?: number;
}

/**
 * Top-level parsed representation of a GitHub Actions workflow file.
 */
export interface GHAWorkflow {
  /** Workflow name */
  name?: string;

  /** Source file path */
  source: string;

  /**
   * Trigger events — the `on:` block.
   * Stored as raw parsed YAML because the schema is too varied to fully type.
   */
  on: Record<string, unknown>;

  /**
   * Workflow-level permissions block (applies to all jobs unless overridden).
   */
  permissions?: Record<string, string>;

  /** Workflow-level environment variables */
  env?: Record<string, string>;

  /** All jobs defined in this workflow */
  jobs: GHAJob[];
}

// ===========================================================================
// GitLab CI AST
// ===========================================================================

/**
 * A single GitLab CI job definition.
 */
export interface GitLabJob {
  /** Job name (the key in the YAML map) */
  name: string;

  /** The Docker image to use */
  image?: string | { name: string; entrypoint?: string[] };

  /** Ordered script commands */
  script: string[];

  /** Commands run before the main script */
  beforeScript?: string[];

  /** Commands run after the main script */
  afterScript?: string[];

  /** Stage this job belongs to */
  stage?: string;

  /** Job-level variables */
  variables?: Record<string, string>;

  /** Cache configuration */
  cache?: GitLabCache;

  /** Artifact configuration */
  artifacts?: Record<string, unknown>;

  /** Whether this job runs in privileged mode (relevant for DinD) */
  privileged?: boolean;

  /** Tag selectors for runner assignment */
  tags?: string[];

  /** 1-based line number */
  line?: number;
}

/**
 * GitLab CI cache configuration block.
 */
export interface GitLabCache {
  /** Files/globs to cache */
  paths?: string[];

  /** Cache key (string or object with `files`) */
  key?: string | Record<string, unknown>;

  /** Cache policy: pull-push, pull, or push */
  policy?: 'pull-push' | 'pull' | 'push';
}

/**
 * Top-level parsed representation of a .gitlab-ci.yml file.
 */
export interface GitLabCIConfig {
  /** Source file path */
  source: string;

  /** Global `image` if defined */
  image?: string;

  /** Ordered stage names */
  stages?: string[];

  /** Global variables */
  variables?: Record<string, string>;

  /** Global cache */
  cache?: GitLabCache;

  /** All job definitions (excludes special keys like `stages`, `variables`, etc.) */
  jobs: GitLabJob[];

  /** Global `before_script` */
  beforeScript?: string[];

  /** Global `after_script` */
  afterScript?: string[];
}
