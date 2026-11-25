// The data the audit works on: MCP server definitions read from client configuration files, and the
// findings the rules produce about them. Nothing here is executed; it is read, normalized and checked.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/** Which client a configuration file belongs to. */
export type Client =
  | "claude-code"
  | "claude-desktop"
  | "cursor"
  | "codex"
  | "gemini-cli"
  | "vscode"
  | "windsurf"
  | "cline"
  | "generic";

/** One MCP server as a client would launch or connect to it. */
export interface ServerDefinition {
  /** The key the client uses for the server ("filesystem", "github", ...). */
  name: string;
  client: Client;
  /** Absolute path of the configuration file the definition came from. */
  file: string;
  /** JSON-pointer-like path inside the file, for reports ("/mcpServers/github"). */
  pointer: string;
  /** "stdio" when the client starts a process; "remote" when it connects to a URL. */
  transport: "stdio" | "remote";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  /** Tools the client runs without asking the user ("*" means every tool of the server). */
  autoApproved: string[];
  /** Gemini CLI's "trust": true, which skips every confirmation for the server. */
  trusted: boolean;
}

/** A client setting outside a single server that changes what servers may do. */
export interface ClientPermission {
  client: Client;
  file: string;
  pointer: string;
  /** The permission rule as written, e.g. "mcp__github__*". */
  rule: string;
}

export interface ConfigFile {
  path: string;
  client: Client;
  /** Unix permission bits of the file, when the platform reports them. */
  mode?: number;
  servers: ServerDefinition[];
  permissions: ClientPermission[];
  /** Set when the file exists but could not be parsed; the audit reports it and continues. */
  error?: string;
}

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  /** What was found, with secrets masked. */
  detail: string;
  /** What to change. */
  fix: string;
  file: string;
  pointer: string;
  server?: string;
  client: Client;
}

/** A tool as a running server describes it in tools/list (only with --probe). */
export interface ToolDescription {
  server: string;
  file: string;
  client: Client;
  name: string;
  description: string;
  /** The input schema serialized, so hidden text inside it is checked too. */
  schema: string;
}
