// mcp-audit as an MCP server (stdio, newline-delimited JSON-RPC 2.0). It offers one read-only tool
// that runs the static audit. It never starts other servers: --probe stays a command-line choice, so
// a prompt cannot make the agent execute every configured server.

import { createInterface } from "node:readline";
import { runAudit } from "./audit.js";
import { RULES } from "./rules.js";
import { summaryLine, TOOL_NAME, TOOL_URL, TOOL_VERSION } from "./report.js";
import type { Severity } from "./types.js";
import { severityRank } from "./types.js";

const SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const TOOL = {
  name: "audit_mcp_configs",
  title: "Audit MCP configurations",
  description:
    "Reads the MCP server configurations of Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf and Cline on this machine, plus any files or project folders given, and reports risks: unpinned packages, plain-text credentials (masked), unencrypted remote servers, broad filesystem access, privileged containers, shell bootstraps and auto-approved tools. Read-only; it starts no server and makes no network request.",
  inputSchema: {
    type: "object",
    properties: {
      paths: { type: "array", items: { type: "string" }, description: "Configuration files to audit in addition to (or instead of) the default locations." },
      projectDirs: { type: "array", items: { type: "string" }, description: "Project folders whose .mcp.json, .cursor, .vscode, .gemini and .claude settings are audited." },
      includeDefaults: { type: "boolean", description: "Also read every client's default configuration locations. Default true." },
      minSeverity: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Lowest severity to return. Default info." },
    },
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

type Message = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };

export function startServer(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): void {
  const reply = (id: Message["id"], result: unknown) => output.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
  const fail = (id: Message["id"], code: number, message: string) => output.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
  const lines = createInterface({ input, crlfDelay: Infinity });
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let message: Message;
    try {
      message = JSON.parse(line) as Message;
    } catch {
      fail(null, -32700, "Parse error");
      return;
    }
    const isRequest = message.id !== undefined && message.id !== null;
    try {
      switch (message.method) {
        case "initialize": {
          const requested = typeof message.params?.protocolVersion === "string" ? message.params.protocolVersion : "";
          const protocolVersion = SUPPORTED_VERSIONS.includes(requested) ? requested : SUPPORTED_VERSIONS[0];
          reply(message.id, {
            protocolVersion,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: TOOL_NAME, title: "MCP configuration audit by Asterion", version: TOOL_VERSION, websiteUrl: TOOL_URL },
            instructions: "Call audit_mcp_configs to check this machine's MCP configurations. Findings never include secrets in full.",
          });
          return;
        }
        case "ping":
          if (isRequest) reply(message.id, {});
          return;
        case "tools/list":
          reply(message.id, { tools: [TOOL] });
          return;
        case "tools/call": {
          const name = message.params?.name;
          if (name !== TOOL.name) {
            fail(message.id, -32602, `Unknown tool: ${String(name)}`);
            return;
          }
          reply(message.id, callAudit((message.params?.arguments ?? {}) as Record<string, unknown>));
          return;
        }
        default:
          if (message.method?.startsWith("notifications/")) return;
          if (isRequest) fail(message.id, -32601, `Method not found: ${String(message.method)}`);
      }
    } catch (error) {
      if (isRequest) fail(message.id, -32603, error instanceof Error ? error.message : "Internal error");
    }
  });
}

function callAudit(args: Record<string, unknown>) {
  const strings = (value: unknown) => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []);
  const minimum = (typeof args.minSeverity === "string" && ["critical", "high", "medium", "low", "info"].includes(args.minSeverity) ? args.minSeverity : "info") as Severity;
  const result = runAudit({ paths: strings(args.paths), projectDirs: strings(args.projectDirs), includeDefaults: args.includeDefaults !== false });
  const findings = result.findings.filter((item) => severityRank(item.severity) <= severityRank(minimum));
  const servers = result.files.reduce((total, file) => total + file.servers.length, 0);
  const header = `${result.files.length} configuration files, ${servers} MCP servers. ${findings.length ? summaryLine(findings) : "No findings."}`;
  const body = findings.map((item) => `- [${item.severity}] ${item.rule} ${item.title}: ${item.detail} Fix: ${item.fix} (${item.file}${item.pointer ? ` ${item.pointer}` : ""})`).join("\n");
  return {
    content: [{ type: "text", text: body ? `${header}\n\n${body}` : header }],
    structuredContent: {
      files: result.files.map((file) => ({ path: file.path, client: file.client, servers: file.servers.length, ...(file.error ? { error: file.error } : {}) })),
      findings,
      rules: RULES.map((rule) => rule.id),
    },
    isError: false,
  };
}
