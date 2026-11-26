// Opt-in (--probe): start each local stdio server the way its client would, ask it only for
// initialize and tools/list, stop it, and check the tool descriptions it returns. This runs the
// servers' code, which the clients already do at every start; remote servers are not contacted.

import { spawn } from "node:child_process";
import { finding } from "./rules.js";
import { redact } from "./secrets.js";
import type { ConfigFile, Finding, ToolDescription } from "./types.js";

const PROTOCOL_VERSION = "2025-06-18";
const MAX_OUTPUT = 4 * 1024 * 1024;

export interface ProbeOutcome {
  tools: ToolDescription[];
  /** Servers that could not be listed, with the reason (timeout, exit, invalid reply). */
  failures: { server: string; file: string; reason: string }[];
}

export async function probeServers(files: ConfigFile[], timeoutMs = 15000): Promise<ProbeOutcome> {
  const outcome: ProbeOutcome = { tools: [], failures: [] };
  for (const file of files) {
    for (const server of file.servers) {
      if (server.transport !== "stdio" || !server.command) continue;
      try {
        const tools = await listTools(server.command, server.args, server.env, timeoutMs);
        for (const tool of tools) {
          outcome.tools.push({ server: server.name, file: file.path, client: file.client, name: tool.name, description: tool.description, schema: tool.schema });
        }
      } catch (error) {
        outcome.failures.push({ server: server.name, file: file.path, reason: error instanceof Error ? error.message : String(error) });
      }
    }
  }
  return outcome;
}

interface RawTool {
  name: string;
  description: string;
  schema: string;
}

export function listTools(command: string, args: string[], env: Record<string, string>, timeoutMs: number): Promise<RawTool[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "ignore"], shell: false, windowsHide: true });
    let buffer = "";
    let received = 0;
    let settled = false;
    const finish = (error: Error | null, tools?: RawTool[]) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout.removeAllListeners();
      child.kill("SIGKILL");
      if (error) reject(error);
      else resolve(tools ?? []);
    };
    const timer = setTimeout(() => finish(new Error(`no tools/list reply within ${timeoutMs / 1000}s`)), timeoutMs);
    const send = (message: object) => child.stdin.write(`${JSON.stringify(message)}\n`);
    child.on("error", (error) => finish(new Error(`could not start: ${error.message}`)));
    child.on("exit", (code) => finish(new Error(`exited with code ${code} before listing its tools`)));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      received += chunk.length;
      if (received > MAX_OUTPUT) return finish(new Error("replied with more than 4 MiB"));
      buffer += chunk;
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        let message: { id?: unknown; result?: unknown; error?: unknown };
        try {
          message = JSON.parse(line) as typeof message;
        } catch {
          continue;
        }
        if (message.id === 1) {
          if (message.error) return finish(new Error("rejected initialize"));
          send({ jsonrpc: "2.0", method: "notifications/initialized" });
          send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
        } else if (message.id === 2) {
          if (message.error) return finish(new Error("rejected tools/list"));
          const result = message.result as { tools?: unknown } | undefined;
          const tools = Array.isArray(result?.tools) ? result.tools : [];
          return finish(
            null,
            tools
              .filter((tool): tool is Record<string, unknown> => typeof tool === "object" && tool !== null)
              .map((tool) => ({
                name: typeof tool.name === "string" ? tool.name : "",
                description: typeof tool.description === "string" ? tool.description : "",
                schema: JSON.stringify(tool.inputSchema ?? {}),
              })),
          );
        }
      }
    });
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "mcp-audit", version: "0.1.1" } } });
  });
}

// Characters that render as nothing or reorder text: a place to hide instructions from the user.
const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿\u{E0000}-\u{E007F}]/u;

// Phrases aimed at the model rather than describing what the tool does. Each is specific enough that
// a normal description does not use it.
const INSTRUCTIONS: readonly { label: string; regex: RegExp }[] = [
  { label: "tells the model to hide something from the user", regex: /\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\s+(?:this\s+to\s+)?(?:the\s+)?user\b/i },
  { label: "tells the model to ignore other instructions", regex: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|other|earlier)\s+(?:instructions|rules|tools|directions)\b/i },
  { label: "uses a hidden-instruction tag", regex: /<\s*(?:important|system|instructions?|secret|hidden)\s*>/i },
  { label: "asks the model to read credentials or keys", regex: /\b(?:read|include|send|pass|attach|cat|upload|append|provide)\b[^.]{0,60}(?:~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.netrc|mcp\.json|claude_desktop_config\.json|private[_ ]key)/i },
  { label: "changes how other tools must be used", regex: /\b(?:before|when|whenever)\s+(?:using|calling|invoking)\s+(?:this|any|the\s+\w+|other)\s+tools?\b.*\b(?:must|always|first)\b/is },
  { label: "asks to send data to an address it names", regex: /\b(?:send|forward|copy|bcc|post)\b[^.]{0,60}\b(?:to|at)\s+(?:https?:\/\/|[\w.+-]+@[\w-]+\.)/i },
];

export function auditTools(files: ConfigFile[], tools: ToolDescription[]): Finding[] {
  const fileOf = (path: string) => files.find((file) => file.path === path) as ConfigFile;
  const findings: Finding[] = [];
  for (const tool of tools) {
    const file = fileOf(tool.file);
    const server = file.servers.find((item) => item.name === tool.server) ?? null;
    const pointer = `${server?.pointer ?? ""}#tools/${tool.name}`;
    const text = `${tool.name}\n${tool.description}\n${tool.schema}`;
    if (HIDDEN.test(text)) {
      const codes = [...new Set([...text].filter((char) => HIDDEN.test(char)).map((char) => `U+${(char.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, "0")}`))];
      findings.push(finding("MCP-TOOL-001", server, file, pointer, `Tool "${tool.name}" of "${tool.server}" contains ${codes.join(", ")}.`, "Do not use this server until its maintainer explains the characters; report it if they hide text."));
    }
    const matched = INSTRUCTIONS.filter((item) => item.regex.test(`${tool.description}\n${tool.schema}`)).map((item) => item.label);
    if (matched.length) {
      findings.push(finding("MCP-TOOL-002", server, file, pointer, `Tool "${tool.name}" of "${tool.server}" ${matched.join("; ")}: "${excerpt(tool.description)}".`, "Remove the server unless you trust its source and the text is legitimate; tool descriptions should describe the tool, not instruct the model."));
    }
  }
  const byName = new Map<string, ToolDescription[]>();
  for (const tool of tools) byName.set(tool.name, [...(byName.get(tool.name) ?? []), tool]);
  for (const [name, owners] of byName) {
    const servers = [...new Set(owners.map((tool) => tool.server))];
    if (servers.length < 2) continue;
    const first = owners[0] as ToolDescription;
    const file = fileOf(first.file);
    findings.push(finding("MCP-TOOL-003", null, file, `#tools/${name}`, `Tool "${name}" is exposed by ${servers.map((server) => `"${server}"`).join(" and ")}.`, "Disable one of the servers or rename its tool so the agent calls the implementation you expect."));
  }
  return findings;
}

function excerpt(text: string): string {
  // Hidden characters are shown as their code point, so the report itself cannot hide anything.
  const visible = [...text].map((char) => (HIDDEN.test(char) ? `<U+${(char.codePointAt(0) as number).toString(16).toUpperCase()}>` : char)).join("");
  const single = redact(visible.replace(/\s+/g, " ").trim());
  return single.length > 160 ? `${single.slice(0, 157)}…` : single;
}
