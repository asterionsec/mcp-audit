// Where each client keeps its MCP configuration, and how each format becomes ServerDefinitions. Files
// are only read. A missing file is skipped; a file that exists but cannot be parsed is reported.

import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir, platform } from "node:os";
import { basename, join, resolve } from "node:path";
import { parseToml, type TomlTable } from "./toml.js";
import type { Client, ClientPermission, ConfigFile, ServerDefinition } from "./types.js";

interface Candidate {
  path: string;
  client: Client;
}

/** The configuration files of every supported client for this user and, optionally, project dirs. */
export function defaultCandidates(projectDirs: string[], env: NodeJS.ProcessEnv = process.env): Candidate[] {
  const home = env.HOME || env.USERPROFILE || homedir();
  const os = platform();
  const appData = env.APPDATA || join(home, "AppData", "Roaming");
  const userConfig =
    os === "darwin" ? join(home, "Library", "Application Support") : os === "win32" ? appData : env.XDG_CONFIG_HOME || join(home, ".config");
  const codexHome = env.CODEX_HOME || join(home, ".codex");
  const candidates: Candidate[] = [
    { path: join(home, ".claude.json"), client: "claude-code" },
    { path: join(home, ".claude", "settings.json"), client: "claude-code" },
    { path: join(userConfig, "Claude", "claude_desktop_config.json"), client: "claude-desktop" },
    { path: join(home, ".cursor", "mcp.json"), client: "cursor" },
    { path: join(codexHome, "config.toml"), client: "codex" },
    { path: join(home, ".gemini", "settings.json"), client: "gemini-cli" },
    { path: join(home, ".codeium", "windsurf", "mcp_config.json"), client: "windsurf" },
    { path: join(userConfig, "Code", "User", "mcp.json"), client: "vscode" },
    { path: join(userConfig, "Code", "User", "settings.json"), client: "vscode" },
    {
      path: join(userConfig, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      client: "cline",
    },
  ];
  candidates.push(...projectCandidates(projectDirs));
  return candidates;
}

/** The MCP files a project folder can carry, for every client that reads them from the project. */
export function projectCandidates(projectDirs: string[]): Candidate[] {
  const candidates: Candidate[] = [];
  for (const dir of projectDirs) {
    const root = resolve(dir);
    candidates.push(
      { path: join(root, ".mcp.json"), client: "claude-code" },
      { path: join(root, ".claude", "settings.json"), client: "claude-code" },
      { path: join(root, ".claude", "settings.local.json"), client: "claude-code" },
      { path: join(root, ".cursor", "mcp.json"), client: "cursor" },
      { path: join(root, ".vscode", "mcp.json"), client: "vscode" },
      { path: join(root, ".gemini", "settings.json"), client: "gemini-cli" },
    );
  }
  return candidates;
}

/** A file named on the command line: its client is guessed from its name and location. */
export function candidateForPath(path: string): Candidate {
  const absolute = resolve(path);
  const name = basename(absolute);
  if (name.endsWith(".toml")) return { path: absolute, client: "codex" };
  if (name === "claude_desktop_config.json") return { path: absolute, client: "claude-desktop" };
  if (name === ".claude.json" || absolute.includes(`${join(".claude", "")}`)) return { path: absolute, client: "claude-code" };
  if (absolute.includes(join(".cursor", ""))) return { path: absolute, client: "cursor" };
  if (absolute.includes(join(".gemini", ""))) return { path: absolute, client: "gemini-cli" };
  if (absolute.includes(join(".vscode", "")) || /[\\/]Code(?: - Insiders)?[\\/]User[\\/]/.test(absolute)) return { path: absolute, client: "vscode" };
  if (name === "mcp_config.json") return { path: absolute, client: "windsurf" };
  if (name === "cline_mcp_settings.json") return { path: absolute, client: "cline" };
  return { path: absolute, client: "generic" };
}

export function loadConfigs(candidates: Candidate[]): ConfigFile[] {
  const seen = new Set<string>();
  const files: ConfigFile[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.path) || !existsSync(candidate.path)) continue;
    seen.add(candidate.path);
    files.push(loadConfig(candidate));
  }
  return files;
}

export function loadConfig(candidate: Candidate): ConfigFile {
  const file: ConfigFile = { path: candidate.path, client: candidate.client, servers: [], permissions: [] };
  try {
    const stat = statSync(candidate.path);
    if (!stat.isFile()) {
      file.error = "not a regular file";
      return file;
    }
    if (stat.size > 16 * 1024 * 1024) {
      file.error = "larger than 16 MiB, skipped";
      return file;
    }
    if (platform() !== "win32") file.mode = stat.mode & 0o777;
    const text = readFileSync(candidate.path, "utf8");
    if (candidate.client === "codex") {
      readCodex(parseToml(text), file);
    } else {
      readJson(JSON.parse(stripJsonc(text)) as unknown, file);
    }
  } catch (error) {
    file.error = error instanceof Error ? error.message : String(error);
  }
  return file;
}

function readJson(document: unknown, file: ConfigFile): void {
  if (!isObject(document)) return;
  const servers = (pointer: string, value: unknown) => {
    if (!isObject(value)) return;
    for (const [name, definition] of Object.entries(value)) {
      const server = normalize(name, definition, file, `${pointer}/${escapePointer(name)}`);
      if (server) file.servers.push(server);
    }
  };
  servers("/mcpServers", document.mcpServers);
  // VS Code: mcp.json {"servers": {...}} and settings.json {"mcp": {"servers": {...}}}.
  if (file.client === "vscode") {
    servers("/servers", document.servers);
    if (isObject(document.mcp)) servers("/mcp/servers", document.mcp.servers);
  }
  // Claude Code keeps per-project servers inside ~/.claude.json.
  if (isObject(document.projects)) {
    for (const [project, settings] of Object.entries(document.projects)) {
      if (isObject(settings)) servers(`/projects/${escapePointer(project)}/mcpServers`, settings.mcpServers);
    }
  }
  // Claude Code settings: permission rules that let MCP tools run without asking.
  if (isObject(document.permissions) && Array.isArray(document.permissions.allow)) {
    document.permissions.allow.forEach((rule, index) => {
      if (typeof rule === "string" && rule.startsWith("mcp__")) {
        file.permissions.push({ client: file.client, file: file.path, pointer: `/permissions/allow/${index}`, rule });
      }
    });
  }
  if (document.enableAllProjectMcpServers === true) {
    file.permissions.push({ client: file.client, file: file.path, pointer: "/enableAllProjectMcpServers", rule: "enableAllProjectMcpServers" });
  }
}

function readCodex(document: TomlTable, file: ConfigFile): void {
  const table = document.mcp_servers;
  if (!isObject(table)) return;
  for (const [name, definition] of Object.entries(table)) {
    if (!isObject(definition)) continue;
    const adapted: Record<string, unknown> = { ...definition };
    if (isObject(definition.http_headers)) adapted.headers = definition.http_headers;
    const server = normalize(name, adapted, file, `/mcp_servers/${escapePointer(name)}`);
    if (server) file.servers.push(server);
  }
}

function normalize(name: string, value: unknown, file: ConfigFile, pointer: string): ServerDefinition | null {
  if (!isObject(value)) return null;
  const url = firstString(value.url, value.serverUrl, value.httpUrl);
  const command = typeof value.command === "string" ? value.command : undefined;
  if (!url && !command) return null;
  const autoApproved = [...stringList(value.autoApprove), ...stringList(value.alwaysAllow)];
  const server: ServerDefinition = {
    name,
    client: file.client,
    file: file.path,
    pointer,
    transport: command ? "stdio" : "remote",
    args: stringList(value.args),
    env: stringMap(value.env),
    headers: stringMap(value.headers),
    autoApproved,
    trusted: value.trust === true,
  };
  if (command) server.command = command;
  if (url) server.url = url;
  return server;
}

/** Removes // and /* *\/ comments and trailing commas outside strings (JSONC, used by VS Code). */
export function stripJsonc(text: string): string {
  let out = "";
  let inString = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index] as string;
    const next = text[index + 1];
    if (inString) {
      out += char;
      if (char === "\\") {
        out += next ?? "";
        index++;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }
    if (char === '"') {
      inString = true;
      out += char;
    } else if (char === "/" && next === "/") {
      while (index < text.length && text[index] !== "\n") index++;
      out += "\n";
    } else if (char === "/" && next === "*") {
      index += 2;
      while (index < text.length && !(text[index] === "*" && text[index + 1] === "/")) index++;
      index++;
    } else if (char === ",") {
      // A trailing comma: the next significant character, past spaces and comments, closes the
      // object or array.
      const ahead = nextSignificant(text, index + 1);
      if (text[ahead] !== "}" && text[ahead] !== "]") out += char;
    } else {
      out += char;
    }
  }
  return out;
}

function nextSignificant(text: string, start: number): number {
  let index = start;
  while (index < text.length) {
    if (/\s/.test(text[index] as string)) index++;
    else if (text[index] === "/" && text[index + 1] === "/") {
      while (index < text.length && text[index] !== "\n") index++;
    } else if (text[index] === "/" && text[index + 1] === "*") {
      const end = text.indexOf("*/", index + 2);
      index = end < 0 ? text.length : end + 2;
    } else break;
  }
  return index;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stringMap(value: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!isObject(value)) return result;
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string") result[key] = item;
    else if (typeof item === "number" || typeof item === "boolean") result[key] = String(item);
  }
  return result;
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function escapePointer(segment: string): string {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

export type { Candidate, ClientPermission };
