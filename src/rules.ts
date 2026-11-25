// The static rules. Each one looks at what a client would run or connect to and reports a concrete,
// fixable risk. They read configuration only; nothing is started or contacted.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { findNamedSecret, findSecret, redact } from "./secrets.js";
import type { ConfigFile, Finding, ServerDefinition, Severity } from "./types.js";

export interface RuleInfo {
  id: string;
  title: string;
  severity: Severity;
  description: string;
}

/** Every rule the tool can report, for --list-rules, SARIF and the documentation. */
export const RULES: readonly RuleInfo[] = [
  { id: "MCP-PIN-001", title: "Server package is not pinned to an exact version", severity: "medium", description: "The client downloads and runs whatever version the registry serves at each start (npx, bunx, uvx, pipx, dlx or a mutable container tag). A compromised or hijacked release then runs with the server's access." },
  { id: "MCP-PIN-002", title: "Server runs code from a git branch or URL", severity: "high", description: "The server is fetched from a git repository or a URL without a commit hash, so whoever controls that branch decides what runs." },
  { id: "MCP-SEC-001", title: "Credential stored in plain text", severity: "high", description: "An API key, token or password is written in the configuration file. Anyone or anything that can read the file can use it." },
  { id: "MCP-NET-001", title: "Remote server over an unencrypted connection", severity: "high", description: "The client talks to a non-local server over http:// or ws://, so tool calls, results and any credentials travel unencrypted." },
  { id: "MCP-FS-001", title: "Filesystem server can reach the whole disk or home directory", severity: "high", description: "A filesystem server is given the root of the disk or the home directory, which includes SSH keys, cloud credentials and every project." },
  { id: "MCP-DOCKER-001", title: "Container started with host-level access", severity: "high", description: "The server's container runs privileged, mounts the Docker socket or the host root, or shares the host's network or process namespace, which removes the isolation the container was meant to give." },
  { id: "MCP-EXEC-001", title: "Server is installed by piping a download into a shell", severity: "high", description: "The launch command downloads a script and runs it at every start, so the content of that URL is executed with your user's permissions." },
  { id: "MCP-APPROVE-001", title: "Server tools run without asking", severity: "medium", description: "The client is set to run some or all of this server's tools without confirmation, so an injected instruction can make the agent use them silently." },
  { id: "MCP-APPROVE-002", title: "Permission rule allows a whole MCP server", severity: "medium", description: "A permission rule lets every tool of a server (or of every server) run without asking." },
  { id: "MCP-APPROVE-003", title: "Project MCP servers start without approval", severity: "medium", description: "enableAllProjectMcpServers starts every server declared in a project's .mcp.json, including repositories you just cloned, without asking first." },
  { id: "MCP-FILE-001", title: "Configuration file is writable by other users", severity: "medium", description: "Another account on this machine can add or change MCP servers, which the client will start with your permissions." },
  { id: "MCP-FILE-002", title: "File with credentials is readable by other users", severity: "medium", description: "The configuration file contains a plain-text credential and its permissions let other accounts on this machine read it." },
  { id: "MCP-TOOL-001", title: "Hidden characters in a tool's name, description or schema", severity: "high", description: "Zero-width, bidirectional or Unicode tag characters can carry instructions the model reads and the user never sees." },
  { id: "MCP-TOOL-002", title: "Tool description contains instructions aimed at the model", severity: "high", description: "The description tells the model to hide things from the user, ignore other instructions or read sensitive files: the pattern of tool poisoning." },
  { id: "MCP-TOOL-003", title: "Two servers expose a tool with the same name", severity: "medium", description: "A tool name used by two servers lets one shadow the other, so the agent may call a different implementation than the one you expect." },
  { id: "MCP-READ-001", title: "Configuration file could not be read", severity: "info", description: "The file exists but is not valid for its format, so its servers were not audited." },
];

const RULE_BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));

export function finding(id: string, server: ServerDefinition | null, file: ConfigFile, pointer: string, detail: string, fix: string, severity?: Severity): Finding {
  const rule = RULE_BY_ID.get(id);
  if (!rule) throw new Error(`unknown rule ${id}`);
  const result: Finding = {
    rule: id,
    severity: severity ?? rule.severity,
    title: rule.title,
    // Details quote commands and URLs; anything that looks like a credential is masked here too.
    detail: redact(detail),
    fix,
    file: file.path,
    pointer,
    client: file.client,
  };
  if (server) result.server = server.name;
  return result;
}

export function auditConfig(file: ConfigFile, home = homedir()): Finding[] {
  const findings: Finding[] = [];
  if (file.error) {
    findings.push(finding("MCP-READ-001", null, file, "", `Could not parse the file: ${file.error}.`, "Fix the syntax error; until then this client ignores or rejects the file."));
    return findings;
  }
  let hasSecret = false;
  for (const server of file.servers) {
    const serverFindings = [
      ...pinning(server, file),
      ...secrets(server, file, home),
      ...transport(server, file),
      ...filesystem(server, file, home),
      ...container(server, file, home),
      ...shellBootstrap(server, file),
      ...approval(server, file),
    ];
    if (serverFindings.some((item) => item.rule === "MCP-SEC-001")) hasSecret = true;
    findings.push(...serverFindings);
  }
  for (const permission of file.permissions) {
    if (permission.rule === "enableAllProjectMcpServers") {
      findings.push(finding("MCP-APPROVE-003", null, file, permission.pointer, "enableAllProjectMcpServers is true.", "Remove it and approve project servers one by one, or list them in enabledMcpjsonServers."));
      continue;
    }
    const parts = permission.rule.split("__");
    const wholeServer = parts.length === 2 || (parts.length === 3 && (parts[2] === "*" || parts[2] === ""));
    if (permission.rule === "mcp__*" || permission.rule === "mcp__") {
      findings.push(finding("MCP-APPROVE-002", null, file, permission.pointer, `"${permission.rule}" lets every tool of every MCP server run without asking.`, "Allow specific read-only tools instead, e.g. mcp__github__get_issue.", "high"));
    } else if (wholeServer) {
      findings.push(finding("MCP-APPROVE-002", null, file, permission.pointer, `"${permission.rule}" lets every tool of the "${parts[1]}" server run without asking.`, `Allow only the tools you need, e.g. mcp__${parts[1]}__<tool>.`));
    }
  }
  if (file.mode !== undefined) {
    if (file.mode & 0o022) {
      findings.push(finding("MCP-FILE-001", null, file, "", `Permissions are ${octal(file.mode)}.`, `chmod 600 "${file.path}"`));
    } else if (hasSecret && file.mode & 0o044) {
      findings.push(finding("MCP-FILE-002", null, file, "", `Permissions are ${octal(file.mode)} and the file holds a plain-text credential.`, `chmod 600 "${file.path}", and move the credential out of the file.`));
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------------------------------
// Version pinning

const SEMVER_EXACT = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const GIT_SHA = /^[0-9a-f]{40}$/i;

function pinning(server: ServerDefinition, file: ConfigFile): Finding[] {
  if (!server.command) return [];
  const launcher = commandName(server.command);
  const args = server.args;
  let spec: string | undefined;
  let kind: "npm" | "python" | "container" | undefined;
  if (["npx", "bunx", "pnpx"].includes(launcher)) {
    spec = firstPackage(args, ["-p", "--package"]);
    const fromFlag = flagValue(args, ["-p", "--package"]);
    if (fromFlag) spec = fromFlag;
    kind = "npm";
  } else if (["pnpm", "yarn", "bun"].includes(launcher) && ["dlx", "x"].includes(args[0] ?? "")) {
    spec = firstPackage(args.slice(1), ["-p", "--package"]);
    kind = "npm";
  } else if (launcher === "uvx" || (launcher === "uv" && args[0] === "tool" && args[1] === "run")) {
    const rest = launcher === "uv" ? args.slice(2) : args;
    spec = flagValue(rest, ["--from"]) ?? firstPackage(rest, ["--with", "--python", "-p"]);
    kind = "python";
  } else if (launcher === "pipx" && args[0] === "run") {
    spec = flagValue(args.slice(1), ["--spec"]) ?? firstPackage(args.slice(1), []);
    kind = "python";
  } else if ((launcher === "docker" || launcher === "podman") && args.includes("run")) {
    spec = containerImage(args);
    kind = "container";
  }
  if (!spec || !kind) return [];
  const pointer = `${server.pointer}/args`;
  if (/^(?:git\+|github:|gitlab:|bitbucket:|https?:\/\/|git:\/\/)/i.test(spec) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec) && kind === "npm" && !spec.startsWith("@")) {
    const ref = spec.split("#")[1] ?? "";
    if (GIT_SHA.test(ref.replace(/^commit=/, ""))) return [];
    return [finding("MCP-PIN-002", server, file, pointer, `"${server.name}" runs ${spec}.`, "Pin the source to a full commit hash (…#<40-char sha>) or install a published, pinned release.")];
  }
  if (kind === "npm") {
    const version = npmVersion(spec);
    if (version && SEMVER_EXACT.test(version)) return [];
    const what = version ? `version "${version}", which can change` : "no version";
    return [finding("MCP-PIN-001", server, file, pointer, `"${server.name}" runs ${spec} with ${what}.`, `Pin an exact version: ${npmName(spec)}@<x.y.z>. Update it deliberately after reviewing the release.`)];
  }
  if (kind === "python") {
    if (/==\s*\d+(?:\.\d+)*(?:[a-z0-9.+-]*)?$/i.test(spec) || /@\s*https?:\/\/.*#sha256=/i.test(spec)) return [];
    return [finding("MCP-PIN-001", server, file, pointer, `"${server.name}" runs ${spec} with no exact version.`, `Pin it: ${spec.split(/[<>=!~ ]/)[0]}==<x.y.z>.`)];
  }
  // Container image: a digest is immutable; a tag can be moved.
  if (spec.includes("@sha256:")) return [];
  const tag = spec.includes(":") && !spec.endsWith(":") ? spec.slice(spec.lastIndexOf(":") + 1) : "";
  if (!tag || tag === "latest" || tag.includes("/")) {
    return [finding("MCP-PIN-001", server, file, pointer, `"${server.name}" runs the image ${spec} without a fixed tag.`, "Pin the image by digest: image@sha256:<digest>.")];
  }
  return [finding("MCP-PIN-001", server, file, pointer, `"${server.name}" runs the image ${spec}; the tag "${tag}" can be moved to another image.`, "Pin the image by digest: image@sha256:<digest>.", "low")];
}

function firstPackage(args: string[], valueFlags: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] as string;
    if (valueFlags.includes(arg)) {
      index++;
      continue;
    }
    if (arg === "--") return args[index + 1];
    if (arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

function flagValue(args: string[], flags: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] as string;
    for (const flag of flags) {
      if (arg === flag) return args[index + 1];
      if (arg.startsWith(`${flag}=`)) return arg.slice(flag.length + 1);
    }
  }
  return undefined;
}

function npmName(spec: string): string {
  const at = spec.lastIndexOf("@");
  return at > 0 ? spec.slice(0, at) : spec;
}

function npmVersion(spec: string): string | undefined {
  const at = spec.lastIndexOf("@");
  return at > 0 ? spec.slice(at + 1) : undefined;
}

function containerImage(args: string[]): string | undefined {
  const start = args.indexOf("run") + 1;
  const valueFlags = new Set(["-e", "--env", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "--platform", "--pid", "--cap-add", "--cap-drop", "--security-opt", "-l", "--label", "--add-host", "--memory", "-m", "--cpus", "--restart", "--pull", "--hostname", "-h", "--device", "--tmpfs", "--ulimit", "--log-driver", "--ipc", "--uts", "--runtime"]);
  for (let index = start; index < args.length; index++) {
    const arg = args[index] as string;
    if (valueFlags.has(arg)) {
      index++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------------
// Secrets

function secrets(server: ServerDefinition, file: ConfigFile, home: string): Finding[] {
  const found: { where: string; pointer: string; kind: string; masked: string }[] = [];
  for (const [name, value] of Object.entries(server.env)) {
    const match = findNamedSecret(name, value);
    if (match) found.push({ where: `env ${name}`, pointer: `${server.pointer}/env/${name}`, ...match });
  }
  for (const [name, value] of Object.entries(server.headers)) {
    const match = findNamedSecret(name, value);
    if (match) found.push({ where: `header ${name}`, pointer: `${server.pointer}/headers/${name}`, ...match });
  }
  server.args.forEach((arg, index) => {
    const pointer = `${server.pointer}/args/${index}`;
    const inline = /^--?([A-Za-z][\w-]*)=(.+)$/.exec(arg);
    const previous = server.args[index - 1];
    const flag = previous && /^--?[A-Za-z][\w-]*$/.test(previous) ? previous.replace(/^-+/, "") : undefined;
    const match = inline ? findNamedSecret(inline[1] as string, inline[2] as string) : flag ? findNamedSecret(flag, arg) : findSecret(arg);
    if (match) found.push({ where: `argument ${index}`, pointer, ...match });
  });
  if (server.url) {
    const direct = findSecret(server.url);
    if (direct) found.push({ where: "url", pointer: `${server.pointer}/url`, ...direct });
    else {
      try {
        const url = new URL(server.url);
        for (const [name, value] of url.searchParams) {
          const match = findNamedSecret(name, value);
          if (match) found.push({ where: `url parameter ${name}`, pointer: `${server.pointer}/url`, ...match });
        }
      } catch {
        // Not a URL the platform can parse; the transport rule reports nothing either.
      }
    }
  }
  if (!found.length) return [];
  const shared = insideRepository(file.path, home);
  return found.map((item) =>
    finding(
      "MCP-SEC-001",
      server,
      file,
      item.pointer,
      `"${server.name}" has a ${item.kind} in its ${item.where}: ${item.masked}.${shared ? " The file is inside a git repository, so it can be committed and shared." : ""}`,
      shared
        ? "Remove it from the file, rotate it, and reference an environment variable instead (${VAR} in Claude Code and VS Code, ${env:VAR} in Cursor)."
        : "Rotate it if the file was ever shared or synced, keep the file private (chmod 600), and prefer an environment variable or the system keychain where the client supports it.",
      shared ? "high" : "medium",
    ),
  );
}

function insideRepository(path: string, home: string): boolean {
  let current = dirname(path);
  for (let depth = 0; depth < 8; depth++) {
    if (current === home || current === dirname(current)) return false;
    if (existsSync(join(current, ".git"))) return true;
    current = dirname(current);
  }
  return false;
}

// ---------------------------------------------------------------------------------------------------
// Transport

function transport(server: ServerDefinition, file: ConfigFile): Finding[] {
  if (!server.url) return [];
  let url: URL;
  try {
    url = new URL(server.url);
  } catch {
    return [];
  }
  if (url.protocol !== "http:" && url.protocol !== "ws:") return [];
  if (isLoopback(url.hostname)) return [];
  return [finding("MCP-NET-001", server, file, `${server.pointer}/url`, `"${server.name}" connects to ${url.protocol}//${url.host}.`, `Use ${url.protocol === "ws:" ? "wss" : "https"}:// for this server.`)];
}

function isLoopback(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, "").toLowerCase();
  return bare === "localhost" || bare.endsWith(".localhost") || bare === "::1" || /^127\.\d+\.\d+\.\d+$/.test(bare);
}

// ---------------------------------------------------------------------------------------------------
// Filesystem reach

function filesystem(server: ServerDefinition, file: ConfigFile, home: string): Finding[] {
  const launch = [server.command ?? "", ...server.args].join(" ").toLowerCase();
  const filesystemServer = /server-filesystem|mcp-server-filesystem|filesystem-mcp|mcp-filesystem|\bfilesystem\b/.test(launch) || /^(?:fs|filesystem|files?)$/i.test(server.name);
  if (!filesystemServer) return [];
  const broad = server.args.filter((arg) => isBroadPath(arg, home));
  if (!broad.length) return [];
  return [finding("MCP-FS-001", server, file, `${server.pointer}/args`, `"${server.name}" is given ${broad.map((path) => `"${path}"`).join(", ")}.`, "Give it only the project folders it needs, never the disk root or your home directory.")];
}

function isBroadPath(arg: string, home: string): boolean {
  const value = arg.replace(/[\\/]+$/, "") || arg;
  if (["/", "~", "$HOME", "${HOME}", "%USERPROFILE%", "/Users", "/home", "/root"].includes(value)) return true;
  if (/^[A-Za-z]:\\?$/.test(value) || /^[A-Za-z]:\\Users$/i.test(value)) return true;
  return value === home.replace(/[\\/]+$/, "");
}

// ---------------------------------------------------------------------------------------------------
// Containers

function container(server: ServerDefinition, file: ConfigFile, home: string): Finding[] {
  if (!server.command || !["docker", "podman"].includes(commandName(server.command)) || !server.args.includes("run")) return [];
  const problems: string[] = [];
  const args = server.args;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] as string;
    const next = args[index + 1] ?? "";
    const [flag, inline] = arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, undefined];
    const value = inline ?? next;
    if (flag === "--privileged") problems.push("--privileged");
    if ((flag === "--network" || flag === "--net") && value === "host") problems.push("--network host");
    if (flag === "--pid" && value === "host") problems.push("--pid host");
    if (flag === "--ipc" && value === "host") problems.push("--ipc host");
    if (flag === "--cap-add" && /^(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN)$/i.test(value)) problems.push(`--cap-add ${value}`);
    if (flag === "--security-opt" && /(?:seccomp|apparmor)=unconfined/i.test(value)) problems.push(`--security-opt ${value}`);
    if (flag === "-v" || flag === "--volume" || flag === "--mount") {
      const source = flag === "--mount" ? (/(?:source|src)=([^,]+)/.exec(value)?.[1] ?? "") : (value.split(":")[0] ?? "");
      if (/docker\.sock$/.test(source)) problems.push(`mounts the Docker socket (${source})`);
      else if (isBroadPath(source, home)) problems.push(`mounts ${source}`);
    }
  }
  if (!problems.length) return [];
  return [finding("MCP-DOCKER-001", server, file, `${server.pointer}/args`, `"${server.name}" container: ${problems.join(", ")}.`, "Drop these options and mount only the folders the server needs, read-only when it only reads.")];
}

// ---------------------------------------------------------------------------------------------------
// Shell bootstrap

function shellBootstrap(server: ServerDefinition, file: ConfigFile): Finding[] {
  if (!server.command) return [];
  const shell = commandName(server.command);
  if (!["sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"].includes(shell)) return [];
  const script = server.args.join(" ");
  const fetches = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i.test(script);
  const executes = /\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b|\beval\b/i.test(script);
  if (!fetches || !executes) return [];
  return [finding("MCP-EXEC-001", server, file, `${server.pointer}/args`, `"${server.name}" starts with: ${shortened(script)}.`, "Install a pinned release once and run it directly; do not execute a download at every start.")];
}

// ---------------------------------------------------------------------------------------------------
// Auto-approval

function approval(server: ServerDefinition, file: ConfigFile): Finding[] {
  const findings: Finding[] = [];
  if (server.trusted) {
    findings.push(finding("MCP-APPROVE-001", server, file, `${server.pointer}/trust`, `"${server.name}" has trust: true, so every tool call runs without confirmation.`, "Remove \"trust\": true and confirm tool calls, at least for tools that write or send data."));
  }
  if (server.autoApproved.length) {
    const all = server.autoApproved.includes("*");
    findings.push(
      finding(
        "MCP-APPROVE-001",
        server,
        file,
        `${server.pointer}/autoApprove`,
        all ? `"${server.name}" auto-approves every tool.` : `"${server.name}" auto-approves ${server.autoApproved.map((tool) => `"${tool}"`).join(", ")}.`,
        "Auto-approve only tools that read and cannot send data out; confirm the rest.",
        all ? "high" : "medium",
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------------------------------

function commandName(command: string): string {
  // The last path segment, with / or \ as separator (a Windows path read on any platform), then its
  // first word, for configurations that put "npx -y" in the command itself.
  const last = command.trim().split(/[\\/]/).pop() ?? "";
  return (last.split(/\s+/)[0] ?? "").replace(/\.(?:cmd|exe|bat|ps1)$/i, "").toLowerCase();
}

function shortened(text: string): string {
  return text.length > 120 ? `${text.slice(0, 117)}…` : text;
}

function octal(mode: number): string {
  return `0${mode.toString(8).padStart(3, "0")}`;
}
