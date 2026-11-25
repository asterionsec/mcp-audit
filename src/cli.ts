#!/usr/bin/env node
// mcp-audit command line. Exit codes: 0 no finding at or above --fail-on, 1 at least one, 2 usage
// or runtime error.

import { runAudit, sortFindings } from "./audit.js";
import { startServer } from "./mcp-server.js";
import { auditTools, probeServers } from "./probe.js";
import { jsonReport, sarifReport, textReport, TOOL_URL, TOOL_VERSION } from "./report.js";
import { RULES } from "./rules.js";
import type { Severity } from "./types.js";
import { SEVERITY_ORDER, severityRank } from "./types.js";

const HELP = `mcp-audit ${TOOL_VERSION}: audit MCP server configurations for security risks.

Usage:
  mcp-audit [options] [config files...]

With no files, reads every supported client's configuration for this user
(Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf, Cline)
and the project files in the current folder.

Options:
  --project <dir>     Also read a project's .mcp.json, .cursor, .vscode, .gemini, .claude (repeatable)
  --no-defaults       Read only the files and projects given
  --format <f>        text (default), json or sarif
  --json, --sarif     Shortcuts for --format
  --fail-on <sev>     Exit 1 when a finding is at or above: critical, high (default), medium, low, info, none
  --probe             Start local stdio servers to read their tool descriptions (runs their code)
  --list-rules        Print the rules and exit
  --mcp               Run as an MCP server over stdio
  --no-color          Plain text output
  -v, --version       Print the version
  -h, --help          Print this help

Nothing leaves your machine. Credentials are shown masked. ${TOOL_URL}
`;

interface Options {
  paths: string[];
  projects: string[];
  defaults: boolean;
  format: "text" | "json" | "sarif";
  failOn: Severity | "none";
  probe: boolean;
  color: boolean;
}

function parse(argv: string[]): Options | "help" | "version" | "rules" | "mcp" {
  const options: Options = { paths: [], projects: [], defaults: true, format: "text", failOn: "high", probe: false, color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index] as string;
    const value = () => {
      const next = argv[++index];
      if (next === undefined || next.startsWith("--")) throw new UsageError(`${arg} needs a value`);
      return next;
    };
    switch (arg) {
      case "-h":
      case "--help":
        return "help";
      case "-v":
      case "--version":
        return "version";
      case "--list-rules":
        return "rules";
      case "--mcp":
        return "mcp";
      case "--project":
        options.projects.push(value());
        break;
      case "--no-defaults":
        options.defaults = false;
        break;
      case "--json":
        options.format = "json";
        break;
      case "--sarif":
        options.format = "sarif";
        break;
      case "--format": {
        const format = value();
        if (format !== "text" && format !== "json" && format !== "sarif") throw new UsageError(`unknown format ${format}`);
        options.format = format;
        break;
      }
      case "--fail-on": {
        const level = value();
        if (level !== "none" && !SEVERITY_ORDER.includes(level as Severity)) throw new UsageError(`unknown severity ${level}`);
        options.failOn = level as Severity | "none";
        break;
      }
      case "--probe":
        options.probe = true;
        break;
      case "--no-color":
        options.color = false;
        break;
      default:
        if (arg.startsWith("-")) throw new UsageError(`unknown option ${arg}`);
        options.paths.push(arg);
    }
  }
  // Files named on the command line are audited on their own, without the default locations.
  if (options.paths.length) options.defaults = false;
  return options;
}

class UsageError extends Error {}

async function main(): Promise<number> {
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`mcp-audit: ${error instanceof Error ? error.message : String(error)}\nRun mcp-audit --help for usage.\n`);
    return 2;
  }
  if (parsed === "help") {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed === "version") {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (parsed === "rules") {
    for (const rule of RULES) process.stdout.write(`${rule.id.padEnd(16)} ${rule.severity.padEnd(8)} ${rule.title}\n`);
    return 0;
  }
  if (parsed === "mcp") {
    startServer();
    return -1;
  }
  const projects = parsed.projects.length || parsed.paths.length ? parsed.projects : [process.cwd()];
  const result = runAudit({ paths: parsed.paths, projectDirs: projects, includeDefaults: parsed.defaults });
  let findings = result.findings;
  if (parsed.probe) {
    process.stderr.write("mcp-audit: --probe starts each local stdio server to read its tool list; remote servers are not contacted.\n");
    const outcome = await probeServers(result.files);
    findings = sortFindings([...findings, ...auditTools(result.files, outcome.tools)]);
    for (const failure of outcome.failures) process.stderr.write(`mcp-audit: could not list tools of "${failure.server}": ${failure.reason}\n`);
  }
  if (parsed.format === "json") process.stdout.write(jsonReport(result.files, findings));
  else if (parsed.format === "sarif") process.stdout.write(sarifReport(findings, process.cwd()));
  else process.stdout.write(textReport(result.files, findings, parsed.color));
  if (parsed.failOn === "none") return 0;
  const threshold = severityRank(parsed.failOn);
  return findings.some((item) => severityRank(item.severity) <= threshold) ? 1 : 0;
}

main().then(
  (code) => {
    if (code >= 0) process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`mcp-audit: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  },
);

