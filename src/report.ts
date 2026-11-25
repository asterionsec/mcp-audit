// Output formats: a readable report for a terminal, JSON for scripts and SARIF 2.1.0 for code
// scanning (GitHub, GitLab, IDEs). All three carry the same findings, already masked.

import { RULES } from "./rules.js";
import type { ConfigFile, Finding, Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

export const TOOL_NAME = "mcp-audit";
export const TOOL_VERSION = "0.1.0";
export const TOOL_URL = "https://asterionsec.com/en/tools/mcp-audit";

const LABEL: Record<Severity, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

export function textReport(files: ConfigFile[], findings: Finding[], color: boolean): string {
  const paint = (code: string, text: string) => (color ? `\u001b[${code}m${text}\u001b[0m` : text);
  const tint: Record<Severity, string> = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };
  const lines: string[] = [];
  const servers = files.reduce((total, file) => total + file.servers.length, 0);
  lines.push(paint("1", `mcp-audit ${TOOL_VERSION}`) + `: ${files.length} configuration file${files.length === 1 ? "" : "s"}, ${servers} MCP server${servers === 1 ? "" : "s"}`);
  for (const file of files) {
    const note = file.error ? paint("33", "  (could not be parsed)") : "";
    lines.push(paint("2", `  ${file.path}  [${file.client}, ${file.servers.length} server${file.servers.length === 1 ? "" : "s"}]`) + note);
  }
  lines.push("");
  if (!findings.length) {
    lines.push(paint("32", "No findings."));
    return lines.join("\n") + "\n";
  }
  for (const item of findings) {
    lines.push(`${paint(tint[item.severity], LABEL[item.severity].padEnd(8))} ${paint("1", item.rule)}  ${item.title}`);
    lines.push(`         ${item.detail}`);
    lines.push(`         ${paint("2", "Fix:")} ${item.fix}`);
    lines.push(paint("2", `         ${item.file}${item.pointer ? `  ${item.pointer}` : ""}`));
    lines.push("");
  }
  lines.push(summaryLine(findings));
  return lines.join("\n") + "\n";
}

export function summaryLine(findings: Finding[]): string {
  const counts = SEVERITY_ORDER.map((severity) => [severity, findings.filter((item) => item.severity === severity).length] as const).filter(([, count]) => count > 0);
  return `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${counts.map(([severity, count]) => `${count} ${severity}`).join(", ")}.`;
}

export function jsonReport(files: ConfigFile[], findings: Finding[]): string {
  return (
    JSON.stringify(
      {
        tool: { name: TOOL_NAME, version: TOOL_VERSION, url: TOOL_URL },
        files: files.map((file) => ({ path: file.path, client: file.client, servers: file.servers.length, ...(file.error ? { error: file.error } : {}) })),
        findings,
      },
      null,
      2,
    ) + "\n"
  );
}

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

export function sarifReport(findings: Finding[], baseDir: string): string {
  const relative = (path: string) => (path.startsWith(baseDir + "/") ? path.slice(baseDir.length + 1) : path);
  return (
    JSON.stringify(
      {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
          {
            tool: {
              driver: {
                name: TOOL_NAME,
                version: TOOL_VERSION,
                informationUri: TOOL_URL,
                rules: RULES.map((rule) => ({
                  id: rule.id,
                  name: rule.id.replace(/-/g, ""),
                  shortDescription: { text: rule.title },
                  fullDescription: { text: rule.description },
                  helpUri: `${TOOL_URL}#${rule.id.toLowerCase()}`,
                  defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
                  properties: { tags: ["security", "mcp"], "security-severity": SECURITY_SEVERITY[rule.severity] },
                })),
              },
            },
            results: findings.map((item) => ({
              ruleId: item.rule,
              level: SARIF_LEVEL[item.severity],
              message: { text: `${item.detail} Fix: ${item.fix}` },
              locations: [
                {
                  physicalLocation: { artifactLocation: { uri: relative(item.file) } },
                  logicalLocations: item.pointer ? [{ fullyQualifiedName: item.pointer }] : [],
                },
              ],
              properties: { severity: item.severity, client: item.client, ...(item.server ? { server: item.server } : {}) },
            })),
          },
        ],
      },
      null,
      2,
    ) + "\n"
  );
}
