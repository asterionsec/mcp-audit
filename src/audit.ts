// Runs the audit end to end: find the configuration files, read them, apply the rules and sort the
// findings so the output is the same for the same input.

import { candidateForPath, defaultCandidates, loadConfigs } from "./discover.js";
import { auditConfig } from "./rules.js";
import type { ConfigFile, Finding } from "./types.js";
import { severityRank } from "./types.js";

export interface AuditOptions {
  /** Files named explicitly. When present, the default locations are not read unless includeDefaults. */
  paths: string[];
  /** Project directories whose .mcp.json, .cursor, .vscode, .gemini and .claude settings are read. */
  projectDirs: string[];
  includeDefaults: boolean;
  env?: NodeJS.ProcessEnv;
  home?: string;
}

export interface AuditResult {
  files: ConfigFile[];
  findings: Finding[];
}

export function runAudit(options: AuditOptions): AuditResult {
  const candidates = [
    ...(options.includeDefaults ? defaultCandidates(options.projectDirs, options.env) : []),
    ...options.paths.map(candidateForPath),
  ];
  const files = loadConfigs(candidates);
  const findings = files.flatMap((file) => auditConfig(file, options.home));
  return { files, findings: sortFindings(findings) };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.file.localeCompare(b.file) ||
      (a.server ?? "").localeCompare(b.server ?? "") ||
      a.rule.localeCompare(b.rule) ||
      a.pointer.localeCompare(b.pointer),
  );
}
