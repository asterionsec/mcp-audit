#!/usr/bin/env node
// Mutation testing by hand: each mutation disables one control in the source. The test suite must
// fail for every one of them; a mutation that survives means a control nobody checks.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

const TEST_FILES = ["test/rules.test.mjs", "test/formats.test.mjs", "test/runtime.test.mjs"];
const TEST_ARGS = ["--test", "--test-timeout=30000", "--test-force-exit", ...TEST_FILES];

export const MUTATIONS = [
  ["exact versions accepted as pinned", "src/rules.ts", "const SEMVER_EXACT = /^v?\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?$/;", "const SEMVER_EXACT = /^.*$/;"],
  ["git sources without a commit", "src/rules.ts", "if (GIT_SHA.test(ref.replace(/^commit=/, \"\"))) return [];", "return [];"],
  ["python pinning", "src/rules.ts", "if (/==\\s*\\d+(?:\\.\\d+)*(?:[a-z0-9.+-]*)?$/i.test(spec) || /@\\s*https?:\\/\\/.*#sha256=/i.test(spec)) return [];", "return [];"],
  ["container digest", "src/rules.ts", "if (spec.includes(\"@sha256:\")) return [];", "return [];"],
  ["known token formats", "src/secrets.ts", "  { kind: \"GitHub token\",", "  { kind: \"GitHub token\", regex: /$^/ }, { kind: \"x\","],
  ["references are not secrets", "src/secrets.ts", "if (REFERENCE.test(trimmed) || PLACEHOLDER.test(trimmed)) return null;", ""],
  ["masking", "src/secrets.ts", "return `${secret.slice(0, visible)}${\"•\".repeat(6)} (${secret.length} chars)`;", "return secret;"],
  ["repository raises severity", "src/rules.ts", "if (existsSync(join(current, \".git\"))) return true;", ""],
  ["loopback is allowed", "src/rules.ts", "if (isLoopback(url.hostname)) return [];", ""],
  ["broad filesystem paths", "src/rules.ts", "  if ([\"/\", \"~\", \"$HOME\",", "  if (false && [\"/\", \"~\", \"$HOME\","],
  ["privileged containers", "src/rules.ts", "if (flag === \"--privileged\") problems.push(\"--privileged\");", ""],
  ["Docker socket mounts", "src/rules.ts", "if (/docker\\.sock$/.test(source)) problems.push(`mounts the Docker socket (${source})`);", "if (false) {}"],
  ["download piped to a shell", "src/rules.ts", "if (!fetches || !executes) return [];", "return [];"],
  ["trusted servers", "src/rules.ts", "if (server.trusted) {", "if (false) {"],
  ["auto-approve everything is high", "src/rules.ts", "all ? \"high\" : \"medium\",", "\"medium\","],
  ["whole-server permission rules", "src/rules.ts", "const wholeServer = parts.length === 2 ||", "const wholeServer = false &&"],
  ["writable configuration files", "src/rules.ts", "if (file.mode & 0o022) {", "if (false) {"],
  ["readable file with secrets", "src/rules.ts", "} else if (hasSecret && file.mode & 0o044) {", "} else if (false) {"],
  ["unparseable files are reported", "src/rules.ts", "findings.push(finding(\"MCP-READ-001\"", "void (finding(\"MCP-READ-001\""],
  ["hidden characters", "src/probe.ts", "if (HIDDEN.test(text)) {", "if (false) {"],
  ["instructions to hide from the user", "src/probe.ts", "{ label: \"tells the model to hide something from the user\", regex:", "{ label: \"tells the model to hide something from the user\", regex: /$^/, x:"],
  ["shadowed tool names", "src/probe.ts", "if (servers.length < 2) continue;", "continue;"],
  ["probe timeout", "src/probe.ts", "const timer = setTimeout(() => finish(new Error(`no tools/list reply within ${timeoutMs / 1000}s`)), timeoutMs);", "const timer = setTimeout(() => {}, 0);"],
  ["TOML escapes", "src/toml.ts", "value += escapes[next] ?? next;", "value += char + next;"],
  ["JSONC trailing commas before comments", "src/discover.ts", "const ahead = nextSignificant(text, index + 1);", "const ahead = index + 1;"],
  ["MCP tool is read-only", "src/mcp-server.ts", "readOnlyHint: true", "readOnlyHint: false"],
  ["unknown MCP method error", "src/mcp-server.ts", "if (isRequest) fail(message.id, -32601,", "if (false) fail(message.id, -32601,"],
  ["project folders without defaults", "src/audit.ts", "projectCandidates(options.projectDirs)),", "[]),"],
  ["fail-on threshold", "src/cli.ts", "return findings.some((item) => severityRank(item.severity) <= threshold) ? 1 : 0;", "return 0;"],
];


function run(command, args) {
  return spawnSync(command, args, { cwd: root, encoding: "utf8" });
}

// Before a file is mutated its original is saved next to it. A run that dies (killed, crashed)
// leaves the backup behind; the next run restores it before doing anything else.
const BACKUP = ".mutate-original";

function restoreLeftovers() {
  for (const file of new Set(MUTATIONS.map((item) => item[1]))) {
    const path = join(root, file);
    if (existsSync(path + BACKUP)) {
      renameSync(path + BACKUP, path);
      console.error(`restored ${file} from an interrupted run`);
    }
  }
}

function main() {
  restoreLeftovers();
  const dirty = MUTATIONS.filter(([, file, from]) => !readFileSync(join(root, file), "utf8").includes(from)).map(([label]) => label);
  if (dirty.length) {
    console.error(`the sources do not match the mutation list (edited or left mutated): ${dirty.join(", ")}`);
    process.exit(2);
  }
  const baseline = run("npx", ["tsc", "-p", "tsconfig.json"]).status === 0 && run(process.execPath, TEST_ARGS).status === 0;
  if (!baseline) {
    console.error("the test suite fails without mutations; fix it first");
    process.exit(2);
  }
  const survivors = [];
  for (const [label, file, from, to] of MUTATIONS) {
    const path = join(root, file);
    const original = readFileSync(path, "utf8");
    writeFileSync(path + BACKUP, original);
    writeFileSync(path, original.replace(from, to));
    try {
      const build = run("npx", ["tsc", "-p", "tsconfig.json"]);
      const killed = build.status !== 0 || run(process.execPath, TEST_ARGS).status !== 0;
      if (!killed) survivors.push(label);
    } finally {
      writeFileSync(path, original);
      unlinkSync(path + BACKUP);
    }
  }
  if (run("npx", ["tsc", "-p", "tsconfig.json"]).status !== 0) {
    console.error("could not rebuild after mutations");
    process.exit(2);
  }
  if (survivors.length) {
    console.error(`surviving mutations (controls no test catches):\n- ${survivors.join("\n- ")}`);
    process.exit(1);
  }
  console.log(`${MUTATIONS.length}/${MUTATIONS.length} mutations killed`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();
