// Reading every client's format, and the three output formats.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { parseToml } from "../dist/toml.js";
import { stripJsonc, defaultCandidates } from "../dist/discover.js";
import { runAudit } from "../dist/audit.js";
import { jsonReport, sarifReport, textReport } from "../dist/report.js";
import { RULES } from "../dist/rules.js";
import { fake, tempDir, writeFile } from "./helpers.mjs";

test("TOML subset: tables, quoted keys, strings, arrays across lines, inline tables, comments", () => {
  const doc = parseToml(`
model = "x" # trailing comment
[projects."/Users/me/a b"]
trust_level = 'trusted'

[mcp_servers.github]
command = "npx"
args = [
  "-y",   # flag
  "@modelcontextprotocol/server-github@2025.4.8",
]
env = { GITHUB_TOKEN = "abc\\"def", "QUOTED KEY" = "v" }
startup_timeout_sec = 20
enabled = true

[mcp_servers.github.env]
EXTRA = "1"

[mcp_servers."remote one"]
url = "https://mcp.example.com/mcp"
http_headers = { Authorization = "Bearer x" }
`);
  assert.equal(doc.projects["/Users/me/a b"].trust_level, "trusted");
  assert.deepEqual(doc.mcp_servers.github.args, ["-y", "@modelcontextprotocol/server-github@2025.4.8"]);
  assert.equal(doc.mcp_servers.github.env.GITHUB_TOKEN, 'abc"def');
  assert.equal(doc.mcp_servers.github.env["QUOTED KEY"], "v");
  assert.equal(doc.mcp_servers.github.env.EXTRA, "1");
  assert.equal(doc.mcp_servers.github.startup_timeout_sec, 20);
  assert.equal(doc.mcp_servers.github.enabled, true);
  assert.equal(doc.mcp_servers["remote one"].url, "https://mcp.example.com/mcp");
});

test("JSONC: comments and trailing commas are removed, strings are kept intact", () => {
  const text = `{
    // a comment
    "servers": { "s": { "command": "node", "args": ["a // not a comment", "b,]"], }, },
    /* block */ "x": "http://example.com/*path*/",
  }`;
  const value = JSON.parse(stripJsonc(text));
  assert.deepEqual(value.servers.s.args, ["a // not a comment", "b,]"]);
  assert.equal(value.x, "http://example.com/*path*/");
});

test("each client format becomes servers", () => {
  const root = tempDir();
  const files = [
    writeFile(root, "claude_desktop_config.json", { mcpServers: { a: { command: "npx", args: ["a"] } } }),
    writeFile(root, ".claude.json", { mcpServers: { b: { type: "http", url: "https://b.example.com/mcp" } }, projects: { "/p": { mcpServers: { c: { command: "node", args: ["c.js"] } } } } }),
    writeFile(root, join(".vscode", "mcp.json"), `{ "servers": { "d": { "type": "stdio", "command": "node", "args": ["d.js"] } }, // jsonc\n }`),
    writeFile(root, join("Code", "User", "settings.json"), { mcp: { servers: { e: { url: "https://e.example.com" } } } }),
    writeFile(root, "config.toml", `[mcp_servers.f]\ncommand = "uvx"\nargs = ["f==1.0.0"]\n`),
    writeFile(root, "mcp_config.json", { mcpServers: { g: { serverUrl: "https://g.example.com/sse" } } }),
    writeFile(root, join(".gemini", "settings.json"), { mcpServers: { h: { httpUrl: "https://h.example.com/mcp" } } }),
  ];
  const result = runAudit({ paths: files, projectDirs: [], includeDefaults: false });
  const names = result.files.flatMap((file) => file.servers.map((server) => `${file.client}:${server.name}:${server.transport}`)).sort();
  assert.deepEqual(names, [
    "claude-code:b:remote",
    "claude-code:c:stdio",
    "claude-desktop:a:stdio",
    "codex:f:stdio",
    "gemini-cli:h:remote",
    "vscode:d:stdio",
    "vscode:e:remote",
    "windsurf:g:remote",
  ]);
});

test("default locations cover every client and the project files", () => {
  const paths = defaultCandidates(["/repo"], { HOME: "/home/u", XDG_CONFIG_HOME: "/home/u/.config" }).map((item) => item.path);
  for (const expected of ["/home/u/.claude.json", "/home/u/.cursor/mcp.json", "/home/u/.codex/config.toml", "/home/u/.gemini/settings.json", "/repo/.mcp.json", "/repo/.vscode/mcp.json", "/repo/.cursor/mcp.json"]) {
    assert.ok(paths.some((path) => path.replace(/\\/g, "/").endsWith(expected.slice(1))), expected);
  }
});

function sample() {
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", {
    mcpServers: {
      leaky: { command: "npx", args: ["-y", "leaky-server"], env: { STRIPE_KEY: fake.stripe() } },
      remote: { url: "http://mcp.example.com/mcp" },
    },
  });
  return { root, result: runAudit({ paths: [path], projectDirs: [], includeDefaults: false }) };
}

test("JSON output is complete and carries no raw secret", () => {
  const { result } = sample();
  const output = jsonReport(result.files, result.findings);
  const parsed = JSON.parse(output);
  assert.equal(parsed.tool.name, "mcp-audit");
  assert.equal(parsed.findings.length, result.findings.length);
  assert.ok(!output.includes(fake.stripe()));
});

test("SARIF output is valid 2.1.0 and every result names a declared rule", () => {
  const { root, result } = sample();
  const sarif = JSON.parse(sarifReport(result.findings, root));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  const declared = new Set(run.tool.driver.rules.map((rule) => rule.id));
  assert.equal(declared.size, RULES.length);
  for (const item of run.results) {
    assert.ok(declared.has(item.ruleId), item.ruleId);
    assert.ok(["error", "warning", "note"].includes(item.level));
    assert.equal(item.locations[0].physicalLocation.artifactLocation.uri, "claude_desktop_config.json");
  }
  assert.ok(!JSON.stringify(sarif).includes(fake.stripe()));
});

test("text output lists files, findings and a summary", () => {
  const { result } = sample();
  const text = textReport(result.files, result.findings, false);
  assert.match(text, /1 configuration file, 2 MCP servers/);
  assert.match(text, /MCP-NET-001/);
  assert.match(text, /\d+ findings?: /);
  assert.ok(!text.includes(fake.stripe()));
  assert.ok(!text.includes("\u001b["), "no colors when disabled");
});
