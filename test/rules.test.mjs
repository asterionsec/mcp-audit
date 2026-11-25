// Every rule with cases that must fire and cases that must not. The negative cases matter as much
// as the positive ones: a tool that cries wolf gets uninstalled.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { runAudit } from "../dist/audit.js";
import { fake, mcpJson, tempDir, writeFile } from "./helpers.mjs";

function audit(config, { name = "claude_desktop_config.json", mode = 0o600, root = tempDir(), home = "/nonexistent-home" } = {}) {
  const path = writeFile(root, name, config, mode);
  return runAudit({ paths: [path], projectDirs: [], includeDefaults: false, home }).findings;
}

const rules = (findings) => findings.map((item) => item.rule).sort();
const has = (findings, rule) => findings.some((item) => item.rule === rule);

test("MCP-PIN-001 flags package launchers without an exact version", () => {
  const cases = {
    "npx -y": { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] },
    "npx latest": { command: "npx", args: ["some-server@latest"] },
    "npx range": { command: "npx", args: ["-y", "@scope/server@^1.2.0"] },
    "npx.cmd on Windows": { command: "C:\\Program Files\\nodejs\\npx.cmd", args: ["server"] },
    "bunx": { command: "bunx", args: ["server"] },
    "pnpm dlx": { command: "pnpm", args: ["dlx", "server"] },
    "uvx": { command: "uvx", args: ["mcp-server-fetch"] },
    "uv tool run": { command: "uv", args: ["tool", "run", "mcp-server-git"] },
    "pipx run": { command: "pipx", args: ["run", "mcp-server-time"] },
    "docker latest": { command: "docker", args: ["run", "-i", "--rm", "ghcr.io/acme/server:latest"] },
    "docker no tag": { command: "docker", args: ["run", "-i", "--rm", "-e", "TOKEN", "acme/server"] },
  };
  for (const [label, server] of Object.entries(cases)) {
    assert.ok(has(audit(mcpJson({ s: server })), "MCP-PIN-001"), label);
  }
});

test("MCP-PIN-001 accepts exact versions and digests", () => {
  const cases = {
    "npx exact": { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@2025.4.8"] },
    "npx prerelease": { command: "npx", args: ["server@1.0.0-beta.2"] },
    "npx -p": { command: "npx", args: ["-p", "server@3.1.4", "server-bin"] },
    "uvx exact": { command: "uvx", args: ["mcp-server-fetch==2025.4.7"] },
    "uvx --from": { command: "uvx", args: ["--from", "mcp-server-git==0.6.2", "mcp-server-git"] },
    "docker digest": { command: "docker", args: ["run", "-i", "--rm", "acme/server@sha256:" + "a".repeat(64)] },
    "node script": { command: "node", args: ["/opt/server/index.js"] },
    "binary": { command: "/usr/local/bin/github-mcp-server", args: ["stdio"] },
  };
  for (const [label, server] of Object.entries(cases)) {
    assert.ok(!has(audit(mcpJson({ s: server })), "MCP-PIN-001"), label);
  }
});

test("MCP-PIN-001 rates a mutable container tag as low", () => {
  const findings = audit(mcpJson({ s: { command: "docker", args: ["run", "-i", "acme/server:1.4"] } }));
  assert.equal(findings.find((item) => item.rule === "MCP-PIN-001")?.severity, "low");
});

test("MCP-PIN-002 flags git sources without a commit hash", () => {
  assert.ok(has(audit(mcpJson({ s: { command: "npx", args: ["github:acme/server"] } })), "MCP-PIN-002"));
  assert.ok(has(audit(mcpJson({ s: { command: "uvx", args: ["--from", "git+https://github.com/acme/server", "server"] } })), "MCP-PIN-002"));
  assert.ok(!has(audit(mcpJson({ s: { command: "npx", args: ["github:acme/server#" + "b".repeat(40)] } })), "MCP-PIN-002"));
});

test("MCP-SEC-001 finds credentials by format and by name, everywhere they can be written", () => {
  const cases = {
    "env github": { command: "node", args: ["s.js"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: fake.github() } },
    "env anthropic": { command: "node", args: ["s.js"], env: { KEY: fake.anthropic() } },
    "env aws": { command: "node", args: ["s.js"], env: { AWS_ACCESS_KEY_ID: fake.aws() } },
    "env by name": { command: "node", args: ["s.js"], env: { ACME_API_KEY: fake.generic() } },
    "header bearer": { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer " + fake.generic() } },
    "header known": { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer " + fake.posthog() } },
    "arg inline": { command: "node", args: ["s.js", "--api-key=" + fake.generic()] },
    "arg after flag": { command: "node", args: ["s.js", "--token", fake.generic()] },
    "arg slack": { command: "node", args: ["s.js", fake.slack()] },
    "url query": { url: "https://mcp.example.com/sse?api_key=" + fake.generic() },
    "url credentials": { command: "node", args: ["s.js", "postgres://admin:" + fake.generic() + "@db.example.com/app"] },
  };
  for (const [label, server] of Object.entries(cases)) {
    assert.ok(has(audit(mcpJson({ s: server })), "MCP-SEC-001"), label);
  }
});

test("MCP-SEC-001 ignores references, placeholders and non-secret values", () => {
  const cases = {
    "env reference": { command: "node", args: ["s.js"], env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" } },
    "env cursor reference": { command: "node", args: ["s.js"], env: { API_KEY: "${env:API_KEY}" } },
    "vscode input": { command: "node", args: ["s.js"], env: { API_KEY: "${input:apiKey}" } },
    "placeholder": { command: "node", args: ["s.js"], env: { API_KEY: "<your-api-key>" } },
    "empty": { command: "node", args: ["s.js"], env: { API_KEY: "" } },
    "not secret name": { command: "node", args: ["s.js"], env: { LOG_LEVEL: "debug-verbose-mode", REGION: "us-east-1-zone-b" } },
    "bearer reference": { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer ${MCP_TOKEN}" } },
    "short value": { command: "node", args: ["s.js"], env: { AUTH: "oauth" } },
    "path arg": { command: "node", args: ["/Users/me/projects/token-service/index.js"] },
  };
  for (const [label, server] of Object.entries(cases)) {
    assert.ok(!has(audit(mcpJson({ s: server })), "MCP-SEC-001"), label);
  }
});

test("MCP-SEC-001 never prints the secret and is high inside a git repository", () => {
  const secret = fake.github();
  const root = tempDir();
  mkdirSync(join(root, ".git"));
  const findings = audit(mcpJson({ s: { command: "node", args: ["s.js"], env: { TOKEN: secret } } }), { name: ".mcp.json", root });
  const item = findings.find((entry) => entry.rule === "MCP-SEC-001");
  assert.equal(item?.severity, "high");
  assert.ok(!JSON.stringify(findings).includes(secret));
  assert.match(item.detail, /git repository/);
  const outside = audit(mcpJson({ s: { command: "node", args: ["s.js"], env: { TOKEN: secret } } }));
  assert.equal(outside.find((entry) => entry.rule === "MCP-SEC-001")?.severity, "medium");
});

test("MCP-NET-001 flags plain http and ws to non-local hosts only", () => {
  assert.ok(has(audit(mcpJson({ s: { url: "http://mcp.example.com/mcp" } })), "MCP-NET-001"));
  assert.ok(has(audit(mcpJson({ s: { url: "ws://10.0.0.5:8080/ws" } })), "MCP-NET-001"));
  for (const url of ["https://mcp.example.com/mcp", "http://localhost:3000/mcp", "http://127.0.0.1:8080/sse", "http://[::1]:9000/mcp", "http://app.localhost/mcp"]) {
    assert.ok(!has(audit(mcpJson({ s: { url } })), "MCP-NET-001"), url);
  }
});

test("MCP-FS-001 flags a filesystem server given the disk root or the home directory", () => {
  const home = "/Users/someone";
  for (const path of ["/", "~", "/Users", home, `${home}/`, "C:\\"]) {
    const findings = audit(mcpJson({ fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", path] } }), { home });
    assert.ok(has(findings, "MCP-FS-001"), path);
  }
  const scoped = audit(mcpJson({ fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", `${home}/projects/app`] } }), { home });
  assert.ok(!has(scoped, "MCP-FS-001"));
  const other = audit(mcpJson({ git: { command: "uvx", args: ["mcp-server-git==0.6.2", "--repository", "/"] } }), { home });
  assert.ok(!has(other, "MCP-FS-001"));
});

test("MCP-DOCKER-001 flags host-level container access", () => {
  const cases = {
    privileged: ["run", "--privileged", "img@sha256:" + "c".repeat(64)],
    socket: ["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img@sha256:" + "c".repeat(64)],
    hostNetwork: ["run", "--network=host", "img@sha256:" + "c".repeat(64)],
    rootMount: ["run", "--mount", "type=bind,source=/,target=/host", "img@sha256:" + "c".repeat(64)],
    capAdd: ["run", "--cap-add", "SYS_ADMIN", "img@sha256:" + "c".repeat(64)],
  };
  for (const [label, args] of Object.entries(cases)) {
    assert.ok(has(audit(mcpJson({ s: { command: "docker", args } })), "MCP-DOCKER-001"), label);
  }
  const safe = audit(mcpJson({ s: { command: "docker", args: ["run", "-i", "--rm", "-v", "./data:/data:ro", "img@sha256:" + "c".repeat(64)] } }));
  assert.ok(!has(safe, "MCP-DOCKER-001"));
});

test("MCP-EXEC-001 flags a download piped into a shell", () => {
  assert.ok(has(audit(mcpJson({ s: { command: "bash", args: ["-c", "curl -fsSL https://example.com/install.sh | sh && server"] } })), "MCP-EXEC-001"));
  assert.ok(has(audit(mcpJson({ s: { command: "powershell", args: ["-Command", "iwr https://example.com/s.ps1 | iex"] } })), "MCP-EXEC-001"));
  assert.ok(!has(audit(mcpJson({ s: { command: "bash", args: ["-c", "cd /opt/server && node index.js"] } })), "MCP-EXEC-001"));
});

test("MCP-APPROVE-001 flags trusted servers and auto-approved tools", () => {
  const gemini = audit({ mcpServers: { s: { command: "node", args: ["s.js"], trust: true } } }, { name: join(".gemini", "settings.json") });
  assert.ok(has(gemini, "MCP-APPROVE-001"));
  const cline = audit({ mcpServers: { s: { command: "node", args: ["s.js"], autoApprove: ["read_file", "write_file"] } } }, { name: "cline_mcp_settings.json" });
  assert.equal(cline.find((item) => item.rule === "MCP-APPROVE-001")?.severity, "medium");
  const everything = audit({ mcpServers: { s: { command: "node", args: ["s.js"], alwaysAllow: ["*"] } } }, { name: "cline_mcp_settings.json" });
  assert.equal(everything.find((item) => item.rule === "MCP-APPROVE-001")?.severity, "high");
  assert.ok(!has(audit({ mcpServers: { s: { command: "node", args: ["s.js"], autoApprove: [] } } }, { name: "cline_mcp_settings.json" }), "MCP-APPROVE-001"));
});

test("MCP-APPROVE-002 and 003 flag broad Claude Code permission rules", () => {
  const settings = { permissions: { allow: ["mcp__*", "mcp__github", "mcp__linear__*", "mcp__github__get_issue", "Bash(git status)"] }, enableAllProjectMcpServers: true };
  const findings = audit(settings, { name: join(".claude", "settings.json") });
  const approve = findings.filter((item) => item.rule === "MCP-APPROVE-002");
  assert.deepEqual(approve.map((item) => item.severity).sort(), ["high", "medium", "medium"]);
  assert.ok(!approve.some((item) => item.detail.includes("get_issue")));
  assert.ok(has(findings, "MCP-APPROVE-003"));
});

test("MCP-FILE-001 and 002 check file permissions", () => {
  if (process.platform === "win32") return;
  const plain = mcpJson({ s: { command: "node", args: ["s.js"] } });
  assert.ok(has(audit(plain, { mode: 0o666 }), "MCP-FILE-001"));
  assert.ok(!has(audit(plain, { mode: 0o644 }), "MCP-FILE-002"));
  const secret = mcpJson({ s: { command: "node", args: ["s.js"], env: { API_KEY: fake.generic() } } });
  assert.ok(has(audit(secret, { mode: 0o644 }), "MCP-FILE-002"));
  assert.ok(!has(audit(secret, { mode: 0o600 }), "MCP-FILE-002"));
});

test("MCP-READ-001 reports an unparseable file and audits the rest", () => {
  const root = tempDir();
  const broken = writeFile(root, "claude_desktop_config.json", "{ not json");
  const good = writeFile(root, "other/claude_desktop_config.json", mcpJson({ s: { url: "http://mcp.example.com" } }));
  const result = runAudit({ paths: [broken, good], projectDirs: [], includeDefaults: false });
  assert.ok(has(result.findings, "MCP-READ-001"));
  assert.ok(has(result.findings, "MCP-NET-001"));
});

test("a careful configuration produces no findings", () => {
  const config = mcpJson({
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@2025.4.8"], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" } },
    fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", "/Users/me/projects/app"] },
    fetch: { command: "uvx", args: ["mcp-server-fetch==2025.4.7"] },
    remote: { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer ${MCP_TOKEN}" } },
    db: { command: "docker", args: ["run", "-i", "--rm", "-v", "./data:/data:ro", "acme/db-mcp@sha256:" + "d".repeat(64)] },
  });
  assert.deepEqual(rules(audit(config, { home: "/Users/me" })), []);
});
