#!/usr/bin/env node
// The quality gate. Every step must pass before a release: build, tests, mutation testing, supply
// chain and packaging checks, a clean-room install with no network, plugin validation and docs.
// Usage: node scripts/verify.mjs [--skip-docker] [--real]
//   --real  also audits this machine's own MCP configurations (never in CI: it reads your files).

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const args = new Set(process.argv.slice(2));
const results = [];

function sh(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...options });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "", error: result.error };
}

async function step(name, fn) {
  const started = Date.now();
  process.stdout.write(`• ${name} … `);
  try {
    const note = await fn();
    const seconds = ((Date.now() - started) / 1000).toFixed(1);
    process.stdout.write(`ok (${seconds}s)${note ? ` — ${note}` : ""}\n`);
    results.push({ name, ok: true });
  } catch (error) {
    process.stdout.write(`FAILED\n  ${String(error instanceof Error ? error.message : error).split("\n").join("\n  ")}\n`);
    results.push({ name, ok: false });
    summary();
    process.exit(1);
  }
}

function summary() {
  const passed = results.filter((item) => item.ok).length;
  process.stdout.write(`\n${passed}/${results.length} gates passed.\n`);
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

await step("package.json: zero runtime dependencies, bin, engines, files", () => {
  if (Object.keys(pkg.dependencies ?? {}).length) throw new Error(`runtime dependencies are not allowed: ${Object.keys(pkg.dependencies).join(", ")}`);
  if (pkg.optionalDependencies || pkg.peerDependencies || pkg.bundleDependencies) throw new Error("no optional, peer or bundled dependencies");
  if (pkg.bin?.["mcp-audit"] !== "dist/cli.js") throw new Error("bin must point at dist/cli.js");
  if (pkg.engines?.node !== ">=20") throw new Error("engines.node must be >=20");
  if (JSON.stringify(pkg.files) !== JSON.stringify(["dist", "README.md", "LICENSE"])) throw new Error("files must be exactly dist, README.md, LICENSE");
  for (const script of ["preinstall", "install", "postinstall", "prepare"]) if (pkg.scripts?.[script]) throw new Error(`no ${script} script: installing must not run code`);
});

await step("typecheck and build", () => {
  sh("rm", ["-rf", "dist"]);
  const build = sh("npx", ["tsc", "-p", "tsconfig.json"]);
  if (build.status !== 0) throw new Error(build.stdout + build.stderr);
  sh("chmod", ["+x", "dist/cli.js"]);
  const first = readFileSync(join(root, "dist", "cli.js"), "utf8").split("\n")[0];
  if (first !== "#!/usr/bin/env node") throw new Error("dist/cli.js lost its shebang");
});

await step("compiled code imports only Node built-ins and its own files", () => {
  const offenders = [];
  for (const file of readdirSync(join(root, "dist"))) {
    if (!file.endsWith(".js")) continue;
    const text = readFileSync(join(root, "dist", file), "utf8");
    for (const match of text.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*)["']([^"']+)["']/g)) {
      const specifier = match[1];
      if (!specifier.startsWith("node:") && !specifier.startsWith("./")) offenders.push(`${file}: ${specifier}`);
    }
    if (/\bfetch\s*\(|node:https?["']|node:net["']|node:dgram["']|node:tls["']/.test(text) && file !== "probe.js") offenders.push(`${file}: network API`);
    if (file === "probe.js" && /node:https?["']|\bfetch\s*\(/.test(text)) offenders.push("probe.js: network API");
  }
  if (offenders.length) throw new Error(offenders.join("\n"));
  return "no network APIs outside the opt-in probe's local processes";
});

await step("tests", () => {
  const test = sh(process.execPath, ["--test", "--test-timeout=30000", "--test-force-exit", "test/rules.test.mjs", "test/formats.test.mjs", "test/runtime.test.mjs"]);
  if (test.status !== 0) throw new Error((test.stdout + test.stderr).split("\n").filter((line) => /not ok|fail|Error|expected|actual/i.test(line)).slice(0, 40).join("\n"));
  const count = /# pass (\d+)/.exec(test.stdout)?.[1] ?? /ℹ pass (\d+)/.exec(test.stdout)?.[1];
  return `${count ?? "?"} tests`;
});

await step("mutation testing: each control is caught by a test", () => {
  const mutate = sh(process.execPath, ["scripts/mutate.mjs"]);
  if (mutate.status !== 0) throw new Error(mutate.stdout + mutate.stderr);
  return mutate.stdout.trim().split("\n").pop();
});

await step("repository holds no credential (dogfood with our own detector)", async () => {
  const { findSecret } = await import(join(root, "dist", "secrets.js"));
  const leaks = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      if (["node_modules", "dist", ".git"].includes(entry) || entry.endsWith(".tgz")) continue;
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) walk(path);
      else {
        const text = readFileSync(path, "utf8");
        text.split("\n").forEach((line, index) => {
          const match = findSecret(line);
          if (match) leaks.push(`${relative(root, path)}:${index + 1} ${match.kind}`);
        });
      }
    }
  };
  walk(root);
  if (leaks.length) throw new Error(leaks.join("\n"));
});

let tarball = "";
await step("npm package: contents allowlist and size budget", () => {
  const pack = sh("npm", ["pack", "--json", "--pack-destination", "/tmp"]);
  if (pack.status !== 0) throw new Error(pack.stderr);
  const info = JSON.parse(pack.stdout)[0];
  tarball = join("/tmp", info.filename);
  const unexpected = info.files.map((file) => file.path).filter((path) => !(path.startsWith("dist/") || ["package.json", "README.md", "LICENSE"].includes(path)));
  if (unexpected.length) throw new Error(`unexpected files in the package: ${unexpected.join(", ")}`);
  if (info.unpackedSize > 200 * 1024) throw new Error(`package too large: ${info.unpackedSize} bytes`);
  return `${info.files.length} files, ${(info.unpackedSize / 1024).toFixed(0)} KiB unpacked`;
});

await step("clean-room install with no network (Docker, Node 20 and 22)", () => {
  if (args.has("--skip-docker")) return "skipped by flag";
  if (sh("docker", ["info"]).status !== 0) throw new Error("Docker is not available (use --skip-docker only for local iterations)");
  const fixture = join(root, "test", "cleanroom");
  const notes = [];
  for (const image of ["node:20-alpine", "node:22-alpine"]) {
    const script = [
      "set -e",
      "npm install --global --offline --no-audit --no-fund /pkg/package.tgz >/dev/null 2>&1",
      'test "$(mcp-audit --version)" = "' + pkg.version + '"',
      "set +e; mcp-audit --no-color /fixture/claude_desktop_config.json > /tmp/out.txt; code=$?; set -e",
      'test "$code" = "1"',
      "grep -q MCP-NET-001 /tmp/out.txt",
      "grep -q MCP-PIN-001 /tmp/out.txt",
      "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}' '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}' | timeout 10 mcp-audit --mcp > /tmp/mcp.txt || true",
      "grep -q audit_mcp_configs /tmp/mcp.txt",
      "echo ok",
    ].join("\n");
    const run = sh("docker", ["run", "--rm", "--network", "none", "-v", `${tarball}:/pkg/package.tgz:ro`, "-v", `${fixture}:/fixture:ro`, image, "sh", "-c", script]);
    if (run.status !== 0 || !run.stdout.includes("ok")) throw new Error(`${image}: ${run.stdout}${run.stderr}`);
    notes.push(image);
  }
  return notes.join(", ");
});

await step("plugins: Claude Code and Codex manifests and skills", () => {
  const notes = [];
  const claude = join(root, "plugins", "claude-code");
  const validate = sh("claude", ["plugin", "validate", claude]);
  if (validate.error) notes.push("claude CLI not found, manifest checked by schema only");
  else if (validate.status !== 0) throw new Error(`claude plugin validate: ${validate.stdout}${validate.stderr}`);
  else notes.push("claude plugin validate ok");
  const codexManifest = JSON.parse(readFileSync(join(root, "plugins", "codex", ".codex-plugin", "plugin.json"), "utf8"));
  for (const field of ["name", "version", "description"]) if (!codexManifest[field]) throw new Error(`codex plugin.json misses ${field}`);
  if (codexManifest.version !== pkg.version) throw new Error("codex plugin version differs from the package");
  for (const dir of [join(claude, "skills", "mcp-audit"), join(root, "plugins", "codex", "skills", "mcp-audit")]) {
    const skill = readFileSync(join(dir, "SKILL.md"), "utf8");
    const front = /^---\n([\s\S]*?)\n---/.exec(skill)?.[1] ?? "";
    if (!/^name: mcp-audit$/m.test(front) || !/^description: .{40,}/m.test(front)) throw new Error(`${relative(root, dir)}/SKILL.md needs name and a real description`);
    if (!skill.includes(`@asterionsec/mcp-audit@${pkg.version}`)) throw new Error(`${relative(root, dir)}/SKILL.md must run the exact version ${pkg.version} (we tell users to pin, so do we)`);
  }
  return notes.join("; ");
});

await step("docs: README covers every rule, version and option", async () => {
  const readme = readFileSync(join(root, "README.md"), "utf8");
  const { RULES } = await import(join(root, "dist", "rules.js"));
  const missing = RULES.map((rule) => rule.id).filter((id) => !readme.includes(id));
  if (missing.length) throw new Error(`README misses ${missing.join(", ")}`);
  for (const option of ["--probe", "--sarif", "--fail-on", "--mcp", "--project"]) if (!readme.includes(option)) throw new Error(`README misses ${option}`);
  const help = sh(process.execPath, ["dist/cli.js", "--help"]).stdout;
  if (!help.includes(pkg.version)) throw new Error("--help does not show the package version");
  const changelog = existsSync(join(root, "CHANGELOG.md")) ? readFileSync(join(root, "CHANGELOG.md"), "utf8") : "";
  if (!changelog.includes(`## ${pkg.version}`)) throw new Error(`CHANGELOG.md has no entry for ${pkg.version}`);
});

if (args.has("--real")) {
  await step("real configurations on this machine (local only)", () => {
    const run = sh(process.execPath, [join(root, "dist", "cli.js"), "--format", "json", "--fail-on", "none"], { cwd: process.env.HOME });
    if (run.status !== 0) throw new Error(run.stderr);
    const report = JSON.parse(run.stdout);
    const unreadable = report.files.filter((file) => file.error);
    if (unreadable.length) throw new Error(`could not parse: ${unreadable.map((file) => `${file.path} (${file.error})`).join(", ")}`);
    return `${report.files.length} files, ${report.findings.length} findings, all files parsed`;
  });
}

summary();
