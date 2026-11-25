// Test helpers. Secrets are assembled at runtime so the repository never contains a string that
// matches a real token format (and so secret scanners do not flag the test suite).
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export const fake = {
  github: () => "gh" + "p_" + "A1b2C3d4E5".repeat(4),
  anthropic: () => "sk-" + "ant-" + "api03-" + "x".repeat(40),
  openai: () => "sk-" + "proj-" + "Y".repeat(40),
  aws: () => "AK" + "IA" + "ABCDEFGHIJKLMNOP",
  slack: () => "xo" + "xb-" + "1234567890-abcdefghij",
  stripe: () => "sk_" + "live_" + "Z".repeat(30),
  google: () => "AI" + "za" + "B".repeat(35),
  supabase: () => "sb_" + "secret_" + "C".repeat(30),
  posthog: () => "ph" + "x_" + "D".repeat(40),
  generic: () => "q9Wm2Lx7Rt4Kp8Vz3Nc6",
};

export function tempDir(prefix = "mcp-audit-") {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function writeFile(root, relative, content, mode = 0o600) {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  chmodSync(path, mode);
  return path;
}

export function mcpJson(servers) {
  return { mcpServers: servers };
}
