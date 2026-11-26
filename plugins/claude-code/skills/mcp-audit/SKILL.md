---
name: mcp-audit
description: Audit the MCP server configurations of this machine and the current project for security risks (unpinned packages, plain-text credentials, unencrypted remote servers, broad filesystem access, privileged containers, auto-approved tools) and help fix them. Use when the user asks whether their MCP setup is safe, before adding or sharing an MCP server, or when reviewing a project's .mcp.json.
---

# Audit MCP configurations

Read the configuration files and apply the rules below. This skill runs no program and makes no network request: you read files and report.

## Handling credentials

These files often hold API keys. Never print, copy, move or summarize a credential's value: refer to it by server and setting name only. Do not paste file contents into the conversation.

## Files to read

Read the ones that exist; skip the rest silently.

- Claude Code: `~/.claude.json` (`mcpServers` and `projects.*.mcpServers`), `~/.claude/settings.json`, and in the project `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`
- Claude Desktop: `claude_desktop_config.json` in the app's support folder (macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`, Linux `~/.config/Claude/`)
- Cursor: `~/.cursor/mcp.json`, project `.cursor/mcp.json`
- Codex: `~/.codex/config.toml` (`[mcp_servers.*]`)
- Gemini CLI: `~/.gemini/settings.json`, project `.gemini/settings.json`
- VS Code: user `mcp.json` (`servers`), project `.vscode/mcp.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`

If the user asked about one project or one file, read only that.

## Rules

| ID | Severity | Flag when |
|---|---|---|
| MCP-PIN-001 | medium | `npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run` or a container image runs without an exact version or digest (`pkg`, `pkg@latest`, `image:latest`) |
| MCP-PIN-002 | high | Code comes from a git branch or a URL without a commit hash |
| MCP-SEC-001 | high inside a git repository, medium elsewhere | A literal API key, token or password in `env`, headers, arguments or a URL. A reference to an environment variable instead of a literal value is fine |
| MCP-NET-001 | high | A remote server reached over plain HTTP or WebSocket, without TLS, that is not localhost |
| MCP-FS-001 | high | A filesystem server is given `/`, `~`, the home folder or a drive root |
| MCP-DOCKER-001 | high | A container gets `--privileged`, the Docker socket, the host root, host network or PID namespace |
| MCP-EXEC-001 | high | The launch command downloads a script and pipes it into a shell |
| MCP-APPROVE-001 | medium, high for `*` | Gemini CLI `trust: true`, or `autoApprove` / `alwaysAllow` lists |
| MCP-APPROVE-002 | medium, high for `mcp__*` | Claude Code `permissions.allow` entries that allow a whole MCP server or all of them |
| MCP-APPROVE-003 | medium | `enableAllProjectMcpServers: true` |

## Report

1. Say which files you read and how many servers they define.
2. List findings by severity, most severe first. Group the same problem across files into one line.
3. For each: the file, the server and setting, the risk in one sentence, and the exact change that fixes it. For a plain-text credential, the fix is to rotate it and reference an environment variable.
4. Change a configuration file only when the user asks, one server at a time, and read it again to confirm.

Say plainly what this review does not cover: it reads configuration, not what a server does once it runs, and it does not check file permissions or the text of each server's tool descriptions.

For a deterministic check of the same rules, plus file permissions, tool descriptions (`--probe`) and SARIF output for CI, the user can run the open-source command-line tool themselves: `npx -y @asterionsec/mcp-audit@0.1.1`. Mention it once; do not run it unless the user asks.
