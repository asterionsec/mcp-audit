# mcp-audit

Audit the MCP servers your AI tools are configured to run, before one of them runs something you did not expect.

`mcp-audit` reads the MCP configuration of Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf and Cline, and reports concrete, fixable risks: packages that are not pinned, credentials written in plain text, unencrypted remote servers, filesystem servers with access to your whole disk, containers with host access, shell bootstraps and tools that run without asking.

It is local and deterministic. It makes no network request, sends nothing anywhere and has no runtime dependencies. Credentials are always shown masked.

```
npx -y @asterionsec/mcp-audit@0.1.1
```

```
mcp-audit 0.1.1: 4 configuration files, 9 MCP servers
  ~/.claude.json  [claude-code, 5 servers]
  ~/Library/Application Support/Claude/claude_desktop_config.json  [claude-desktop, 3 servers]
  ...

HIGH     MCP-SEC-001  Credential stored in plain text
         "github" has a GitHub token in its env GITHUB_PERSONAL_ACCESS_TOKEN: ghp_•••••• (40 chars).
         The file is inside a git repository, so it can be committed and shared.
         Fix: Remove it from the file, rotate it, and reference an environment variable instead.
         ./.mcp.json  /mcpServers/github/env/GITHUB_PERSONAL_ACCESS_TOKEN

MEDIUM   MCP-PIN-001  Server package is not pinned to an exact version
         "filesystem" runs @modelcontextprotocol/server-filesystem with no version.
         Fix: Pin an exact version: @modelcontextprotocol/server-filesystem@<x.y.z>.
```

## Why

An MCP server runs with your user's permissions, and the agent that calls it reads text you never see. Most configurations copied from a README run `npx -y some-server`, which downloads whatever version the registry serves at every start, and keep API keys next to it in a file other programs can read. Those are the two ways a single compromised package or leaked file turns into access to your machine and accounts. This tool finds them in seconds.

## Usage

```
mcp-audit [options] [config files...]
```

With no files it reads every supported client's configuration for your user and the project files in the current folder.

| Option | What it does |
|---|---|
| `--project <dir>` | Also read a project's `.mcp.json`, `.cursor/`, `.vscode/`, `.gemini/` and `.claude/` settings (repeatable) |
| `--no-defaults` | Read only the files and projects given |
| `--format text\|json\|sarif`, `--json`, `--sarif` | Output format. SARIF 2.1.0 works with GitHub code scanning |
| `--fail-on <severity>` | Exit 1 when a finding is at or above `critical`, `high` (default), `medium`, `low` or `info`; `none` always exits 0 |
| `--probe` | Start each local stdio server, read its tool list and check the descriptions (see below) |
| `--list-rules` | Print the rules |
| `--mcp` | Run as an MCP server |
| `--no-color` | Plain output |

Exit codes: `0` nothing at or above `--fail-on`, `1` at least one finding at or above it, `2` usage or runtime error.

### In CI

```yaml
- run: npx -y @asterionsec/mcp-audit@0.1.1 --no-defaults --project . --sarif > mcp-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

### As an MCP server

```json
{ "mcpServers": { "mcp-audit": { "command": "npx", "args": ["-y", "@asterionsec/mcp-audit@0.1.1", "--mcp"] } } }
```

It exposes one read-only tool, `audit_mcp_configs`. The MCP server never starts other servers: `--probe` is a command-line choice, so a prompt cannot make your agent execute every configured server.

### --probe

The static rules read configuration only. `--probe` goes one step further: it starts each local stdio server the way your client would, sends `initialize` and `tools/list`, stops it, and checks what the tools say about themselves. It runs those servers' code (your client already does, every time it starts); remote servers are not contacted.

## Rules

| ID | Severity | What it finds |
|---|---|---|
| <a id="mcp-pin-001"></a>`MCP-PIN-001` | medium | `npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run` or a container image without an exact version or digest |
| <a id="mcp-pin-002"></a>`MCP-PIN-002` | high | Code from a git branch or URL without a commit hash |
| <a id="mcp-sec-001"></a>`MCP-SEC-001` | high in a git repository, medium elsewhere | API keys, tokens and passwords in `env`, headers, arguments or URLs, by format (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe, Google, Supabase and more) or by name (`*_API_KEY`, `Authorization`, `--token`, ...). References like `${VAR}` are not flagged |
| <a id="mcp-net-001"></a>`MCP-NET-001` | high | A non-local remote server over `http://` or `ws://` |
| <a id="mcp-fs-001"></a>`MCP-FS-001` | high | A filesystem server given `/`, `~`, your home folder or a drive root |
| <a id="mcp-docker-001"></a>`MCP-DOCKER-001` | high | `--privileged`, the Docker socket, the host root, host network or PID namespace, dangerous capabilities |
| <a id="mcp-exec-001"></a>`MCP-EXEC-001` | high | A launch command that downloads a script and pipes it into a shell |
| <a id="mcp-approve-001"></a>`MCP-APPROVE-001` | medium, high for `*` | Gemini CLI `trust: true`, Cline/Roo `autoApprove` or `alwaysAllow` |
| <a id="mcp-approve-002"></a>`MCP-APPROVE-002` | medium, high for `mcp__*` | Claude Code permission rules that allow a whole server, or every server |
| <a id="mcp-approve-003"></a>`MCP-APPROVE-003` | medium | `enableAllProjectMcpServers`, which starts any cloned repository's servers |
| <a id="mcp-file-001"></a>`MCP-FILE-001` | medium | A configuration file other users can write |
| <a id="mcp-file-002"></a>`MCP-FILE-002` | medium | A file with plain-text credentials that other users can read |
| <a id="mcp-tool-001"></a>`MCP-TOOL-001` | high | Zero-width, bidirectional or Unicode tag characters in a tool (with `--probe`) |
| <a id="mcp-tool-002"></a>`MCP-TOOL-002` | high | A tool description that instructs the model: hide things from the user, ignore other instructions, read keys (with `--probe`) |
| <a id="mcp-tool-003"></a>`MCP-TOOL-003` | medium | Two servers exposing a tool with the same name (with `--probe`) |
| <a id="mcp-read-001"></a>`MCP-READ-001` | info | A configuration file that exists but could not be parsed |

## What it reads

| Client | Files |
|---|---|
| Claude Code | `~/.claude.json` (user and per-project servers), `~/.claude/settings.json`, project `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json` |
| Claude Desktop | `claude_desktop_config.json` in the app's support folder |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` |
| Codex | `~/.codex/config.toml` (or `$CODEX_HOME`), `[mcp_servers.*]` |
| Gemini CLI | `~/.gemini/settings.json`, project `.gemini/settings.json` |
| VS Code | user `mcp.json` and `settings.json`, project `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | `cline_mcp_settings.json` in VS Code's global storage |

## Limits

- The static rules see what is configured, not what a server does once it runs. A pinned, local, well-configured server can still be malicious; `--probe` checks only what it says about its tools.
- Credentials are recognized by format and by name. A secret with no known format under a neutral name (`OPTIONS=…`) is not found.
- `--probe` lists tools of local stdio servers only.

## Quality

Every release passes `npm run verify`: type checking, the test suite (every rule with cases that must and must not fire, the official MCP SDK as a client, real processes for `--probe`), mutation testing (each control is disabled in turn and a test must fail), a scan of the repository with the tool's own detector, a package contents allowlist, and a clean-room install and run in Node 20 and 22 containers with no network.

## About

Made by [Asterion](https://asterionsec.com/en/ai-agent-penetration-testing), which pentests AI agents and the MCP servers they use. Found a problem in mcp-audit itself? See [SECURITY.md](SECURITY.md).

Apache-2.0.
