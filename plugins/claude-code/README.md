# Asterion MCP Audit

A skill that audits the MCP servers configured on your machine and in the current project, and helps you fix what it finds.

Claude reads the MCP configuration of Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, VS Code and Windsurf and reports:

- packages that are not pinned to an exact version (`npx -y some-server`);
- API keys, tokens and passwords written in plain text (never shown);
- remote servers over unencrypted connections;
- filesystem servers with access to your whole disk or home folder;
- containers started with host-level access;
- tools and servers that run without asking.

## Use

Ask: "audit my MCP configuration", "is my MCP setup safe?" or "review this project's .mcp.json".

Claude reads the files, explains each finding and proposes the exact change. It edits configuration files only when you ask, and never prints or moves a credential.

## Privacy

The skill runs no program and makes no network request. It sends nothing to Asterion or anyone else.

## More

The same rules as a deterministic command-line tool, with file-permission checks, tool-description checks and SARIF output for CI: [github.com/asterionsec/mcp-audit](https://github.com/asterionsec/mcp-audit). Apache-2.0.
