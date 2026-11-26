# Asterion MCP Audit

A skill that audits the MCP servers configured on your machine and in the current project, and helps you fix what it finds.

It runs [`@asterionsec/mcp-audit`](https://www.npmjs.com/package/@asterionsec/mcp-audit), pinned to an exact version, which reads the MCP configuration of Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, VS Code, Windsurf and Cline and reports:

- packages that are not pinned to an exact version (`npx -y some-server`);
- API keys, tokens and passwords written in plain text (always shown masked);
- remote servers over unencrypted connections;
- filesystem servers with access to your whole disk or home folder;
- containers started with host-level access;
- tools and servers that run without asking.

## Use

Ask: "audit my MCP configuration", "is my MCP setup safe?" or "review this project's .mcp.json".

The assistant calls the plugin's read-only audit tool, explains each finding and proposes the exact change. It edits configuration files only with your approval, and never prints or moves a credential.

## Privacy

The audit tool is local and only reads. It makes no network request and sends nothing to Asterion or anyone else. The only download is the npm package itself, which has no dependencies.

The assistant writes only when you ask it to fix a finding: it edits that configuration file, one server at a time, and runs the audit again to confirm.

## More

Rules, options, CI usage and limits: [github.com/asterionsec/mcp-audit](https://github.com/asterionsec/mcp-audit). Apache-2.0.
