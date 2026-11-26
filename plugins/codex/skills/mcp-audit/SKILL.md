---
name: mcp-audit
description: Audit the MCP server configurations of this machine and the current project for security risks (unpinned packages, plain-text credentials, unencrypted remote servers, broad filesystem access, privileged containers, auto-approved tools) and help fix them. Use when the user asks whether their MCP setup is safe, before adding or sharing an MCP server, or when reviewing a project's .mcp.json.
---

# Audit MCP configurations

Call the `audit_mcp_configs` tool of this plugin's `mcp-audit` server (it runs `@asterionsec/mcp-audit@0.1.1`). It is read-only, starts no other server and makes no network request; credentials appear masked.

- For everything on this machine plus the current project: pass `projectDirs` with the project folder.
- For a single project only: pass `includeDefaults: false` and `projectDirs`.
- For specific files: pass `paths`.

Then:

1. Summarize the findings by severity. Group repeated findings (the same credential in several files) instead of listing each one.
2. For each finding, explain the concrete risk in one sentence and propose the exact change from its `fix` field, applied to the file and pointer it names.
3. Never print, copy or move a credential's value. When a credential is in plain text, tell the user to rotate it and to reference an environment variable instead; edit the file only if they ask.
4. Change configuration files only with the user's approval, one server at a time, and call the tool again to confirm the finding is gone.

The tool checks configuration only. Checking what each server's tools say about themselves (`--probe`) starts those servers, so it is a command the user runs on purpose: `npx -y @asterionsec/mcp-audit@0.1.1 --probe`. Mention it; do not run it for them unprompted.
