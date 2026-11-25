# workspace-notes-mcp

Lightweight stdio Model Context Protocol (MCP) server for formatting structured release notes and engineering changelogs.

## Capabilities

- `health_check()`: Reports server readiness and protocol version.
- `format_release_note(title, body, notes_context?)`: Formats a clean Markdown release note block from structured inputs.

## Running (stdio JSON-RPC 2.0)

```bash
python3 server.py
```
