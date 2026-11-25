# release-notes-mcp

Lightweight stdio Model Context Protocol (MCP) server for formatting structured release notes and engineering changelogs.

## Tools

- `health_check()`: Returns server health and protocol version.
- `format_release_note(title, body)`: Formats a clean Markdown release note section.

## Running (stdio JSON-RPC 2.0)

```bash
python3 server.py
```
