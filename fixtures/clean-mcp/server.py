#!/usr/bin/env python3
"""Clean stdio JSON-RPC 2.0 MCP server (`release-notes-mcp`).

Exposes two benign tools (`health_check` and `format_release_note`) with
zero filesystem probes, zero hidden directives, and zero outbound network calls.
"""

from __future__ import annotations

import json
import sys
from typing import Any

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "health_check",
        "description": "Returns the operational status and protocol version of release-notes-mcp.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "format_release_note",
        "description": "Formats a structured Markdown release note from title and body inputs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Release note heading title.",
                },
                "body": {
                    "type": "string",
                    "description": "Release note summary body text.",
                },
            },
            "required": ["title", "body"],
        },
    },
]


def _emit(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def handle_request(req: dict[str, Any]) -> None:
    method = req.get("method")
    req_id = req.get("id")
    if not isinstance(method, str) or not method:
        if req_id is not None:
            _emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32600, "message": "Invalid Request: 'method' must be a non-empty string"},
                }
            )
        return

    raw_params = req.get("params")
    if raw_params is None:
        params: dict[str, Any] = {}
    elif not isinstance(raw_params, dict):
        if req_id is not None:
            _emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: expected object"},
                }
            )
        return
    else:
        params = raw_params

    if method == "initialize":
        if req_id is not None:
            _emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "release-notes-mcp",
                            "version": "0.2.0",
                        },
                    },
                }
            )
        return

    if method == "notifications/initialized":
        if req_id is not None:
            _emit({"jsonrpc": "2.0", "id": req_id, "result": {}})
        return

    if method == "tools/list":
        if req_id is not None:
            _emit({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        return

    if method == "resources/list":
        if req_id is not None:
            _emit({"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}})
        return

    if method == "prompts/list":
        if req_id is not None:
            _emit({"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}})
        return

    if method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            if req_id is not None:
                _emit(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Invalid params: 'name' must be a non-empty string"},
                    }
                )
            return

        raw_args = params.get("arguments")
        if raw_args is None:
            arguments: dict[str, Any] = {}
        elif not isinstance(raw_args, dict):
            if req_id is not None:
                _emit(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object"},
                    }
                )
            return
        else:
            arguments = raw_args

        if tool_name == "health_check":
            if req_id is not None:
                _emit(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps({"status": "ok", "version": "0.2.0"})}],
                            "isError": False,
                        },
                    }
                )
            return

        if tool_name == "format_release_note":
            raw_title = arguments.get("title")
            raw_body = arguments.get("body")
            title = "Release" if raw_title is None else str(raw_title)
            body = "" if raw_body is None else str(raw_body)
            formatted = f"## {title}\n\n{body.strip()}\n"
            if req_id is not None:
                _emit(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": formatted}],
                            "isError": False,
                        },
                    }
                )
            return

        if req_id is not None:
            _emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }
            )
        return

    if req_id is not None:
        _emit(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )


def main() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
            continue
        if isinstance(req, dict):
            handle_request(req)
        else:
            _emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request: expected JSON object"}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
