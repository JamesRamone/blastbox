#!/usr/bin/env python3
"""Stdio JSON-RPC 2.0 MCP Client Harness for Blastbox Detonation.

Supports two-phase autonomous detonation inside `/home/sprite/detonation`:
  Phase A (`--discover-only`):
    Spawns the MCP server, executes `initialize` -> `notifications/initialized`
    -> `tools/list` (+ best-effort `resources/list` & `prompts/list`), and
    writes the discovery catalog JSON so the Controller agent can plan probes.
  Phase B (`--plan <plan.json>`, or standalone full-coverage fallback):
    Executes `initialize` -> `notifications/initialized` -> `tools/list` ->
    every planned `tools/call` under `strace -f`, writing the full transcript
    to `.blastbox_mcp_transcript.json`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def send_rpc(proc: subprocess.Popen[str], payload: dict[str, Any]) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def recv_rpc(
    proc: subprocess.Popen[str],
    expected_id: int,
    *,
    raise_on_error: bool = True,
) -> dict[str, Any]:
    assert proc.stdout is not None
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError(f"MCP server closed stdout unexpectedly while waiting for id={expected_id}")
        stripped = line.strip()
        if not stripped:
            continue
        msg = json.loads(stripped)
        if isinstance(msg, dict) and msg.get("id") == expected_id:
            if raise_on_error and "error" in msg and msg["error"] is not None:
                raise RuntimeError(f"MCP JSON-RPC error for id={expected_id}: {msg['error']}")
            return msg


def _synthesize_args_from_schema(tool_spec: dict[str, Any]) -> dict[str, Any]:
    schema = tool_spec.get("inputSchema")
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict) or not props:
        return {}
    required = schema.get("required")
    keys = [str(k) for k in required] if isinstance(required, list) else list(props.keys())[:3]
    args: dict[str, Any] = {}
    for key in keys:
        ps = props.get(key) if isinstance(props.get(key), dict) else {}
        ptype = ps.get("type")
        if ptype == "integer":
            args[key] = 1
        elif ptype == "number":
            args[key] = 1.0
        elif ptype == "boolean":
            args[key] = True
        elif ptype == "array":
            args[key] = ["blastbox-probe"]
        elif ptype == "object":
            args[key] = {}
        else:
            args[key] = "blastbox-probe"
    return args


def _resolve_server_entrypoint(work_dir: Path) -> tuple[dict[str, Any], str, Path]:
    manifest_path = work_dir / "mcp_manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            manifest = loaded

    entrypoint = str(manifest.get("entrypoint") or "server.py")
    work_dir_resolved = work_dir.resolve()
    server_path = (work_dir_resolved / entrypoint).resolve()
    if not server_path.is_relative_to(work_dir_resolved):
        raise ValueError(f"MCP server entrypoint escapes work_dir: {entrypoint}")
    if not server_path.exists():
        raise FileNotFoundError(f"MCP server entrypoint not found: {server_path}")
    return manifest, entrypoint, server_path


def _discover_server_capabilities(proc: subprocess.Popen[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], int]:
    req_id = 1
    send_rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "blastbox-mcp-probe", "version": "2.0"},
            },
        },
    )
    init_resp = recv_rpc(proc, req_id, raise_on_error=True)
    req_id += 1

    send_rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    send_rpc(proc, {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}})
    list_resp = recv_rpc(proc, req_id, raise_on_error=True)
    req_id += 1
    raw_tools_list = list_resp.get("result")
    tools_list = raw_tools_list if isinstance(raw_tools_list, dict) else {}

    resources_list: dict[str, Any] = {}
    send_rpc(proc, {"jsonrpc": "2.0", "id": req_id, "method": "resources/list", "params": {}})
    res_resp = recv_rpc(proc, req_id, raise_on_error=False)
    req_id += 1
    if isinstance(res_resp.get("result"), dict):
        resources_list = res_resp["result"]

    prompts_list: dict[str, Any] = {}
    send_rpc(proc, {"jsonrpc": "2.0", "id": req_id, "method": "prompts/list", "params": {}})
    prm_resp = recv_rpc(proc, req_id, raise_on_error=False)
    req_id += 1
    if isinstance(prm_resp.get("result"), dict):
        prompts_list = prm_resp["result"]

    init_result = init_resp.get("result") if isinstance(init_resp.get("result"), dict) else {}
    return init_result, tools_list, resources_list, prompts_list, req_id


def run_probe(
    work_dir: Path,
    transcript_path: Path,
    *,
    discover_only: bool = False,
    catalog_path: Path | None = None,
    plan_path: Path | None = None,
) -> dict[str, Any]:
    manifest, entrypoint, server_path = _resolve_server_entrypoint(work_dir)

    proc = subprocess.Popen(
        [sys.executable, str(server_path)],
        cwd=str(work_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    )

    try:
        init_result, tools_list, resources_list, prompts_list, next_id = _discover_server_capabilities(proc)
        server_info = init_result.get("serverInfo") if isinstance(init_result.get("serverInfo"), dict) else {}
        server_name = manifest.get("server_name") or server_info.get("name") or work_dir.name
        raw_tools = tools_list.get("tools")
        tools = [t for t in (raw_tools if isinstance(raw_tools, list) else []) if isinstance(t, dict)]

        if discover_only:
            catalog = {
                "server_entrypoint": entrypoint,
                "server_name": server_name,
                "initialize": init_result,
                "tools_list": tools_list,
                "resources_list": resources_list,
                "prompts_list": prompts_list,
            }
            if proc.stdin:
                proc.stdin.close()
            rc = proc.wait(timeout=15)
            if rc != 0:
                raise RuntimeError(f"MCP server exited with non-zero code {rc} during discovery")
            target_catalog = catalog_path or transcript_path
            target_catalog.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
            print(
                f"[blastbox-mcp-probe] discover=ok tools_count={len(tools)} "
                f"tools={[t.get('name') for t in tools]}",
                flush=True,
            )
            return catalog

        # Determine tool-call plan
        planned_calls: list[dict[str, Any]] = []
        plan_obj: dict[str, Any] | None = None
        if plan_path and plan_path.exists():
            loaded_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            if isinstance(loaded_plan, dict) and isinstance(loaded_plan.get("calls"), list):
                plan_obj = loaded_plan
                for entry in loaded_plan["calls"]:
                    if isinstance(entry, dict) and isinstance(entry.get("tool"), str) and entry["tool"]:
                        planned_calls.append(
                            {
                                "tool": entry["tool"],
                                "arguments": entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {},
                                "reason": str(entry.get("reason") or "Planned by Blastbox agent"),
                            }
                        )

        if not planned_calls:
            if not tools:
                raise RuntimeError("MCP server returned no callable tools in tools/list")
            for tool_spec in tools:
                tname = str(tool_spec.get("name") or "").strip()
                if not tname:
                    continue
                planned_calls.append(
                    {
                        "tool": tname,
                        "arguments": _synthesize_args_from_schema(tool_spec),
                        "reason": "Full-surface tool coverage",
                    }
                )

        tools_calls: list[dict[str, Any]] = []
        for call_spec in planned_calls:
            req_id = next_id
            next_id += 1
            send_rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {
                        "name": call_spec["tool"],
                        "arguments": call_spec["arguments"],
                    },
                },
            )
            resp = recv_rpc(proc, req_id, raise_on_error=False)
            if "error" in resp and resp["error"] is not None:
                tools_calls.append(
                    {
                        "tool": call_spec["tool"],
                        "arguments": call_spec["arguments"],
                        "reason": call_spec["reason"],
                        "result": {"isError": True},
                        "error": resp["error"],
                    }
                )
            else:
                res_obj = resp.get("result") if isinstance(resp.get("result"), dict) else {}
                tools_calls.append(
                    {
                        "tool": call_spec["tool"],
                        "arguments": call_spec["arguments"],
                        "reason": call_spec["reason"],
                        "result": res_obj,
                        "error": None,
                    }
                )

        if proc.stdin:
            proc.stdin.close()
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = -1
            server_err = "MCP server timed out during shutdown wait"
        else:
            server_err = f"MCP server exited with non-zero code {rc}" if rc != 0 else None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    primary_call = tools_calls[-1] if tools_calls else {"tool": None, "arguments": {}, "result": {}}
    transcript = {
        "server_entrypoint": entrypoint,
        "server_name": server_name,
        "server_exit_code": rc,
        "server_error": server_err,
        "initialize": init_result,
        "tools_list": tools_list,
        "resources_list": resources_list,
        "prompts_list": prompts_list,
        "plan_used": plan_obj,
        "tools_calls": tools_calls,
        "tools_call": primary_call,
    }
    transcript_path.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
    summary_pairs = ", ".join(
        f"{c['tool']}(isError={bool((c.get('result') or {}).get('isError'))})" for c in tools_calls
    )
    print(
        f"[blastbox-mcp-probe] initialize=ok tools_count={len(tools)} executed={len(tools_calls)} [{summary_pairs}]",
        flush=True,
    )
    return transcript


def main() -> int:
    parser = argparse.ArgumentParser(description="Blastbox MCP stdio JSON-RPC 2.0 probe harness")
    parser.add_argument("--work-dir", type=Path, default=Path("/home/sprite/detonation"))
    parser.add_argument(
        "--transcript",
        type=Path,
        default=Path("/home/sprite/detonation/.blastbox_mcp_transcript.json"),
    )
    parser.add_argument("--discover-only", action="store_true", help="Only run initialize + list methods and emit catalog")
    parser.add_argument("--catalog", type=Path, default=None, help="Output path for --discover-only catalog")
    parser.add_argument("--plan", type=Path, default=None, help="Optional agent probe plan JSON path")
    args = parser.parse_args()
    run_probe(
        args.work_dir,
        args.transcript,
        discover_only=args.discover_only,
        catalog_path=args.catalog,
        plan_path=args.plan,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
