#!/usr/bin/env python3
"""Idempotent setup & lockdown verifier for the air-gapped Detonator Sprite.

Creates (if missing) and hardens `blastbox-detonator` so untrusted payloads:
  1. Have ZERO raw secrets in the VM environment.
  2. Have ZERO Sprite labels (`--clear-labels`), denying ALL Sprites Connectors
     (including allowed GitHub/OpenRouter routes).
  3. Have an explicit deny-all outbound network policy (`{"domain": "*", "action": "deny"}`)
     enforced outside the microVM boundary.
  4. Have `strace`, `curl`, `python3`, and `setuptools` pre-installed before lockdown.
  5. Snapshot a clean baseline checkpoint ready for detonation & overlay rewind.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import config  # noqa: E402

CHECKPOINT_ID_RE = re.compile(r"\b(v\d+)\b")


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def _sprite_exists(sprite: str) -> bool:
    proc = _run([config.SPRITE_BIN, "info", sprite], check=False)
    return proc.returncode == 0


def _set_network_policy(sprite: str, rules: list[dict[str, str]]) -> dict[str, Any]:
    payload = json.dumps({"rules": rules})
    proc = _run(
        [
            config.SPRITE_BIN,
            "api",
            f"/v1/sprites/{sprite}/policy/network",
            "--",
            "-sS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
        ],
        check=True,
    )
    try:
        return json.loads(proc.stdout) if proc.stdout.strip() else {"rules": rules}
    except json.JSONDecodeError:
        return {"raw": proc.stdout.strip(), "rules": rules}


def get_network_policy(sprite: str) -> dict[str, Any]:
    proc = _run(
        [config.SPRITE_BIN, "api", f"/v1/sprites/{sprite}/policy/network", "--", "-sS"],
        check=True,
    )
    raw = proc.stdout.strip()
    return json.loads(raw) if raw else {}


def ensure_tools_installed(sprite: str) -> None:
    check_cmd = (
        'export PATH="/.sprite/bin:$PATH"; '
        "command -v strace >/dev/null 2>&1 && "
        "command -v curl >/dev/null 2>&1 && "
        "/.sprite/bin/python3 -c 'import setuptools' >/dev/null 2>&1"
    )
    probe = _run(
        [config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "bash", "-c", check_cmd],
        check=False,
    )
    if probe.returncode != 0:
        print(f"[init-detonator] Installing strace/curl/setuptools on '{sprite}' before locking egress...", flush=True)
        # Temporarily allow defaults during one-time package bootstrap, then immediately deny all.
        _set_network_policy(sprite, [{"include": "defaults"}])
        install_cmd = (
            'export PATH="/.sprite/bin:$PATH"; '
            "if ! command -v strace >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then "
            "sudo apt-get update -qq && DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq strace curl >/dev/null; "
            "fi; "
            "if ! /.sprite/bin/python3 -c 'import setuptools' >/dev/null 2>&1; then "
            "/.sprite/bin/python3 -m pip install -q --no-cache-dir setuptools; "
            "fi"
        )
        _run([config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "bash", "-c", install_cmd], check=True)

    # Warm Sprite lazy language shims (e.g. rustc checked by pip) so /etc/profile.d/languages_*
    # is already initialized in the clean baseline checkpoint rather than written during detonation.
    _run(
        [
            config.SPRITE_BIN,
            "exec",
            "-s",
            sprite,
            "--no-stdin",
            "--",
            "bash",
            "-c",
            "/.sprite/bin/rustc --version >/dev/null 2>&1 || true",
        ],
        check=False,
    )


def verify_isolation(sprite: str) -> dict[str, Any]:
    info_proc = _run([config.SPRITE_BIN, "info", sprite], check=True)
    info_text = info_proc.stdout
    if config.CONTROLLER_LABEL in info_text:
        raise RuntimeError(
            f"SECURITY FAILURE: Detonator sprite '{sprite}' still carries label '{config.CONTROLLER_LABEL}'!\n{info_text}"
        )

    policy = get_network_policy(sprite)
    rules = policy.get("rules") if isinstance(policy, dict) else None
    has_deny_all = isinstance(rules, list) and any(
        isinstance(r, dict) and r.get("domain") == "*" and r.get("action") == "deny" for r in rules
    )
    if not has_deny_all:
        raise RuntimeError(f"SECURITY FAILURE: Detonator '{sprite}' lacks deny-all network policy: {policy}")

    # Live proof inside the detonator: zero secrets, external internet blocked, AND allowed GitHub Connector route blocked
    allowed_issue_url = (
        f"{config.GITHUB_GATEWAY}/repos/{config.DEFAULT_REPO}/issues"
    )
    verify_py = f"""
import json, os, subprocess, sys
forbidden = {list(config.FORBIDDEN_ENV_VARS)!r}
leaked = [v for v in forbidden if v in os.environ]
if leaked:
    raise RuntimeError(f"Forbidden secrets found in detonator env: {{leaked}}")

def probe_curl(args):
    p = subprocess.run(["curl", "-sS", "--max-time", "3", "-w", "\\nHTTP_STATUS:%{{http_code}}", *args], capture_output=True, text=True, check=False)
    return {{"rc": p.returncode, "stdout": p.stdout.strip()[:200], "stderr": p.stderr.strip()[:200]}}

ext = probe_curl(["https://example.com"])
conn = probe_curl(["-X", "POST", "-H", "Content-Type: application/json", "-d", '{{"title":"x","body":"y"}}', "{allowed_issue_url}"])
print(json.dumps({{
    "zero_secrets_verified": True,
    "env_count": len(os.environ),
    "external_egress_probe": ext,
    "connector_allowed_route_probe": conn,
}}))
"""
    exec_proc = _run(
        [config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "/.sprite/bin/python3", "-c", verify_py],
        check=True,
    )
    probe_res = json.loads(exec_proc.stdout.strip().splitlines()[-1])

    ext_ok = probe_res["external_egress_probe"]["rc"] != 0 or "HTTP_STATUS:200" not in probe_res["external_egress_probe"]["stdout"]
    conn_out = probe_res["connector_allowed_route_probe"]["stdout"]
    conn_blocked = probe_res["connector_allowed_route_probe"]["rc"] != 0 or (
        "HTTP_STATUS:200" not in conn_out and "HTTP_STATUS:201" not in conn_out
    )
    if not ext_ok or not conn_blocked:
        raise RuntimeError(f"SECURITY FAILURE: Detonator isolation probe failed: {probe_res}")

    return {
        "policy": policy,
        "info": info_text.strip(),
        "probe": probe_res,
    }


def setup_detonator(sprite: str = config.DETONATOR_SPRITE, *, create_checkpoint: bool = True) -> dict[str, Any]:
    created = False
    if not _sprite_exists(sprite):
        print(f"[init-detonator] Creating isolated detonator Sprite '{sprite}' (no labels)...", flush=True)
        _run([config.SPRITE_BIN, "create", "--skip-console", sprite], check=True)
        created = True

    print(f"[init-detonator] Clearing labels & enforcing private sprite URL auth on '{sprite}'...", flush=True)
    _run([config.SPRITE_BIN, "config", "update", "-s", sprite, "--clear-labels", "--url-auth", "sprite"], check=True)

    ensure_tools_installed(sprite)

    print(f"[init-detonator] Applying strict deny-all outbound network policy on '{sprite}'...", flush=True)
    _set_network_policy(sprite, [{"domain": "*", "action": "deny"}])

    verification = verify_isolation(sprite)

    checkpoint_id = None
    if create_checkpoint:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        cp_proc = _run(
            [config.SPRITE_BIN, "checkpoint", "create", "-s", sprite, "--comment", f"blastbox-detonator-clean-{ts}"],
            check=True,
        )
        m = CHECKPOINT_ID_RE.search(f"{cp_proc.stdout}\n{cp_proc.stderr}")
        checkpoint_id = m.group(1) if m else None

    return {
        "ok": True,
        "detonator_sprite": sprite,
        "created": created,
        "unlabeled": True,
        "network_policy": verification["policy"],
        "isolation_probe": verification["probe"],
        "checkpoint_created": checkpoint_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize & lock down Blastbox air-gapped detonator Sprite")
    parser.add_argument("--sprite", default=config.DETONATOR_SPRITE, help="Detonator Sprite name")
    parser.add_argument("--no-checkpoint", action="store_true", help="Skip baseline checkpoint creation")
    args = parser.parse_args()

    res = setup_detonator(args.sprite, create_checkpoint=not args.no_checkpoint)
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
