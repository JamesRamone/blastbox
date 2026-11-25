#!/usr/bin/env python3
"""Deploy Blastbox Controller Agent + Public Dashboard onto Controller Sprite.

Deploys the controller scripts, public web console, optional `.env`, sanitized
history, and the standalone static `sprite` CLI binary into the Controller
Sprite, auto-creating the Sprite if absent, registering `blastbox-web` (port 8080,
`--url-auth public`) and `blastbox-agent`, ensuring `config.CONTROLLER_LABEL` is
set on the controller, and verifying `/health` and `/` return HTTP 200.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import config  # noqa: E402
import init_dashboard  # noqa: E402


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def _sprite_exists(sprite: str) -> bool:
    proc = subprocess.run([config.SPRITE_BIN, "info", sprite], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def _validate_dotenv_has_no_secrets(env_path: Path) -> None:
    text = env_path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key in config.FORBIDDEN_ENV_VARS:
            raise RuntimeError(f"SECURITY FAILURE: Forbidden raw secret key {key!r} found in {env_path}")


def setup_controller(
    *,
    controller_sprite: str = config.CONTROLLER_SPRITE,
    detonator_sprite: str = config.DETONATOR_SPRITE,
    history_path: Path = SCRIPT_DIR / "history.json",
    public_url: str = config.PUBLIC_URL,
    create_checkpoint: bool = False,
) -> dict[str, Any]:
    if not _sprite_exists(controller_sprite):
        print(f"[init-controller] Creating controller Sprite '{controller_sprite}'...", flush=True)
        _run([config.SPRITE_BIN, "create", "--skip-console", controller_sprite], check=True)

    # Ensure controller Sprite carries the Connector label and public URL auth
    _run(
        [
            config.SPRITE_BIN,
            "config",
            "update",
            "-s",
            controller_sprite,
            "--label",
            config.CONTROLLER_LABEL,
            "--url-auth",
            "public",
        ],
        check=True,
    )
    resolved_public_url = public_url or config.detect_sprite_url(controller_sprite)

    # Deploy public dashboard service first
    dash_res = init_dashboard.setup_dashboard(
        sprite=controller_sprite,
        history_path=history_path,
        public_url=resolved_public_url,
        create_checkpoint=False,
    )

    # Push agent code & static sprite CLI onto controller
    _run(
        [
            config.SPRITE_BIN,
            "exec",
            "-s",
            controller_sprite,
            "--no-stdin",
            "--",
            "bash",
            "-c",
            "rm -rf /home/sprite/blastbox-agent/fixtures && mkdir -p /home/sprite/blastbox-agent /home/sprite/.local/bin",
        ],
        check=True,
    )

    agent_files = [
        ("config.py", "config.py"),
        ("url_guard.py", "url_guard.py"),
        ("agent_planner.py", "agent_planner.py"),
        ("blastbox.py", "blastbox.py"),
        ("extract_iocs.py", "extract_iocs.py"),
        ("mcp_probe.py", "mcp_probe.py"),
        ("slack_bot.py", "slack_bot.py"),
        ("sprite_triage.py", "sprite_triage.py"),
        ("init_dashboard.py", "init_dashboard.py"),
        ("controller_agent.py", "controller_agent.py"),
        ("web/agent_run.sh", "agent_run.sh"),
    ]
    for src_rel, dst_name in agent_files:
        src = SCRIPT_DIR / src_rel
        _run(
            [
                config.SPRITE_BIN,
                "file",
                "push",
                "-s",
                controller_sprite,
                "-p",
                str(src),
                f"/home/sprite/blastbox-agent/{dst_name}",
            ],
            check=True,
        )

    dotenv_local = SCRIPT_DIR / ".env"
    if dotenv_local.is_file():
        _validate_dotenv_has_no_secrets(dotenv_local)
        _run(
            [
                config.SPRITE_BIN,
                "file",
                "push",
                "-s",
                controller_sprite,
                "-p",
                str(dotenv_local),
                "/home/sprite/blastbox-agent/.env",
            ],
            check=True,
        )

    fixtures_dir = SCRIPT_DIR / "fixtures"
    if fixtures_dir.is_dir():
        _run(
            [
                config.SPRITE_BIN,
                "file",
                "push",
                "-s",
                controller_sprite,
                "-r",
                "-p",
                str(fixtures_dir),
                "/home/sprite/blastbox-agent/fixtures",
            ],
            check=True,
        )

    remote_check = _run(
        [
            config.SPRITE_BIN,
            "exec",
            "-s",
            controller_sprite,
            "--no-stdin",
            "--",
            "bash",
            "-c",
            "test -x /home/sprite/.local/bin/sprite && echo OK || echo MISSING",
        ],
        check=True,
    )
    if "MISSING" in remote_check.stdout:
        print(f"[init-controller] Installing sprite CLI directly inside '{controller_sprite}' via sprites.dev/install.sh...", flush=True)
        _run(
            [
                config.SPRITE_BIN,
                "exec",
                "-s",
                controller_sprite,
                "--no-stdin",
                "--",
                "bash",
                "-c",
                "SPRITE_INSTALL_BIN_DIR=/home/sprite/.local/bin curl -fsSL https://sprites.dev/install.sh | sh",
            ],
            check=True,
        )

    svc_cmd = (
        'export PATH="/home/sprite/.local/bin:/.sprite/bin:$PATH"; '
        "chmod +x /home/sprite/blastbox-agent/agent_run.sh /home/sprite/.local/bin/sprite; "
        "sprite-env services delete blastbox-agent 2>/dev/null || true; "
        "sprite-env services create blastbox-agent "
        "--cmd /home/sprite/blastbox-agent/agent_run.sh "
        "--dir /home/sprite/blastbox-agent "
        "--no-stream"
    )
    _run([config.SPRITE_BIN, "exec", "-s", controller_sprite, "--no-stdin", "--", "bash", "-c", svc_cmd], check=True)

    # Check if sprite CLI inside controller already has org auth for detonator control
    auth_check = _run(
        [
            config.SPRITE_BIN,
            "exec",
            "-s",
            controller_sprite,
            "--no-stdin",
            "--",
            "bash",
            "-c",
            f"timeout 8s /home/sprite/.local/bin/sprite info {detonator_sprite} </dev/null >/dev/null 2>&1 && echo AUTH_OK || echo AUTH_PENDING",
        ],
        check=True,
    )
    cli_authenticated = "AUTH_OK" in auth_check.stdout

    # Run one synchronous poll cycle to populate agent_status.json immediately
    _run(
        [
            config.SPRITE_BIN,
            "exec",
            "-s",
            controller_sprite,
            "--no-stdin",
            "--",
            "bash",
            "-c",
            (
                'export PATH="/home/sprite/.local/bin:/.sprite/bin:$PATH"; '
                "PYTHONPATH=/home/sprite/blastbox-agent /.sprite/bin/python3 /home/sprite/blastbox-agent/controller_agent.py "
                "--once --history-file /home/sprite/blastbox-web/history.json "
                "--status-file /home/sprite/blastbox-web/agent_status.json "
                "--state-file /home/sprite/blastbox-agent/agent_state.json "
                "--work-dir /home/sprite/blastbox-agent >/dev/null"
            ),
        ],
        check=True,
    )

    if create_checkpoint:
        _run([config.SPRITE_BIN, "checkpoint", "create", "-s", controller_sprite, "--comment", "blastbox-controller-ready"], check=True)

    return {
        "ok": True,
        "controller_sprite": controller_sprite,
        "detonator_sprite": detonator_sprite,
        "public_url": public_url,
        "services": ["blastbox-web", "blastbox-agent"],
        "sprite_cli_authenticated_on_controller": cli_authenticated,
        "next_step_if_auth_pending": (
            None
            if cli_authenticated
            else f"sprite console -s {controller_sprite}  # then run: sprite login && sprite-env services restart blastbox-agent"
        ),
        "dashboard": dash_res,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy Blastbox Controller Agent + Web Console")
    parser.add_argument("--controller-sprite", default=config.CONTROLLER_SPRITE)
    parser.add_argument("--detonator-sprite", default=config.DETONATOR_SPRITE)
    parser.add_argument("--history", type=Path, default=SCRIPT_DIR / "history.json")
    parser.add_argument("--public-url", default=config.PUBLIC_URL)
    parser.add_argument("--checkpoint", action="store_true")
    args = parser.parse_args()

    res = setup_controller(
        controller_sprite=args.controller_sprite,
        detonator_sprite=args.detonator_sprite,
        history_path=args.history.resolve(),
        public_url=args.public_url,
        create_checkpoint=args.checkpoint,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
