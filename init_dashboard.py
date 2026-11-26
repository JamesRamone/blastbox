#!/usr/bin/env python3
"""Idempotent setup & sync helper for Blastbox's public :8080 status dashboard.

Deploys `web/server.py`, `web/run.sh`, and sanitized `history.json` into
`/home/sprite/blastbox-web/` on the trusted Controller Sprite, registers the
persistent `blastbox-web` service on port 8080, configures `--url-auth public`,
and verifies `GET /health` and `GET /` return HTTP 200.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import config  # noqa: E402

DEFAULT_PUBLIC_URL = config.PUBLIC_URL
DEFAULT_HISTORY_PATH = SCRIPT_DIR / "history.json"
CHECKPOINT_ID_RE = re.compile(r"\b(v\d+)\b")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def sanitize_value(obj: Any) -> Any:
    return config.sanitize_value(obj)


def load_or_init_history(
    history_path: Path = DEFAULT_HISTORY_PATH,
    sprite_name: str = config.CONTROLLER_SPRITE,
    detonator_sprite: str = config.DETONATOR_SPRITE,
    public_url: str = DEFAULT_PUBLIC_URL,
) -> dict[str, Any]:
    if history_path.exists():
        raw = json.loads(history_path.read_text(encoding="utf-8"))
        data = sanitize_value(raw) if isinstance(raw, dict) else {}
    else:
        data = {}
    if not isinstance(data.get("runs"), list):
        data["runs"] = []
    data["schema_version"] = 2
    data["sprite_name"] = sprite_name
    data["detonator_sprite"] = detonator_sprite
    data["public_url"] = public_url
    data.setdefault("updated_at", _now_utc())
    history_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def sync_history_to_sprite(
    sprite: str,
    history_path: Path = DEFAULT_HISTORY_PATH,
) -> dict[str, Any]:
    data = load_or_init_history(history_path, sprite_name=sprite)
    # Merge the controller's history first so runs recorded by the controller agent
    # (Slack / PR watcher) since the last sync are kept instead of overwritten.
    with tempfile.TemporaryDirectory() as tmpdir:
        remote_path = Path(tmpdir) / "remote_history.json"
        pulled = _run(
            [config.SPRITE_BIN, "file", "pull", "-s", sprite, "/home/sprite/blastbox-web/history.json", str(remote_path)],
            check=False,
        )
        remote_runs: list[Any] = []
        if pulled.returncode == 0 and remote_path.is_file():
            try:
                remote = json.loads(remote_path.read_text(encoding="utf-8"))
                remote_runs = remote.get("runs") or [] if isinstance(remote, dict) else []
            except json.JSONDecodeError:
                remote_runs = []
    merged: dict[str, Any] = {}
    for run in [*remote_runs, *data["runs"]]:
        if isinstance(run, dict) and run.get("run_id"):
            merged[str(run["run_id"])] = run
    runs = sorted(merged.values(), key=lambda r: str(r.get("timestamp_utc") or ""))
    data["runs"] = sanitize_value(runs[-config.MAX_HISTORY_RUNS :])
    if data["runs"]:
        data["updated_at"] = max(data.get("updated_at") or "", str(data["runs"][-1].get("timestamp_utc") or ""))
    history_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(history_path), "/home/sprite/blastbox-web/history.json"])
    return data


def wait_for_public_health(public_url: str, timeout_s: int = 25) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    health_url = f"{public_url.rstrip('/')}/health"
    last_err = ""
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(health_url, headers={"Accept": "application/json", "User-Agent": "blastbox-init/2.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if resp.status == 200:
                    parsed = json.loads(raw)
                    if parsed.get("ok") is True:
                        return parsed
                last_err = f"HTTP {resp.status}: {raw[:200]}"
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
            last_err = str(exc)
        time.sleep(1.5)
    raise RuntimeError(f"Timed out waiting for {health_url} HTTP 200: {last_err}")


def setup_dashboard(
    sprite: str = config.CONTROLLER_SPRITE,
    history_path: Path = DEFAULT_HISTORY_PATH,
    public_url: str = DEFAULT_PUBLIC_URL,
    create_checkpoint: bool = False,
) -> dict[str, Any]:
    public_url = public_url or config.detect_sprite_url(sprite)
    if not public_url:
        raise RuntimeError(f"Could not determine public URL for controller Sprite '{sprite}'. Set BLASTBOX_PUBLIC_URL.")

    server_local = SCRIPT_DIR / "web" / "server.py"
    run_local = SCRIPT_DIR / "web" / "run.sh"
    config_local = SCRIPT_DIR / "config.py"
    if not server_local.exists() or not run_local.exists():
        raise FileNotFoundError("Missing web/server.py or web/run.sh")

    _run([config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "bash", "-c", "mkdir -p /home/sprite/blastbox-web/assets"])
    _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(server_local), "/home/sprite/blastbox-web/server.py"])
    _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(run_local), "/home/sprite/blastbox-web/run.sh"])
    _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(config_local), "/home/sprite/blastbox-web/config.py"])
    dotenv_local = SCRIPT_DIR / ".env"
    if dotenv_local.is_file():
        _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(dotenv_local), "/home/sprite/blastbox-web/.env"])

    if history_path.exists():
        history = load_or_init_history(history_path, sprite_name=sprite, public_url=public_url)
        _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(history_path), "/home/sprite/blastbox-web/history.json"])
    else:
        has_remote = _run(
            [config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "bash", "-c", "test -f /home/sprite/blastbox-web/history.json && echo YES || echo NO"],
            check=True,
        )
        if "YES" in has_remote.stdout:
            pulled = _run([config.SPRITE_BIN, "file", "pull", "-s", sprite, "/home/sprite/blastbox-web/history.json", str(history_path)], check=False)
            history = load_or_init_history(history_path, sprite_name=sprite, public_url=public_url) if pulled.returncode == 0 else {"runs": []}
        else:
            history = load_or_init_history(history_path, sprite_name=sprite, public_url=public_url)
            _run([config.SPRITE_BIN, "file", "push", "-s", sprite, "-p", str(history_path), "/home/sprite/blastbox-web/history.json"])
    turkey_asset = SCRIPT_DIR / "docs" / "hacksgiving-turkey.png"
    if turkey_asset.is_file():
        _run(
            [
                config.SPRITE_BIN,
                "file",
                "push",
                "-s",
                sprite,
                "-p",
                str(turkey_asset),
                "/home/sprite/blastbox-web/assets/hacksgiving-turkey.png",
            ]
        )

    service_cmd = (
        'export PATH="/.sprite/bin:$PATH"; '
        "chmod +x /home/sprite/blastbox-web/run.sh /home/sprite/blastbox-web/server.py; "
        "sprite-env services delete blastbox-web 2>/dev/null || true; "
        "sprite-env services create blastbox-web "
        "--cmd /home/sprite/blastbox-web/run.sh "
        "--dir /home/sprite/blastbox-web "
        "--http-port 8080 "
        "--no-stream"
    )
    _run([config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin", "--", "bash", "-c", service_cmd])

    _run([config.SPRITE_BIN, "config", "update", "-s", sprite, "--url-auth", "public"])

    health = wait_for_public_health(public_url, timeout_s=25)
    if not health.get("zero_secrets_in_env"):
        raise RuntimeError(f"SECURITY FAILURE: /health reported zero_secrets_in_env={health.get('zero_secrets_in_env')}")

    root_req = urllib.request.Request(public_url.rstrip("/") + "/", headers={"User-Agent": "blastbox-init/2.0"})
    with urllib.request.urlopen(root_req, timeout=10) as resp:
        root_status = resp.status
        root_body = resp.read().decode("utf-8", errors="replace")
    if root_status != 200 or "blastbox" not in root_body.lower():
        raise RuntimeError(f"Unexpected root response from {public_url}: HTTP {root_status}")

    checkpoint_id = None
    if create_checkpoint:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        cp_proc = _run([config.SPRITE_BIN, "checkpoint", "create", "-s", sprite, "--comment", f"blastbox-web-baseline-{ts}"])
        m = CHECKPOINT_ID_RE.search(f"{cp_proc.stdout}\n{cp_proc.stderr}")
        checkpoint_id = m.group(1) if m else None

    return {
        "ok": True,
        "sprite": sprite,
        "public_url": public_url,
        "url_auth": "public",
        "health": health,
        "root_http_status": root_status,
        "runs_count": len(history["runs"]),
        "checkpoint_created": checkpoint_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize Blastbox :8080 public dashboard on Controller Sprite")
    parser.add_argument("--sprite", default=config.CONTROLLER_SPRITE, help="Controller Sprite name")
    parser.add_argument("--history", type=Path, default=DEFAULT_HISTORY_PATH, help="Canonical history.json path")
    parser.add_argument("--public-url", default=DEFAULT_PUBLIC_URL, help="Public Sprite URL")
    parser.add_argument("--checkpoint", action="store_true", help="Create snapshot checkpoint on controller")
    args = parser.parse_args()

    result = setup_dashboard(
        sprite=args.sprite,
        history_path=args.history.resolve(),
        public_url=args.public_url,
        create_checkpoint=args.checkpoint,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
