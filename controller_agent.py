#!/usr/bin/env python3
"""Autonomous PR-watching Controller Agent for Blastbox (runs on Controller Sprite).

Continuously polls the watched GitHub repository via the zero-secret Sprites
GitHub Connector. Whenever a new pull request or new commit SHA appears, it
orchestrates air-gapped detonation inside `blastbox-detonator`, verifies generic
filesystem rollback, runs LLM triage, posts the GitHub PR audit comment, and
updates the live dashboard history.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import blastbox  # noqa: E402
import config  # noqa: E402

PR_NUM_RE = re.compile(r"/pull/(\d+)(?:$|[/?#])")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(config.sanitize_value(data), indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _check_sprite_cli_ready(detonator_sprite: str) -> tuple[bool, str | None]:
    if not Path(config.SPRITE_BIN).exists():
        return False, f"sprite binary not found at {config.SPRITE_BIN}"
    try:
        org_proc = subprocess.run(
            [config.SPRITE_BIN, "org", "list"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if org_proc.returncode != 0 or "No organizations" in (org_proc.stdout + org_proc.stderr):
            err = (org_proc.stderr or org_proc.stdout or "").strip()
            return False, err[:240] or "sprite CLI not authenticated on controller Sprite"
        proc = subprocess.run(
            [config.SPRITE_BIN, "info", detonator_sprite],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return True, None
        err = (proc.stderr or proc.stdout or "").strip()
        return False, err[:240] or "sprite CLI not authenticated on controller Sprite"
    except subprocess.TimeoutExpired:
        return False, "sprite CLI auth check timed out (awaiting sprite login)"


def _fetch_open_prs(repo: str) -> list[dict[str, Any]]:
    url = f"{config.GITHUB_GATEWAY}/repos/{repo}/pulls?state=open&per_page=20"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "blastbox-controller-agent/2.0",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
    return parsed if isinstance(parsed, list) else []


def _load_or_seed_state(state_path: Path, history_path: Path) -> dict[str, Any]:
    if state_path.exists():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("audited"), dict):
                return loaded
        except (OSError, json.JSONDecodeError):
            pass

    audited: dict[str, str] = {}
    if history_path.exists():
        try:
            hist = json.loads(history_path.read_text(encoding="utf-8"))
            for run in hist.get("runs", []) if isinstance(hist, dict) else []:
                if not isinstance(run, dict):
                    continue
                target_url = str(run.get("target_url") or "")
                head_sha = str(run.get("head_sha") or "")
                m = PR_NUM_RE.search(target_url)
                if m and head_sha:
                    audited[f"{m.group(1)}:{head_sha}"] = str(run.get("run_id") or "seeded")
        except (OSError, json.JSONDecodeError):
            pass

    state = {"audited": audited, "last_run_id": None}
    _write_json_atomic(state_path, state)
    return state


def run_poll_cycle(
    *,
    repo: str,
    controller_sprite: str,
    detonator_sprite: str,
    history_path: Path,
    state_path: Path,
    status_path: Path,
    work_dir: Path,
    no_post: bool = False,
) -> dict[str, Any]:
    state = _load_or_seed_state(state_path, history_path)
    sprite_ok, sprite_err = _check_sprite_cli_ready(detonator_sprite)

    open_prs: list[dict[str, Any]] = []
    gh_err: str | None = None
    try:
        raw_prs = _fetch_open_prs(repo)
        for pr in raw_prs:
            if not isinstance(pr, dict):
                continue
            head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
            open_prs.append(
                {
                    "number": pr.get("number"),
                    "title": pr.get("title"),
                    "head_ref": head.get("ref"),
                    "head_sha": head.get("sha"),
                    "html_url": pr.get("html_url"),
                }
            )
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
        gh_err = str(exc)[:240]

    new_runs: list[str] = []
    run_err: str | None = None
    if sprite_ok and not gh_err:
        for pr in open_prs:
            pr_num = pr.get("number")
            head_sha = pr.get("head_sha")
            pr_url = pr.get("html_url")
            if not pr_num or not head_sha or not pr_url:
                continue
            key = f"{pr_num}:{head_sha}"
            if key in state["audited"]:
                continue
            print(
                f"[blastbox-agent] Auditing new PR commit {repo}#{pr_num} @ {str(head_sha)[:10]}...",
                flush=True,
            )
            try:
                summary = blastbox.run_audit(
                    str(pr_url),
                    mode="pr",
                    controller_sprite=controller_sprite,
                    detonator_sprite=detonator_sprite,
                    repo=repo,
                    output_dir=work_dir / "last_run",
                    history_path=history_path,
                    no_post=no_post,
                    no_dashboard_sync=False,
                    local_controller=True,
                )
                run_id = str(summary.get("run_id") or "")
                state["audited"][key] = run_id
                state["last_run_id"] = run_id
                new_runs.append(run_id)
                _write_json_atomic(state_path, state)
            except Exception as exc:  # noqa: BLE001
                run_err = str(exc)[:280]
                print(f"[blastbox-agent] Audit error on PR #{pr_num}: {run_err}", flush=True)
    elif not sprite_ok:
        print(
            f"[blastbox-agent] Sprite CLI auth pending on controller '{controller_sprite}': {sprite_err}",
            flush=True,
        )

    status = {
        "ok": True,
        "mode": "autonomous-pr-watcher",
        "controller_sprite": controller_sprite,
        "detonator_sprite": detonator_sprite,
        "watched_repo": repo,
        "poll_interval_seconds": config.POLL_INTERVAL_SECONDS,
        "sprite_cli_authenticated": sprite_ok,
        "sprite_cli_note": None if sprite_ok else f"Run 'sprite console -s {controller_sprite}' then 'sprite login' to enable autonomous detonator control",
        "last_poll_utc": _now_utc(),
        "open_prs_seen": [
            {"number": p["number"], "head_ref": p["head_ref"], "head_sha": str(p["head_sha"])[:10]}
            for p in open_prs
        ],
        "audited_commits_count": len(state.get("audited") or {}),
        "last_audited_run_id": state.get("last_run_id"),
        "new_runs_this_cycle": new_runs,
        "last_error": run_err or gh_err,
    }
    _write_json_atomic(status_path, status)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Blastbox Autonomous PR-Watching Controller Agent")
    parser.add_argument("--repo", default=config.DEFAULT_REPO)
    parser.add_argument("--controller-sprite", default=config.CONTROLLER_SPRITE)
    parser.add_argument("--detonator-sprite", default=config.DETONATOR_SPRITE)
    parser.add_argument("--history-file", type=Path, default=Path("/home/sprite/blastbox-web/history.json"))
    parser.add_argument("--status-file", type=Path, default=Path("/home/sprite/blastbox-web/agent_status.json"))
    parser.add_argument("--state-file", type=Path, default=SCRIPT_DIR / "agent_state.json")
    parser.add_argument("--work-dir", type=Path, default=SCRIPT_DIR)
    parser.add_argument("--interval", type=int, default=config.POLL_INTERVAL_SECONDS)
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")
    parser.add_argument("--no-post", action="store_true", help="Skip GitHub commenting during poll")
    args = parser.parse_args()

    stopping = False

    def _handle_sig(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    print(
        f"[blastbox-agent] Starting autonomous PR watcher on controller '{args.controller_sprite}' "
        f"-> detonator '{args.detonator_sprite}' (repo={args.repo}, interval={args.interval}s)",
        flush=True,
    )

    while not stopping:
        status = run_poll_cycle(
            repo=args.repo,
            controller_sprite=args.controller_sprite,
            detonator_sprite=args.detonator_sprite,
            history_path=args.history_file,
            state_path=args.state_file,
            status_path=args.status_file,
            work_dir=args.work_dir,
            no_post=args.no_post,
        )
        if args.once:
            print(json.dumps(status, indent=2))
            return 0
        for _ in range(max(1, args.interval)):
            if stopping:
                break
            time.sleep(1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
