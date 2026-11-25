#!/usr/bin/env python3
"""Autonomous PR & Slack Controller Agent for Blastbox (runs on Controller Sprite).

Continuously polls the watched GitHub repository and Slack `#blastbox` channels
via zero-secret Sprites Connectors. Whenever a new PR/commit SHA or `@blastbox
boom <target>` Slack command appears, it orchestrates air-gapped detonation
inside `blastbox-detonator`, verifies generic filesystem rollback, runs LLM
triage, posts GitHub/Slack verdict reports, and updates the live dashboard.
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
import slack_bot  # noqa: E402

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
    state: dict[str, Any] = {
        "audited": {},
        "last_run_id": None,
        "slack_last_ts": {},
        "slack_handled_ts": {},
    }
    loaded_existing = False
    if state_path.exists():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("audited"), dict):
                state = loaded
                loaded_existing = True
        except (OSError, json.JSONDecodeError):
            pass

    changed = not loaded_existing
    for key in ("slack_last_ts", "slack_handled_ts"):
        if not isinstance(state.get(key), dict):
            state[key] = {}
            changed = True
    if history_path.exists():
        try:
            hist = json.loads(history_path.read_text(encoding="utf-8"))
            for run in hist.get("runs", []) if isinstance(hist, dict) else []:
                if not isinstance(run, dict):
                    continue
                target_url = str(run.get("target_url") or "")
                head_sha = str(run.get("head_sha") or "")
                run_id = str(run.get("run_id") or "seeded")
                m = PR_NUM_RE.search(target_url)
                if m and head_sha:
                    key = f"{m.group(1)}:{head_sha}"
                    if key not in state["audited"]:
                        state["audited"][key] = run_id
                        changed = True
                if run_id and run_id != "seeded":
                    state["last_run_id"] = run_id
        except (OSError, json.JSONDecodeError):
            pass

    if changed:
        _write_json_atomic(state_path, state)
    return state


def _ts_key(ts: str) -> tuple[int, int]:
    parts = ts.split(".", 1)
    try:
        sec = int(parts[0] or 0)
        sub = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return (sec, sub)
    except ValueError:
        return (0, 0)


def _poll_slack_channels(
    *,
    state: dict[str, Any],
    state_path: Path,
    sprite_ok: bool,
    sprite_err: str | None,
    controller_sprite: str,
    detonator_sprite: str,
    repo: str,
    history_path: Path,
    work_dir: Path,
    no_post: bool,
    new_runs: list[str],
    flush_fn: Any,
    cache: dict[str, Any],
    bot_user: str | None = None,
    bot_user_id: str | None = None,
) -> dict[str, Any]:
    channels = list(config.SLACK_CHANNELS)
    if not channels:
        return {
            "slack_connected": False,
            "slack_bot_user": None,
            "slack_channels": [],
            "slack_err": None,
        }

    now_mono = time.monotonic()
    backoff_until = float(cache.get("slack_backoff_until") or 0.0)
    if now_mono < backoff_until:
        return {
            "slack_connected": bool(bot_user_id or bot_user),
            "slack_bot_user": bot_user or "sprites_bot",
            "slack_channels": channels,
            "slack_err": None,
        }

    if not bot_user_id:
        try:
            auth_info = slack_bot.auth_test()
            bot_user = str(auth_info.get("user") or "sprites_bot")
            bot_user_id = str(auth_info.get("user_id") or "")
            cache["slack_auth_checked_at"] = now_mono
            cache["slack_bot_user"] = bot_user
            cache["slack_bot_user_id"] = bot_user_id
        except slack_bot.SlackRateLimitError as exc:
            cache["slack_backoff_until"] = time.monotonic() + exc.retry_after
            print(f"[blastbox-agent] Slack rate-limited on auth.test; backing off {exc.retry_after}s", flush=True)
            return {
                "slack_connected": bool(bot_user),
                "slack_bot_user": bot_user,
                "slack_channels": channels,
                "slack_err": None,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "slack_connected": False,
                "slack_bot_user": None,
                "slack_channels": channels,
                "slack_err": f"Slack auth.test failed: {str(exc)[:180]}",
            }

    bot_user = bot_user or "sprites_bot"
    slack_err: str | None = None

    for channel in channels:
        last_ts = state["slack_last_ts"].get(channel)
        if last_ts is None:
            try:
                recent = slack_bot.fetch_history(channel, limit=10)
                seed_ts = str(recent[-1].get("ts") or "0") if recent else "0"
                state["slack_last_ts"][channel] = seed_ts
                _write_json_atomic(state_path, state)
                print(f"[blastbox-agent] Seeded Slack cursor for {channel} at ts={seed_ts}", flush=True)
            except slack_bot.SlackRateLimitError as exc:
                cache["slack_backoff_until"] = time.monotonic() + exc.retry_after
                print(
                    f"[blastbox-agent] Slack rate-limited on conversations.history ({channel}); backing off {exc.retry_after}s",
                    flush=True,
                )
                break
            except Exception as exc:  # noqa: BLE001
                slack_err = f"Slack history {channel}: {str(exc)[:180]}"
            continue

        try:
            msgs = slack_bot.fetch_history(channel, oldest=last_ts, limit=25)
        except slack_bot.SlackRateLimitError as exc:
            cache["slack_backoff_until"] = time.monotonic() + exc.retry_after
            print(
                f"[blastbox-agent] Slack rate-limited on conversations.history ({channel}); backing off {exc.retry_after}s",
                flush=True,
            )
            break
        except Exception as exc:  # noqa: BLE001
            slack_err = f"Slack history {channel}: {str(exc)[:180]}"
            continue

        for msg in msgs:
            ts = str(msg.get("ts") or "")
            if not ts or _ts_key(ts) <= _ts_key(str(last_ts)):
                continue

            # Advance cursor right away so malformed messages never loop indefinitely.
            state["slack_last_ts"][channel] = ts
            last_ts = ts
            _write_json_atomic(state_path, state)

            subtype = str(msg.get("subtype") or "")
            if msg.get("bot_id") or (bot_user_id and msg.get("user") == bot_user_id) or subtype in {"bot_message", "channel_join", "channel_leave"}:
                continue

            cmd = slack_bot.parse_boom_command(str(msg.get("text") or ""), bot_user_id=bot_user_id)
            if not cmd:
                continue

            dedup_key = f"{channel}:{ts}"
            if dedup_key in state["slack_handled_ts"]:
                continue

            raw_target = cmd["target"]
            slack_bot.add_reaction(channel, ts, "bomb")

            if not sprite_ok:
                err_msg = sprite_err or "controller Sprite CLI is not authenticated"
                try:
                    slack_bot.post_message(
                        channel,
                        f":warning: Cannot detonate `{raw_target}`: controller `{controller_sprite}` sprite CLI is unauthenticated (`{err_msg}`).",
                        thread_ts=ts,
                    )
                except Exception:  # noqa: BLE001
                    pass
                state["slack_handled_ts"][dedup_key] = "error:sprite-auth"
                _write_json_atomic(state_path, state)
                continue

            target_arg, resolved_mode, target_no_post = slack_bot.resolve_boom_target(raw_target, work_dir)
            effective_no_post = bool(no_post or target_no_post)
            job_label = f"Slack {resolved_mode.upper()}: {raw_target[:48]}"
            print(f"[blastbox-agent] {job_label} (channel={channel}, ts={ts})", flush=True)
            flush_fn(active_job=job_label)

            try:
                slack_bot.post_message(
                    channel,
                    f":bomb: Detonating `{raw_target}` (`{resolved_mode}`) inside air-gapped Sprite `{detonator_sprite}`...",
                    thread_ts=ts,
                )
            except Exception as exc:  # noqa: BLE001
                slack_err = f"Slack thread ack failed: {str(exc)[:180]}"

            state["slack_handled_ts"][dedup_key] = "running"
            _write_json_atomic(state_path, state)

            try:
                summary = blastbox.run_audit(
                    target_arg,
                    mode=resolved_mode,
                    controller_sprite=controller_sprite,
                    detonator_sprite=detonator_sprite,
                    repo=repo,
                    output_dir=work_dir / "last_run",
                    history_path=history_path,
                    no_post=effective_no_post,
                    no_dashboard_sync=False,
                    local_controller=True,
                )
                run_id = str(summary.get("run_id") or "")
                state["slack_handled_ts"][dedup_key] = run_id or "done"
                if run_id:
                    state["last_run_id"] = run_id
                    new_runs.append(run_id)
                _write_json_atomic(state_path, state)

                fallback, blocks = slack_bot.format_slack_verdict(summary, config.PUBLIC_URL)
                slack_bot.post_message(channel, fallback, thread_ts=ts, blocks=blocks)
            except Exception as exc:  # noqa: BLE001
                err_text = config.redact_host_paths(str(exc))[:240]
                slack_err = err_text
                state["slack_handled_ts"][dedup_key] = f"error:{err_text[:80]}"
                _write_json_atomic(state_path, state)
                print(f"[blastbox-agent] Slack audit error on {raw_target}: {err_text}", flush=True)
                try:
                    slack_bot.post_message(
                        channel,
                        f":x: Audit rejected or failed before verdict for `{raw_target}`: `{err_text}`",
                        thread_ts=ts,
                    )
                except Exception:  # noqa: BLE001
                    pass

    return {
        "slack_connected": True,
        "slack_bot_user": bot_user,
        "slack_channels": channels,
        "slack_err": slack_err,
    }


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
    poll_prs: bool = True,
    poll_slack: bool = True,
    cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if cache is None:
        cache = {}
    state = _load_or_seed_state(state_path, history_path)
    sprite_ok, sprite_err = _check_sprite_cli_ready(detonator_sprite)

    open_prs: list[dict[str, Any]] = list(cache.get("open_prs") or [])
    gh_err: str | None = cache.get("gh_err")
    if poll_prs or "open_prs" not in cache:
        open_prs = []
        gh_err = None
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
        cache["open_prs"] = list(open_prs)
        cache["gh_err"] = gh_err

    now_mono = time.monotonic()
    auth_checked_at = float(cache.get("slack_auth_checked_at") or 0.0)
    backoff_until = float(cache.get("slack_backoff_until") or 0.0)
    slack_meta: dict[str, Any] = dict(cache.get("slack_meta") or {})
    if poll_slack and config.SLACK_CHANNELS:
        need_auth = (
            not slack_meta.get("slack_connected")
            or not cache.get("slack_bot_user_id")
            or (now_mono - auth_checked_at) >= 900.0
        )
        if need_auth and now_mono >= backoff_until:
            try:
                auth_info = slack_bot.auth_test()
                cache["slack_auth_checked_at"] = now_mono
                cache["slack_bot_user"] = str(auth_info.get("user") or "sprites_bot")
                cache["slack_bot_user_id"] = str(auth_info.get("user_id") or "")
                slack_meta = {
                    "slack_connected": True,
                    "slack_bot_user": cache["slack_bot_user"],
                    "slack_channels": list(config.SLACK_CHANNELS),
                    "slack_err": None,
                }
            except slack_bot.SlackRateLimitError as exc:
                cache["slack_backoff_until"] = now_mono + exc.retry_after
                print(f"[blastbox-agent] Slack rate-limited on auth.test; backing off {exc.retry_after}s", flush=True)
                slack_meta = {
                    "slack_connected": bool(slack_meta.get("slack_connected")),
                    "slack_bot_user": cache.get("slack_bot_user"),
                    "slack_channels": list(config.SLACK_CHANNELS),
                    "slack_err": None,
                }
            except Exception as exc:  # noqa: BLE001
                slack_meta = {
                    "slack_connected": False,
                    "slack_bot_user": None,
                    "slack_channels": list(config.SLACK_CHANNELS),
                    "slack_err": f"Slack auth.test failed: {str(exc)[:180]}",
                }
            cache["slack_meta"] = dict(slack_meta)

    new_runs: list[str] = []

    def _flush_status(*, active_job: str | None = None, last_error: str | None = None) -> dict[str, Any]:
        slack_err = slack_meta.get("slack_err")
        payload = {
            "ok": True,
            "mode": "autonomous-pr-and-slack-watcher",
            "controller_sprite": controller_sprite,
            "detonator_sprite": detonator_sprite,
            "watched_repo": repo,
            "poll_interval_seconds": config.POLL_INTERVAL_SECONDS,
            "slack_poll_interval_seconds": config.SLACK_POLL_INTERVAL_SECONDS,
            "sprite_cli_authenticated": sprite_ok,
            "sprite_cli_note": None if sprite_ok else f"Run 'sprite console -s {controller_sprite}' then 'sprite login' to enable autonomous detonator control",
            "slack_connected": bool(slack_meta.get("slack_connected")),
            "slack_bot_user": slack_meta.get("slack_bot_user"),
            "slack_channels": list(slack_meta.get("slack_channels") or config.SLACK_CHANNELS),
            "slack_commands_handled": len(state.get("slack_handled_ts") or {}),
            "active_job": active_job,
            "last_poll_utc": _now_utc(),
            "open_prs_seen": [
                {"number": p["number"], "head_ref": p["head_ref"], "head_sha": str(p["head_sha"])[:10]}
                for p in open_prs
            ],
            "audited_commits_count": len(state.get("audited") or {}),
            "last_audited_run_id": state.get("last_run_id"),
            "new_runs_this_cycle": new_runs,
            "last_error": last_error or gh_err or slack_err,
        }
        _write_json_atomic(status_path, payload)
        return payload

    # Flush immediately so /health reflects auth & connector readiness before detonations run
    _flush_status(active_job=None)

    run_err: str | None = None
    if poll_prs and sprite_ok and not gh_err:
        for pr in open_prs:
            pr_num = pr.get("number")
            head_sha = pr.get("head_sha")
            pr_url = pr.get("html_url")
            if not pr_num or not head_sha or not pr_url:
                continue
            key = f"{pr_num}:{head_sha}"
            if key in state["audited"]:
                continue
            job_label = f"Auditing {repo}#{pr_num} @ {str(head_sha)[:10]}"
            print(f"[blastbox-agent] {job_label}...", flush=True)
            _flush_status(active_job=job_label)
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
    elif poll_prs and not sprite_ok:
        print(
            f"[blastbox-agent] Sprite CLI auth pending on controller '{controller_sprite}': {sprite_err}",
            flush=True,
        )

    if poll_slack and config.SLACK_CHANNELS:
        slack_meta = _poll_slack_channels(
            state=state,
            state_path=state_path,
            sprite_ok=sprite_ok,
            sprite_err=sprite_err,
            controller_sprite=controller_sprite,
            detonator_sprite=detonator_sprite,
            repo=repo,
            history_path=history_path,
            work_dir=work_dir,
            no_post=no_post,
            new_runs=new_runs,
            flush_fn=_flush_status,
            cache=cache,
            bot_user=cache.get("slack_bot_user"),
            bot_user_id=cache.get("slack_bot_user_id"),
        )
        cache["slack_meta"] = dict(slack_meta)

    return _flush_status(active_job=None, last_error=run_err)


def main() -> int:
    parser = argparse.ArgumentParser(description="Blastbox Autonomous PR & Slack Controller Agent")
    parser.add_argument("--repo", default=config.DEFAULT_REPO)
    parser.add_argument("--controller-sprite", default=config.CONTROLLER_SPRITE)
    parser.add_argument("--detonator-sprite", default=config.DETONATOR_SPRITE)
    parser.add_argument("--history-file", type=Path, default=Path("/home/sprite/blastbox-web/history.json"))
    parser.add_argument("--status-file", type=Path, default=Path("/home/sprite/blastbox-web/agent_status.json"))
    parser.add_argument("--state-file", type=Path, default=SCRIPT_DIR / "agent_state.json")
    parser.add_argument("--work-dir", type=Path, default=SCRIPT_DIR)
    parser.add_argument("--interval", type=int, default=config.POLL_INTERVAL_SECONDS)
    parser.add_argument("--slack-interval", type=int, default=config.SLACK_POLL_INTERVAL_SECONDS)
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")
    parser.add_argument("--no-post", action="store_true", help="Skip GitHub commenting during poll")
    args = parser.parse_args()

    stopping = False

    def _handle_sig(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    slack_channels = ",".join(config.SLACK_CHANNELS) or "none"
    print(
        f"[blastbox-agent] Starting autonomous PR + Slack watcher on controller '{args.controller_sprite}' "
        f"-> detonator '{args.detonator_sprite}' (repo={args.repo}, pr_interval={args.interval}s, "
        f"slack_channels={slack_channels}, slack_interval={args.slack_interval}s)",
        flush=True,
    )

    poll_cache: dict[str, Any] = {}
    next_pr_poll = 0.0

    while not stopping:
        now = time.monotonic()
        do_pr = now >= next_pr_poll
        if do_pr:
            next_pr_poll = now + max(1, args.interval)
        status = run_poll_cycle(
            repo=args.repo,
            controller_sprite=args.controller_sprite,
            detonator_sprite=args.detonator_sprite,
            history_path=args.history_file,
            state_path=args.state_file,
            status_path=args.status_file,
            work_dir=args.work_dir,
            no_post=args.no_post,
            poll_prs=do_pr,
            poll_slack=True,
            cache=poll_cache,
        )
        if args.once:
            print(json.dumps(status, indent=2))
            return 0
        for _ in range(max(1, args.slack_interval)):
            if stopping:
                break
            time.sleep(1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
