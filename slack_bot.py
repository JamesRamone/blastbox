#!/usr/bin/env python3
"""Zero-secret Slack Bot Connector client and `@blastbox boom` parser.

Communicates exclusively through the Sprites Slack Gateway
(`https://api.sprites.dev/v1/gateway/slack_bot/<connector_id>/...`) with zero
raw Slack bot tokens stored inside any Sprite VM.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import config

SLACK_LINK_RE = re.compile(r"<(https?://[^|>]+)(?:\|[^>]+)?>")
PR_URL_RE = re.compile(r"^https?://github\.com/[^/]+/[^/]+/pull/\d+(?:/.*)?$")


class SlackRateLimitError(RuntimeError):
    """Raised when Slack returns HTTP 429 rate limiting with a Retry-After delay."""

    def __init__(self, retry_after: int, message: str) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def _slack_request(
    method: str,
    api_method: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    url = f"{config.SLACK_GATEWAY.rstrip('/')}/{api_method.lstrip('/')}"
    if params:
        filtered = {k: v for k, v in params.items() if v is not None}
        if filtered:
            url = f"{url}?{urllib.parse.urlencode(filtered)}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "blastbox-slack/1.0",
    }
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        if err.code == 429:
            try:
                raw_ra = int(str(err.headers.get("Retry-After") or "60").strip())
            except (TypeError, ValueError):
                raw_ra = 60
            retry_after = max(10, min(300, raw_ra))
            raise SlackRateLimitError(
                retry_after,
                f"Slack gateway HTTP 429 on {api_method} (retry after {retry_after}s): {raw[:200]}",
            ) from err
        raise RuntimeError(f"Slack gateway HTTP {err.code} on {api_method}: {raw[:240]}") from err

    if not isinstance(parsed, dict):
        raise RuntimeError(f"Unexpected Slack response on {api_method}: {str(parsed)[:200]}")
    if not parsed.get("ok"):
        if parsed.get("error") == "ratelimited":
            raise SlackRateLimitError(60, f"Slack API ratelimited on {api_method}")
        raise RuntimeError(f"Slack API error on {api_method}: {parsed.get('error') or parsed}")
    return parsed


def auth_test() -> dict[str, Any]:
    return _slack_request("GET", "auth.test")


def fetch_history(
    channel: str,
    *,
    oldest: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    res = _slack_request(
        "GET",
        "conversations.history",
        params={"channel": channel, "oldest": oldest, "limit": limit},
    )
    msgs = res.get("messages")
    if not isinstance(msgs, list):
        return []
    # Return chronological order (oldest -> newest)
    return sorted(
        [m for m in msgs if isinstance(m, dict)],
        key=lambda m: float(m.get("ts") or 0.0),
    )


def post_message(
    channel: str,
    text: str,
    *,
    thread_ts: str | None = None,
    blocks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "channel": channel,
        "text": text,
        "unfurl_links": False,
        "unfurl_media": False,
    }
    if thread_ts:
        payload["thread_ts"] = thread_ts
    if blocks:
        payload["blocks"] = blocks
    return _slack_request("POST", "chat.postMessage", json_body=payload)


def add_reaction(channel: str, timestamp: str, name: str = "bomb") -> bool:
    try:
        _slack_request(
            "POST",
            "reactions.add",
            json_body={"channel": channel, "timestamp": timestamp, "name": name},
        )
        return True
    except Exception:
        return False


def _strip_slack_links(text: str) -> str:
    return SLACK_LINK_RE.sub(lambda m: m.group(1), text)


def parse_boom_command(text: str, bot_user_id: str | None = None) -> dict[str, str] | None:
    """Parse `@blastbox boom <target>`, `<@BOT> boom <target>`, or `boom <target>`."""
    if not text or not isinstance(text, str):
        return None
    cleaned = _strip_slack_links(text).strip()

    prefixes = [r"!boom"]
    if bot_user_id:
        prefixes.append(rf"<@{re.escape(bot_user_id)}>[\s,:]*boom")
    prefixes.extend(
        [
            r"<@[A-Z0-9]+>[\s,:]*boom",
            r"@?(?:blastbox|sprites_bot)[\s,:]+boom",
            r"boom",
        ]
    )
    pattern = re.compile(r"^(?:" + "|".join(prefixes) + r")\s+(\S+)", re.IGNORECASE)
    m = pattern.match(cleaned)
    if not m:
        return None
    target = m.group(1).strip().strip("`\"'<>")
    if not target:
        return None
    return {"target": target, "raw_text": text}


def resolve_boom_target(raw_target: str, base_dir: Path) -> tuple[str, str, bool]:
    """Map Slack target string or shortcut into `(target_arg, mode, no_post)`."""
    low = raw_target.strip().lower()
    fixtures = base_dir / "fixtures"
    shortcuts: dict[str, tuple[str, str, bool]] = {
        "poisoned-skill": (str(fixtures / "poisoned-skill"), "skill", True),
        "skill-bad": (str(fixtures / "poisoned-skill"), "skill", True),
        "clean-skill": (str(fixtures / "clean-skill"), "skill", True),
        "skill-clean": (str(fixtures / "clean-skill"), "skill", True),
        "poisoned-mcp": (str(fixtures / "poisoned-mcp"), "mcp", True),
        "mcp-bad": (str(fixtures / "poisoned-mcp"), "mcp", True),
        "clean-mcp": (str(fixtures / "clean-mcp"), "mcp", True),
        "mcp-clean": (str(fixtures / "clean-mcp"), "mcp", True),
        "poisoned-pr": (f"https://github.com/{config.DEFAULT_REPO}/pull/1", "pr", False),
        "clean-pr": (f"https://github.com/{config.DEFAULT_REPO}/pull/8", "pr", False),
    }
    if low in shortcuts:
        return shortcuts[low]

    if PR_URL_RE.match(raw_target):
        return raw_target, "pr", False

    return raw_target, "skill", True


def format_slack_verdict(summary: dict[str, Any], public_url: str) -> tuple[str, list[dict[str, Any]]]:
    verdict = str(summary.get("deterministic_verdict") or "UNKNOWN").upper()
    score = summary.get("deterministic_risk_score", 0)
    mode = str(summary.get("mode") or "unknown").upper()
    target = summary.get("target") or {}
    target_label = str(target.get("pr_url") or target.get("target_label") or "target")
    detonator = summary.get("detonator_sprite") or config.DETONATOR_SPRITE
    cp = summary.get("checkpoint_restored") or "n/a"
    rollback_ok = bool(summary.get("rollback_verified"))
    fs_created = summary.get("fs_created_during_detonation") or []
    counts = summary.get("ioc_counts") or {}
    plan = summary.get("agent_plan") or {}
    gh_url = (summary.get("github_publish") or {}).get("html_url")
    run_id = summary.get("run_id") or ""
    wall_s = summary.get("wall_seconds") or "n/a"

    if verdict == "BLOCK":
        badge = f":rotating_light: *BLOCK ({score}/100)*"
    elif verdict == "REVIEW":
        badge = f":warning: *REVIEW ({score}/100)*"
    else:
        badge = f":white_check_mark: *PASS ({score}/100)*"

    fallback = f"Blastbox {verdict} ({score}/100) for {target_label} | {public_url}"

    links = [f"<{public_url}|Open Live Dashboard>"]
    if gh_url:
        links.append(f"<{gh_url}|Open GitHub Audit>")

    plan_targets = ", ".join(str(x) for x in (plan.get("targets") or [])) or "default"
    findings_lines = [
        f"• Sens reads: `{counts.get('sensitive_file_probes', 0)}`  |  "
        f"FS writes: `{counts.get('unexpected_writes', 0)}`  |  "
        f"Net/DNS: `{counts.get('network_connects', 0)}/{counts.get('dns_queries', 0)}`  |  "
        f"Prompt injection: `{counts.get('prompt_injection_signals', 0) + counts.get('mcp_tool_poisoning', 0)}`"
    ]
    if fs_created:
        findings_lines.append(f"• Out-of-workspace files caught & wiped: `{', '.join(fs_created[:3])}`")

    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{badge}  ·  `{mode}`  ·  `{wall_s}s`\n*Target:* `{target_label}`",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Air-Gapped Sandbox*\n`{detonator}` (`* -> deny`)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Overlay Rollback*\n`{cp}` ({'verified 0 left' if rollback_ok else 'unverified'})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*LLM Probe Plan*\n`{plan_targets}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Run ID*\n`{run_id}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(findings_lines),
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Zero-secret Connectors (Slack + GitHub + OpenRouter)  |  {'  ·  '.join(links)}",
                }
            ],
        },
    ]
    return fallback, blocks
