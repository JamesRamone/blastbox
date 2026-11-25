#!/usr/bin/env python3
"""Blastbox Public Status & Run History Web Server (Port 8080).

Lightweight stdlib ThreadingHTTPServer running inside the trusted `blastbox`
Controller Sprite via `sprite-env services` with `--url-auth public`. Reads
`history.json` and `agent_status.json` dynamically on every request.

Security invariants:
  - Never expose raw API tokens, secret env vars, or sensitive local host paths.
  - HTML-escape all dynamic run fields and validate HTTP(S) URLs before rendering.
"""

from __future__ import annotations

import html
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
HISTORY_PATH = Path(os.environ.get("BLASTBOX_HISTORY_PATH", str(APP_DIR / "history.json")))
AGENT_STATUS_PATH = Path(os.environ.get("BLASTBOX_AGENT_STATUS_PATH", str(APP_DIR / "agent_status.json")))
PORT = int(os.environ.get("PORT", "8080"))

GITHUB_CONNECTOR_ID = os.environ.get("BLASTBOX_GITHUB_CONNECTOR_ID") or "<github-connector-id>"
OPENROUTER_CONNECTOR_ID = os.environ.get("BLASTBOX_OPENROUTER_CONNECTOR_ID") or "<openrouter-connector-id>"
SLACK_CONNECTOR_ID = os.environ.get("BLASTBOX_SLACK_CONNECTOR_ID") or "<slack-connector-id>"
DEFAULT_DETONATOR = os.environ.get("BLASTBOX_DETONATOR_SPRITE") or "blastbox-detonator"
DEFAULT_PUBLIC_URL = os.environ.get("BLASTBOX_PUBLIC_URL") or "https://blastbox-3xb.sprites.app"
ASSETS_DIR = Path(os.environ.get("BLASTBOX_ASSETS_DIR", str(APP_DIR / "assets")))
ALLOWED_ASSETS: dict[str, tuple[Path, str]] = {
    "/assets/hacksgiving-turkey.png": (ASSETS_DIR / "hacksgiving-turkey.png", "image/png"),
}
REPO_FALLBACK_ASSETS: dict[str, Path] = {
    "/assets/hacksgiving-turkey.png": APP_DIR.parent / "docs" / "hacksgiving-turkey.png",
}

FORBIDDEN_ENV_VARS = (
    "GITHUB_TOKEN",
    "OPENROUTER_API_KEY",
    "FLY_API_TOKEN",
    "SPRITES_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
)

HOST_PATH_RE = re.compile(
    r"(?:/var)?/home/[A-Za-z0-9._-]+(?:/[^\s\"'<>`]*)?|/Users/[A-Za-z0-9._-]+(?:/[^\s\"'<>`]*)?"
)
SENSITIVE_KEYS = {
    "local_path",
    "artifacts_dir",
    "env",
    "tokens",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "credentials",
    "credential",
}
SAFE_METADATA_KEYS = {
    "zero_secrets_verified",
    "zero_secrets",
    "prompt_tokens",
    "completion_tokens",
    "reasoning_tokens",
    "total_tokens",
}
SENSITIVE_KEY_RE = re.compile(
    r"(?:api_?key|secret|password|passwd|authorization|credential|(?:^|_)tokens?(?:$|_))",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{4,}"
    r"|github_pat_[A-Za-z0-9_]{4,}"
    r"|sk-or-(?:v1-)?[A-Za-z0-9_-]{4,}"
    r"|FlyV1\s+[A-Za-z0-9._~+/=-]{4,}"
    r"|AKIA[0-9A-Z]{4,}"
    r"|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{4,}"
    r")"
)

SIGNAL_SPECS: tuple[tuple[str, str], ...] = (
    ("sensitive_file_probes", "Sensitive file probes"),
    ("unexpected_writes", "Unexpected writes"),
    ("network_connects", "Network connects"),
    ("dns_queries", "DNS queries"),
    ("notable_subprocesses", "Notable subprocesses"),
    ("connector_policy_denials", "Connector / gateway blocks"),
    ("prompt_injection_signals", "Doc / prompt injection"),
    ("mcp_tool_poisoning", "MCP / SKILL poisoning"),
)

FINDING_PTS_RE = re.compile(r"\s*\[\+(\d+)\]\s*$")


def _sanitize_str(value: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        text = match.group(0)
        if text == "/home/sprite" or text.startswith("/home/sprite/"):
            return text
        return "[REDACTED_HOST_PATH]"

    cleaned = HOST_PATH_RE.sub(_repl, value)
    return TOKEN_RE.sub("[REDACTED_TOKEN]", cleaned)


def _sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if k_lower in SENSITIVE_KEYS or (
                k_lower not in SAFE_METADATA_KEYS and SENSITIVE_KEY_RE.search(k_lower)
            ):
                continue
            cleaned[k] = _sanitize_obj(v)
        return cleaned
    if isinstance(obj, list):
        return [_sanitize_obj(item) for item in obj]
    if isinstance(obj, str):
        return _sanitize_str(obj)
    return obj


def check_zero_secrets_in_env() -> bool:
    return not any(var in os.environ for var in FORBIDDEN_ENV_VARS)


def load_sanitized_history() -> dict[str, Any]:
    default_payload: dict[str, Any] = {
        "schema_version": 2,
        "sprite_name": "blastbox",
        "detonator_sprite": DEFAULT_DETONATOR,
        "public_url": DEFAULT_PUBLIC_URL,
        "updated_at": None,
        "runs": [],
    }
    if not HISTORY_PATH.exists():
        return default_payload
    try:
        raw = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_payload
    if not isinstance(raw, dict):
        return default_payload
    sanitized = _sanitize_obj(raw)
    if not isinstance(sanitized.get("runs"), list):
        sanitized["runs"] = []
    sanitized.setdefault("schema_version", 2)
    sanitized.setdefault("sprite_name", "blastbox")
    sanitized.setdefault("detonator_sprite", DEFAULT_DETONATOR)
    sanitized.setdefault("public_url", DEFAULT_PUBLIC_URL)
    return sanitized


def load_agent_status() -> dict[str, Any] | None:
    if not AGENT_STATUS_PATH.exists():
        return None
    try:
        raw = json.loads(AGENT_STATUS_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return _sanitize_obj(raw)
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_http_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith("https://") or value.startswith("http://")


def _format_utc(ts: Any, *, short: bool = False) -> str:
    raw = str(ts or "").strip()
    if not raw or raw.lower() == "pending":
        return "pending"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2}))?Z?$", raw)
    if m:
        if short:
            return f"{m.group(1)} {m.group(2)} UTC"
        sec = m.group(3) or "00"
        return f"{m.group(1)} {m.group(2)}:{sec} UTC"
    return raw


def _kind_display(kind: Any) -> str:
    k = str(kind or "unknown").strip().lower()
    if k == "pr":
        return "GitHub PR"
    if k == "mcp":
        return "MCP server"
    if k == "skill":
        return "Agent SKILL.md"
    if k == "local":
        return "Local package"
    return k or "Unknown"


def _verdict_key(verdict: Any) -> str:
    v = str(verdict or "").strip().upper()
    if v in ("BLOCK", "REVIEW", "PASS"):
        return v
    return "UNKNOWN"


def _verdict_class(verdict: Any) -> str:
    v = _verdict_key(verdict)
    if v == "BLOCK":
        return "status-block"
    if v == "REVIEW":
        return "status-review"
    if v == "PASS":
        return "status-pass"
    return "status-neutral"


def _safe_json_for_script(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"))
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--")
    )


def _split_finding_points(text: str) -> tuple[str, str | None]:
    m = FINDING_PTS_RE.search(text)
    if not m:
        return text, None
    return text[: m.start()].strip(), f"+{m.group(1)} pts"


def _normalize_run(run: dict[str, Any]) -> dict[str, Any]:
    counts_raw = run.get("ioc_counts") if isinstance(run.get("ioc_counts"), dict) else {}
    counts: dict[str, int] = {
        "total_strace_lines": max(0, _safe_int(counts_raw.get("total_strace_lines"), 0)),
    }
    for key, _ in SIGNAL_SPECS:
        counts[key] = max(0, _safe_int(counts_raw.get(key), 0))

    raw_findings = run.get("top_findings") if isinstance(run.get("top_findings"), list) else []
    findings = [str(item) for item in raw_findings[:6] if item is not None]

    verdict = _verdict_key(run.get("verdict"))
    risk_score = max(0, min(100, _safe_int(run.get("risk_score"), 0)))
    llm_verdict = str(run.get("llm_verdict") or verdict).upper()
    kind_raw = str(run.get("target_kind") or "unknown").strip().lower()
    target_url = str(run.get("target_url") or "")
    gh_url = str(run.get("github_artifact_url") or "")
    raw_gh_status = run.get("github_publish_status")
    wall_num = _safe_float(run.get("wall_seconds"))
    wall_display = f"{wall_num:.2f}".rstrip("0").rstrip(".") if wall_num is not None else "n/a"

    pi_resisted = bool(run.get("prompt_injection_resisted"))
    pi_detected = bool(run.get("prompt_injection_detected"))
    exec_summary = run.get("executive_summary") or run.get("ai_summary")

    raw_plan = run.get("agent_plan") if isinstance(run.get("agent_plan"), dict) else {}
    plan_targets = [str(x) for x in (raw_plan.get("targets") or []) if x is not None]
    plan_suspicious = [str(x) for x in (raw_plan.get("suspicious_tools") or []) if x is not None]
    fs_created = [str(x) for x in (run.get("fs_created_during_detonation") or []) if x is not None]

    detonator_sprite = str(run.get("detonator_sprite") or DEFAULT_DETONATOR)
    egress_denied = bool(run.get("detonator_egress_denied", False))
    unlabeled = bool(run.get("detonator_unlabeled", False))

    return {
        "run_id": str(run.get("run_id") or ""),
        "timestamp_utc": str(run.get("timestamp_utc") or ""),
        "timestamp_short": _format_utc(run.get("timestamp_utc"), short=True),
        "timestamp_full": _format_utc(run.get("timestamp_utc"), short=False),
        "target_kind": kind_raw,
        "target_kind_label": _kind_display(kind_raw),
        "target_label": str(run.get("target_label") or "Unknown target"),
        "target_url": target_url if _is_http_url(target_url) else "",
        "verdict": verdict,
        "risk_score": risk_score,
        "llm_verdict": llm_verdict,
        "openrouter_model": str(run.get("openrouter_model") or "n/a"),
        "prompt_injection_detected": pi_detected,
        "prompt_injection_resisted": pi_resisted,
        "detonator_sprite": detonator_sprite,
        "detonator_isolation": (
            f"{detonator_sprite} (unlabeled, deny-all egress)"
            if (unlabeled and egress_denied)
            else detonator_sprite
        ),
        "checkpoint_restored": str(run.get("checkpoint_restored") or "n/a"),
        "rollback_verified": bool(run.get("rollback_verified")),
        "fs_created_during_detonation": fs_created,
        "agent_plan": {
            "planner_source": str(raw_plan.get("planner_source") or "n/a"),
            "model_used": str(raw_plan.get("model_used") or "n/a"),
            "rationale": str(raw_plan.get("rationale") or ""),
            "targets": plan_targets,
            "suspicious_tools": plan_suspicious,
        },
        "zero_secrets_verified": bool(run.get("zero_secrets_verified")),
        "policy_403_status": str(run.get("policy_403_status") or "n/a"),
        "github_publish_status": None if raw_gh_status is None else str(raw_gh_status),
        "github_artifact_url": gh_url if _is_http_url(gh_url) else "",
        "ioc_counts": counts,
        "top_findings": findings,
        "wall_seconds": wall_display,
        "executive_summary": str(exec_summary).strip() if isinstance(exec_summary, str) and exec_summary.strip() else "",
    }


def _render_dossier_html(run: dict[str, Any] | None) -> str:
    if run is None:
        return (
            '<div class="dossier-empty">'
            "<h3>No detonation selected</h3>"
            "<p>Run <code>./demo.sh</code>, <code>./demo.sh --clean-pr</code>, or <code>./demo.sh --mcp</code> to record an audit run and inspect its kernel telemetry here.</p>"
            "</div>"
        )

    verdict = run["verdict"]
    verdict_cls = _verdict_class(verdict)
    score = run["risk_score"]
    target_label = html.escape(run["target_label"])
    if run["target_url"]:
        target_heading = (
            f'<a class="dossier-title-link" href="{html.escape(run["target_url"])}" '
            f'target="_blank" rel="noopener">{target_label}</a>'
        )
    else:
        target_heading = target_label

    gh_status = run["github_publish_status"]
    if run["github_artifact_url"]:
        action_html = (
            f'<a class="primary-action" href="{html.escape(run["github_artifact_url"])}" '
            f'target="_blank" rel="noopener">Open GitHub report</a>'
        )
        gh_proof = f"HTTP {html.escape(gh_status)}" if gh_status is not None else "Published"
    elif gh_status is None:
        action_html = '<span class="dossier-action-muted">Skipped (--no-post)</span>'
        gh_proof = "Skipped (--no-post)"
    else:
        action_html = f'<span class="dossier-action-muted">HTTP {html.escape(gh_status)}</span>'
        gh_proof = f"HTTP {html.escape(gh_status)}"

    counts = run["ioc_counts"]
    max_sig = max([counts.get(k, 0) for k, _ in SIGNAL_SPECS] + [1])
    signal_rows_html: list[str] = []
    for key, label in SIGNAL_SPECS:
        val = counts.get(key, 0)
        pct = int(round((val / max_sig) * 100)) if val > 0 else 0
        row_cls = "signal-item signal-active" if val > 0 else "signal-item signal-zero"
        signal_rows_html.append(
            f'<div class="{row_cls}">'
            f'<div class="signal-head">'
            f'<span class="signal-name">{html.escape(label)}</span>'
            f'<span class="signal-val">{val}</span>'
            f"</div>"
            f'<div class="signal-track" aria-hidden="true"><span class="signal-bar" style="width:{pct}%"></span></div>'
            f"</div>"
        )

    if run["prompt_injection_detected"] and run["prompt_injection_resisted"]:
        pi_status_text = "Detected and resisted"
        pi_status_cls = "proof-ok"
    elif run["prompt_injection_detected"]:
        pi_status_text = "Detected, not resisted"
        pi_status_cls = "proof-alert"
    else:
        pi_status_text = "None detected"
        pi_status_cls = "proof-ok"

    exec_summary_html = ""
    if run["executive_summary"]:
        exec_summary_html = f'<p class="ai-summary">{html.escape(run["executive_summary"])}</p>'

    plan = run["agent_plan"]
    plan_targets_str = ", ".join(plan["targets"]) if plan["targets"] else "Default stages"
    plan_html = ""
    if plan["rationale"]:
        susp_note = (
            f' (flagged suspicious: <span class="mono">{html.escape(", ".join(plan["suspicious_tools"]))}</span>)'
            if plan["suspicious_tools"]
            else ""
        )
        plan_html = (
            f'<div class="plan-block">'
            f'<div class="plan-meta">Agent probe plan (<span class="mono">{html.escape(plan["planner_source"])}</span>): '
            f'exercised <span class="mono">{html.escape(plan_targets_str)}</span>{susp_note}</div>'
            f'<p class="plan-rationale">{html.escape(plan["rationale"])}</p>'
            f"</div>"
        )

    findings_items: list[str] = []
    for raw_item in run["top_findings"]:
        body_text, pts = _split_finding_points(raw_item)
        pts_html = f'<span class="finding-pts">{html.escape(pts)}</span>' if pts else ""
        findings_items.append(
            f'<li class="finding-row"><span class="finding-text">{html.escape(body_text)}</span>{pts_html}</li>'
        )
    if not findings_items:
        findings_items.append(
            '<li class="finding-row"><span class="finding-text">No out-of-policy kernel, filesystem, or metadata signals recorded.</span></li>'
        )

    rollback_cls = "proof-ok" if run["rollback_verified"] else "proof-alert"
    fs_created_cnt = len(run["fs_created_during_detonation"])
    rollback_note = (
        f"Verified clean ({fs_created_cnt} created -> 0 left)"
        if run["rollback_verified"]
        else "Unverified"
    )
    zero_cls = "proof-ok" if run["zero_secrets_verified"] else "proof-alert"
    zero_note = "Verified (0 tokens)" if run["zero_secrets_verified"] else "Failed"
    syscalls_str = f"{counts.get('total_strace_lines', 0):,}"

    return f"""
      <div class="dossier-band dossier-head">
        <div class="dossier-head-main">
          <h3 class="dossier-title">{target_heading}</h3>
          <p class="dossier-sub">{html.escape(run['target_kind_label'])} &middot; {html.escape(run['timestamp_full'])}</p>
        </div>
        <div class="dossier-head-action">{action_html}</div>
      </div>

      <div class="dossier-band risk-band">
        <div class="risk-meta">
          <div class="risk-verdict-wrap">
            <span class="status-cell {verdict_cls}">{html.escape(verdict)}</span>
            <span class="risk-score-text">Risk score <strong>{score} / 100</strong></span>
          </div>
          <span class="risk-duration">Duration <span class="mono">{html.escape(run['wall_seconds'])}s</span></span>
        </div>
        <div class="risk-track" role="progressbar" aria-valuenow="{score}" aria-valuemin="0" aria-valuemax="100" aria-label="Risk score">
          <span class="risk-fill {verdict_cls}" style="width:{score}%"></span>
        </div>
      </div>

      <div class="dossier-band">
        <dl class="proof-grid">
          <div class="proof-item">
            <dt>Run ID</dt>
            <dd class="mono">{html.escape(run['run_id'])}</dd>
          </div>
          <div class="proof-item">
            <dt>Detonator sandbox</dt>
            <dd class="mono">{html.escape(run['detonator_isolation'])}</dd>
          </div>
          <div class="proof-item">
            <dt>Filesystem rollback</dt>
            <dd><span class="mono">{html.escape(run['checkpoint_restored'])}</span> &middot; <span class="{rollback_cls}">{html.escape(rollback_note)}</span></dd>
          </div>
          <div class="proof-item">
            <dt>Zero-secret VM</dt>
            <dd class="{zero_cls}">{zero_note}</dd>
          </div>
          <div class="proof-item">
            <dt>Controller policy</dt>
            <dd class="mono">HTTP {html.escape(run['policy_403_status'])} on /user/repos &middot; {gh_proof}</dd>
          </div>
          <div class="proof-item">
            <dt>Syscalls traced</dt>
            <dd class="mono">{html.escape(syscalls_str)}</dd>
          </div>
        </dl>
      </div>

      <div class="dossier-band">
        <h4 class="band-title">Deterministic kernel and metadata signals</h4>
        <div class="signal-grid">
          {"".join(signal_rows_html)}
        </div>
      </div>

      <div class="dossier-band">
        <h4 class="band-title">AI agent planning and triage</h4>
        <dl class="triage-grid">
          <div class="proof-item">
            <dt>Model</dt>
            <dd class="mono">{html.escape(run['openrouter_model'])}</dd>
          </div>
          <div class="proof-item">
            <dt>AI verdict</dt>
            <dd><span class="mono">{html.escape(run['llm_verdict'])}</span></dd>
          </div>
          <div class="proof-item">
            <dt>Prompt injection</dt>
            <dd class="{pi_status_cls}">{pi_status_text}</dd>
          </div>
        </dl>
        {plan_html}
        {exec_summary_html}
      </div>

      <div class="dossier-band dossier-band-last">
        <h4 class="band-title">Top deterministic findings</h4>
        <ul class="findings-list">
          {"".join(findings_items)}
        </ul>
      </div>
    """


def render_dashboard_html(
    history: dict[str, Any],
    zero_secrets_ok: bool,
    agent_status: dict[str, Any] | None = None,
) -> str:
    if not isinstance(history, dict):
        history = {}
    raw_runs = history.get("runs")
    runs: list[dict[str, Any]] = [
        _normalize_run(r)
        for r in reversed(raw_runs if isinstance(raw_runs, list) else [])
        if isinstance(r, dict)
    ]
    updated_at_display = html.escape(_format_utc(history.get("updated_at"), short=False))
    sprite_name = html.escape(str(history.get("sprite_name") or "blastbox"))
    detonator_name = html.escape(str(history.get("detonator_sprite") or DEFAULT_DETONATOR))

    total_runs = len(runs)
    blocked_count = sum(1 for r in runs if r["verdict"] == "BLOCK")
    passed_count = sum(1 for r in runs if r["verdict"] == "PASS")
    pr_count = sum(1 for r in runs if r["target_kind"] == "pr")
    mcp_count = sum(1 for r in runs if r["target_kind"] == "mcp")
    skill_count = sum(1 for r in runs if r["target_kind"] == "skill")
    verified_rollbacks = sum(1 for r in runs if r["rollback_verified"])
    latest_cp = html.escape(runs[0]["checkpoint_restored"]) if runs else "none"

    if total_runs:
        rollback_value = f"{verified_rollbacks}/{total_runs} clean"
        rollback_note = f"FS diff verified, latest {latest_cp}"
    else:
        rollback_value = "Ready"
        rollback_note = "Baseline checkpoint pending first run"

    if isinstance(agent_status, dict):
        watched_repo = html.escape(str(agent_status.get("watched_repo") or ""))
        cli_auth = bool(agent_status.get("sprite_cli_authenticated"))
        slack_ok = bool(agent_status.get("slack_connected"))
        active_job = str(agent_status.get("active_job") or "").strip()
        if active_job:
            agent_note = html.escape(active_job)
        elif cli_auth and slack_ok:
            agent_note = f"Watching {watched_repo} and Slack #blastbox"
        elif cli_auth:
            agent_note = f"Watching {watched_repo} (autonomous control active)"
        else:
            agent_note = f"Watching {watched_repo} (awaiting controller sprite login)"
    else:
        agent_note = f"Unlabeled {detonator_name}, deny-all egress, 0 tokens"

    ledger_rows: list[str] = []
    for idx, run in enumerate(runs):
        is_active = idx == 0
        row_cls = "run-row is-active" if is_active else "run-row"
        aria_sel = "true" if is_active else "false"
        verdict = run["verdict"]
        verdict_cls = _verdict_class(verdict)
        search_blob = " ".join(
            [
                run["target_label"],
                run["run_id"],
                run["checkpoint_restored"],
                run["target_kind_label"],
                verdict,
            ]
        ).lower()
        ledger_rows.append(
            f'<tr class="{row_cls}" tabindex="0" role="row" aria-selected="{aria_sel}" '
            f'data-run-id="{html.escape(run["run_id"])}" '
            f'data-kind="{html.escape(run["target_kind"])}" '
            f'data-verdict="{html.escape(verdict)}" '
            f'data-search="{html.escape(search_blob)}">'
            f'<td class="col-target">'
            f'<div class="row-target-title">{html.escape(run["target_label"])}</div>'
            f'<div class="row-target-meta">'
            f'<span>{html.escape(run["target_kind_label"])}</span>'
            f"<span>&middot;</span>"
            f'<span class="mono">{html.escape(run["timestamp_short"])}</span>'
            f"<span>&middot;</span>"
            f'<span class="mono">{html.escape(run["checkpoint_restored"])}</span>'
            f"</div>"
            f'<div class="row-run-id mono">{html.escape(run["run_id"])}</div>'
            f"</td>"
            f'<td class="col-verdict">'
            f'<span class="status-cell {verdict_cls}">{html.escape(verdict)} &middot; {run["risk_score"]}</span>'
            f"</td>"
            f'<td class="col-duration mono">{html.escape(run["wall_seconds"])}s</td>'
            f"</tr>"
        )

    if ledger_rows:
        ledger_body = "\n".join(ledger_rows)
        ledger_empty_hidden = " hidden"
    else:
        ledger_body = ""
        ledger_empty_hidden = ""

    initial_dossier = _render_dossier_html(runs[0] if runs else None)
    runs_json_safe = _safe_json_for_script(runs)

    secret_status_cls = "nav-status-ok" if zero_secrets_ok else "nav-status-alert"
    secret_status_text = "Zero-secret VM" if zero_secrets_ok else "Secret env alert"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Blastbox: Isolated Detonation Audit Console</title>
  <script>
    (function () {{
      try {{
        var saved = localStorage.getItem("blastbox-theme");
        if (saved === "hacksgiving" || saved === "lab") {{
          document.documentElement.setAttribute("data-theme", saved);
        }}
      }} catch (e) {{}}
    }})();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #F1F3F5;
      --surface: #FFFFFF;
      --surface-subtle: #F7F8FA;
      --surface-hover: #EDF0F4;
      --topbar-bg: rgba(255, 255, 255, 0.94);
      --ink: #10151C;
      --ink-secondary: #374151;
      --muted: #526071;
      --border: #D5DCE4;
      --border-subtle: #E5E9EF;
      --accent: #C8281E;
      --accent-hover: #A61F17;
      --block-ink: #B42318;
      --block-bg: #FEF2F2;
      --block-border: #F5C2C0;
      --review-ink: #92400E;
      --review-bg: #FFFBEB;
      --review-border: #F5D791;
      --pass-ink: #0F6B46;
      --pass-bg: #ECFDF5;
      --pass-border: #A7E3C6;
      --font-sans: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      --font-mono: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --text-heading: 1.25rem;
      --text-body: 0.9375rem;
      --text-sm: 0.8125rem;
      --ease: cubic-bezier(0.22, 1, 0.36, 1);
    }}
    html[data-theme="hacksgiving"] {{
      --bg: #FAF8F5;
      --surface: #FFFFFF;
      --surface-subtle: #F4F0FA;
      --surface-hover: #ECE5F6;
      --topbar-bg: rgba(250, 248, 245, 0.94);
      --ink: #1E1633;
      --ink-secondary: #3C3156;
      --muted: #5A4E75;
      --border: #DDD4EC;
      --border-subtle: #EAE3F4;
      --accent: #6D28D9;
      --accent-hover: #5B21B6;
    }}
    *, *::before, *::after {{
      box-sizing: border-box;
    }}
    html {{
      scroll-behavior: smooth;
      background: var(--bg);
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: var(--font-sans);
      font-size: var(--text-body);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      overflow-x: clip;
    }}
    a {{
      color: var(--ink);
      text-decoration: none;
      transition: color 160ms var(--ease);
    }}
    a:hover {{
      color: var(--accent);
    }}
    a:focus-visible, button:focus-visible, select:focus-visible, input:focus-visible, tr:focus-visible {{
      outline: 2px solid var(--accent);
      outline-offset: -2px;
    }}
    code, .mono {{
      font-family: var(--font-mono);
      font-variant-numeric: tabular-nums;
    }}
    code {{
      font-size: inherit;
      background: var(--surface-subtle);
      border: 1px solid var(--border-subtle);
      padding: 0.05rem 0.3rem;
      border-radius: 3px;
    }}
    .nowrap {{
      white-space: nowrap;
    }}

    /* Top bar */
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 40;
      background: var(--topbar-bg);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border);
    }}
    .topbar-inner {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }}
    .brand-group {{
      display: flex;
      align-items: center;
      gap: 0.85rem;
      min-width: 0;
    }}
    .brand {{
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      color: var(--ink);
      white-space: nowrap;
    }}
    .brand:hover {{
      color: var(--ink);
    }}
    .brand-mark {{
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }}
    .sprite-context {{
      font-size: var(--text-sm);
      color: var(--muted);
      padding-left: 0.85rem;
      border-left: 1px solid var(--border);
      white-space: nowrap;
    }}
    .topnav {{
      display: flex;
      align-items: center;
      gap: 1.25rem;
      font-size: var(--text-sm);
      font-weight: 500;
      white-space: nowrap;
    }}
    .topnav a {{
      color: var(--ink-secondary);
    }}
    .topnav a:hover {{
      color: var(--accent);
    }}
    .nav-status {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding-left: 1.1rem;
      border-left: 1px solid var(--border);
      font-size: var(--text-sm);
      font-weight: 600;
      white-space: nowrap;
    }}
    .nav-status-ok {{
      color: var(--pass-ink);
    }}
    .nav-status-alert {{
      color: var(--block-ink);
    }}
    .theme-switch {{
      display: inline-flex;
      border: 1px solid var(--border);
      background: var(--surface);
      flex-shrink: 0;
    }}
    .theme-btn {{
      appearance: none;
      border: none;
      border-right: 1px solid var(--border);
      background: transparent;
      color: var(--ink-secondary);
      font-family: var(--font-sans);
      font-size: var(--text-sm);
      font-weight: 500;
      padding: 0.32rem 0.65rem;
      min-height: 30px;
      cursor: pointer;
      white-space: nowrap;
      transition: background-color 150ms var(--ease), color 150ms var(--ease);
    }}
    .theme-btn:last-child {{
      border-right: none;
    }}
    .theme-btn:hover {{
      background: var(--surface-hover);
      color: var(--ink);
    }}
    .theme-btn[aria-pressed="true"] {{
      background: var(--ink);
      color: var(--surface);
    }}

    /* Main container */
    .shell {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 1.75rem 1.5rem 3.5rem;
    }}

    /* Console header + KPI strip */
    .console-head {{
      margin-bottom: 1.75rem;
    }}
    .console-title-row {{
      margin-bottom: 1.25rem;
    }}
    h1 {{
      margin: 0 0 0.45rem;
      font-size: clamp(1.625rem, 2.4vw, 2.125rem);
      font-weight: 600;
      letter-spacing: -0.03em;
      line-height: 1.15;
      color: var(--ink);
    }}
    .console-desc {{
      margin: 0;
      max-width: 65ch;
      font-size: var(--text-body);
      color: var(--ink-secondary);
    }}
    .kpi-strip {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    .kpi-cell {{
      padding: 1rem 1.15rem;
      border-right: 1px solid var(--border-subtle);
      min-width: 0;
    }}
    .kpi-cell:last-child {{
      border-right: none;
    }}
    .kpi-label {{
      font-size: var(--text-sm);
      color: var(--muted);
      font-weight: 500;
      margin-bottom: 0.35rem;
    }}
    .kpi-value {{
      font-size: var(--text-heading);
      font-weight: 600;
      letter-spacing: -0.02em;
      line-height: 1.2;
      font-variant-numeric: tabular-nums;
      color: var(--ink);
    }}
    .kpi-ok {{
      color: var(--pass-ink);
    }}
    .kpi-note {{
      margin-top: 0.3rem;
      font-size: var(--text-sm);
      color: var(--muted);
      overflow-wrap: anywhere;
    }}

    /* Section header + controls */
    .workbench-section {{
      margin-bottom: 2.5rem;
    }}
    .section-bar {{
      display: flex;
      flex-wrap: wrap;
      align-items: flex-end;
      justify-content: space-between;
      gap: 0.9rem 1.25rem;
      margin-bottom: 0.9rem;
    }}
    .section-title-group {{
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 0.45rem 0.9rem;
    }}
    h2 {{
      margin: 0;
      font-size: var(--text-heading);
      font-weight: 600;
      letter-spacing: -0.02em;
      line-height: 1.2;
      color: var(--ink);
    }}
    .updated-note {{
      font-size: var(--text-sm);
      color: var(--muted);
    }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.65rem;
    }}
    .segmented {{
      display: inline-flex;
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    .seg-tab {{
      appearance: none;
      border: none;
      border-right: 1px solid var(--border-subtle);
      background: transparent;
      color: var(--ink-secondary);
      font-family: var(--font-sans);
      font-size: var(--text-sm);
      font-weight: 500;
      padding: 0.48rem 0.8rem;
      cursor: pointer;
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
      transition: background-color 150ms var(--ease), color 150ms var(--ease);
    }}
    .seg-tab:last-child {{
      border-right: none;
    }}
    .seg-tab:hover {{
      background: var(--surface-hover);
      color: var(--ink);
    }}
    .seg-tab[aria-selected="true"] {{
      background: var(--ink);
      color: var(--surface);
    }}
    .control-select, .control-search {{
      font-family: var(--font-sans);
      font-size: var(--text-sm);
      color: var(--ink);
      background: var(--surface);
      border: 1px solid var(--border);
      padding: 0.48rem 0.7rem;
      border-radius: 0;
      min-height: 36px;
      transition: border-color 150ms var(--ease);
    }}
    .control-select:hover, .control-search:hover {{
      border-color: var(--muted);
    }}
    .control-search {{
      width: 240px;
      max-width: 100%;
    }}
    .control-search::placeholder {{
      color: var(--muted);
    }}

    /* Master-detail workbench */
    .workbench {{
      display: grid;
      grid-template-columns: minmax(320px, 43%) minmax(0, 57%);
      background: var(--surface);
      border: 1px solid var(--border);
      align-items: start;
    }}
    .ledger-pane {{
      border-right: 1px solid var(--border);
      max-height: 780px;
      overflow-y: auto;
      min-width: 0;
    }}
    .ledger-table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    .ledger-table thead th {{
      position: sticky;
      top: 0;
      z-index: 5;
      background: var(--surface-subtle);
      border-bottom: 1px solid var(--border);
      padding: 0.65rem 0.9rem;
      text-align: left;
      font-size: var(--text-sm);
      font-weight: 600;
      color: var(--muted);
    }}
    .ledger-table thead th.col-verdict {{
      width: 124px;
    }}
    .ledger-table thead th.col-duration {{
      width: 82px;
      text-align: right;
    }}
    .run-row {{
      cursor: pointer;
      border-bottom: 1px solid var(--border-subtle);
      transition: background-color 150ms var(--ease);
    }}
    .run-row:hover {{
      background: var(--surface-hover);
    }}
    .run-row.is-active {{
      background: var(--surface-subtle);
      box-shadow: inset 3px 0 0 var(--accent);
    }}
    .run-row td {{
      padding: 0.8rem 0.9rem;
      vertical-align: top;
    }}
    .row-target-title {{
      font-size: var(--text-body);
      font-weight: 600;
      color: var(--ink);
      line-height: 1.3;
      overflow-wrap: anywhere;
    }}
    .row-target-meta {{
      margin-top: 0.25rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
      font-size: var(--text-sm);
      color: var(--muted);
    }}
    .row-run-id {{
      margin-top: 0.2rem;
      font-size: var(--text-sm);
      color: var(--muted);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .col-verdict {{
      white-space: nowrap;
    }}
    .col-duration {{
      text-align: right;
      font-size: var(--text-sm);
      color: var(--ink-secondary);
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }}
    .status-cell {{
      display: inline-block;
      padding: 0.16rem 0.5rem;
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      font-weight: 600;
      border-radius: 3px;
      border: 1px solid var(--border);
      font-variant-numeric: tabular-nums;
      line-height: 1.35;
    }}
    .status-block {{
      color: var(--block-ink);
      background: var(--block-bg);
      border-color: var(--block-border);
    }}
    .status-review {{
      color: var(--review-ink);
      background: var(--review-bg);
      border-color: var(--review-border);
    }}
    .status-pass {{
      color: var(--pass-ink);
      background: var(--pass-bg);
      border-color: var(--pass-border);
    }}
    .status-neutral {{
      color: var(--muted);
      background: var(--surface-subtle);
      border-color: var(--border);
    }}
    .ledger-empty {{
      padding: 2rem 1.25rem;
      text-align: center;
      color: var(--muted);
      font-size: var(--text-body);
    }}

    /* Dossier pane */
    .dossier-pane {{
      min-width: 0;
      background: var(--surface);
      transition: opacity 160ms var(--ease);
    }}
    .dossier-pane.is-updating {{
      opacity: 0.65;
    }}
    .dossier-band {{
      padding: 1.2rem 1.4rem;
      border-bottom: 1px solid var(--border-subtle);
    }}
    .dossier-band-last {{
      border-bottom: none;
    }}
    .dossier-head {{
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.85rem 1.25rem;
    }}
    .dossier-head-main {{
      min-width: 0;
      flex: 1 1 260px;
    }}
    .dossier-title {{
      margin: 0;
      font-size: var(--text-heading);
      font-weight: 600;
      letter-spacing: -0.02em;
      line-height: 1.25;
      color: var(--ink);
      overflow-wrap: anywhere;
    }}
    .dossier-title-link {{
      color: var(--ink);
      text-decoration: underline;
      text-decoration-color: var(--border);
      text-underline-offset: 3px;
    }}
    .dossier-title-link:hover {{
      color: var(--accent);
      text-decoration-color: var(--accent);
    }}
    .dossier-sub {{
      margin: 0.3rem 0 0;
      font-size: var(--text-sm);
      color: var(--muted);
    }}
    .dossier-head-action {{
      flex-shrink: 0;
    }}
    .primary-action {{
      display: inline-block;
      background: var(--ink);
      color: var(--surface);
      font-size: var(--text-body);
      font-weight: 500;
      padding: 0.5rem 0.95rem;
      border: 1px solid var(--ink);
      transition: background-color 160ms var(--ease), border-color 160ms var(--ease), color 160ms var(--ease);
    }}
    .primary-action:hover {{
      background: var(--accent);
      border-color: var(--accent);
      color: var(--surface);
    }}
    .dossier-action-muted {{
      font-size: var(--text-sm);
      color: var(--muted);
      font-family: var(--font-mono);
    }}

    /* Risk bar */
    .risk-band {{
      background: var(--surface-subtle);
    }}
    .risk-meta {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem 1rem;
      margin-bottom: 0.6rem;
    }}
    .risk-verdict-wrap {{
      display: flex;
      align-items: center;
      gap: 0.7rem;
    }}
    .risk-score-text, .risk-duration {{
      font-size: var(--text-sm);
      color: var(--ink-secondary);
      font-variant-numeric: tabular-nums;
    }}
    .risk-track {{
      width: 100%;
      height: 6px;
      background: var(--border-subtle);
      overflow: hidden;
    }}
    .risk-fill {{
      display: block;
      height: 100%;
      border: none;
      padding: 0;
      transition: width 220ms var(--ease);
    }}
    .risk-fill.status-block {{
      background: var(--block-ink);
    }}
    .risk-fill.status-review {{
      background: var(--review-ink);
    }}
    .risk-fill.status-pass {{
      background: var(--pass-ink);
    }}
    .risk-fill.status-neutral {{
      background: var(--muted);
    }}

    /* Proof & triage definition grids */
    .proof-grid, .triage-grid {{
      margin: 0;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.9rem 1.15rem;
    }}
    .proof-item {{
      min-width: 0;
    }}
    .proof-item dt {{
      font-size: var(--text-sm);
      color: var(--muted);
      margin-bottom: 0.2rem;
    }}
    .proof-item dd {{
      margin: 0;
      font-size: var(--text-sm);
      font-weight: 500;
      color: var(--ink);
      overflow-wrap: anywhere;
    }}
    .proof-ok {{
      color: var(--pass-ink);
      font-weight: 600;
    }}
    .proof-alert {{
      color: var(--block-ink);
      font-weight: 600;
    }}

    /* Signal matrix */
    .band-title {{
      margin: 0 0 0.85rem;
      font-size: var(--text-body);
      font-weight: 600;
      color: var(--ink);
    }}
    .signal-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.75rem 1.5rem;
    }}
    .signal-item {{
      min-width: 0;
    }}
    .signal-head {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 0.5rem;
      margin-bottom: 0.3rem;
      font-size: var(--text-sm);
    }}
    .signal-name {{
      color: var(--ink-secondary);
    }}
    .signal-val {{
      font-family: var(--font-mono);
      font-weight: 600;
      font-variant-numeric: tabular-nums;
    }}
    .signal-active .signal-val {{
      color: var(--accent);
    }}
    .signal-zero .signal-name, .signal-zero .signal-val {{
      color: var(--muted);
      font-weight: 400;
    }}
    .signal-track {{
      height: 4px;
      background: var(--border-subtle);
      width: 100%;
    }}
    .signal-bar {{
      display: block;
      height: 100%;
      background: var(--accent);
      transition: width 220ms var(--ease);
    }}
    .plan-block {{
      margin-top: 0.9rem;
      padding-top: 0.8rem;
      border-top: 1px solid var(--border-subtle);
    }}
    .plan-meta {{
      font-size: var(--text-sm);
      color: var(--ink);
      font-weight: 500;
      margin-bottom: 0.25rem;
    }}
    .plan-rationale {{
      margin: 0;
      max-width: 65ch;
      font-size: var(--text-sm);
      color: var(--muted);
    }}
    .ai-summary {{
      margin: 0.85rem 0 0;
      max-width: 65ch;
      font-size: var(--text-body);
      color: var(--ink-secondary);
    }}

    /* Findings list */
    .findings-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      border-top: 1px solid var(--border-subtle);
    }}
    .finding-row {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 1rem;
      padding: 0.6rem 0;
      border-bottom: 1px solid var(--border-subtle);
      font-size: var(--text-body);
      color: var(--ink-secondary);
    }}
    .finding-text {{
      min-width: 0;
      overflow-wrap: anywhere;
    }}
    .finding-pts {{
      flex-shrink: 0;
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      font-weight: 600;
      color: var(--accent);
      font-variant-numeric: tabular-nums;
    }}
    .dossier-empty {{
      padding: 2.5rem 1.5rem;
      color: var(--muted);
    }}
    .dossier-empty h3 {{
      margin: 0 0 0.5rem;
      font-size: var(--text-heading);
      color: var(--ink);
    }}
    .dossier-empty p {{
      margin: 0;
      max-width: 55ch;
    }}

    /* Below-the-fold architecture section */
    .arch-section {{
      padding-top: 0.5rem;
      margin-bottom: 2.5rem;
    }}
    .arch-intro {{
      margin: 0.45rem 0 1.25rem;
      max-width: 65ch;
      font-size: var(--text-body);
      color: var(--ink-secondary);
    }}
    .pipeline-track {{
      list-style: none;
      margin: 0 0 1.25rem;
      padding: 0;
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    .pipeline-step {{
      padding: 1.05rem 1.1rem;
      border-right: 1px solid var(--border-subtle);
      min-width: 0;
    }}
    .pipeline-step:last-child {{
      border-right: none;
    }}
    .step-index {{
      font-family: var(--font-mono);
      font-size: var(--text-sm);
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 0.35rem;
    }}
    .step-title {{
      font-size: var(--text-body);
      font-weight: 600;
      color: var(--ink);
      margin: 0 0 0.35rem;
    }}
    .step-desc {{
      margin: 0;
      font-size: var(--text-sm);
      color: var(--muted);
      line-height: 1.5;
    }}

    .arch-figure {{
      margin: 0 0 1.25rem;
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(260px, 1fr);
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    .arch-figure-media {{
      background: #FAF8F5;
      border-right: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .arch-figure-media img {{
      display: block;
      width: 100%;
      height: auto;
    }}
    .arch-figure-caption {{
      padding: 1.25rem 1.4rem;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 0.65rem;
    }}
    .arch-figure-caption h3 {{
      margin: 0;
      font-size: var(--text-heading);
      font-weight: 600;
      color: var(--ink);
    }}
    .arch-figure-caption p {{
      margin: 0;
      font-size: var(--text-body);
      color: var(--ink-secondary);
      line-height: 1.55;
    }}
    .arch-slack-list {{
      margin: 0.25rem 0 0;
      padding-left: 1.15rem;
      font-size: var(--text-sm);
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }}

    .arch-details {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      background: var(--surface);
      border: 1px solid var(--border);
    }}
    .arch-col {{
      padding: 1.25rem 1.4rem;
      border-right: 1px solid var(--border-subtle);
      min-width: 0;
    }}
    .arch-col:last-child {{
      border-right: none;
    }}
    .arch-col h3 {{
      margin: 0 0 0.7rem;
      font-size: var(--text-body);
      font-weight: 600;
      color: var(--ink);
    }}
    .arch-col p {{
      margin: 0 0 0.75rem;
      max-width: 62ch;
      font-size: var(--text-body);
      color: var(--ink-secondary);
    }}
    .arch-col p:last-child {{
      margin-bottom: 0;
    }}
    .boundary-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: var(--text-sm);
    }}
    .boundary-table th, .boundary-table td {{
      text-align: left;
      padding: 0.55rem 0.6rem;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: top;
    }}
    .boundary-table th {{
      color: var(--muted);
      font-weight: 600;
      background: var(--surface-subtle);
    }}
    .boundary-table tr:last-child td {{
      border-bottom: none;
    }}

    /* Footer */
    footer {{
      border-top: 1px solid var(--border);
      padding-top: 1.15rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 0.6rem 1.5rem;
      font-size: var(--text-sm);
      color: var(--muted);
    }}
    .footer-links {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.9rem;
      align-items: center;
    }}
    .footer-links a {{
      color: var(--ink-secondary);
      text-decoration: underline;
      text-decoration-color: var(--border);
      text-underline-offset: 3px;
    }}
    .footer-links a:hover {{
      color: var(--accent);
      text-decoration-color: var(--accent);
    }}

    /* Responsive */
    @media (max-width: 1080px) {{
      .kpi-strip {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .kpi-cell:nth-child(2) {{
        border-right: none;
      }}
      .kpi-cell:nth-child(1), .kpi-cell:nth-child(2) {{
        border-bottom: 1px solid var(--border-subtle);
      }}
      .pipeline-track {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .pipeline-step {{
        border-bottom: 1px solid var(--border-subtle);
      }}
      .pipeline-step:nth-child(2n) {{
        border-right: none;
      }}
    }}
    @media (max-width: 960px) {{
      .workbench {{
        grid-template-columns: minmax(0, 1fr);
      }}
      .ledger-pane {{
        border-right: none;
        border-bottom: 1px solid var(--border);
        max-height: 380px;
      }}
      .arch-details, .arch-figure {{
        grid-template-columns: minmax(0, 1fr);
      }}
      .arch-figure-media {{
        border-right: none;
        border-bottom: 1px solid var(--border-subtle);
      }}
      .arch-col {{
        border-right: none;
        border-bottom: 1px solid var(--border-subtle);
      }}
      .arch-col:last-child {{
        border-bottom: none;
      }}
    }}
    @media (max-width: 720px) {{
      .topbar-inner {{
        padding: 0.65rem 1rem;
        flex-wrap: wrap;
        gap: 0.5rem 0.75rem;
      }}
      .brand-group {{
        flex-shrink: 0;
      }}
      .sprite-context, .nav-jump {{
        display: none;
      }}
      .topnav {{
        width: 100%;
        flex-wrap: wrap;
        justify-content: space-between;
        gap: 0.45rem 0.65rem;
        border-top: 1px solid var(--border-subtle);
        padding-top: 0.45rem;
      }}
      .nav-status {{
        border-left: none;
        padding-left: 0;
      }}
      .shell {{
        padding: 1.25rem 1rem 2.5rem;
      }}
      .kpi-strip {{
        grid-template-columns: minmax(0, 1fr);
      }}
      .kpi-cell {{
        border-right: none;
        border-bottom: 1px solid var(--border-subtle);
      }}
      .kpi-cell:last-child {{
        border-bottom: none;
      }}
      .toolbar {{
        width: 100%;
      }}
      .segmented {{
        width: 100%;
      }}
      .seg-tab {{
        flex: 1 1 0;
        text-align: center;
        padding: 0.5rem 0.45rem;
      }}
      .control-select, .control-search {{
        flex: 1 1 140px;
        width: auto;
      }}
      .proof-grid, .triage-grid, .signal-grid, .pipeline-track {{
        grid-template-columns: minmax(0, 1fr);
      }}
      .pipeline-step {{
        border-right: none;
      }}
      .pipeline-step:last-child {{
        border-bottom: none;
      }}
      .dossier-band {{
        padding: 1rem 1rem;
      }}
      .ledger-table thead th.col-duration, .col-duration {{
        display: none;
      }}
      .ledger-table thead th.col-verdict {{
        width: 112px;
      }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      html {{
        scroll-behavior: auto;
      }}
      *, *::before, *::after {{
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }}
    }}
  </style>
</head>
<body id="top">
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-group">
        <a class="brand" href="#top">
          <svg class="brand-mark" viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <rect x="1.5" y="1.5" width="17" height="17" stroke="currentColor" stroke-width="1.6"/>
            <path d="M10 4.5V15.5M4.5 10H15.5" stroke="var(--border)" stroke-width="1.2"/>
            <rect x="7" y="7" width="6" height="6" fill="var(--accent)"/>
          </svg>
          <span>BLASTBOX</span>
        </a>
        <span class="sprite-context mono">{sprite_name} -&gt; {detonator_name}</span>
      </div>
      <nav class="topnav" aria-label="Primary navigation">
        <a class="nav-jump" href="#runs">Runs</a>
        <a class="nav-jump" href="#architecture">Architecture</a>
        <a href="/api/runs">JSON API</a>
        <a href="/health">Health</a>
        <div class="theme-switch" role="group" aria-label="Theme mode">
          <button type="button" class="theme-btn" data-theme-set="lab" aria-pressed="true">Lab</button>
          <button type="button" class="theme-btn" data-theme-set="hacksgiving" aria-pressed="false">Hacksgiving</button>
        </div>
        <span class="nav-status {secret_status_cls}">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="M5.2 8.1L7.1 10L11 6.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="square"/>
          </svg>
          <span>{secret_status_text}</span>
        </span>
      </nav>
    </div>
  </header>

  <main class="shell">
    <section class="console-head">
      <div class="console-title-row">
        <h1>Isolated PR, MCP, and SKILL.md detonation</h1>
        <p class="console-desc">
          Untrusted pull requests, stdio MCP servers, and agent <code>SKILL.md</code> packages triggered directly or via Slack <code>@blastbox boom</code> detonate inside an unlabeled, deny-all egress Fly.io Sprite under kernel strace, rewind to a clean overlay checkpoint, and receive zero-secret triage from the controller Sprite.
        </p>
      </div>
      <div class="kpi-strip" role="region" aria-label="Isolation and detonation summary">
        <div class="kpi-cell">
          <div class="kpi-label">Recorded detonations</div>
          <div class="kpi-value">{total_runs}</div>
          <div class="kpi-note">{pr_count} PR, {mcp_count} MCP, {skill_count} SKILL.md, {blocked_count} blocked, {passed_count} passed</div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">Detonator isolation</div>
          <div class="kpi-value kpi-ok">Air-gapped</div>
          <div class="kpi-note">{agent_note}</div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">Controller policy</div>
          <div class="kpi-value">403 / 201</div>
          <div class="kpi-note">3 zero-secret Connectors, /user/repos denied</div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">Overlay rollback</div>
          <div class="kpi-value">{rollback_value}</div>
          <div class="kpi-note">{rollback_note}</div>
        </div>
      </div>
    </section>

    <section id="runs" class="workbench-section">
      <div class="section-bar">
        <div class="section-title-group">
          <h2>Detonation runs</h2>
          <span class="updated-note">Updated <span class="mono">{updated_at_display}</span></span>
        </div>
        <div class="toolbar">
          <div class="segmented" role="tablist" aria-label="Filter by target kind">
            <button type="button" class="seg-tab" role="tab" aria-selected="true" data-kind-filter="all">All ({total_runs})</button>
            <button type="button" class="seg-tab" role="tab" aria-selected="false" data-kind-filter="pr">GitHub PR ({pr_count})</button>
            <button type="button" class="seg-tab" role="tab" aria-selected="false" data-kind-filter="mcp">MCP server ({mcp_count})</button>
            <button type="button" class="seg-tab" role="tab" aria-selected="false" data-kind-filter="skill">SKILL.md ({skill_count})</button>
          </div>
          <select id="verdict-filter" class="control-select" aria-label="Filter by verdict">
            <option value="all">All verdicts</option>
            <option value="BLOCK">Block</option>
            <option value="REVIEW">Review</option>
            <option value="PASS">Pass</option>
          </select>
          <input id="run-search" class="control-search" type="search" aria-label="Search runs" placeholder="Search target, run ID, or checkpoint">
        </div>
      </div>

      <div class="workbench">
        <div class="ledger-pane">
          <table class="ledger-table" aria-label="Detonation run ledger">
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col" class="col-verdict">Verdict</th>
                <th scope="col" class="col-duration">Duration</th>
              </tr>
            </thead>
            <tbody id="ledger-body">
              {ledger_body}
            </tbody>
          </table>
          <div id="ledger-empty" class="ledger-empty"{ledger_empty_hidden}>
            {'No detonation runs recorded yet.' if total_runs == 0 else 'No runs match the current filters.'}
          </div>
        </div>

        <article id="dossier-pane" class="dossier-pane" aria-live="polite">
          {initial_dossier}
        </article>
      </div>
    </section>

    <section id="architecture" class="arch-section">
      <h2>Two-Sprite air-gapped rollback architecture</h2>
      <p class="arch-intro">
        Untrusted code never shares a VM with Sprites Connectors or the public dashboard. Detonation executes inside an unlabeled, deny-all egress Sprite, while an autonomous controller Sprite plans probes, rewinds the overlay, scores kernel syscalls, and publishes reports.
      </p>

      <ol class="pipeline-track">
        <li class="pipeline-step">
          <div class="step-index">Step 1</div>
          <h3 class="step-title">Air-gap preflight</h3>
          <p class="step-desc">Verify <code>{detonator_name}</code> holds 0 secrets, 0 labels, and active <code class="nowrap">* -&gt; deny</code> network policy, then snapshot baseline FS and checkpoint.</p>
        </li>
        <li class="pipeline-step">
          <div class="step-index">Step 2</div>
          <h3 class="step-title">LLM probe planning</h3>
          <p class="step-desc">Controller Sprite inspects PR tree or MCP <code>tools/list</code> via OpenRouter Connector and plans targeted tool calls and stages.</p>
        </li>
        <li class="pipeline-step">
          <div class="step-index">Step 3</div>
          <h3 class="step-title">Strace detonation</h3>
          <p class="step-desc">Run planned install, tests, or MCP calls inside <code>{detonator_name}</code> under expanded <code>strace -f</code> and capture pre/post FS diff.</p>
        </li>
        <li class="pipeline-step">
          <div class="step-index">Step 4</div>
          <h3 class="step-title">Overlay rewind</h3>
          <p class="step-desc">Pull traces, execute <code>sprite restore</code> on <code>{detonator_name}</code>, verify 0 remaining <code>/home/sprite</code> diffs, and sweep <code>/tmp</code>.</p>
        </li>
        <li class="pipeline-step">
          <div class="step-index">Step 5</div>
          <h3 class="step-title">Deterministic triage</h3>
          <p class="step-desc">Score syscalls, DNS, FS diffs, and prompt injection deterministically, then publish GitHub, Slack, and dashboard verdicts.</p>
        </li>
      </ol>

      <figure class="arch-figure">
        <div class="arch-figure-media">
          <img src="/assets/hacksgiving-turkey.png" alt="Hand-drawn illustration of a controller robot chef rewinding an armored glass oven containing a detonating payload" loading="lazy">
        </div>
        <figcaption class="arch-figure-caption">
          <h3>Hacksgiving detonation and rewind</h3>
          <p>
            The controller Sprite watches GitHub PRs and Slack <code>#blastbox</code>, detonates untrusted payloads behind an armored deny-all network wall on <code>{detonator_name}</code>, and rewinds the overlay checkpoint back to clean steel.
          </p>
          <ul class="arch-slack-list">
            <li><code class="nowrap">@blastbox boom poisoned-skill</code></li>
            <li><code class="nowrap">@blastbox boom clean-skill</code></li>
            <li><code class="nowrap">@blastbox boom https://.../SKILL.md</code></li>
          </ul>
        </figcaption>
      </figure>

      <div class="arch-details">
        <div class="arch-col">
          <h3>Two-Sprite security boundary</h3>
          <table class="boundary-table">
            <thead>
              <tr>
                <th scope="col">Sprite role</th>
                <th scope="col">Connectors and network</th>
                <th scope="col">Trust boundary</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><span class="mono">{sprite_name}</span> (Controller)</td>
                <td>GitHub + OpenRouter + Slack Bot Connectors (<code>HTTP 403</code> on <code>/user/repos</code>)</td>
                <td>Never executes untrusted PR, MCP, or SKILL.md code</td>
              </tr>
              <tr>
                <td><span class="mono">{detonator_name}</span> (Detonator)</td>
                <td>Zero labels (Connectors denied), <code class="nowrap">* -&gt; deny</code> egress</td>
                <td>Runs untrusted code; rewound via <code class="nowrap">sprite restore</code></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="arch-col">
          <h3>Generic filesystem diff and checkpoint persistence</h3>
          <p>
            Instead of looking for a single hardcoded marker file, Blastbox hashes and snapshots <code>/home/sprite</code> and <code>/tmp</code> before detonation, after detonation, and after <code>sprite restore</code>.
          </p>
          <p>
            Every file created outside the workspace is flagged in telemetry and verified absent after overlay rewind, while sanitized history lives safely on the separate Controller Sprite.
          </p>
        </div>
      </div>
    </section>

    <footer>
      <div>
        Blastbox on Fly.io Sprites (<span class="mono">{sprite_name}</span> -&gt; <span class="mono">{detonator_name}</span>) &middot; Connectors: GitHub <span class="mono">{html.escape(GITHUB_CONNECTOR_ID)}</span>, OpenRouter <span class="mono">{html.escape(OPENROUTER_CONNECTOR_ID)}</span>, Slack <span class="mono">{html.escape(SLACK_CONNECTOR_ID)}</span>
      </div>
      <div class="footer-links">
        <a href="/api/runs">/api/runs</a>
        <a href="/health">/health</a>
        <span>Zero raw tokens or host paths exposed</span>
      </div>
    </footer>
  </main>

  <script id="blastbox-runs-data" type="application/json">{runs_json_safe}</script>
  <script>
    (function () {{
      var dataEl = document.getElementById("blastbox-runs-data");
      var ledgerBody = document.getElementById("ledger-body");
      var ledgerEmpty = document.getElementById("ledger-empty");
      var dossierPane = document.getElementById("dossier-pane");
      var verdictSelect = document.getElementById("verdict-filter");
      var searchInput = document.getElementById("run-search");
      var kindTabs = Array.prototype.slice.call(document.querySelectorAll("[data-kind-filter]"));
      if (!dataEl || !ledgerBody || !dossierPane) return;

      var runs = [];
      try {{
        runs = JSON.parse(dataEl.textContent || "[]");
      }} catch (_err) {{
        runs = [];
      }}
      var runsById = Object.create(null);
      for (var i = 0; i < runs.length; i++) {{
        runsById[runs[i].run_id] = runs[i];
      }}

      var SIGNAL_SPECS = [
        ["sensitive_file_probes", "Sensitive file probes"],
        ["unexpected_writes", "Unexpected writes"],
        ["network_connects", "Network connects"],
        ["dns_queries", "DNS queries"],
        ["notable_subprocesses", "Notable subprocesses"],
        ["connector_policy_denials", "Connector / gateway blocks"],
        ["prompt_injection_signals", "README prompt injection"],
        ["mcp_tool_poisoning", "MCP metadata poisoning"]
      ];

      function escapeHtml(val) {{
        return String(val == null ? "" : val)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }}

      function isHttpUrl(url) {{
        return typeof url === "string" && (url.indexOf("https://") === 0 || url.indexOf("http://") === 0);
      }}

      function verdictClass(v) {{
        if (v === "BLOCK") return "status-block";
        if (v === "REVIEW") return "status-review";
        if (v === "PASS") return "status-pass";
        return "status-neutral";
      }}

      function splitFindingPoints(text) {{
        var match = String(text).match(/\\s*\\[\\+(\\d+)\\]\\s*$/);
        if (!match) return {{ text: String(text), pts: "" }};
        return {{
          text: String(text).slice(0, match.index).trim(),
          pts: "+" + match[1] + " pts"
        }};
      }}

      function renderDossier(run) {{
        if (!run) {{
          dossierPane.innerHTML =
            '<div class="dossier-empty">' +
            '<h3>No matching detonation run</h3>' +
            '<p>Adjust the kind tabs, verdict selector, or search query to inspect a recorded run.</p>' +
            '</div>';
          return;
        }}
        var vCls = verdictClass(run.verdict);
        var score = Math.max(0, Math.min(100, Number(run.risk_score) || 0));
        var targetLabel = escapeHtml(run.target_label);
        var titleHtml = isHttpUrl(run.target_url)
          ? '<a class="dossier-title-link" href="' + escapeHtml(run.target_url) + '" target="_blank" rel="noopener">' + targetLabel + '</a>'
          : targetLabel;

        var actionHtml = "";
        var ghProof = "";
        if (isHttpUrl(run.github_artifact_url)) {{
          actionHtml = '<a class="primary-action" href="' + escapeHtml(run.github_artifact_url) + '" target="_blank" rel="noopener">Open GitHub report</a>';
          ghProof = run.github_publish_status != null ? "HTTP " + escapeHtml(run.github_publish_status) : "Published";
        }} else if (run.github_publish_status == null) {{
          actionHtml = '<span class="dossier-action-muted">Skipped (--no-post)</span>';
          ghProof = "Skipped (--no-post)";
        }} else {{
          actionHtml = '<span class="dossier-action-muted">HTTP ' + escapeHtml(run.github_publish_status) + '</span>';
          ghProof = "HTTP " + escapeHtml(run.github_publish_status);
        }}

        var counts = run.ioc_counts || {{}};
        var maxSig = 1;
        for (var s = 0; s < SIGNAL_SPECS.length; s++) {{
          var cVal = Number(counts[SIGNAL_SPECS[s][0]]) || 0;
          if (cVal > maxSig) maxSig = cVal;
        }}
        var signalsHtml = "";
        for (var j = 0; j < SIGNAL_SPECS.length; j++) {{
          var sKey = SIGNAL_SPECS[j][0];
          var sLabel = SIGNAL_SPECS[j][1];
          var val = Number(counts[sKey]) || 0;
          var pct = val > 0 ? Math.round((val / maxSig) * 100) : 0;
          var cls = val > 0 ? "signal-item signal-active" : "signal-item signal-zero";
          signalsHtml +=
            '<div class="' + cls + '">' +
            '<div class="signal-head"><span class="signal-name">' + escapeHtml(sLabel) + '</span><span class="signal-val">' + val + '</span></div>' +
            '<div class="signal-track" aria-hidden="true"><span class="signal-bar" style="width:' + pct + '%"></span></div>' +
            '</div>';
        }}

        var piText = "None detected";
        var piCls = "proof-ok";
        if (run.prompt_injection_detected && run.prompt_injection_resisted) {{
          piText = "Detected and resisted";
          piCls = "proof-ok";
        }} else if (run.prompt_injection_detected) {{
          piText = "Detected, not resisted";
          piCls = "proof-alert";
        }}

        var findings = Array.isArray(run.top_findings) ? run.top_findings : [];
        var findingsHtml = "";
        if (findings.length === 0) {{
          findingsHtml = '<li class="finding-row"><span class="finding-text">No out-of-policy kernel, filesystem, or metadata signals recorded.</span></li>';
        }} else {{
          for (var f = 0; f < findings.length; f++) {{
            var split = splitFindingPoints(findings[f]);
            findingsHtml +=
              '<li class="finding-row"><span class="finding-text">' + escapeHtml(split.text) + '</span>' +
              (split.pts ? '<span class="finding-pts">' + escapeHtml(split.pts) + '</span>' : '') +
              '</li>';
          }}
        }}

        var fsCreated = Array.isArray(run.fs_created_during_detonation) ? run.fs_created_during_detonation.length : 0;
        var rollbackCls = run.rollback_verified ? "proof-ok" : "proof-alert";
        var rollbackNote = run.rollback_verified ? ("Verified clean (" + fsCreated + " created -> 0 left)") : "Unverified";
        var zeroCls = run.zero_secrets_verified ? "proof-ok" : "proof-alert";
        var zeroNote = run.zero_secrets_verified ? "Verified (0 tokens)" : "Failed";
        var syscalls = (Number(counts.total_strace_lines) || 0).toLocaleString("en-US");
        var summaryHtml = run.executive_summary
          ? '<p class="ai-summary">' + escapeHtml(run.executive_summary) + '</p>'
          : "";

        var plan = run.agent_plan || {{}};
        var planHtml = "";
        if (plan.rationale) {{
          var targets = Array.isArray(plan.targets) && plan.targets.length ? plan.targets.join(", ") : "Default stages";
          var susp = Array.isArray(plan.suspicious_tools) && plan.suspicious_tools.length
            ? ' (flagged suspicious: <span class="mono">' + escapeHtml(plan.suspicious_tools.join(", ")) + '</span>)'
            : "";
          planHtml =
            '<div class="plan-block">' +
              '<div class="plan-meta">Agent probe plan (<span class="mono">' + escapeHtml(plan.planner_source || "n/a") + '</span>): ' +
              'exercised <span class="mono">' + escapeHtml(targets) + '</span>' + susp + '</div>' +
              '<p class="plan-rationale">' + escapeHtml(plan.rationale) + '</p>' +
            '</div>';
        }}

        dossierPane.classList.add("is-updating");
        dossierPane.innerHTML =
          '<div class="dossier-band dossier-head">' +
            '<div class="dossier-head-main">' +
              '<h3 class="dossier-title">' + titleHtml + '</h3>' +
              '<p class="dossier-sub">' + escapeHtml(run.target_kind_label) + ' &middot; ' + escapeHtml(run.timestamp_full) + '</p>' +
            '</div>' +
            '<div class="dossier-head-action">' + actionHtml + '</div>' +
          '</div>' +
          '<div class="dossier-band risk-band">' +
            '<div class="risk-meta">' +
              '<div class="risk-verdict-wrap">' +
                '<span class="status-cell ' + vCls + '">' + escapeHtml(run.verdict) + '</span>' +
                '<span class="risk-score-text">Risk score <strong>' + score + ' / 100</strong></span>' +
              '</div>' +
              '<span class="risk-duration">Duration <span class="mono">' + escapeHtml(run.wall_seconds) + 's</span></span>' +
            '</div>' +
            '<div class="risk-track" role="progressbar" aria-valuenow="' + score + '" aria-valuemin="0" aria-valuemax="100" aria-label="Risk score">' +
              '<span class="risk-fill ' + vCls + '" style="width:' + score + '%"></span>' +
            '</div>' +
          '</div>' +
          '<div class="dossier-band">' +
            '<dl class="proof-grid">' +
              '<div class="proof-item"><dt>Run ID</dt><dd class="mono">' + escapeHtml(run.run_id) + '</dd></div>' +
              '<div class="proof-item"><dt>Detonator sandbox</dt><dd class="mono">' + escapeHtml(run.detonator_isolation) + '</dd></div>' +
              '<div class="proof-item"><dt>Filesystem rollback</dt><dd><span class="mono">' + escapeHtml(run.checkpoint_restored) + '</span> &middot; <span class="' + rollbackCls + '">' + escapeHtml(rollbackNote) + '</span></dd></div>' +
              '<div class="proof-item"><dt>Zero-secret VM</dt><dd class="' + zeroCls + '">' + zeroNote + '</dd></div>' +
              '<div class="proof-item"><dt>Controller policy</dt><dd class="mono">HTTP ' + escapeHtml(run.policy_403_status) + ' on /user/repos &middot; ' + ghProof + '</dd></div>' +
              '<div class="proof-item"><dt>Syscalls traced</dt><dd class="mono">' + escapeHtml(syscalls) + '</dd></div>' +
            '</dl>' +
          '</div>' +
          '<div class="dossier-band">' +
            '<h4 class="band-title">Deterministic kernel and metadata signals</h4>' +
            '<div class="signal-grid">' + signalsHtml + '</div>' +
          '</div>' +
          '<div class="dossier-band">' +
            '<h4 class="band-title">AI agent planning and triage</h4>' +
            '<dl class="triage-grid">' +
              '<div class="proof-item"><dt>Model</dt><dd class="mono">' + escapeHtml(run.openrouter_model) + '</dd></div>' +
              '<div class="proof-item"><dt>AI verdict</dt><dd><span class="mono">' + escapeHtml(run.llm_verdict) + '</span></dd></div>' +
              '<div class="proof-item"><dt>Prompt injection</dt><dd class="' + piCls + '">' + piText + '</dd></div>' +
            '</dl>' +
            planHtml +
            summaryHtml +
          '</div>' +
          '<div class="dossier-band dossier-band-last">' +
            '<h4 class="band-title">Top deterministic findings</h4>' +
            '<ul class="findings-list">' + findingsHtml + '</ul>' +
          '</div>';
        window.requestAnimationFrame(function () {{
          dossierPane.classList.remove("is-updating");
        }});
      }}

      var activeKind = "all";
      var activeRunId = runs.length ? runs[0].run_id : "";

      function getAllRows() {{
        return Array.prototype.slice.call(ledgerBody.querySelectorAll("tr.run-row"));
      }}

      function selectRun(runId, focusRow) {{
        activeRunId = runId;
        var rows = getAllRows();
        for (var i = 0; i < rows.length; i++) {{
          var matched = rows[i].getAttribute("data-run-id") === runId;
          rows[i].classList.toggle("is-active", matched);
          rows[i].setAttribute("aria-selected", matched ? "true" : "false");
          if (matched && focusRow) rows[i].focus();
        }}
        renderDossier(runsById[runId] || null);
      }}

      function applyFilters() {{
        var verdictVal = verdictSelect ? verdictSelect.value : "all";
        var query = searchInput ? searchInput.value.trim().toLowerCase() : "";
        var rows = getAllRows();
        var visibleRows = [];
        for (var i = 0; i < rows.length; i++) {{
          var row = rows[i];
          var kindOk = activeKind === "all" || row.getAttribute("data-kind") === activeKind;
          var verdictOk = verdictVal === "all" || row.getAttribute("data-verdict") === verdictVal;
          var searchText = row.getAttribute("data-search") || "";
          var searchOk = !query || searchText.indexOf(query) !== -1;
          var show = kindOk && verdictOk && searchOk;
          row.hidden = !show;
          if (show) visibleRows.push(row);
        }}
        if (ledgerEmpty) {{
          ledgerEmpty.hidden = visibleRows.length > 0;
        }}
        var activeVisible = visibleRows.some(function (r) {{
          return r.getAttribute("data-run-id") === activeRunId;
        }});
        if (!activeVisible) {{
          if (visibleRows.length > 0) {{
            selectRun(visibleRows[0].getAttribute("data-run-id"), false);
          }} else {{
            activeRunId = "";
            renderDossier(null);
          }}
        }}
      }}

      ledgerBody.addEventListener("click", function (ev) {{
        var row = ev.target && ev.target.closest ? ev.target.closest("tr.run-row") : null;
        if (!row) return;
        selectRun(row.getAttribute("data-run-id"), false);
      }});

      ledgerBody.addEventListener("keydown", function (ev) {{
        var row = ev.target && ev.target.closest ? ev.target.closest("tr.run-row") : null;
        if (!row) return;
        var visibleRows = getAllRows().filter(function (r) {{ return !r.hidden; }});
        var idx = visibleRows.indexOf(row);
        if (ev.key === "Enter" || ev.key === " ") {{
          ev.preventDefault();
          selectRun(row.getAttribute("data-run-id"), false);
        }} else if (ev.key === "ArrowDown" && idx >= 0 && idx < visibleRows.length - 1) {{
          ev.preventDefault();
          selectRun(visibleRows[idx + 1].getAttribute("data-run-id"), true);
        }} else if (ev.key === "ArrowUp" && idx > 0) {{
          ev.preventDefault();
          selectRun(visibleRows[idx - 1].getAttribute("data-run-id"), true);
        }}
      }});

      kindTabs.forEach(function (tab) {{
        tab.addEventListener("click", function () {{
          activeKind = tab.getAttribute("data-kind-filter") || "all";
          kindTabs.forEach(function (t) {{
            t.setAttribute("aria-selected", t === tab ? "true" : "false");
          }});
          applyFilters();
        }});
      }});

      if (verdictSelect) verdictSelect.addEventListener("change", applyFilters);
      if (searchInput) searchInput.addEventListener("input", applyFilters);

      var themeButtons = Array.prototype.slice.call(document.querySelectorAll("[data-theme-set]"));
      function applyTheme(mode) {{
        var next = mode === "hacksgiving" ? "hacksgiving" : "lab";
        if (next === "hacksgiving") {{
          document.documentElement.setAttribute("data-theme", "hacksgiving");
        }} else {{
          document.documentElement.setAttribute("data-theme", "lab");
        }}
        themeButtons.forEach(function (btn) {{
          btn.setAttribute("aria-pressed", btn.getAttribute("data-theme-set") === next ? "true" : "false");
        }});
        try {{
          localStorage.setItem("blastbox-theme", next);
        }} catch (e) {{}}
      }}
      var initialTheme = document.documentElement.getAttribute("data-theme") || "lab";
      applyTheme(initialTheme);
      themeButtons.forEach(function (btn) {{
        btn.addEventListener("click", function () {{
          applyTheme(btn.getAttribute("data-theme-set"));
        }});
      }});
    }})();
  </script>
</body>
</html>
"""


class BlastboxHandler(BaseHTTPRequestHandler):
    server_version = "BlastboxWeb/2.0"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[blastbox-web] {self.address_string()} - {format % args}", flush=True)

    def _send_bytes(
        self,
        status: int,
        content_type: str,
        body: bytes,
        *,
        cache_control: str = "no-store",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ALLOWED_ASSETS:
            asset_path, content_type = ALLOWED_ASSETS[path]
            if not asset_path.is_file():
                fallback = REPO_FALLBACK_ASSETS.get(path)
                if fallback is not None and fallback.is_file():
                    asset_path = fallback
            if asset_path.is_file():
                self._send_bytes(
                    200,
                    content_type,
                    asset_path.read_bytes(),
                    cache_control="public, max-age=300",
                )
                return

        history = load_sanitized_history()
        agent_status = load_agent_status()
        zero_secrets_ok = check_zero_secrets_in_env()

        if path == "/health":
            payload = {
                "ok": True,
                "service": "blastbox-web",
                "sprite_name": history.get("sprite_name", "blastbox"),
                "detonator_sprite": history.get("detonator_sprite", DEFAULT_DETONATOR),
                "runs_count": len(history.get("runs", [])),
                "zero_secrets_in_env": zero_secrets_ok,
                "connectors": {
                    "github": GITHUB_CONNECTOR_ID,
                    "openrouter": OPENROUTER_CONNECTOR_ID,
                    "slack_bot": SLACK_CONNECTOR_ID,
                },
                "updated_at": history.get("updated_at"),
                "agent": agent_status,
            }
            self._send_bytes(
                200,
                "application/json; charset=utf-8",
                (json.dumps(payload, indent=2) + "\n").encode("utf-8"),
            )
            return

        if path == "/api/runs":
            self._send_bytes(
                200,
                "application/json; charset=utf-8",
                (json.dumps(history, indent=2) + "\n").encode("utf-8"),
            )
            return

        if path in ("/", "/index.html"):
            page = render_dashboard_html(history, zero_secrets_ok, agent_status=agent_status)
            self._send_bytes(200, "text/html; charset=utf-8", page.encode("utf-8"))
            return

        self._send_bytes(
            404,
            "application/json; charset=utf-8",
            (json.dumps({"error": "not found", "path": path}) + "\n").encode("utf-8"),
        )


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), BlastboxHandler)
    print(f"[blastbox-web] listening on 0.0.0.0:{PORT} (history={HISTORY_PATH})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
