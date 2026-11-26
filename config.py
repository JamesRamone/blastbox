#!/usr/bin/env python3
"""Centralized configuration and sanitization helpers for Blastbox.

All Sprite names, Sprites Connector IDs, repositories, public URLs, and paths
can be overridden via environment variables (or an optional local `.env` file)
so anyone can self-host Blastbox on their own Fly.io account.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_dotenv_if_present() -> None:
    env_file = SCRIPT_DIR / ".env"
    if not env_file.is_file():
        return
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


_load_dotenv_if_present()


def resolve_sprite_bin() -> str:
    env_bin = os.environ.get("BLASTBOX_SPRITE_BIN")
    if env_bin:
        return env_bin
    which_bin = shutil.which("sprite")
    if which_bin:
        return which_bin
    return str(Path.home() / ".local" / "bin" / "sprite")


def _env_value(name: str, default: str = "") -> str:
    val = (os.environ.get(name) or "").strip()
    if val.startswith("<") and val.endswith(">"):
        return ""
    return val or default


def require_setting(env_name: str, value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned or (cleaned.startswith("<") and cleaned.endswith(">")):
        raise RuntimeError(
            f"Missing required Blastbox setting {env_name}. "
            "Copy .env.example to .env and fill in your Fly.io Connector / repo values."
        )
    return cleaned


def detect_sprite_url(sprite: str) -> str:
    """Resolve `https://...` URL from `sprite info <sprite>` when configured public URL is empty."""
    proc = shutil.which(SPRITE_BIN) or (SPRITE_BIN if Path(SPRITE_BIN).exists() else "")
    if not proc or not sprite:
        return ""
    import subprocess  # local import to keep module lightweight

    res = subprocess.run([proc, "info", sprite], stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return ""
    m = re.search(r"^\s*URL:\s*(https://\S+)", res.stdout, re.MULTILINE)
    return m.group(1).strip() if m else ""


SPRITE_BIN = resolve_sprite_bin()
CONTROLLER_SPRITE = _env_value("BLASTBOX_CONTROLLER_SPRITE") or _env_value("BLASTBOX_SPRITE") or "blastbox"
DETONATOR_SPRITE = _env_value("BLASTBOX_DETONATOR_SPRITE") or "blastbox-detonator"

GITHUB_CONNECTOR_ID = _env_value("BLASTBOX_GITHUB_CONNECTOR_ID")
OPENROUTER_CONNECTOR_ID = _env_value("BLASTBOX_OPENROUTER_CONNECTOR_ID")
OPENAI_CONNECTOR_ID = _env_value("BLASTBOX_OPENAI_CONNECTOR_ID")
ANTHROPIC_CONNECTOR_ID = _env_value("BLASTBOX_ANTHROPIC_CONNECTOR_ID")
SLACK_CONNECTOR_ID = _env_value("BLASTBOX_SLACK_CONNECTOR_ID")
SLACK_PROVIDER = _env_value("BLASTBOX_SLACK_PROVIDER", "slack_bot")

GITHUB_GATEWAY = f"https://api.sprites.dev/v1/gateway/github/{GITHUB_CONNECTOR_ID}" if GITHUB_CONNECTOR_ID else ""
OPENROUTER_GATEWAY = f"https://api.sprites.dev/v1/gateway/openrouter/{OPENROUTER_CONNECTOR_ID}" if OPENROUTER_CONNECTOR_ID else ""
OPENAI_GATEWAY = f"https://api.sprites.dev/v1/gateway/openai/{OPENAI_CONNECTOR_ID}" if OPENAI_CONNECTOR_ID else ""
ANTHROPIC_GATEWAY = f"https://api.sprites.dev/v1/gateway/anthropic/{ANTHROPIC_CONNECTOR_ID}" if ANTHROPIC_CONNECTOR_ID else ""
SLACK_GATEWAY = f"https://api.sprites.dev/v1/gateway/{SLACK_PROVIDER}/{SLACK_CONNECTOR_ID}" if SLACK_CONNECTOR_ID else ""

SLACK_CHANNELS = [
    c.strip()
    for c in _env_value("BLASTBOX_SLACK_CHANNELS").split(",")
    if c.strip()
]
SLACK_CHANNEL_LABEL = _env_value("BLASTBOX_SLACK_CHANNEL_LABEL", "#blastbox")
SLACK_POLL_INTERVAL_SECONDS = max(3, int(_env_value("BLASTBOX_SLACK_POLL_INTERVAL", "15")))

DEFAULT_REPO = _env_value("BLASTBOX_REPO")
PUBLIC_URL = _env_value("BLASTBOX_PUBLIC_URL")
CONTROLLER_LABEL = _env_value("BLASTBOX_CONTROLLER_LABEL", "blastbox")
GOLDEN_CHECKPOINT_COMMENT = "blastbox-detonator-golden"

POLL_INTERVAL_SECONDS = max(5, int(_env_value("BLASTBOX_POLL_INTERVAL", "30")))
DETONATION_TIMEOUT_SECONDS = max(5, int(_env_value("BLASTBOX_DETONATION_TIMEOUT", "20")))
MAX_DETONATOR_CHECKPOINTS = max(2, int(_env_value("BLASTBOX_MAX_CHECKPOINTS", "8")))
ALLOWED_PR_AUTHORS = {
    a.strip().lower()
    for a in _env_value("BLASTBOX_ALLOWED_PR_AUTHORS").split(",")
    if a.strip()
}
MAX_HISTORY_RUNS = max(5, int(_env_value("BLASTBOX_MAX_HISTORY_RUNS", "50")))

LLM_PROVIDER = _env_value("BLASTBOX_LLM_PROVIDER").lower()
if LLM_PROVIDER == "claude":
    LLM_PROVIDER = "anthropic"
if not LLM_PROVIDER:
    if OPENROUTER_CONNECTOR_ID:
        LLM_PROVIDER = "openrouter"
    elif OPENAI_CONNECTOR_ID:
        LLM_PROVIDER = "openai"
    elif ANTHROPIC_CONNECTOR_ID:
        LLM_PROVIDER = "anthropic"
    else:
        LLM_PROVIDER = "openrouter"

OPENROUTER_MODEL = (
    os.environ.get("BLASTBOX_LLM_MODEL")
    or os.environ.get("BLASTBOX_OPENROUTER_MODEL")
    or os.environ.get("OPENROUTER_MODEL")
    or "nvidia/nemotron-3.5-lightning:free"
)
OPENAI_MODEL = os.environ.get("BLASTBOX_LLM_MODEL") or os.environ.get("BLASTBOX_OPENAI_MODEL") or "gpt-4.1-mini"
ANTHROPIC_MODEL = (
    os.environ.get("BLASTBOX_LLM_MODEL")
    or os.environ.get("BLASTBOX_ANTHROPIC_MODEL")
    or "claude-sonnet-4-20250514"
)

PROVIDER_DEFAULT_MODELS: dict[str, list[str]] = {
    "openrouter": [
        OPENROUTER_MODEL,
        "nvidia/nemotron-3.5-lightning:free",
        "nvidia/nemotron-3-ultra-550b-a55b:free",
        "openrouter/free",
    ],
    "openai": [
        OPENAI_MODEL,
        "gpt-4.1-mini",
        "gpt-4o-mini",
    ],
    "anthropic": [
        ANTHROPIC_MODEL,
        "claude-sonnet-4-20250514",
        "claude-3-5-haiku-latest",
    ],
}
DEFAULT_MODELS = list(dict.fromkeys(PROVIDER_DEFAULT_MODELS.get(LLM_PROVIDER, PROVIDER_DEFAULT_MODELS["openrouter"])))


def resolve_llm_connector() -> tuple[str, str, str, list[str]]:
    """Return `(provider, connector_id, gateway_url, model_candidates)` for the active LLM Connector."""
    provider = LLM_PROVIDER
    if provider == "openai":
        cid = require_setting("BLASTBOX_OPENAI_CONNECTOR_ID", OPENAI_CONNECTOR_ID)
        return "openai", cid, OPENAI_GATEWAY, list(dict.fromkeys(PROVIDER_DEFAULT_MODELS["openai"]))
    if provider == "anthropic":
        cid = require_setting("BLASTBOX_ANTHROPIC_CONNECTOR_ID", ANTHROPIC_CONNECTOR_ID)
        return "anthropic", cid, ANTHROPIC_GATEWAY, list(dict.fromkeys(PROVIDER_DEFAULT_MODELS["anthropic"]))
    if provider == "openrouter":
        cid = require_setting("BLASTBOX_OPENROUTER_CONNECTOR_ID", OPENROUTER_CONNECTOR_ID)
        return "openrouter", cid, OPENROUTER_GATEWAY, list(dict.fromkeys(PROVIDER_DEFAULT_MODELS["openrouter"]))
    raise RuntimeError(f"Unsupported BLASTBOX_LLM_PROVIDER={provider!r} (expected openrouter, openai, or anthropic)")


def call_llm_connector(
    system_prompt: str,
    user_prompt: str,
    *,
    preferred_model: str | None = None,
    max_tokens: int = 700,
    timeout: int = 40,
    user_agent: str = "blastbox-llm/2.0",
) -> tuple[bool, str, str, dict[str, Any], str, list[str]]:
    """Call OpenRouter, OpenAI, or Anthropic via Fly.io Sprites Connector Gateway.

    Returns `(ok, content, model_used, usage, provider, errors)`.
    """
    import json
    import urllib.request

    provider, _cid, gateway, default_models = resolve_llm_connector()
    models: list[str] = []
    if preferred_model:
        models.append(preferred_model)
    for m in default_models:
        if m and m not in models:
            models.append(m)

    errors: list[str] = []
    for model in models:
        if provider == "anthropic":
            url = f"{gateway}/v1/messages"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
                "User-Agent": user_agent,
            }
            body: dict[str, Any] = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": 0.1,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
        else:
            url = f"{gateway}/v1/chat/completions"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": user_agent,
            }
            body = {
                "model": model,
                "temperature": 0.1,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            if provider == "openrouter" and "nemotron" in model:
                body["reasoning"] = {"effort": "none"}

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001 - connection resets etc. must fall through to the next model
            errors.append(f"{provider}/{model}: {str(exc)[:180]}")
            continue

        if not isinstance(parsed, dict):
            errors.append(f"{provider}/{model}: non-dict response")
            continue

        if provider == "anthropic":
            blocks = parsed.get("content")
            if not isinstance(blocks, list) or not blocks:
                errors.append(f"{provider}/{model}: empty content")
                continue
            content = "\n".join(
                str(b.get("text") or "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
            ).strip()
        else:
            choices = parsed.get("choices")
            if not isinstance(choices, list) or not choices:
                errors.append(f"{provider}/{model}: empty choices")
                continue
            content = str((choices[0].get("message") or {}).get("content") or "").strip()

        if not content:
            errors.append(f"{provider}/{model}: empty text")
            continue

        usage = parsed.get("usage") if isinstance(parsed.get("usage"), dict) else {}
        return True, content, str(parsed.get("model") or model), usage, provider, errors

    return False, "", "deterministic-fallback", {}, provider, errors


FORBIDDEN_ENV_VARS = (
    "GITHUB_TOKEN",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
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


def redact_host_paths(text: str) -> str:
    """Redact local workstation paths while preserving /home/sprite/... VM paths."""

    def _repl(match: re.Match[str]) -> str:
        found = match.group(0)
        if found == "/home/sprite" or found.startswith("/home/sprite/"):
            return found
        return "[REDACTED_HOST_PATH]"

    cleaned = HOST_PATH_RE.sub(_repl, text)
    return TOKEN_RE.sub("[REDACTED_TOKEN]", cleaned)


def sanitize_value(obj: Any) -> Any:
    """Recursively strip sensitive keys, token literals, and workstation paths."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if k_lower in SENSITIVE_KEYS or (
                k_lower not in SAFE_METADATA_KEYS and SENSITIVE_KEY_RE.search(k_lower)
            ):
                continue
            cleaned[k] = sanitize_value(v)
        return cleaned
    if isinstance(obj, list):
        return [sanitize_value(item) for item in obj]
    if isinstance(obj, str):
        return redact_host_paths(obj)
    return obj


def check_zero_secrets_in_env() -> bool:
    return not any(var in os.environ for var in FORBIDDEN_ENV_VARS)
