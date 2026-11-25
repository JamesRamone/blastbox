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


SPRITE_BIN = resolve_sprite_bin()
CONTROLLER_SPRITE = (
    os.environ.get("BLASTBOX_CONTROLLER_SPRITE")
    or os.environ.get("BLASTBOX_SPRITE")
    or "blastbox"
)
DETONATOR_SPRITE = os.environ.get("BLASTBOX_DETONATOR_SPRITE") or "blastbox-detonator"

GITHUB_CONNECTOR_ID = os.environ.get("BLASTBOX_GITHUB_CONNECTOR_ID") or "<github-connector-id>"
OPENROUTER_CONNECTOR_ID = os.environ.get("BLASTBOX_OPENROUTER_CONNECTOR_ID") or "<openrouter-connector-id>"
SLACK_CONNECTOR_ID = os.environ.get("BLASTBOX_SLACK_CONNECTOR_ID") or "<slack-connector-id>"
SLACK_PROVIDER = os.environ.get("BLASTBOX_SLACK_PROVIDER") or "slack_bot"

GITHUB_GATEWAY = f"https://api.sprites.dev/v1/gateway/github/{GITHUB_CONNECTOR_ID}"
OPENROUTER_GATEWAY = f"https://api.sprites.dev/v1/gateway/openrouter/{OPENROUTER_CONNECTOR_ID}"
SLACK_GATEWAY = f"https://api.sprites.dev/v1/gateway/{SLACK_PROVIDER}/{SLACK_CONNECTOR_ID}"

SLACK_CHANNELS = [
    c.strip()
    for c in (os.environ.get("BLASTBOX_SLACK_CHANNELS") or "<slack-channel-id>").split(",")
    if c.strip()
]
SLACK_POLL_INTERVAL_SECONDS = max(3, int(os.environ.get("BLASTBOX_SLACK_POLL_INTERVAL", "15")))

DEFAULT_REPO = os.environ.get("BLASTBOX_REPO") or "JamesRamone/hacksgiving-blastbox-demo"
PUBLIC_URL = os.environ.get("BLASTBOX_PUBLIC_URL") or "https://blastbox-3xb.sprites.app"
CONTROLLER_LABEL = os.environ.get("BLASTBOX_CONTROLLER_LABEL") or "hacksgiving"

POLL_INTERVAL_SECONDS = max(5, int(os.environ.get("BLASTBOX_POLL_INTERVAL", "30")))
DETONATION_TIMEOUT_SECONDS = max(5, int(os.environ.get("BLASTBOX_DETONATION_TIMEOUT", "20")))
MAX_DETONATOR_CHECKPOINTS = max(2, int(os.environ.get("BLASTBOX_MAX_CHECKPOINTS", "8")))

OPENROUTER_MODEL = (
    os.environ.get("BLASTBOX_OPENROUTER_MODEL")
    or os.environ.get("OPENROUTER_MODEL")
    or "nvidia/nemotron-3.5-lightning:free"
)
DEFAULT_MODELS = [
    OPENROUTER_MODEL,
    "nvidia/nemotron-3.5-lightning:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "openrouter/free",
]

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
