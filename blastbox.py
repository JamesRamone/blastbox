#!/usr/bin/env python3
"""Blastbox — Two-Sprite Air-Gapped PR / Package / MCP Sandbox Auditor.

Architecture:
  - Trusted Controller Sprite (`blastbox`): Holds zero raw API tokens, watches
    PRs, runs LLM probe planning & triage via Sprites Connectors, publishes
    GitHub audit comments/issues, and serves the public status dashboard.
  - Air-Gapped Detonator Sprite (`blastbox-detonator`): Holds ZERO raw tokens,
    ZERO labels (all Connectors denied), and an explicit deny-all outbound
    network policy (`* -> deny`). Executes untrusted targets under expanded
    `strace -f`, diffs the filesystem before/after, and rewinds via `sprite restore`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import agent_planner  # noqa: E402
import config  # noqa: E402
import extract_iocs  # noqa: E402
import init_dashboard  # noqa: E402

PR_URL_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:/.*)?$")
GH_BLOB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
CHECKPOINT_ID_RE = re.compile(r"\b(v\d+)\b")
MAX_REMOTE_SKILL_BYTES = 256 * 1024

# Generic filesystem snapshot helper executed inside the Detonator Sprite.
# Captures /home/sprite (excluding /home/sprite/detonation) and /tmp (excluding /tmp/.blastbox_run).
FS_SNAPSHOT_PY = r"""
import hashlib, json, os
from pathlib import Path

def snap_root(root_str, skip_prefixes):
    out = {}
    root = Path(root_str)
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        # Prune skipped prefixes
        kept_dirs = []
        for d in sorted(dirnames):
            full_d = str(dp / d)
            if any(full_d == sp or full_d.startswith(sp + "/") for sp in skip_prefixes):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            full = dp / name
            full_s = str(full)
            if any(full_s == sp or full_s.startswith(sp + "/") for sp in skip_prefixes):
                continue
            try:
                st = full.lstat()
                if os.path.islink(full_s):
                    out[full_s] = {"type": "link", "target": os.readlink(full_s), "size": st.st_size}
                elif os.path.isfile(full_s):
                    digest = None
                    if st.st_size <= 2 * 1024 * 1024:
                        digest = hashlib.sha256(full.read_bytes()).hexdigest()
                    out[full_s] = {"type": "file", "size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha256": digest}
            except OSError:
                continue
    return out

snapshot = {
    "home": snap_root("/home/sprite", ["/home/sprite/detonation"]),
    "tmp": snap_root("/tmp", ["/tmp/.blastbox_run", "/tmp/.X11-unix", "/tmp/.ICE-unix", "/tmp/systemd-private"]),
    "detonation_exists": Path("/home/sprite/detonation").exists(),
}
print(json.dumps(snapshot))
"""


def log(step: str, msg: str) -> None:
    print(f"[blastbox] [{step}] {msg}", flush=True)


def run_cmd(cmd: list[str], *, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def sprite_exec(
    sprite: str,
    remote_cmd: list[str],
    *,
    files: list[str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = [config.SPRITE_BIN, "exec", "-s", sprite, "--no-stdin"]
    for mapping in files or []:
        cmd.extend(["--file", mapping])
    cmd.append("--")
    cmd.extend(remote_cmd)
    return run_cmd(cmd, check=check)


def sprite_push(sprite: str, local_path: Path, remote_path: str, *, recursive: bool = False) -> None:
    cmd = [config.SPRITE_BIN, "file", "push", "-s", sprite, "-p"]
    if recursive:
        cmd.append("-r")
    cmd.extend([str(local_path), remote_path])
    run_cmd(cmd, check=True)


def sprite_pull(sprite: str, remote_path: str, local_path: Path, *, check: bool = True) -> bool:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [config.SPRITE_BIN, "file", "pull", "-s", sprite, remote_path, str(local_path)]
    proc = run_cmd(cmd, check=False)
    if proc.returncode != 0:
        if check:
            raise RuntimeError(f"sprite file pull failed for {remote_path}: {proc.stderr or proc.stdout}")
        return False
    return True


def _run_controller_python(
    controller_sprite: str,
    script_path: Path,
    args: list[str],
    *,
    local_controller: bool,
    upload_files: list[tuple[Path, str]] | None = None,
    download_files: list[tuple[str, Path]] | None = None,
) -> subprocess.CompletedProcess[str]:
    if local_controller:
        # Execute directly inside the trusted controller Sprite
        for local_src, remote_tmp in upload_files or []:
            Path(remote_tmp).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_src, remote_tmp)
        proc = run_cmd([sys.executable, str(script_path), *args], check=True)
        for remote_tmp, local_dst in download_files or []:
            local_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(remote_tmp, local_dst)
        return proc

    remote_script = f"/tmp/.ctrl_{script_path.name}"
    file_args = [f"{script_path}:{remote_script}"]
    for local_src, remote_tmp in upload_files or []:
        file_args.append(f"{local_src}:{remote_tmp}")
    proc = sprite_exec(controller_sprite, ["/.sprite/bin/python3", remote_script, *args], files=file_args, check=True)
    for remote_tmp, local_dst in download_files or []:
        sprite_pull(controller_sprite, remote_tmp, local_dst, check=True)
    cleanup_targets = [remote_script] + [r for _, r in (upload_files or [])] + [r for r, _ in (download_files or [])]
    sprite_exec(controller_sprite, ["rm", "-f", *cleanup_targets], check=False)
    return proc


def _compute_fs_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    created: list[str] = []
    modified: list[str] = []
    deleted: list[str] = []
    home_created: list[str] = []
    home_modified: list[str] = []
    tmp_created: list[str] = []

    for bucket, target_created, target_modified in (
        ("home", home_created, home_modified),
        ("tmp", tmp_created, []),
    ):
        b_map = before.get(bucket) or {}
        a_map = after.get(bucket) or {}
        for path, a_meta in sorted(a_map.items()):
            if path not in b_map:
                created.append(path)
                target_created.append(path)
            elif b_map[path] != a_meta:
                modified.append(path)
                if bucket == "home":
                    target_modified.append(path)
        for path in sorted(b_map):
            if path not in a_map:
                deleted.append(path)

    return {
        "created_outside_workspace": created,
        "modified_outside_workspace": modified,
        "deleted_outside_workspace": deleted,
        "home_created": home_created,
        "home_modified": home_modified,
        "tmp_created": tmp_created,
    }


def _safe_target_label(local_dir: Path) -> str:
    resolved = local_dir.resolve()
    try:
        return resolved.relative_to(SCRIPT_DIR).as_posix()
    except ValueError:
        return resolved.name


def verify_detonator_preflight(
    controller_sprite: str,
    detonator_sprite: str,
    run_dir: Path,
    *,
    history_path: Path,
    sync_dashboard: bool = True,
    local_controller: bool = False,
) -> dict[str, Any]:
    log("1/9", f"Verifying isolation, zero secrets, and deny-all egress on '{detonator_sprite}'...")

    # 1. Verify detonator has ZERO controller labels (Connectors denied)
    info_proc = run_cmd([config.SPRITE_BIN, "info", detonator_sprite], check=True)
    if config.CONTROLLER_LABEL in info_proc.stdout:
        raise RuntimeError(
            f"SECURITY FAILURE: Detonator '{detonator_sprite}' has label '{config.CONTROLLER_LABEL}'. "
            "Run ./init_detonator.py to lock down the detonator Sprite."
        )

    # 2. Verify active deny-all outbound network policy on detonator
    pol_proc = run_cmd(
        [config.SPRITE_BIN, "api", f"/v1/sprites/{detonator_sprite}/policy/network", "--", "-sS"],
        check=True,
    )
    policy = json.loads(pol_proc.stdout.strip() or "{}")
    rules = policy.get("rules") if isinstance(policy, dict) else []
    deny_all_active = isinstance(rules, list) and any(
        isinstance(r, dict) and r.get("domain") == "*" and r.get("action") == "deny" for r in rules
    )
    if not deny_all_active:
        raise RuntimeError(
            f"SECURITY FAILURE: Detonator '{detonator_sprite}' lacks deny-all network policy (* -> deny): {policy}"
        )

    # 3. Clean stale workspace/scratch, check zero secret env vars, and snapshot FS before
    prep_cmd = (
        'export PATH="/.sprite/bin:$PATH"; '
        "rm -rf /home/sprite/detonation /tmp/.blastbox_run; "
        "mkdir -p /tmp/.blastbox_run; "
        "env | cut -d= -f1 | sort"
    )
    env_proc = sprite_exec(detonator_sprite, ["bash", "-c", prep_cmd], check=True)
    env_names = [line.strip() for line in env_proc.stdout.splitlines() if line.strip()]
    leaked = [var for var in config.FORBIDDEN_ENV_VARS if var in env_names]
    if leaked:
        raise RuntimeError(f"SECURITY FAILURE: Forbidden secret env vars present in '{detonator_sprite}': {leaked}")

    snap_proc = sprite_exec(detonator_sprite, ["/.sprite/bin/python3", "-c", FS_SNAPSHOT_PY], check=True)
    fs_before = json.loads(snap_proc.stdout.strip().splitlines()[-1])
    (run_dir / "fs_before.json").write_text(json.dumps(fs_before, indent=2) + "\n", encoding="utf-8")

    # 4. Ensure controller dashboard is ready (never detonating on controller)
    if sync_dashboard and not local_controller:
        init_dashboard.load_or_init_history(
            history_path, sprite_name=controller_sprite, public_url=config.PUBLIC_URL
        )
        local_hist_sha = hashlib.sha256(history_path.read_bytes()).hexdigest()
        ctrl_proc = sprite_exec(
            controller_sprite,
            [
                "bash",
                "-c",
                (
                    'export PATH="/.sprite/bin:$PATH"; '
                    'WEB_OK=0; if [ -f /home/sprite/blastbox-web/server.py ] && sprite-env services list 2>/dev/null | grep -q "blastbox-web"; then WEB_OK=1; fi; '
                    'HIST_SHA=""; if [ -f /home/sprite/blastbox-web/history.json ]; then '
                    'HIST_SHA=$(sha256sum /home/sprite/blastbox-web/history.json | cut -d" " -f1); fi; '
                    'echo "WEB_OK=$WEB_OK"; echo "HIST_SHA=$HIST_SHA"'
                ),
            ],
            check=True,
        )
        web_ok = False
        remote_sha = ""
        for line in ctrl_proc.stdout.splitlines():
            if line.startswith("WEB_OK="):
                web_ok = line.split("=", 1)[1].strip() == "1"
            elif line.startswith("HIST_SHA="):
                remote_sha = line.split("=", 1)[1].strip()
        if not web_ok:
            log("1/9", "Dashboard service missing on controller; running init_dashboard setup...")
            init_dashboard.setup_dashboard(
                sprite=controller_sprite,
                history_path=history_path,
                public_url=config.PUBLIC_URL,
                create_checkpoint=False,
            )
        elif remote_sha != local_hist_sha:
            init_dashboard.sync_history_to_sprite(controller_sprite, history_path)

    info = {
        "controller_sprite": controller_sprite,
        "detonator_sprite": detonator_sprite,
        "zero_secrets_verified": True,
        "detonator_unlabeled": True,
        "detonator_egress_denied": True,
        "network_policy": policy,
        "checked_absent": list(config.FORBIDDEN_ENV_VARS),
        "env_var_names": env_names,
    }
    (run_dir / "preflight_env.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    log(
        "1/9",
        f"Detonator '{detonator_sprite}' preflight PASSED (0 secrets, 0 labels, * -> deny egress, {len(env_names)} benign env vars).",
    )
    return info


def create_baseline_checkpoint(sprite: str, *, prefix: str = "blastbox-detonator-clean", step_label: str = "2/9") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    comment = f"{prefix}-{ts}"
    log(step_label, f"Creating checkpoint on '{sprite}' ({comment})...")
    proc = run_cmd([config.SPRITE_BIN, "checkpoint", "create", "-s", sprite, "--comment", comment])
    combined = f"{proc.stdout}\n{proc.stderr}"
    m = CHECKPOINT_ID_RE.search(combined)
    if not m:
        raise RuntimeError(f"Could not parse checkpoint version ID from output:\n{combined}")
    version_id = m.group(1)
    log(step_label, f"Checkpoint created on '{sprite}': {version_id}")
    return version_id


def _run_pr_fetch_on_controller(
    controller_sprite: str,
    pr_url: str,
    owner: str,
    repo: str,
    pr_number: int,
    run_dir: Path,
    *,
    local_controller: bool,
) -> tuple[dict[str, Any], Path]:
    fetch_code = f"""
import base64, json, sys, urllib.request
from pathlib import Path

BASE = "{config.GITHUB_GATEWAY}/repos/{owner}/{repo}"
OUT_BUNDLE = Path(sys.argv[1])

def gh_get(path):
    req = urllib.request.Request(BASE + path, headers={{"Accept": "application/vnd.github+json", "User-Agent": "blastbox-fetch/2.0"}})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

pr = gh_get("/pulls/{pr_number}")
head_sha = pr["head"]["sha"]
head_ref = pr["head"]["ref"]
tree = gh_get(f"/git/trees/{{head_sha}}?recursive=1")

files = {{}}
for entry in tree.get("tree", []):
    if entry.get("type") != "blob":
        continue
    rel = entry["path"]
    blob = gh_get(f"/git/blobs/{{entry['sha']}}")
    raw = base64.b64decode(blob["content"]) if blob.get("encoding") == "base64" else blob["content"].encode("utf-8")
    files[rel] = {{
        "b64": base64.b64encode(raw).decode("ascii"),
        "mode": entry.get("mode", "100644"),
    }}

bundle = {{
    "meta": {{
        "mode": "pr",
        "pr_url": pr.get("html_url", "{pr_url}"),
        "owner": "{owner}",
        "repo": "{repo}",
        "pr_number": {pr_number},
        "title": pr.get("title"),
        "author": (pr.get("user") or {{}}).get("login"),
        "head_ref": head_ref,
        "head_sha": head_sha,
        "files_fetched": sorted(files.keys()),
    }},
    "files": files,
}}
OUT_BUNDLE.write_text(json.dumps(bundle), encoding="utf-8")
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_script = Path(tmpdir) / "fetch_pr.py"
        tmp_script.write_text(fetch_code, encoding="utf-8")
        remote_bundle = "/tmp/.ctrl_pr_bundle.json"
        local_bundle = Path(tmpdir) / "pr_bundle.json"
        _run_controller_python(
            controller_sprite,
            tmp_script,
            [remote_bundle],
            local_controller=local_controller,
            download_files=[(remote_bundle, local_bundle)],
        )
        bundle = json.loads(local_bundle.read_text(encoding="utf-8"))

    staged_dir = run_dir / "_staged_pr"
    if staged_dir.exists():
        shutil.rmtree(staged_dir)
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged_resolved = staged_dir.resolve()
    for rel, file_obj in bundle["files"].items():
        target = (staged_resolved / rel).resolve()
        if not target.is_relative_to(staged_resolved):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(file_obj["b64"]))
        if file_obj.get("mode") == "100755":
            os.chmod(target, 0o755)

    meta = bundle["meta"]
    (run_dir / "pr_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta, staged_dir


def _run_agent_planner(
    controller_sprite: str,
    *,
    mode: str,
    input_payload: dict[str, Any],
    run_dir: Path,
    model: str | None,
    local_controller: bool,
) -> dict[str, Any]:
    planner_script = SCRIPT_DIR / "agent_planner.py"
    with tempfile.TemporaryDirectory() as tmpdir:
        local_in = Path(tmpdir) / "planner_input.json"
        local_out = run_dir / "agent_plan.json"
        local_in.write_text(json.dumps(input_payload, indent=2) + "\n", encoding="utf-8")
        remote_in = "/tmp/.ctrl_planner_in.json"
        remote_out = "/tmp/.ctrl_planner_out.json"
        args = ["--mode", mode, "--input", remote_in, "--output", remote_out]
        if model:
            args.extend(["--model", model])
        _run_controller_python(
            controller_sprite,
            planner_script,
            args,
            local_controller=local_controller,
            upload_files=[(local_in, remote_in)],
            download_files=[(remote_out, local_out)],
        )
    return json.loads((run_dir / "agent_plan.json").read_text(encoding="utf-8"))


def _normalize_skill_url(raw_url: str) -> str:
    url = raw_url.strip()
    m = GH_BLOB_RE.match(url)
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}"
    return url


def validate_untrusted_https_url(raw_url: str) -> str:
    """Validate an untrusted HTTPS URL against strict SSRF rules."""
    url = _normalize_skill_url(raw_url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Only HTTPS URLs are permitted for untrusted fetch (got scheme={parsed.scheme!r})")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("URL is missing a hostname")
    if (
        host == "localhost"
        or host == "api.sprites.dev"
        or host.endswith(".sprites.dev")
        or host.endswith(".local")
        or host.endswith(".internal")
        or host.endswith(".localhost")
    ):
        raise ValueError(f"Blocked internal/gateway hostname: {host}")

    # Direct IP literal check
    try:
        ip_lit = ipaddress.ip_address(host)
        if not ip_lit.is_global:
            raise ValueError(f"Blocked non-global IP literal: {host}")
    except ValueError as exc:
        if "Blocked non-global IP" in str(exc):
            raise

    port = parsed.port or 443
    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Failed to resolve host {host}: {exc}") from exc
    if not addr_infos:
        raise ValueError(f"No DNS addresses resolved for {host}")

    for info in addr_infos:
        sockaddr = info[4]
        ip_str = sockaddr[0].split("%", 1)[0]
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_global:
            raise ValueError(f"Blocked non-global resolved IP {ip_str} for host {host}")
    return url


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> urllib.request.Request | None:
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        validated = validate_untrusted_https_url(resolved)
        return super().redirect_request(req, fp, code, msg, headers, validated)


def fetch_untrusted_url_safely(raw_url: str, *, max_bytes: int = MAX_REMOTE_SKILL_BYTES) -> tuple[str, str]:
    """Fetch untrusted Markdown/skill content over HTTPS with SSRF & size guards."""
    safe_url = validate_untrusted_https_url(raw_url)
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    req = urllib.request.Request(
        safe_url,
        headers={
            "Accept": "text/markdown, text/plain;q=0.9, */*;q=0.5",
            "User-Agent": "blastbox-skill-fetch/1.0",
        },
    )
    with opener.open(req, timeout=15) as resp:
        final_url = validate_untrusted_https_url(resp.geturl())
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"Remote target exceeds {max_bytes} byte limit")
    return final_url, raw.decode("utf-8", errors="replace")


def _run_skill_url_fetch_on_controller(
    controller_sprite: str,
    raw_url: str,
    run_dir: Path,
    *,
    local_controller: bool,
) -> tuple[str, str]:
    if local_controller:
        final_url, text = fetch_untrusted_url_safely(raw_url)
        return final_url, text

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        runner = tmp / "fetch_skill.py"
        runner.write_text(
            f"""
import ipaddress, json, re, socket, sys, urllib.parse, urllib.request
from pathlib import Path

GH_BLOB_RE = re.compile(r"^https://github\\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$")
MAX_BYTES = {MAX_REMOTE_SKILL_BYTES}

def validate_url(raw):
    url = raw.strip()
    m = GH_BLOB_RE.match(url)
    if m:
        url = f"https://raw.githubusercontent.com/{{m.group(1)}}/{{m.group(2)}}/{{m.group(3)}}/{{m.group(4)}}"
    p = urllib.parse.urlsplit(url)
    if p.scheme.lower() != "https":
        raise ValueError(f"Only HTTPS URLs permitted (got {{p.scheme!r}})")
    host = (p.hostname or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host == "api.sprites.dev" or host.endswith((".sprites.dev", ".local", ".internal", ".localhost")):
        raise ValueError(f"Blocked internal/gateway hostname: {{host}}")
    try:
        ip_lit = ipaddress.ip_address(host)
        if not ip_lit.is_global:
            raise ValueError(f"Blocked non-global IP literal: {{host}}")
    except ValueError as exc:
        if "Blocked non-global IP" in str(exc):
            raise
    for info in socket.getaddrinfo(host, p.port or 443, type=socket.SOCK_STREAM):
        ip_obj = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not ip_obj.is_global:
            raise ValueError(f"Blocked non-global IP {{ip_obj}} for {{host}}")
    return url

class SafeRedir(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        v = validate_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, v)

safe_u = validate_url({raw_url!r})
req = urllib.request.Request(safe_u, headers={{"Accept": "text/markdown, text/plain;q=0.9", "User-Agent": "blastbox-skill-fetch/1.0"}})
with urllib.request.build_opener(SafeRedir()).open(req, timeout=15) as r:
    final_u = validate_url(r.geturl())
    raw = r.read(MAX_BYTES + 1)
if len(raw) > MAX_BYTES:
    raise ValueError("Remote skill file exceeds 256 KB")
Path(sys.argv[1]).write_text(json.dumps({{"url": final_u, "text": raw.decode("utf-8", errors="replace")}}), encoding="utf-8")
""",
            encoding="utf-8",
        )
        remote_out = "/tmp/.ctrl_skill_bundle.json"
        local_out = tmp / "skill_bundle.json"
        _run_controller_python(
            controller_sprite,
            runner,
            [remote_out],
            local_controller=False,
            download_files=[(remote_out, local_out)],
        )
        data = json.loads(local_out.read_text(encoding="utf-8"))
        return str(data["url"]), str(data["text"])


def stage_and_plan_target(
    *,
    controller_sprite: str,
    detonator_sprite: str,
    resolved_mode: str,
    pr_match: re.Match[str] | None,
    raw_target: str,
    local_dir: Path | None,
    default_repo: str,
    run_dir: Path,
    model: str | None,
    local_controller: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    sprite_exec(
        detonator_sprite,
        ["bash", "-c", "rm -rf /home/sprite/detonation && mkdir -p /home/sprite/detonation /tmp/.blastbox_run"],
        check=True,
    )

    if pr_match:
        owner, repo, pr_num_str = pr_match.group(1), pr_match.group(2), pr_match.group(3)
        log("3/9", f"Fetching PR #{pr_num_str} ({owner}/{repo}) via controller GitHub Connector & planning probes...")
        meta, staged_dir = _run_pr_fetch_on_controller(
            controller_sprite,
            raw_target.strip(),
            owner,
            repo,
            int(pr_num_str),
            run_dir,
            local_controller=local_controller,
        )
        readme_file = staged_dir / "README.md"
        readme_excerpt = readme_file.read_text(encoding="utf-8", errors="replace")[:2000] if readme_file.exists() else ""
        agent_plan = _run_agent_planner(
            controller_sprite,
            mode="pr",
            input_payload={
                "pr_meta": meta,
                "files": meta["files_fetched"],
                "readme_excerpt": readme_excerpt,
            },
            run_dir=run_dir,
            model=model,
            local_controller=local_controller,
        )
        for child in sorted(staged_dir.iterdir()):
            sprite_push(detonator_sprite, child, f"/home/sprite/detonation/{child.name}", recursive=child.is_dir())
        shutil.rmtree(staged_dir, ignore_errors=True)
        meta["controller_sprite"] = controller_sprite
        meta["detonator_sprite"] = detonator_sprite
        log("3/9", f"Staged {len(meta['files_fetched'])} PR files to '{detonator_sprite}' (agent stages={agent_plan.get('stages')}).")
        return meta, agent_plan

    if resolved_mode == "skill":
        skill_url: str | None = None
        if URL_RE.match(raw_target.strip()):
            log("3/9", f"Fetching untrusted SKILL.md via SSRF-guarded Controller '{controller_sprite}'...")
            skill_url, skill_text = _run_skill_url_fetch_on_controller(
                controller_sprite,
                raw_target.strip(),
                run_dir,
                local_controller=local_controller,
            )
            parsed_u = urllib.parse.urlsplit(skill_url)
            skill_label = f"{parsed_u.hostname}{parsed_u.path}"
        else:
            assert local_dir is not None
            if local_dir.is_file():
                skill_file = local_dir
                skill_label = _safe_target_label(local_dir)
            else:
                if not local_dir.is_dir():
                    raise FileNotFoundError(f"Local skill path does not exist: {local_dir}")
                cand_upper = local_dir / "SKILL.md"
                cand_lower = local_dir / "skill.md"
                skill_file = cand_upper if cand_upper.exists() else cand_lower
                if not skill_file.exists():
                    raise FileNotFoundError(f"No SKILL.md found in {local_dir}")
                skill_label = _safe_target_label(local_dir)
            skill_text = skill_file.read_text(encoding="utf-8", errors="replace")

        blocks = agent_planner.extract_fenced_code_blocks(skill_text)
        agent_plan = _run_agent_planner(
            controller_sprite,
            mode="skill",
            input_payload={
                "skill_label": skill_label,
                "skill_text": skill_text,
                "blocks": blocks,
            },
            run_dir=run_dir,
            model=model,
            local_controller=local_controller,
        )

        # Stage SKILL.md and planned executable blocks onto blastbox-detonator
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            local_skill = tmp / "SKILL.md"
            local_skill.write_text(skill_text, encoding="utf-8")
            sprite_push(detonator_sprite, local_skill, "/home/sprite/detonation/SKILL.md")

            blocks_dir = tmp / ".blastbox_skill_blocks"
            blocks_dir.mkdir()
            selected_indices = agent_plan.get("block_indices") or [b["index"] for b in blocks]
            blocks_by_idx = {b["index"]: b for b in blocks}
            manifest_blocks: list[dict[str, str]] = []
            for idx in selected_indices:
                blk = blocks_by_idx.get(idx)
                if not blk:
                    continue
                ext = "py" if blk["lang"] == "python" else "sh"
                fname = f"block_{idx}.{ext}"
                (blocks_dir / fname).write_text(blk["code"], encoding="utf-8")
                manifest_blocks.append({"file": fname, "lang": blk["lang"]})
            (blocks_dir / "manifest.json").write_text(json.dumps(manifest_blocks, indent=2), encoding="utf-8")
            (blocks_dir / "run.py").write_text(
                (
                    "import json, subprocess, sys\n"
                    "from pathlib import Path\n"
                    "bdir = Path('/home/sprite/detonation/.blastbox_skill_blocks')\n"
                    "manifest = json.loads((bdir / 'manifest.json').read_text(encoding='utf-8'))\n"
                    "if not manifest:\n"
                    "    print('[blastbox-skill] No executable code blocks found; static scan only.', flush=True)\n"
                    "for item in manifest:\n"
                    "    fpath = bdir / item['file']\n"
                    "    cmd = [sys.executable, str(fpath)] if item['lang'] == 'python' else ['bash', str(fpath)]\n"
                    "    print(f\"[blastbox-skill] Running {item['file']} ({item['lang']})\", flush=True)\n"
                    "    proc = subprocess.run(cmd, cwd='/home/sprite/detonation', check=False)\n"
                    "    print(f\"[blastbox-skill] {item['file']} exit={proc.returncode}\", flush=True)\n"
                ),
                encoding="utf-8",
            )
            sprite_push(detonator_sprite, blocks_dir, "/home/sprite/detonation/.blastbox_skill_blocks", recursive=True)

        owner, repo = default_repo.split("/", 1)
        log("3/9", f"Staged SKILL.md ({len(manifest_blocks)} planned code blocks) to '{detonator_sprite}'.")
        return (
            {
                "mode": "skill",
                "target_label": skill_label,
                "skill_url": skill_url,
                "owner": owner,
                "repo": repo,
                "controller_sprite": controller_sprite,
                "detonator_sprite": detonator_sprite,
            },
            agent_plan,
        )

    assert local_dir is not None
    if not local_dir.is_dir():
        raise FileNotFoundError(f"Local target directory does not exist: {local_dir}")

    safe_label = _safe_target_label(local_dir)
    log("3/9", f"Staging {resolved_mode} target '{safe_label}' to '{detonator_sprite}' & running discovery/planning...")
    files_list: list[str] = []
    for child in sorted(local_dir.iterdir()):
        if child.name in (".git", "__pycache__", ".pytest_cache"):
            continue
        sprite_push(detonator_sprite, child, f"/home/sprite/detonation/{child.name}", recursive=child.is_dir())
        files_list.append(child.name)

    owner, repo = default_repo.split("/", 1)
    if resolved_mode == "mcp":
        probe_local = SCRIPT_DIR / "mcp_probe.py"
        if not probe_local.exists():
            raise FileNotFoundError(f"Missing MCP probe harness: {probe_local}")
        sprite_push(detonator_sprite, probe_local, "/home/sprite/detonation/.blastbox_mcp_probe.py")

        # Phase A: discover MCP tools/resources/prompts inside detonator
        discover_cmd = (
            'export PATH="/.sprite/bin:$PATH"; '
            "cd /home/sprite/detonation && "
            "/.sprite/bin/python3 /home/sprite/detonation/.blastbox_mcp_probe.py "
            "--work-dir /home/sprite/detonation --discover-only --catalog /tmp/.blastbox_run/mcp_catalog.json"
        )
        sprite_exec(detonator_sprite, ["bash", "-c", discover_cmd], check=True)
        catalog_local = run_dir / "mcp_catalog.json"
        sprite_pull(detonator_sprite, "/tmp/.blastbox_run/mcp_catalog.json", catalog_local, check=True)
        catalog = json.loads(catalog_local.read_text(encoding="utf-8"))

        # Phase B: LLM Agent plans tool calls & arguments inside clean controller
        agent_plan = _run_agent_planner(
            controller_sprite,
            mode="mcp",
            input_payload=catalog,
            run_dir=run_dir,
            model=model,
            local_controller=local_controller,
        )
        sprite_push(detonator_sprite, run_dir / "agent_plan.json", "/tmp/.blastbox_run/agent_plan.json")

        server_name = catalog.get("server_name")
        entrypoint = catalog.get("server_entrypoint") or "server.py"
        planned_names = [c.get("tool") for c in (agent_plan.get("calls") or [])]
        log("3/9", f"LLM probe planner selected MCP tools {planned_names} (suspicious={agent_plan.get('suspicious_tools')}).")
        info = {
            "mode": "mcp",
            "target_label": f"{safe_label} ({server_name})" if server_name else safe_label,
            "owner": owner,
            "repo": repo,
            "controller_sprite": controller_sprite,
            "detonator_sprite": detonator_sprite,
            "entrypoint": entrypoint,
        }
        return info, agent_plan

    readme_file = local_dir / "README.md"
    readme_excerpt = readme_file.read_text(encoding="utf-8", errors="replace")[:2000] if readme_file.exists() else ""
    agent_plan = _run_agent_planner(
        controller_sprite,
        mode="pr",
        input_payload={"pr_meta": {"title": safe_label}, "files": files_list, "readme_excerpt": readme_excerpt},
        run_dir=run_dir,
        model=model,
        local_controller=local_controller,
    )
    info = {
        "mode": resolved_mode,
        "target_label": safe_label,
        "owner": owner,
        "repo": repo,
        "controller_sprite": controller_sprite,
        "detonator_sprite": detonator_sprite,
    }
    return info, agent_plan


def run_strace_detonation(
    detonator_sprite: str,
    run_dir: Path,
    *,
    mode: str,
    agent_plan: dict[str, Any],
) -> dict[str, Any]:
    timeout_s = config.DETONATION_TIMEOUT_SECONDS
    if mode == "mcp":
        log("4/9", f"Detonating MCP probe plan inside air-gapped '{detonator_sprite}' under strace ({timeout_s}s timeout)...")
        inner_cmd = (
            '    cd /home/sprite/detonation\n'
            '    echo "=== [blastbox] mcp stdio JSON-RPC planned probe ==="\n'
            '    "\'"$REAL_PYTHON"\'" /home/sprite/detonation/.blastbox_mcp_probe.py '
            '--work-dir /home/sprite/detonation '
            '--plan /tmp/.blastbox_run/agent_plan.json '
            '--transcript /home/sprite/detonation/.blastbox_mcp_transcript.json'
        )
    elif mode == "skill":
        targets = agent_plan.get("targets") or []
        log("4/9", f"Detonating SKILL.md blocks {targets} inside air-gapped '{detonator_sprite}' under strace ({timeout_s}s timeout)...")
        inner_cmd = (
            '    cd /home/sprite/detonation\n'
            '    echo "=== [blastbox] SKILL.md fenced code detonation ==="\n'
            '    "\'"$REAL_PYTHON"\'" /home/sprite/detonation/.blastbox_skill_blocks/run.py'
        )
    else:
        stages = [s for s in (agent_plan.get("stages") or []) if s in ("pip_install", "unittest", "pytest", "import_check")]
        if not stages:
            stages = ["pip_install", "unittest"]
        log("4/9", f"Detonating PR/package stages {stages} inside air-gapped '{detonator_sprite}' under strace ({timeout_s}s timeout)...")
        stage_cmds = ['    cd /home/sprite/detonation']
        if "pip_install" in stages:
            stage_cmds.extend(
                [
                    '    if [ -f setup.py ] || [ -f pyproject.toml ]; then',
                    '      echo "=== [blastbox] pip install (offline, no build isolation) ==="',
                    '      "\'"$REAL_PYTHON"\'" -m pip install --no-build-isolation --no-deps --no-cache-dir --disable-pip-version-check --target /home/sprite/detonation/.pkg_install .',
                    '    fi',
                ]
            )
        if "unittest" in stages:
            stage_cmds.extend(
                [
                    '    if [ -d tests ]; then',
                    '      echo "=== [blastbox] unittest discover ==="',
                    '      PYTHONPATH=/home/sprite/detonation/.pkg_install "\'"$REAL_PYTHON"\'" -m unittest discover -s tests -v',
                    '    fi',
                ]
            )
        if "pytest" in stages and "unittest" not in stages:
            stage_cmds.extend(
                [
                    '    if [ -d tests ] && "\'"$REAL_PYTHON"\'" -m pytest --version >/dev/null 2>&1; then',
                    '      echo "=== [blastbox] pytest ==="',
                    '      PYTHONPATH=/home/sprite/detonation/.pkg_install "\'"$REAL_PYTHON"\'" -m pytest -q',
                    '    elif [ -d tests ]; then',
                    '      echo "=== [blastbox] unittest discover ==="',
                    '      PYTHONPATH=/home/sprite/detonation/.pkg_install "\'"$REAL_PYTHON"\'" -m unittest discover -s tests -v',
                    '    fi',
                ]
            )
        if "import_check" in stages and "unittest" not in stages and "pytest" not in stages:
            stage_cmds.append(
                '    PYTHONPATH=/home/sprite/detonation/.pkg_install:/home/sprite/detonation "\'"$REAL_PYTHON"\'" -c "import os, pkgutil; print([m.name for m in pkgutil.iter_modules([\".\", \".pkg_install\"])])"'
            )
        inner_cmd = "\n".join(stage_cmds)

    trace_events = (
        "execve,execveat,open,openat,openat2,creat,connect,sendto,sendmsg,sendmmsg,"
        "socket,unlink,unlinkat,rename,renameat,renameat2,link,linkat,symlink,symlinkat,chmod,fchmodat"
    )

    detonate_bash = f"""
export PATH="/.sprite/bin:$PATH"
REAL_PYTHON="$(/.sprite/bin/python3 -c 'import sys; print(sys.executable)')"
mkdir -p /home/sprite/detonation/.blastbox_tmp /home/sprite/detonation/.pkg_install /tmp/.blastbox_run
rm -f /tmp/.blastbox_run/blastbox.strace /tmp/.blastbox_run/command.stdout /tmp/.blastbox_run/command.stderr /tmp/.blastbox_run/detonation_meta.json
TMPDIR=/home/sprite/detonation/.blastbox_tmp \\
PIP_DISABLE_PIP_VERSION_CHECK=1 \\
PIP_NO_CACHE_DIR=1 \\
timeout {timeout_s}s strace -f -s 256 \\
  -e trace={trace_events} \\
  -o /tmp/.blastbox_run/blastbox.strace \\
  bash -c '
{inner_cmd}
  ' >/tmp/.blastbox_run/command.stdout 2>/tmp/.blastbox_run/command.stderr
RC=$?
/.sprite/bin/python3 - <<'PY' "$RC"
import json, sys
from pathlib import Path
strace_file = Path("/tmp/.blastbox_run/blastbox.strace")
meta = {{
    "exit_code": int(sys.argv[1]),
    "timed_out": int(sys.argv[1]) == 124,
    "strace_bytes": strace_file.stat().st_size if strace_file.exists() else 0,
}}
Path("/tmp/.blastbox_run/detonation_meta.json").write_text(json.dumps(meta, indent=2) + "\\n", encoding="utf-8")
print(json.dumps(meta))
PY
"""
    proc = sprite_exec(detonator_sprite, ["bash", "-c", detonate_bash], check=True)
    det_meta = json.loads(proc.stdout.strip().splitlines()[-1])
    (run_dir / "detonation_meta.json").write_text(json.dumps(det_meta, indent=2) + "\n", encoding="utf-8")

    # Capture generic post-detonation filesystem snapshot BEFORE sprite restore
    snap_after_proc = sprite_exec(detonator_sprite, ["/.sprite/bin/python3", "-c", FS_SNAPSHOT_PY], check=True)
    fs_after = json.loads(snap_after_proc.stdout.strip().splitlines()[-1])
    fs_before = json.loads((run_dir / "fs_before.json").read_text(encoding="utf-8"))
    fs_diff = _compute_fs_diff(fs_before, fs_after)
    (run_dir / "fs_after.json").write_text(json.dumps(fs_after, indent=2) + "\n", encoding="utf-8")
    (run_dir / "fs_diff.json").write_text(json.dumps(fs_diff, indent=2) + "\n", encoding="utf-8")

    log(
        "4/9",
        f"Detonation finished (exit_code={det_meta['exit_code']}, strace={det_meta['strace_bytes']} bytes, "
        f"fs_created_outside={len(fs_diff['created_outside_workspace'])}).",
    )
    return det_meta


def pull_forensic_artifacts(detonator_sprite: str, run_dir: Path, *, mode: str) -> None:
    log("5/9", f"Pulling forensic artifacts from '{detonator_sprite}'...")
    sprite_pull(detonator_sprite, "/tmp/.blastbox_run/blastbox.strace", run_dir / "blastbox.strace", check=True)
    sprite_pull(detonator_sprite, "/tmp/.blastbox_run/command.stdout", run_dir / "command.stdout", check=True)
    sprite_pull(detonator_sprite, "/tmp/.blastbox_run/command.stderr", run_dir / "command.stderr", check=True)
    readme_ok = sprite_pull(detonator_sprite, "/home/sprite/detonation/README.md", run_dir / "README.md", check=False)
    if not readme_ok:
        (run_dir / "README.md").write_text("", encoding="utf-8")
    skill_ok = False
    if mode == "skill":
        skill_ok = sprite_pull(detonator_sprite, "/home/sprite/detonation/SKILL.md", run_dir / "SKILL.md", check=False)
    mcp_ok = False
    if mode == "mcp":
        mcp_ok = sprite_pull(
            detonator_sprite,
            "/home/sprite/detonation/.blastbox_mcp_transcript.json",
            run_dir / "mcp_transcript.json",
            check=True,
        )
    log("5/9", f"Pulled strace, stdout/stderr, README.md (present={readme_ok}, skill={skill_ok}, mcp_transcript={mcp_ok}).")


def _prune_detonator_checkpoints(detonator_sprite: str, keep: int) -> list[str]:
    proc = run_cmd([config.SPRITE_BIN, "checkpoint", "list", "-s", detonator_sprite], check=False)
    if proc.returncode != 0:
        return []
    candidates: list[str] = []
    for line in proc.stdout.splitlines():
        if "blastbox-detonator-clean-" in line:
            m = CHECKPOINT_ID_RE.search(line)
            if m and m.group(1) not in candidates:
                candidates.append(m.group(1))
    if len(candidates) <= keep:
        return []
    # Keep newest `keep` checkpoints (sort numerically by vN)
    candidates.sort(key=lambda v: int(v[1:]))
    to_delete = candidates[:-keep]
    deleted: list[str] = []
    for cp in to_delete:
        d_proc = run_cmd([config.SPRITE_BIN, "checkpoint", "delete", "-s", detonator_sprite, cp], check=False)
        if d_proc.returncode == 0:
            deleted.append(cp)
    return deleted


def restore_checkpoint_and_verify(detonator_sprite: str, checkpoint_id: str, run_dir: Path) -> dict[str, Any]:
    log("6/9", f"Restoring '{detonator_sprite}' to clean baseline checkpoint {checkpoint_id} ...")
    time.sleep(1.5)
    restore_output = ""
    restore_attempts = 0
    last_err = ""
    for attempt in range(1, 4):
        restore_attempts = attempt
        restore_proc = run_cmd([config.SPRITE_BIN, "restore", "-s", detonator_sprite, checkpoint_id], check=False)
        restore_output = (restore_proc.stdout + restore_proc.stderr).strip()
        if restore_proc.returncode == 0:
            break
        last_err = restore_output
        if attempt < 3:
            backoff = attempt * 4
            log("6/9", f"Transient restore error on attempt {attempt}/3; retrying in {backoff}s...")
            time.sleep(backoff)
    else:
        raise RuntimeError(
            f"sprite restore -s {detonator_sprite} {checkpoint_id} failed after {restore_attempts} attempts:\n{last_err}"
        )

    # Generic post-restore filesystem diff check against fs_before.json
    fs_before = json.loads((run_dir / "fs_before.json").read_text(encoding="utf-8"))
    snap_post_proc = sprite_exec(detonator_sprite, ["/.sprite/bin/python3", "-c", FS_SNAPSHOT_PY], check=True)
    fs_post_restore = json.loads(snap_post_proc.stdout.strip().splitlines()[-1])
    post_diff = _compute_fs_diff(fs_before, fs_post_restore)

    detonation_exists_after = bool(fs_post_restore.get("detonation_exists"))
    home_created_after = post_diff["home_created"]
    home_modified_after = post_diff["home_modified"]
    tmp_persisted_on_vdb = post_diff["tmp_created"]

    # Sweep ALL newly created /tmp artifacts generically + /tmp/.blastbox_run
    sweep_targets = tmp_persisted_on_vdb + ["/tmp/.blastbox_run"]
    sweep_script = (
        "import json, shutil, sys\n"
        "from pathlib import Path\n"
        "for raw in json.loads(sys.argv[1]):\n"
        "    p = Path(raw)\n"
        "    if p.is_symlink() or p.is_file():\n"
        "        p.unlink(missing_ok=True)\n"
        "    elif p.is_dir():\n"
        "        shutil.rmtree(p, ignore_errors=True)\n"
    )
    sprite_exec(
        detonator_sprite,
        ["/.sprite/bin/python3", "-c", sweep_script, json.dumps(sweep_targets)],
        check=True,
    )

    snap_after_sweep_proc = sprite_exec(detonator_sprite, ["/.sprite/bin/python3", "-c", FS_SNAPSHOT_PY], check=True)
    fs_after_sweep = json.loads(snap_after_sweep_proc.stdout.strip().splitlines()[-1])
    sweep_diff = _compute_fs_diff(fs_before, fs_after_sweep)
    tmp_remaining_after_sweep = sweep_diff["tmp_created"]

    if detonation_exists_after:
        raise RuntimeError("ROLLBACK FAILED: /home/sprite/detonation still exists after sprite restore!")
    if home_created_after or home_modified_after:
        raise RuntimeError(
            f"ROLLBACK FAILED: Unexpected /home/sprite files persisted after sprite restore: "
            f"created={home_created_after}, modified={home_modified_after}"
        )

    pruned = _prune_detonator_checkpoints(detonator_sprite, config.MAX_DETONATOR_CHECKPOINTS)

    verify_info = {
        "detonator_sprite": detonator_sprite,
        "checkpoint_id": checkpoint_id,
        "restore_attempts": restore_attempts,
        "restore_cli_output": restore_output,
        "detonation_dir_exists_after_restore": detonation_exists_after,
        "home_created_after_restore": home_created_after,
        "home_modified_after_restore": home_modified_after,
        "tmp_persisted_on_vdb": tmp_persisted_on_vdb,
        "tmp_remaining_after_sweep": tmp_remaining_after_sweep,
        "pruned_checkpoints": pruned,
    }
    (run_dir / "restore_verification.json").write_text(json.dumps(verify_info, indent=2) + "\n", encoding="utf-8")
    log(
        "6/9",
        f"Restored {detonator_sprite}@{checkpoint_id}: /home/sprite diff={len(home_created_after)}+{len(home_modified_after)}, "
        f"detonation_removed={not detonation_exists_after}, /tmp_on_vdb_swept={len(tmp_persisted_on_vdb)}->{len(tmp_remaining_after_sweep)}.",
    )
    return verify_info


def run_clean_sprite_triage(
    controller_sprite: str,
    run_dir: Path,
    iocs: dict[str, Any],
    target_info: dict[str, Any],
    agent_plan: dict[str, Any],
    *,
    no_post: bool = False,
    model: str | None = None,
    local_controller: bool = False,
) -> dict[str, Any]:
    log("8/9", f"Running zero-secret Connector triage & GitHub publish inside Controller '{controller_sprite}'...")
    readme_text = (run_dir / "README.md").read_text(encoding="utf-8", errors="replace") if (run_dir / "README.md").exists() else ""
    skill_text = (run_dir / "SKILL.md").read_text(encoding="utf-8", errors="replace") if (run_dir / "SKILL.md").exists() else ""
    combined_doc = skill_text or readme_text
    if skill_text and readme_text:
        combined_doc = f"{skill_text}\n\n{readme_text}"
    mcp_tools_list = None
    mcp_transcript_path = run_dir / "mcp_transcript.json"
    if mcp_transcript_path.exists():
        mcp_data = json.loads(mcp_transcript_path.read_text(encoding="utf-8"))
        mcp_tools_list = mcp_data.get("tools_list")

    triage_input: dict[str, Any] = {
        "iocs": iocs,
        "readme_excerpt": combined_doc[:3000],
        "target_info": config.sanitize_value(target_info),
        "agent_plan": config.sanitize_value(agent_plan),
    }
    if mcp_tools_list is not None:
        triage_input["mcp_tools_list"] = mcp_tools_list

    local_input = run_dir / "triage_input.json"
    local_input.write_text(json.dumps(triage_input, indent=2) + "\n", encoding="utf-8")

    triage_script = SCRIPT_DIR / "sprite_triage.py"
    remote_in = "/tmp/.ctrl_triage_input.json"
    remote_out_json = "/tmp/.ctrl_triage_result.json"
    remote_out_md = "/tmp/.ctrl_report.md"
    args = [
        "--input",
        remote_in,
        "--output-json",
        remote_out_json,
        "--output-md",
        remote_out_md,
    ]
    if no_post:
        args.append("--no-post")
    if model:
        args.extend(["--model", model])

    _run_controller_python(
        controller_sprite,
        triage_script,
        args,
        local_controller=local_controller,
        upload_files=[(local_input, remote_in)],
        download_files=[
            (remote_out_json, run_dir / "triage_result.json"),
            (remote_out_md, run_dir / "report.md"),
        ],
    )

    triage_result = json.loads((run_dir / "triage_result.json").read_text(encoding="utf-8"))
    log("8/9", "Controller Connector triage succeeded.")
    return triage_result


def _build_sanitized_run_record(
    *,
    resolved_mode: str,
    target_info: dict[str, Any],
    iocs: dict[str, Any],
    triage_result: dict[str, Any],
    restore_info: dict[str, Any],
    preflight: dict[str, Any],
    agent_plan: dict[str, Any],
    wall_seconds: float,
) -> dict[str, Any]:
    now_dt = datetime.now(timezone.utc)
    ts_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_compact = now_dt.strftime("%Y%m%dT%H%M%SZ")

    if resolved_mode == "pr":
        pr_num = target_info.get("pr_number", 0)
        suffix = f"pr-{pr_num}"
        target_label = f"{target_info.get('owner')}/{target_info.get('repo')}#{pr_num} ({target_info.get('head_ref')})"
        target_url = target_info.get("pr_url")
    elif resolved_mode == "skill":
        raw_label = str(target_info.get("target_label") or "SKILL.md")
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", raw_label).strip("-").lower()[:32] or "skill"
        suffix = f"skill-{slug}"
        target_label = raw_label
        target_url = target_info.get("skill_url")
    else:
        raw_label = str(target_info.get("target_label") or resolved_mode)
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", raw_label).strip("-").lower()[:32] or "target"
        suffix = f"{resolved_mode}-{slug}"
        target_label = raw_label
        target_url = None

    openrouter_triage = triage_result.get("openrouter_triage") or {}
    triage_obj = openrouter_triage.get("triage") or {}
    github_pub = triage_result.get("github_publish") or {}
    fs_diff = (iocs.get("context") or {}).get("fs_diff") or {}

    rollback_ok = (
        not restore_info.get("detonation_dir_exists_after_restore")
        and not restore_info.get("home_created_after_restore")
        and not restore_info.get("home_modified_after_restore")
        and not restore_info.get("tmp_remaining_after_sweep")
    )

    if agent_plan.get("mode") == "mcp":
        planned_items = [c.get("tool") for c in (agent_plan.get("calls") or []) if isinstance(c, dict)]
    elif agent_plan.get("mode") == "skill":
        planned_items = list(agent_plan.get("targets") or [])
    else:
        planned_items = list(agent_plan.get("stages") or [])

    record = {
        "run_id": f"{ts_compact}-{suffix}",
        "timestamp_utc": ts_iso,
        "target_kind": resolved_mode,
        "target_label": target_label,
        "target_url": target_url,
        "head_sha": target_info.get("head_sha"),
        "verdict": iocs.get("verdict"),
        "risk_score": iocs.get("risk_score"),
        "llm_verdict": triage_obj.get("recommended_verdict"),
        "openrouter_model": openrouter_triage.get("model_used"),
        "executive_summary": triage_obj.get("executive_summary"),
        "prompt_injection_detected": bool(openrouter_triage.get("prompt_injection_detected")),
        "prompt_injection_resisted": bool(openrouter_triage.get("prompt_injection_resisted")),
        "controller_sprite": preflight.get("controller_sprite"),
        "detonator_sprite": preflight.get("detonator_sprite"),
        "detonator_unlabeled": bool(preflight.get("detonator_unlabeled")),
        "detonator_egress_denied": bool(preflight.get("detonator_egress_denied")),
        "checkpoint_restored": restore_info.get("checkpoint_id"),
        "rollback_verified": rollback_ok,
        "fs_created_during_detonation": fs_diff.get("created_outside_workspace") or [],
        "agent_plan": {
            "planner_source": agent_plan.get("planner_source"),
            "model_used": agent_plan.get("model_used"),
            "rationale": agent_plan.get("rationale"),
            "targets": planned_items,
            "suspicious_tools": agent_plan.get("suspicious_tools") or [],
        },
        "zero_secrets_verified": bool(
            preflight.get("zero_secrets_verified")
            and (triage_result.get("zero_secrets") or {}).get("zero_secrets_verified")
        ),
        "policy_403_status": (triage_result.get("policy_403_check") or {}).get("http_status"),
        "github_publish_status": github_pub.get("http_status"),
        "github_artifact_url": github_pub.get("html_url"),
        "ioc_counts": iocs.get("counts") or {},
        "top_findings": (iocs.get("scoring_reasons") or [])[:6],
        "wall_seconds": round(wall_seconds, 2),
    }
    return config.sanitize_value(record)


def persist_history_and_verify_dashboard(
    controller_sprite: str,
    history_path: Path,
    run_record: dict[str, Any],
    *,
    public_url: str = config.PUBLIC_URL,
    local_controller: bool = False,
) -> dict[str, Any]:
    log("9/9", f"Persisting sanitized run '{run_record['run_id']}' to controller dashboard & verifying HTTP 200...")
    history = init_dashboard.load_or_init_history(
        history_path, sprite_name=controller_sprite, public_url=public_url
    )
    history["runs"].append(run_record)
    history["updated_at"] = run_record["timestamp_utc"]
    history = config.sanitize_value(history)
    history_path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")

    web_history = Path("/home/sprite/blastbox-web/history.json")
    if local_controller:
        if web_history.parent.is_dir() and web_history.resolve() != history_path.resolve():
            shutil.copy2(history_path, web_history)
    else:
        init_dashboard.sync_history_to_sprite(controller_sprite, history_path)

    api_url = f"{public_url.rstrip('/')}/api/runs"
    root_url = f"{public_url.rstrip('/')}/"
    deadline = time.monotonic() + 20
    api_body = ""
    api_status = 0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(api_url, headers={"User-Agent": "blastbox-verify/2.0"}), timeout=8) as resp:
                api_status = resp.status
                api_body = resp.read().decode("utf-8", errors="replace")
            if api_status == 200 and run_record["run_id"] in api_body:
                break
        except Exception:
            pass
        time.sleep(1.0)
    else:
        raise RuntimeError(f"Live dashboard {api_url} did not reflect run {run_record['run_id']} within timeout (status={api_status})")

    with urllib.request.urlopen(urllib.request.Request(root_url, headers={"User-Agent": "blastbox-verify/2.0"}), timeout=10) as resp:
        html_status = resp.status
        html_body = resp.read().decode("utf-8", errors="replace")

    if html_status != 200 or run_record["run_id"] not in html_body:
        raise RuntimeError(f"Live dashboard {root_url} failed check (status={html_status})")
    if "/var/home/" in api_body or "/var/home/" in html_body:
        raise RuntimeError("SECURITY FAILURE: Host path '/var/home/' leaked in public dashboard response!")

    log("9/9", f"Public dashboard verified (HTTP 200, runs={len(history['runs'])}).")
    return {
        "public_url": public_url,
        "api_status": api_status,
        "html_status": html_status,
        "runs_total": len(history["runs"]),
    }


def run_audit(
    target: str,
    *,
    mode: str = "auto",
    controller_sprite: str = config.CONTROLLER_SPRITE,
    detonator_sprite: str = config.DETONATOR_SPRITE,
    repo: str = config.DEFAULT_REPO,
    output_dir: Path = SCRIPT_DIR / "last_run",
    history_path: Path = SCRIPT_DIR / "history.json",
    model: str | None = None,
    no_post: bool = False,
    no_dashboard_sync: bool = False,
    local_controller: bool = False,
) -> dict[str, Any]:
    run_start = time.monotonic()
    run_dir = output_dir.resolve()
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    history_resolved = history_path.resolve()

    pr_match = PR_URL_RE.match(target.strip())
    if pr_match:
        resolved_mode = "pr"
        local_dir = None
    elif URL_RE.match(target.strip()):
        resolved_mode = mode if mode in ("skill",) else "skill"
        local_dir = None
    else:
        local_dir = Path(target)
        if mode == "skill" or (
            mode == "auto"
            and (
                (local_dir.is_file() and local_dir.suffix.lower() == ".md")
                or (local_dir / "SKILL.md").exists()
                or (local_dir / "skill.md").exists()
            )
        ):
            resolved_mode = "skill"
        elif mode == "mcp" or (
            mode == "auto"
            and ((local_dir / "mcp_manifest.json").exists() or (local_dir / "server.py").exists())
        ):
            resolved_mode = "mcp"
        else:
            resolved_mode = "local"

    preflight = verify_detonator_preflight(
        controller_sprite,
        detonator_sprite,
        run_dir,
        history_path=history_resolved,
        sync_dashboard=not no_dashboard_sync,
        local_controller=local_controller,
    )

    checkpoint_id = create_baseline_checkpoint(
        detonator_sprite, prefix="blastbox-detonator-clean", step_label="2/9"
    )

    try:
        target_info, agent_plan = stage_and_plan_target(
            controller_sprite=controller_sprite,
            detonator_sprite=detonator_sprite,
            resolved_mode=resolved_mode,
            pr_match=pr_match,
            raw_target=target,
            local_dir=local_dir,
            default_repo=repo,
            run_dir=run_dir,
            model=model,
            local_controller=local_controller,
        )
        run_strace_detonation(detonator_sprite, run_dir, mode=resolved_mode, agent_plan=agent_plan)
        pull_forensic_artifacts(detonator_sprite, run_dir, mode=resolved_mode)
    finally:
        restore_info = restore_checkpoint_and_verify(detonator_sprite, checkpoint_id, run_dir)

    log("7/9", "Extracting deterministic IOCs from strace + fs_diff + metadata ...")
    iocs = extract_iocs.extract_all_iocs(run_dir)
    log(
        "7/9",
        f"Deterministic verdict: {iocs['verdict']} (risk_score={iocs['risk_score']}/100, counts={json.dumps(iocs['counts'])})",
    )

    triage_result = run_clean_sprite_triage(
        controller_sprite,
        run_dir,
        iocs,
        target_info,
        agent_plan,
        no_post=no_post,
        model=model,
        local_controller=local_controller,
    )

    wall_seconds = round(time.monotonic() - run_start, 2)
    run_record = _build_sanitized_run_record(
        resolved_mode=resolved_mode,
        target_info=target_info,
        iocs=iocs,
        triage_result=triage_result,
        restore_info=restore_info,
        preflight=preflight,
        agent_plan=agent_plan,
        wall_seconds=wall_seconds,
    )

    dashboard_sync = None
    if not no_dashboard_sync:
        dashboard_sync = persist_history_and_verify_dashboard(
            controller_sprite,
            history_resolved,
            run_record,
            local_controller=local_controller,
        )

    try:
        rel_artifacts = run_dir.relative_to(SCRIPT_DIR.parent).as_posix()
    except ValueError:
        rel_artifacts = run_dir.name

    final_summary = config.sanitize_value(
        {
            "run_id": run_record["run_id"],
            "mode": resolved_mode,
            "target": target_info,
            "controller_sprite": controller_sprite,
            "detonator_sprite": detonator_sprite,
            "checkpoint_restored": checkpoint_id,
            "rollback_verified": run_record["rollback_verified"],
            "fs_created_during_detonation": run_record["fs_created_during_detonation"],
            "zero_secrets_verified": run_record["zero_secrets_verified"],
            "policy_403_verified": triage_result["policy_403_check"]["blocked_as_expected"],
            "policy_403_status": triage_result["policy_403_check"]["http_status"],
            "deterministic_verdict": iocs["verdict"],
            "deterministic_risk_score": iocs["risk_score"],
            "ioc_counts": iocs["counts"],
            "agent_plan": run_record["agent_plan"],
            "openrouter_model": triage_result["openrouter_triage"]["model_used"],
            "llm_recommended_verdict": (triage_result["openrouter_triage"].get("triage") or {}).get("recommended_verdict"),
            "prompt_injection_detected": run_record["prompt_injection_detected"],
            "prompt_injection_resisted": triage_result["openrouter_triage"]["prompt_injection_resisted"],
            "github_publish": triage_result["github_publish"],
            "dashboard": dashboard_sync,
            "wall_seconds": round(time.monotonic() - run_start, 2),
            "artifacts_rel": rel_artifacts,
        }
    )
    (run_dir / "summary.json").write_text(json.dumps(final_summary, indent=2) + "\n", encoding="utf-8")
    return final_summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Blastbox — Two-Sprite Air-Gapped PR/Package/MCP Auditor")
    parser.add_argument(
        "target",
        help="Local repository/MCP/SKILL.md path OR GitHub PR / HTTPS SKILL.md URL",
    )
    parser.add_argument("--sprite", "--controller-sprite", dest="controller_sprite", default=config.CONTROLLER_SPRITE)
    parser.add_argument("--detonator-sprite", default=config.DETONATOR_SPRITE)
    parser.add_argument("--mode", choices=("auto", "pr", "mcp", "skill"), default="auto")
    parser.add_argument("--output-dir", type=Path, default=SCRIPT_DIR / "last_run")
    parser.add_argument("--repo", default=config.DEFAULT_REPO)
    parser.add_argument("--history-file", type=Path, default=SCRIPT_DIR / "history.json")
    parser.add_argument("--model", default=None, help="Optional OpenRouter model override")
    parser.add_argument("--no-post", action="store_true", help="Do not post PR comment / Issue to GitHub")
    parser.add_argument("--no-dashboard-sync", action="store_true", help="Skip updating public dashboard history.json")
    parser.add_argument("--local-controller", action="store_true", help="Run controller steps locally (inside controller Sprite)")
    args = parser.parse_args()

    final_summary = run_audit(
        args.target,
        mode=args.mode,
        controller_sprite=args.controller_sprite,
        detonator_sprite=args.detonator_sprite,
        repo=args.repo,
        output_dir=args.output_dir,
        history_path=args.history_file,
        model=args.model,
        no_post=args.no_post,
        no_dashboard_sync=args.no_dashboard_sync,
        local_controller=args.local_controller,
    )
    print("\n=== BLASTBOX RUN SUMMARY ===")
    print(json.dumps(final_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
