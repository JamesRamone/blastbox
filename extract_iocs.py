#!/usr/bin/env python3
"""Deterministic IOC and behavioral signal extractor for Blastbox.

Parses strace syscall logs, command stdout/stderr, generic filesystem before/after
diffs, timeout exit codes, README.md/SKILL.md text, and MCP discovery metadata
with zero LLM involvement. Produces structured findings with exact telemetry
evidence lines, risk score, and deterministic verdict (BLOCK/REVIEW/PASS).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import config  # noqa: E402

WORKSPACE_PREFIX = "/home/sprite/detonation"
GITHUB_CONNECTOR_ID = config.GITHUB_CONNECTOR_ID

# Sensitive file path patterns probed via open/openat/openat2
SENSITIVE_PATH_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("proc_environ", re.compile(r"^/proc/(?:self|\d+)/environ$"), "Reads process environment via /proc/*/environ"),
    (
        "ssh_material",
        re.compile(r"(?:^|/)\.ssh/(?!known_hosts$)(?:id_[^/]+|authorized_keys|config|[^/]+\.(?:pem|key))$"),
        "Probes SSH private key or config material",
    ),
    ("etc_shadow", re.compile(r"^/etc/(?:shadow|gshadow)$"), "Probes system password shadow file"),
    ("aws_creds", re.compile(r"(?:^|/)\.aws(?:/|$)"), "Probes AWS credentials/config"),
    ("netrc", re.compile(r"(?:^|/)\.netrc$"), "Probes .netrc credential file"),
    ("git_credentials", re.compile(r"(?:^|/)\.git-credentials$"), "Probes git credential store"),
    ("fly_auth", re.compile(r"/\.config/fly-agent-auth(?:/|$)"), "Probes Fly agent auth directory"),
    ("sprites_auth", re.compile(r"(?:^|/)\.sprites(?:/|$)"), "Probes Fly Sprites CLI credential store"),
    ("npmrc_pypirc", re.compile(r"(?:^|/)\.(?:npmrc|pypirc)$"), "Probes package registry token file (.npmrc/.pypirc)"),
    ("docker_config", re.compile(r"(?:^|/)\.docker/config\.json$"), "Probes Docker registry credentials"),
    ("kube_config", re.compile(r"(?:^|/)\.kube/config$"), "Probes Kubernetes config"),
]

# Paths that are expected/benign write targets during pip install & Python runtime
BENIGN_WRITE_PREFIXES = (
    WORKSPACE_PREFIX + "/",
    WORKSPACE_PREFIX,
    "/dev/",
    "/proc/self/fd",
    "/.sprite/",
    "/tmp/pip-",
    "/tmp/build-",
)

# Subprocess binaries worth flagging when invoked by untrusted build/test code
NOTABLE_BINARIES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "scp",
    "sh",
    "bash",
    "dash",
    "zsh",
    "chmod",
    "chown",
    "sudo",
    "base64",
    "openssl",
}

# Prompt-injection / reviewer-override rules for untrusted README text
PROMPT_INJECTION_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "ignore_instructions",
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
        "Attempts to override reviewer system instructions",
    ),
    (
        "ignore_audit_findings",
        re.compile(r"(?:ignore|disregard|override)[^\n]{0,80}(?:strace|syscall|audit|security)\s+findings", re.IGNORECASE),
        "Instructs automated reviewer to disregard syscall/audit findings",
    ),
    (
        "secret_exfil_prompt",
        re.compile(
            r"(?:reveal|print|output|disclose|expose|dump)[^\n]{0,80}(?:GITHUB_TOKEN|OPENROUTER_API_KEY|FLY_API_TOKEN|AWS_SECRET|API_KEY|SPRITES_TOKEN)",
            re.IGNORECASE,
        ),
        "Attempts to coerce AI reviewer into leaking API secrets/tokens",
    ),
    (
        "forced_approval",
        re.compile(
            r"(?:"
            r"set\s+(?:the\s+)?(?:risk\s+)?verdict\s+to\s+`?(?:PASS|APPROVED?)`?"
            r"|(?:reply|respond|return|output)\s+(?:strictly|always|only|unconditionally)\b[^\n]{0,40}\b(?:LGTM(?:\s*/\s*Approved)?|PASS|APPROVED?)\b"
            r"|(?:always|must|unconditionally)\s+(?:reply|respond|return|output|approve|mark(?:\s+as)?)\b[^\n]{0,40}\b(?:LGTM(?:\s*/\s*Approved)?|PASS|APPROVED?)\b"
            r"|\bLGTM\s*/\s*Approved\b"
            r"|\bpre-?approved\s+`?(?:PASS|LGTM)`?\b"
            r"|(?:reply|respond|return|output|approve|verdict)[^\n]{0,60}\b(?:PASS|LGTM|approved)\b[^\n]{0,60}(?:regardless|even\s+if|override|ignore|malicious|unsafe)"
            r"|(?:override|ignore|even\s+if|regardless)[^\n]{0,60}(?:reply|respond|return|output|approve|verdict)[^\n]{0,40}\b(?:PASS|LGTM|approved)\b"
            r")",
            re.IGNORECASE,
        ),
        "Attempts to force an automated PASS / LGTM approval",
    ),
    (
        "ai_reviewer_directive",
        re.compile(
            r"(?:(?:system\s+instruction|important\s+note|instruction)[^\n]{0,60}(?:automated\s+)?ai\s+(?:pr\s+)?reviewer"
            r"|(?:automated\s+)?ai\s+(?:pr\s+)?reviewer\s+note)",
            re.IGNORECASE,
        ),
        "Directs embedded prompt instructions at automated AI PR reviewers",
    ),
]

# Additional MCP metadata poisoning rules (checked on tools/list, resources/list, prompts/list)
MCP_POISONING_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "mcp_hidden_directive_tag",
        re.compile(r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION)\s*>", re.IGNORECASE),
        "Embeds hidden <IMPORTANT>/<SYSTEM> directive tags inside MCP metadata",
    ),
    (
        "mcp_conceal_from_user",
        re.compile(r"do\s+not\s+(?:mention|tell|show|inform)[^\n]{0,60}user", re.IGNORECASE),
        "Instructs MCP agent to conceal actions from the user",
    ),
    (
        "mcp_ssh_or_secret_read",
        re.compile(
            r"(?:(?<![a-zA-Z0-9_-])(?:~/?|/home/[^/\s]+/)?\.ssh(?:/|(?=$|[\s\"'`),:;]))"
            r"|/proc/(?:self|\d+)/environ"
            r"|/etc/(?:shadow|gshadow)"
            r"|(?<![a-zA-Z0-9_-])(?:~/?|/home/[^/\s]+/)?\.aws/credentials"
            r"|(?<![a-zA-Z0-9_-])(?:~/?|/home/[^/\s]+/)?\.netrc\b"
            r"|(?:read|exfiltrate|steal|copy|cat|inspect|look\s+at|access|open)[^\n]{0,60}(?:\.ssh|credentials|secrets?|id_rsa|id_ed25519))",
            re.IGNORECASE,
        ),
        "References SSH/credential paths or instructs agent/reviewer to read sensitive credential files",
    ),
    (
        "mcp_exfil_command",
        re.compile(
            r"(?:\b(?:curl|wget)\s+(?:https?://|-[a-zA-Z]|[a-zA-Z0-9.-]+\.[a-z]{2,}/)"
            r"|\b(?:run|exec(?:ute)?|invoke|pipe\s+(?:[^\n]{0,20}\s+)?to)\s+(?:curl|wget|nc|ncat|netcat)\b)",
            re.IGNORECASE,
        ),
        "Instructs running curl/wget/netcat network or exfiltration commands inside MCP metadata",
    ),
    (
        "mcp_base64_directive",
        re.compile(
            r"(?:\bbase64\s+(?:-d|--decode|-w\s*0)\b"
            r"|\b(?:pipe\s+(?:[^\n]{0,20}\s+)?to|echo\b[^\n]{0,40}\|)\s*base64\b"
            r"|\bbase64\b[^\n]{0,60}\|\s*(?:ba)?sh\b)",
            re.IGNORECASE,
        ),
        "Contains base64 decode/obfuscation pipeline directives inside MCP metadata",
    ),
]

# Strace line regexes (supporting open, openat, openat2, creat, link/symlink/rename/unlink/chmod, execve/execveat)
RE_STRACE_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))?\s*(.*)$")
RE_OPEN = re.compile(r'\bopen\("([^"]+)"\s*,\s*([^,)\s]+(?:[|][^,)\s]+)*)')
RE_OPENAT = re.compile(r'\bopenat2?\([^,]+,\s*"([^"]+)"\s*,\s*([^,)\s]+(?:[|][^,)\s]+)*|(?:\{[^}]+\}))')
RE_CREAT = re.compile(r'\bcreat\("([^"]+)"\s*,')
RE_FS_MUTATE = re.compile(
    r'\b(unlinkat|unlink|renameat2|renameat|rename|linkat|link|symlinkat|symlink|fchmodat|chmod)\((.+)'
)
RE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
RE_EXECVE = re.compile(
    r'\bexecve(?:at)?\((?:[^,]+,\s*)?"([^"]+)",\s*\[((?:"(?:[^"\\]|\\.)*"(?:\.\.\.)?(?:,\s*)?|\.\.\.(?:,\s*)?)*)\]'
)
RE_CONNECT_V4 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)\}'
)
RE_CONNECT_V6 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"\)'
)
RE_URL = re.compile(r"https?://[^\s\"'\]\\,]+")
RE_RETURN_CODE = re.compile(r"\)\s*=\s*(-?\d+)(?:\s+([A-Z0-9_]+))?")


def _is_write_open(flags_str: str) -> bool:
    return any(tok in flags_str for tok in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))


def _is_benign_write_path(path: str) -> bool:
    if not path.startswith("/"):
        # Relative paths inside cwd (/home/sprite/detonation) are in-workspace
        return not path.startswith("..")
    for prefix in BENIGN_WRITE_PREFIXES:
        if path == prefix or path.startswith(prefix):
            return True
    return False


def _extract_open_syscall(line: str) -> tuple[str, str, str] | None:
    m_openat = RE_OPENAT.search(line)
    if m_openat:
        syscall = "openat2" if "openat2(" in line else "openat"
        return syscall, m_openat.group(1), m_openat.group(2)
    m_open = RE_OPEN.search(line)
    if m_open:
        return "open", m_open.group(1), m_open.group(2)
    m_creat = RE_CREAT.search(line)
    if m_creat:
        return "creat", m_creat.group(1), "O_WRONLY|O_CREAT|O_TRUNC"
    return None


def _classify_ip(ip_str: str, port: int) -> str:
    if port == 53:
        return "dns_resolver"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "outbound_connect"
    if ip_obj.is_loopback:
        return "loopback"
    # RFC 5737 documentation / sinkhole test ranges
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        if ip_obj in ipaddress.ip_network(net):
            return "sinkhole_probe"
    if ip_obj.is_private:
        return "private_network"
    return "outbound_connect"


def _parse_argv_preview(argv_raw: str) -> list[str]:
    return RE_QUOTED.findall(argv_raw)


def _extract_dns_domains_from_send(line: str) -> list[str]:
    """Extract queried domains from strace sendto()/sendmsg()/sendmmsg() wire payloads."""
    blobs: list[str] = []
    blobs.extend(re.findall(r'sendto\(\d+,\s*"([^"]+)"', line))
    blobs.extend(re.findall(r'iov_base="([^"]+)"', line))
    if not blobs:
        return []
    domains: list[str] = []
    for raw in blobs:
        cleaned = re.sub(r"\\(?:x[0-9a-fA-F]{2}|[0-7]{1,3}|[abfnrtv\"\\])", ".", raw)
        cleaned = re.sub(r"[^a-zA-Z0-9.-]", ".", cleaned)
        for cand in re.findall(r"[a-zA-Z0-9-]{2,}(?:\.[a-zA-Z0-9-]{2,}){1,5}", cleaned):
            cand_clean = cand.strip(".-").lower()
            if any(
                cand_clean.endswith(tld)
                for tld in (".invalid", ".dev", ".com", ".org", ".net", ".io", ".app", ".internal", ".local")
            ):
                if cand_clean not in domains:
                    domains.append(cand_clean)
    return domains


RE_HARNESS_SCRIPT = re.compile(
    r"^(?:\\n|\s)*cd /home/sprite/detonation(?:\\n|\s)+.*===\s*\[blastbox\]\s",
    re.DOTALL,
)


def _is_harness_or_pyenv_execve(
    line_pid: str | None,
    root_pid: str | None,
    harness_excluded: bool,
    binary: str,
    argv: list[str],
) -> tuple[bool, bool]:
    """Exclude the single outer blastbox harness bash -c wrapper and pyenv shims."""
    if binary.startswith("/.sprite/languages/python/pyenv/") or (
        len(argv) >= 2 and Path(binary).name in ("bash", "sh") and argv[1].startswith("/.sprite/languages/python/pyenv/")
    ):
        return True, harness_excluded
    if (
        not harness_excluded
        and line_pid is not None
        and line_pid == root_pid
        and Path(binary).name in ("bash", "sh")
        and len(argv) >= 3
        and argv[0] in ("bash", "sh")
        and argv[1] == "-c"
        and RE_HARNESS_SCRIPT.match(argv[2])
    ):
        return True, True
    return False, harness_excluded


def parse_strace(strace_text: str) -> dict[str, Any]:
    sensitive_map: dict[tuple[str, str], dict[str, Any]] = {}
    write_map: dict[str, dict[str, Any]] = {}
    connect_map: dict[tuple[str, int], dict[str, Any]] = {}
    subprocess_map: dict[str, dict[str, Any]] = {}
    probe_urls: dict[str, dict[str, Any]] = {}
    dns_domains: dict[str, str] = {}

    total_lines = 0
    root_pid: str | None = None
    harness_excluded = False
    for line_no, raw_line in enumerate(strace_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        total_lines += 1
        m_prefix = RE_STRACE_PREFIX.match(line)
        line_pid = (m_prefix.group(1) or m_prefix.group(2)) if m_prefix else None
        if root_pid is None and line_pid is not None:
            root_pid = line_pid

        ret_m = RE_RETURN_CODE.search(line)
        ret_code = int(ret_m.group(1)) if ret_m else None
        ret_err = ret_m.group(2) if ret_m else None

        # 1. open / openat / openat2 / creat
        open_parsed = _extract_open_syscall(line)
        if open_parsed:
            open_syscall, path, flags = open_parsed

            # Sensitive path probes
            for rule_id, pattern, desc in SENSITIVE_PATH_RULES:
                if pattern.search(path):
                    key = (rule_id, path)
                    if key not in sensitive_map:
                        sensitive_map[key] = {
                            "rule": rule_id,
                            "path": path,
                            "description": desc,
                            "flags": flags,
                            "result": (
                                f"{ret_code} ({ret_err})"
                                if ret_code is not None and ret_err
                                else (str(ret_code) if ret_code is not None else "unfinished")
                            ),
                            "count": 1,
                            "line": line_no,
                            "evidence": line[:240],
                        }
                    else:
                        sensitive_map[key]["count"] += 1
                    break

            # Unexpected writes outside workspace (only if not failed ENOENT/EACCES on non-creat)
            if _is_write_open(flags) and not _is_benign_write_path(path):
                if path not in write_map:
                    write_map[path] = {
                        "path": path,
                        "syscall": open_syscall,
                        "flags": flags,
                        "count": 1,
                        "line": line_no,
                        "evidence": line[:240],
                    }
                else:
                    write_map[path]["count"] += 1

        # 1b. unlink / rename / link / symlink / chmod outside workspace
        m_fs = RE_FS_MUTATE.search(line)
        if m_fs:
            syscall_name = m_fs.group(1)
            quoted_paths = RE_QUOTED.findall(m_fs.group(2).split(")", 1)[0])
            for fs_path in quoted_paths:
                if not _is_benign_write_path(fs_path):
                    if fs_path not in write_map:
                        write_map[fs_path] = {
                            "path": fs_path,
                            "syscall": syscall_name,
                            "flags": syscall_name,
                            "count": 1,
                            "line": line_no,
                            "evidence": line[:240],
                        }
                    else:
                        write_map[fs_path]["count"] += 1

        # 2. execve / execveat (only successful executions, ignoring failed PATH lookup ENOENT probes)
        m_exec = RE_EXECVE.search(line)
        if m_exec and ret_code != -1:
            binary, argv_raw = m_exec.group(1), m_exec.group(2)
            argv = _parse_argv_preview(argv_raw)
            bin_name = Path(binary).name
            is_excluded, harness_excluded = _is_harness_or_pyenv_execve(
                line_pid, root_pid, harness_excluded, binary, argv
            )
            if bin_name in NOTABLE_BINARIES and not is_excluded:
                sig = f"{binary} {' '.join(argv[1:])}".strip()
                if sig not in subprocess_map:
                    subprocess_map[sig] = {
                        "binary": binary,
                        "name": bin_name,
                        "argv": argv,
                        "count": 1,
                        "line": line_no,
                        "evidence": line[:240],
                    }
                else:
                    subprocess_map[sig]["count"] += 1

                for url in RE_URL.findall(argv_raw):
                    if url not in probe_urls:
                        probe_urls[url] = {
                            "url": url,
                            "source": f"execve:{bin_name}",
                            "line": line_no,
                            "evidence": line[:240],
                        }

        # 3. connect() AF_INET / AF_INET6
        m_c4 = RE_CONNECT_V4.search(line)
        if m_c4:
            port, ip_str = int(m_c4.group(1)), m_c4.group(2)
            kind = _classify_ip(ip_str, port)
            key = (ip_str, port)
            if key not in connect_map:
                connect_map[key] = {
                    "ip": ip_str,
                    "port": port,
                    "family": "AF_INET",
                    "classification": kind,
                    "count": 1,
                    "line": line_no,
                    "evidence": line[:240],
                }
            else:
                connect_map[key]["count"] += 1

        m_c6 = RE_CONNECT_V6.search(line)
        if m_c6:
            port, ip_str = int(m_c6.group(1)), m_c6.group(2)
            kind = _classify_ip(ip_str, port)
            key = (ip_str, port)
            if key not in connect_map:
                connect_map[key] = {
                    "ip": ip_str,
                    "port": port,
                    "family": "AF_INET6",
                    "classification": kind,
                    "count": 1,
                    "line": line_no,
                    "evidence": line[:240],
                }
            else:
                connect_map[key]["count"] += 1

        # 4. sendto() / sendmsg() / sendmmsg() DNS & SNI queries
        if "sendto(" in line or "sendmsg(" in line or "sendmmsg(" in line:
            for dom in _extract_dns_domains_from_send(line):
                if dom not in dns_domains:
                    dns_domains[dom] = line[:240]

    return {
        "total_strace_lines": total_lines,
        "sensitive_file_probes": list(sensitive_map.values()),
        "unexpected_writes": list(write_map.values()),
        "network_connects": list(connect_map.values()),
        "dns_queries": [{"domain": d, "evidence": ev} for d, ev in dns_domains.items()],
        "probe_urls": list(probe_urls.values()),
        "notable_subprocesses": list(subprocess_map.values()),
    }


def merge_fs_diff_into_writes(
    writes: list[dict[str, Any]],
    fs_diff: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Augment strace write detections with generic pre/post filesystem diff findings."""
    if not isinstance(fs_diff, dict):
        return writes
    merged = list(writes)
    existing_paths = {item.get("path") for item in merged}

    for field, flag in (
        ("created_outside_workspace", "fs_diff_created"),
        ("modified_outside_workspace", "fs_diff_modified"),
        ("deleted_outside_workspace", "fs_diff_deleted"),
    ):
        entries = fs_diff.get(field)
        if not isinstance(entries, list):
            continue
        for raw_path in entries:
            path = str(raw_path)
            if not path or path in existing_paths or _is_benign_write_path(path):
                continue
            existing_paths.add(path)
            merged.append(
                {
                    "path": path,
                    "syscall": "fs_diff",
                    "flags": flag,
                    "count": 1,
                    "line": 0,
                    "evidence": f"fs_diff ({flag}): {path}",
                }
            )
    return merged


def parse_connector_denials(stdout_text: str, stderr_text: str, probe_urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Sprites Connector policy denials or air-gapped gateway blocks during detonation."""
    denials: list[dict[str, Any]] = []
    combined = f"{stdout_text}\n{stderr_text}"
    seen_urls: set[str] = set()

    for line in combined.splitlines():
        if "403" in line and (
            "endpoint is blocked by policy" in line
            or "/v1/gateway/" in line
            or "HTTP_STATUS:403" in line
        ):
            urls = RE_URL.findall(line)
            conn_label = GITHUB_CONNECTOR_ID or "<connector>"
            url = urls[0] if urls else f"https://api.sprites.dev/v1/gateway/github/{conn_label}/user/repos"
            if url not in seen_urls:
                seen_urls.add(url)
                denials.append(
                    {
                        "url": url,
                        "http_status": 403,
                        "reason": "endpoint is blocked by policy",
                        "evidence": line.strip()[:260],
                    }
                )

    # Also capture any /v1/gateway/ attempt observed in strace execve (e.g. blocked by air-gapped detonator)
    for item in probe_urls:
        url = item["url"]
        if "/v1/gateway/" in url and url not in seen_urls:
            seen_urls.add(url)
            denials.append(
                {
                    "url": url,
                    "http_status": 0,
                    "reason": "blocked by air-gapped detonator egress/label policy",
                    "evidence": item["evidence"],
                }
            )

    return denials


def scan_readme_prompt_injection(readme_text: str, *, source: str = "README.md") -> list[dict[str, Any]]:
    """Deterministic static scan for reviewer-override / prompt-injection patterns."""
    findings: list[dict[str, Any]] = []
    if not readme_text:
        return findings

    rules = (
        list(PROMPT_INJECTION_RULES) + list(MCP_POISONING_RULES)
        if source == "SKILL.md"
        else list(PROMPT_INJECTION_RULES)
    )
    lines = readme_text.splitlines()
    for rule_id, pattern, desc in rules:
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append(
                    {
                        "source": source,
                        "rule": rule_id,
                        "description": desc,
                        "line": idx,
                        "excerpt": line.strip()[:220],
                    }
                )
                break
        else:
            m = pattern.search(readme_text)
            if m:
                findings.append(
                    {
                        "source": source,
                        "rule": rule_id,
                        "description": desc,
                        "line": readme_text[: m.start()].count("\n") + 1,
                        "excerpt": m.group(0).replace("\n", " ")[:220],
                    }
                )
    return findings


def _iter_strings(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(obj, str):
        items.append((prefix, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            child_prefix = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_iter_strings(v, child_prefix))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            items.extend(_iter_strings(v, f"{prefix}[{idx}]"))
    return items


def scan_mcp_tool_poisoning(mcp_transcript: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Deterministic static scan for prompt-injection metadata in MCP tools, resources, and prompts."""
    findings: list[dict[str, Any]] = []
    if not isinstance(mcp_transcript, dict):
        return findings

    combined_rules = list(PROMPT_INJECTION_RULES) + list(MCP_POISONING_RULES)
    seen: set[tuple[str, str, str]] = set()

    def _scan_item(item_name: str, candidates: list[tuple[str, str]]) -> None:
        for field_path, text in candidates:
            for rule_id, pattern, desc in combined_rules:
                m = pattern.search(text)
                if m:
                    key = (item_name, field_path, rule_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        {
                            "tool": item_name,
                            "field": field_path,
                            "rule": rule_id,
                            "description": desc,
                            "excerpt": m.group(0).replace("\n", " ")[:220],
                        }
                    )

    tools = ((mcp_transcript.get("tools_list") or {}).get("tools")) or []
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = str(tool.get("name") or "<unnamed>")
            candidates: list[tuple[str, str]] = []
            if isinstance(tool.get("name"), str):
                candidates.append(("name", tool["name"]))
            if isinstance(tool.get("description"), str):
                candidates.append(("description", tool["description"]))
            if tool.get("inputSchema") is not None:
                candidates.extend(_iter_strings(tool["inputSchema"], "inputSchema"))
            _scan_item(tool_name, candidates)

    for list_key, item_key in (("resources_list", "resources"), ("prompts_list", "prompts")):
        entries = ((mcp_transcript.get(list_key) or {}).get(item_key)) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or entry.get("uri") or f"<{list_key}>")
            _scan_item(name, _iter_strings(entry, list_key))

    return findings


def compute_risk_and_verdict(
    strace_data: dict[str, Any],
    connector_denials: list[dict[str, Any]],
    prompt_injections: list[dict[str, Any]],
    mcp_tool_poisoning: list[dict[str, Any]] | None = None,
    detonation_timeouts: list[dict[str, Any]] | None = None,
    *,
    skill_block_count: int | None = None,
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    high_severity = False

    sens = strace_data["sensitive_file_probes"]
    if sens:
        pts = min(40, 20 + 10 * len(sens))
        score += pts
        high_severity = True
        paths = ", ".join(item["path"] for item in sens[:4])
        reasons.append(f"Sensitive file probes ({len(sens)}): {paths} [+{pts}]")

    writes = strace_data["unexpected_writes"]
    if writes:
        pts = min(35, 15 + 10 * len(writes))
        score += pts
        if any(w["path"].startswith("/home/sprite/") for w in writes):
            high_severity = True
        paths = ", ".join(item["path"] for item in writes[:4])
        reasons.append(f"Unexpected writes outside workspace ({len(writes)}): {paths} [+{pts}]")

    non_dns_connects = [
        c for c in strace_data["network_connects"] if c["classification"] not in ("dns_resolver", "loopback")
    ]
    probe_urls = strace_data["probe_urls"]
    dns_queries = strace_data["dns_queries"]
    if non_dns_connects or probe_urls or dns_queries:
        signal_count = max(len(non_dns_connects), len(probe_urls), len(dns_queries))
        pts = min(35, 15 + 10 * signal_count)
        score += pts
        high_severity = True
        targets = [f"{c['ip']}:{c['port']} ({c['classification']})" for c in non_dns_connects[:3]]
        if not targets and dns_queries:
            targets = [f"DNS:{d['domain']}" for d in dns_queries[:3]]
        reasons.append(
            f"Outbound network probes ({len(non_dns_connects)} connect, {len(dns_queries)} DNS, {len(probe_urls)} URLs): {', '.join(targets)} [+{pts}]"
        )

    subprocs = strace_data["notable_subprocesses"]
    if subprocs:
        pts = min(20, 10 + 5 * len(subprocs))
        score += pts
        names = sorted({s["name"] for s in subprocs})
        reasons.append(f"Notable subprocess spawns ({len(subprocs)}): {', '.join(names)} [+{pts}]")

    if connector_denials:
        pts = 25
        score += pts
        high_severity = True
        reasons.append(f"Blocked / air-gapped Connector route attempted ({len(connector_denials)}) [+{pts}]")

    if prompt_injections:
        skill_hits = [p for p in prompt_injections if p.get("source") == "SKILL.md"]
        if skill_hits:
            pts = min(50, 25 + 10 * len(skill_hits))
            if any(
                p.get("rule")
                in (
                    "mcp_hidden_directive_tag",
                    "mcp_conceal_from_user",
                    "mcp_ssh_or_secret_read",
                    "mcp_exfil_command",
                    "mcp_base64_directive",
                    "secret_exfil_prompt",
                    "ignore_instructions",
                    "forced_approval",
                )
                for p in skill_hits
            ):
                high_severity = True
            score += pts
            reasons.append(f"Untrusted SKILL.md / README prompt-injection patterns ({len(prompt_injections)} rules matched) [+{pts}]")
        else:
            pts = min(25, 15 + 5 * len(prompt_injections))
            score += pts
            reasons.append(f"Untrusted README prompt-injection patterns ({len(prompt_injections)} rules matched) [+{pts}]")

    if mcp_tool_poisoning:
        pts = min(35, 20 + 5 * len(mcp_tool_poisoning))
        score += pts
        high_severity = True
        rules = ", ".join(sorted({item["rule"] for item in mcp_tool_poisoning})[:4])
        reasons.append(f"MCP metadata poisoning ({len(mcp_tool_poisoning)} rules: {rules}) [+{pts}]")

    if detonation_timeouts:
        pts = 25
        score += pts
        reasons.append(f"Detonation timeout hit (exit code 124; possible sleep/evasion) [+{pts}]")

    if skill_block_count == 0 and score < 20 and not high_severity:
        pts = 25
        score += pts
        reasons.append(f"No runnable code blocks found in SKILL.md / URL (static-only scan) [+{pts}]")

    final_score = min(100, score)
    if final_score >= 50 or high_severity:
        verdict = "BLOCK"
    elif final_score >= 20:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "high_severity_triggered": high_severity,
        "scoring_reasons": reasons,
    }


def extract_all_iocs(run_dir: Path) -> dict[str, Any]:
    strace_path = run_dir / "blastbox.strace"
    stdout_path = run_dir / "command.stdout"
    stderr_path = run_dir / "command.stderr"
    readme_path = run_dir / "README.md"
    skill_path = run_dir / "SKILL.md"

    def _load_json(name: str) -> Any:
        p = run_dir / name
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        return None

    strace_text = strace_path.read_text(encoding="utf-8", errors="replace") if strace_path.exists() else ""
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    readme_text = readme_path.read_text(encoding="utf-8", errors="replace") if readme_path.exists() else ""
    skill_text = skill_path.read_text(encoding="utf-8", errors="replace") if skill_path.exists() else ""
    mcp_transcript = _load_json("mcp_transcript.json")
    fs_diff = _load_json("fs_diff.json")
    detonation_meta = _load_json("detonation_meta.json")

    strace_data = parse_strace(strace_text)
    strace_data["unexpected_writes"] = merge_fs_diff_into_writes(strace_data["unexpected_writes"], fs_diff)

    connector_denials = parse_connector_denials(stdout_text, stderr_text, strace_data["probe_urls"])
    prompt_injections = scan_readme_prompt_injection(readme_text, source="README.md")
    if skill_text:
        prompt_injections.extend(scan_readme_prompt_injection(skill_text, source="SKILL.md"))
    mcp_tool_poisoning = scan_mcp_tool_poisoning(mcp_transcript)

    detonation_timeouts: list[dict[str, Any]] = []
    if isinstance(detonation_meta, dict) and detonation_meta.get("exit_code") == 124:
        detonation_timeouts.append(
            {
                "exit_code": 124,
                "reason": "Detonation exceeded timeout boundary (exit 124); payload may be sleeping or stalling",
            }
        )

    skill_block_count = None
    if isinstance(detonation_meta, dict) and detonation_meta.get("mode") == "skill":
        raw_cnt = detonation_meta.get("skill_block_count")
        if isinstance(raw_cnt, int):
            skill_block_count = raw_cnt

    scoring = compute_risk_and_verdict(
        strace_data,
        connector_denials,
        prompt_injections,
        mcp_tool_poisoning,
        detonation_timeouts=detonation_timeouts,
        skill_block_count=skill_block_count,
    )

    non_dns_connects = [
        c for c in strace_data["network_connects"] if c.get("classification") not in ("dns_resolver", "loopback")
    ]

    result: dict[str, Any] = {
        "schema_version": "blastbox-iocs-v2",
        "deterministic": True,
        **scoring,
        "counts": {
            "total_strace_lines": strace_data["total_strace_lines"],
            "sensitive_file_probes": len(strace_data["sensitive_file_probes"]),
            "unexpected_writes": len(strace_data["unexpected_writes"]),
            "network_connects": len(non_dns_connects),
            "dns_queries": len(strace_data["dns_queries"]),
            "probe_urls": len(strace_data["probe_urls"]),
            "notable_subprocesses": len(strace_data["notable_subprocesses"]),
            "connector_policy_denials": len(connector_denials),
            "prompt_injection_signals": len(prompt_injections),
            "mcp_tool_poisoning": len(mcp_tool_poisoning),
            "detonation_timeouts": len(detonation_timeouts),
        },
        "findings": {
            "sensitive_file_probes": strace_data["sensitive_file_probes"],
            "unexpected_writes": strace_data["unexpected_writes"],
            "network_connects": strace_data["network_connects"],
            "dns_queries": strace_data["dns_queries"],
            "probe_urls": strace_data["probe_urls"],
            "notable_subprocesses": strace_data["notable_subprocesses"],
            "connector_policy_denials": connector_denials,
            "prompt_injection_signals": prompt_injections,
            "mcp_tool_poisoning": mcp_tool_poisoning,
            "detonation_timeouts": detonation_timeouts,
        },
        "context": {
            "preflight_env": _load_json("preflight_env.json"),
            "pr_meta": _load_json("pr_meta.json"),
            "mcp_transcript": mcp_transcript,
            "fs_diff": fs_diff,
            "post_run_markers": _load_json("post_run_markers.json"),
            "restore_verification": _load_json("restore_verification.json"),
            "detonation_meta": detonation_meta,
        },
    }

    out_path = run_dir / "iocs.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic IOC extractor for Blastbox strace telemetry")
    parser.add_argument("run_dir", type=Path, help="Path to Blastbox run artifact directory (e.g. ./last_run)")
    args = parser.parse_args()

    result = extract_all_iocs(args.run_dir)
    print(
        json.dumps(
            {
                "verdict": result["verdict"],
                "risk_score": result["risk_score"],
                "counts": result["counts"],
                "output": str(args.run_dir / "iocs.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
