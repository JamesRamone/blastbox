#!/usr/bin/env python3
"""Strict SSRF-safe HTTPS fetcher with pinned-IP TLS connections.

Shared by `blastbox.py` locally and invoked as a standalone script on the
Controller Sprite so there is only one implementation of URL validation,
GitHub `blob` -> `raw` normalization, private-IP blocking, and redirect checks.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path
from typing import Any

MAX_REMOTE_BYTES = 256 * 1024
MAX_REDIRECTS = 3
GH_BLOB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$")

BLOCKED_HOSTS = {"localhost", "api.sprites.dev"}
BLOCKED_SUFFIXES = (".sprites.dev", ".local", ".internal", ".localhost")


def normalize_skill_url(raw_url: str) -> str:
    url = raw_url.strip()
    m = GH_BLOB_RE.match(url)
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}"
    return url


def validate_and_resolve_https_url(raw_url: str) -> tuple[str, str, list[str]]:
    """Validate URL rules and resolve public/global IPv4/IPv6 addresses.

    Returns `(normalized_url, hostname, pinned_ips)`.
    """
    url = normalize_skill_url(raw_url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Only HTTPS URLs are permitted for untrusted fetch (got scheme={parsed.scheme!r})")
    if parsed.port not in (None, 443):
        raise ValueError(f"Only standard HTTPS port 443 is permitted (got port={parsed.port})")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded userinfo credentials are rejected")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("URL is missing a hostname")
    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
        raise ValueError(f"Blocked internal/gateway hostname: {host}")

    try:
        ip_lit = ipaddress.ip_address(host)
        if not ip_lit.is_global:
            raise ValueError(f"Blocked non-global IP literal: {host}")
    except ValueError as exc:
        if "Blocked non-global IP" in str(exc):
            raise

    try:
        addr_infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Failed to resolve host {host}: {exc}") from exc
    if not addr_infos:
        raise ValueError(f"No DNS addresses resolved for {host}")

    pinned_ips: list[str] = []
    seen_ips: set[str] = set()
    for info in addr_infos:
        ip_str = str(info[4][0]).split("%", 1)[0]
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_global:
            raise ValueError(f"Blocked non-global resolved IP {ip_str} for host {host}")
        if ip_str not in seen_ips:
            seen_ips.add(ip_str)
            pinned_ips.append(ip_str)

    return url, host, pinned_ips


def validate_untrusted_https_url(raw_url: str) -> str:
    url, _host, _ips = validate_and_resolve_https_url(raw_url)
    return url


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect directly to pre-validated IP while keeping SNI & cert verification."""

    def __init__(self, host: str, pinned_ip: str, *, timeout: int = 15, context: ssl.SSLContext | None = None) -> None:
        super().__init__(host, port=443, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, 443), timeout=self.timeout, source_address=self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_untrusted_url_safely(raw_url: str, *, max_bytes: int = MAX_REMOTE_BYTES, timeout: int = 15) -> tuple[str, str]:
    """Fetch untrusted HTTPS content with pinned-IP TLS sockets and redirect validation."""
    current_url = raw_url
    ssl_ctx = ssl.create_default_context()

    for _hop in range(MAX_REDIRECTS + 1):
        norm_url, host, pinned_ips = validate_and_resolve_https_url(current_url)
        parsed = urllib.parse.urlsplit(norm_url)
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query = f"{path_and_query}?{parsed.query}"

        last_exc: Exception | None = None
        resp_status = 0
        resp_headers: Any = None
        body = b""
        fetched = False

        for pinned_ip in pinned_ips:
            conn = _PinnedHTTPSConnection(host, pinned_ip, timeout=timeout, context=ssl_ctx)
            try:
                conn.request(
                    "GET",
                    path_and_query,
                    headers={
                        "Host": host,
                        "Accept": "text/markdown, text/plain;q=0.9, */*;q=0.5",
                        "User-Agent": "blastbox-skill-fetch/2.0",
                        "Connection": "close",
                    },
                )
                resp = conn.getresponse()
                resp_status = resp.status
                resp_headers = resp.headers
                if resp_status in (301, 302, 303, 307, 308):
                    location = resp.getheader("Location")
                    if not location:
                        raise ValueError(f"HTTP {resp_status} redirect missing Location header")
                    current_url = urllib.parse.urljoin(norm_url, location)
                    fetched = True
                    break
                if resp_status >= 400:
                    raise RuntimeError(f"Remote HTTPS fetch failed with HTTP {resp_status} for {norm_url}")
                body = resp.read(max_bytes + 1)
                fetched = True
                break
            except OSError as exc:
                last_exc = exc
            finally:
                conn.close()

        if not fetched:
            raise RuntimeError(f"Failed connecting to validated IPs for {host}: {last_exc}")

        if resp_status in (301, 302, 303, 307, 308):
            continue

        if len(body) > max_bytes:
            raise ValueError(f"Remote target exceeds {max_bytes} byte limit")
        return norm_url, body.decode("utf-8", errors="replace")

    raise ValueError(f"Exceeded maximum {MAX_REDIRECTS} redirects while fetching URL")


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: url_guard.py <https_url> <out_json_path>", file=sys.stderr)
        return 2
    final_url, text = fetch_untrusted_url_safely(sys.argv[1])
    Path(sys.argv[2]).write_text(json.dumps({"url": final_url, "text": text}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
