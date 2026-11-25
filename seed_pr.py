#!/usr/bin/env python3
"""Seed (or reuse) Blastbox demo PRs via the Controller Sprite's GitHub Connector.

Supports both:
  - Poisoned fixture PR (`fixtures/poisoned-pr` -> branch `demo/poisoned-slugify-pr`)
  - Clean PASS fixture PR (`--clean`, `fixtures/clean-pr` -> branch `feat/slugify-lite-clean`)
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import config  # noqa: E402

REMOTE_SEED_SCRIPT = r"""
import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
owner = payload["owner"]
repo = payload["repo"]
branch = payload["branch"]
base_branch = payload["base_branch"]
title = payload["title"]
pr_body = payload["body"]
files = payload["files"]
gateway = payload["github_gateway"]

API = f"{gateway}/repos/{owner}/{repo}"

def gh_req(method, path, body=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "blastbox-seeder/2.0",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return err.code, parsed

st, ref = gh_req("GET", f"/git/ref/heads/{branch}")
branch_created = False
if st == 404:
    st_main, main_ref = gh_req("GET", f"/git/ref/heads/{base_branch}")
    if st_main != 200:
        raise RuntimeError(f"Failed to read base branch {base_branch}: HTTP {st_main} {main_ref}")
    main_sha = main_ref["object"]["sha"]
    st_cr, cr_ref = gh_req("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": main_sha})
    if st_cr not in (200, 201):
        raise RuntimeError(f"Failed to create branch {branch}: HTTP {st_cr} {cr_ref}")
    branch_created = True
elif st != 200:
    raise RuntimeError(f"Failed to check branch {branch}: HTTP {st} {ref}")

updated_files = []
unchanged_files = []
for rel_path, content_b64 in sorted(files.items()):
    st_f, existing = gh_req("GET", f"/contents/{rel_path}?ref={branch}")
    existing_sha = None
    if st_f == 200 and isinstance(existing, dict):
        existing_sha = existing.get("sha")
        existing_raw = base64.b64decode(existing.get("content", ""))
        desired_raw = base64.b64decode(content_b64)
        if existing_raw == desired_raw:
            unchanged_files.append(rel_path)
            continue
    put_body = {
        "message": f"chore: sync {rel_path} on {branch}",
        "content": content_b64,
        "branch": branch,
    }
    if existing_sha:
        put_body["sha"] = existing_sha
    st_put, put_res = gh_req("PUT", f"/contents/{rel_path}", put_body)
    if st_put not in (200, 201):
        raise RuntimeError(f"Failed to upsert {rel_path}: HTTP {st_put} {put_res}")
    updated_files.append(rel_path)

st_prs, prs = gh_req("GET", f"/pulls?state=open&head={owner}:{branch}")
if st_prs != 200:
    raise RuntimeError(f"Failed to list PRs: HTTP {st_prs} {prs}")

if prs:
    pr = prs[0]
    created_pr = False
else:
    st_pr, pr = gh_req(
        "POST",
        "/pulls",
        {
            "title": title,
            "head": branch,
            "base": base_branch,
            "body": pr_body,
        },
    )
    if st_pr not in (200, 201):
        raise RuntimeError(f"Failed to create PR: HTTP {st_pr} {pr}")
    created_pr = True

print(
    json.dumps(
        {
            "pr_url": pr["html_url"],
            "pr_number": pr["number"],
            "head_ref": pr["head"]["ref"],
            "head_sha": pr["head"]["sha"],
            "branch_created": branch_created,
            "pr_created": created_pr,
            "updated_files": updated_files,
            "unchanged_files": unchanged_files,
        },
        indent=2,
    )
)
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed or reuse Blastbox demo PRs via GitHub Connector")
    parser.add_argument("--sprite", default=config.CONTROLLER_SPRITE)
    parser.add_argument("--repo", default=config.DEFAULT_REPO)
    parser.add_argument("--clean", action="store_true", help="Seed the clean PASS slugify-lite PR instead of poisoned PR")
    parser.add_argument("--branch", default=None)
    parser.add_argument("--fixture-dir", type=Path, default=None)
    args = parser.parse_args()

    if args.clean:
        branch = args.branch or "feat/slugify-lite-clean"
        fixture_dir = args.fixture_dir or (SCRIPT_DIR / "fixtures" / "clean-pr")
        title = "feat: add clean slugify-lite ASCII helper (v0.2.1)"
        body = (
            "Adds `slugify-lite` v0.2.1, a minimal zero-dependency ASCII slug utility with unit tests.\n\n"
            "No external telemetry, environment inspection, or out-of-workspace filesystem access."
        )
    else:
        branch = args.branch or "demo/poisoned-slugify-pr"
        fixture_dir = args.fixture_dir or (SCRIPT_DIR / "fixtures" / "poisoned-pr")
        title = "feat: add slugify-lite utility package"
        body = (
            "Adds `slugify-lite`, a lightweight zero-dependency ASCII slug helper with passing unit tests.\n\n"
            "Includes standard runtime compatibility checks during installation and tests."
        )

    owner, repo = args.repo.split("/", 1)
    files_b64: dict[str, str] = {}
    for path in sorted(fixture_dir.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            rel = path.relative_to(fixture_dir).as_posix()
            files_b64[rel] = base64.b64encode(path.read_bytes()).decode("ascii")

    payload = {
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "base_branch": "main",
        "title": title,
        "body": body,
        "github_gateway": config.GITHUB_GATEWAY,
        "files": files_b64,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        payload_file = tmp / "seed_payload.json"
        script_file = tmp / "remote_seed.py"
        payload_file.write_text(json.dumps(payload), encoding="utf-8")
        script_file.write_text(REMOTE_SEED_SCRIPT, encoding="utf-8")

        cmd = [
            config.SPRITE_BIN,
            "exec",
            "-s",
            args.sprite,
            "--no-stdin",
            "--file",
            f"{payload_file}:/tmp/.ctrl_seed_payload.json",
            "--file",
            f"{script_file}:/tmp/.ctrl_seed_remote.py",
            "--",
            "bash",
            "-c",
            (
                'export PATH="/.sprite/bin:$PATH"; '
                "/.sprite/bin/python3 /tmp/.ctrl_seed_remote.py /tmp/.ctrl_seed_payload.json; "
                "RC=$?; rm -f /tmp/.ctrl_seed_payload.json /tmp/.ctrl_seed_remote.py; exit $RC"
            ),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"seed_pr failed (rc={proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        print(proc.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
