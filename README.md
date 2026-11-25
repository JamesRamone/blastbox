![Blastbox Hacksgiving Two-Sprite Detonation Oven](docs/hacksgiving-turkey.png)

# Blastbox

[![Runs on Fly.io](https://img.shields.io/badge/Runs%20on-Fly.io-8636EA?style=flat&logo=flydotio&logoColor=white)](https://fly.io)
[![Built with Sprites](https://img.shields.io/badge/Built%20with-Sprites-10151C?style=flat&logo=linux&logoColor=white)](https://sprites.dev)
[![Zero-Secret Connectors](https://img.shields.io/badge/Connectors-Zero--Secret-0F6B46?style=flat)](https://blastbox-3xb.sprites.app/health)
[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-C8281E?style=flat)](https://blastbox-3xb.sprites.app)

**Zero-secret, two-Sprite detonation agent for untrusted GitHub pull requests, stdio MCP servers, and agent `SKILL.md` packages — triggered automatically from GitHub or via Slack `@blastbox boom <url>`.**  
Blastbox catches malicious code, poisoned MCP tools, and prompt-injected skill files whose tests pass or return `isError: false` while quietly reading SSH keys, writing persistence files, attempting exfiltration, or hijacking reviewers.

Live Dashboard (with `Lab` and `Hacksgiving` themes): [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app) · Demo Video: *Coming before submission*

![Blastbox Forensic Audit Dashboard](docs/dashboard.png)

---

## Why Two Sprites?

Running untrusted code in the same VM that holds Sprites Connectors lets a malicious payload call *allowed* Connector routes (such as creating GitHub issues or posting to Slack) even when `/user/repos` returns `HTTP 403`. Blastbox splits control from detonation across two Firecracker Sprites:

```text
  GitHub PR / Stdio MCP / Agent SKILL.md (CLI, PR Watcher, or Slack `@blastbox boom`)
           │
           ▼
┌───────────────────────────────┐        sprite exec / restore         ┌────────────────────────────────────┐
│  Controller Sprite: blastbox  │ ────────────────────────────────────▶│  Detonator: blastbox-detonator     │
│  • Zero raw tokens in env     │                                      │  • ZERO raw tokens in env          │
│  • GitHub+OpenRouter+Slack    │        pulls strace + fs_diff        │  • ZERO labels (Connectors denied) │
│  • SSRF-guarded HTTPS fetcher │ ◀────────────────────────────────────│  • Egress policy: * -> deny        │
│  • LLM probe planner & triage │                                      │  • Expanded strace + fs snapshot   │
│  • Always-on PR + Slack agent │   never runs untrusted target code   │  • Wiped via `sprite restore`      │
└───────────────────────────────┘                                      └────────────────────────────────────┘
```

1. **Air-gapped detonation (`blastbox-detonator`):** Holds zero raw tokens, zero labels (all Sprites Connectors denied, returning `curl` DNS/egress failure even on allowed routes), and an active `* -> deny` outbound network policy enforced outside the VM.
2. **Slack ChatOps + Autonomous PR Watcher (`controller_agent.py`):** Polls GitHub PRs every 30s and Slack `#blastbox` every 5s via zero-secret Sprites Connectors. Any user can drop `@blastbox boom <url>` (such as `@blastbox boom https://totallysafeskills.com/skill.md` or `@blastbox boom poisoned-skill`), get a `:bomb:` reaction and live Block Kit verdict card in the thread, and inspect full trace telemetry on the public web console.
3. **LLM agent probe planning (`agent_planner.py`):** Before detonation, the Controller Sprite inspects the PR file tree, MCP `tools/list` (`resources/list`, `prompts/list`), or `SKILL.md` fenced code blocks via the OpenRouter Connector and picks which tools/arguments and blocks to detonate under `strace`.
4. **Generic filesystem diff + overlay rewind:** Blastbox hashes `/home/sprite` and `/tmp` before detonation, after detonation, and after `sprite restore`. Every unexpected file written outside `/home/sprite/detonation` is caught deterministically regardless of path name, verified absent from `/home/sprite` post-restore, and swept from `/tmp` (`/dev/vdb`).

---

## Live-Verified Runs

All six scenarios (`--pr`, `--clean-pr`, `--mcp`, `--clean-mcp`, `--skill`, `--clean-skill`) plus autonomous PR-watcher runs executed live on `blastbox` against `blastbox-detonator` and persisted to [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app):

| Scenario | Verdict | Score | Agent Probe Plan | Generic FS Diff -> Post-Restore | Runtime | Artifact / Notes |
|---|---|---:|---|---|---:|---|
| **Poisoned PR** (`demo/poisoned-slugify-pr`) | **`BLOCK`** | `100/100` | `pip_install`, `import_check`, `unittest` | `2` created (`~/.config/slugify-cache/session.dat`, `/tmp/.slugify_build_cache`) -> `0` left | `40.37s` | [PR #1 Autonomous Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/1#issuecomment-7157400949) |
| **Clean PR** (`feat/slugify-lite-clean`) | **`PASS`** | `0/100` | `pip_install`, `import_check`, `pytest` | `0` created (`3,494` syscalls traced cleanly) -> `0` left | `42.53s` | [PR #8 Autonomous Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/8#issuecomment-7157386908) |
| **Poisoned 2-Tool MCP** (`fixtures/poisoned-mcp`) | **`BLOCK`** | `100/100` | Flagged & ran `format_release_note` + `health_check` | `2` created (`~/.local/share/notes-mcp/state.bin`, `/tmp/.notes_mcp_cache`) -> `0` left | `27.47s` | [Issue #9](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/9) |
| **Clean 2-Tool MCP** (`fixtures/clean-mcp`) | **`PASS`** | `0/100` | Ran `health_check` + `format_release_note` | `0` created (`181` syscalls traced cleanly) -> `0` left | `24.63s` | [Issue #10](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/10) |
| **Poisoned `SKILL.md`** (`fixtures/poisoned-skill`) | **`BLOCK`** | `100/100` | Extracted `<IMPORTANT>` injection & ran `block_0.bash` | `2` created (`~/.config/skill-telemetry/agent.dat`, `/tmp/.skill_preflight_cache`) -> `0` left | `119.02s` | Restored `v20`; 7 prompt-injection rules |
| **Clean `SKILL.md`** (`fixtures/clean-skill`) | **`PASS`** | `0/100` | Selected benign `block_0.python` TOC helper | `0` created (`151` syscalls traced cleanly) -> `0` left | `253.99s` | Restored `v22`; 0 IOCs |

---

## Slack `#blastbox` Commands

Inside your connected Slack channel (`#blastbox`, Bot Connector via Sprites `slack_bot` gateway), type any of:

```text
@blastbox boom poisoned-skill
@blastbox boom clean-skill
@blastbox boom poisoned-mcp
@blastbox boom https://raw.githubusercontent.com/<owner>/<repo>/main/SKILL.md
@blastbox boom https://github.com/<owner>/<repo>/pull/<number>
```

Remote HTTPS `SKILL.md` URLs are validated with an SSRF guard on the controller Sprite (blocking `http://`, loopback, RFC1918 private ranges, cloud metadata `169.254.169.254`, and `api.sprites.dev`) before staging into `blastbox-detonator`.

---

## Self-Host on Your Fly.io Account

All Sprite names, Connector IDs, Slack channels, repositories, and URLs are configurable via environment variables or `.env` (see [`.env.example`](.env.example)).

### 1. Create Sprites Connectors in Your Fly.io Org
Create three Sprites Connectors scoped to sprites carrying `--label hacksgiving`:
- **GitHub Connector:** Allow `/user` and `/repos/<owner>/<repo>*`; block `/user/repos*`, `/user/keys*`, `/repos/*/admin/*`, `/repos/*/hooks*`.
- **OpenRouter Connector:** Allow `/v1/chat/completions`, `/v1/models`; block `/v1/keys*`.
- **Slack Bot Connector (`slack_bot`):** Scoped bot token in your workspace for `auth.test`, `conversations.history`, `chat.postMessage`, and `reactions.add`, with the bot invited to your trigger channel.

### 2. Configure & Bootstrap Both Sprites

```bash
cp .env.example .env
# Edit .env with your Fly.io Connector IDs, Slack channel ID, target repo, and Sprite names

# Create & lock down the unlabeled deny-all egress Detonator Sprite:
python3 init_detonator.py

# Deploy the web dashboard (:8080, public) + autonomous PR & Slack controller agent:
python3 init_controller.py

# Authenticate `sprite` CLI once inside Controller Sprite (required for autonomous control):
sprite console -s blastbox
# inside console: sprite login && sprite-env services restart blastbox-agent
```

### 3. Run Demos

```bash
./demo.sh               # Poisoned PR       -> BLOCK (100/100)
./demo.sh --clean-pr    # Clean PR          -> PASS  (0/100)
./demo.sh --mcp         # Poisoned MCP      -> BLOCK (100/100)
./demo.sh --clean-mcp   # Clean MCP         -> PASS  (0/100)
./demo.sh --skill       # Poisoned SKILL.md -> BLOCK (100/100)
./demo.sh --clean-skill # Clean SKILL.md    -> PASS  (0/100)
./demo.sh --all         # Run all 6 scenarios sequentially
```

You can also audit any local directory, PR URL, or HTTPS `SKILL.md` URL directly:

```bash
python3 blastbox.py https://github.com/<owner>/<repo>/pull/<number> --mode pr
python3 blastbox.py ./path/to/untrusted-mcp-server --mode mcp
python3 blastbox.py https://example.com/SKILL.md --mode skill
```

---

## Known Limitations

- **Ptrace visibility & timeout evasion:** Tracing uses `strace -f` (`execve`/`execveat`, `open`/`openat`/`openat2`/`creat`, `connect`/`sendto`/`sendmsg`/`sendmmsg`, `unlink*`/`rename*`/`link*`/`symlink*`/`chmod*`) rather than kernel eBPF; binaries that detect `TracerPid` or deliberately sleep past the 20s window are bounded by `timeout` (exit `124` triggers at least a `REVIEW` verdict so sleeping cannot silently return `PASS`).
- **Ecosystem scope:** PR, MCP, and `SKILL.md` runners currently execute Python (`pip` + `unittest`/`pytest`, Python stdio MCP servers) and Python/Bash fenced `SKILL.md` blocks; Node/`npm` and arbitrary container entrypoints are natural next extensions.
- **`/tmp` persistence on `/dev/vdb`:** Because `/tmp` on Fly.io Sprites lives on `/dev/vdb` outside the checkpointed root overlay, `blastbox.py` captures a generic before/after diff of `/tmp` and sweeps all newly created `/tmp` paths post-restore.
