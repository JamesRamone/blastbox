![Blastbox Hacksgiving Two-Sprite Detonation Oven](docs/hacksgiving-turkey.png)

# Blastbox

[![Runs on Fly.io](https://img.shields.io/badge/Runs%20on-Fly.io-8636EA?style=flat&logo=flydotio&logoColor=white)](https://fly.io)
[![Built with Sprites](https://img.shields.io/badge/Built%20with-Sprites-10151C?style=flat&logo=linux&logoColor=white)](https://sprites.dev)
[![Zero-Secret Connectors](https://img.shields.io/badge/Connectors-Zero--Secret-0F6B46?style=flat)](#how-it-works)
[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-6D28D9?style=flat)](https://blastbox-3xb.sprites.app)

Blastbox safely detonates untrusted GitHub pull requests, stdio MCP servers, and AI agent `SKILL.md` files inside a disposable network-isolated VM before you review or install them. It catches hidden supply-chain payloads whose unit tests still pass or return `isError: false` (SSH key reads, persistence file drops, outbound exfiltration attempts, and prompt injections), rewinds the sandbox to a clean snapshot, and posts the forensic verdict to GitHub, Slack, and a public dashboard.

## Try It

- **Live Audit Console:** [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app)
- **Slack `#blastbox` triggers:**
  ```text
  @blastbox boom poisoned-skill
  @blastbox boom clean-skill
  @blastbox boom poisoned-mcp
  @blastbox boom https://raw.githubusercontent.com/<owner>/<repo>/main/SKILL.md
  @blastbox boom https://github.com/<owner>/<repo>/pull/<number>
  @blastbox help
  ```
- **Local CLI demos:**
  ```bash
  ./demo.sh --all         # Run all 6 scenarios (PR, MCP, SKILL.md)
  ./demo.sh --skill       # Poisoned SKILL.md -> BLOCK (100/100)
  ./demo.sh --clean-skill # Clean SKILL.md    -> PASS  (0/100)
  python3 blastbox.py https://example.com/SKILL.md --mode skill
  ```

Remote HTTPS URLs pass controller-side pinned-IP SSRF validation (`url_guard.py`: HTTPS port `443` only, loopback/RFC1918/`169.254.169.254`/`*.sprites.dev` blocked) before staging into the detonator.

![Blastbox Live Hacksgiving Audit Dashboard](docs/dashboard.png)

---

## How It Works

Running untrusted code inside the same VM that holds API credentials or Sprites Connectors lets malicious code abuse allowed routes even without raw tokens on disk. Blastbox splits orchestration from execution across two Firecracker Sprites:

```text
  GitHub PR  ·  Stdio MCP Server  ·  Agent SKILL.md (PR Watcher / Slack @blastbox boom / CLI)
           │
           ▼
┌───────────────────────────────┐        sprite exec / restore         ┌────────────────────────────────────┐
│  Controller Sprite: blastbox  │ ────────────────────────────────────▶│  Detonator: blastbox-detonator     │
│  • GitHub + OpenRouter + Slack│                                      │  • ZERO raw tokens or labels       │
│  • Pinned-IP SSRF URL fetcher │        pulls strace + fs_diff        │  • Egress policy: * -> deny        │
│  • LLM planner & PR/Slack bot │ ◀────────────────────────────────────│  • strace -f + pre/post FS diff    │
│  • Public :8080 web console   │   never executes untrusted targets   │  • Restored to golden checkpoint   │
└───────────────────────────────┘                                      └────────────────────────────────────┘
```

- **Air-gapped detonator (`blastbox-detonator`):** Carries `0` raw credentials, `0` labels (all Connectors denied), an outbound `* -> deny` egress policy enforced outside the VM, and an immutable golden baseline checkpoint (`blastbox-detonator-golden`, currently `v27`) reused across detonations.
- **Scoped Controller (`blastbox`):** Polls GitHub PRs and Slack `#blastbox` using route-scoped zero-secret Sprites Connectors, asks OpenRouter (`agent_planner.py`) which tools/stages/fenced code blocks to probe, detonates them under `strace -f` inside the detonator, and publishes forensic verdicts back to GitHub and Slack.
- **Generic FS diff & overlay rewind:** Hashes `/home/sprite` and `/tmp` (`/var/tmp`, `/dev/shm`) before detonation, after detonation, and after `sprite restore` to detect arbitrary dropped files and verify `0` remain post-rewind.

---

## Live-Verified Runs

Six canonical runs (`3 BLOCK`, `3 PASS` across PRs, stdio MCP servers, and `SKILL.md` files) persisted on [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app):

| Scenario | Verdict | Score | Planned Targets | Generic FS Diff -> Post-Restore | Runtime | Artifact / Checkpoint |
|---|---|---:|---|---|---:|---|
| **Poisoned `SKILL.md`** (`fixtures/poisoned-skill`) | **`BLOCK`** (`AI: BLOCK`) | `100/100` | `block_0.bash` | `2` created (`~/.config/skill-telemetry/agent.dat`, `/tmp/.skill_preflight_cache`) -> `0` left (`1,516` syscalls) | `138.58s` | Restored `v27` |
| **Clean `SKILL.md`** (`fixtures/clean-skill`) | **`PASS`** (`AI: PASS`) | `0/100` | `block_0.python` | `0` created (`151` syscalls traced cleanly) -> `0` left | `131.17s` | Restored `v27` |
| **Poisoned PR** (`demo/poisoned-slugify-pr`) | **`BLOCK`** (`AI: BLOCK`) | `100/100` | `pip_install`, `import_check`, `unittest` | `2` created (`~/.config/slugify-cache/session.dat`, `/tmp/.slugify_build_cache`) -> `0` left (`3,776` syscalls) | `40.37s` | [PR #1 Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/1#issuecomment-7157400949), `v17` |
| **Clean PR** (`feat/slugify-lite-clean`) | **`PASS`** (`AI: PASS`) | `0/100` | `pip_install`, `import_check`, `pytest` | `0` created (`3,569` syscalls traced cleanly) -> `0` left | `137.78s` | [PR #8 Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/8#issuecomment-7161347370), `v27` |
| **Poisoned 2-Tool MCP** (`fixtures/poisoned-mcp`) | **`BLOCK`** (`AI: BLOCK`) | `100/100` | `health_check`, `format_release_note` | `2` created (`~/.local/share/notes-mcp/state.bin`, `/tmp/.notes_mcp_cache`) -> `0` left (`493` syscalls) | `27.47s` | [Issue #9](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/9), `v10` |
| **Clean 2-Tool MCP** (`fixtures/clean-mcp`) | **`PASS`** (`AI: PASS`) | `0/100` | `health_check`, `format_release_note` | `0` created (`181` syscalls traced cleanly) -> `0` left | `24.63s` | [Issue #10](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/10), `v12` |

*Note: The bundled `fixtures/` payloads safely simulate real supply-chain attack techniques (RFC 5737 sinkhole probes `192.0.2.1:4444`, `.invalid` DNS lookups, SSH key reads, temp file drops, and prompt injections) without live exploits.*

---

## Self-Host in 3 Steps

### Prerequisites

- Fly.io account with the local [`sprite`](https://sprites.dev) CLI installed and logged in
- Python 3.10+ locally
- OpenRouter account (plus GitHub repo for PR watching)
- Optional Slack app (`slack_bot` Connector) with bot scopes `channels:history`, `chat:write`, and `reactions:write`, invited to your target channel

All Sprite names, Connector IDs, repositories, and Slack channels are configured via [`.env.example`](.env.example).

1. **Create Sprites Connectors** scoped to `BLASTBOX_CONTROLLER_LABEL` (default `blastbox`):
   - **GitHub:** allow `/user` and `/repos/<owner>/<repo>*`; deny `/user/repos*`, `/user/keys*`, `/repos/*/admin/*`, `/repos/*/hooks*`.
   - **OpenRouter:** allow `/v1/chat/completions`, `/v1/models`; deny `/v1/keys*`.
   - **Slack Bot (`slack_bot`, optional):** allow `auth.test`, `conversations.history`, `chat.postMessage`, `reactions.add`. Set `BLASTBOX_SLACK_CHANNELS` to the Slack **channel ID** (e.g. `C0123456789` from right-clicking the channel -> *View channel details*), not `#channel-name`.
2. **Configure and provision both Sprites:**
   ```bash
   cp .env.example .env
   # Edit .env with your Connector IDs, BLASTBOX_REPO, and optional Slack channel ID
   python3 init_detonator.py   # Auto-creates unlabeled deny-all egress Sprite + golden checkpoint
   python3 init_controller.py  # Auto-creates Controller Sprite, detects URL, starts web + agent
   ```
3. **Authenticate the `sprite` CLI once inside the controller:**
   ```bash
   sprite console -s blastbox
   # Inside controller shell:
   sprite login && sprite-env services restart blastbox-agent
   ```

---

## Known Limitations

- **Controller `sprite login` trust boundary:** The Controller Sprite executes `sprite exec` and `sprite restore` against `blastbox-detonator`, so it carries an authenticated `sprite login` session. Blastbox therefore never executes untrusted targets on the controller and treats all detonator outputs (`strace`, MCP transcripts, README/`SKILL.md` content) as untrusted data.
- **Userspace `ptrace` tracing and timeout evasion:** Blastbox relies on `strace -f` (`execve*`, `open*`/`creat`, `connect`/`send*`, `unlink*`/`rename*`/`link*`/`symlink*`/`chmod*`) rather than kernel eBPF; detonations hitting the `20s` timeout (`detonation_timeouts`) automatically score at least `REVIEW` so sleeping payloads cannot earn `PASS`.
- **Ecosystem and fixture scope:** Currently audits Python PR packages (`pip` + `unittest`/`pytest`), Python stdio MCP servers, and fenced Python/Bash code blocks in `SKILL.md` files; included `fixtures/` are deterministic threat-model simulations.
- **`/tmp` outside the checkpointed root overlay:** `/tmp`, `/var/tmp`, and `/dev/shm` reside on `/dev/vdb` outside the Firecracker root overlay snapshot, so Blastbox hashes and compares those directories before and after detonation and sweeps newly created files post-restore.
