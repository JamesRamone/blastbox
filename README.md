![Blastbox Hacksgiving Two-Sprite Detonation Oven](docs/hacksgiving-turkey.png)

# Blastbox

[![Runs on Fly.io](https://img.shields.io/badge/Runs%20on-Fly.io-8636EA?style=flat&logo=flydotio&logoColor=white)](https://fly.io)
[![Built with Sprites](https://img.shields.io/badge/Built%20with-Sprites-10151C?style=flat&logo=linux&logoColor=white)](https://sprites.dev)
[![Zero-Secret Connectors](https://img.shields.io/badge/Connectors-Zero--Secret-0F6B46?style=flat)](https://blastbox-3xb.sprites.app/health)
[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-6D28D9?style=flat)](https://blastbox-3xb.sprites.app)

**Zero-secret, two-Sprite detonation agent for untrusted GitHub pull requests, stdio MCP servers, and agent `SKILL.md` files.**  
Blastbox catches supply-chain payloads whose tests pass or return `isError: false` while quietly probing SSH keys, dropping persistence files, attempting exfiltration, or embedding prompt injections — then rewinds the detonator Sprite back to clean steel.

Live Audit Console: [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app)

![Blastbox Live Hacksgiving Audit Dashboard](docs/dashboard.png)

---

## How It Works

Running untrusted code in the same VM that holds Sprites Connectors would let malicious code call allowed Connector routes even with zero raw tokens. Blastbox isolates control from detonation across two Firecracker Sprites:

```text
  GitHub PR  ·  Stdio MCP Server  ·  Agent SKILL.md (GitHub / Slack @blastbox boom / CLI)
           │
           ▼
┌───────────────────────────────┐        sprite exec / restore         ┌────────────────────────────────────┐
│  Controller Sprite: blastbox  │ ────────────────────────────────────▶│  Detonator: blastbox-detonator     │
│  • GitHub + OpenRouter + Slack│                                      │  • ZERO raw tokens or labels       │
│  • SSRF-guarded HTTPS fetcher │        pulls strace + fs_diff        │  • Egress policy: * -> deny        │
│  • LLM planner & PR/Slack bot │ ◀────────────────────────────────────│  • strace -f + pre/post FS diff    │
│  • Public :8080 web console   │   never executes untrusted targets   │  • Restored via `sprite restore`   │
└───────────────────────────────┘                                      └────────────────────────────────────┘
```

- **Air-gapped detonation (`blastbox-detonator`):** Holds zero raw tokens, zero labels (all Connectors denied), and an outbound `* -> deny` egress policy enforced outside the VM.
- **Autonomous PR + Slack `@blastbox boom` agent (`controller_agent.py`):** Polls GitHub PRs and Slack `#blastbox` via zero-secret Connectors, asks OpenRouter (`agent_planner.py`) what tools/stages/blocks to target, detonates under `strace -f`, and posts forensic verdicts back to GitHub and Slack threads.
- **Generic FS diff + checkpoint rewind:** Hashes `/home/sprite` and `/tmp` before detonation, after detonation, and after `sprite restore` — catching arbitrary persistence files and verifying `0` left post-rewind.

---

## Live-Verified Runs

Six canonical runs (`3 BLOCK`, `3 PASS`, across PRs, MCP servers, and Slack-triggered `SKILL.md` files) persisted on [`https://blastbox-3xb.sprites.app`](https://blastbox-3xb.sprites.app):

| Scenario | Verdict | Score | Planned Targets | Generic FS Diff -> Post-Restore | Runtime | Artifact |
|---|---|---:|---|---|---:|---|
| **Poisoned `SKILL.md`** (`fixtures/poisoned-skill`) | **`BLOCK`** | `100/100` | `block_0.bash` | `2` created (`~/.config/skill-telemetry/agent.dat`, `/tmp/.skill_preflight_cache`) -> `0` left | `162.22s` | Slack `@blastbox boom`, restored `v24` |
| **Clean `SKILL.md`** (`fixtures/clean-skill`) | **`PASS`** | `0/100` | `block_0.python` | `0` created (`151` syscalls traced cleanly) -> `0` left | `253.99s` | Restored `v22` |
| **Poisoned PR** (`demo/poisoned-slugify-pr`) | **`BLOCK`** | `100/100` | `pip_install`, `import_check`, `unittest` | `2` created (`~/.config/slugify-cache/session.dat`, `/tmp/.slugify_build_cache`) -> `0` left | `40.37s` | [PR #1 Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/1#issuecomment-7157400949), `v17` |
| **Clean PR** (`feat/slugify-lite-clean`) | **`PASS`** | `0/100` | `pip_install`, `import_check`, `pytest` | `0` created (`3,494` syscalls traced cleanly) -> `0` left | `42.53s` | [PR #8 Comment](https://github.com/JamesRamone/hacksgiving-blastbox-demo/pull/8#issuecomment-7157386908), `v15` |
| **Poisoned 2-Tool MCP** (`fixtures/poisoned-mcp`) | **`BLOCK`** | `100/100` | `health_check`, `format_release_note` | `2` created (`~/.local/share/notes-mcp/state.bin`, `/tmp/.notes_mcp_cache`) -> `0` left | `27.47s` | [Issue #9](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/9), `v10` |
| **Clean 2-Tool MCP** (`fixtures/clean-mcp`) | **`PASS`** | `0/100` | `health_check`, `format_release_note` | `0` created (`181` syscalls traced cleanly) -> `0` left | `24.63s` | [Issue #10](https://github.com/JamesRamone/hacksgiving-blastbox-demo/issues/10), `v12` |

---

## Slack `#blastbox` & CLI Demos

Trigger isolated detonations from Slack (`#blastbox` via Sprites `slack_bot` Connector):

```text
@blastbox boom poisoned-skill
@blastbox boom clean-skill
@blastbox boom poisoned-mcp
@blastbox boom https://raw.githubusercontent.com/<owner>/<repo>/main/SKILL.md
@blastbox boom https://github.com/<owner>/<repo>/pull/<number>
```

Remote HTTPS URLs pass controller-side SSRF validation (`http://`, loopback, RFC1918, `169.254.169.254`, and `api.sprites.dev` blocked) before staging into `blastbox-detonator`.

Run any demo or custom target from the CLI:

```bash
./demo.sh --all         # Run all 6 scenarios (PR, MCP, SKILL.md)
./demo.sh --skill       # Poisoned SKILL.md -> BLOCK (100/100)
./demo.sh --clean-skill # Clean SKILL.md    -> PASS  (0/100)
python3 blastbox.py https://example.com/SKILL.md --mode skill
```

---

## Self-Host in 3 Steps

All Sprite names, Connector IDs, Slack channels, and repos are configurable via [`.env.example`](.env.example).

1. **Create 3 Sprites Connectors** scoped to `--label hacksgiving`:
   - **GitHub:** allow `/user` and `/repos/<owner>/<repo>*`; deny `/user/repos*`, `/user/keys*`, `/repos/*/admin/*`, `/repos/*/hooks*`.
   - **OpenRouter:** allow `/v1/chat/completions`, `/v1/models`; deny `/v1/keys*`.
   - **Slack Bot (`slack_bot`):** allow `auth.test`, `conversations.history`, `chat.postMessage`, `reactions.add` with the bot invited to your channel.
2. **Configure & provision both Sprites:**
   ```bash
   cp .env.example .env
   python3 init_detonator.py   # Unlabeled deny-all egress detonator Sprite
   python3 init_controller.py  # Public :8080 web dashboard + PR/Slack controller agent
   ```
3. **Authenticate the `sprite` CLI once inside the controller** (`sprite console -s blastbox` -> `sprite login && sprite-env services restart blastbox-agent`).

---

## Known Limitations

- **Ptrace visibility & timeout evasion:** Uses `strace -f` (`execve*`, `open*`/`creat`, `connect`/`send*`, `unlink*`/`rename*`/`link*`/`symlink*`/`chmod*`) rather than kernel eBPF; timeout (`20s`) yields at least `REVIEW` so sleeping cannot return `PASS`.
- **Ecosystem scope:** Covers Python PR packages (`pip` + `unittest`/`pytest`), Python stdio MCP servers, and Python/Bash fenced `SKILL.md` blocks.
- **`/tmp` on `/dev/vdb`:** `/tmp` sits outside the checkpointed root overlay, so Blastbox captures a generic `/tmp` before/after diff and sweeps newly created `/tmp` paths post-restore.
