#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER_SPRITE="${BLASTBOX_CONTROLLER_SPRITE:-${BLASTBOX_SPRITE:-blastbox}}"
DETONATOR_SPRITE="${BLASTBOX_DETONATOR_SPRITE:-blastbox-detonator}"
REPO="${BLASTBOX_REPO:-JamesRamone/hacksgiving-blastbox-demo}"
PUBLIC_URL="${BLASTBOX_PUBLIC_URL:-https://blastbox-3xb.sprites.app}"

usage() {
  cat <<'EOF'
Usage: ./demo.sh [OPTION]

Options:
  (default), --pr   Seed & detonate poisoned GitHub PR -> BLOCK (100/100)
  --clean-pr        Seed & detonate benign GitHub PR -> PASS (0/100)
  --mcp             Detonate poisoned 2-tool stdio MCP server -> BLOCK (100/100)
  --clean-mcp       Detonate clean 2-tool stdio MCP server -> PASS (0/100)
  --skill           Detonate poisoned SKILL.md (hidden directives + shell block) -> BLOCK (100/100)
  --clean-skill     Detonate clean SKILL.md -> PASS (0/100)
  --all             Run all 6 scenarios sequentially
  -h, --help        Show this help message and exit

Environment overrides:
  BLASTBOX_CONTROLLER_SPRITE  Controller Sprite name (default: blastbox)
  BLASTBOX_DETONATOR_SPRITE   Air-gapped Detonator Sprite name (default: blastbox-detonator)
  BLASTBOX_REPO               Target GitHub owner/repo (default: JamesRamone/hacksgiving-blastbox-demo)
  BLASTBOX_PUBLIC_URL         Public dashboard URL (default: https://blastbox-3xb.sprites.app)
EOF
}

MODE="pr"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pr) MODE="pr"; shift ;;
    --clean-pr) MODE="clean-pr"; shift ;;
    --mcp) MODE="mcp"; shift ;;
    --clean-mcp) MODE="clean-mcp"; shift ;;
    --skill) MODE="skill"; shift ;;
    --clean-skill) MODE="clean-skill"; shift ;;
    --all) MODE="all"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[demo] Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

now_epoch() {
  python3 -c 'import time; print(f"{time.monotonic():.3f}")'
}

print_summary() {
  local elapsed_s="$1"
  python3 - "${SCRIPT_DIR}/last_run/summary.json" "${PUBLIC_URL}" "${elapsed_s}" <<'PY'
import json, sys
from pathlib import Path

s = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
public_url = sys.argv[2]
elapsed = sys.argv[3]
counts = s["ioc_counts"]
target = s["target"]
plan = s.get("agent_plan") or {}
gh_pub = s.get("github_publish") or {}

print("----------------------------------------------------------------")
if s.get("mode") == "pr":
    print(f"Target (PR):                {target.get('pr_url')}")
else:
    print(f"Target ({s.get('mode', 'local').upper()}):               {target.get('target_label')}")
print(f"Sprites (Ctrl -> Det):      {s.get('controller_sprite')} -> {s.get('detonator_sprite')} (unlabeled, * -> deny egress)")
if gh_pub.get("html_url"):
    print(f"GitHub Report URL:          {gh_pub.get('html_url')} (HTTP {gh_pub.get('http_status')})")
else:
    print(f"GitHub Report URL:          {gh_pub.get('kind', 'skipped')}")
print(f"Baseline Checkpoint:        {s['checkpoint_restored']} (generic FS diff rollback verified: {s['rollback_verified']})")
print(f"Deterministic Verdict:      {s['deterministic_verdict']} (risk_score={s['deterministic_risk_score']}/100)")
print(f"Agent Probe Plan:           {plan.get('targets')} via {plan.get('planner_source')}")
print(f"AI Triage Verdict:          {s['llm_recommended_verdict']} via {s['openrouter_model']}")
print(f"Prompt-Injection Resisted:  {s['prompt_injection_resisted']} (detected={s.get('prompt_injection_detected')})")
print(f"Zero-Secret VM Proof:       {s['zero_secrets_verified']}")
print(f"Connector 403 Policy Proof: HTTP {s['policy_403_status']} (blocked={s['policy_403_verified']})")
print(
    f"IOC Counts:                 sensitive_files={counts['sensitive_file_probes']}, "
    f"unexpected_writes={counts['unexpected_writes']}, net_connects={counts['network_connects']}, "
    f"dns_queries={counts['dns_queries']}, subprocesses={counts['notable_subprocesses']}, "
    f"gateway_blocks={counts['connector_policy_denials']}, prompt_pi={counts['prompt_injection_signals']}, "
    f"mcp_poison={counts.get('mcp_tool_poisoning', 0)}"
)
dash = s.get("dashboard") or {}
print(f"Public Dashboard:           {public_url} (HTTP {dash.get('html_status', 'n/a')}, total_runs={dash.get('runs_total', 'n/a')})")
print(f"Demo Wall Time:             {elapsed}s")
print("----------------------------------------------------------------")
PY
}

run_pr_demo() {
  local clean_flag="$1"
  local label="$2"
  local start_t end_t elapsed
  start_t="$(now_epoch)"
  echo "================================================================"
  echo "  BLASTBOX — ${label}"
  echo "  Controller: ${CONTROLLER_SPRITE} -> Detonator: ${DETONATOR_SPRITE}"
  echo "  Repo: ${REPO} | Dashboard: ${PUBLIC_URL}"
  echo "================================================================"
  echo ""

  local seed_args=("--sprite" "${CONTROLLER_SPRITE}" "--repo" "${REPO}")
  if [[ "${clean_flag}" == "1" ]]; then
    seed_args+=("--clean")
  fi

  echo "[demo] Step 1/2: Seeding (or reusing) PR via zero-secret GitHub Connector..."
  SEED_JSON="$(python3 "${SCRIPT_DIR}/seed_pr.py" "${seed_args[@]}")"
  PR_URL="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pr_url"])' "${SEED_JSON}")"
  PR_NUM="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pr_number"])' "${SEED_JSON}")"
  echo "[demo] PR ready: ${PR_URL} (#${PR_NUM})"
  echo ""

  echo "[demo] Step 2/2: Running air-gapped two-Sprite PR detonation & dashboard sync..."
  python3 "${SCRIPT_DIR}/blastbox.py" "${PR_URL}" --mode pr \
    --controller-sprite "${CONTROLLER_SPRITE}" \
    --detonator-sprite "${DETONATOR_SPRITE}" \
    --repo "${REPO}"
  end_t="$(now_epoch)"
  elapsed="$(python3 -c "print(f'{float(${end_t}) - float(${start_t}):.2f}')")"
  print_summary "${elapsed}"
}

run_dir_demo() {
  local fixture_rel="$1"
  local mode_arg="$2"
  local label="$3"
  local extra_flag="${4:-}"
  local start_t end_t elapsed
  local target_dir="${SCRIPT_DIR}/${fixture_rel}"
  start_t="$(now_epoch)"
  echo "================================================================"
  echo "  BLASTBOX — ${label}"
  echo "  Controller: ${CONTROLLER_SPRITE} -> Detonator: ${DETONATOR_SPRITE}"
  echo "  Target: ${fixture_rel} | Dashboard: ${PUBLIC_URL}"
  echo "================================================================"
  echo ""

  local args=("${target_dir}" "--mode" "${mode_arg}" "--controller-sprite" "${CONTROLLER_SPRITE}" "--detonator-sprite" "${DETONATOR_SPRITE}" "--repo" "${REPO}")
  if [[ -n "${extra_flag}" ]]; then
    args+=("${extra_flag}")
  fi

  python3 "${SCRIPT_DIR}/blastbox.py" "${args[@]}"
  end_t="$(now_epoch)"
  elapsed="$(python3 -c "print(f'{float(${end_t}) - float(${start_t}):.2f}')")"
  print_summary "${elapsed}"
}

case "${MODE}" in
  pr) run_pr_demo "0" "Poisoned PR Detonation Demo (BLOCK)" ;;
  clean-pr) run_pr_demo "1" "Clean Benign PR Detonation Demo (PASS)" ;;
  mcp) run_dir_demo "fixtures/poisoned-mcp" "mcp" "Poisoned 2-Tool MCP Server Demo (BLOCK)" ;;
  clean-mcp) run_dir_demo "fixtures/clean-mcp" "mcp" "Clean 2-Tool MCP Server Demo (PASS)" ;;
  skill) run_dir_demo "fixtures/poisoned-skill" "skill" "Poisoned SKILL.md Detonation Demo (BLOCK)" "--no-post" ;;
  clean-skill) run_dir_demo "fixtures/clean-skill" "skill" "Clean SKILL.md Detonation Demo (PASS)" "--no-post" ;;
  all)
    TOTAL_START="$(now_epoch)"
    run_pr_demo "0" "1/6 Poisoned PR Detonation (BLOCK)"
    echo ""
    run_pr_demo "1" "2/6 Clean Benign PR Detonation (PASS)"
    echo ""
    run_dir_demo "fixtures/poisoned-mcp" "mcp" "3/6 Poisoned 2-Tool MCP Detonation (BLOCK)"
    echo ""
    run_dir_demo "fixtures/clean-mcp" "mcp" "4/6 Clean 2-Tool MCP Detonation (PASS)"
    echo ""
    run_dir_demo "fixtures/poisoned-skill" "skill" "5/6 Poisoned SKILL.md Detonation (BLOCK)" "--no-post"
    echo ""
    run_dir_demo "fixtures/clean-skill" "skill" "6/6 Clean SKILL.md Detonation (PASS)" "--no-post"
    TOTAL_END="$(now_epoch)"
    TOTAL_ELAPSED="$(python3 -c "print(f'{float(${TOTAL_END}) - float(${TOTAL_START}):.2f}')")"
    echo ""
    echo "[demo] Combined (--all, 6 runs) total elapsed wall time: ${TOTAL_ELAPSED}s"
    ;;
esac
