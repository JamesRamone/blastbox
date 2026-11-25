#!/usr/bin/env bash
set -euo pipefail

export PATH="/home/sprite/.local/bin:/.sprite/bin:$PATH"
export PYTHONPATH="/home/sprite/blastbox-agent"
exec /.sprite/bin/python3 /home/sprite/blastbox-agent/controller_agent.py \
  --history-file /home/sprite/blastbox-web/history.json \
  --status-file /home/sprite/blastbox-web/agent_status.json \
  --state-file /home/sprite/blastbox-agent/agent_state.json \
  --work-dir /home/sprite/blastbox-agent
