#!/usr/bin/env bash
set -euo pipefail

export PATH="/home/sprite/.local/bin:/.sprite/bin:$PATH"
export PYTHONPATH="/home/sprite/blastbox-agent"

# A Sprite pauses ~30s after its last activity, and a polling loop does not count
# as activity. Hold a Sprites Tasks API task (5m expiry, refreshed every 60s) so the
# PR + Slack watcher keeps polling while nobody is looking. The task expires on its
# own if this script dies without cleaning up.
task_api() {
  curl -s --unix-socket /.sprite/api.sock -H "Content-Type: application/json" "$@" >/dev/null || true
}
while true; do
  task_api -X PUT http://sprite/v1/tasks/blastbox-agent -d '{"expire": "5m"}'
  sleep 60
done &
HEARTBEAT_PID=$!

/.sprite/bin/python3 /home/sprite/blastbox-agent/controller_agent.py \
  --history-file /home/sprite/blastbox-web/history.json \
  --status-file /home/sprite/blastbox-web/agent_status.json \
  --state-file /home/sprite/blastbox-agent/agent_state.json \
  --work-dir /home/sprite/blastbox-agent &
AGENT_PID=$!

cleanup() {
  kill "$AGENT_PID" "$HEARTBEAT_PID" 2>/dev/null || true
  task_api -X DELETE http://sprite/v1/tasks/blastbox-agent
}
trap cleanup EXIT
trap 'exit 143' TERM INT
wait "$AGENT_PID"
