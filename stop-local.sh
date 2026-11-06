#!/usr/bin/env bash
# Stop the processes started by start-local.sh (including their child processes).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$ROOT/output/run"
stopped=0
for f in "$PID_DIR"/*.pid; do
  [ -e "$f" ] || continue
  pid="$(cat "$f")"
  if kill -0 "$pid" 2>/dev/null; then
    # start-local.sh uses setsid, so pid == process group id: this also reaches npm/vite/uvicorn children
    { kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null; } && echo "Stopped $(basename "$f" .pid) (PID $pid)" && stopped=1
  fi
  rm -f "$f"
done
[ "$stopped" -eq 1 ] || echo "No managed SOAR processes found."
