#!/usr/bin/env bash
# Start the local SOAR stack (API + remediation worker + dashboard) in the background.
# Usage: ./start-local.sh [--no-worker] [--check-only] [--free-ports]
set -euo pipefail

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
DASHBOARD_PORT="${DASHBOARD_PORT:-5173}"
TIMEOUT_SEC="${STARTUP_TIMEOUT_SEC:-45}"
NO_WORKER=0 CHECK_ONLY=0 FREE_PORTS=0
for arg in "$@"; do
  case "$arg" in
    --no-worker) NO_WORKER=1 ;;
    --check-only) CHECK_ONLY=1 ;;
    --free-ports) FREE_PORTS=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PID_DIR="$ROOT/output/run"
LOG_DIR="$ROOT/output/logs"
mkdir -p "$PID_DIR" "$LOG_DIR"

[ -f .env.local ] || { echo "Missing .env.local (try: cp .env.example .env.local, then set SOAR_AUTH_TOKENS_JSON)" >&2; exit 1; }
command -v npm >/dev/null || { echo "npm not found in PATH" >&2; exit 1; }
if [ -x .venv/bin/python3 ]; then PY="$ROOT/.venv/bin/python3"; else PY="$(command -v python3)"; fi

port_pids() { # PIDs listening on TCP port $1
  if command -v lsof >/dev/null; then lsof -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true
  else ss -ltnpH "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 || true; fi
}
for port in "$BACKEND_PORT" "$DASHBOARD_PORT"; do
  pids="$(port_pids "$port")"
  [ -z "$pids" ] && continue
  if [ "$FREE_PORTS" -eq 1 ]; then kill $pids; sleep 1
  else echo "Port $port already in use (PID $pids). Free it or pass --free-ports." >&2; exit 1; fi
done

export SOAR_POLICY_EXECUTION_MODE=queued
export SOAR_APPROVAL_REQUIRED_ACTIONS=isolate_host,kill_process,block_ip
export SOAR_DB_TARGET="$ROOT/output/soar-local.db"

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "python: $PY"; echo "db:     $SOAR_DB_TARGET"; echo "CheckOnly: nothing started."; exit 0
fi

start() { # name, command...
  local name="$1"; shift
  setsid nohup "$@" >"$LOG_DIR/$name.log" 2>&1 &
  echo $! >"$PID_DIR/$name.pid"
}
wait_http() { # url; ready = any HTTP response (401 still proves the proxy chain works)
  for _ in $(seq "$TIMEOUT_SEC"); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$1")" != 000 ] && return 0; sleep 1
  done
  return 1
}

start backend "$PY" -m uvicorn api.app:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload
wait_http "http://$BACKEND_HOST:$BACKEND_PORT/health" || { echo "Backend not ready; see $LOG_DIR/backend.log" >&2; exit 1; }
[ "$NO_WORKER" -eq 1 ] || start worker "$PY" scripts/run_remediation_worker.py
start dashboard npm --prefix dashboard run dev
wait_http "http://localhost:$DASHBOARD_PORT/soar-api/api/v1/dashboard/bootstrap" || { echo "Dashboard proxy not ready; see $LOG_DIR/dashboard.log" >&2; exit 1; }

echo "Local stack is up. Dashboard: http://localhost:$DASHBOARD_PORT  Backend: http://$BACKEND_HOST:$BACKEND_PORT/health"
echo "Logs: $LOG_DIR   Stop with ./stop-local.sh"
