#!/usr/bin/env bash
# Serve dashboard/dist statically and run the Playwright smoke tests.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PORT="${PLAYWRIGHT_PORT:-4174}"

[ -f dist/index.html ] || { echo "Missing dashboard/dist. Run 'npm run build' first." >&2; exit 1; }

node tests/static-server.cjs &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 40); do curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 0.25; done
curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" || { echo "Static server did not start on port $PORT" >&2; exit 1; }

npx playwright test --workers=1 --reporter=line
