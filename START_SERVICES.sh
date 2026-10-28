#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill any existing processes on ports 8765 and 3000
echo "Cleaning up existing processes..."
pids_8765="$(lsof -ti:8765 || true)"
if [ -n "$pids_8765" ]; then
  kill -9 $pids_8765 2>/dev/null || true
fi

pids_3000="$(lsof -ti:3000 || true)"
if [ -n "$pids_3000" ]; then
  kill -9 $pids_3000 2>/dev/null || true
fi
sleep 2

# Start backend
echo "Starting backend on port 8765..."
cd "$ROOT_DIR"
if [ -x "$ROOT_DIR/.venv/bin/python3" ]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python3"
elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  echo "Error: no Python executable found in $ROOT_DIR/.venv/bin"
  exit 1
fi

nohup env UVICORN_RELOAD=false "$PYTHON_BIN" -m webapp > backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend started (PID: $BACKEND_PID)"

# Wait for backend to be ready
sleep 5

# Start frontend
echo "Starting frontend on port 3000..."
cd "$ROOT_DIR/frontend"
nohup npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "URL Audit Kit is running"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Frontend:  http://localhost:3000"
echo "Backend:   http://localhost:8765"
echo "API Docs:  http://localhost:8765/docs"
echo ""
echo "Logs:"
echo "  Backend:  tail -f backend.log"
echo "  Frontend: tail -f frontend.log"
echo ""
echo "To stop: ./STOP_SERVICES.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
