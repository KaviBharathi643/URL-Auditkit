#!/bin/bash

echo "Stopping URL Audit Kit services..."

# Kill backend (port 8765)
pids_8765="$(lsof -ti:8765 || true)"
if [ -n "$pids_8765" ]; then
  kill -9 $pids_8765 2>/dev/null || true
  echo "Backend stopped"
else
  echo "Backend not running"
fi

# Kill frontend (port 3000)
pids_3000="$(lsof -ti:3000 || true)"
if [ -n "$pids_3000" ]; then
  kill -9 $pids_3000 2>/dev/null || true
  echo "Frontend stopped"
else
  echo "Frontend not running"
fi

# Kill any remaining python webapp processes
pkill -f "python.*-m webapp" 2>/dev/null || true

# Kill any remaining next dev processes
pkill -f "next dev" 2>/dev/null || true

echo "All services stopped"
