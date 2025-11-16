#!/usr/bin/env bash
if [ -z "${BASH_VERSION-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -euo pipefail

# stop.sh - stop wMailServer started by start.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Find pids for wMailServer.py
if command -v pgrep >/dev/null 2>&1; then
  pids=$(pgrep -f "wMailServer.py" | tr '\n' ' ')
else
  pids=$(ps aux | grep "[w]MailServer.py" | awk '{print $2}' | tr '\n' ' ')
fi

if [ -z "$pids" ]; then
  echo "No wMailServer process found."
  exit 0
fi

echo "Stopping wMailServer PIDs: $pids"
for pid in $pids; do
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    for i in {1..10}; do
      if kill -0 "$pid" 2>/dev/null; then
        sleep 1
      else
        break
      fi
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "PID $pid did not exit, sending SIGKILL"
      kill -9 "$pid" || true
    else
      echo "PID $pid stopped"
    fi
  else
    echo "PID $pid not running"
  fi
done

echo "All done."

exit 0
