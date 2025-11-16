#!/usr/bin/env bash
if [ -z "${BASH_VERSION-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -euo pipefail

# start.sh - start wMailServer in background for debugging
# Does NOT write PID files; finds processes by name using pgrep or ps|grep

# Resolve script dir (scripts/) and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOGFILE="$WORKDIR/logs/output.log"

echo "Starting wMailServer (debug mode). Logs -> $LOGFILE"
nohup python3 "$WORKDIR/wMailServer.py" >> "$LOGFILE" 2>&1 &

# wait a moment for the process to start
sleep 0.5

# Try pgrep first, fallback to ps|grep if not available
if command -v pgrep >/dev/null 2>&1; then
  pids=$(pgrep -f "wMailServer.py" | tr '\n' ' ')
else
  pids=$(ps aux | grep "[w]MailServer.py" | awk '{print $2}' | tr '\n' ' ')
fi

if [ -z "$pids" ]; then
  echo "Failed to detect wMailServer process after start. Check $LOGFILE for errors."
  exit 1
fi

echo "Started wMailServer, PIDs: $pids"
echo "Follow logs with: tail -f $LOGFILE"

exit 0
