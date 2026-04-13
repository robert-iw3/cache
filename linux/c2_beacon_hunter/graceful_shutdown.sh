#!/bin/bash
# graceful_shutdown.sh - Safely terminates c2_beacon_hunter (v2.7)

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== c2_beacon_hunter v2.7 Graceful Shutdown ==="

# 1. Container mode (Docker or Podman)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "c2-beacon-hunter"; then
    echo "Stopping Docker container..."
    docker stop -t 30 c2-beacon-hunter || true
    echo "Container stopped gracefully."
    exit 0
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q "c2-beacon-hunter"; then
    echo "Stopping Podman container..."
    podman stop -t 30 c2-beacon-hunter || true
    echo "Container stopped gracefully."
    exit 0
fi

# 2. Systemd service
if systemctl is-active --quiet c2_beacon_hunter.service; then
    echo "Stopping systemd service (SIGTERM sent)..."
    sudo systemctl stop c2_beacon_hunter.service
    echo "Service stopped gracefully. Final export completed."
    exit 0
fi

# 3. Standalone Python process
PID=$(pgrep -f "c2_beacon_hunter.py" | head -n 1)
if [ -n "$PID" ]; then
    echo "Found standalone process (PID $PID). Sending SIGTERM..."
    kill -TERM "$PID" 2>/dev/null || true
    echo "Waiting up to 30 seconds for clean shutdown..."
    for i in {1..30}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            echo "Process terminated gracefully. Final export completed."
            exit 0
        fi
        sleep 1
    done
    echo "Process did not terminate gracefully, forcing kill..."
    kill -9 "$PID" 2>/dev/null || true
    exit 0
fi

echo "No c2_beacon_hunter instance found running."