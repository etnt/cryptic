#!/bin/bash

# Stop Cryptic server running in daemon mode
#
# Usage: stop-server.sh

# Get absolute path to project root (parent directory of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PID_FILE="$PROJECT_ROOT/logs/server.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "Error: No PID file found at $PID_FILE"
    echo "The server may not be running in daemon mode."
    exit 1
fi

PID=$(cat "$PID_FILE")

echo "Stopping Cryptic server (PID: $PID)..."

# Check if process is running
if ps -p "$PID" > /dev/null 2>&1; then
    # Try graceful shutdown first
    kill "$PID"
    
    # Wait up to 10 seconds for graceful shutdown
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            echo "Server stopped successfully."
            rm "$PID_FILE"
            exit 0
        fi
        sleep 1
    done
    
    # Force kill if still running
    echo "Graceful shutdown timed out, forcing termination..."
    kill -9 "$PID"
    sleep 1
    
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "Server forcefully terminated."
        rm "$PID_FILE"
        exit 0
    else
        echo "Error: Failed to stop server process."
        exit 1
    fi
else
    echo "Warning: Process $PID is not running."
    echo "Removing stale PID file."
    rm "$PID_FILE"
    exit 0
fi
