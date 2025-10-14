#!/bin/bash

# Start Cryptic server with WebSocket mTLS using environment variables
#
# Usage: start-server.sh [HOST] [PORT]
#   HOST: Server host/IP (default: localhost)
#   PORT: Server port (default: 8443)
#
# Example:
#   ./start-server.sh                    # localhost:8443
#   ./start-server.sh 0.0.0.0 9000       # Listen on all interfaces, port 9000

# Get absolute path to project root (parent directory of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse command-line arguments
SERVER_HOST="${1:-localhost}"
SERVER_PORT="${2:-8443}"

# Set default certificate paths if not already set (use absolute paths)
export CRYPTIC_SERVER_CERT="${CRYPTIC_SERVER_CERT:-$PROJECT_ROOT/CA/certs/server.crt}"
export CRYPTIC_SERVER_KEY="${CRYPTIC_SERVER_KEY:-$PROJECT_ROOT/CA/private/server.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-$PROJECT_ROOT/CA/certs/ca.crt}"

# Set server host and port via environment variables
export CRYPTIC_SERVER_HOST="${CRYPTIC_SERVER_HOST:-$SERVER_HOST}"
export CRYPTIC_SERVER_PORT="${CRYPTIC_SERVER_PORT:-$SERVER_PORT}"

echo "Cryptic Server Configuration:"
echo "  Server Host: $CRYPTIC_SERVER_HOST"
echo "  Server Port: $CRYPTIC_SERVER_PORT"
echo "  Server Cert: $CRYPTIC_SERVER_CERT"
echo "  Server Key:  $CRYPTIC_SERVER_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"

# Enable file logging by default (can be overridden)
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_file_logger}"
echo "  Event Handlers: $CRYPTIC_EVENT_HANDLERS"
echo ""

echo "Starting Cryptic application with WebSocket mTLS..."
# Use absolute paths - no need to change directory
# FIXME a better way to start the server !!
erl -sname server@localhost -pa $PROJECT_ROOT/_build/default/lib/*/ebin -eval "
application:ensure_all_started(cryptic),
timer:sleep(1000),
inet:i(),
io:format(\"~nServer running!~n\"),
io:format(\"   WebSocket mTLS:   wss://$CRYPTIC_SERVER_HOST:$CRYPTIC_SERVER_PORT/ws~n\"),
io:format(\"   Press Ctrl+C to stop~n~n\"),
timer:sleep(infinity).
"
