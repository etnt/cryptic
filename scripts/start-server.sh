#!/bin/bash

# Start Cryptic server with WebSocket mTLS using environment variables

# Get absolute path to project root (parent directory of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Set default certificate paths if not already set (use absolute paths)
export CRYPTIC_SERVER_CERT="${CRYPTIC_SERVER_CERT:-$PROJECT_ROOT/CA/certs/server.crt}"
export CRYPTIC_SERVER_KEY="${CRYPTIC_SERVER_KEY:-$PROJECT_ROOT/CA/private/server.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-$PROJECT_ROOT/CA/certs/ca.crt}"

echo "Cryptic Server Configuration:"
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
io:format(\"   WebSocket mTLS:   wss://localhost:8443/ws~n\"),
io:format(\"   Press Ctrl+C to stop~n~n\"),
timer:sleep(infinity).
"
