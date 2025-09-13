#!/bin/bash

# Start Cryptic server with WebSocket mTLS using environment variables

cd "$(dirname "$0")/.."

# Set default certificate paths if not already set
export CRYPTIC_SERVER_CERT="${CRYPTIC_SERVER_CERT:-CA/certs/server.crt}"
export CRYPTIC_SERVER_KEY="${CRYPTIC_SERVER_KEY:-CA/private/server.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-CA/certs/ca.crt}"

echo "🔧 Cryptic Server Configuration:"
echo "  Server Cert: $CRYPTIC_SERVER_CERT"
echo "  Server Key:  $CRYPTIC_SERVER_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"

# Enable file logging by default (can be overridden)
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_file_logger}"
echo "  Event Handlers: $CRYPTIC_EVENT_HANDLERS"
echo ""

echo "🚀 Starting Cryptic application with WebSocket mTLS..."
erl -pa _build/default/lib/*/ebin -eval "
application:ensure_all_started(cryptic),
timer:sleep(1000),
inet:i(),
io:format(\"~n✅ Server running!~n\"),
io:format(\"   WebSocket mTLS:   wss://localhost:8443/ws~n\"),
io:format(\"   Press Ctrl+C to stop~n~n\"),
timer:sleep(infinity).
"
