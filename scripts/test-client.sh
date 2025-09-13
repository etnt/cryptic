#!/bin/bash

# Start Cryptic WebSocket client for testing (no UI)

cd "$(dirname "$0")/.."

# Default username
USERNAME="${1:-alice}"

# Set default certificate paths if not already set
export CRYPTIC_CLIENT_CERT="${CRYPTIC_CLIENT_CERT:-CA/client_keys/${USERNAME}.crt}"
export CRYPTIC_CLIENT_KEY="${CRYPTIC_CLIENT_KEY:-CA/client_keys/${USERNAME}.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-CA/certs/ca.crt}"

echo "🔧 Cryptic Client Test Configuration for user: $USERNAME"
echo "  Client Cert: $CRYPTIC_CLIENT_CERT"
echo "  Client Key:  $CRYPTIC_CLIENT_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"

# Enable console logging for testing
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_console_logger}"
echo "  Event Handlers: $CRYPTIC_EVENT_HANDLERS"
echo ""

# Check if certificate files exist
if [ ! -f "$CRYPTIC_CLIENT_CERT" ]; then
    echo "❌ Error: Client certificate not found: $CRYPTIC_CLIENT_CERT"
    echo "Available users:"
    ls CA/client_keys/*.crt 2>/dev/null | xargs -n1 basename | sed 's/.crt$//' | sed 's/^/  /'
    exit 1
fi

if [ ! -f "$CRYPTIC_CLIENT_KEY" ]; then
    echo "❌ Error: Client key not found: $CRYPTIC_CLIENT_KEY"
    exit 1
fi

echo "🧪 Starting WebSocket test client (for developers)..."
erl -pa _build/default/lib/*/ebin -eval "
%% Start the event manager for logging
{ok, _} = gen_event:start_link({local, cryptic_event_manager}),
{ok, Client} = cryptic_ws_client:start_link(\"$USERNAME\", \"localhost\"),
io:format(\"~n✅ Test client connected as: $USERNAME~n\"),
io:format(\"   Commands:~n\"),
io:format(\"     cryptic_ws_client:send_command(~p, <<\\\"Hello server!\\\">>).~n\", [Client]),
io:format(\"     cryptic_ws_client:send_command(~p, <<\\\"/help\\\">>).~n\", [Client]),
io:format(\"     cryptic_ws_client:send_command(~p, <<\\\"/users\\\">>).~n\", [Client]),
io:format(\"     cryptic_ws_client:stop(~p).~n\"),
io:format(\"~n   Press Ctrl+G then 'q' to quit~n~n\"),
timer:sleep(infinity).
"
