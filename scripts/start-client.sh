#!/bin/bash

# Start Cryptic WebSockeecho "🚀 Starting Cryptic WebSocket mTLS Client UI..."
echo "   Username: $USERNAME"
echo "   Server: ${SERVER:-localhost}"
echo ""
erl -pa _build/default/lib/*/ebin -noshell -eval "cryptic_ws_ui:start("$USERNAME", "${SERVER:-localhost}")."ent using environment variables

cd "$(dirname "$0")/.."

# Default username
USERNAME="${1:-alice}"

# Set default certificate paths if not already set
export CRYPTIC_CLIENT_CERT="${CRYPTIC_CLIENT_CERT:-CA/client_keys/${USERNAME}.crt}"
export CRYPTIC_CLIENT_KEY="${CRYPTIC_CLIENT_KEY:-CA/client_keys/${USERNAME}.key}"
export CRYPTIC_CA_CERT="${CRYPTIC_CA_CERT:-CA/certs/ca.crt}"

echo "🔧 Cryptic Client Configuration for user: $USERNAME"
echo "  Client Cert: $CRYPTIC_CLIENT_CERT"
echo "  Client Key:  $CRYPTIC_CLIENT_KEY"
echo "  CA Cert:     $CRYPTIC_CA_CERT"

# Enable file logging by default for client (can be overridden)
export CRYPTIC_EVENT_HANDLERS="${CRYPTIC_EVENT_HANDLERS:-cryptic_file_logger}"
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

echo "🔌 Starting Cryptic WebSocket UI..."
erl -pa _build/default/lib/*/ebin -eval "
cryptic_ws_ui:start(\"$USERNAME\", \"localhost\").
" -noinput
