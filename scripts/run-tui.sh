#!/bin/bash
#
# Cryptic TUI Docker Helper Script
# Simplifies running the TUI client in Docker with proper certificate paths
#
# Usage:
#   ./run-tui.sh [username]
#   ./run-tui.sh alice    # Connect as alice
#   ./run-tui.sh bob      # Connect as bob
#

set -e

# Configuration
DEFAULT_USERNAME="alice"
SERVER_HOST="cryptic-server"  # Docker service name
SERVER_PORT="8443"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
    echo -e "${BLUE}[TUI]${NC} $1"
}

success() {
    echo -e "${GREEN}[TUI]${NC} ✓ $1"
}

warn() {
    echo -e "${YELLOW}[TUI]${NC} ⚠️  $1"
}

# Parse arguments
USERNAME="${1:-$DEFAULT_USERNAME}"

# Check if .cryptic directory exists
CRYPTIC_DIR="${HOME}/.cryptic"
if [ ! -d "$CRYPTIC_DIR" ]; then
    warn "Cryptic directory not found: $CRYPTIC_DIR"
    warn ""
    warn "This directory stores:"
    warn "  - Certificates and cryptographic keys"
    warn "  - Session states (Double Ratchet)"
    warn "  - Message database (if --enable-db)"
    warn "  - Log files"
    warn ""
    warn "Run the setup script first:"
    warn "  scripts/setup-docker-tui.sh"
    exit 1
fi

# Construct certificate path (must match Docker service name)
CERT_DIR="${CRYPTIC_DIR}/${USERNAME}/${SERVER_HOST}_${SERVER_PORT}/certificates"

# Check if certificates exist
if [ ! -d "$CERT_DIR" ]; then
    warn "Certificate directory not found: $CERT_DIR"
    warn ""
    warn "Run the setup script first:"
    warn "  scripts/setup-docker-tui.sh"
    warn ""
    warn "Or manually request certificate with correct hostname:"
    warn "  bin/cryptic-onboard request https://cryptic-server:8443"
    exit 1
fi

if [ ! -f "$CERT_DIR/${USERNAME}.crt" ] || \
   [ ! -f "$CERT_DIR/${USERNAME}.key" ]; then
    warn "Missing certificate files in $CERT_DIR"
    exit 1
fi

success "Found certificates for user '$USERNAME'"

# Check directory permissions
if [ ! -w "$CRYPTIC_DIR" ]; then
    warn "No write permission on $CRYPTIC_DIR"
    warn "The container needs to write:"
    warn "  - Session states (sessions/*.session)"
    warn "  - Identity keys (keys.encrypted)"
    warn "  - Database (cryptic_chat.db if --enable-db)"
    warn "  - Logs (logs/*.log)"
    warn ""
    warn "Fix with: chmod -R u+rwX $CRYPTIC_DIR"
    exit 1
fi

# Check if server is running
info "Checking if cryptic-server is running..."
if ! docker-compose ps cryptic-server | grep -q "Up"; then
    warn "Server is not running. Starting it now..."
    docker-compose up -d cryptic-server
    info "Waiting for server to be healthy..."
    sleep 5
fi

# Check Erlang cookie
COOKIE_FILE="${HOME}/.erlang.cookie"
if [ ! -f "$COOKIE_FILE" ]; then
    warn "Erlang cookie not found: $COOKIE_FILE"
    warn "Creating default cookie..."
    echo -n "cryptic_secret_cookie" > "$COOKIE_FILE"
    chmod 400 "$COOKIE_FILE"
fi

info "Configuration:"
echo "  Username:     $USERNAME"
echo "  Server:       ${SERVER_HOST}:${SERVER_PORT}"
echo "  Certificates: $CERT_DIR"
echo "  Cookie:       $COOKIE_FILE"
echo ""

# Run TUI using docker-compose
info "Starting Cryptic TUI..."
echo ""

TUI_USERNAME="$USERNAME" \
docker-compose run --rm cryptic-tui

