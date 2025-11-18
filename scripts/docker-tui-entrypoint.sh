#!/bin/bash
#
# Docker entrypoint script for Cryptic TUI client
# Sets up environment and launches bin/cryptic --tui
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[TUI]${NC} $1"
}

success() {
    echo -e "${GREEN}[TUI]${NC} ✓ $1"
}

warn() {
    echo -e "${YELLOW}[TUI]${NC} ⚠️  $1"
}

error() {
    echo -e "${RED}[TUI]${NC} ✗ $1" >&2
    exit 1
}

# Fix permissions on mounted volumes
fix_permissions() {
    local dir="$1"
    if [ -d "$dir" ]; then
        # Get the actual owner UID
        local owner_uid=$(stat -c %u "$dir" 2>/dev/null || stat -f %u "$dir" 2>/dev/null || echo "0")
        local cryptic_uid=$(id -u cryptic)
        
        if [ "$owner_uid" != "$cryptic_uid" ]; then
            info "Fixing permissions for $dir..."
            chown -R cryptic:cryptic "$dir" 2>/dev/null || warn "Could not change ownership of $dir"
        fi
    fi
}

# Set up Erlang cookie
setup_erlang_cookie() {
    local cookie_file="/home/cryptic/.erlang.cookie"
    
    if [ -n "$ERLANG_COOKIE" ]; then
        info "Setting up Erlang cookie from environment..."
        echo -n "$ERLANG_COOKIE" > "$cookie_file"
        chmod 400 "$cookie_file" 2>/dev/null || true
        chown cryptic:cryptic "$cookie_file" 2>/dev/null || true
        success "Erlang cookie configured"
    elif [ -f "$cookie_file" ]; then
        success "Using existing Erlang cookie from $cookie_file"
        # Try to fix permissions, but ignore errors if file is read-only mounted
        chmod 400 "$cookie_file" 2>/dev/null || true
        chown cryptic:cryptic "$cookie_file" 2>/dev/null || true
    else
        warn "No Erlang cookie provided. Generating random cookie..."
        # Generate random cookie
        ERLANG_COOKIE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
        echo -n "$ERLANG_COOKIE" > "$cookie_file"
        chmod 400 "$cookie_file" 2>/dev/null || true
        chown cryptic:cryptic "$cookie_file" 2>/dev/null || true
        info "Generated cookie: $ERLANG_COOKIE"
        warn "Set ERLANG_COOKIE environment variable to match other nodes!"
    fi
}

# Verify certificate files exist
check_certificates() {
    local cert_dir="/home/cryptic/.cryptic/${CRYPTIC_USERNAME}/${CRYPTIC_SERVER_HOST}_${CRYPTIC_SERVER_PORT}/certificates"
    
    if [ ! -d "$cert_dir" ]; then
        warn "Certificate directory not found: $cert_dir"
        warn "You may need to run onboarding first:"
        warn "  docker compose run --rm cryptic-tui sh -c \"cryptic --onboard\""
        return 1
    fi
    
    if [ ! -f "$cert_dir/${CRYPTIC_USERNAME}.crt" ] || \
       [ ! -f "$cert_dir/${CRYPTIC_USERNAME}.key" ] || \
       [ ! -f "$cert_dir/ca.crt" ]; then
        warn "Missing certificate files in $cert_dir"
        warn "Required files:"
        warn "  - ${CRYPTIC_USERNAME}.crt"
        warn "  - ${CRYPTIC_USERNAME}.key"
        warn "  - ca.crt"
        warn "Run onboarding: docker compose run --rm cryptic-tui sh -c \"cryptic --onboard\""
        return 1
    fi
    
    success "Certificates found in $cert_dir"
    return 0
}

# Display connection info
show_connection_info() {
    cat <<EOF

╔═══════════════════════════════════════════════════════════════╗
║           Cryptic TUI Client Container                        ║
╚═══════════════════════════════════════════════════════════════╝

Connection Details:
  Username:        ${CRYPTIC_USERNAME}
  Server:          ${CRYPTIC_SERVER_HOST}:${CRYPTIC_SERVER_PORT}
  Node Name:       ${CRYPTIC_NODE_NAME}
  Enable DB:       ${CRYPTIC_ENABLE_DB}

Keyboard Shortcuts:
  Ctrl+Q - Quit
  Tab    - Switch tabs
  Enter  - Send message

EOF
}

# Main execution
main() {
    info "Cryptic TUI Container Starting..."
    
    # Fix permissions on mounted volumes
    fix_permissions "/home/cryptic/.cryptic"
    
    # Set up Erlang cookie
    setup_erlang_cookie
    
    # Check certificates (warn but don't fail - user might be onboarding)
    check_certificates || warn "Continuing without certificates (use --onboard to set up)..."
    
    # Show connection info
    show_connection_info
    
    # If command is cryptic-tui (default), run bin/cryptic --tui
    if [ "$1" = "cryptic-tui" ]; then
        info "Starting Cryptic TUI via bin/cryptic --tui..."
        
        # Execute as cryptic user with bin/cryptic script
        exec su-exec cryptic /opt/cryptic/bin/cryptic --tui \
            -u "${CRYPTIC_USERNAME}" \
            -s "${CRYPTIC_SERVER_HOST}" \
            -p "${CRYPTIC_SERVER_PORT}" \
            --name "${CRYPTIC_NODE_NAME}" \
            $([ "${CRYPTIC_ENABLE_DB}" = "true" ] && echo "--enable-db")
    else
        # Run custom command as cryptic user
        info "Running custom command: $@"
        exec su-exec cryptic "$@"
    fi
}

main "$@"
