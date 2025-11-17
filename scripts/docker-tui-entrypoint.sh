#!/bin/bash
#
# Docker entrypoint script for Cryptic TUI client
# Sets up Erlang node and launches the Rust TUI
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
        if [ "$(stat -c %u "$dir" 2>/dev/null || stat -f %u "$dir")" != "$(id -u cryptic)" ]; then
            info "Fixing permissions for $dir..."
            chown -R cryptic:cryptic "$dir" 2>/dev/null || true
        fi
    fi
}

# Set up Erlang cookie
setup_erlang_cookie() {
    local cookie_file="/home/cryptic/.erlang.cookie"
    
    if [ -n "$ERLANG_COOKIE" ]; then
        info "Setting up Erlang cookie..."
        echo -n "$ERLANG_COOKIE" > "$cookie_file"
        chmod 400 "$cookie_file"
        chown cryptic:cryptic "$cookie_file"
        success "Erlang cookie configured"
    elif [ ! -f "$cookie_file" ]; then
        warn "No Erlang cookie provided. Generating random cookie..."
        # Generate random cookie
        ERLANG_COOKIE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
        echo -n "$ERLANG_COOKIE" > "$cookie_file"
        chmod 400 "$cookie_file"
        chown cryptic:cryptic "$cookie_file"
        warn "Generated cookie: $ERLANG_COOKIE"
        warn "Set ERLANG_COOKIE environment variable to match other nodes!"
    else
        success "Using existing Erlang cookie from $cookie_file"
    fi
}

# Start background Erlang node for cryptic_engine
start_erlang_node() {
    info "Starting Erlang client node: ${CRYPTIC_NODE_NAME}@$(hostname)..."
    
    # Start Erlang node in background using the release
    cd /opt/cryptic/erlang
    
    # Set node name
    export RELEASE_NODE="${CRYPTIC_NODE_NAME}@$(hostname)"
    export RELEASE_COOKIE="$ERLANG_COOKIE"
    
    # Start in background mode
    su-exec cryptic bin/cryptic daemon &
    ERLANG_PID=$!
    
    # Wait for node to start
    sleep 3
    
    if ps -p $ERLANG_PID > /dev/null 2>&1; then
        success "Erlang node started (PID: $ERLANG_PID)"
    else
        error "Failed to start Erlang node"
    fi
}

# Verify certificate files exist
check_certificates() {
    local cert_dir="/home/cryptic/.cryptic/${CRYPTIC_USERNAME}/certificates"
    
    if [ ! -d "$cert_dir" ]; then
        warn "Certificate directory not found: $cert_dir"
        warn "Mount certificates as volume: -v /path/to/certs:$cert_dir"
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
  Erlang Node:     ${CRYPTIC_NODE_NAME}@$(hostname)
  Target Node:     ${ERLANG_NODE}
  Cookie:          ${ERLANG_COOKIE:0:8}...
  Username:        ${CRYPTIC_USERNAME}

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
    
    # Start background Erlang node
    start_erlang_node
    
    # Check certificates (warn but don't fail)
    check_certificates || warn "Continuing without certificates..."
    
    # Show connection info
    show_connection_info
    
    # If command is cryptic-tui, run as cryptic user
    if [ "$1" = "cryptic-tui" ]; then
        shift
        
        # Build command arguments
        TUI_ARGS="--node ${ERLANG_NODE} --cookie ${ERLANG_COOKIE}"
        
        info "Starting Cryptic TUI..."
        info "Command: cryptic-tui $TUI_ARGS $@"
        echo ""
        
        # Execute as cryptic user with proper TTY
        exec su-exec cryptic cryptic-tui $TUI_ARGS "$@"
    else
        # Run custom command as cryptic user
        info "Running custom command: $@"
        exec su-exec cryptic "$@"
    fi
}

main "$@"
