#!/bin/sh
#
# Docker Admin Bootstrap Script
#
# This script is designed to run INSIDE the cryptic server container to
# bootstrap the first admin user. It:
#   1. Creates a GPG key for the admin user (if not exists)
#   2. Exports the public key to the bootstrap directory
#   3. Reloads the bootstrap registrations into the running server
#
# Usage (from host):
#   docker exec -it cryptic-server bootstrap-admin <username>
#
# Example:
#   docker exec -it cryptic-server bootstrap-admin alice
#

set -e

# Simple output functions (no colors for maximum compatibility)
info() { printf "ℹ %s\n" "$1"; }
success() { printf "✓ %s\n" "$1"; }
warn() { printf "⚠ %s\n" "$1"; }
error() { printf "✗ %s\n" "$1"; }

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <admin-username>"
    echo ""
    echo "Bootstrap the first admin user for the Cryptic server."
    echo "This creates a GPG key and registers it so the user can"
    echo "request a TLS certificate via the onboarding process."
    echo ""
    echo "Example:"
    echo "  $0 alice"
    exit 1
fi

USERNAME="$1"
GPG_EMAIL="${USERNAME}@cryptic.local"

# Determine bootstrap directory
# In the release, it's under the priv directory
if [ -d "/opt/cryptic/lib" ]; then
    # Find the cryptic priv directory in the release
    PRIV_DIR=$(find /opt/cryptic/lib -type d -name "priv" -path "*/cryptic-*/priv" 2>/dev/null | head -1)
    if [ -z "$PRIV_DIR" ]; then
        PRIV_DIR="/opt/cryptic/priv"
    fi
else
    PRIV_DIR="/opt/cryptic/priv"
fi

BOOTSTRAP_DIR="$PRIV_DIR/ca/bootstrap"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Cryptic Server - Admin Bootstrap                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
info "Username: $USERNAME"
info "GPG Email: $GPG_EMAIL"
info "Bootstrap Dir: $BOOTSTRAP_DIR"
echo ""

# Ensure GPG directory exists with correct permissions
GNUPGHOME="${GNUPGHOME:-/home/cryptic/.gnupg}"
export GNUPGHOME
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# Check if GPG key already exists
if gpg --list-keys "$GPG_EMAIL" > /dev/null 2>&1; then
    warn "GPG key for $GPG_EMAIL already exists"
    FINGERPRINT=$(gpg --list-keys --keyid-format LONG "$GPG_EMAIL" 2>/dev/null | grep -A1 "^pub" | tail -1 | awk '{print $1}')
    info "Fingerprint: $FINGERPRINT"
else
    info "Creating GPG key for $GPG_EMAIL..."
    
    # Create GPG key config file (no passphrase for server-side key)
    GPG_CONF=$(mktemp)
    cat > "$GPG_CONF" << GPGEOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: $USERNAME
Name-Email: $GPG_EMAIL
Expire-Date: 0
%commit
GPGEOF

    # Generate the key
    if gpg --batch --gen-key "$GPG_CONF"; then
        rm -f "$GPG_CONF"
        success "GPG key created successfully!"
        FINGERPRINT=$(gpg --list-keys --keyid-format LONG "$GPG_EMAIL" 2>/dev/null | grep -A1 "^pub" | tail -1 | awk '{print $1}')
        info "Fingerprint: $FINGERPRINT"
    else
        rm -f "$GPG_CONF"
        error "Failed to create GPG key"
        exit 1
    fi
fi

echo ""

# Create bootstrap directory
info "Setting up bootstrap directory..."
mkdir -p "$BOOTSTRAP_DIR"

# Export GPG public key
OUTPUT_FILE="$BOOTSTRAP_DIR/${USERNAME}.gpg"
info "Exporting public key to: $OUTPUT_FILE"

gpg --armor --export "$GPG_EMAIL" > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    error "Failed to export GPG public key"
    rm -f "$OUTPUT_FILE"
    exit 1
fi

success "Public key exported!"
echo ""

# Try to reload bootstrap registrations in the running server
info "Reloading bootstrap registrations in server..."

# Use erl_call to execute Erlang code in the running node
if command -v erl_call > /dev/null 2>&1; then
    # Try to reload via erl_call
    RESULT=$(erl_call -n cryptic@localhost -a 'cryptic_ca_bootstrap reload_bootstrap []' 2>&1 || true)
    
    if echo "$RESULT" | grep -q "ok"; then
        success "Bootstrap registrations reloaded!"
    else
        warn "Could not reload automatically. The registration will be loaded on next server restart."
        info "Or run manually in the Erlang shell:"
        echo "    cryptic_ca_bootstrap:reload_bootstrap()."
    fi
else
    warn "erl_call not found. Registration will be loaded on next server restart."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Bootstrap Complete!                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
success "Admin user '$USERNAME' has been registered!"
echo ""
info "Next steps:"
echo "  1. The admin can now run the onboarding process:"
echo ""
echo "     docker run -it --rm --name cryptic-client \\"
echo "       -v ~/.cryptic:/home/cryptic/.cryptic \\"
echo "       -v ~/.gnupg:/home/cryptic/.gnupg \\"
echo "       --add-host=cryptic-server:host-gateway \\"
echo "       ghcr.io/etnt/cryptic-tui:latest sh -c 'cryptic --onboard'"
echo ""
echo "  2. During onboarding, use the same username: $USERNAME"
echo "  3. After getting their certificate, the admin can register other users"
echo ""
