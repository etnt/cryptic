#!/bin/sh
#
# Docker Admin Bootstrap Script
#
# This script exports an existing GPG public key to the server's bootstrap
# directory. The admin must already have a GPG key on their machine.
#
# Usage:
#   # Export your GPG key to the bootstrap directory
#   docker run -it --rm \
#     -v $(pwd)/priv/ca/bootstrap:/bootstrap:rw \
#     -v ~/.gnupg:/gnupg:ro \
#     ghcr.io/etnt/cryptic:latest sh -c 'bootstrap-admin alice'
#
# Or if you have the GPG public key file already:
#   cp alice.gpg priv/ca/bootstrap/
#

set -e

# Simple output functions
info() { printf "ℹ %s\n" "$1"; }
success() { printf "✓ %s\n" "$1"; }
warn() { printf "⚠ %s\n" "$1"; }
error() { printf "✗ %s\n" "$1"; }

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <admin-username>"
    echo ""
    echo "Export an existing GPG public key to the bootstrap directory."
    echo ""
    echo "Prerequisites:"
    echo "  - You must have a GPG key for <username>@cryptic.local"
    echo "  - Mount your ~/.gnupg as /gnupg (read-only)"
    echo "  - Mount the bootstrap dir as /bootstrap (read-write)"
    echo ""
    echo "Example:"
    echo "  docker run -it --rm \\"
    echo "    -v \$(pwd)/priv/ca/bootstrap:/bootstrap:rw \\"
    echo "    -v ~/.gnupg:/gnupg:ro \\"
    echo "    ghcr.io/etnt/cryptic:latest sh -c 'bootstrap-admin alice'"
    echo ""
    echo "Or generate a key first on your host:"
    echo "  gpg --quick-generate-key 'alice <alice@cryptic.local>' rsa4096"
    exit 1
fi

USERNAME="$1"
GPG_EMAIL="${USERNAME}@cryptic.local"

# Check for mounted directories
GNUPG_MOUNT="/gnupg"
BOOTSTRAP_MOUNT="/bootstrap"

# Also check the release priv directory as fallback
if [ -d "/opt/cryptic/lib" ]; then
    PRIV_DIR=$(find /opt/cryptic/lib -type d -name "priv" -path "*/cryptic-*/priv" 2>/dev/null | head -1)
    if [ -n "$PRIV_DIR" ] && [ -d "$PRIV_DIR/ca/bootstrap" ]; then
        BOOTSTRAP_MOUNT="$PRIV_DIR/ca/bootstrap"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Cryptic Server - Admin Bootstrap                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
info "Username: $USERNAME"
info "GPG Email: $GPG_EMAIL"
echo ""

# Check if GPG keyring is mounted
if [ ! -d "$GNUPG_MOUNT" ]; then
    error "GPG keyring not mounted at $GNUPG_MOUNT"
    echo ""
    echo "Mount your GPG keyring with: -v ~/.gnupg:/gnupg:ro"
    exit 1
fi

# Check if bootstrap directory is mounted
if [ ! -d "$BOOTSTRAP_MOUNT" ]; then
    error "Bootstrap directory not mounted at $BOOTSTRAP_MOUNT"
    echo ""
    echo "Mount the bootstrap directory with:"
    echo "  -v \$(pwd)/priv/ca/bootstrap:/bootstrap:rw"
    exit 1
fi

# Use the mounted GPG keyring (read-only copy to avoid locks)
TEMP_GNUPGHOME=$(mktemp -d)
cp -r "$GNUPG_MOUNT"/* "$TEMP_GNUPGHOME/" 2>/dev/null || true
chmod -R 700 "$TEMP_GNUPGHOME"
export GNUPGHOME="$TEMP_GNUPGHOME"

# Cleanup on exit
cleanup() {
    rm -rf "$TEMP_GNUPGHOME"
}
trap cleanup EXIT

# Check if the key exists
info "Looking for GPG key: $GPG_EMAIL"

if ! gpg --list-keys "$GPG_EMAIL" > /dev/null 2>&1; then
    error "GPG key for $GPG_EMAIL not found!"
    echo ""
    echo "Generate a key on your host machine first:"
    echo "  gpg --quick-generate-key '$USERNAME <$GPG_EMAIL>' rsa4096"
    echo ""
    echo "Or with full options:"
    echo "  gpg --full-generate-key"
    echo "  (use email: $GPG_EMAIL)"
    exit 1
fi

# Get and display fingerprint
FINGERPRINT=$(gpg --list-keys --keyid-format LONG "$GPG_EMAIL" 2>/dev/null | grep -E "^\s+[A-F0-9]" | head -1 | tr -d ' ')
info "Found key with fingerprint: $FINGERPRINT"
echo ""

# Export GPG public key
OUTPUT_FILE="$BOOTSTRAP_MOUNT/${USERNAME}.gpg"
info "Exporting public key to: $OUTPUT_FILE"

gpg --armor --export "$GPG_EMAIL" > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    error "Failed to export GPG public key"
    rm -f "$OUTPUT_FILE"
    exit 1
fi

success "Public key exported!"
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Bootstrap Complete!                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
success "Admin user '$USERNAME' has been registered!"
echo ""
info "GPG Fingerprint: $FINGERPRINT"
echo ""
info "Next steps:"
echo "  1. Start the Cryptic server (it will read the bootstrap directory)"
echo ""
echo "  2. Run the onboarding process:"
echo ""
echo "     docker run -it --rm --name cryptic-client \\"
echo "       -v ~/.cryptic:/home/cryptic/.cryptic \\"
echo "       -v ~/.gnupg:/home/cryptic/.gnupg \\"
echo "       --add-host=cryptic-server:host-gateway \\"
echo "       ghcr.io/etnt/cryptic-tui:latest sh -c 'cryptic --onboard'"
echo ""
echo "  3. During onboarding, use the same GPG key ($GPG_EMAIL)"
echo "     The fingerprint is already registered!"
echo ""
