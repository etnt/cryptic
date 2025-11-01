#!/usr/bin/env bash
#
# Bootstrap GPG registration for existing user certificates
#
# This script exports a user's GPG public key to the bootstrap directory,
# where the server will automatically load it on startup.
#
# Usage: ./bootstrap_gpg.sh <username>
#
# Example: ./bootstrap_gpg.sh admin

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Bootstrap directory - use the source priv directory, not _build
BOOTSTRAP_DIR="$PROJECT_ROOT/priv/ca/bootstrap"

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <username>"
    echo "Example: $0 admin"
    exit 1
fi

USERNAME="$1"

# Get GPG email
GPG_EMAIL="${USERNAME}@cryptic.local"

echo "Bootstrapping GPG registration for: $USERNAME"
echo "GPG email: $GPG_EMAIL"
echo ""

# Check if GPG key exists
if ! gpg --list-keys "$GPG_EMAIL" > /dev/null 2>&1; then
    echo "Error: No GPG key found for $GPG_EMAIL"
    echo ""

    # Ask if user wants to create the key
    read -p "Would you like to create a GPG key for $GPG_EMAIL now? [y/N] " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Creating GPG key for $GPG_EMAIL..."
        echo ""

        # Create GPG key
        gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: $USERNAME
Name-Email: $GPG_EMAIL
Expire-Date: 0
%commit
EOF

        if [ $? -eq 0 ]; then
            echo ""
            echo "✓ GPG key created successfully!"
            echo ""
        else
            echo ""
            echo "Error: Failed to create GPG key"
            exit 1
        fi
    else
        echo ""
        echo "You can create a GPG key manually with:"
        echo ""
        echo "  gpg --batch --gen-key <<EOF"
        echo "  %no-protection"
        echo "  Key-Type: RSA"
        echo "  Key-Length: 4096"
        echo "  Name-Real: $USERNAME"
        echo "  Name-Email: $GPG_EMAIL"
        echo "  Expire-Date: 0"
        echo "  %commit"
        echo "  EOF"
        echo ""
        exit 1
    fi
fi

# Create bootstrap directory if it doesn't exist
mkdir -p "$BOOTSTRAP_DIR"

# Export GPG public key to bootstrap directory
OUTPUT_FILE="$BOOTSTRAP_DIR/${USERNAME}.gpg"

echo "Exporting GPG public key to: $OUTPUT_FILE"
gpg --armor --export "$GPG_EMAIL" > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    echo "Error: Failed to export GPG public key"
    rm -f "$OUTPUT_FILE"
    exit 1
fi

echo ""
echo "✓ GPG public key exported successfully!"
echo ""
echo "The server will automatically load this registration on next startup."
echo "File: $OUTPUT_FILE"
echo ""
echo "To apply immediately without restart, you can reload the bootstrap:"
echo "  # From the Erlang shell:"
echo "  {ok, DbRef} = cryptic_ca_init:get_db_ref()."
echo "  cryptic_ca_bootstrap:load_bootstrap_registrations(DbRef)."
