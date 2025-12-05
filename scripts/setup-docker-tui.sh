#!/bin/bash
#
# Setup Cryptic TUI for Docker
# Helper script to configure certificates and cookies for Docker deployment
#
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${BLUE}[SETUP]${NC} $1"; }
success() { echo -e "${GREEN}[SETUP]${NC} ✓ $1"; }
warn() { echo -e "${YELLOW}[SETUP]${NC} ⚠️  $1"; }
error() { echo -e "${RED}[SETUP]${NC} ✗ $1" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║      Cryptic TUI Docker Setup Assistant                      ║
╚══════════════════════════════════════════════════════════════╝
EOF

echo ""
info "This script helps set up your client identity for Docker TUI."
info "It wraps the 'cryptic-onboard' tool with Docker-specific setup."
echo ""

# Check if .cryptic directory exists
if [ -d "${HOME}/.cryptic" ]; then
    success "Found existing ~/.cryptic directory"
    
    # Check for existing identities
    EXISTING_USERS=$(find "${HOME}/.cryptic" -maxdepth 1 -type d ! -path "${HOME}/.cryptic" -exec basename {} \; 2>/dev/null | grep -v "^logs$" | grep -v "^gpg-export$")
    
    if [ -n "$EXISTING_USERS" ]; then
        info "Found existing user identities:"
        echo "$EXISTING_USERS" | sed 's/^/  - /'
        echo ""
        read -p "Set up a new user or use existing? [new/existing]: " choice
        
        if [ "$choice" = "existing" ]; then
            info "You can use the existing setup. Run:"
            echo "  scripts/run-tui.sh <username>"
            exit 0
        fi
    fi
fi

echo ""
info "Starting cryptic-onboard wizard..."
info "Note: When prompted for server URL, use: https://cryptic-server:8443"
echo ""

# Run the cryptic-onboard tool
"${REPO_ROOT}/bin/cryptic-onboard"

# Check result
ONBOARD_RESULT=$?

if [ $ONBOARD_RESULT -ne 0 ]; then
    warn "Onboarding was cancelled or encountered an error."
    exit $ONBOARD_RESULT
fi

echo ""
success "Onboarding complete!"
echo ""

# Try to detect username from .cryptic directory
LATEST_USER=$(find "${HOME}/.cryptic" -maxdepth 1 -type d ! -path "${HOME}/.cryptic" -exec basename {} \; 2>/dev/null | grep -v "^logs$" | grep -v "^gpg-export$" | tail -1)

if [ -n "$LATEST_USER" ]; then
    USERNAME="$LATEST_USER"
    CERT_DIR="${HOME}/.cryptic/${USERNAME}/cryptic-server_8443/certificates"
else
    warn "Could not detect username. Using 'alice' as default."
    USERNAME="alice"
    CERT_DIR="${HOME}/.cryptic/alice/cryptic-server_8443/certificates"
fi

# Verify Erlang cookie exists
info "Checking Erlang cookie..."
COOKIE_FILE="${HOME}/.erlang.cookie"

if [ ! -f "$COOKIE_FILE" ]; then
    info "Creating Erlang cookie..."
    COOKIE="cryptic_secret_cookie"
    echo -n "$COOKIE" > "$COOKIE_FILE"
    chmod 400 "$COOKIE_FILE"
    success "Created Erlang cookie: $COOKIE_FILE"
else
    success "Erlang cookie exists: $COOKIE_FILE"
fi

echo ""
success "Setup complete!"
echo ""

cat << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Next Steps:

1. Build the Docker images:
   $ docker-compose build

2. Start the Cryptic server:
   $ docker-compose up -d cryptic-server

3. Wait for server to be healthy:
   $ docker-compose ps

4. Start the TUI client:
   $ TUI_USERNAME=$USERNAME docker-compose run --rm cryptic-tui

Or use the helper script:
   $ scripts/run-tui.sh $USERNAME

Your setup:
  Username:     $USERNAME
  Certificates: $CERT_DIR
  Cookie:       $COOKIE_FILE

Storage locations (mounted in Docker):
  ~/.cryptic/$USERNAME/cryptic-server_8443/
    ├── certificates/        # mTLS certificates
    │   ├── $USERNAME.crt
    │   ├── $USERNAME.key
    │   └── ca.crt
    ├── keys.encrypted       # Identity keys (X3DH)
    ├── sessions/            # Double Ratchet states
    │   └── *.session
    ├── cryptic_chat.db      # Message history (if --enable-db)
    └── logs/                # Application logs

Note: The entire ~/.cryptic directory is mounted read-write
      in the Docker container for persistent storage.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For help, see: docs/DOCKER.md

EOF
