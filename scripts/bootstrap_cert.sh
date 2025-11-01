#!/usr/bin/env bash
#
# Bootstrap Certificate Generation Script
#
# This script generates a client certificate for a user and places it in the
# standard Cryptic certificate directory structure:
#   $HOME/.cryptic/$USERNAME/$SERVER_$PORT/certificates/
#
# The certificate files are named:
#   $USERNAME.pem  (combined certificate + key for some tools)
#   $USERNAME.crt  (certificate only)
#   $USERNAME.key  (private key only)
#
# Usage:
#   ./scripts/bootstrap_cert.sh <username> <server_host> <server_port>
#
# Arguments:
#   username    - The username for the certificate (e.g., "admin", "alice")
#   server_host - Server hostname (e.g., "localhost", "server.example.com")
#   server_port - Server port (e.g., "8443")
#
# Example:
#   ./scripts/bootstrap_cert.sh admin localhost 8443
#   ./scripts/bootstrap_cert.sh alice server.example.com 8443
#

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CA_DIR="$PROJECT_ROOT/CA"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check arguments
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo -e "${RED}Error: Username, server host, and server port are required${NC}"
    echo "Usage: $0 <username> <server_host> <server_port>"
    echo ""
    echo "Example:"
    echo "  $0 admin localhost 8443"
    echo "  $0 alice server.example.com 8443"
    exit 1
fi

USERNAME="$1"
SERVER_HOST="$2"
SERVER_PORT="$3"

echo -e "${GREEN}Bootstrapping certificate for user: ${USERNAME}${NC}"
echo -e "${GREEN}Server: ${SERVER_HOST}:${SERVER_PORT}${NC}"
echo ""

# Check if CA directory exists
if [ ! -d "$CA_DIR" ]; then
    echo -e "${RED}Error: CA directory not found at $CA_DIR${NC}"
    exit 1
fi

# Check if CA certificates exist
if [ ! -f "$CA_DIR/certs/ca.crt" ]; then
    echo -e "${YELLOW}Warning: CA root certificate not found${NC}"
    echo "You may need to run: cd CA && make all"
    echo ""
    read -p "Do you want to generate CA certificates now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Generating CA certificates..."
        cd "$CA_DIR"
        make all
        cd "$PROJECT_ROOT"
        echo ""
    else
        echo -e "${RED}Cannot proceed without CA certificates${NC}"
        exit 1
    fi
fi

# Generate client certificate
echo "Checking for existing certificates..."

# Debug: show what we're looking for
echo "DEBUG: CA_DIR=$CA_DIR"
echo "DEBUG: USERNAME=$USERNAME"
echo "DEBUG: Search pattern: $CA_DIR/client_keys/${USERNAME}@*.crt"

# Check if certificates already exist for this user
EXISTING_CERT=$(ls -t "$CA_DIR/client_keys/${USERNAME}@"*".crt" 2>/dev/null | head -1)
EXISTING_KEY=$(ls -t "$CA_DIR/client_keys/${USERNAME}@"*".key" 2>/dev/null | head -1)

if [ -n "$EXISTING_CERT" ] && [ -n "$EXISTING_KEY" ]; then
    echo -e "${GREEN}Found existing certificates for $USERNAME${NC}"
    echo "  Certificate: $(basename "$EXISTING_CERT")"
    echo "  Private key: $(basename "$EXISTING_KEY")"
    CLIENT_CERT="$EXISTING_CERT"
    CLIENT_KEY="$EXISTING_KEY"
    echo ""
    echo "Using existing certificates. To regenerate, delete them first:"
    echo "  rm $CA_DIR/client_keys/${USERNAME}@*.{crt,key,pem}"
    echo ""
    SKIP_GENERATION=true
else
    SKIP_GENERATION=false
fi

if [ "$SKIP_GENERATION" = "false" ]; then
    echo "Generating new client certificate..."
    
    # Use the new gen-client-cert.sh script if it exists, otherwise fall back to Makefile
    if [ -x "$CA_DIR/scripts/gen-client-cert.sh" ]; then
        echo "Using gen-client-cert.sh for certificate generation"
        echo ""
        
        # Derive email from username - use cryptic.local domain for local testing
        # This matches the GPG key registration in bootstrap
        EMAIL="${USERNAME}@cryptic.local"
        
        # Capitalize username for Common Name
        CNAME=$(echo "${USERNAME}" | sed 's/\b\(.\)/\u\1/')
        
        echo "Certificate details:"
        echo "  Common Name: $CNAME"
        echo "  Email: $EMAIL"
        echo ""
        
        cd "$CA_DIR"
        echo -e "${CNAME}\n${EMAIL}\n" | ./scripts/gen-client-cert.sh
        cd "$PROJECT_ROOT"
        
        # Find the most recent certificate files for this username
        # They will be named: ${USERNAME}@*_*.crt and ${USERNAME}@*_*.key
        echo "Searching for certificates matching: ${USERNAME}@*.crt"
        CLIENT_CERT=$(ls -t "$CA_DIR/client_keys/${USERNAME}@"*".crt" 2>/dev/null | head -1)
        echo "Searching for keys matching: ${USERNAME}@*.key"
        CLIENT_KEY=$(ls -t "$CA_DIR/client_keys/${USERNAME}@"*".key" 2>/dev/null | head -1)
        
        if [ -n "$CLIENT_CERT" ]; then
            echo "Found certificate: $(basename "$CLIENT_CERT")"
        fi
        if [ -n "$CLIENT_KEY" ]; then
            echo "Found key: $(basename "$CLIENT_KEY")"
        fi
    else
        echo "Using CA Makefile for certificate generation"
        cd "$CA_DIR"
        make client USERNAME="$USERNAME"
        cd "$PROJECT_ROOT"
        CLIENT_CERT="$CA_DIR/client_keys/${USERNAME}-cert.pem"
        CLIENT_KEY="$CA_DIR/client_keys/${USERNAME}-key.pem"
    fi
fi

echo ""

# Check if certificate was created
if [ -z "$CLIENT_CERT" ] || [ -z "$CLIENT_KEY" ] || [ ! -f "$CLIENT_CERT" ] || [ ! -f "$CLIENT_KEY" ]; then
    echo -e "${RED}Error: Certificate generation failed${NC}"
    echo "Expected files not found in: $CA_DIR/client_keys/"
    echo "Looked for files matching: ${USERNAME}@*.{crt,key} or ${USERNAME}-{cert,key}.pem"
    exit 1
fi

echo "Found certificate files:"
echo "  Certificate: $CLIENT_CERT"
echo "  Private key: $CLIENT_KEY"
echo ""

# Create target directory structure
CERT_DIR="$HOME/.cryptic/$USERNAME/${SERVER_HOST}_${SERVER_PORT}/certificates"
mkdir -p "$CERT_DIR"

# Copy certificate files with standard naming
echo "Installing certificate files to: $CERT_DIR"
cp "$CLIENT_CERT" "$CERT_DIR/${USERNAME}.crt"
cp "$CLIENT_KEY" "$CERT_DIR/${USERNAME}.key"

# Create combined PEM file (some tools need cert+key in one file)
cat "$CLIENT_CERT" "$CLIENT_KEY" > "$CERT_DIR/${USERNAME}.pem"

# Also copy CA certificate for verification
cp "$CA_DIR/certs/ca.crt" "$CERT_DIR/ca.crt"

echo -e "${GREEN}Certificate installation complete!${NC}"
echo ""
echo "Certificate files installed:"
echo "  Certificate:     $CERT_DIR/${USERNAME}.crt"
echo "  Private key:     $CERT_DIR/${USERNAME}.key"
echo "  Combined PEM:    $CERT_DIR/${USERNAME}.pem"
echo "  CA certificate:  $CERT_DIR/ca.crt"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Start the server if not already running"
echo "2. Connect using the console:"
echo ""
echo "   ./scripts/cryptic_console --username $USERNAME \\"
echo "     --cert $CERT_DIR/${USERNAME}.crt \\"
echo "     --key $CERT_DIR/${USERNAME}.key"
echo ""
echo "   Or specify the server explicitly:"
echo ""
echo "   ./scripts/cryptic_console --username $USERNAME \\"
echo "     --server $SERVER_HOST --port $SERVER_PORT \\"
echo "     --cert $CERT_DIR/${USERNAME}.crt \\"
echo "     --key $CERT_DIR/${USERNAME}.key"
echo ""
