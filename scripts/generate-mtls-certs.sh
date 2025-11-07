#!/bin/bash

# Generate mTLS certificates for Cryptic chat server

set -e

echo "🔐 Generating mTLS Server Certificates for Cryptic..."

DIR=priv/ssl

# Create SSL directory if it doesn't exist
mkdir -p ${DIR}

# Create (if not created)
if [ ! -f "${DIR}/index.txt" ]; then
  touch ${DIR}/index.txt
fi

if [ ! -f "${DIR}/serial" ]; then
  echo "01" > ${DIR}/serial
fi

DNS_SANS=""
echo "Enter DNS Subject Alternative Name (SAN) (unless localhost only) - press Enter to skip:"
echo -n "DNS names (comma-separated): " ; read DNS_SANS

# Build SAN string for OpenSSL config file format (DNS.3 = hostname, DNS.4 = hostname, ...)
SAN_LINES=""
if [ -n "$DNS_SANS" ]; then
    # Convert comma-separated DNS names to OpenSSL config format
    # Start from DNS.3 (DNS.1 and DNS.2 are already in the config)
    INDEX=3
    IFS=',' read -ra NAMES <<< "$DNS_SANS"
    for name in "${NAMES[@]}"; do
        # Trim whitespace
        name=$(echo "$name" | xargs)
        if [ -n "$SAN_LINES" ]; then
            SAN_LINES="$SAN_LINES"$'\n'
        fi
        SAN_LINES="${SAN_LINES}DNS.$INDEX = $name"
        INDEX=$((INDEX + 1))
    done
fi

# Create temporary config file with SAN extension
TEMP_CONFIG="/tmp/openssl_san_server.cnf"
cp ${DIR}/../openssl.cnf "$TEMP_CONFIG"

# Add SAN to the [ alt_names_server ] section after DNS.2 line
if [ -n "$SAN_LINES" ]; then
    # Use awk to insert multiple lines after DNS.2
    awk -v san="$SAN_LINES" '/^DNS\.2 = / { print; print san; next }1' "$TEMP_CONFIG" > "$TEMP_CONFIG.tmp"
    mv "$TEMP_CONFIG.tmp" "$TEMP_CONFIG"
fi

CONFIG_FILE="$TEMP_CONFIG"

# 1. Generate CA certificate (self-signed root) and private key
echo "1. Creating Certificate Authority certificate..."
openssl req -x509 -days 3650 -sha384 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
  -keyout ${DIR}/ca.key -nodes -out ${DIR}/ca.crt \
  -subj "/C=US/ST=Development/L=Development/O=Cryptic CA/OU=Development/CN=Cryptic Root CA"

# 2. Generate server private key
echo "2. Generating server CSR and private key..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout ${DIR}/server.key \
  -nodes -out ${DIR}/server.csr \
  -subj "/C=US/ST=Development/L=Development/O=Cryptic CA/OU=Development/CN=Cryptic Server"

# 3. Generate server certificate signed by CA
echo "3. Generating server certificate..."
openssl ca -config ${CONFIG_FILE} -extensions v3_server -batch -notext \
  -in ${DIR}/server.csr -days 3652 -out ${DIR}/server.crt


# Clean up temporary files
rm ${DIR}/server.csr

# Set appropriate permissions
chmod 600 ${DIR}/*.key ${DIR}/*.pem
chmod 644 ${DIR}/*.crt

echo ""
echo "✅ mTLS certificates generated successfully!"
echo ""
echo "📁 Certificate Authority:"
echo "   - ${DIR}/ca.crt (Certificate Authority - distribute to clients)"
echo "   - ${DIR}/ca.key (CA Private Key - KEEP SECURE!)"
echo ""
echo "🖥️  Server certificates:"
echo "   - ${DIR}/server.crt (Server certificate)"
echo "   - ${DIR}/server.key (Server private key - KEEP SECURE!)"
echo ""
echo "⚠️  SECURITY NOTES:"
echo "   - These are development certificates with 365-day expiry"
echo "   - Private keys (.key files) must be kept secure"
echo "   - For production, use proper CA-signed certificates"
echo "   - Consider certificate revocation mechanisms for production"
echo ""
