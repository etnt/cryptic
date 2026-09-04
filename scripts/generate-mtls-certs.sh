#!/bin/sh

# Generate mTLS certificates for Cryptic chat server
# POSIX-compatible for Alpine/BusyBox

set -e

echo "🔐 Generating mTLS Server Certificates for Cryptic..."

DIR="${DIR:-priv/ssl}"

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
# Prefer the CRYPTIC_CERT_DNS_SANS env var (used by the container entrypoint so
# certificate generation is fully non-interactive). Only fall back to an
# interactive prompt when connected to a TTY; on EOF/no TTY we skip silently.
if [ -n "${CRYPTIC_CERT_DNS_SANS:-}" ]; then
    DNS_SANS="${CRYPTIC_CERT_DNS_SANS}"
    echo "Using DNS SANs from CRYPTIC_CERT_DNS_SANS: ${DNS_SANS}"
elif [ -t 0 ]; then
    printf "Enter DNS Subject Alternative Name (SAN) - press Enter to skip\nDNS names (comma-separated): "
    read DNS_SANS || DNS_SANS=""
fi

# Extra IP-address SANs (comma-separated). RFC 6125 / 5280 require raw IP
# literals to appear as iPAddress SANs (IP.N), not dNSName SANs, or strict
# TLS clients reject the certificate.
IP_SANS="${CRYPTIC_CERT_IP_SANS:-}"

# Detect whether a value is an IP literal (IPv4 dotted-quad or IPv6 with ':').
# Anything matching is emitted as IP.N so operators can list IPs in either
# CRYPTIC_CERT_DNS_SANS or CRYPTIC_CERT_IP_SANS and still get a valid cert.
is_ip_addr() {
    case "$1" in
        *:*) return 0 ;;          # IPv6 (contains a colon)
        *[!0-9.]*) return 1 ;;    # contains a non-digit/non-dot -> not IPv4
        *.*.*.*) return 0 ;;      # dotted quad
        *) return 1 ;;
    esac
}

# Build SAN string for OpenSSL config file format. DNS.1/DNS.2 and IP.1/IP.2
# already live in the base config, so extra entries start at index 3.
SAN_LINES=""
DNS_INDEX=3
IP_INDEX=3

append_san_line() {
    if [ -n "$SAN_LINES" ]; then
        SAN_LINES="${SAN_LINES}
$1"
    else
        SAN_LINES="$1"
    fi
}

add_san_entry() {
    entry=$(echo "$1" | xargs)
    [ -z "$entry" ] && return 0
    if is_ip_addr "$entry"; then
        append_san_line "IP.$IP_INDEX = $entry"
        IP_INDEX=$((IP_INDEX + 1))
    else
        append_san_line "DNS.$DNS_INDEX = $entry"
        DNS_INDEX=$((DNS_INDEX + 1))
    fi
}

# POSIX-compatible: use echo and tr instead of bash arrays.
for name in $(echo "$DNS_SANS" | tr ',' ' '); do
    add_san_entry "$name"
done
for ip in $(echo "$IP_SANS" | tr ',' ' '); do
    add_san_entry "$ip"
done

if [ -n "$SAN_LINES" ]; then
    echo "Adding Subject Alternative Names:"
    echo "$SAN_LINES" | sed 's/^/   /'
fi

# Find openssl.cnf - check multiple locations
OPENSSL_CNF=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check locations in order of preference
for cnf_path in \
    "${SCRIPT_DIR}/openssl.cnf" \
    "${SCRIPT_DIR}/../priv/openssl.cnf" \
    "./priv/openssl.cnf" \
    "./lib/cryptic-1.0.0/priv/openssl.cnf" \
    "/opt/cryptic/lib/cryptic-1.0.0/priv/openssl.cnf"; do
    if [ -f "$cnf_path" ]; then
        OPENSSL_CNF="$cnf_path"
        break
    fi
done

if [ -z "$OPENSSL_CNF" ]; then
    echo "❌ Error: Cannot find openssl.cnf"
    echo "   Searched in:"
    echo "   - ${SCRIPT_DIR}/openssl.cnf"
    echo "   - ${SCRIPT_DIR}/../priv/openssl.cnf"
    echo "   - ./priv/openssl.cnf"
    echo "   - ./lib/cryptic-1.0.0/priv/openssl.cnf"
    echo "   - /opt/cryptic/lib/cryptic-1.0.0/priv/openssl.cnf"
    exit 1
fi

echo "Using OpenSSL config: $OPENSSL_CNF"

# Create temporary config file with SAN extension
TEMP_CONFIG="/tmp/openssl_san_server.cnf"
rm -f "$TEMP_CONFIG"
cp "$OPENSSL_CNF" "$TEMP_CONFIG"

# Update the dir path in the config to match our $DIR
# This replaces "dir = priv/ssl" (or similar) with the actual DIR path
# Use temporary file for POSIX compatibility (Alpine/BusyBox doesn't support sed -i the same way)
sed "s|^dir[[:space:]]*=.*|dir = $DIR|" "$TEMP_CONFIG" > "$TEMP_CONFIG.tmp" && mv "$TEMP_CONFIG.tmp" "$TEMP_CONFIG"

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
rm -f ${DIR}/server.csr
rm -f "$TEMP_CONFIG"

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
