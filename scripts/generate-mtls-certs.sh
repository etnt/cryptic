#!/bin/bash

# Generate mTLS certificates for Cryptic chat server
# This creates a complete PKI infrastructure with CA and client certificates

set -e

echo "🔐 Generating mTLS certificates for Cryptic..."

# Create SSL directory if it doesn't exist
mkdir -p priv/ssl

# 1. Generate Certificate Authority (CA) private key
echo "1. Generating Certificate Authority private key..."
openssl genrsa -out priv/ssl/ca.key 4096

# 2. Generate CA certificate (self-signed root)
echo "2. Creating Certificate Authority certificate..."
openssl req -new -x509 -days 3650 -key priv/ssl/ca.key -out priv/ssl/ca.crt \
  -subj "/C=US/ST=Development/L=Development/O=Cryptic CA/OU=Development/CN=Cryptic Root CA"

# 3. Generate server private key
echo "3. Generating server private key..."
openssl genrsa -out priv/ssl/server.key 2048

# 4. Generate server certificate signing request
echo "4. Creating server certificate signing request..."
openssl req -new -key priv/ssl/server.key -out priv/ssl/server.csr \
  -subj "/C=US/ST=Development/L=Development/O=Cryptic Server/OU=Development/CN=localhost"

# 5. Generate server certificate signed by CA
echo "5. Generating server certificate..."
openssl x509 -req -days 365 -in priv/ssl/server.csr \
  -CA priv/ssl/ca.crt -CAkey priv/ssl/ca.key -CAcreateserial \
  -out priv/ssl/server.crt

# 6. Generate client certificates for default users
echo "6. Generating client certificates..."
users=("alice" "bob" "charlie" "admin" "guest")

for user in "${users[@]}"; do
    echo "   - Generating certificate for: $user"
    
    # Client private key
    openssl genrsa -out "priv/ssl/client_${user}.key" 2048
    
    # Client certificate signing request
    openssl req -new -key "priv/ssl/client_${user}.key" \
      -out "priv/ssl/client_${user}.csr" \
      -subj "/C=US/ST=Development/L=Development/O=Cryptic User/OU=Development/CN=${user}"
    
    # Client certificate signed by CA
    openssl x509 -req -days 365 -in "priv/ssl/client_${user}.csr" \
      -CA priv/ssl/ca.crt -CAkey priv/ssl/ca.key -CAcreateserial \
      -out "priv/ssl/client_${user}.crt"
    
    # Clean up CSR
    rm "priv/ssl/client_${user}.csr"
    
    # Create client bundle (certificate + private key) for easy distribution
    cat "priv/ssl/client_${user}.crt" "priv/ssl/client_${user}.key" \
      > "priv/ssl/client_${user}.pem"
    
    # Create client bundle with CA for verification
    cat "priv/ssl/client_${user}.crt" "priv/ssl/client_${user}.key" "priv/ssl/ca.crt" \
      > "priv/ssl/client_${user}_bundle.pem"
done

# Clean up temporary files
rm priv/ssl/server.csr
rm priv/ssl/ca.srl 2>/dev/null || true

# Set appropriate permissions
chmod 600 priv/ssl/*.key priv/ssl/*.pem
chmod 644 priv/ssl/*.crt

echo ""
echo "✅ mTLS certificates generated successfully!"
echo ""
echo "📁 Certificate Authority:"
echo "   - priv/ssl/ca.crt (Certificate Authority - distribute to clients)"
echo "   - priv/ssl/ca.key (CA Private Key - KEEP SECURE!)"
echo ""
echo "🖥️  Server certificates:"
echo "   - priv/ssl/server.crt (Server certificate)"
echo "   - priv/ssl/server.key (Server private key - KEEP SECURE!)"
echo ""
echo "👥 Client certificates (distribute to respective users):"
for user in "${users[@]}"; do
    echo "   - priv/ssl/client_${user}.pem (${user}'s certificate + key)"
    echo "   - priv/ssl/client_${user}_bundle.pem (${user}'s cert + key + CA)"
done
echo ""
echo "⚠️  SECURITY NOTES:"
echo "   - These are development certificates with 365-day expiry"
echo "   - Private keys (.key files) must be kept secure"
echo "   - For production, use proper CA-signed certificates"
echo "   - Consider certificate revocation mechanisms for production"
echo ""
echo "🚀 Start the mTLS server with:"
echo "   erl -pa _build/default/lib/*/ebin"
echo "   1> cryptic_server:start_mtls(#{})."
echo ""
echo "📱 Connect clients with certificates:"
echo "   1> cryptic_cecho_ui:start_mtls(\"https://localhost:8443\", \"priv/ssl/client_alice.pem\")."
echo ""
echo "🧪 Test with curl:"
echo "   curl --cert priv/ssl/client_alice.pem --cacert priv/ssl/ca.crt \\"
echo "        https://localhost:8443/list_users"
