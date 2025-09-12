#!/bin/bash

# Generate development SSL certificates for Cryptic chat server
# WARNING: These are self-signed certificates for DEVELOPMENT ONLY
# For production, use proper CA-signed certificates (e.g., Let's Encrypt)

set -e

echo "Generating development SSL certificates..."

# Create SSL directory if it doesn't exist
mkdir -p priv/ssl

# Generate private key
echo "1. Generating private key..."
openssl genrsa -out priv/ssl/server.key 2048

# Generate certificate signing request
echo "2. Creating certificate signing request..."
openssl req -new -key priv/ssl/server.key -out priv/ssl/server.csr -subj "/C=US/ST=Development/L=Development/O=Cryptic Chat/OU=Development/CN=localhost"

# Generate self-signed certificate (valid for 1 year)
echo "3. Generating self-signed certificate..."
openssl x509 -req -days 365 -in priv/ssl/server.csr -signkey priv/ssl/server.key -out priv/ssl/server.crt

# Add Subject Alternative Names for localhost variants
echo "4. Adding Subject Alternative Names..."
cat > priv/ssl/openssl.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Development
O = Cryptic Chat
OU = Development Team
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
DNS.3 = ::1
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Regenerate certificate with SAN
openssl req -new -key priv/ssl/server.key -out priv/ssl/server.csr -config priv/ssl/openssl.conf
openssl x509 -req -days 365 -in priv/ssl/server.csr -signkey priv/ssl/server.key -out priv/ssl/server.crt -extensions v3_req -extfile priv/ssl/openssl.conf

# Clean up temporary files
rm priv/ssl/server.csr priv/ssl/openssl.conf

# Set appropriate permissions
chmod 600 priv/ssl/server.key
chmod 644 priv/ssl/server.crt

echo "✅ Development SSL certificates generated successfully!"
echo ""
echo "Files created:"
echo "  - priv/ssl/server.key (private key - keep secure!)"
echo "  - priv/ssl/server.crt (certificate - valid for 365 days)"
echo ""
echo "⚠️  WARNING: These are self-signed certificates for DEVELOPMENT only!"
echo "   Browsers will show security warnings - this is normal for development."
echo ""
echo "🔒 For production, use proper CA-signed certificates:"
echo "   - Let's Encrypt (free): https://letsencrypt.org/"
echo "   - Commercial CA certificates"
echo ""
echo "🚀 Start the HTTPS server with:"
echo "   erl -pa _build/default/lib/*/ebin"
echo "   1> cryptic_server:start_https(#{})."
echo ""
echo "📱 Connect clients with:"
echo "   1> cryptic_cecho_ui:start(\"https://localhost:8443\")."
