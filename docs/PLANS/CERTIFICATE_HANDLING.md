# Cryptic - Certificate Handling

The Cryptic system uses the [`myca`](https://github.com/etnt/myca.git)
Certificate Authority framework for managing X.509 certificates required for
WebSocket mTLS authentication. This section explains how to set up the CA
infrastructure and manage client certificates.

## CA Infrastructure Setup

The certificate infrastructure is based on the `myca` framework located in
the `CA/` directory. This provides a complete Certificate Authority with
modern elliptic curve cryptography (secp384r1) for enhanced security and
performance.

### Initial CA and Server Certificate Creation

```bash
# Navigate to the CA directory
cd CA/

# Generate CA certificate and server certificate (first time setup)
make all
```

This creates:
- **CA certificate** (`certs/ca.crt`) - Root certificate for signing all other certificates
- **Server certificate** (`certs/server.crt`) and key (`private/server.key`) - Used by the WebSocket server
- Directory structure for organized certificate management:
  - `certs/` - CA and issued certificates
  - `private/` - Private keys (CA and server)
  - `csr/` - Certificate signing requests
  - `client_keys/` - Client certificates and keys
  - `crl/` - Certificate revocation lists

### Pre-defined Client Certificates

The system comes with several pre-configured client certificates for immediate testing:

- **alice** - `CA/client_keys/alice.{crt,key,pem}`
- **bob** - `CA/client_keys/bob.{crt,key,pem}`
- **charlie** - `CA/client_keys/charlie.{crt,key,pem}`
- **admin** - `CA/client_keys/admin.{crt,key,pem}`

Each client has three files:
- `.crt` - Certificate only
- `.key` - Private key only  
- `.pem` - Combined certificate and private key (used by Erlang SSL)

## Creating New Client Certificates

To create a new client certificate for additional users:

```bash
cd CA/
make client
```

The system will prompt for:
- **Client name**: Full name of the user (e.g., "Dave Anderson")
- **Client email**: Email address (e.g., "dave@example.com")
- **Subject Alternative Names (SANs)**: Optional additional identities

Example session:
```bash
❯ make client
Enter client name: Dave Anderson
Enter client email: dave@example.com
Do you want to add Subject Alternative Names (SANs)? (y/N): y
Enter Subject Alternative Names (SANs) - press Enter to skip each type:
DNS names (comma-separated): dave.internal.com
IP addresses (comma-separated): 192.168.1.50
Email addresses (comma-separated): d.anderson@example.com
URIs (comma-separated): 
```

This generates:
```bash
# Certificate files
CA/client_keys/dave@example.com_Mon-Sep-13-14:23:45-CEST-2025.crt
CA/client_keys/dave@example.com_Mon-Sep-13-14:23:45-CEST-2025.key
CA/client_keys/dave@example.com_Mon-Sep-13-14:23:45-CEST-2025.pem
```

### Verifying Username Extraction

To see what username will be extracted from a certificate:

```bash
# Check certificate details
openssl x509 -in CA/client_keys/alice.crt -text -noout | grep -A5 "Subject:"
openssl x509 -in CA/client_keys/alice.crt -text -noout | grep -A10 "Subject Alternative Name"

# Example output:
#   Subject: CN=EMP-5432, emailAddress=alice@company.com, O=Company, C=US
#   X509v3 Subject Alternative Name:
#       email:alice@company.com, DNS:alice.internal.company.com
# Extracted username: alice (from email local part)
```

## Certificate Verification and Management

### Verify Certificate Validity
```bash
cd CA/
./scripts/verify-crt.sh client_keys/alice.crt
# Output: client_keys/alice.crt: OK
```

### Generate Certificate Fingerprint
```bash
cd CA/
./scripts/fingerprint.sh client_keys/alice.crt
# Output: sha256 Fingerprint=A1:B2:C3:D4:E5:F6:...
```

### View Certificate Details
```bash
cd CA/
openssl x509 -in client_keys/alice.crt -text -noout
```

## Certificate Revocation

To revoke a compromised or no longer valid certificate:

```bash
cd CA/
./scripts/revoke-cert.sh certs/02.pem  # Revoke certificate with serial 02
```

This updates:
- `index.txt` - Marks certificate as revoked (status flag changes from 'V' to 'R')
- `crl/rootca.crl` - Certificate Revocation List for the Erlang SSL application

### Check Revocation Status
```bash
cd CA/
./scripts/print-crl.sh  # View all revoked certificates
```

## Using Certificates with Cryptic

### Starting the Server with Certificates
```bash
# Use the provided script that sets up certificate paths
./scripts/start-server.sh
```

### Starting Clients with Specific Certificates
```bash
# Start client with alice's certificate
./scripts/start-client.sh alice

# Start client with bob's certificate  
./scripts/start-client.sh bob

# Start client with charlie's certificate
./scripts/start-client.sh charlie
```

The start scripts automatically configure the WebSocket client to use:
- CA certificate for server verification: `CA/certs/ca.crt`
- Client certificate for mTLS authentication: `CA/client_keys/{user}.pem`

### Manual Certificate Configuration

For custom setups, use environment variables to specify certificate paths as
demonstrated in the start scripts:

**Environment Variables for Certificate Paths**:
```bash
# Set certificate paths via environment variables
export CRYPTIC_CLIENT_CERT="CA/client_keys/alice.crt"
export CRYPTIC_CLIENT_KEY="CA/client_keys/alice.key" 
export CRYPTIC_CA_CERT="CA/certs/ca.crt"

# Start client with custom certificate configuration
erl -pa _build/default/lib/*/ebin -eval "cryptic_ws_ui:start(\"alice\", \"localhost\")." -noinput
```

This approach allows flexible certificate management without modifying code,
making it suitable for different deployment environments.


## How to securely deliver a client certificate using GPG

### Recipient — create keypair and share public key
1. Create a GPG keypair (interactive; choose RSA 3072+ or ECC):
```
gpg --full-generate-key
```
- Follow prompts: select key type (RSA or ECC), size, expiry, and
  user ID (name/email). Protect with a strong passphrase.

2. Export your public key to send to the sender:
```
gpg --armor --export you@example.com > recipient_pub.asc
```
- Replace you@example.com with the UID you used when creating the key.
- Send recipient_pub.asc to the sender (email, paste, or file transfer).
  Never send your private key.

3. Keep your private key safe (stored in GPG keyring). Optionally export
   an ASCII-armored backup for safekeeping:
```
gpg --armor --export-secret-keys you@example.com > recipient_priv_backup.asc
chmod 600 recipient_priv_backup.asc
# store this backup offline/encrypted; do NOT send it
```

### Sender — encrypt the private SSL key with recipient’s public key

Assume you have the recipient’s public key file recipient_pub.asc and the
SSL private key file mykey.pem.

1. Import the recipient public key (optional, for local keyring use):
```
gpg --import recipient_pub.asc
```

2. Encrypt the file to the recipient (creates mykey.gpg):
```
gpg --encrypt --recipient you@example.com --output mykey.gpg mykey.pem
```
- If you did not import the key, use the recipient’s key ID or the 
  recipient option with the email shown in recipient_pub.asc.
- For a file that only the recipient can decrypt, omit --sign.
  To also sign, add `--sign` and ensure you have a local signing key.

3. Send mykey.gpg to the recipient.

### Recipient — decrypt the received file
Assume you received mykey.gpg.

1. Decrypt:
```
gpg --output mykey.pem --decrypt mykey.gpg
```
- If the private key is passphrase-protected, GPG will prompt for it.

2. Secure the decrypted private key:
```
chmod 600 mykey.pem
```
- Verify contents and store it securely (e.g., in an encrypted filesystem or hardware token).

3. Remove temporary files if any.

---

### Optional: verify signature (if sender signed)
If the sender signed the encrypted file, GPG will report the signature status
during decryption. To manually check:
```
gpg --verify mykey.gpg
```

### Extract the Certificate and Key from a PEM file
```
# Extract Certificate
openssl x509 -in my.pem > my.crt

# Extract Private Key
openssl pkey -in my.pem > my.key
```


### Security notes (brief)
- Never share private keys or backups.  
- Use a strong passphrase for your GPG private key.  
- Prefer using GPG’s default secure algorithms; update GPG if using old versions.


## Certificate Security Features

### Modern Cryptography
- **Algorithm**: Elliptic Curve (secp384r1) instead of RSA for better security/performance
- **Validity**: 10-year certificate lifetime (3652 days) for production stability
- **Key Size**: 384-bit EC keys provide equivalent security to 7680-bit RSA keys

### Subject Alternative Names (SAN) Support
Client certificates can include multiple identity types:
- **DNS names**: For domain-based authentication
- **IP addresses**: For IP-based connections
- **Email addresses**: For email-based identity verification  
- **URIs**: For service endpoint authentication

### Certificate Revocation List (CRL)
- Real-time revocation checking during WebSocket mTLS handshake
- Automatic CRL updates when certificates are revoked
- Proper CRL formatting for Erlang SSL application compatibility

## Production Certificate Management

### Certificate Rotation Strategy
```bash
# Generate new server certificate (keeping same CA)
cd CA/
./scripts/gen-server-cert.sh

# Generate new client certificate for existing user
make client  # Enter same user details to replace old certificate
```

### Backup and Recovery
```bash
# Backup critical certificate infrastructure
tar -czf cryptic-ca-backup-$(date +%Y%m%d).tar.gz CA/

# Essential files to backup:
# - CA/certs/ca.crt (CA certificate)
# - CA/private/ca.key (CA private key) 
# - CA/index.txt (certificate database)
# - CA/serial (certificate serial counter)
# - CA/client_keys/ (all client certificates)
```

### Monitoring Certificate Expiration
```bash
# Check certificate expiration dates
cd CA/
for cert in client_keys/*.crt; do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -noout -dates
done
```

This certificate infrastructure provides enterprise-grade security for the Cryptic messaging system, ensuring strong authentication and secure transport for all WebSocket mTLS communications.

