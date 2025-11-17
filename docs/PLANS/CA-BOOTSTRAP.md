# CA Bootstrap Procedure

**Purpose**: One-time setup of Certificate Authority for GPG onboarding  
**Approach**: Use myca (OpenSSL wrapper) for CA and server certificates  
**Frequency**: Once per deployment (or when rotating CA)

## Prerequisites

- OpenSSL installed (`openssl version` should work)
- Write access to `CA/` directory
- Understanding of certificate lifecycle (see PHASE3-CERTIFICATE-APPROACH.md)

## Quick Start

```bash
cd CA
make all
```

This will:
1. Create directory structure (`certs/`, `private/`, `csr/`, etc.)
2. Generate CA root certificate (valid 10 years)
3. Generate server certificate (valid 10 years)
4. Initialize Certificate Revocation List (CRL)

## Step-by-Step Procedure

### Step 1: Configure Subject Information

The CA uses environment variables for certificate subject fields:

```bash
cd CA
./scripts/gen-subject-env.sh
```

This creates `SUBJECT.env` with prompts for:
- **CC** (Country Code): Two-letter country code (e.g., "US", "SE")
- **STATE**: State or province name
- **CITY**: City or locality name
- **ORG**: Organization name (e.g., "Cryptic Messaging")
- **CNAME**: Common Name for CA (e.g., "Cryptic CA")
- **EMAIL**: Contact email address

**Example SUBJECT.env**:
```bash
CC="US"
STATE="California"
CITY="San Francisco"
ORG="Cryptic Messaging"
CNAME="Cryptic Root CA"
EMAIL="ca@cryptic.example.org"
```

### Step 2: Generate CA Root Certificate

```bash
make gen_root_ca
```

This creates:
- `private/ca.key` - **CA private key (KEEP SECRET!)**
- `certs/ca.crt` - CA public certificate (distribute to clients)

**Certificate Details**:
- Algorithm: ECDSA with secp384r1 (P-384)
- Validity: 10 years (3650 days)
- Signature: SHA-384
- Self-signed (issuer = subject)

**Verify CA certificate**:
```bash
openssl x509 -in certs/ca.crt -text -noout
```

Look for:
- `Subject: CN=Cryptic Root CA` (matches SUBJECT.env)
- `Issuer: CN=Cryptic Root CA` (self-signed)
- `Validity: Not After: <10 years from now>`
- `Public Key Algorithm: id-ecPublicKey` with `secp384r1`

### Step 3: Generate Server Certificate

```bash
make gen_server_cert
```

This creates:
- `private/server.key` - Server TLS private key
- `csr/server.csr` - Certificate Signing Request (CSR)
- `certs/server.crt` - Signed server certificate

**Certificate Details**:
- Algorithm: ECDSA with secp384r1 (P-384)
- Validity: 10 years (3652 days)
- Extensions: `v3_server` (TLS Server Authentication)
- Signed by: CA root certificate

**Verify server certificate**:
```bash
openssl verify -CAfile certs/ca.crt certs/server.crt
# Expected: certs/server.crt: OK
```

**Check certificate chain**:
```bash
openssl x509 -in certs/server.crt -text -noout | grep -A 3 "Issuer"
# Issuer should be the CA root certificate
```

### Step 4: Initialize Certificate Revocation List (CRL)

```bash
make init_crl
```

This creates:
- `crl/ca.crl` - Certificate Revocation List (empty initially)

The CRL is used to publish revoked certificates. Initially empty, it's updated when certificates are revoked.

### Step 5: Verify Complete Setup

Check that all files were created:

```bash
ls -la certs/
# Should contain: ca.crt, server.crt

ls -la private/
# Should contain: ca.key, server.key

ls -la crl/
# Should contain: ca.crl
```

**Test certificate chain**:
```bash
cd CA
./scripts/verify-crt.sh certs/server.crt
# Expected: certs/server.crt: OK
```

## Generated Files

### Public Files (Safe to Distribute)

```
certs/ca.crt          # CA root certificate - distribute to all clients
certs/server.crt      # Server TLS certificate - install on server
crl/ca.crl            # Certificate Revocation List - publish publicly
```

### Private Files (SECRET - Protect with File Permissions)

```
private/ca.key        # CA private key - CRITICAL SECRET
private/server.key    # Server TLS private key - SECRET
```

**Set proper permissions**:
```bash
chmod 600 private/*.key
chmod 700 private/
```

### Database Files (CA State)

```
index.txt             # Certificate database (issued, revoked)
serial                # Next serial number for certificates
crlnumber             # Next CRL number
```

## Security Checklist

- [ ] CA private key (`private/ca.key`) has 600 permissions
- [ ] Private directory has 700 permissions
- [ ] CA private key is backed up (encrypted!)
- [ ] Backup is stored offline (USB, encrypted volume)
- [ ] Only CA administrator has access to `private/` directory
- [ ] CA certificate (`certs/ca.crt`) is distributed to all clients
- [ ] Server certificate is installed in Erlang app configuration

## Backup Procedure

**CRITICAL**: Back up CA private key immediately after generation!

```bash
# Create encrypted backup
cd CA
tar czf ca-backup-$(date +%Y%m%d).tar.gz \
    private/ certs/ca.crt index.txt* serial* crlnumber*

# Encrypt backup (requires GPG)
gpg --symmetric --cipher-algo AES256 ca-backup-$(date +%Y%m%d).tar.gz

# Move encrypted backup to safe location
mv ca-backup-*.tar.gz.gpg /secure/backup/location/

# Delete unencrypted backup
rm ca-backup-*.tar.gz
```

**Verify backup**:
```bash
# Decrypt and verify
gpg --decrypt ca-backup-*.tar.gz.gpg | tar tzv
# Should list: private/ca.key, certs/ca.crt, etc.
```

## Integration with Erlang Application

After generating CA certificates, configure the Erlang application to load them:

### Update sys.config

```erlang
{cryptic_ca, [
    %% CA certificate files (from myca)
    {ca_cert_file, "CA/certs/ca.crt"},
    {ca_key_file, "CA/private/ca.key"},
    
    %% Server certificate (for mTLS)
    {server_cert_file, "CA/certs/server.crt"},
    {server_key_file, "CA/private/server.key"},
    
    %% Certificate policy
    {cert_default_lifetime_days, 7},
    {cert_max_lifetime_days, 30}
]}
```

### Load at Application Startup

The `cryptic_ca_store` module will load these files at startup:

```erlang
% In cryptic_ca_store:init/0
{ok, CACertPEM} = file:read_file("CA/certs/ca.crt"),
{ok, CAKeyPEM} = file:read_file("CA/private/ca.key"),

% Parse PEM
[{_, CACertDER, _}] = public_key:pem_decode(CACertPEM),
CACert = public_key:pkix_decode_cert(CACertDER, otp),

[ECKey | _] = public_key:pem_decode(CAKeyPEM),
CAKey = public_key:pem_entry_decode(ECKey),

% Store in application environment
application:set_env(cryptic_ca, ca_cert, CACert),
application:set_env(cryptic_ca, ca_key, CAKey).
```

## Docker Deployment

When deploying with Docker, mount CA files as volumes:

```yaml
# docker-compose.yml
services:
  cryptic-server:
    volumes:
      # CA certificates (read-only)
      - ./CA/certs/ca.crt:/opt/cryptic/certs/ca.crt:ro
      - ./CA/certs/server.crt:/opt/cryptic/certs/server.crt:ro
      
      # CA private keys (read-only, secure!)
      - ./CA/private/ca.key:/opt/cryptic/certs/ca.key:ro
      - ./CA/private/server.key:/opt/cryptic/certs/server.key:ro
```

**Update sys.config for Docker paths**:
```erlang
{cryptic_ca, [
    {ca_cert_file, "/opt/cryptic/certs/ca.crt"},
    {ca_key_file, "/opt/cryptic/certs/ca.key"},
    {server_cert_file, "/opt/cryptic/certs/server.crt"},
    {server_key_file, "/opt/cryptic/certs/server.key"}
]}
```

## CA Rotation (Future)

When rotating CA (expiry, compromise, etc.):

1. Generate new CA using same procedure
2. Keep old CA certificate for verification of old certs
3. Issue new server certificate from new CA
4. Gradually migrate clients to new CA trust
5. Revoke old CA after grace period

## Troubleshooting

### Error: "SUBJECT.env file not found"

**Cause**: Missing subject configuration  
**Fix**: Run `./scripts/gen-subject-env.sh` to create it

### Error: "private/ca.key: Permission denied"

**Cause**: Wrong file permissions  
**Fix**: `chmod 600 private/ca.key`

### Error: "unable to load CA private key"

**Cause**: Corrupted key file or wrong path  
**Fix**: Verify file exists: `ls -la private/ca.key`  
**Fix**: Check file format: `openssl ec -in private/ca.key -text -noout`

### Certificate Verification Fails

**Symptom**: `openssl verify` returns error  
**Diagnosis**:
```bash
# Check certificate details
openssl x509 -in certs/server.crt -text -noout

# Verify issuer matches CA
openssl x509 -in certs/server.crt -noout -issuer
openssl x509 -in certs/ca.crt -noout -subject
# Issuer of server.crt should match subject of ca.crt
```

## Next Steps

After CA bootstrap is complete:

1. ✅ CA root certificate generated
2. ✅ Server certificate generated
3. ✅ Private keys secured
4. ✅ Backup created
5. → Implement `cryptic_ca_store` module (load CA cert/key)
6. → Implement `cryptic_ca_serial` module (serial number management)
7. → Implement `cryptic_ca_cert` module (client cert issuance)
8. → Update REST API to use certificate issuance

---

**See Also**:
- [PHASE3-CERTIFICATE-APPROACH.md](./PHASE3-CERTIFICATE-APPROACH.md) - Detailed implementation plan
- [CERTIFICATE-ISSUANCE-OPTIONS.md](./CERTIFICATE-ISSUANCE-OPTIONS.md) - Analysis of options
- [CA/README.md](../CA/README.md) - myca documentation
