# Admin-Mediated GPG Onboarding Design

## Overview

This document describes a simplified onboarding flow where
**administrators directly register user GPG keys** via the console,
eliminating the need for invite tokens, invite certificates, and
complex state machines.

## Core Principle

**Administrators are the gatekeepers**: Only authenticated admins can
register new users by storing their GPG public keys in the database.
Users then prove possession of the corresponding private key to receive
certificates.

## Security Model

### Authorization
- **Admin controls who joins**: Alice (authenticated admin) explicitly
  registers Bob's GPG key
- **No self-service**: Users cannot register themselves directly
- **Audit trail**: All registrations logged with admin fingerprint and timestamp

### Authentication  
- **Proof of possession**: Users must prove they control the GPG private key
  via signatures
- **No shared secrets**: No invite tokens to manage, expire, or steal
- **Two-factor by design**: Requires both admin approval (GPG key in DB) AND
  user's private key

### Defense in Depth
1. **Admin layer**: Only authenticated admins can register GPG keys (via mTLS console)
2. **Application layer**: `/ca/v1/csr` validates GPG fingerprint is registered
3. **Cryptographic layer**: User must sign CSR with registered GPG private key
4. **TLS layer**: Issued certificates validated at connection time via `verify_peer`

## Onboarding Flow

## Onboarding Flow

### Quick Start: Interactive Wizard (Recommended)

Bob can use the interactive wizard for a guided onboarding experience:

```bash
$ cryptic-onboard

   ╔═══════════════════════════════════════════════════════════════╗
   ║           Welcome to Cryptic Onboarding Wizard                ║
   ║                                                               ║
   ║  This wizard will guide you through the complete process      ║
   ║  of setting up your Cryptic secure messaging account.         ║
   ╚═══════════════════════════════════════════════════════════════╝

What would you like to do?

  1) Generate a new GPG key pair
  2) Export GPG public key for admin registration
  3) Request a TLS certificate from server
  4) Check certificate status and expiration
  5) Complete onboarding walkthrough (steps 1-3)
  6) Show help and documentation
  0) Exit

Enter your choice [0-6]:
```

**Option 5 (Complete walkthrough)** provides a step-by-step guided process:
- Checks for or generates GPG key
- Exports public key for admin
- Prompts to wait for admin registration
- Requests certificate from server
- Confirms successful onboarding

### Manual Process

For users who prefer direct commands:

### Step 1: Bob Generates GPG Key

Bob creates a GPG key pair using the wizard or manually:

**Using the wizard:**
```bash
$ cryptic-onboard
# Select option 1: Generate a new GPG key pair
```

**Using direct command:**
```bash
$ cryptic-onboard generate-gpg
Real name: Bob Smith
Email address: bob@example.com
Comment (optional): Cryptic user

✓ GPG key generated successfully!

Your new GPG key:
pub   rsa4096 2025-11-04 [SC] [expires: 2027-11-04]
      04764AB164BC1B9869162AAEB64C51FF9569D67B
uid           [ultimate] Bob Smith (Cryptic user) <bob@example.com>
sub   rsa4096 2025-11-04 [E] [expires: 2027-11-04]
```

**Or manually with gpg:**
```bash
$ gpg --full-generate-key
# Select: (1) RSA and RSA (default)
# Key size: 4096
# Expiration: 0 (does not expire, or set expiration)
# Real name: Bob Smith
# Email: bob@example.com
# Passphrase: <strong passphrase>

$ gpg --list-secret-keys --keyid-format LONG bob@example.com
sec   rsa4096/64C51FF9569D67B 2025-11-04 [SC]
      04764AB164BC1B9869162AAEB64C51FF9569D67B
uid                 [ultimate] Bob Smith <bob@example.com>
ssb   rsa4096/ABC123DEF456789 2025-11-04 [E]
```

**Fingerprint**: `04764AB164BC1B9869162AAEB64C51FF9569D67B`

### Step 2: Bob Exports Public Key for Alice

**Using the wizard:**
```bash
$ cryptic-onboard
# Select option 2: Export GPG public key for admin registration
```

**Using direct command:**
```bash
$ cryptic-onboard export-gpg
```

**Or manually:**
```bash
$ gpg --armor --export bob@example.com > bob_pubkey.asc
```

Bob sends the exported file to Alice via secure channel:
- Email (encrypted with Alice's GPG key)
- Signal/WhatsApp (file attachment)
- In-person (USB drive, QR code)
- Secure file transfer (SFTP, encrypted cloud storage)

### Step 3: Bob Sends Public Key to Alice

**Important**: Only the **public key** is shared. The private key never leaves
Bob's machine.

### Step 3: Alice Registers Bob's GPG Key

Alice connects to the server console (already authenticated with her GPG-based
certificate via mTLS WebSocket):

```erlang
%% Via WebSocket (/ca/ws) - send JSON command
{
  "type": "register_user",
  "gpg_fingerprint": "04764AB164BC1B9869162AAEB64C51FF9569D67B",
  "gpg_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "email": "bob@example.com",
  "metadata": {
    "name": "Bob Smith",
    "team": "Engineering",
    "notes": "New hire, started 2025-11-04"
  }
}
```

Server response:
```json
{
  "type": "register_user_response",
  "status": "success",
  "gpg_fingerprint": "04764AB164BC1B9869162AAEB64C51FF9569D67B",
  "registered_at": 1730736000,
  "registered_by": "ALICE_GPG_FINGERPRINT"
}
```

**Database operations**:
```sql
-- Insert GPG identity
INSERT INTO gpg_identities (
    fingerprint,
    email,
    public_key,
    registered_at,
    registered_by,
    status,
    metadata
) VALUES (
    '04764AB164BC1B9869162AAEB64C51FF9569D67B',
    'bob@example.com',
    '-----BEGIN PGP PUBLIC KEY BLOCK-----...',
    1730736000,
    'ALICE_GPG_FINGERPRINT',
    'active',
    '{"name": "Bob Smith", "team": "Engineering"}'
);

-- Audit log
INSERT INTO audit_log (
    timestamp,
    event_type,
    actor_fingerprint,
    target_fingerprint,
    details
) VALUES (
    1730736000,
    'user_registered',
    'ALICE_GPG_FINGERPRINT',
    '04764AB164BC1B9869162AAEB64C51FF9569D67B',
    '{"email": "bob@example.com", "method": "admin_mediated"}'
);
```

### Step 4: Bob Requests Certificate

After Alice confirms registration, Bob requests a certificate.

**Using the wizard:**
```bash
$ cryptic-onboard
# Select option 3: Request a TLS certificate from server
# Enter server URL (or press Enter for default)
```

**Using direct command:**
```bash
$ cryptic-onboard request https://relay.cryptic.example.org:8443

[1/5] Generating client key pair...
✓ Generated 2048-bit RSA key pair
  Private key: ~/.cryptic/04764AB.../private/client.key
  
[2/5] Creating CSR with GPG fingerprint in SAN...
✓ Created CSR with:
  CN: bob@example.com
  SAN: DNS:04764AB164BC1B9869162AAEB64C51FF9569D67B.gpg.cryptic.local

[3/5] Signing CSR with GPG key...
Enter GPG passphrase for 04764AB164BC1B9869162AAEB64C51FF9569D67B:
✓ Signed CSR with GPG private key

[4/5] Requesting certificate from server...
Connecting to https://relay.cryptic.example.org:8443/ca/v1/csr...
✓ Certificate issued successfully!

[5/5] Saving certificate...
✓ Certificate saved:
  ~/.cryptic/04764AB.../certs/client.pem
  
Certificate Details:
  Serial:         A1B2C3D4E5F6...
  Valid from:     2025-11-04 10:30:00 UTC
  Valid until:    2025-11-11 10:30:00 UTC (7 days)
  Fingerprint:    04764AB164BC1B9869162AAEB64C51FF9569D67B

✓ Setup complete! You can now connect to Cryptic.
```

**Or step-by-step manually:**
```bash
# Generate private key
openssl genrsa -out ~/.cryptic/client_key.pem 2048

# Create CSR with GPG fingerprint in SAN
openssl req -new \
  -key ~/.cryptic/client_key.pem \
  -out /tmp/client_csr.pem \
  -subj "/CN=bob@example.com/emailAddress=bob@example.com" \
  -addext "subjectAltName=DNS:04764AB164BC1B9869162AAEB64C51FF9569D67B.gpg.cryptic.local,email:bob@example.com"

# Sign the CSR with GPG private key to prove possession
gpg --detach-sign --armor -u 04764AB164BC1B9869162AAEB64C51FF9569D67B /tmp/client_csr.pem
```

### Step 5: CSR Submitted to Server (Automatic)

The `cryptic-onboard` script handles this automatically, but here's what happens:

```bash
curl -X POST https://cryptic.local:8443/ca/v1/csr \
  --cacert CA/certs/ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
    "gpg_fingerprint": "04764AB164BC1B9869162AAEB64C51FF9569D67B",
    "signature": "-----BEGIN PGP SIGNATURE-----\niQIzBAAB...\n-----END PGP SIGNATURE-----"
  }'
```

**Server validation** (in `cryptic_ca_rest_handler`):

```erlang
%% 1. Verify GPG fingerprint is registered
case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
    {ok, Identity} ->
        %% 2. Extract GPG public key
        PubKey = maps:get(public_key, Identity),
        
        %% 3. Verify signature on CSR
        case cryptic_gpg:verify_signature(CSR, Signature, PubKey) of
            true ->
                %% 4. Validate CSR structure
                case validate_csr(CSR, GpgFp) of
                    ok ->
                        %% 5. Sign certificate
                        sign_and_issue_certificate(CSR, GpgFp);
                    {error, Reason} ->
                        {error, {invalid_csr, Reason}}
                end;
            false ->
                {error, invalid_signature}
        end;
    {error, not_found} ->
        {error, gpg_not_registered}
end
```

**Certificate issuance**:
```erlang
%% Generate certificate with 7-day validity
NotBefore = erlang:universaltime(),
NotAfter = add_days(NotBefore, 7),

Certificate = #'OTPCertificate'{
    %% Subject: CN=bob@example.com
    %% SAN: DNS:04764AB164BC1B9869162AAEB64C51FF9569D67B.gpg.cryptic.local
    %%      EMAIL:bob@example.com
    %% Issuer: Cryptic CA
    %% Validity: 7 days
    %% Serial: unique
},

SignedCert = public_key:pkix_sign(Certificate, CAPrivateKey),

%% Store in database
cryptic_ca_store:insert_certificate(DbRef, #{
    serial => SerialNumber,
    gpg_fingerprint => GpgFp,
    issued_at => erlang:system_time(second),
    expires_at => calendar:datetime_to_gregorian_seconds(NotAfter),
    status => active
}),

%% Return to Bob
{ok, #{certificate => SignedCert, expires_at => NotAfter}}.
```

Server response:
```json
{
  "status": "success",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTC...\n-----END CERTIFICATE-----",
  "expires_at": "2025-11-11T10:00:00Z",
  "serial": "1A2B3C4D5E6F",
  "validity_days": 7
}
```

### Step 6: Bob Saves and Uses Certificate

```bash
[5/5] Certificate issued successfully!
✓ Saved certificate: ~/.cryptic/client_cert.pem
✓ Certificate expires: 2025-11-11 10:00:00 UTC (7 days)

Certificate details:
  Subject: CN=bob@example.com
  Issuer: CN=Cryptic CA
  Serial: 1A2B3C4D5E6F
  GPG Fingerprint: 04764AB164BC1B9869162AAEB64C51FF9569D67B
  Valid: 2025-11-04 to 2025-11-11

Onboarding complete! You can now connect to the server:
  $ cryptic --cert ~/.cryptic/client_cert.pem --key ~/.cryptic/client_key.pem
```

**Bob connects with mTLS**:
```bash
$ cryptic --cert ~/.cryptic/client_cert.pem --key ~/.cryptic/client_key.pem

Connecting to wss://cryptic.local:8443/ws...
✓ TLS handshake successful
✓ Certificate validated
✓ GPG fingerprint verified: 04764AB164BC1B9869162AAEB64C51FF9569D67B
✓ Connected as: bob@example.com

cryptic>
```

## Server Architecture

### Database Schema

**GPG Identities Table** (existing, minor updates):
```sql
CREATE TABLE gpg_identities (
    fingerprint TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    public_key TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    registered_by TEXT,  -- Fingerprint of admin who registered this user
    status TEXT NOT NULL DEFAULT 'active',  -- active, suspended, revoked
    metadata TEXT,  -- JSON: {name, team, notes, etc.}
    
    FOREIGN KEY (registered_by) REFERENCES gpg_identities(fingerprint),
    CHECK (status IN ('active', 'suspended', 'revoked'))
);

CREATE INDEX idx_gpg_email ON gpg_identities(email);
CREATE INDEX idx_gpg_status ON gpg_identities(status);
CREATE INDEX idx_gpg_registered_by ON gpg_identities(registered_by);
```

**Certificates Table** (existing):
```sql
CREATE TABLE certificates (
    serial TEXT PRIMARY KEY,
    gpg_fingerprint TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_reason TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    
    FOREIGN KEY (gpg_fingerprint) REFERENCES gpg_identities(fingerprint),
    CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_cert_fingerprint ON certificates(gpg_fingerprint);
CREATE INDEX idx_cert_expires ON certificates(expires_at);
CREATE INDEX idx_cert_status ON certificates(status);
```

**Audit Log Table** (existing):
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor_fingerprint TEXT,  -- Who performed the action
    target_fingerprint TEXT,  -- Who was affected
    details TEXT,  -- JSON with event-specific data
    ip_address TEXT,
    
    FOREIGN KEY (actor_fingerprint) REFERENCES gpg_identities(fingerprint),
    FOREIGN KEY (target_fingerprint) REFERENCES gpg_identities(fingerprint)
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_actor ON audit_log(actor_fingerprint);
CREATE INDEX idx_audit_target ON audit_log(target_fingerprint);
```

### Endpoints

#### Authenticated Endpoints (Require mTLS)

**`/ca/ws` - CA WebSocket** (existing):
- Admin commands: `register_user`, `list_users`, `suspend_user`, `revoke_user`
- User commands: `get_my_info`, `list_my_certificates`, `revoke_my_certificate`
- Authentication: GPG fingerprint extracted from client certificate SAN
- Authorization: Admin-only commands check user role/permissions

**`/ws` - General WebSocket** (existing):
- Chat and messaging
- Requires valid client certificate with registered GPG fingerprint

#### Unauthenticated Endpoint

**`POST /ca/v1/csr` - Certificate Signing Request**:
- **Input**: CSR + GPG fingerprint + GPG signature on CSR
- **Validation**:
  1. GPG fingerprint exists in database
  2. GPG fingerprint status is 'active'
  3. CSR contains matching GPG fingerprint in SAN
  4. Signature on CSR is valid (proves private key possession)
- **Output**: Signed X.509 certificate
- **Rate limiting**: 5 requests per fingerprint per hour
- **Security**: Can't be abused - requires registered GPG key + private key

### TLS Configuration

**Port 8443** (mTLS for authenticated endpoints):
```erlang
TLSOptions = [
    {verify, verify_peer},
    {verify_fun, {fun verify_peer/4, []}},
    {fail_if_no_peer_cert, false},  % Allow /ca/v1/csr without cert
    {versions, ['tlsv1.2', 'tlsv1.3']},
    {cacertfile, "CA/certs/ca.crt"},
    {certfile, "CA/certs/server.crt"},
    {keyfile, "CA/private/server.key"}
]
```

**verify_peer callback**:
```erlang
verify_peer(_OtpCert, _DerCert, {extension, Extension}, UserState) ->
    case Extension of
        %% SAN extension with GPG fingerprint
        {'Extension', {2,5,29,17}, _Critical, SANValues} ->
            case extract_gpg_from_san(SANValues) of
                {ok, GpgFp} ->
                    %% Verify GPG fingerprint is registered
                    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
                        {ok, Identity} ->
                            Status = maps:get(status, Identity),
                            if
                                Status =:= <<"active">> ->
                                    {valid, UserState#{
                                        auth_type => gpg,
                                        gpg_fingerprint => GpgFp,
                                        email => maps:get(email, Identity)
                                    }};
                                true ->
                                    {fail, {bad_cert, user_not_active}}
                            end;
                        {error, not_found} ->
                            {fail, {bad_cert, gpg_not_registered}}
                    end;
                {error, _} ->
                    {unknown, UserState}
            end;
        _ ->
            {unknown, UserState}
    end;

verify_peer(_OtpCert, _DerCert, valid_peer, UserState) ->
    {valid, UserState};

verify_peer(_OtpCert, _DerCert, {bad_cert, Reason}, _UserState) ->
    {fail, {bad_cert, Reason}}.
```

**Handler-level access control**:
```erlang
%% In cryptic_ca_rest_handler:init/2
init(Req, State = #{operation := Operation}) ->
    case Operation of
        csr ->
            %% Unauthenticated endpoint - validate in handler
            handle_csr(Req, State);
        
        _ ->
            %% All other operations require mTLS
            case cowboy_req:cert(Req) of
                undefined ->
                    reply_error(Req, 401, <<"Client certificate required">>);
                _Cert ->
                    %% Authenticated - proceed
                    handle_operation(Req, State)
            end
    end.
```

## Removed Components

Since we're eliminating invite tokens and invite certificates, the following are **not needed**:

❌ **Invites Table**: No invite token management
❌ **Invite Certificates**: Users never get temporary bootstrap certificates  
❌ **State Machine**: No active → registered → consumed transitions
❌ **Invite Token Expiration**: No time-limited tokens to track
❌ **`/ca/v1/invite-cert` Endpoint**: No invite certificate issuance
❌ **Invite Token Validation in verify_peer**: Only validate GPG fingerprints

## Updated Components

### cryptic_ca_store.erl

**Remove**:
- `create_invite/2`
- `get_invite/2`
- `update_invite_status/4`
- `list_invites_by_inviter/2`
- Invites table schema

**Add/Update**:
- `register_user/2` - Store GPG identity (called by admin)
- `get_gpg_identity/2` - Already exists
- `update_gpg_status/3` - Suspend/activate/revoke users

### cryptic_ca_rest_handler.erl

**Update**:
- `handle_csr/2` - Validate GPG fingerprint + signature, issue certificate
- Remove `register_gpg` operation (now admin-only via WebSocket)

### cryptic_ca_ws_handler.erl

**Add**:
- `register_user` command (admin only)
- `list_users` command (admin only)
- `suspend_user` command (admin only)
- `revoke_user` command (admin only)

### cryptic-onboard script

**Simplify**:
```bash
#!/bin/bash
# Usage: cryptic-onboard --gpg-fp <fingerprint>

# 1. Generate client key pair
# 2. Create CSR with GPG fingerprint in SAN
# 3. Sign CSR with GPG private key
# 4. POST to /ca/v1/csr
# 5. Save certificate
```

## Implementation Plan

### Phase 1: Update Database Schema ✅ (Mostly Done)
- ✅ GPG identities table already exists
- ✅ Certificates table already exists  
- ✅ Audit log table already exists
- ⏳ Add `registered_by` column to gpg_identities
- ⏳ Remove invites table (or deprecate)

### Phase 2: Implement `/ca/v1/csr` Endpoint
- Create REST handler for CSR submission
- Validate GPG fingerprint is registered
- Verify GPG signature on CSR
- Sign and issue certificate (7-day validity)
- Store certificate record in database
- Return signed certificate to client

### Phase 3: Admin Commands via WebSocket
- `register_user` - Alice registers Bob's GPG key
- `list_users` - View all registered users
- `suspend_user` - Temporarily disable user
- `revoke_user` - Permanently disable user
- `get_user_info` - View user details

### Phase 4: Update cryptic-onboard Script
- Generate client key pair
- Create CSR with GPG fingerprint in SAN
- Sign CSR with GPG private key
- Submit to `/ca/v1/csr`
- Save certificate locally

### Phase 5: Certificate Lifecycle Management
- Auto-renewal reminder (client-side)
- Certificate rotation (before expiration)
- Revocation checking
- Expired certificate cleanup

### Phase 6: Testing
- Test admin registration flow
- Test CSR submission and signing
- Test signature validation
- Test suspended/revoked user rejection
- Test certificate expiration
- Test mTLS connection with issued cert

### Phase 7: Documentation
- Update onboarding guide
- Document admin commands
- Update security architecture docs
- Create troubleshooting guide

## Security Considerations

### Threat Model

| Attack Vector | Mitigation |
|---------------|------------|
| **Unauthorized registration** | Only authenticated admins can register users (via mTLS WebSocket) |
| **Stolen GPG public key** | Useless without private key to sign CSR |
| **CSR replay attack** | Each CSR generates unique certificate serial; old certs expire |
| **Man-in-the-middle** | TLS with CA certificate validation |
| **Compromised certificate** | Admin can revoke via WebSocket; certificate expires in 7 days |
| **Compromised GPG private key** | Admin can suspend/revoke user; certificate becomes invalid |
| **DoS on /ca/v1/csr** | Rate limiting per GPG fingerprint; signature validation is expensive for attacker |

### Advantages Over Invite Tokens

✅ **Simpler**: No token lifecycle management
✅ **No shared secrets**: No tokens to steal, leak, or intercept
✅ **Direct trust**: Admin explicitly approves each user
✅ **Fewer attack vectors**: One unauthenticated endpoint vs. two
✅ **Better audit trail**: Clear record of who registered whom
✅ **No expiration complexity**: No need to track token expiration
✅ **Self-documenting**: GPG key contains user identity

### Trade-offs

⚠️ **Admin overhead**: Alice must manually register each user (but this is also a feature - explicit approval)
⚠️ **Out-of-band key exchange**: Bob must send GPG key to Alice securely
⚠️ **No self-service**: Users can't onboard themselves (but this is intentional)

## Comparison: Invite Tokens vs Admin-Mediated

| Aspect | Invite Tokens | Admin-Mediated |
|--------|---------------|----------------|
| **Complexity** | High (state machine) | Low (direct registration) |
| **Components** | Invites table, tokens, invite certs | Just GPG identities |
| **User experience** | Self-service after getting token | Admin must register |
| **Security** | Token + GPG key | GPG key only |
| **Attack surface** | 2 unauthenticated endpoints | 1 unauthenticated endpoint |
| **Expiration** | Tokens expire, complex cleanup | Certificates expire (simpler) |
| **Audit trail** | Who created invite, when used | Who registered whom |
| **Scalability** | Better for large teams | Better for small teams |
| **Control** | Admin creates invites ahead of time | Admin registers on-demand |

## Conclusion

The **Admin-Mediated GPG Registration** approach is simpler, more secure, and easier to maintain than invite tokens. It eliminates:
- Invite token management
- State machine complexity  
- Temporary invite certificates
- Multiple unauthenticated endpoints

While it requires more admin involvement (Alice must manually register Bob's GPG key), this provides:
- Explicit authorization control
- Clearer audit trail
- Simpler codebase
- Fewer security attack vectors

This approach is ideal for **small to medium teams** where admins can directly manage user onboarding.
