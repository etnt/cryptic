# Implementation Plan: Invitation-Based GPG Registration Protocol

    Project: Cryptic Secure Messaging
    Feature: GPG-based Certificate Authority with Invitation System
    Status: Planning Phase
    Created: 2025-10-27

## Executive Summary

This document outlines the implementation plan for adding invitation-based
onboarding to the Cryptic messaging system using GPG identities and short-lived
TLS certificates. The system enables existing verified users to invite new
users through cryptographically signed tokens, eliminating the need for manual
admin approval while maintaining strong identity verification.

## Goals & Requirements

### Primary Goals

1. **Decentralized Trust**: Enable existing users to onboard new users without admin intervention
2. **Strong Identity**: Use GPG keys as root of trust for certificate issuance
3. **Privacy-Preserving**: Store only GPG fingerprints, no PII required
4. **Security**: Defend against replay, forgery, and token leakage attacks
5. **Federation-Ready**: Design compatible with federated server architecture

### Non-Goals

- Replacing existing X3DH/Double Ratchet message encryption
- Building a full PKI infrastructure with intermediate CAs
- Supporting non-GPG identity mechanisms (initially)

### Success Criteria

- [ ] New users can register with invite token + GPG key
- [ ] Users can request and receive short-lived TLS certificates
- [ ] Certificates automatically renew before expiry
- [ ] Invite tokens are one-time use with expiration
- [ ] System tracks invitation chain for accountability
- [ ] Zero PII storage (only GPG fingerprints)

## Architecture Overview

### Key Components

```
┌─────────────────────────────────────────────────────────────────┐
│                  Cryptic Server (CA)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────┐      ┌────────────────┐                     │
│  │  Invite Token  │      │   GPG Registry │                     │
│  │    Manager     │◄────►│   (esqlite)    │                     │
│  └────────────────┘      └────────────────┘                     │
│         │                         │                             │
│         │                         │                             │
│         ▼                         ▼                             │
│  ┌────────────────┐      ┌────────────────┐                     │
│  │  GPG Verifier  │      │  Certificate   │                     │
│  │  (erl_gpg)     │      │    Issuer      │                     │
│  │                │      │    (myca)      │                     │
│  └────────────────┘      └────────────────┘                     │
│         │                         │                             │
│         └─────────┬───────────────┘                             │
│                   │                                             │
│                   ▼                                             │
│         ┌────────────────────┐                                  │
│         │  WebSocket API     │                                  │
│         │  + REST Endpoints  │                                  │
│         │      (Cowboy)      │                                  │
│         └────────────────────┘                                  │
│                   │                                             │
└───────────────────┼─────────────────────────────────────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Trusted Client      │
         │  (cryptic_console)   │
         ├──────────────────────┤
         │ - Invite creation UI │
         │ - GPG registration   │
         │ - Cert requests      │
         │ - Auto renewal       │
         └──────────────────────┘
```

## Client vs Server Responsibilities

### Server Responsibilities (Cryptic Server)

**Storage** (using esqlite):
- Invite tokens and consumption tracking
- GPG registry (fingerprints, public keys, status)
- Audit logs (encrypted if needed)

**Verification**:
- GPG signature validation (using `erl_gpg`)
- Token expiry and one-time use enforcement
- Fingerprint verification

**Certificate Operations** (using `myca`):
- CSR validation
- Certificate issuance (default: 7 days, configurable)
- Serial number management
- Certificate renewal

**API Endpoints**:
- WebSocket API for trusted client operations
- REST endpoints for certificate requests

### Client Responsibilities (Trusted Client - cryptic_console)

**User Interface**:
- Invite creation command (`:invite create`)
- Registration workflow
- Certificate request commands
- Status checking

**Local Operations**:
- GPG key management (generation, export)
- TLS key pair generation
- CSR creation
- GPG signing of CSRs
- Certificate renewal automation

**Communication**:
- WebSocket connection to server
- Secure transmission of invite requests
- Certificate retrieval and storage

### Data Flow

**Onboarding Flow**:
```
Alice (Inviter)     → Uses :invite create in cryptic_console
   via WebSocket   ↓
Server              → Creates signed invite token
                    → Returns token to Alice
                    ↓
Alice               → Sends token to Bob (out-of-band: QR, email, etc.)
                    ↓
Bob (Invitee)       → Generates GPG key (if needed)
                    → Exports GPG public key
                    ↓
Bob                 → POST /ca/v1/register-gpg (token + GPG pubkey)
                    ↓
Server              → Verifies Alice's signature (using erl_gpg)
                    → Validates token expiry
                    → Marks token consumed
                    → Registers Bob's GPG fingerprint (esqlite)
                    ↓
Bob                 → Generates TLS key pair
                    → Creates CSR
                    → Signs CSR with GPG key
                    ↓
Bob                 → POST /ca/v1/csr (CSR + GPG signature)
                    ↓
Server              → Validates GPG signature
                    → Issues certificate (using myca, 7 days default)
                    ↓
Bob                 → Uses certificate for mTLS connections
                    → Auto-renews before expiry
```

### Two-Key Architecture

| Key Type    | Purpose        | Lifespan            | Usage                      |
|-------------|----------------|---------------------|----------------------------|
| **GPG Key** | Identity proof | Years               | Sign invites, CSRs, proofs |
| **TLS Key** | Session auth   | 7 days (default)    | mTLS connections           |

## Implementation Phases

### Phase 1: Foundation & Storage (Week 1-2) ✅ COMPLETED

**Objective**: Set up SQLite storage and integrate erl_gpg library

#### Tasks

1. **Database Schema Design (esqlite)**
   - [x] Design SQLite schema for invite storage
   - [x] Design schema for GPG registry
   - [x] Create migration scripts
   - [x] Add indexes for fingerprint lookups
   - [x] Implement encrypted storage (reuse existing cryptic code)

2. **GPG Integration (erl_gpg library)**
   - [x] Integrate existing `erl_gpg` library
   - [x] Implement signature verification wrapper
   - [x] Implement fingerprint computation wrapper
   - [x] Test token signing and verification
   - [x] Document erl_gpg usage patterns

3. **Storage Modules**
   ```erlang
   cryptic_ca_store.erl      % SQLite storage abstraction (esqlite)
   cryptic_invite_mgr.erl    % Invite lifecycle management
   cryptic_gpg_registry.erl  % GPG key registry operations
   ```

#### Deliverables

- [x] Working GPG signature verification (via erl_gpg)
- [x] SQLite schema implemented (esqlite)
- [x] Basic storage operations (CRUD)
- [x] Unit tests for storage layer (45/45 tests passing)

#### Storage Schema (SQLite via esqlite)

```sql
-- Invites table
CREATE TABLE invites (
    invite_id TEXT PRIMARY KEY,
    inviter_fp TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER DEFAULT 0,
    consumed_at INTEGER,
    consumed_by_fp TEXT,
    meta TEXT,  -- JSON blob
    FOREIGN KEY (inviter_fp) REFERENCES gpg_identities(gpg_fp)
);

CREATE INDEX idx_invites_inviter ON invites(inviter_fp);
CREATE INDEX idx_invites_expires ON invites(expires_at);

-- GPG Registry table
CREATE TABLE gpg_identities (
    gpg_fp TEXT PRIMARY KEY,
    gpg_pub_armor TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('verified_via_invite', 'verified_bootstrap', 'pending', 'revoked')),
    inviter_fp TEXT,  -- NULL for bootstrap users
    registered_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    invite_id TEXT,  -- NULL for bootstrap users
    FOREIGN KEY (invite_id) REFERENCES invites(invite_id)
);

CREATE INDEX idx_gpg_status ON gpg_identities(status);
CREATE INDEX idx_gpg_inviter ON gpg_identities(inviter_fp);

-- Audit log table
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    gpg_fp TEXT,
    invite_id TEXT,
    details TEXT,  -- JSON blob
    ip_address TEXT
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_type ON audit_log(event_type);
```

**Note**: Sensitive data (GPG public keys, invite metadata) will be encrypted
using the same encryption approach already used in cryptic's message storage.

### Phase 2: API Implementation (Week 2-3) ✅ COMPLETED

**Objective**: Implement WebSocket and REST APIs for invite and certificate operations

#### Tasks

1. **WebSocket API Design (for cryptic_console)**
   - [x] Design WebSocket message protocol for invite operations
   - [x] Implement authentication for WebSocket connections (using existing mTLS)
   - [x] Add rate limiting for invite creation
   - [x] Implement invite creation handler
   - [x] Implement status query handlers

2. **REST API Design (for certificate operations)**
   - [x] Define REST endpoints for registration and cert requests
   - [x] Implement request/response schemas
   - [x] GPG signature validation (using erl_gpg)
   - [x] Design rate limiting policies

3. **Endpoint Implementation**
   ```erlang
   cryptic_ca_ws_handler.erl    % WebSocket handlers for trusted clients
   cryptic_ca_rest_handler.erl  % REST handlers for cert operations
   cryptic_ca_rate_limiter.erl  % Token bucket rate limiting
   ```

   **WebSocket Commands** (from cryptic_console):
   - [x] `invite_create` - Create invite token
   - [x] `invite_list` - List my created invites
   - [x] `invite_revoke` - Revoke unused invite
   - [x] `status_check` - Check registration status
   - [x] `gpg_register_bootstrap` - Register GPG key for existing mTLS user (bootstrap)

   **REST Endpoints** (public access):
   - [x] `POST /ca/v1/register-gpg` - Register with invite
   - [x] `POST /ca/v1/csr` - Request certificate (placeholder for Phase 3)
   - [x] `GET /ca/v1/status/:fingerprint` - Check status

2. **Request Validation**
   - [x] WebSocket message validation for invite commands
   - [x] JSON schema validation for REST endpoints
   - [x] GPG signature validation (erl_gpg)
   - [x] Token expiry checking
   - [x] Input sanitization

3. **Rate Limiting Implementation**
   - [x] Token bucket algorithm implementation
   - [x] Per-IP rate limits (register_gpg, status)
   - [x] Per-GPG fingerprint limits (invite_create, invite_list, invite_revoke, csr)
   - [x] Configurable policies via sys.config
   - [x] ETS-based storage with automatic cleanup
   - [x] Statistics and monitoring support
   - [x] Unit tests (7/7 passing)

#### API Specifications

**WebSocket Commands** (from cryptic_console, authenticated via existing mTLS):

**invite_create**:
```erlang
% Request (WebSocket message from cryptic_console)
{invite_create, #{
  expiry_hours => 24,
  meta => #{note => <<"Inviting Bob">>}
}}

% Response
{invite_created, #{
  invite_id => <<"inv-8f3b12a4">>,
  token => <<"-----BEGIN PGP SIGNED MESSAGE-----...">>,
  expires_at => <<"2025-10-28T12:00:00Z">>
}}
```

**invite_list**:
```erlang
% Request
{invite_list, #{}}

% Response
{invite_list, [
  #{invite_id => <<"inv-8f3b12a4">>, 
    expires_at => <<"2025-10-28T12:00:00Z">>,
    consumed => false}
]}
```

**invite_revoke**:
```erlang
% Request
{invite_revoke, #{invite_id => <<"inv-8f3b12a4">>}}

% Response
{invite_revoked, #{invite_id => <<"inv-8f3b12a4">>}}
```

**gpg_register_bootstrap** (for users with existing mTLS certificates):
```erlang
% Request (WebSocket message from authenticated cryptic_console)
{gpg_register_bootstrap, #{
  gpg_pub => <<"-----BEGIN PGP PUBLIC KEY BLOCK-----...">>,
  proof => <<"signed-challenge-response">>  % GPG signature of server challenge
}}

% Response
{gpg_registered, #{
  gpg_fp => <<"6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A">>,
  status => <<"verified_bootstrap">>,
  registered_at => <<"2025-10-27T10:30:00Z">>
}}
```

**Note**: The bootstrap registration is for the initial admin user(s) who
already have TLS certificates but need to register their GPG key to start
creating invites. This uses the existing mTLS authentication to prove identity,
then associates a GPG key with that authenticated connection.

---

**REST Endpoints** (public access for certificate operations):

**POST /ca/v1/register-gpg** (Public)
```json
Request:
{
  "invite_token": "-----BEGIN PGP SIGNED MESSAGE-----...",
  "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
  "bind_proof": "BASE64(...)"  // Optional nonce signature
}

Response:
{
  "status": "verified",
  "gpg_fp": "6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A",
  "issued_at": "2025-10-27T10:30:00Z"
}
```

**POST /ca/v1/csr** (Authenticated via GPG signature)
```json
Request:
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "gpg_fp": "6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A",
  "gpg_sig_b64": "BASE64(...)"
}

Response:
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "expires_at": "2025-10-28T10:30:00Z",
  "issued_at": "2025-10-27T10:30:00Z"
}
```

#### Deliverables

- [x] All REST endpoints implemented
- [x] All WebSocket commands implemented
- [x] Request validation complete
- [x] Cowboy routing configuration
- [x] Rate limiting implementation (token bucket algorithm)
- [x] Integration tests for happy path (basic, comprehensive pending)
- [x] Error handling for edge cases
- [x] Documentation complete (RATE-LIMITING.md)

**Status**: ✅ Phase 2 Complete - All core API functionality implemented including comprehensive rate limiting with token bucket algorithm. Ready for Phase 3 (Certificate Issuance).

### Phase 3: Certificate Issuance (Week 3-4) ✅ COMPLETED

**Objective**: Implement certificate issuance using pure Erlang approach

**Approach**: Use **Erlang public_key for all certificate operations** (production-safe, high-performance). See [PHASE3-CERTIFICATE-APPROACH.md](./PHASE3-CERTIFICATE-APPROACH.md), [CERTIFICATE-ISSUANCE-OPTIONS.md](./CERTIFICATE-ISSUANCE-OPTIONS.md), and [PHASE3-COMPLETION-REPORT.md](./PHASE3-COMPLETION-REPORT.md) for detailed analysis.

#### Tasks

1. **CA Bootstrap (one-time setup)**
   - [x] Generate CA root certificate using OpenSSL
   - [x] Generate server certificate using OpenSSL
   - [x] Document CA bootstrap procedure
   - [x] Securely store CA private key (file permissions)
   - [x] Configure CA certificate paths in sys.config

2. **Certificate Modules (Erlang public_key)**
   ```erlang
   cryptic_ca_store.erl      % Load CA cert/key at startup
   cryptic_ca_serial.erl     % Serial number management (ETS)
   cryptic_ca_cert.erl       % Client cert issuance (public_key)
   ```

3. **CA Certificate Loader (cryptic_ca_store.erl)**
   - [x] Load CA certificate from PEM file
   - [x] Load CA private key from PEM file (secure permissions)
   - [x] Parse using public_key:pem_decode/1
   - [x] Store in application environment
   - [x] Validate CA certificate and key pair

4. **Serial Number Management (cryptic_ca_serial.erl)**
   - [x] Initialize serial number counter (ETS table)
   - [x] Implement atomic increment (thread-safe)
   - [x] Add persistence support (backup/recovery)
   - [x] Handle counter overflow (reset after threshold)

5. **Client Certificate Issuance (cryptic_ca_cert.erl)**
   - [x] Parse CSR using public_key:pem_decode/1
   - [x] Extract subject and public key from CSR
   - [x] Build OTPTBSCertificate record (manual ASN.1)
   - [x] Sign using public_key:pkix_sign/2 (production-safe)
   - [x] Encode to PEM using public_key:pem_encode/1
   - [x] Add GPG fingerprint to Subject Alternative Name

6. **Certificate Extensions**
   - [x] Key Usage: Digital Signature + Key Encipherment
   - [x] Extended Key Usage: TLS Client Authentication
   - [x] Subject Alternative Name: GPG fingerprint (custom OID)
   - [x] Validity period: 7 days default, configurable

7. **Security Controls**
   - [x] CSR cryptographic signature verification (public_key:verify/4)
   - [x] Multi-algorithm support (ECDSA, RSA, DSA, EdDSA)
   - [x] Fingerprint verification (must be in gpg_identities table)
   - [x] Rate limiting per fingerprint (integrated from Phase 2)
   - [x] Certificate lifetime enforcement (7 days default, max 30)
   - [x] CSR validation (structural + cryptographic)

8. **Integration with REST API**
   - [x] Update POST /ca/v1/csr handler to use cryptic_ca_cert
   - [x] Add certificate validation before issuance
   - [x] Implement certificate issuance workflow
   - [x] Return certificate with metadata (expiry, serial)

#### Certificate Policy

- **Validity**: **7 days (default)**, configurable (1-30 days)
- **Key Algorithm**: ECDSA with secp384r1 (P-384)
- **Signature Algorithm**: SHA256withECDSA
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: TLS Web Client Authentication
- **Subject**: CN=<gpg_fingerprint>@cryptic.example.org
- **SAN**: GPG fingerprint in otherName field (custom OID)

#### Implementation Notes

**Pure Erlang Approach:**
- **Erlang public_key**: All certificate operations (CA + client certs)
- **Security**: Production-safe ASN.1 record construction with `pkix_sign/2`
- **Performance**: No shell overhead (40-500x faster than OpenSSL CLI)
- **Type Safety**: Compile-time verification of ASN.1 structures

**Production-Safe Certificate Construction:**
```erlang
% DON'T use test helpers:
% {Cert, Key} = public_key:pkix_test_root_cert("CA", Opts)  % TEST ONLY!

% DO use manual ASN.1 construction:
TBSCert = #'OTPTBSCertificate'{...},  % Manual record
Cert = #'OTPCertificate'{tbsCertificate = TBSCert, ...},
SignedCert = public_key:pkix_sign(Cert, CAKey)  % PRODUCTION SAFE
```

#### Deliverables

- [x] CA root certificate generated (OpenSSL)
- [x] Server certificate generated (OpenSSL)
- [x] CA cert/key loader implemented (cryptic_ca_store)
- [x] Serial number manager implemented (cryptic_ca_serial)
- [x] Client cert issuance implemented (cryptic_ca_cert)
- [x] CSR validation working (structural + cryptographic)
- [x] Certificate issuance functional (7 day default)
- [x] Multi-algorithm support (ECDSA, RSA, DSA, EdDSA)
- [x] OpenSSL compatibility verified
- [x] Unit tests for all modules (7/7 passing)
- [x] Integration with REST API complete
- [x] Phase 3 completion report documented

**Status**: ✅ **Phase 3 Complete** - Full certificate issuance with cryptographic signature verification implemented. All 7 tests passing. See [PHASE3-COMPLETION-REPORT.md](./PHASE3-COMPLETION-REPORT.md) for detailed analysis.

### Phase 4: Client Tools & UX (Week 4-5)

**Objective**: Build client tooling for onboarding and certificate management

**Key Design Decision**: Split tooling based on authentication state:
- **Pre-authentication** (no cert yet): External bash script for registration and initial cert request
- **Post-authentication** (has cert): Console commands within `cryptic_console` for management

#### Tool Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Client-Side Tooling                                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  External Script (cryptic-onboard)                                  │
│  ├─ register <invite_file>      # POST /ca/v1/register-gpg          │
│  ├─ request                      # POST /ca/v1/csr                  │
│  └─ info <cert_file>             # Display cert details (OpenSSL)   │
│                                                                     │
│  Console Commands (cryptic_console) - requires mTLS                 │
│  ├─ invite create                # WebSocket to server              │
│  ├─ invite list                  # WebSocket to server              │
│  ├─ invite show <id>             # WebSocket to server              │
│  ├─ invite revoke <id>           # WebSocket to server              │
│  ├─ cert status                  # Check local cert + query server  │
│  └─ cert renew                   # Request new cert via WebSocket   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 1. External Onboarding Script (`bin/cryptic-onboard`)

This bash script handles the initial registration and certificate request workflow for **new users who don't have certificates yet**.

**Why bash script?**
- ✅ No mTLS required (uses public REST API)
- ✅ Simple dependency (just `curl`, `openssl`, `gpg`)
- ✅ Can be run before cryptic_console access
- ✅ Easy to share and audit
- ✅ Works on any Unix-like system

##### Script Commands

**`cryptic-onboard register <invite_file>`** - Register GPG key with CA

```bash
#!/bin/bash
# Usage: cryptic-onboard register ~/Downloads/alice-invite.txt

# 1. Read invite token from file
INVITE_TOKEN=$(cat "$1")

# 2. Export GPG public key (auto-detect or prompt)
GPG_KEY_EMAIL="bob@example.com"  # From user or GPG default
GPG_PUBKEY=$(gpg --armor --export "$GPG_KEY_EMAIL")

# 3. Call REST API
curl -X POST https://ca.cryptic.example.org/ca/v1/register-gpg \
  -H "Content-Type: application/json" \
  -d "{
    \"invite_token\": \"$INVITE_TOKEN\",
    \"gpg_pub\": \"$GPG_PUBKEY\"
  }"

# 4. Save GPG fingerprint to ~/.cryptic/config.json
# Output: "✓ Registration successful! GPG FP: ABC123..."
```

**Output**:
```bash
$ cryptic-onboard register alice-invite.txt

Cryptic Registration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1/3] Reading invite token...                               ✓
[2/3] Exporting GPG public key (bob@example.com)...         ✓
[3/3] Submitting to CA...                                   ✓

✓ Registration successful!

GPG Fingerprint: ABC123DEF456...
Status:          verified_via_invite
Registered:      2025-11-01 16:00:00 UTC

Configuration saved to ~/.cryptic/config.json

Next step: Request your first certificate
  cryptic-onboard request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**`cryptic-onboard request <username> [server_url]`** - Request TLS certificate

```bash
#!/bin/bash
# Usage: cryptic-onboard request alice
#        cryptic-onboard request alice wss://relay.cryptic.example.org:8443

USERNAME="$1"
if [ -z "$USERNAME" ]; then
    echo "Error: Username required"
    echo "Usage: cryptic-onboard request <username> [server_url]"
    exit 1
fi

# Parse server URL to extract host and port
CA_URL="${2:-wss://relay.cryptic.example.org:8443}"
SERVER_HOST=$(echo "$CA_URL" | sed -E 's|^wss?://([^:/]+).*|\1|')
SERVER_PORT=$(echo "$CA_URL" | sed -E 's|^wss?://[^:]+:([0-9]+).*|\1|')
SERVER_PORT="${SERVER_PORT:-8443}"  # Default to 8443 if not specified

# Create user and server-specific directory structure
CERT_DIR="${HOME}/.cryptic/${USERNAME}/${SERVER_HOST}_${SERVER_PORT}"
CERT_SUBDIR="${CERT_DIR}/certificates"
KEY_SUBDIR="${CERT_DIR}/private"
mkdir -p "$CERT_SUBDIR" "$KEY_SUBDIR"

GPG_FP=$(jq -r '.gpg_fingerprint' ~/.cryptic/config.json)

# 1. Generate TLS key pair (or reuse existing)
KEY_FILE="${KEY_SUBDIR}/client.key"
if [ ! -f "$KEY_FILE" ]; then
    openssl ecparam -genkey -name secp384r1 -out "$KEY_FILE"
    chmod 600 "$KEY_FILE"
fi

# 2. Create CSR
CSR_FILE="${CERT_DIR}/client.csr"
openssl req -new -key "$KEY_FILE" \
  -subj "/CN=${GPG_FP}@${SERVER_HOST}" \
  -out "$CSR_FILE"

# 3. Sign CSR with GPG key
CSR_DATA=$(cat "$CSR_FILE")
GPG_SIG=$(echo "$CSR_DATA" | gpg --armor --detach-sign)

# 4. Submit to CA (convert wss:// to https:// for REST API)
CA_REST_URL="https://${SERVER_HOST}:${SERVER_PORT}"
CERT_FILE="${CERT_SUBDIR}/client.pem"

curl -X POST "${CA_REST_URL}/ca/v1/csr" \
  -H "Content-Type: application/json" \
  -d "{
    \"csr_pem\": \"$CSR_DATA\",
    \"gpg_fp\": \"$GPG_FP\",
    \"gpg_sig_b64\": \"$(echo "$GPG_SIG" | base64)\"
  }" | jq -r '.cert_pem' > "$CERT_FILE"

# 5. Display success
echo "✓ Certificate issued! Saved to ${CERT_FILE}"
echo "  Private key: ${KEY_FILE}"
```

**Output**:
```bash
$ cryptic-onboard request bob wss://relay.cryptic.example.org:8443

Certificate Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1/4] Generating TLS key pair (ECDSA secp384r1)...          ✓
[2/4] Creating Certificate Signing Request (CSR)...         ✓
[3/4] Signing CSR with GPG key (bob@example.com)...         ✓
      [GPG password prompt]
[4/4] Submitting to CA...                                   ✓

✓ Certificate issued successfully!

Certificate Details:
  Serial:    1234567890
  Subject:   CN=ABC123DEF456@relay.cryptic.example.org
  Issuer:    CN=Cryptic CA
  Valid:     2025-11-01 16:15:00 → 2025-11-08 16:15:00 (7 days)
  
  Files:
    Certificate: ~/.cryptic/bob/relay.cryptic.example.org_8443/certificates/client.pem
    Private Key: ~/.cryptic/bob/relay.cryptic.example.org_8443/private/client.key

Directory structure:
  ~/.cryptic/bob/relay.cryptic.example.org_8443/
    ├── certificates/
    │   └── client.pem
    └── private/
        └── client.key

You can now connect to Cryptic using the console:
  cryptic-console --cert ~/.cryptic/bob/relay.cryptic.example.org_8443/certificates/client.pem \
                  --key ~/.cryptic/bob/relay.cryptic.example.org_8443/private/client.key \
                  connect wss://relay.cryptic.example.org:8443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**`cryptic-onboard info [username] [cert_file|server_url]`** - Display certificate information

```bash
#!/bin/bash
# Usage: cryptic-onboard info alice [cert_file]
#        cryptic-onboard info alice wss://relay.cryptic.example.org:8443
#        cryptic-onboard info alice    # List all certs for alice
#        cryptic-onboard info           # List all users and their certs
# Uses OpenSSL to display certificate details

USERNAME="$1"

if [ -z "$USERNAME" ]; then
    # No username: list all users
    echo "Available users:"
    find ~/.cryptic -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read user_dir; do
        username=$(basename "$user_dir")
        echo "  $username"
        find "$user_dir" -name "client.pem" -type f 2>/dev/null | while read cert; do
            server_dir=$(dirname $(dirname "$cert"))
            server_name=$(basename "$server_dir")
            echo "    └─ $server_name"
        done
    done
    exit 0
fi

if [ -f "$2" ]; then
    # Second argument is a file path
    CERT_FILE="$2"
elif [ -n "$2" ]; then
    # Second argument is a server URL, extract host:port
    SERVER_HOST=$(echo "$2" | sed -E 's|^wss?://([^:/]+).*|\1|')
    SERVER_PORT=$(echo "$2" | sed -E 's|^wss?://[^:]+:([0-9]+).*|\1|')
    SERVER_PORT="${SERVER_PORT:-8443}"
    CERT_FILE="${HOME}/.cryptic/${USERNAME}/${SERVER_HOST}_${SERVER_PORT}/certificates/client.pem"
else
    # No second argument: list all certs for this user
    echo "Available certificates for $USERNAME:"
    find ~/.cryptic/$USERNAME -name "client.pem" -type f 2>/dev/null | while read cert; do
        server_dir=$(dirname $(dirname "$cert"))
        server_name=$(basename "$server_dir")
        echo "  $server_name"
    done
    exit 0
fi

if [ ! -f "$CERT_FILE" ]; then
    echo "Error: Certificate not found: $CERT_FILE"
    exit 1
fi

openssl x509 -in "$CERT_FILE" -noout -text -subject -issuer -dates -serial | \
  awk '...'  # Format nicely
```

**Output**:
```bash
# Show certificate for specific user and server
$ cryptic-onboard info bob wss://relay.cryptic.example.org:8443

Certificate Information
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User:             bob
Server:           relay.cryptic.example.org:8443
Subject:          CN=ABC123DEF456@relay.cryptic.example.org
Issuer:           CN=Cryptic CA
Serial:           1234567890

Validity:
  Not Before:     2025-11-01 16:15:00 UTC
  Not After:      2025-11-08 16:15:00 UTC
  Remaining:      6d 23h 45m

Public Key:
  Algorithm:      ECDSA
  Curve:          secp384r1 (P-384)
  Size:           384 bits

Files:
  Certificate:    ~/.cryptic/bob/relay.cryptic.example.org_8443/certificates/client.pem
  Private Key:    ~/.cryptic/bob/relay.cryptic.example.org_8443/private/client.key
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# List all certificates for a user
$ cryptic-onboard info bob

Available certificates for bob:
  relay.cryptic.example.org_8443
  backup.cryptic.example.org_9443
  federated.example.com_8443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# List all users and their certificates
$ cryptic-onboard info

Available users:
  alice
    └─ relay.cryptic.example.org_8443
    └─ backup.cryptic.example.org_9443
  bob
    └─ relay.cryptic.example.org_8443
    └─ federated.example.com_8443
  charlie
    └─ relay.cryptic.example.org_8443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### 2. Console Commands (cryptic_console) - Authenticated Users

These commands are for **users who already have valid certificates** and can connect to the server via mTLS.

##### Invite Commands (Inviter Workflow)

**`invite create [OPTIONS]`** - Create invitation token (via WebSocket)

```erlang
% Console command in cryptic_console (authenticated via mTLS)
cryptic> invite create --expires 24h --note "Welcome Bob"
```

**Implementation**: Sends WebSocket message to server, displays GPG-signed token

**`invite list [OPTIONS]`** - List your invitations

```erlang
cryptic> invite list
cryptic> invite list --status active
```

**`invite show <invite_id>`** - Show invite details

```erlang
cryptic> invite show inv-8f3b12a4
```

**`invite revoke <invite_id>`** - Revoke unused invitation

```erlang
cryptic> invite revoke inv-8f3b12a4
```

##### Certificate Commands (Certificate Management)

**`cert status`** - Check current certificate status

```erlang
% Shows local cert info + queries server for status
cryptic> cert status
```

**Output**:
```
Certificate Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status:        Valid ✓
Serial:        1234567890
Expires:       2025-11-08 16:15:00 UTC (6d 8h remaining)
Auto-renewal:  Enabled (scheduled in 3d 4h)

GPG Identity:
  Fingerprint: ABC123DEF456...
  Status:      verified_via_invite
  Email:       bob@example.com

Local Files:
  Certificate: ~/.cryptic/certs/client-cert.pem
  Private Key: ~/.cryptic/certs/client-key.pem
  
⚠️  Certificate expires in 6 days. Auto-renewal scheduled.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**`cert renew [OPTIONS]`** - Manually renew certificate

```erlang
% Request new cert via WebSocket (authenticated connection)
cryptic> cert renew
cryptic> cert renew --force        % Renew even if not close to expiry
cryptic> cert renew --new-key      % Generate new TLS key (re-key)
```

**Implementation**:
1. Generate new CSR (reuse existing key or generate new one)
2. Sign CSR with GPG key (local operation)
3. Send renewal request via WebSocket to server
4. Server issues new certificate
5. Save new certificate locally
6. Update auto-renewal schedule

**Output**:
```
Certificate Renewal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1/4] Creating new CSR (reusing existing key)...            ✓
[2/4] Signing CSR with GPG key...                           ✓
      [GPG password prompt]
[3/4] Requesting new certificate from server...             ✓
[4/4] Updating local certificate...                         ✓

✓ Certificate renewed successfully!

Old expiry: 2025-11-08 16:15:00 UTC
New expiry: 2025-11-15 16:15:00 UTC (7 days from now)
Serial:     1234567891

Next auto-renewal scheduled in 3.5 days.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### Tasks

1. **External Onboarding Script** (`bin/cryptic-onboard`)
   - [ ] `register <invite_file>` - Call POST /ca/v1/register-gpg
   - [ ] `request` - Generate TLS key, create CSR, sign with GPG, call POST /ca/v1/csr
   - [ ] `info [cert_file]` - Display certificate information using OpenSSL
   - [ ] Bash script with `curl`, `openssl`, `gpg` dependencies
   - [ ] Configuration file support (`~/.cryptic/config.json`)
   - [ ] Error handling and user-friendly output

2. **Console Commands Implementation** (cryptic_console - requires mTLS)
   - [ ] `invite create` - WebSocket message construction, display GPG-signed token
   - [ ] `invite list` - WebSocket query, formatted output
   - [ ] `invite show` - Detailed invite display
   - [ ] `invite revoke` - WebSocket revocation request
   - [ ] `cert status` - Local certificate inspection + server query
   - [ ] `cert renew` - Generate CSR, sign with GPG, WebSocket renewal request

3. **Client Library** (Erlang - for console commands)
   ```erlang
   cryptic_ca_client.erl     % Client-side helper functions
   ```
   - [ ] GPG signature creation (`sign_with_gpg/2`)
   - [ ] CSR generation (`generate_csr/2`)
   - [ ] Certificate status checking (`get_cert_status/1`)
   - [ ] Local certificate storage (`save_cert/2`, `load_cert/1`)
   - [ ] Auto-renewal daemon logic (`check_renewal_needed/1`)

4. **WebSocket Protocol Extensions** (for console commands)
   - [ ] `cert_renew` message type (authenticated via mTLS)
   - [ ] `cert_status_query` message type
   - [ ] Response handlers for renewal workflow

5. **Auto-Renewal Daemon** (background process in cryptic_console)
   - [ ] Monitor certificate expiry (check every hour)
   - [ ] Trigger renewal at 50% lifetime (3.5 days for 7-day cert)
   - [ ] Execute renewal workflow automatically
   - [ ] Graceful handling of renewal failures (retry logic)
   - [ ] Notify user of successful/failed renewals
   - [ ] Configurable renewal threshold (default 50%)

6. **Documentation**
   - [ ] User guide: Complete onboarding walkthrough
     * Alice creates invite in console
     * Bob uses `cryptic-onboard` script for registration and cert request
     * Bob connects to console with certificate
   - [ ] Script README: Installation, usage, dependencies
   - [ ] Command reference: All `invite` and `cert` commands with examples
   - [ ] Admin guide: Bootstrap first user, CA operations
   - [ ] Troubleshooting: Common issues (GPG not found, renewal failures, etc.)

#### User Experience Flow

**New User Onboarding (Bob)**:
```bash
# 1. Bob receives invite token from Alice (file: alice-invite.txt)

# 2. Register with the CA
bob$ cryptic-cli cert register alice-invite.txt
✓ Registration successful! GPG fingerprint: ABC123...

# 3. Request first certificate
bob$ cryptic-cli cert request
✓ Certificate issued! Valid for 7 days.

# 4. Connect to Cryptic
bob$ cryptic-cli connect wss://cryptic.example.org:8443
✓ Connected via mTLS!

# 5. Auto-renewal happens automatically in 3.5 days
# (or manual: cryptic-cli cert renew)
```

**Existing User Inviting (Alice)**:
```bash
# 1. Create invite for Bob
alice$ cryptic-cli invite create --note "Welcome Bob"
✓ Invite created: inv-8f3b12a4

# 2. Share token with Bob (copy from output, send via Signal/email)

# 3. Monitor invite status
alice$ cryptic-cli invite list
inv-8f3b12a4    Active    ...

# 4. Later: check if Bob used it
alice$ cryptic-cli invite show inv-8f3b12a4
Status: Consumed
Consumed By: ABC123... (Bob's GPG FP)
```

#### Deliverables

- [ ] Working CLI tools
- [ ] Client library complete
- [ ] User documentation
- [ ] Example scripts and workflows

### Phase 5: Security Hardening (Week 5-6)

**Objective**: Implement security controls and audit logging

#### Tasks

1. **Anti-Abuse Mechanisms**
   - [ ] Rate limiting per inviter (max invites/day)
   - [ ] Rate limiting per IP address
   - [ ] Invite quota management
   - [ ] Suspicious activity detection

2. **Audit & Logging**
   ```erlang
   cryptic_ca_audit.erl      % Audit logging (writes to SQLite)
   ```
   - [ ] Invite creation logging (stored in audit_log table)
   - [ ] Registration attempts (success/failure)
   - [ ] Certificate issuance logging (via myca)
   - [ ] Revocation events
   - [ ] Log retention policies (SQLite VACUUM)

3. **Monitoring & Alerting**
   - [ ] Metrics for invite usage
   - [ ] Certificate issuance rate (myca metrics)
   - [ ] Failed GPG verification attempts (erl_gpg)
   - [ ] Expiry warnings (7 days default)

#### Security Controls

| Control                 | Implementation                     |
|-------------------------|------------------------------------|
| Invite rate limit       | 10 invites/user/day (configurable) |
| Registration rate limit | 100 attempts/IP/hour               |
| Token TTL               | 24-72 hours                        |
| Certificate lifetime    | 7 days (default, configurable)     |
| Revocation check        | On every cert request              |

#### Deliverables

- [ ] Rate limiting implemented
- [ ] Audit logging complete (SQLite storage)
- [ ] Monitoring dashboard
- [ ] Security documentation

### Phase 6: Testing & QA (Week 6-7)

**Objective**: Comprehensive testing and quality assurance

#### Test Categories

1. **Unit Tests**
   - [ ] GPG operations (erl_gpg: signature verification, fingerprint)
   - [ ] Storage operations (esqlite: CRUD, atomicity, encryption)
   - [ ] Token validation logic
   - [ ] Certificate generation (myca integration)

2. **Integration Tests**
   - [ ] End-to-end onboarding flow (WebSocket + REST)
   - [ ] Certificate renewal flow (7 day default)
   - [ ] Revocation flow
   - [ ] Error scenarios (expired token, invalid GPG signature)

3. **Security Tests**
   - [ ] Replay attack prevention
   - [ ] Token reuse prevention
   - [ ] GPG signature forgery attempts (erl_gpg)
   - [ ] Rate limiting enforcement
   - [ ] SQLite encryption verification

4. **Performance Tests**
   - [ ] Concurrent registration requests
   - [ ] Certificate issuance throughput (myca)
   - [ ] SQLite query performance (esqlite)
   - [ ] GPG operation latency (erl_gpg)

#### Test Coverage Goals

- Unit test coverage: >80%
- Integration test coverage: 100% of happy paths
- Security test coverage: All threat model scenarios

#### Deliverables

- [ ] Full test suite implemented
- [ ] Performance benchmarks documented
- [ ] Security audit passed
- [ ] Load testing results

### Phase 7: Deployment & Operations (Week 7-8)

**Objective**: Production deployment and operational readiness

#### Tasks

1. **Deployment Preparation**
   - [ ] Create deployment scripts
   - [ ] Configure production environment
   - [ ] Set up CA key management
   - [ ] Configure backup procedures
   - [ ] Update Docker configuration for CA database

2. **Docker Integration**
   - [ ] Add SQLite database volume mount to docker-compose.yml
   - [ ] Configure myca certificate paths in Docker environment
   - [ ] Set up persistent storage for CA database
   - [ ] Update health checks to verify CA functionality
   - [ ] Document environment variables for CA configuration

3. **Operational Procedures**
   - [ ] Runbook for common operations
   - [ ] Incident response procedures
   - [ ] SQLite backup and recovery procedures
   - [ ] myca CA key rotation procedures

4. **Migration Plan**
   - [ ] Bootstrap initial admin users (register GPG keys via WebSocket bootstrap command)
   - [ ] Create initial invite tokens (WebSocket)
   - [ ] Gradual rollout strategy
   - [ ] Rollback procedures

#### Bootstrap Procedure for First Admin

```bash
# Admin already has TLS certificate and can connect via cryptic_console
admin$ cryptic connect --cert admin-cert.pem --key admin-key.pem

# In cryptic_console, register GPG key (bootstrap mode)
cryptic> :gpg register --pubkey ~/.gnupg/admin-pubkey.asc

# Server validates mTLS connection and registers GPG key
# Status: verified_bootstrap (no invite required)

# Admin can now create invites for other users
cryptic> :invite create --expires 24h --note "Welcome Bob"
```

#### Docker Deployment Configuration

The cryptic server uses Docker for deployment (see [DOCKER.md](./DOCKER.md)).
The CA functionality requires additional volume mounts and configuration:

**Volume Mounts Required**:
```yaml
# Add to docker-compose.yml
services:
  cryptic-server:
    volumes:
      # Existing mTLS certificates
      - ./CA/certs/server.crt:/opt/cryptic/certs/server.crt:ro
      - ./CA/private/server.key:/opt/cryptic/certs/server.key:ro
      - ./CA/certs/ca.crt:/opt/cryptic/certs/ca.crt:ro
      
      # CA database (persistent)
      - cryptic-ca-db:/opt/cryptic/data/ca
      
      # myca certificates (if different from mTLS CA)
      - ./CA/certs/myca-cert.pem:/opt/cryptic/certs/myca-cert.pem:ro
      - ./CA/private/myca-key.pem:/opt/cryptic/certs/myca-key.pem:ro

volumes:
  cryptic-ca-db:
    driver: local
```

**Environment Variables**:
```yaml
services:
  cryptic-server:
    environment:
      # Existing variables
      - CRYPTIC_SERVER_HOST=0.0.0.0
      - CRYPTIC_SERVER_PORT=8443
      
      # CA-specific variables
      - CRYPTIC_CA_DB_FILE=/opt/cryptic/data/ca/cryptic_ca.db
      - CRYPTIC_CA_DB_ENCRYPTION_KEY=${CRYPTIC_DB_KEY}
      - CRYPTIC_CA_MYCA_CONFIG=/opt/cryptic/certs/myca.config
      - CRYPTIC_CA_CERT_LIFETIME_DAYS=7
```

**Backup Strategy**:
```bash
# Backup CA database from Docker volume
docker compose exec cryptic-server sqlite3 /opt/cryptic/data/ca/cryptic_ca.db ".backup /tmp/ca_backup.db"
docker cp cryptic-server:/tmp/ca_backup.db ./backups/ca_backup_$(date +%Y%m%d).db

# Or backup the entire volume
docker run --rm -v cryptic-ca-db:/data -v $(pwd)/backups:/backup \
  alpine tar czf /backup/ca_db_$(date +%Y%m%d).tar.gz /data
```

#### Production Checklist

- [ ] CA root certificate configured in myca
- [ ] SQLite database backups configured (esqlite encryption enabled)
- [ ] Docker volumes configured for CA database persistence
- [ ] Environment variables set for CA configuration
- [ ] Monitoring and alerting active
- [ ] Rate limiting tuned for production
- [ ] Security logging enabled (audit_log table)
- [ ] Documentation complete
- [ ] On-call procedures established

#### Deliverables

- [ ] Production deployment successful
- [ ] Operations documentation
- [ ] Incident response plan
- [ ] Monitoring dashboards

## Technical Decisions

### GPG Library Choice

**Decision**: Use erl_gpg library (already implemented)

**Rationale**:
- Native Erlang implementation
- GPG signature verification
- Fingerprint computation
- No external CLI dependencies
- Already proven in production

### Database Choice

**Decision**: Use esqlite library with encryption

**Rationale**:
- Experience from cryptic message storage
- SQLite encryption support (sensitive invite data)
- Simple deployment (embedded database)
- ACID compliance for invite/registration transactions
- Familiar to team from existing cryptic codebase

### CA Implementation

**Decision**: Reuse existing myca library

**Rationale**:
- Already implemented and tested CA functionality
- Certificate generation and signing
- Serial number management
- No need to reimplement CA operations
- Proven in cryptic's existing certificate workflows

### Certificate Lifetime

**Decision**: 7 days (default, configurable 1-30 days)

**Rationale**:
- Short enough to limit exposure window
- Long enough to avoid frequent renewal UX issues
- Default: 7 days with auto-renewal at 50% lifetime (~3.5 days)
- Configurable per deployment needs

### Token Expiry

**Rationale**: 24-72 hours
- Short enough to limit token leakage risk
- Long enough for async invite delivery (email, etc.)
- Default: 24 hours

### WebSocket vs REST API Split

**Decision**: WebSocket for trusted clients (cryptic_console), REST for public operations

**Rationale**:
- Invite creation requires trust → WebSocket from authenticated cryptic_console
- Certificate requests need public access → REST API
- WebSocket already used for console communication
- Clear separation between administrative and public operations

## Module Structure

```
src/
├── cryptic_ca_sup.erl               % CA supervisor
├── cryptic_ca_app.erl               % CA application
├── cryptic_ca_ws_handler.erl        % WebSocket handler (invites from console)
├── cryptic_ca_rest_handler.erl      % REST handler (public cert requests)
├── cryptic_ca_store.erl             % esqlite storage abstraction
├── cryptic_ca_cert.erl              % myca integration for cert operations
├── cryptic_ca_gpg.erl               % erl_gpg integration wrapper
├── cryptic_invite_mgr.erl           % Invite lifecycle
├── cryptic_gpg_registry.erl         % GPG identity registry
├── cryptic_ca_audit.erl             % Audit logging (SQLite)
└── cryptic_ca_client.erl            % Client helper library

test/
├── cryptic_ca_SUITE.erl             % Common Test suite
├── cryptic_gpg_tests.erl            % erl_gpg unit tests
├── cryptic_store_tests.erl          % esqlite storage tests
├── cryptic_invite_tests.erl         % Invite unit tests
└── cryptic_integration_SUITE.erl    % Integration tests

priv/
└── (CA certificates managed by myca)
```

## Configuration

```erlang
%% config/sys.config
{cryptic_ca, [
    %% Storage (esqlite)
    {storage_backend, esqlite},
    {db_file, "data/ca/cryptic_ca.db"},  % Docker: /opt/cryptic/data/ca/cryptic_ca.db
    {db_encryption_key, {env, "CRYPTIC_DB_KEY"}},  % Optional encryption

    %% GPG (erl_gpg library)
    {gpg_library, erl_gpg},
    {gpg_timeout, 5000},

    %% CA Certificate (myca library)
    {ca_library, myca},
    {ca_config_file, "priv/ca/myca.config"},  % myca configuration

    %% Certificate Policy
    {cert_default_lifetime_days, 7},           % 7 days default
    {cert_max_lifetime_days, 30},              % Max 30 days
    {cert_renewal_threshold, 0.5},             % Renew at 50% lifetime

    %% Invite Policy
    {invite_default_ttl_hours, 24},
    {invite_max_ttl_hours, 72},
    {invite_rate_limit_per_user, 10},          % per day

    %% Rate Limiting
    {registration_rate_limit, {100, 3600}},    % 100/hour per IP
    {csr_rate_limit, {50, 3600}},              % 50/hour per fingerprint

    %% WebSocket (for cryptic_console invite creation)
    {ws_auth_required, true},                  % mTLS authentication
    {ws_admin_role, "ca_admin"},               % Required role for invites

    %% Audit
    {audit_enabled, true},                     % Log to SQLite audit_log table
    {audit_retention_days, 90}
]}.
```

**Note**: When deploying with Docker, paths will be different. The database
file will be at `/opt/cryptic/data/ca/cryptic_ca.db` inside the container,
 mounted from a Docker volume.
See [Docker Deployment Configuration](#docker-deployment-configuration) in
Phase 7 for details.

## Security Considerations

### Threat Mitigation

| Threat                   | Mitigation                                         |
|--------------------------|----------------------------------------------------|
| **Invite forgery**       | GPG signature verification (erl_gpg)               |
| **Token replay**         | One-time use flag + expiry (SQLite check)          |
| **Token leakage**        | Short TTL (24-72h), nonce binding                  |
| **CSR spoofing**         | GPG signature over CSR (erl_gpg)                   |
| **Rate limiting bypass** | Multiple rate limit layers (IP, user, fingerprint) |
| **CA key compromise**    | myca handles key security, SQLite encryption       |
| **DB compromise**        | esqlite encryption for sensitive invite data       |

### Privacy Protection

- **No PII storage**: Only GPG fingerprints stored
- **Minimal logging**: Only essential audit events
- **Fingerprint unlinkability**: No cross-referencing with external systems
- **Optional metadata**: Invite metadata is optional and not required

## Monitoring & Observability

### Key Metrics

```erlang
%% Invite metrics
cryptic_ca_invites_created_total
cryptic_ca_invites_consumed_total
cryptic_ca_invites_expired_total

%% Registration metrics
cryptic_ca_registrations_attempted_total
cryptic_ca_registrations_successful_total
cryptic_ca_registrations_failed_total{reason}

%% Certificate metrics
cryptic_ca_certs_issued_total
cryptic_ca_certs_renewed_total
cryptic_ca_cert_issuance_duration_seconds

%% Security metrics
cryptic_ca_rate_limit_hits_total{endpoint}
cryptic_ca_verification_failures_total{reason}
```

### Alerts

- High rate of failed verifications (potential attack)
- CA certificate approaching expiry
- Disk space low (for audit logs)
- Unusual invite creation patterns

## Risks & Mitigation

| Risk                 | Impact   | Probability | Mitigation                                         |
|----------------------|----------|-------------|----------------------------------------------------|
| CA key compromise    | Critical | Low         | Encrypted storage, access controls, audit logging  |
| GPG integration bugs | High     | Medium      | Extensive testing, sandboxing, fallback mechanisms |
| Database corruption  | High     | Low         | Regular backups, replication, transaction logs     |
| Rate limiting bypass | Medium   | Medium      | Multiple limit layers, adaptive throttling         |
| Documentation gaps   | Medium   | Medium      | Continuous review, user feedback                   |

## Success Metrics

### Technical Metrics

- [ ] <100ms p95 latency for GPG signature verification
- [ ] <200ms p95 latency for certificate issuance
- [ ] >99.9% uptime for CA endpoints
- [ ] Zero data loss events

### Adoption Metrics

- [ ] 80% of new users onboard via invites (vs manual)
- [ ] <5% failed registration attempts (UX issues)
- [ ] 95% automatic certificate renewal success rate

## Timeline Summary

| Phase                   | Duration    | Deliverable               |
|-------------------------|-------------|---------------------------|
| Phase 1: Foundation     | 2 weeks     | Storage + GPG integration |
| Phase 2: REST API       | 1 week      | All endpoints functional  |
| Phase 3: Certificates   | 1 week      | CA issuing certificates   |
| Phase 4: Client Tools   | 1 week      | CLI + documentation       |
| Phase 5: Security       | 1 week      | Hardening + audit         |
| Phase 6: Testing        | 1 week      | Full test coverage        |
| Phase 7: Deployment     | 1 week      | Production ready          |
| **Total**               | **8 weeks** | **Production deployment** |

## Future Enhancements

### Post-V1 Features

- [ ] Support for multiple CA roots (trust rotation)
- [ ] Hardware Security Module (HSM) integration
- [ ] Web UI for invite management
- [ ] Integration with identity providers (optional OIDC)
- [ ] Support for alternative identity backends (age, minisign)
- [ ] Cross-CA federation (trust between different CA instances)
- [ ] Automated certificate renewal daemon
- [ ] Revocation checking via OCSP
- [ ] Certificate transparency logging

## References

- [Invitation-Based GPG Registration Protocol](./INVITATION-BASED-ONBOARDING.md)
- [Naming and Addressing Scheme](./NAMING-ADDRESSING-SCHEME.md)
- [Docker Deployment Guide](./DOCKER.md)
- [OpenPGP RFC 4880](https://tools.ietf.org/html/rfc4880)
- [X.509 Certificate RFC 5280](https://tools.ietf.org/html/rfc5280)
- [PKCS#10 CSR RFC 2986](https://tools.ietf.org/html/rfc2986)

## Appendix A: Example Flows

### Complete Onboarding Example

```bash
# Alice creates invite for Bob
alice$ cryptic-ca invite create --expires 24h --note "Welcome Bob"
# Output: invite-8f3b12a4.asc

# Alice sends invite-8f3b12a4.asc to Bob (email, QR, etc.)

# Bob generates GPG key (if doesn't have one)
bob$ gpg --gen-key

# Bob exports public key
bob$ gpg --armor --export bob@example.com > bob-pubkey.asc

# Bob registers
bob$ cryptic-ca register \
  --invite invite-8f3b12a4.asc \
  --gpg-key bob-pubkey.asc

# Output: Successfully registered! GPG fingerprint: 6A2C1F...

# Bob generates TLS key pair
bob$ openssl ecparam -genkey -name prime256v1 -out bob-tls.key

# Bob creates CSR
bob$ openssl req -new -key bob-tls.key \
  -subj "/CN=bob@cryptic.example.org" \
  -out bob.csr

# Bob requests certificate
bob$ cryptic-ca cert request \
  --csr bob.csr \
  --gpg-fp 6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A

# Output: bob-cert.pem (valid for 24 hours)

# Bob connects to cryptic server
bob$ cryptic connect \
  --cert bob-cert.pem \
  --key bob-tls.key \
  --server relay.cryptic.example.org
```

## Appendix B: Database Queries

### Common Operations

```erlang
%% Create invite
create_invite(InviterFP, ExpiryHours) ->
    InviteId = generate_invite_id(),
    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = InviterFP,
        issued_at = erlang:system_time(second),
        expires_at = erlang:system_time(second) + (ExpiryHours * 3600)
    },
    mnesia:transaction(fun() -> mnesia:write(Invite) end).

%% Consume invite
consume_invite(InviteId, ConsumerFP) ->
    mnesia:transaction(fun() ->
        [Invite] = mnesia:read(invite, InviteId),
        case Invite#invite.consumed of
            false ->
                Updated = Invite#invite{
                    consumed = true,
                    consumed_at = erlang:system_time(second),
                    consumed_by_fp = ConsumerFP
                },
                mnesia:write(Updated),
                {ok, consumed};
            true ->
                {error, already_consumed}
        end
    end).

%% Register GPG identity
register_gpg(GpgFP, GpgPub, InviterFP, InviteId) ->
    Identity = #gpg_identity{
        gpg_fp = GpgFP,
        gpg_pub_armor = GpgPub,
        status = verified_via_invite,
        inviter_fp = InviterFP,
        invite_id = InviteId,
        registered_at = erlang:system_time(second),
        last_seen = erlang:system_time(second)
    },
    mnesia:transaction(fun() -> mnesia:write(Identity) end).
```

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-27  
**Author**: Cryptic Development Team  
**Status**: Ready for Review
