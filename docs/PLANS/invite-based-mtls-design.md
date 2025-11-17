# Invite-Based mTLS Authentication Design

## Overview

This document describes a security architecture where **all** connections to the Cryptic server require valid client certificates, eliminating unauthenticated endpoints entirely. The design uses two types of certificates:

1. **Invite-based certificates** - Temporary, used during initial onboarding
2. **GPG-based certificates** - Production certificates for authenticated users

## Problem Statement

### Current Issues

- Server has `{fail_if_no_peer_cert, false}` to allow unauthenticated REST endpoints (should be `true`)
- `/ca/v1/register-gpg` and `/ca/v1/csr` are publicly accessible
- Creates attack surface for DoS, enumeration, and abuse
- Mixed security model: some endpoints use mTLS, others don't

### Security Concerns

- **Private key distribution**: Original proposal had Admin generating invite certificates and distributing private keys to users - major security risk
- **Public endpoints**: Unauthenticated endpoints can be abused
- **No TLS-layer rejection**: Invalid requests only rejected at application layer

## Proposed Solution

### Core Principle

**Every connection requires a valid client certificate, verified at TLS layer.**

The certificate must contain either:
- A valid **invite token** (for onboarding), OR
- A registered **GPG fingerprint** (for production use)

### Certificate Types

#### 1. Invite-Based Certificate

**Purpose**: Bootstrap authentication for new users

**Characteristics**:
- Client generates own key pair (no private key distribution!)
- Contains invite token in certificate CN or custom extension
- Time-limited (e.g., 24 hours)
- Single-use or limited-use
- Allows access only to registration endpoints

**Certificate Structure**:
```
Subject:
  CN: invite:inv_abc123xyz
  (or) CN: bob@example.com

Subject Alternative Name:
  email: bob@example.com

Custom Extension (optional):
  OID: 1.3.6.1.4.1.99999.1 (invite token)
  Value: inv_abc123xyz

Validity:
  Not Before: 2025-11-04 10:00:00 UTC
  Not After:  2025-11-05 10:00:00 UTC  (24 hours)
```

#### 2. GPG-Based Certificate

**Purpose**: Production authentication for registered users

**Characteristics**:
- Contains user's GPG fingerprint in SAN extension
- Short-lived (1-7 days, automatically rotated by client)
- Allows full access to all services
- Automatic renewal before expiration (client-side)
- Already implemented in current design

**Certificate Structure**:
```
Subject:
  CN: bob@example.com

Subject Alternative Name:
  email: bob@example.com
  DNS: 04764AB164BC1B9869162AAEB64C51FF9569D67B.gpg.cryptic.local

Validity:
  Not Before: 2025-11-04 10:00:00 UTC
  Not After:  2025-11-11 10:00:00 UTC  (7 days)
```

**Automatic Rotation**:
- Client monitors certificate expiration
- Automatically requests new certificate when <24 hours remain
- Seamless transition (no user intervention required)
- Uses existing GPG cert to authenticate renewal request

## Onboarding Flow

### Phase 1: Admin Creates Invite

```erlang
%% Admin executes via cryptic console
cryptic:create_invite(#{
    created_by => "admin",
    email => "bob@example.com",
    max_uses => 1,
    expires_at => {{2025,11,5},{10,0,0}}
}).

%% Returns:
{ok, #{
    token => <<"inv_abc123xyz">>,
    created_at => {{2025,11,4},{10,0,0}},
    expires_at => {{2025,11,5},{10,0,0}}
}}
```

**Database Storage**:
```sql
INSERT INTO invites (
    token,
    created_by,
    created_at,
    expires_at,
    max_uses,
    current_uses,
    status,
    metadata
) VALUES (
    'inv_abc123xyz',
    'admin',
    '2025-11-04 10:00:00',
    '2025-11-05 10:00:00',
    1,
    0,
    'active',
    '{"email": "bob@example.com"}'
);
```

### Phase 2: Admin Shares Invite Token

Admin sends **only the token string** to Bob via secure channel:
- Email
- Signal/WhatsApp
- In-person
- Encrypted message

**Shared data**: `inv_abc123xyz` (just the token, no keys!)

### Phase 3: Bob Requests Invite Certificate

Bob runs the onboarding script:

```bash
$ ./bin/cryptic-onboard --invite inv_abc123xyz --email bob@example.com
```

**Script actions**:

1. Generate fresh key pair locally (client-side)
   ```bash
   openssl genrsa -out /tmp/invite_key.pem 2048
   ```

2. Create CSR with invite token in CN or extension
   ```bash
   openssl req -new \
     -key /tmp/invite_key.pem \
     -out /tmp/invite_csr.pem \
     -subj "/CN=invite:inv_abc123xyz/emailAddress=bob@example.com"
   ```

3. POST CSR to CA (unauthenticated endpoint)
   ```bash
   curl -X POST https://cryptic.local:8443/ca/v1/invite-cert \
     --cacert CA/certs/ca.crt \
     -H "Content-Type: application/json" \
     -d '{
       "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
       "invite_token": "inv_abc123xyz"
     }'
   ```

4. CA validates and signs certificate
   - Verify invite token exists in database
   - Check not expired: `NOW() < expires_at`
   - Check not exhausted: `current_uses < max_uses`
   - Validate CSR signature
   - Sign certificate with invite token in CN/extension
   - Update database: `current_uses++`, `status='in_use'`

5. CA returns signed certificate (not private key!)
   ```json
   {
     "certificate": "-----BEGIN CERTIFICATE-----...",
     "expires_at": "2025-11-05T10:00:00Z"
   }
   ```

6. Script saves certificate
   ```bash
   # Save to user's config directory
   ~/.cryptic/invite_cert.pem
   ~/.cryptic/invite_key.pem
   ```

### Phase 4: Bob Registers GPG Key

```bash
$ ./bin/cryptic-onboard --register-gpg
```

**Script actions**:

1. Prompt user to select or generate GPG key
   ```
   Available GPG keys:
   [1] Bob Smith <bob@example.com> (04764AB164BC1B9869162AAEB64C51FF9569D67B)
   [2] Generate new GPG key
   
   Select key [1-2]: 1
   ```

2. Export GPG public key
   ```bash
   gpg --armor --export 04764AB164BC1B9869162AAEB64C51FF9569D67B > /tmp/bob_pubkey.asc
   ```

3. Sign registration request with GPG
   ```bash
   echo -n "register:bob@example.com:$(date -u +%Y%m%d%H%M%S)" > /tmp/payload.txt
   gpg --detach-sign --armor -u 04764AB164BC1B9869162AAEB64C51FF9569D67B /tmp/payload.txt
   ```

4. POST to CA using invite certificate for mTLS
   ```bash
   curl -X POST https://cryptic.local:8443/ca/v1/register-gpg \
     --cacert CA/certs/ca.crt \
     --cert ~/.cryptic/invite_cert.pem \
     --key ~/.cryptic/invite_key.pem \
     -H "Content-Type: application/json" \
     -d '{
       "email": "bob@example.com",
       "gpg_fingerprint": "04764AB164BC1B9869162AAEB64C51FF9569D67B",
       "gpg_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
       "signature": "-----BEGIN PGP SIGNATURE-----...",
       "payload": "register:bob@example.com:20251104100000"
     }'
   ```

5. TLS handshake: verify_peer validates invite token
   ```erlang
   %% In cryptic_server:verify_peer/4
   verify_peer(OtpCert, _DerCert, valid_peer, UserState) ->
       case extract_cn_from_cert(OtpCert) of
           {ok, <<"invite:", InviteToken/binary>>} ->
               case verify_invite_token(InviteToken) of
                   {ok, InviteInfo} ->
                       {valid, UserState#{invite_token => InviteToken,
                                          invite_info => InviteInfo}};
                   {error, Reason} ->
                       {fail, {bad_cert, {invalid_invite, Reason}}}
               end;
           %% ... other cases
       end.
   ```

6. Application layer: Validate GPG signature
   ```erlang
   %% In cryptic_ca_rest_handler
   verify_gpg_signature(GpgFp, Payload, Signature, PubKey) ->
       %% Verify signature matches public key
       %% Verify payload timestamp within 5 minutes
       %% Verify email matches request
   ```

7. CA stores GPG identity
   ```sql
   INSERT INTO gpg_identities (
       fingerprint,
       email,
       public_key,
       registered_at,
       registered_via_invite
   ) VALUES (
       '04764AB164BC1B9869162AAEB64C51FF9569D67B',
       'bob@example.com',
       '-----BEGIN PGP PUBLIC KEY BLOCK-----...',
       '2025-11-04 10:00:00',
       'inv_abc123xyz'
   );
   
   UPDATE invites 
   SET status = 'used', 
       used_at = '2025-11-04 10:00:00',
       used_by_fingerprint = '04764AB164BC1B9869162AAEB64C51FF9569D67B'
   WHERE token = 'inv_abc123xyz';
   ```

### Phase 5: Bob Requests Production Certificate

```bash
$ ./bin/cryptic-onboard --request-cert
```

**Script actions**:

1. Generate new key pair for production certificate
   ```bash
   openssl genrsa -out ~/.cryptic/client_key.pem 2048
   ```

2. Create CSR with GPG fingerprint in SAN
   ```bash
   openssl req -new \
     -key ~/.cryptic/client_key.pem \
     -out /tmp/client_csr.pem \
     -subj "/CN=bob@example.com/emailAddress=bob@example.com" \
     -addext "subjectAltName=email:bob@example.com,DNS:04764AB164BC1B9869162AAEB64C51FF9569D67B.gpg.cryptic.local"
   ```

3. Sign CSR request with GPG
   ```bash
   gpg --detach-sign --armor -u 04764AB164BC1B9869162AAEB64C51FF9569D67B /tmp/client_csr.pem
   ```

4. POST CSR to CA using invite certificate
   ```bash
   curl -X POST https://cryptic.local:8443/ca/v1/csr \
     --cacert CA/certs/ca.crt \
     --cert ~/.cryptic/invite_cert.pem \
     --key ~/.cryptic/invite_key.pem \
     -H "Content-Type: application/json" \
     -d '{
       "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
       "gpg_fingerprint": "04764AB164BC1B9869162AAEB64C51FF9569D67B",
       "signature": "-----BEGIN PGP SIGNATURE-----..."
     }'
   ```

5. CA validates and issues certificate
   - TLS layer: Verify invite token or GPG fingerprint
   - Application layer: Verify GPG fingerprint is registered
   - Verify GPG signature on CSR
   - Sign certificate
   - Store certificate record

6. Script saves production certificate
   ```bash
   ~/.cryptic/client_cert.pem
   ~/.cryptic/client_key.pem
   ```

7. Clean up invite certificate
   ```bash
   rm ~/.cryptic/invite_cert.pem ~/.cryptic/invite_key.pem
   ```

### Phase 6: Bob Uses Production Certificate

```bash
$ cryptic --cert ~/.cryptic/client_cert.pem --key ~/.cryptic/client_key.pem
```

**Connection**:
- TLS handshake: verify_peer extracts GPG fingerprint from SAN
- Validates fingerprint is registered
- Full access to all services (/ws, /ca/ws, etc.)

## TLS Layer Verification

### verify_peer Function Logic

```erlang
%% Handle certificate extensions (SAN with GPG fingerprint)
verify_peer(_OtpCert, _DerCert, {extension, Extension}, UserState) ->
    case Extension of
        %% SAN extension - check for GPG fingerprint
        {'Extension', {2,5,29,17}, _Critical, SANValues} ->
            case extract_gpg_from_san(SANValues) of
                {ok, GpgFp} ->
                    %% Production certificate with GPG fingerprint
                    case verify_gpg_fingerprint(GpgFp) of
                        true ->
                            ?info("VERIFY_PEER: Valid GPG cert - ~s", [GpgFp]),
                            {valid, UserState#{auth_type => gpg,
                                               gpg_fingerprint => GpgFp}};
                        false ->
                            ?warning("VERIFY_PEER: Unregistered GPG - ~s", [GpgFp]),
                            {fail, {bad_cert, unregistered_gpg_fingerprint}};
                        {error, Reason} ->
                            ?error("VERIFY_PEER: GPG verification error - ~p", [Reason]),
                            {fail, {bad_cert, gpg_verification_error}}
                    end;
                {error, _} ->
                    %% No GPG fingerprint in SAN
                    {unknown, UserState}
            end;
        
        %% Custom extension - check for invite token
        %% OID 1.3.6.1.4.1.99999.1 = invite token extension
        {'Extension', {1,3,6,1,4,1,99999,1}, _Critical, InviteData} ->
            case decode_invite_extension(InviteData) of
                {ok, InviteToken} ->
                    %% Invite certificate
                    case verify_invite_token(InviteToken) of
                        {ok, InviteInfo} ->
                            ?info("VERIFY_PEER: Valid invite cert - ~s", [InviteToken]),
                            {valid, UserState#{auth_type => invite,
                                               invite_token => InviteToken,
                                               invite_info => InviteInfo}};
                        {error, expired} ->
                            ?warning("VERIFY_PEER: Expired invite - ~s", [InviteToken]),
                            {fail, {bad_cert, expired_invite_token}};
                        {error, exhausted} ->
                            ?warning("VERIFY_PEER: Exhausted invite - ~s", [InviteToken]),
                            {fail, {bad_cert, exhausted_invite_token}};
                        {error, not_found} ->
                            ?warning("VERIFY_PEER: Unknown invite - ~s", [InviteToken]),
                            {fail, {bad_cert, unknown_invite_token}};
                        {error, Reason} ->
                            ?error("VERIFY_PEER: Invite verification error - ~p", [Reason]),
                            {fail, {bad_cert, invite_verification_error}}
                    end;
                {error, _Reason} ->
                    {fail, {bad_cert, malformed_invite_extension}}
            end;
        
        _Other ->
            {unknown, UserState}
    end;

%% Handle valid_peer event - check CN for invite token
verify_peer(OtpCert, _DerCert, valid_peer, UserState) ->
    %% Alternative: invite token in CN instead of extension
    case extract_cn_from_cert(OtpCert) of
        {ok, <<"invite:", InviteToken/binary>>} ->
            case verify_invite_token(InviteToken) of
                {ok, InviteInfo} ->
                    ?info("VERIFY_PEER: Valid invite cert (CN) - ~s", [InviteToken]),
                    {valid, UserState#{auth_type => invite,
                                       invite_token => InviteToken,
                                       invite_info => InviteInfo}};
                {error, Reason} ->
                    ?warning("VERIFY_PEER: Invalid invite (CN) - ~s: ~p", 
                             [InviteToken, Reason]),
                    {fail, {bad_cert, {invalid_invite, Reason}}}
            end;
        _ ->
            %% No invite in CN, already checked extensions
            {valid, UserState}
    end;

%% All other events
verify_peer(_OtpCert, _DerCert, valid, UserState) ->
    {valid, UserState};

verify_peer(_OtpCert, _DerCert, {bad_cert, _} = Reason, _UserState) ->
    {fail, Reason};

verify_peer(_OtpCert, _DerCert, Reason, UserState) ->
    ?debug("VERIFY_PEER: Unknown reason - ~p", [Reason]),
    {unknown, UserState}.
```

### Invite Token Verification

The invite token has a strict lifecycle with state transitions:

**State Machine**:
```
active → registered → consumed → [expired/revoked]
```

**State Transitions**:
1. **active** → **registered**: First use - Bob registers GPG key
2. **registered** → **consumed**: Second use - Bob requests production certificate
3. Any state → **expired**: Automatic when `expires_at` passes
4. Any state → **revoked**: Manual revocation by admin

**Validation Rules**:
- `active`: Accept only for GPG registration (`/ca/v1/register-gpg`)
- `registered`: Accept only for production CSR (`/ca/v1/csr`)
- `consumed`: Reject all uses (invite fully used)
- `expired`: Reject all uses (time limit passed)
- `revoked`: Reject all uses (admin cancelled)

```erlang
-spec verify_invite_token(binary(), atom()) -> {ok, map()} | {error, term()}.
verify_invite_token(InviteToken, Operation) ->
    try
        %% Look up database from ETS
        case ets:lookup(cryptic_ca_storage, db_ref) of
            [{db_ref, DbRef}] ->
                case cryptic_ca_store:get_invite(DbRef, InviteToken) of
                    {ok, Invite} ->
                        %% Check expiration first
                        Now = calendar:universal_time(),
                        ExpiresAt = maps:get(expires_at, Invite),
                        if
                            Now > ExpiresAt ->
                                {error, expired};
                            true ->
                                %% Check state and operation compatibility
                                Status = maps:get(status, Invite),
                                case {Status, Operation} of
                                    %% Active invite: only for GPG registration
                                    {<<"active">>, register_gpg} ->
                                        {ok, Invite};
                                    {<<"active">>, _} ->
                                        {error, {invalid_operation, 
                                                <<"Active invite can only be used for GPG registration">>}};
                                    
                                    %% Registered invite: only for production CSR
                                    {<<"registered">>, csr} ->
                                        {ok, Invite};
                                    {<<"registered">>, register_gpg} ->
                                        {error, {already_registered,
                                                <<"GPG key already registered with this invite">>}};
                                    {<<"registered">>, _} ->
                                        {error, {invalid_operation,
                                                <<"Registered invite can only be used for certificate request">>}};
                                    
                                    %% Consumed invite: reject everything
                                    {<<"consumed">>, _} ->
                                        {error, consumed};
                                    
                                    %% Revoked invite: reject everything
                                    {<<"revoked">>, _} ->
                                        {error, revoked};
                                    
                                    %% Unknown state
                                    {UnknownStatus, _} ->
                                        {error, {unknown_status, UnknownStatus}}
                                end
                        end;
                    {error, not_found} ->
                        {error, not_found};
                    {error, Reason} ->
                        {error, Reason}
                end;
            [] ->
                {error, ca_not_initialized}
        end
    catch
        error:badarg ->
            {error, ca_storage_not_available};
        ErrorClass:ErrorReason ->
            {error, {ErrorClass, ErrorReason}}
    end.

%% @doc Update invite status after successful operation
-spec update_invite_status(binary(), atom(), term()) -> ok | {error, term()}.
update_invite_status(InviteToken, Operation, Metadata) ->
    try
        case ets:lookup(cryptic_ca_storage, db_ref) of
            [{db_ref, DbRef}] ->
                NewStatus = case Operation of
                    register_gpg -> <<"registered">>;
                    csr -> <<"consumed">>
                end,
                cryptic_ca_store:update_invite_status(DbRef, InviteToken, NewStatus, Metadata);
            [] ->
                {error, ca_not_initialized}
        end
    catch
        error:badarg ->
            {error, ca_storage_not_available};
        ErrorClass:ErrorReason ->
            {error, {ErrorClass, ErrorReason}}
    end.
```

**State Transition Examples**:

```erlang
%% Example 1: Successful GPG registration
1. Status: active
2. Bob registers GPG key
3. verify_invite_token(Token, register_gpg) → {ok, Invite}
4. update_invite_status(Token, register_gpg, #{gpg_fp => "04764..."})
5. Status: registered

%% Example 2: Successful production certificate request
1. Status: registered
2. Bob requests production cert
3. verify_invite_token(Token, csr) → {ok, Invite}
4. update_invite_status(Token, csr, #{cert_serial => "ABC123"})
5. Status: consumed

%% Example 3: Attempt to reuse consumed invite (BLOCKED)
1. Status: consumed
2. Attacker tries to use invite again
3. verify_invite_token(Token, register_gpg) → {error, consumed}
4. Connection rejected at TLS layer

%% Example 4: Attempt to skip GPG registration (BLOCKED)
1. Status: active
2. Bob tries to request cert without registering GPG
3. verify_invite_token(Token, csr) → {error, {invalid_operation, ...}}
4. Connection rejected at TLS layer
```

## Server Configuration

### TLS Options

```erlang
TLSOptions = [
    {verify, verify_peer},
    {verify_fun, {fun verify_peer/4, []}},
    {fail_if_no_peer_cert, true},  % REQUIRE client certificates
    {versions, ['tlsv1.2', 'tlsv1.3']},
    {cacertfile, CACertFile},
    {certfile, ServerCertFile},
    {keyfile, ServerKeyFile}
]
```

### Endpoint Access Control

All endpoints now require mTLS. Access control in handlers:

```erlang
%% cryptic_ca_rest_handler:init/2
init(Req, State = #{operation := Operation}) ->
    %% Extract authentication from connection
    case cowboy_req:cert(Req) of
        undefined ->
            %% Should never happen with fail_if_no_peer_cert=true
            {ok, reply_error(Req, 401, <<"Client certificate required">>), State};
        Cert ->
            %% Get auth info from verify_peer (stored in connection state)
            AuthType = cowboy_req:peer_data(Req, auth_type),
            case {Operation, AuthType} of
                %% Invite certs can only access these endpoints
                {issue_invite_cert, _} ->
                    %% Special case: uses invite token in request body
                    handle_operation(Req, State);
                
                {register_gpg, invite} ->
                    %% Only invite certs can register GPG
                    handle_operation(Req, State);
                
                {csr, invite} ->
                    %% Invite certs can request GPG-based certs
                    handle_operation(Req, State);
                
                {csr, gpg} ->
                    %% GPG certs can renew themselves
                    handle_operation(Req, State);
                
                %% All other operations require GPG cert
                {_, gpg} ->
                    handle_operation(Req, State);
                
                {_, invite} ->
                    {ok, reply_error(Req, 403, 
                        <<"This operation requires a GPG-based certificate">>), 
                     State};
                
                _ ->
                    {ok, reply_error(Req, 401, <<"Invalid authentication">>), State}
            end
    end.
```

## Database Schema

### Invites Table

```sql
CREATE TABLE invites (
    token TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',  -- State machine: active → registered → consumed
                                              -- Also: expired (automatic), revoked (manual)
    
    -- GPG registration (first use)
    registered_at TIMESTAMP,                  -- When GPG key was registered
    registered_by_fingerprint TEXT,           -- GPG fingerprint that was registered
    
    -- Production cert request (second use)
    consumed_at TIMESTAMP,                    -- When production cert was requested
    consumed_cert_serial TEXT,                -- Serial number of issued production cert
    
    -- Admin tracking
    revoked_at TIMESTAMP,                     -- When manually revoked by admin
    revoked_by TEXT,                          -- Admin who revoked it
    revoked_reason TEXT,                      -- Why it was revoked
    
    metadata TEXT,                            -- JSON: {email, notes, etc.}
    
    FOREIGN KEY (created_by) REFERENCES gpg_identities(fingerprint),
    FOREIGN KEY (registered_by_fingerprint) REFERENCES gpg_identities(fingerprint),
    
    -- Constraints to ensure state consistency
    CHECK (status IN ('active', 'registered', 'consumed', 'expired', 'revoked')),
    CHECK ((status = 'registered' AND registered_at IS NOT NULL) OR status != 'registered'),
    CHECK ((status = 'consumed' AND consumed_at IS NOT NULL) OR status != 'consumed'),
    CHECK ((status = 'revoked' AND revoked_at IS NOT NULL) OR status != 'revoked')
);

CREATE INDEX idx_invites_status ON invites(status);
CREATE INDEX idx_invites_expires_at ON invites(expires_at);
CREATE INDEX idx_invites_registered_fingerprint ON invites(registered_by_fingerprint);

-- View for tracking invite lifecycle
CREATE VIEW invite_lifecycle AS
SELECT 
    token,
    status,
    created_at,
    expires_at,
    registered_at,
    consumed_at,
    CASE 
        WHEN status = 'consumed' THEN 
            CAST((julianday(consumed_at) - julianday(created_at)) * 24 * 60 AS INTEGER)
        WHEN status = 'registered' THEN
            CAST((julianday(registered_at) - julianday(created_at)) * 24 * 60 AS INTEGER)
        ELSE NULL
    END AS completion_time_minutes,
    registered_by_fingerprint
FROM invites;
```

### GPG Identities Table (existing)

```sql
CREATE TABLE gpg_identities (
    fingerprint TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    public_key TEXT NOT NULL,
    registered_at TIMESTAMP NOT NULL,
    registered_via_invite TEXT,
    status TEXT NOT NULL DEFAULT 'active',  -- active, suspended, revoked
    FOREIGN KEY (registered_via_invite) REFERENCES invites(token)
);
```

## Security Analysis

### Threat Model

| Attack Vector | Mitigation |
|---------------|------------|
| **Stolen invite token** | Time-limited (24h), single-use, requires subsequent GPG key registration |
| **Man-in-the-middle** | TLS with certificate pinning, verify CA cert |
| **Replay attacks** | GPG signatures include timestamp (5-minute window) |
| **Certificate forgery** | All certs signed by CA, chain validation at TLS layer |
| **DoS on /ca/v1/invite-cert** | Rate limiting, require valid invite token in request body |
| **Invite enumeration** | Constant-time invite validation, rate limiting |
| **Compromised invite cert** | Time-limited, can't access production endpoints, can be revoked |
| **Compromised GPG cert** | Can be revoked, requires compromising both cert private key AND GPG private key for full attack |

### Defense in Depth

1. **TLS Layer**
   - Certificate chain validation (can't forge CA signature)
   - Mutual TLS (all connections authenticated)
   - Custom verify_peer (validates invite/GPG before application code runs)

2. **Application Layer**
   - GPG signature verification (proves possession of GPG private key)
   - Endpoint access control (invite certs have limited permissions)
   - Database validation (invite not expired/exhausted)

3. **Operational**
   - Invite expiration (reduce attack window)
   - Usage tracking (detect anomalies)
   - Audit logging (forensics)
   - Certificate revocation (respond to compromise)

## Alternative: Invite in CN vs Extension

### Option A: Invite in CN Field

**Pros**:
- Simpler - no custom extension needed
- Standard OpenSSL tools work out of box
- Easy to inspect: `openssl x509 -noout -subject`

**Cons**:
- CN is being deprecated in favor of SAN
- Less structured than dedicated extension
- Mixing authentication info with identity

**Example**:
```
CN: invite:inv_abc123xyz
```

### Option B: Invite in Custom Extension

**Pros**:
- Proper separation of concerns
- Follows X.509 extension model
- Future-proof (CN deprecation)

**Cons**:
- Requires custom OpenSSL config
- Harder to inspect without parsing tools
- More complex implementation

**Example**:
```
Extensions:
    1.3.6.1.4.1.99999.1: (invite token)
        inv_abc123xyz
```

### Recommendation

**Use CN for invite token** (`invite:<token>` format):
- Simpler implementation and tooling
- Easier debugging and inspection
- CN deprecation doesn't affect us (we're not using it for identity, just auth)
- Can always migrate to extension later if needed

## Implementation Roadmap

### Phase 1: Database & Invite Management
- [ ] Add `invites` table to schema
- [ ] Implement `cryptic_ca_store:create_invite/2`
- [ ] Implement `cryptic_ca_store:get_invite/2`
- [ ] Implement `cryptic_ca_store:update_invite_usage/2`
- [ ] Add console commands: `create_invite`, `list_invites`, `revoke_invite`

### Phase 2: Invite Certificate Issuance
- [ ] Add `/ca/v1/invite-cert` endpoint
- [ ] Implement CSR validation for invite certs
- [ ] Implement invite token validation
- [ ] Generate and sign invite certificates
- [ ] Update invite usage tracking

### Phase 3: TLS Layer Verification
- [ ] Add `extract_cn_from_cert/1` helper
- [ ] Implement `verify_invite_token/1` function
- [ ] Update `verify_peer/4` to handle invite tokens
- [ ] Store auth type in connection state
- [ ] Change `{fail_if_no_peer_cert, true}`

### Phase 4: Endpoint Access Control
- [ ] Update handler `init/2` to check auth type
- [ ] Implement endpoint permission matrix
- [ ] Add proper error responses for unauthorized access
- [ ] Remove old unauthenticated endpoint logic

### Phase 5: Client Tooling
- [ ] Update `cryptic-onboard` script
- [ ] Add `--invite` flag for bootstrap flow
- [ ] Implement invite cert request
- [ ] Implement GPG registration with invite cert
- [ ] Implement production cert request
- [ ] Add cert management commands (renew, revoke)

### Phase 6: Testing & Documentation
- [ ] Unit tests for invite management
- [ ] Integration tests for full onboarding flow
- [ ] Security audit of TLS verification
- [ ] Load testing of invite cert endpoint
- [ ] Update user documentation
- [ ] Update operational runbook

## Open Questions

1. **Invite token format**: Random bytes? UUID? HMAC-based?
   - Recommendation: `base64url(crypto:strong_rand_bytes(32))` = ~43 chars
   - Pattern: `inv_<base64url>`

2. **Custom OID for invite extension**: Need to register or use private range?
   - Private enterprise number: 1.3.6.1.4.1.XXXXX
   - Or use unregistered: 1.3.6.1.4.1.99999.1

3. **Invite cert validity period**: 24 hours? 7 days?
   - Recommendation: 24 hours (matches invite expiration)
   - Configurable per-invite

4. **Can invite certs renew themselves?**: Or require new invite?
   - Recommendation: No renewal, single-use for registration only
   - Forces completion of GPG registration within time limit

5. **Rate limiting on /ca/v1/invite-cert**: How aggressive?
   - Recommendation: 5 requests per IP per hour
   - Stricter than other endpoints since it's the only one without prior auth

6. **Audit logging**: What events to log?
   - Invite creation, usage, expiration
   - Certificate issuance (both types)
   - Failed verification attempts
   - Authentication type switches

## Comparison with Original Design

| Aspect | Original Design | New Design |
|--------|----------------|------------|
| **Private key distribution** | Admin generates and shares | Client generates own keys ✅ |
| **Unauthenticated endpoints** | `/ca/v1/register-gpg`, `/ca/v1/csr` | Only `/ca/v1/invite-cert` |
| **TLS configuration** | `fail_if_no_peer_cert=false` | `fail_if_no_peer_cert=true` ✅ |
| **Attack surface** | Multiple public endpoints | Single limited endpoint ✅ |
| **Verification layers** | Application only | TLS + Application ✅ |
| **Bootstrap security** | Relies on shared secret (invite) | Requires both invite + GPG key ✅ |
| **Invite material** | Token + cert + private key | Token only ✅ |

## Conclusion

This design provides **strong security guarantees** while maintaining a **reasonable user experience**:

✅ **No private key distribution** - eliminates major security risk  
✅ **TLS-layer verification** - rejects invalid connections early  
✅ **Minimal unauthenticated surface** - only one limited endpoint  
✅ **Defense in depth** - multiple verification layers  
✅ **Clear separation** - invite certs vs production certs  
✅ **Time-limited invites** - reduces attack window  
✅ **Audit trail** - complete tracking of onboarding flow  

The trade-off is **additional complexity** in the onboarding flow, but the security benefits justify it.
