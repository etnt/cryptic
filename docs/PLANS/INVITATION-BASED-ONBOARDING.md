# Invitation-Based GPG Registration Protocol

## Purpose & Goals

- Let existing, verified users (**Inviters**) bootstrap new users
  (**Invitees**) into the CA trust domain without manual admin intervention
- Use GPG signatures as the root of identity for certificate issuance
- Keep privacy: store only GPG fingerprints and minimal metadata
- Defend against replay, forgery, and token leakage (expiry, one-time use, nonce binding)

## Threat Model

- **Network eavesdropping**: Attacker may snoop on network traffic (mitigated by HTTPS/TLS)
- **Invite forgery**: Attacker may try to fabricate invites (prevented by GPG signatures)
- **Token reuse**: Attacker may reuse a leaked invite token (mitigated with short TTL and one-time flags)

## Overview

## Overview

1. An existing verified user (**Alice**) creates an invite token signed by her GPG key
2. Alice gives that token to the prospective user (**Bob**) out-of-band (QR, email, paste)
3. Bob sends his GPG public key + the invite token to the CA's `/register-gpg` endpoint
4. CA verifies:
   - The invite token signature is valid under Alice's GPG pubkey
   - Optionally, Alice is a trusted inviter (status check)
   - The token hasn't expired or been used already
   - The token is bound to the request (nonce or recipient hint)
5. On success, CA marks Bob's GPG pubkey as verified (or `verified-via-invite`) 
   and allows CSR/cert issuance

## Key Architecture: Two Separate Key Pairs

It's important to understand that users maintain **two distinct cryptographic key pairs** in this system:

### 1. GPG Key Pair (Identity Key)

**Purpose**: Long-term cryptographic identity, proves "I am Bob"

**Components**:
- **GPG Private Key** (`bob_gpg.sec`) - Kept secure, never shared
- **GPG Public Key** (`bob_gpg.pub`) - Shared with CA during registration

**Usage**:
- Sign invite tokens (when acting as inviter)
- Sign CSRs or nonces to prove identity when requesting certificates
- Can be used for email signing, file encryption, etc. (outside cryptic)

**Lifecycle**:
- Long-lived (years), Bob's permanent identity
- Carefully backed up and protected
- Rotation requires re-registration with new invite

**Registration**: Sent to CA during initial onboarding via `/register-gpg`

### 2. TLS Key Pair (Session Key)

**Purpose**: Ephemeral credential for TLS/mTLS connections

**Components**:
- **TLS Private Key** (`bob_tls.key`) - Kept secure, used for TLS handshakes
- **TLS Public Key** - Embedded in CSR, signed by CA into certificate

**Usage**:
- Mutual TLS (mTLS) authentication to cryptic servers
- Session encryption
- Only valid while certificate is not expired

**Lifecycle**:
- Short-lived (24-168 hours via certificate expiry)
- Can be regenerated at any time
- Rotated with each certificate renewal

**Registration**: Public key sent via CSR to `/ca/v1/csr`, signed by CA into certificate

### Key Relationship Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│ Bob's Cryptographic Identity                                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ GPG Key Pair (Long-term Identity)                             │   │
│  ├───────────────────────────────────────────────────────────────┤   │
│  │                                                               │   │
│  │  GPG Private Key          GPG Public Key                      │   │
│  │  (bob_gpg.sec)           (bob_gpg.pub)                        │   │
│  │       │                       │                               │   │
│  │       │                       └──→ Sent to CA during          │   │
│  │       │                            registration               │   │
│  │       │                                                       │   │
│  │       └──→ Signs CSR/nonce as proof of Bob's identity         │   │
│  │                                                               │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ TLS Key Pair (Ephemeral Session)                              │   │
│  ├───────────────────────────────────────────────────────────────┤   │
│  │                                                               │   │
│  │  TLS Private Key          TLS Public Key                      │   │
│  │  (bob_tls.key)           (in CSR)                             │   │
│  │       │                       │                               │   │
│  │       │                       └──→ Embedded in CSR, signed    │   │
│  │       │                            by CA into certificate     │   │
│  │       │                                                       │   │
│  │       ├──→ Self-signs CSR (proves possession)                 │   │
│  │       │                                                       │   │
│  │       └──→ Used for mTLS connections after cert issuance      │   │
│  │                                                               │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Complete Certificate Request with Both Keys

```bash
# Bob already has GPG key pair from registration
# Now Bob needs a TLS certificate for connections

# Step 1: Generate TLS key pair (or reuse existing)
bob$ openssl ecparam -genkey -name prime256v1 -out bob_tls.key

# Step 2: Create CSR containing TLS public key
bob$ openssl req -new -key bob_tls.key -out bob.csr \
  -subj "/CN=bob@cryptic.example.org"

# CSR now contains:
#   - Bob's TLS public key (extracted from bob_tls.key)
#   - Subject info (CN=bob@cryptic.example.org)
#   - Self-signature (using bob_tls.key, proves possession)

# Step 3: Sign CSR with GPG private key as proof of identity
bob$ gpg --detach-sign --armor -o csr_proof.sig bob.csr

# Step 4: Submit to CA
bob$ curl -X POST https://ca.example.org/ca/v1/csr \
  -d '{
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "gpg_fp": "6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A",
    "gpg_sig_b64": "BASE64(csr_proof.sig)"
  }'

# CA verifies:
#   1. CSR is well-formed and self-signed correctly (TLS key)
#   2. gpg_fp is in verified status (from registration)
#   3. GPG signature over CSR is valid (proves Bob's identity)
#   4. Issues certificate binding Bob's identity to TLS public key

# Step 5: Receive certificate
# bob_cert.pem contains:
#   - Bob's TLS public key (from CSR)
#   - CA's signature (vouching for Bob's identity)
#   - Expiry time (24-168 hours from now)
#   - Subject: CN=bob@cryptic.example.org

# Step 6: Use for mTLS connections
bob$ cryptic connect --cert bob_cert.pem --key bob_tls.key
```

### Why Two Separate Key Pairs?

**Separation of Concerns**:
- **GPG key** = Who you are (identity)
- **TLS key** = Current session credential (authorization)

**Security Benefits**:
1. **Limited blast radius**: Compromised TLS key doesn't compromise GPG identity
2. **Easy rotation**: TLS key can be regenerated at any cert renewal
3. **Revocation scope**: Can revoke certificate without revoking GPG key
4. **Algorithm flexibility**: Can use different crypto (e.g., GPG: RSA 4096, TLS: ECDSA P-256)
5. **Temporal isolation**: Old TLS keys become useless after cert expires

**Operational Benefits**:
1. **Backup strategy**: GPG key backed up carefully, TLS key can be ephemeral
2. **Key storage**: GPG key on secure device, TLS key on application server
3. **Multi-device**: Same GPG identity, different TLS keys per device
4. **Renewal simplicity**: New cert with new TLS key, same GPG proof

### Common Workflow Patterns

**Initial Onboarding** (uses GPG key):
1. Alice creates invite, signs with her GPG key
2. Bob generates GPG key pair
3. Bob submits invite + GPG public key
4. CA verifies and registers Bob's GPG fingerprint

**Certificate Issuance** (uses both keys):
1. Bob generates TLS key pair
2. Bob creates CSR with TLS public key
3. Bob signs CSR with GPG private key
4. CA issues certificate for TLS public key

**Daily Usage** (uses TLS key):
1. Bob connects with TLS certificate + private key
2. Server verifies certificate via mTLS
3. Secure connection established

**Certificate Renewal** (uses both keys):
1. Bob generates new TLS key pair (or reuses old)
2. Bob creates new CSR
3. Bob signs CSR with same GPG private key
4. CA issues new certificate (no new invite needed)

### Key Format Examples

**GPG Public Key** (sent during registration):
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGcOXBkBDAC8h3wvXxGPQdF0...
=abcd
-----END PGP PUBLIC KEY BLOCK-----
```

**TLS Private Key** (kept secret):
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIqhdmFgNOKd3E88WR...
-----END EC PRIVATE KEY-----
```

**CSR** (contains TLS public key):
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBVDCBuwIBADAmMSQwIgYDVQ...
-----END CERTIFICATE REQUEST-----
```

**GPG Signature over CSR** (proves identity):
```
-----BEGIN PGP SIGNATURE-----
iQGzBAABCgAdFiEEaiwfjYs+Si...
-----END PGP SIGNATURE-----
```

**Issued Certificate** (TLS public key + CA signature):
```
-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIRAKBag9...
-----END CERTIFICATE-----
```

### Summary

| Aspect | GPG Key Pair | TLS Key Pair |
|--------|-------------|--------------|
| **Purpose** | Prove identity to CA | Authenticate to servers |
| **Lifespan** | Years (permanent identity) | Hours/days (via cert expiry) |
| **Usage** | Sign invites, CSRs, proofs | mTLS connections |
| **Rotation** | Rare, requires re-registration | Frequent, with cert renewal |
| **Compromise impact** | Identity stolen | Session compromised |
| **Storage** | Carefully backed up | Can be ephemeral |
| **Sent to CA** | Public key during registration | Public key in CSR |

This two-key architecture provides **defense in depth**: even if a TLS key is compromised, the attacker cannot create new certificates without Bob's GPG private key.

## Token Design Choices

Two main design options:

1. **Minimal self-contained token** — Contains inviter fingerprint, nonce,
   expiry, and a detached GPG signature. Lightweight, CA must already know
  inviter's GPG pubkey or be able to fetch it.

2. **Self-contained inviter pubkey token** — Includes inviter's full public
   key inside the token. Verifiable immediately but increases token size and
may permit inviter impersonation if token creation is not out-of-band protected.

This spec uses the **minimal self-contained token** with an optional
`inviter_pub` field if CA lacks inviter pubkey.

## Token Fields

The token is a JSON object with the following fields:

```json
{
  "inviter_fp": "6A2C...F3B1",      // Short hex/colonless 40/64 chars fingerprint
  "invite_id": "inv-8f3b12",        // Unique token identifier (UUID or random)
  "issued_at": "2025-10-26T09:30:00Z",
  "expires_at": "2025-10-27T09:30:00Z",
  "nonce": "r4nd0m-32-bytes",       // Optional: protects against replay
  "aud": "ca.example.org",          // Optional: intended CA audience
  "scope": {                        // Optional: scope or usage
    "caps": ["gpg-register"]
  },
  "meta": {                         // Optional: human note
    "inviter_label": "Alice-phone"
  }
}
```

This JSON is signed by the inviter's GPG key. The `invite_token` that gets
shared is the ASCII-armored JSON + ASCII-armored detached signature (or a
combined armored block).

## REST API

### 1. Create Invite (Inviter → Client UI / Script)

No CA call needed if inviter signs locally. Optionally the CA can create/log
the token on behalf of the inviter.

#### Local Creation (Recommended)

Inviter creates token JSON locally and produces detached ASCII-armored signature:

```bash
inviter$ echo -n '{"inviter_fp":"6A2C...","invite_id":"inv-8f3b12",...}' > token.json
inviter$ gpg --clearsign --output token.json.asc token.json
# Hand token.json.asc to invitee
```

#### Optional Server-Side Generation

```http
POST /ca/v1/invite
Authorization: mTLS (inviter client cert)
Content-Type: application/json

{
  "expiry_hours": 24,
  "meta": {...}
}
```

**Response:**
```json
{
  "invite_id": "inv-8f3b12",
  "token": "<signed token>"
}
```

CA may store `invite_id` and `inviter_fp`.

### 2. Register GPG Pubkey Using Invite (Invitee → CA)

#### Endpoint

```http
POST /ca/v1/register-gpg
Content-Type: multipart/form-data or application/json
```

#### Fields

- `invite_token`: ASCII-armored signed token (string)
- `gpg_pub_armor`: ASCII-armored GPG public key (string)
- `proof_signature`: (optional) signature over a CA-provided nonce (if 2-step)
- `client_auth`: (optional) session info (not required for initial registration)

#### Example JSON Body

```json
{
  "invite_token": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{...}\n-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
  "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "bind_proof": "B64(sig of nonce by new GPG key)"
}
```

#### Response

- **200 OK** → `{ "status": "verified", "gpg_fp": "...", "issued_at": "..."}`
- **202 Accepted** → `{ "status": "pending", "reason": "invite accepted; awaiting admin" }`
- **4xx** → error details

## Sequence Diagram

```
Alice (inviter)                  Bob (invitee)                    CA
      |                                |                           |
      | 1. Generate token.json         |                           |
      |    and sign with GPG           |                           |
      |--------------------------------→                           |
      |    Send token.json.asc         |                           |
      |                                |                           |
      |                                | 2. Prepare gpg_pub.asc    |
      |                                |    POST /register-gpg     |
      |                                |---------------------------→
      |                                |                           |
      |                                |    3. Verify signature    |
      |                                |       Check expiry        |
      |                                |       Verify GPG pubkey   |
      |                                |                           |
      |                                |←--------------------------|
      |                                |    4. Return verification |
```

## Detailed Sequence

1. **Alice (inviter)**: Generates `token.json` locally and signs it with GPG:
   ```bash
   token.json.asc = GPG.sign(token.json)
   ```
   She sends `token.json.asc` to Bob.

2. **Bob (invitee)**: Prepares `gpg_pub.asc` (his public key) and POSTs to
   `/ca/v1/register-gpg` with `invite_token = token.json.asc`.

3. **CA**: Upon receiving the request:
   - Parses `invite_token` to extract `token_json`
   - Verifies `signature(inviter_fp, token_json)`:
     - Fetch inviter GPG pubkey from CA store (or keyserver) by `inviter_fp`
     - Or, if token included `inviter_pub`, use it and check `inviter_fp` matches
   - Checks `expires_at`, `invite_id` not used already, `aud` matches
   - Verifies `gpg_pub` is well-formed; computes `gpg_fp` (fingerprint)
   - Optionally asks for a `bind_proof`: CA sends nonce earlier; invitee
     returns `signature(nonce, gpg_priv)`
   - If all checks pass → set `{gpg_fp, status: verified-via-invite}`

## Example Token

### token.json

```json
{
  "inviter_fp": "6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A",
  "invite_id": "inv-8f3b12",
  "issued_at": "2025-10-26T09:30:00Z",
  "expires_at": "2025-10-27T09:30:00Z",
  "nonce": "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6",
  "aud": "ca.example.org"
}
```

Signed to produce `token.json.asc` using `gpg --clearsign token.json`.

## Binding & Anti-Replay Mechanisms

- **Invite uniqueness**: `invite_id` must be random and checked for one-time
  use (mark consumed after successful registration)
- **Nonce binding**: The token should include a nonce or `email_hash` to allow
  CA to require invitee to sign a fresh challenge or include proof that the
  invitee holds the GPG private key
- **Short TTL**: Tokens should be short-lived (e.g., 24–72 hours)
- **One-time use**: Tokens should be single-use by `invite_id`
- **Rate-limiting**: CA should limit registrations per inviter to prevent
  mass invites
- **Replay protection**: When CA accepts a token it marks `invite_id` consumed;
  subsequent use fails

## Verification Logic (Pseudocode)

```python
function handle_register_gpg(invite_token_armored, gpg_pub_armored, optional_bind_proof):
    token_json, sig = parse_clearsigned(invite_token_armored)
    inviter_fp = token_json["inviter_fp"]
    invite_id = token_json["invite_id"]
    expires_at = token_json["expires_at"]
    nonce = token_json.get("nonce")

    if current_time() > expires_at:
        return error("token expired")

    if invite_already_consumed(invite_id):
        return error("token already used")

    # Fetch inviter public key (from CA store or token)
    inviter_pub = get_inviter_pubkey(inviter_fp)
    if not inviter_pub:
        return error("unknown inviter")

    if not verify_gpg_signature(inviter_pub, token_json, sig):
        return error("invalid token signature")

    # Now validate candidate GPG pubkey
    if not is_valid_gpg_pubkey(gpg_pub_armored):
        return error("invalid gpg pubkey")

    gpg_fp = fingerprint_of(gpg_pub_armored)

    # Optional: require proof-of-possession by verifying a signature over the nonce 
    if nonce is not None:
        if not optional_bind_proof:
            return error("bind proof required")
        if not verify_signature_with_pubkey(gpg_pub_armored, nonce, optional_bind_proof):
            return error("bind proof invalid")

    # Register the gpg key as verified
    store_gpg_registration(
        gpg_fp, gpg_pub_armored, inviter_fp, invite_id, 
        verified=true, timestamp=now()
    )

    mark_invite_consumed(invite_id)

    return success({"status": "verified", "gpg_fp": gpg_fp})
```

## Erlang Implementation Sketch

This is a high-level sketch — adapt to your OTP/DB stack (Mnesia/ETS/PostgreSQL).

### Parse and Verify Clearsigned Token

```erlang
%% @doc Parse and verify clearsigned token
-spec verify_invite_token(string()) -> {ok, TokenJson} | {error, term()}.
verify_invite_token(TokenArmored) ->
    case gpg:clearsign_parse(TokenArmored) of
        {ok, TokenJson, Sig, SignerKeyId} ->
            InviterFP = maps:get(<<"inviter_fp">>, TokenJson),
            case ca_store:get_inviter_pubkey(InviterFP) of
                {ok, InviterPub} ->
                    case gpg:verify_detached(InviterPub, TokenJson, Sig) of
                        ok -> {ok, TokenJson};
                        {error, _} = Err -> Err
                    end;
                error -> {error, inviter_unknown}
            end;
        {error, _} = Err -> Err
    end.
```

### Main Endpoint Handler

```erlang
%% @doc Main endpoint handler for GPG registration
handle_register_gpg(RequestBody) ->
    TokenArmored = maps:get(<<"invite_token">>, RequestBody),
    GpgPubArmored = maps:get(<<"gpg_pub">>, RequestBody),
    BindProofB64 = maps:get(<<"bind_proof">>, RequestBody, undefined),

    case verify_invite_token(TokenArmored) of
        {ok, TokenJson} ->
            InviteId = maps:get(<<"invite_id">>, TokenJson),
            ExpiresAt = parse_datetime(maps:get(<<"expires_at">>, TokenJson)),
            Now = erlang:system_time(second),
            
            if 
                Now > ExpiresAt -> 
                    reply_error(expired);
                ca_store:invite_used(InviteId) -> 
                    reply_error(already_used);
                true ->
                    case gpg_lib:is_valid_pub(GpgPubArmored) of
                        true ->
                            GpgFP = gpg_lib:fingerprint(GpgPubArmored),
                            InviterFP = maps:get(<<"inviter_fp">>, TokenJson),

                            % Optional bind proof verification
                            case maps:is_key(<<"nonce">>, TokenJson) of
                                true ->
                                    Nonce = maps:get(<<"nonce">>, TokenJson),
                                    case verify_bind_proof(GpgPubArmored, BindProofB64, Nonce) of
                                        ok -> 
                                            register_and_reply(InviteId, InviterFP, GpgFP, GpgPubArmored);
                                        {error, _} = E -> 
                                            reply_error(E)
                                    end;
                                false -> 
                                    register_and_reply(InviteId, InviterFP, GpgFP, GpgPubArmored)
                            end;
                        false -> 
                            reply_error(invalid_gpg_pub)
                    end
            end;
        {error, Reason} -> 
            reply_error(Reason)
    end.
```

### Notes

- `gpg:clearsign_parse/1`, `gpg:verify_detached/3`, `gpg_lib:is_valid_pub/1`
  are placeholders for whichever GPG integration library you use (gpgme,
  command-line gpg, or an Erlang binding)
- Use sandboxing and safe argument passing when invoking external GPG process

## CA-Side Storage Schema

### Invites Table

```erlang
invites => #{
    invite_id => #{
        inviter_fp => binary(),
        issued_at => integer(),
        expires_at => integer(),
        consumed => boolean(),
        consumed_at => integer() | null,
        meta => map()
    }
}
```

### GPG Registry Table

```erlang
gpg_registry => #{
    gpg_fp => #{
        gpg_pub_armor => binary(),
        status => verified_via_invite | pending | revoked,
        inviter_fp => binary(),     % Who invited them
        registered_at => integer(),
        last_seen => integer()
    }
}
```

**Privacy Note**: Keep only what you need. Avoid storing PII or email unless
explicitly required.

## Certificate Issuance (After Verification)

Once `gpg_fp` is verified:

1. **Invitee creates local CSR** and signs it with GPG as proof:
   - CSR (PKCS#10) created locally
   - `proof_sig = Sign_GPG(CSR || nonce)` or `Sign_GPG(nonce)` provided by CA

2. **Invitee POSTs CSR** + `gpg_fp` to `/ca/v1/csr`

3. **CA verifies**:
   - `gpg_fp` is verified
   - `proof_sig` validates using stored `gpg_pub`
   - Optionally binds CSR fields (e.g., SANs) to allowed patterns

4. **CA issues** short-lived client cert and returns

### Example CSR Request

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "gpg_fp": "6A2C1F...",
  "gpg_sig_b64": "BASE64(...)"
}
```

CA verifies `gpg_sig_b64` is a valid signature over CSR (or CA-provided nonce)
using stored `gpg_pub`.

## Anti-Abuse & Operational Policies

- **Invite rate limits**: Limit invites per inviter per day
- **Invite moderation**: Optionally require trusted-inviter lists for
  new registrants
- **Short cert lifetime**: Keep client certs short-lived (24–168 hours) to
  reduce need for revocation
- **Revoke on compromise**: Expose admin API to mark `gpg_fp` as revoked;
  CA rejects CSRs/cert usage
- **Log minimally and redact**: Store only invites and fingerprints; avoid
  storing PGP private material or full PGP keyrings unless needed
- **Key rotation**: Allow inviter to rotate GPG keys; treat rotated keys as
  new fingerprint and optionally require re-invite
- **Fallback TOFU**: Allow self-registration without invite but mark as pending
  or require manual approval

## Example End-to-End Flow

### Step 1: Alice Creates Invite

```bash
# Alice creates token.json, signs with GPG → token.json.asc and gives to Bob
alice$ gpg --clearsign token.json
```

### Step 2: Bob Registers

```bash
# Bob registers his GPG public key
bob$ curl -X POST https://ca.example.org/ca/v1/register-gpg \
  -F "invite_token=@token.json.asc" \
  -F "gpg_pub=@bob.pub.asc"
```

CA verifies signer (Alice), checks token expiry, computes `gpg_fp` for Bob,
returns `200 verified`.

### Step 3: Bob Requests Certificate

```bash
# Bob creates CSR locally, signs CSR with his GPG key over CA nonce
bob$ curl -X POST https://ca.example.org/ca/v1/csr \
  -d '{"csr":"...","gpg_fp":"...","gpg_sig_b64":"..."}'
```

### Step 4: CA Issues Certificate

CA issues `client.crt` (short TTL). Bob uses it for mTLS.

## Integration Tips for Erlang/OTP

- Use `gpgme` or spawn `gpg` in a tightly controlled environment to validate
  clearsigned tokens and verify detached signatures
- Keep GPG operations synchronous and sandboxed; avoid long-running gpg
  processes per request
- Use Mnesia or ETS for fast invite lookups and consumption tracking
- Consider rate-limiting at the cowboy/elli handler level
- Log invite creation and consumption events for audit trails

Token design choices

Two main design options:

Minimal self-contained token — contains inviter fingerprint, nonce, expiry,
and a detached GPG signature. Lightweight, CA must already know inviter’s
GPG pubkey or be able to fetch it.

Self-contained inviter pubkey token — includes inviter’s full public key
inside the token. Verifiable immediately but increases token size and may
permit inviter impersonation if token creation is not out-of-band protected.

This spec uses the minimal self-contained token with an optional inviter_pub 
field if CA lacks inviter pubkey.

Token fields (JSON)
```json
{
  "inviter_fp": "6A2C...F3B1",      // short hex/colonless 40/64 chars fingerprint
  "invite_id": "inv-8f3b12",        // unique token identifier (UUID or random)
  "issued_at": "2025-10-26T09:30:00Z",
  "expires_at": "2025-10-27T09:30:00Z",
  "nonce": "r4nd0m-32-bytes",       // optional: protects against replay
  "aud": "ca.example.org",          // optional: intended CA audience
  "scope": { "caps": ["gpg-register"] }, // optional: scope or usage
  "meta": { "inviter_label": "Alice-phone" } // optional human note
}
```


This JSON is signed by the inviter’s GPG key. The invite_token that gets 
shared is the ASCII-armored JSON + ASCII-armored detached signature (or a
combined armored block).

## REST API (suggested)
1. Create invite (inviter → client UI / script)

No CA call needed if inviter signs locally. Optionally the CA can create/log the token on behalf of the inviter.

Local creation (recommended): inviter creates token JSON locally and produces detached ASCII-armored signature:

inviter$ echo -n '{"inviter_fp":"6A2C...","invite_id":"inv-8f3b12",...}' > token.json
inviter$ gpg --clearsign --output token.json.asc token.json
# Hand token.json.asc to invitee


Optional server-side generation (CA endpoint)

POST /ca/v1/invite
Authorization: mTLS (inviter client cert)
Body: { "expiry_hours": 24, "meta": {...} }
Response: { "invite_id": "inv-8f3b12", "token": "<signed token>" }


CA may store invite_id and inviter_fp.

2. Register GPG pubkey using invite (invitee → CA)

Endpoint

POST /ca/v1/register-gpg
Content-Type: multipart/form-data or application/json
Fields:
 - invite_token: ASCII-armored signed token (string)
 - gpg_pub_armor: ASCII-armored GPG public key (string)
 - proof_signature: (optional) signature over a CA-provided nonce (if 2-step)
 - client_auth: (optional) session info (not required for initial registration)


Example JSON body (compact)

{
  "invite_token": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{...}\n-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
  "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  "bind_proof": "B64(sig of nonce by new GPG key)"
}


Response

200 OK → { "status": "verified", "gpg_fp": "...", "issued_at": "..."}

202 Accepted → { "status": "pending", "reason": "invite accepted; awaiting admin" }

4xx → error details.

Sequence (textual)

Alice (inviter): generates token.json locally and signs it with GPG:

token.json.asc = GPG.sign(token.json)

She sends token.json.asc to Bob.

Bob (invitee): prepares gpg_pub.asc (his public key) and POSTs to /ca/v1/register-gpg with invite_token = token.json.asc.

CA: upon receiving the request:

Parses invite_token to extract token_json.

Verifies signature(inviter_fp, token_json):

Fetch inviter GPG pubkey from CA store (or keyserver) by inviter_fp.

Or, if token included inviter_pub, use it and check inviter_fp matches.

Checks expires_at, invite_id not used already, aud matches.

Verifies gpg_pub is well-formed; computes gpg_fp (fingerprint).

Optionally asks for a bind_proof: CA sends nonce earlier; invitee returns signature(nonce, gpg_priv).

If all checks pass → set {gpg_fp, status: verified-via-invite}.

Example token (ASCII-armored)

token.json:

```json
{
  "inviter_fp": "6A2C1F8D8B3E4A2F9C3B5D6E7F1A2B3C4D5E6F7A",
  "invite_id": "inv-8f3b12",
  "issued_at": "2025-10-26T09:30:00Z",
  "expires_at": "2025-10-27T09:30:00Z",
  "nonce": "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6",
  "aud": "ca.example.org"
}
```

Signed to produce token.json.asc using gpg --clearsign token.json.

Binding & anti-replay (practical considerations)

Invite uniqueness: invite_id must be random and checked for one-time use
(mark consumed after successful registration).

Nonce binding: the token should include a nonce or email_hash to allow CA
to require invitee to sign a fresh challenge or include proof that the
invitee holds the GPG private key.

Short TTL: tokens should be short-lived (e.g., 24–72 hours).

One-time use: tokens should be single-use by invite_id.

Rate-limiting: CA should limit registrations per inviter to prevent mass invites.

Replay protection: when CA accepts a token it marks invite_id consumed; subsequent use fails.


Verification logic — pseudocode (language-agnostic)
```
function handle_register_gpg(invite_token_armored, gpg_pub_armored, optional_bind_proof):
    token_json, sig = parse_clearsigned(invite_token_armored)
    inviter_fp = token_json["inviter_fp"]
    invite_id = token_json["invite_id"]
    expires_at = token_json["expires_at"]
    nonce = token_json.get("nonce")

    if current_time() > expires_at:
        return error("token expired")

    if invite_already_consumed(invite_id):
        return error("token already used")

    # fetch inviter public key (from CA store or token)
    inviter_pub = get_inviter_pubkey(inviter_fp)
    if not inviter_pub:
        return error("unknown inviter")

    if not verify_gpg_signature(inviter_pub, token_json, sig):
        return error("invalid token signature")

    # Now validate candidate GPG pubkey
    if not is_valid_gpg_pubkey(gpg_pub_armored):
        return error("invalid gpg pubkey")

    gpg_fp = fingerprint_of(gpg_pub_armored)

    # Optional: require proof-of-possession by verifying a signature over the nonce 
    # (either signed by the new gpg key or a CA challenge signed)
    if nonce is not None:
        if not optional_bind_proof:
            return error("bind proof required")
        if not verify_signature_with_pubkey(gpg_pub_armored, nonce, optional_bind_proof):
            return error("bind proof invalid")

    # register the gpg key as verified
    store_gpg_registration(gpg_fp, gpg_pub_armored, inviter_fp, invite_id, verified=true, timestamp=now())

    mark_invite_consumed(invite_id)

    return success({ "status": "verified", "gpg_fp": gpg_fp })
```

## Erlang-style sketch (verification + storage)

This is a high-level sketch — adapt to your OTP/DB stack (Mnesia/ETS/pgsql).

 ```erlang
%% parse and verify clearsigned token
-spec verify_invite_token(string()) -> {ok, TokenJson} | {error, term()}.
verify_invite_token(TokenArmored) ->
    case gpg:clearsign_parse(TokenArmored) of
        {ok, TokenJson, Sig, SignerKeyId} ->
            InviterFP = maps:get(<<"inviter_fp">>, TokenJson),
            case ca_store:get_inviter_pubkey(InviterFP) of
                {ok, InviterPub} ->
                    case gpg:verify_detached(InviterPub, TokenJson, Sig) of
                        ok -> {ok, TokenJson};
                        {error, _} = Err -> Err
                    end;
                error -> {error, inviter_unknown}
            end;
        {error, _} = Err -> Err
    end.

%% main endpoint handler
handle_register_gpg(RequestBody) ->
    TokenArmored = RequestBody#{"invite_token"},
    GpgPubArmored = RequestBody#{"gpg_pub"},
    BindProofB64 = maps:get("bind_proof", RequestBody, undefined),

    case verify_invite_token(TokenArmored) of
        {ok, TokenJson} ->
            InviteId = maps:get(<<"invite_id">>, TokenJson),
            ExpiresAt = parse_datetime(maps:get(<<"expires_at">>, TokenJson)),
            now = erlang:system_time(second),
            if now > ExpiresAt -> reply_error(expired);
               ca_store:invite_used(InviteId) -> reply_error(already_used);
               true ->
                    case gpg_lib:is_valid_pub(GpgPubArmored) of
                        true ->
                            GpgFP = gpg_lib:fingerprint(GpgPubArmored),
                            % optional bind proof verification
                            case maps:is_key(<<"nonce">>, TokenJson) of
                                true ->
                                    Nonce = maps:get(<<"nonce">>, TokenJson),
                                    case verify_bind_proof(GpgPubArmored, BindProofB64, Nonce) of
                                        ok -> register_and_reply(InviteId, InviterFP, GpgFP, GpgPubArmored);
                                        {error,_} = E -> reply_error(E)
                                    end;
                                false -> register_and_reply(InviteId, InviterFP, GpgFP, GpgPubArmored)
                            end;
                        false -> reply_error(invalid_gpg_pub)
                    end
            end;
        {error, Reason} -> reply_error(Reason)
    end.
```

Notes:

gpg:clearsign_parse/1, gpg:verify_detached/3, gpg_lib:is_valid_pub/1 are
placeholders for whichever GPG integration library you use (gpgme,
command-line gpg, or an Erlang binding).

Use sandboxing and safe argument passing when invoking external GPG process.

CA-side storage schema (minimal)
```
invites: {
  invite_id => {
     inviter_fp,
     issued_at,
     expires_at,
     consumed: bool,
     consumed_at: timestamp | null,
     meta: {...}
  }
}

gpg_registry: {
  gpg_fp => {
     gpg_pub_armor,
     status: "verified-via-invite" | "pending" | "revoked",
     inviter_fp,     % who invited them
     registered_at,
     last_seen
  }
}
```

You should keep only what you need.
Avoid storing PII or email unless explicitly required.


Certificate issuance (after verification)

Once gpg_fp is verified:

Invitee creates local CSR and signs it with GPG as a proof:

CSR (PKCS#10) created locally.

proof_sig = Sign_GPG(CSR || nonce) or Sign_GPG(nonce) provided by CA.

Invitee POSTs CSR + gpg_fp to /ca/v1/csr.

CA verifies:

gpg_fp is verified.

proof_sig validates using stored gpg_pub.

Optionally binds CSR fields (e.g., SANs) to allowed patterns.

CA issues short-lived client cert and returns.

Example CSR request (JSON):

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "gpg_fp": "6A2C1F...",
  "gpg_sig_b64": "BASE64(...)"
}
```

CA verifies gpg_sig_b64 is a valid signature over CSR (or CA-provided nonce)
using stored gpg_pub.


## Anti-abuse & operational policies

Invite rate limits: limit invites per inviter per day.

Invite moderation: optionally require trusted-inviter lists for new registrants.

Short cert lifetime: keep client certs short-lived (24–168 hours) to reduce need for revocation.

Revoke on compromise: expose admin API to mark gpg_fp as revoked; CA rejects CSRs / cert usage.

Log minimally and redact: store only invites and fingerprints; avoid storing PGP private material or full PGP keyrings unless needed.

Key rotation: allow inviter to rotate GPG keys; treat rotated keys as new fingerprint and optionally require re-invite.

Fallback TOFU: allow self-registration without invite but mark as pending or require manual approval.

Example end-to-end (compact)

Alice creates token.json, signs with GPG → token.json.asc and gives to Bob.

Bob runs:

```bash
curl -X POST https://ca.example.org/ca/v1/register-gpg \
  -F "invite_token=@token.json.asc" \
  -F "gpg_pub=@bob.pub.asc"
```

CA verifies signer (Alice), checks token expiry, computes gpg_fp for Bob,
optionally sends back 200 verified.

Bob creates CSR locally, signs CSR with his GPG key over CA nonce:

```bash
curl -X POST https://ca.example.org/ca/v1/csr \
  -d '{"csr":"...","gpg_fp":"...","gpg_sig_b64":"..."}'
```

CA issues client.crt (short TTL). Bob uses it for mTLS.

## Onboarding Flow Summary

The complete onboarding process follows these steps:

1. **Alice (existing verified user)** creates an invite token:
   - Generates JSON token with her GPG fingerprint, invite ID, expiry, and nonce
   - Signs the token with her GPG private key
   - Shares the signed token with Bob out-of-band (QR code, email, secure message)

2. **Bob (new user)** receives the invite and prepares to register:
   - Exports his GPG public key
   - Submits both the invite token and his GPG public key to `/ca/v1/register-gpg`

3. **CA verifies the registration**:
   - Validates Alice's signature on the invite token
   - Checks token hasn't expired or been used
   - Optionally verifies Alice is a trusted inviter
   - Validates Bob's GPG public key format
   - Computes Bob's GPG fingerprint
   - Optionally requires proof-of-possession (Bob signs a nonce)
   - Marks Bob's GPG fingerprint as `verified-via-invite`

4. **Bob requests a certificate**:
   - Creates a local PKCS#10 CSR
   - Signs the CSR (or a CA-provided nonce) with his GPG key
   - Posts CSR + GPG fingerprint + signature to `/ca/v1/csr`

5. **CA issues certificate**:
   - Verifies Bob's GPG fingerprint is verified
   - Validates the GPG signature over the CSR/nonce
   - Issues short-lived client certificate (24-168 hours)
   - Returns certificate to Bob

6. **Bob uses certificate for mTLS**:
   - Establishes secure connections using the client certificate
   - Certificate proves Bob's identity tied to his GPG key

**Key point**: This is **invitation-based**, not open registration. Bob cannot self-register without an invite from an existing trusted user (Alice). This creates a Web of Trust model where the CA delegates trust decisions to its existing verified users.

## Certificate Expiry & Renewal

Client certificates are intentionally short-lived (24-168 hours) to limit exposure if compromised. When a certificate expires:

### What Happens on Expiry

1. **mTLS authentication fails** - The expired certificate can no longer be used for mutual TLS connections
2. **Client detects expiration** - Clients should proactively check certificate validity (e.g., on startup or periodically)
3. **Service interruption** - Without a valid certificate, the client cannot connect

### Renewal Process

Since the client's GPG key is already registered and verified, renewal is **much simpler** than initial onboarding:

1. **Client generates new CSR**:
   ```bash
   openssl req -new -key client.key -out client.csr
   ```

2. **Client signs proof with existing GPG key**:
   ```bash
   gpg --detach-sign --armor -o csr_proof.sig client.csr
   ```

3. **Client requests new certificate**:
   ```bash
   curl -X POST https://ca.example.org/ca/v1/csr \
     -d '{
       "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
       "gpg_fp": "6A2C1F...",
       "gpg_sig_b64": "BASE64(...)"
     }'
   ```

4. **CA verifies and issues**:
   - Verifies `gpg_fp` is still in good standing (not revoked)
   - Validates GPG signature proves possession of private key
   - Issues new short-lived certificate

### Key Characteristics

- **No new invite needed** - The GPG key is already registered in the trust domain
- **Same GPG identity** - Client continues using the same GPG key
- **Automated renewal** - Clients should implement automatic renewal before expiration
- **Proactive timing** - Renew at ~50% of certificate lifetime to avoid service interruption
- **Grace period** - Consider allowing renewal slightly before expiration
- **Revocation check** - CA must verify GPG fingerprint hasn't been revoked
- **Audit trail** - Log all certificate issuances for security monitoring

### Erlang Client Renewal Sketch

```erlang
%% @doc Check if certificate needs renewal and renew if necessary
-spec check_and_renew_cert(CertPath, KeyPath, GpgFP) -> ok | {error, term()}.
check_and_renew_cert(CertPath, KeyPath, GpgFP) ->
    case cert_utils:get_expiry(CertPath) of
        {ok, ExpiryTime} ->
            Now = erlang:system_time(second),
            TimeToExpiry = ExpiryTime - Now,
            RenewalThreshold = 3600 * 12,  % Renew at 50% of 24h lifetime
            
            if TimeToExpiry < RenewalThreshold ->
                renew_certificate(CertPath, KeyPath, GpgFP);
               true ->
                ok
            end;
        {error, _} = Err -> Err
    end.

%% @doc Renew client certificate using existing GPG key
-spec renew_certificate(CertPath, KeyPath, GpgFP) -> ok | {error, term()}.
renew_certificate(CertPath, KeyPath, GpgFP) ->
    % Generate new CSR
    {ok, CSR} = openssl:gen_csr(KeyPath),
    
    % Sign CSR with GPG key
    {ok, Signature} = gpg:sign_detached(CSR, GpgFP),
    
    % Request new certificate from CA
    ReqBody = #{
        <<"csr_pem">> => CSR,
        <<"gpg_fp">> => GpgFP,
        <<"gpg_sig_b64">> => base64:encode(Signature)
    },
    
    case http_client:post("https://ca.example.org/ca/v1/csr", ReqBody) of
        {ok, #{<<"cert_pem">> := NewCert}} ->
            file:write_file(CertPath, NewCert);
        {error, _} = Err -> Err
    end.
```

### Best Practices

- **Monitor expiry** - Check certificate validity on every client startup
- **Retry logic** - Implement exponential backoff if renewal fails
- **Backup certificates** - Keep previous valid certificate during renewal
- **Atomic replacement** - Only replace old certificate after successful renewal
- **Alert on failure** - Notify users/admins if renewal repeatedly fails
- **Pre-expiry notification** - Warn users before certificate expires

## Real-World Usage & Validation

The invitation-based onboarding pattern using cryptographic identities is well-established and used in several production systems. This section validates the design choices and provides context on similar implementations.

### Existing Implementations

**PGP/GPG Web of Trust**
- This protocol is essentially a modernized, API-driven version of the classic PGP Web of Trust
- Classic model: Key signing parties where people verify identities in person and sign keys
- Your approach: Automates this with invite tokens instead of physical meetings
- Innovation: JSON tokens with REST API instead of manual key signing

**Signal's Safety Numbers**
- Uses QR codes and safety numbers for out-of-band key verification
- Similar trust model but for end-to-end encryption keys
- Widely regarded as user-friendly and secure
- Demonstrates that cryptographic verification can have good UX

**Tailscale/Headscale**
- Uses invite tokens for joining private networks
- Authentication via OIDC/SSO instead of GPG
- Similar trust delegation to network administrators
- Proven scalable in production environments

**Matrix Homeserver Invitations**
- Federated chat protocol with invite-based room/server joining
- Trust flows through existing members
- Demonstrates scalability in federated systems
- Similar use case to cryptic (federated messaging)

**Keybase (archived but influential)**
- Used proof-based verification (social media, websites, GPG)
- Invite system for teams with cryptographic verification
- Showed GPG-based systems can have accessible UX
- Validated combining GPG with modern API design

**SPIFFE/SPIRE**
- Workload identity framework using attestation
- For services rather than humans, but similar delegation pattern
- Production use at major cloud providers
- Demonstrates scalability of cryptographic identity delegation

### Why This Approach Is Effective

**Security Benefits:**
- **No central trust bottleneck** - Distributed trust model scales without single point of failure
- **Cryptographic proof** - Much harder to forge than passwords, emails, or SMS codes
- **Auditability** - Clear chain of who invited whom enables trust graph analysis
- **Revocation control** - Can track and revoke based on inviter relationships
- **Replay resistance** - Nonce binding and one-time tokens prevent reuse

**Operational Benefits:**
- **Reduces admin burden** - No manual approval required for each user
- **Natural rate limiting** - Inviters won't spam if they're accountable for invitees
- **Organic growth** - Mirrors real social trust networks
- **Self-moderating** - Bad inviters can lose invitation privileges
- **Privacy-preserving** - Only fingerprints stored, no PII required

**Architectural Benefits:**
- **Federated-friendly** - Doesn't require central identity provider
- **Offline-capable** - Tokens can be created and verified offline
- **API-driven** - Easy to integrate with various clients
- **Standards-based** - Uses existing GPG/TLS infrastructure

### Design Innovations

Your implementation adds several improvements over classic Web of Trust:

1. **JSON tokens instead of manual key signing**
   - Machine-readable, API-friendly format
   - Easier to integrate with modern applications
   - Can include metadata (expiry, scope, nonce)

2. **Short-lived client certificates**
   - Reduces need for complex revocation infrastructure
   - Limits exposure window if compromised
   - Enables proactive security (renew frequently)

3. **Nonce binding**
   - Prevents replay attacks on invite tokens
   - Ties token to specific registration attempt
   - Additional layer beyond expiry-based protection

4. **One-time invite tokens**
   - Prevents token sharing/reuse
   - Clear audit trail of who used which invite
   - Rate limiting mechanism built in

5. **Status tracking**
   - `verified-via-invite`, `pending`, `revoked` states
   - Enables gradual trust elevation
   - Flexible policy enforcement

### Potential Challenges & Mitigations

**Challenge: Bootstrapping Problem**
- Need initial seed users to start invitation chain
- **Mitigation**: Admin-created initial users, then organic growth
- **Fallback**: Optional TOFU mode with manual approval for first users

**Challenge: Inviter Accountability**
- If Alice invites malicious Bob, is Alice responsible?
- **Mitigation**: Track `inviter_fp` in registry, can revoke Alice's invite privileges
- **Policy**: Implement reputation system or invite quotas

**Challenge: Key Management UX**
- GPG can be intimidating for non-technical users
- **Mitigation**: Provide CLI tools or GUI wrappers for key generation
- **Alternative**: Support multiple identity backends (GPG, age, minisign)
- **Future**: Consider browser-based WebCrypto for web clients

**Challenge: Exclusion Risk**
- Purely invite-based can create closed communities
- **Mitigation**: "Fallback TOFU" option with pending status
- **Policy**: Allow admin override or public invite tokens for open instances

**Challenge: Invite Token Leakage**
- Tokens could be intercepted or shared publicly
- **Mitigation**: Short TTL (24-72 hours), one-time use, nonce binding
- **Best Practice**: Use secure out-of-band channels (QR, encrypted email)

### Comparison with Alternative Approaches

**vs. OAuth/OIDC:**
- OAuth requires external identity provider (Google, GitHub, etc.)
- Your approach is self-contained and privacy-preserving
- Trade-off: OAuth easier for users, GPG more private

**vs. Email Verification:**
- Email can be intercepted, spoofed, or provider can read
- GPG provides cryptographic proof of identity
- Trade-off: Email ubiquitous, GPG requires setup

**vs. Phone/SMS Verification:**
- SMS vulnerable to SIM swapping attacks
- Requires sharing phone number (privacy concern)
- GPG more secure but less familiar to users

**vs. Open Registration:**
- Open registration enables spam, abuse, and sybil attacks
- Your approach naturally rate-limits via invitation accountability
- Better for communities prioritizing trust over scale

### Use Cases Best Suited for This Protocol

This invitation-based GPG registration is particularly well-suited for:

- **Privacy-focused messaging** (like cryptic) - No PII collection required
- **Federated systems** - No central identity provider needed
- **Trust-based communities** - Organic growth through existing relationships
- **Technical audiences** - Users comfortable with GPG/command-line tools
- **Small to medium deployments** - Sweet spot before scaling challenges emerge
- **Environments requiring strong identity** - Cryptographic proof preferred over passwords

### Validation & Industry Perspective

The pattern is **well-established and respected** in security-conscious communities:

- Used in production by privacy-focused projects (Tor, I2P, etc.)
- Academic research validates Web of Trust models for distributed systems
- Recommended by security professionals for high-assurance environments
- Proven scalable when combined with proper tooling

The key innovations in your design (JSON tokens, REST API, short-lived certs) make this approach **more practical for modern applications** while maintaining the security properties of classic GPG Web of Trust.

### Conclusion

Your invitation-based GPG registration protocol stands on solid theoretical and practical foundations. It's a pragmatic middle ground that balances:
- Security (cryptographic proof) vs. usability (API-driven)
- Privacy (no PII) vs. convenience (requires GPG setup)
- Openness (organic growth) vs. protection (invitation required)
- Centralization (single CA) vs. decentralization (distributed trust)

For cryptic's federated, privacy-focused messaging use case, this is an **excellent choice**.

ntegration tips for Erlang / OTP

Use gpgme or spawn gpg in a tightly controlled environment to validate clearsigned tokens and verify detached signatures.

Keep GPG operations synchronous and sandboxed; avoid long-running gpg processes per request.


