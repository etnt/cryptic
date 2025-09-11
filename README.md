# Cryptic - End-to-End Encrypted Chat System

A proof-of-concept implementation of an end-to-end encrypted chat system built in Erlang/OTP, demonstrating modern cryptographic protocols and secure message exchange.

## Overview

Cryptic implements a secure messaging system using:
- **X25519** key agreement for establishing shared secrets
- **XChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **HKDF-SHA256** key derivation with ephemeral-based salts for enhanced security
- **HTTP REST API** for prekey distribution and message delivery
- **Forward secrecy** through ephemeral keys for each message exchange

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Alice     │                    │     Bob     │
│             │                    │             │
│ 1. Generate │                    │ 1. Upload   │
│    ephemeral│                    │    prekey   │
│    keypair  │                    │             │
│             │   2. Get prekey    │             │
│             │◄─────────────────── │             │
│             │                    │             │
│ 3. Compute  │                    │             │
│    shared   │                    │             │
│    secret   │                    │             │
│             │                    │             │
│ 4. Derive   │                    │             │
│    AEAD key │                    │             │
│             │                    │             │
│ 5. Encrypt  │  Encrypted blob    │ 6. Decrypt  │
│    message  │──────────────────► │    message  │
└─────────────┘                    └─────────────┘
```

## Cryptographic Protocol

### 1. Key Exchange
- Bob generates a long-term X25519 keypair and uploads his public key (prekey) to the server
- Alice generates an ephemeral X25519 keypair for each message
- Alice retrieves Bob's prekey and computes: `shared_secret = X25519(alice_ephemeral_private, bob_prekey_public)`
- Bob computes the same shared secret: `shared_secret = X25519(bob_prekey_private, alice_ephemeral_public)`

### 2. Key Derivation
- Both parties derive an AEAD encryption key using HKDF-SHA256:
  ```
  salt = SHA256(ephemeral_public_key)
  aead_key = HKDF-SHA256(shared_secret, salt, "encryption", 32)
  ```
- The ephemeral public key as salt ensures unique keys for each message exchange

### 3. Message Encryption
- Alice encrypts her message using XChaCha20-Poly1305:
  ```
  {ciphertext, nonce} = XChaCha20-Poly1305-Encrypt(message, aead_key, "")
  ```
- The encrypted blob contains: ephemeral public key, nonce, and ciphertext

### 4. Message Transmission
- Alice sends the encrypted blob to the server via HTTP POST
- Bob retrieves pending messages via HTTP GET
- Bob decrypts using the same derived AEAD key

## Security Features

### Forward Secrecy
- **Ephemeral keys**: Each message uses a fresh ephemeral keypair
- **Unique AEAD keys**: Different ephemeral keys produce different encryption keys
- **Past message security**: Compromise of current keys doesn't affect previous messages

### Cryptographic Strength
- **X25519**: Elliptic curve Diffie-Hellman with Curve25519 (128-bit security)
- **XChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **HKDF-SHA256**: Cryptographically strong key derivation
- **Libsodium**: Battle-tested cryptographic library via NIF

### Enhanced Key Derivation
- **Ephemeral-based salt**: Uses `SHA256(ephemeral_public_key)` as HKDF salt
- **Deterministic**: Both parties derive identical keys
- **Unique per exchange**: Different ephemeral keys → different AEAD keys
- **No protocol overhead**: Salt derivation requires no additional data transmission

## Project Structure

```
cryptic/
├── README.md                    # This file
├── rebar.config                 # Erlang build configuration
├── docs/
│   └── CRYPTIC_PLAN.md         # Original design document
├── src/
│   ├── cryptic.app.src         # OTP application metadata
│   ├── cryptic_server.erl      # HTTP server with Cowboy routing
│   ├── cryptic_handlers.erl    # HTTP request handlers
│   ├── cryptic_lib.erl         # High-level crypto API and HKDF
│   ├── cryptic_nif.erl         # NIF interface definitions
│   └── cryptic_client_example.erl # E2EE client demonstration
├── c_src/
│   ├── cryptic_nif.c           # Libsodium NIF implementation
│   └── Makefile                # NIF compilation rules
├── priv/
│   └── cryptic_nif.so          # Compiled NIF shared library
└── scripts/
    └── cryptic_client_example.erl # Client example script
```

## API Endpoints

### Prekey Management
- `POST /upload_prekey/{user_id}` - Upload a user's public prekey
- `GET /get_prekey/{user_id}` - Retrieve a user's public prekey

### Message Delivery
- `POST /send_blob` - Send an encrypted message blob
- `GET /recv_blobs/{user_id}` - Retrieve pending encrypted messages

### Message Format
```json
{
  "from": "alice",
  "to": "bob", 
  "ephemeral": "base64_ephemeral_public_key",
  "nonce": "base64_nonce",
  "cipher": "base64_ciphertext"
}
```

## Building and Running

### Prerequisites
- Erlang/OTP 27+
- Libsodium development libraries
- Rebar3 build tool

### Build
```bash
# Install libsodium (macOS)
brew install libsodium

# Clone and build
git clone <repository>
cd cryptic
rebar3 compile
```

### Start Server
```bash
# Terminal 1: Start the server
erl -pa _build/default/lib/*/ebin
1> cryptic_server:start().
```

### Run Client Demo
```bash
# Terminal 2: Run the client example
erl -pa _build/default/lib/*/ebin -s cryptic_client_example test -s init stop -noshell
```

### Expected Output
```
Generating keypairs for alice and bob...
Bob prekey uploaded.
RespData from get_prekey: "{\"user_id\":\"bob\",\"pub\":\"...\"}"
Alice - EphPub: <<"...">>
Alice - Shared: <<"...">>
Alice - AeadKey: <<"...">>
Alice sent encrypted blob to server.
Bob received: [{"from":"alice","ephemeral":"...","nonce":"...","cipher":"..."}]
Bob - Shared: <<"...">>
Bob - AeadKey: <<"...">>
Bob decrypted message: <<"Hello Bob!">>
```

## Implementation Details

### Custom NIF (Native Implemented Functions)
The system uses a custom C NIF that wraps libsodium functions:
- `gen_keypair/0` - Generate X25519 keypair
- `scalarmult/2` - X25519 scalar multiplication
- `aead_encrypt/3` - XChaCha20-Poly1305 encryption
- `aead_decrypt/4` - XChaCha20-Poly1305 decryption
- `rand_bytes/1` - Cryptographically secure random bytes

### HKDF Implementation
Pure Erlang implementation of HKDF-SHA256:
```erlang
hkdf_sha256(IKM, Salt, Info, L) ->
    PRK = crypto:mac(hmac, sha256, Salt, IKM),
    T1 = crypto:mac(hmac, sha256, PRK, <<Info/binary, 1:8>>),
    binary:part(T1, 0, L).
```

### Error Handling
- Comprehensive NIF error checking with descriptive error atoms
- HTTP request validation and proper error responses
- Base64 encoding/decoding with error handling
- Cryptographic operation failure detection

## Security Considerations

### Limitations
- **In-memory storage**: Messages and prekeys stored in ETS (not persistent)
- **No authentication**: No user authentication or message authentication beyond crypto
- **No replay protection**: Messages could theoretically be replayed
- **Single prekey**: Bob uses one prekey for all conversations

### Production Considerations
For production use, consider adding:
- User authentication and authorization
- Message ordering and replay protection
- Persistent storage with proper key management
- Key rotation mechanisms
- Multiple prekeys per user (X3DH protocol)
- Perfect forward secrecy with Double Ratchet

## Testing Different Security Modes

The implementation provides three key derivation approaches:

```erlang
% Most secure: Random salt (requires salt transmission)
{AeadKey, Salt} = cryptic_lib:derive_aead_key_random(SharedSecret),

% Good compromise: Ephemeral-based salt (current implementation)
AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPubKey),

% Simple: Fixed salt (less secure)
AeadKey = cryptic_lib:derive_aead_key_simple(SharedSecret),
```

## License

Mozilla Public License Version 2.0
