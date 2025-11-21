# Cryptic - End-to-End Encrypted Chat System

**Author:** Cryptic Team  
**Version:** 1.0.0

## Overview

Cryptic is an end-to-end encrypted chat system built in Erlang/OTP.
It implements WebSocket mTLS communication, real-time messaging, and
cryptographic protocols based on Signal's specifications.

### Core Features

- **WebSocket mTLS** - Certificate-based client authentication
- **Double Ratchet Protocol** - Forward secrecy and break-in recovery
- **X3DH Key Agreement** - Asynchronous initial session establishment
- **X25519** - Elliptic curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305** - AEAD encryption via libsodium NIFs
- **Blake2b KDF** - High-performance key derivation (39x faster than pure Erlang)
- **Event Bus Architecture** - Pub/sub system for component communication
- **GPG-based Onboarding** - Certificate issuance via signed CSRs
- **SQLite Message Storage** - Encrypted chat history with ChaCha20-Poly1305
- **Automatic Certificate Renewal** - X.509 client certificate lifecycle management
- **External TUI Support** - Rust-based terminal UI via Erlang distribution protocol

## Architecture

```
┌──────────────────┐       WebSocket mTLS          ┌──────────────────┐
│   Client (Alice) │  ←──────────────────────→     │  Client (Bob)    │
│   cryptic_console│                               │  cryptic_console │
└────────┬─────────┘                               └─────────┬────────┘
         │                                                   │
         │ event_bus pub/sub                                 │
         │                                                   │
    ┌────┴────────────────────────────┐                      │
    │                                 │                      │
    ▼                                 ▼                      │
┌──────────────┐              ┌─────────────┐                │
│ ws_client    │  ←─────────  │   engine    │                │
│ (WebSocket)  │              │ (Crypto)    │  ratchet state │
└──────┬───────┘              └─────────────┘                │
       │                                                     │
       │ encrypted messages                                  │
       │                                                     │
       └────────────┬                                        │
                    │                                        │
              WebSocket mTLS                                 │
                    │                                        │
                    │                                        │
                    │                                        │
                    ▼                                        │
┌──────────────────────────────────────────────────────┐     │
│           WebSocket mTLS Server                      │     │
│         (cryptic_server + cryptic_ws_handler)        │     │
│                                                      │     │
│  • Certificate authentication (GPG-signed)           │     │
│  • Message routing between clients                   │     │
│  • CA REST API (certificate issuance/renewal)        │     │
│  • GPG key registry (user verification)              │     │
└──────────────────────────────────────────────────────┘     │
                                                             │
                    WebSocket mTLS                           │
                          │                                  │
                          └──────────────────────────────────┘
```

## Key Components

### Server Components

**`cryptic_server`**  
Main server application managing WebSocket mTLS server lifecycle, ETS table initialization, and configuration. Supervises both messaging and CA subsystems.

**`cryptic_ws_handler`**  
Cowboy WebSocket handler managing client connections with mTLS authentication. Routes encrypted messages between users and maintains server-side message queues for offline delivery.

**`cryptic_ca_*` (CA Subsystem)**  
- `cryptic_ca_rest_handler` - REST API for certificate issuance and renewal
- `cryptic_ca_store` - CA certificate/key management and serial number tracking
- `cryptic_ca_cert` - X.509 certificate generation with GPG fingerprint SANs
- `cryptic_ca_gpg` - GPG signature verification for CSR authentication
- `cryptic_gpg_registry` - Stores user GPG public keys for verification

### Client Components

**`cryptic_console`**  
Terminal interface with command parser, ANSI rendering, and asynchronous message handling. Implements two-process architecture: UI process and message receiver process via `cryptic_event_bus` subscriptions.

**`cryptic_shell`**  
Line editor with Emacs keybindings, command history (last 100 commands), and secure password input. Operates in raw terminal mode for character-by-character control.

**`cryptic_ws_client`**  
WebSocket client with automatic reconnection, keepalive timers, and mTLS connection management. Publishes/subscribes to `cryptic_event_bus` for component decoupling.

### Core Cryptographic Components

**`cryptic_engine`**  
Messaging orchestrator (gen_server) coordinating X3DH and Double Ratchet operations. Implements callback behavior for storage, network, and UI integration. Manages session lifecycle and pending message queues.

**`cryptic_ratchet_engine`**  
Double Ratchet state machine (gen_statem) with separate states for initiator/responder roles. Handles DH ratchet steps, chain key advancement, and out-of-order message processing.

**`cryptic_double_ratchet`**  
Protocol implementation with symmetric-key ratcheting, DH ratchet steps, skipped message key store (max 1000 keys), and header encryption. Pure functional implementation with no process state.

**`cryptic_lib`**  
X3DH implementation, X25519 key operations, ChaCha20-Poly1305 encryption, and key bundle storage. Provides file-based encrypted storage for identity keys and session states.

**`cryptic_nif`**  
Libsodium bindings via NIFs: X25519 (crypto_scalarmult), ChaCha20-Poly1305 (crypto_aead_chacha20poly1305_ietf), Blake2b KDF (crypto_generichash), and secure random bytes.

### Infrastructure Components

**`cryptic_event_bus`**  
Pub/sub event system (gen_server) with filter-based subscriptions, topic support, automatic dead subscriber cleanup via process monitors, and safe error handling (filter crashes isolated per subscriber).

**`cryptic_chat_storage`**  
SQLite3 storage backend via esqlite. Stores encrypted messages with ChaCha20-Poly1305 using user passphrase-derived keys. Supports conversation queries, timestamp filtering, and message status tracking.

**`cryptic_cert_renewal`**  
Automatic certificate renewal monitor (gen_server). Parses X.509 validity periods, calculates renewal trigger times (configurable threshold), generates CSRs using existing keys (RSA/EC support), GPG-signs CSRs, submits to CA REST API, installs new certificates, and triggers WebSocket reconnection. Includes retry logic with exponential backoff and manual renewal API.

**`cryptic_cert_monitor`**  
Certificate expiration tracking and alerting system for proactive certificate lifecycle management.

**`cryptic_event_manager`**  
Event logging infrastructure with pluggable handlers for file logging (`cryptic_file_logger`), console output (`cryptic_console_logger`), and message-specific logging (`cryptic_msg_logger`).

## Cryptographic Protocol

### 1. Certificate-based Authentication

- Server runs integrated CA with REST API (`/ca/v1/csr`)
- New users generate GPG keypair and CSR
- CSR is GPG-signed with user's private key
- Admin approves user by uploading GPG public key to server
- User submits signed CSR to CA REST endpoint
- CA verifies GPG signature against registered public key
- CA issues X.509 certificate with GPG fingerprint in SAN extension
- Certificate used for mTLS WebSocket authentication
- Automatic renewal via `cryptic_cert_renewal` before expiration

### 2. X3DH Key Agreement (Initial Session)

- Client generates X25519 identity keypair and signed prekey on startup
- Client uploads prekey bundle to server via WebSocket
- Server stores bundle in ETS table keyed by username
- First message: sender fetches receiver's prekey bundle
- Sender computes X3DH shared secret using ephemeral key
- X3DH output becomes initial root key for Double Ratchet
- Receiver reconstructs shared secret upon receiving X3DH message
- Both parties initialize matching ratchet sessions

### 3. Double Ratchet Protocol (Ongoing)

**Chain Key Ratcheting (Symmetric)**
- Separate sending/receiving chains per direction
- Each message advances chain key: `CK_new = KDF(CK_old)`
- Message keys derived from chain key: `MK = KDF(CK, 0x01)`
- Chain keys never reused - deleted after derivation

**DH Ratchet Steps (Asymmetric)**
- Occurs on first message in new direction
- Generate fresh X25519 ephemeral keypair
- Compute new DH shared secret with peer's public key
- Derive new root key and chain key
- Provides break-in recovery and forward secrecy

**Out-of-Order Message Handling**
- Skipped message key store (max 1000 keys)
- Pre-derive keys for gaps in message sequence
- Messages decrypt correctly even if delivered out-of-order
- Automatic cleanup of old skipped keys

**Performance**
- Blake2b KDF via NIF: 39x faster than pure Erlang
- ChaCha20-Poly1305 AEAD via libsodium NIF
- All cryptographic operations use hardware acceleration when available

## Security Properties

### Cryptographic Primitives

- **X25519**: ECDH key agreement (Curve25519, ~128-bit security)
- **ChaCha20-Poly1305**: AEAD encryption (256-bit keys, 96-bit nonces)
- **Blake2b**: Cryptographic hash and KDF (configurable output, faster than SHA-2)
- **Libsodium**: Industry-standard cryptographic library via NIFs

### Forward Secrecy

- **Message-level**: Each message uses unique derived key, immediately deleted
- **Chain-level**: Chain keys advance with each message, old keys deleted
- **DH ratchet**: New ephemeral keypair on direction change
- **Past security**: Compromise of current keys doesn't affect past messages

### Break-in Recovery

- **DH ratchet step**: Generates new shared secret independent of compromised state
- **Recovery time**: One round-trip after compromise (when direction changes)
- **Bidirectional**: Both sending and receiving chains protected

### Out-of-Order Delivery

- **Skipped keys**: Pre-derive and store keys for missing message numbers (max 1000)
- **Gap handling**: Messages with gaps in sequence numbers handled automatically
- **Delayed messages**: Messages arriving late still decrypt correctly
- **Cleanup**: Skipped keys removed after use or on limit exceeded

### Authentication

- **Certificate-based**: X.509 client certificates with GPG-verified identity
- **GPG signatures**: All certificate requests authenticated with GPG private keys
- **SAN extensions**: GPG fingerprints embedded in certificate for binding
- **Mutual TLS**: Both client and server authenticate each other

### Storage Security

- **Key encryption**: Identity keys and session states encrypted with ChaCha20-Poly1305
- **Passphrase-derived keys**: User passphrase + random salt + Blake2b KDF
- **Message history**: SQLite database with per-message encryption
- **Key isolation**: Each user's keys stored in separate directory (`~/.cryptic/username/`)

## Quick Start

### Server Startup

```bash
# Start server with WebSocket mTLS and CA subsystem
./scripts/start-server.sh

# Server binds to 0.0.0.0:8443 by default
# CA REST API available at https://localhost:8443/ca/v1/
```

### Client Startup

```bash
# Standard console mode
./bin/cryptic -u alice --enable-db

# With custom server
./bin/cryptic -u alice -s example.com -p 9443

# TUI mode (requires cryptic-tui: github.com/etnt/cryptic-tui)
./bin/cryptic -u alice --tui
```

### User Onboarding

```bash
# Interactive wizard for new users
./bin/cryptic --onboard

# Steps:
# 1. Generate GPG keypair
# 2. Export GPG public key for admin
# 3. Admin uploads GPG key to server
# 4. User submits GPG-signed CSR
# 5. CA verifies signature and issues certificate
```

### Basic Usage

```
connect                    # Connect to server with mTLS
send <user> <message>     # Send encrypted message (auto-ratchet)
chat <user>               # Enter chat mode with user
list_users                # Show registered users
key_status                # Display ratchet session info
inbox                     # Check pending messages
help                      # Show all commands
:cr                       # Manual certificate renewal
```

## Building and Development

### Prerequisites

- Erlang/OTP 27+
- Libsodium (via Homebrew, apt, or source)
- Rebar3
- SQLite3 (for message storage)
- GPG (for certificate onboarding)

### Build

```bash
# macOS
brew install libsodium

# Build
rebar3 compile

# Generate documentation
rebar3 edoc
# or: rebar3 ex_doc

# Run tests
rebar3 eunit
```

### Certificate Authority Setup

```bash
cd CA/
make all                           # Initialize CA
make client                        # Generate client cert
./scripts/verify-crt.sh certs/alice.crt
./scripts/revoke-cert.sh certs/02.pem
```

Pre-configured test certificates in `CA/client_keys/`:
- alice.{crt,key,pem}
- bob.{crt,key,pem}
- charlie.{crt,key,pem}
- admin.{crt,key,pem}

## Known Limitations

- **Server-side storage**: Messages and sessions stored in ETS (in-memory, non-persistent)
- **Single prekey bundle**: One prekey per user (no rotation implemented)
- **GPG dependency**: Onboarding requires GPG installed and configured
- **Session cleanup**: Ratchet sessions persist until client disconnect
- **Skipped key limit**: Maximum 1000 skipped message keys per session

## WebSocket Message Protocol

### Client → Server

**Certificate/Key Management**
- `{"type": "upload_identity_keys", ...}` - Upload X3DH identity keys and prekeys
- `{"type": "get_key_bundle", "username": "bob"}` - Request user's public keys

**Messaging**
- `{"type": "x3dh", ...}` - Initial X3DH message (session establishment)
- `{"type": "ratchet", ...}` - Double Ratchet message (ongoing conversation)
- `{"type": "send_message", ...}` - Generic message (engine determines protocol)

**User Management**
- `{"type": "list_users"}` - Get list of registered users
- `{"type": "user_status", "username": "alice"}` - Check if user is online

### Server → Client

**Connection**
- `{"type": "welcome", ...}` - Connection confirmed, username assigned

**Certificate/Key Management**
- `{"type": "key_bundle", "username": "bob", ...}` - User's public key bundle
- `{"type": "success", ...}` - Operation succeeded

**Messaging**
- `{"type": "message", ...}` - Incoming encrypted message (X3DH or ratchet)
- `{"type": "message_sent", ...}` - Message delivery confirmed

**User Management**
- `{"type": "users", "users": [...]}` - Registered users list
- `{"type": "user_status", ...}` - User online/offline status
- `{"type": "error", ...}` - Error occurred

### CA REST API

**POST /ca/v1/csr**
```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "gpg_fp": "ABCD1234...",
  "gpg_sig_b64": "base64_encoded_signature"
}
```

**Response (200 OK)**
```json
{
  "status": "issued",
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "serial": 42,
  "expires_at": 1732627533
}
```

## Building and Development

### Prerequisites

- Erlang/OTP 27+
- Libsodium development libraries
- Rebar3 build tool

### Build Commands

```bash
# Install dependencies (macOS)
$ brew install libsodium

# Build the application
$ rebar3 compile

# Generate documentation
$ rebar3 edoc

# Run tests
$ rebar3 eunit
```

## API Documentation

For detailed module documentation:

**Core**
- `cryptic_server` - Server lifecycle and supervision
- `cryptic_ws_handler` - WebSocket connection handling and message routing
- `cryptic_engine` - Messaging orchestration and session management
- `cryptic_ratchet_engine` - Double Ratchet state machine
- `cryptic_double_ratchet` - Protocol implementation
- `cryptic_lib` - X3DH and cryptographic operations

**Client**
- `cryptic_console` - Terminal UI
- `cryptic_ws_client` - WebSocket client with reconnection
- `cryptic_shell` - Line editor with history

**Infrastructure**
- `cryptic_event_bus` - Pub/sub event system
- `cryptic_chat_storage` - SQLite encrypted message storage
- `cryptic_cert_renewal` - Automatic certificate renewal
- `cryptic_nif` - Libsodium bindings

**CA**
- `cryptic_ca_rest_handler` - Certificate issuance REST API
- `cryptic_ca_gpg` - GPG signature verification
- `cryptic_gpg_registry` - User GPG key storage

## License

Mozilla Public License Version 2.0
