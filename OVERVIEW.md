# Cryptic - End-to-End Encrypted Chat System

**Author:** Cryptic Team  
**Version:** 1.0.0

## Overview

Cryptic is a professional implementation of an end-to-end encrypted chat system built in Erlang/OTP. It features WebSocket mTLS communication, real-time messaging, and implements state-of-the-art cryptographic protocols including the Double Ratchet algorithm for secure message exchange.

The system implements a secure messaging platform using:

- **WebSocket mTLS** communication for real-time, certificate-authenticated messaging
- **Double Ratchet Protocol** for forward secrecy and break-in recovery
- **X3DH Key Agreement** for initial session establishment
- **X25519** Diffie-Hellman key exchange for ephemeral key ratcheting
- **ChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **Blake2b KDF** high-performance key derivation (39x faster than Erlang)
- **Automatic session initialization** and seamless protocol upgrade
- **Perfect forward secrecy** and break-in recovery through DH ratcheting
- **Professional Terminal UI** with real-time chat capabilities and session management
- **Color-coded interface** with interactive chat mode and comprehensive status display

## Architecture

```
┌─────────────────┐           WebSocket mTLS            ┌───────────────┐
│     Alice       │         ←──────────────────→        │      Bob      │
│  (Terminal UI)  │                                     │ (Terminal UI) │
└─────────┬───────┘                                     └───────┬───────┘
          │                                                     │
          │ 1. Connect with client cert                         │ 1. Connect with client cert
          │ 2. Auto-generate keypair                            │ 2. Auto-generate keypair
          │ 3. Upload prekey                                    │ 3. Upload prekey
          │                                                     │
          │ ┌─────────────────────────────────────────────────┐ │
          └─│            WebSocket mTLS Server                │─┘
            │        Certificate Authentication               │
            │     Real-time Message Forwarding                │
            │        User/Prekey Management                   │
            └─────────────────────────────────────────────────┘
```

## Key Components

```
                        ┌──────────────────┐
                        │      START       │         Terminal
                        └──────────────────┘
                                 │
                                 ▼
                        ┌──────────────────────┐
                        │   cryptic_console    │    Erlang script
                        └──────────────────────┘
                                  │
                                  ▼
                        ┌──────────────────────┐
                        │  cryptic_console.erl │── ┐
                        └──────────────────────┘    ╲
                     ╱            │                  ╲
                    ╱             │                   ╲
                    ▼             ▼                    ▼
    ┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
    │ cryptic_ws_client.erl│  │   cryptic_engine.erl │  │  cryptic_shell.erl │
    └──────────────────────┘  └──────────────────────┘  └────────────────────┘
                │                         │
                │                         ▼
                │              ┌────────────────────────────┐
                │              │ cryptic_ratchet_engine.erl │
                │              └────────────────────────────┘
                │
                │
────────────────┼─────────────────────────────────────────────────────────────
    External Network (WebSocket TLS connection)
────────────────┼─────────────────────────────────────────────────────────────
                │
                ▼
    ┌──────────────────────┐
    │  cryptic_server.erl  │
    └──────────────────────┘

```

### Server Components

**`cryptic_server`**
Main server process that manages the WebSocket mTLS server startup, ETS table creation, and overall application lifecycle. Provides configuration management through environment variables and handles graceful shutdown.

**`cryptic_ws_handler`**
Enhanced Cowboy WebSocket handler that manages individual client connections and Double Ratchet session state. Handles mTLS authentication using client certificates, processes JSON commands, manages ratchet state persistence, and routes encrypted messages between users in real-time.

### Client Components

**`cryptic_console`**
Interactive terminal console interface providing a sophisticated command-line experience for secure messaging. Features asynchronous message delivery, input buffer preservation across interruptions, command history navigation, and ANSI colored output. Uses a two-process architecture to handle incoming messages while waiting for user input without blocking.

**`cryptic_shell`**
Enhanced interactive shell with advanced line editing capabilities and Emacs-style keybindings. Provides character-by-character editing with cursor movement, command history (last 100 commands), arrow key support for navigation and history, secure password input with masking, and robust escape sequence handling. Operates in raw terminal mode for precise keystroke control.

**`cryptic_ws_client`**
WebSocket client that handles mTLS connections to the server. Manages automatic keypair generation, prekey upload, message encryption/decryption, and provides a clean API for messaging operations.

**`cryptic_ws_ui`**
Professional terminal user interface built with ncurses (cecho). Provides comprehensive Double Ratchet session management, real-time chat functionality, automatic X3DH-to-ratchet initialization, unified encrypted message handling, session status display, and an intuitive user experience for secure messaging.

### Supporting Components

**`cryptic_engine`**
Main messaging engine implemented as a gen_server that coordinates encrypted message exchange from a user's perspective. Orchestrates X3DH key agreement and Double Ratchet protocol operations through a flexible callback API, enabling drop-in integration across different contexts (console, web, mobile). Manages session lifecycle, pending messages, key bundle storage, and seamless protocol transitions.

**`cryptic_ratchet_engine`**
Double Ratchet state engine using gen_statem behavior covering the full protocol lifecycle. Maintains separate initiator and responder chain keys for bidirectional communication, ensuring proper cryptographic separation between message directions. Provides callback-based architecture for UI-agnostic integration.

**`cryptic_double_ratchet`**
Complete Double Ratchet protocol implementation providing forward secrecy and break-in recovery. Manages sending/receiving chains, DH ratchet steps, skipped message key store, and high-performance cryptographic operations using native Blake2b KDF.

**`cryptic_lib`** 
Enhanced cryptographic library providing high-level encryption operations and X3DH key agreement. Implements X3DH sender/receiver initialization with automatic session key return for seamless Double Ratchet integration, message encryption/decryption, and storage management.

**`cryptic_nif`**
Native Interface Functions (NIFs) providing high-performance cryptographic primitives. Wraps libsodium functions for X25519 key exchange, ChaCha20-Poly1305 AEAD encryption, Blake2b key derivation (39x performance improvement), and secure random number generation.

**`cryptic_event_manager`**
Event management system for logging and monitoring. Provides structured event handling with configurable output destinations and log levels.

**`cryptic_console_logger`**
Console-based event logger that outputs formatted log messages to the terminal. Used for debugging and real-time monitoring of system events.

**`cryptic_file_logger`**
File-based event logger that writes structured log entries to files. Supports log rotation and persistent audit trails for security events.

**`cryptic_app`**
OTP application behavior implementation that starts the supervision tree and initializes the Cryptic application components.

**`cryptic_sup`**
Root supervisor that manages the fault-tolerant supervision tree for all Cryptic processes, ensuring system reliability and automatic restart capabilities.

## Cryptographic Protocol

### 1. WebSocket mTLS Authentication

- Client connects to WebSocket server using mutual TLS authentication
- Client certificate provides cryptographic identity verification
- Secure channel established for all subsequent communication

### 2. X3DH Key Agreement (Initial Session Setup)

- Upon WebSocket connection, client automatically generates X25519 identity and prekey bundles
- Client uploads prekey bundle to server via WebSocket message
- Server stores prekey bundle and associates it with client connection
- First message exchange uses X3DH protocol to establish shared secret

### 3. X3DH Message Exchange (Session Initialization)

1. Alice generates fresh ephemeral X25519 keypair for X3DH initialization
2. Alice fetches Bob's prekey bundle via WebSocket: `{"type": "get_prekey", "user": "bob"}`
3. Alice performs X3DH key agreement with Bob's bundle
4. X3DH produces shared secret for Double Ratchet initialization
5. Alice automatically initializes Double Ratchet session with X3DH shared secret
6. Alice sends first encrypted message using Double Ratchet protocol
7. Bob receives X3DH message, performs key agreement, and initializes matching ratchet session

### 4. Double Ratchet Protocol (Ongoing Communication)

1. Both parties maintain separate sending and receiving chain keys
2. Message encryption uses current sending chain key and advances the chain
3. Message decryption uses receiving chain key and handles gaps/reordering
4. DH ratchet steps occur on direction changes: generate new DH keypair and rotate chains
5. High-performance Blake2b KDF (39x faster) for all key derivation operations
6. Skipped message key store handles out-of-order and delayed message delivery
7. Forward secrecy: past messages remain secure even if current keys compromised
8. Break-in recovery: security restored after DH ratchet step following compromise

## Security Features

### Cryptographic Strength

- **X25519**: Elliptic curve Diffie-Hellman with Curve25519 (128-bit security)
- **ChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **Blake2b KDF**: High-performance cryptographically strong key derivation (39x faster than Erlang)
- **Libsodium**: Battle-tested cryptographic library via NIF
- **Double Ratchet**: State-of-the-art protocol used by Signal, WhatsApp, and other secure messengers

### Forward Secrecy and Break-in Recovery

- **Chain key ratcheting**: Each message advances chain keys, providing forward secrecy
- **DH ratchet steps**: New ephemeral DH keypairs generated on direction changes
- **Independent chains**: Separate sending and receiving chains for each party
- **Past message security**: Compromise of current keys doesn't affect previous messages
- **Break-in recovery**: Security restored after DH ratchet step following compromise
- **Unique message keys**: Every message encrypted with a unique derived key
- **No key reuse**: Chain keys and message keys never reused across messages

### Out-of-Order Message Handling

- **Skipped message key store**: Pre-derives keys for missing messages
- **Delayed delivery support**: Messages can arrive out-of-order and still decrypt
- **Gap handling**: Automatic key derivation for skipped message numbers
- **Forward secrecy preservation**: Skipped keys automatically cleaned up after use

### Transport Security

- **Certificate-based authentication**: Client certificates provide cryptographic identity
- **Mutual TLS**: Both client and server authenticate each other
- **Secure transport**: All communication encrypted at transport layer
- **Connection persistence**: Maintains secure channel for real-time messaging

## Quick Start

### Starting the Server

```bash
# Use the following script
./scripts/start-server.sh
```

### Starting a Client

```bash
# Use the following script for the client: 'alice'
./scripts/start-client.sh alice
```

### Basic Usage

1. Connect to server: `connect`
2. Send messages: `send <user> <message>` (automatically uses Double Ratchet)
3. Enter chat mode: `chat <user>` (seamless ratchet session management)
4. Check session status: `key_status` (view Double Ratchet session information)
5. Check inbox: `inbox`
6. List users: `list_users`
7. Get help: `help`

## Certificate Management

The system uses X.509 client certificates for mTLS authentication. Certificate infrastructure is managed using the included Certificate Authority (CA) framework:

- **CA Setup**: `cd CA/ && make all`
- **New Client Cert**: `cd CA/ && make client`
- **Certificate Verification**: `./scripts/verify-crt.sh client_keys/alice.crt`
- **Revocation**: `./scripts/revoke-cert.sh certs/02.pem`

Pre-configured client certificates are available for immediate testing:

- alice - `CA/client_keys/alice.{crt,key,pem}`
- bob - `CA/client_keys/bob.{crt,key,pem}`
- charlie - `CA/client_keys/charlie.{crt,key,pem}`
- admin - `CA/client_keys/admin.{crt,key,pem}`

## WebSocket Message Protocol

### Client to Server Messages

- `{"type": "upload_prekey", "prekey": "base64_public_key"}` - Upload X3DH prekey bundle
- `{"type": "get_prekey", "user": "bob"}` - Request another user's prekey bundle
- `{"type": "send_message", "to": "bob", "ephemeral": "...", "nonce": "...", "cipher": "..."}` - Send X3DH encrypted message (initial)
- `{"type": "send_ratchet_message", "to": "bob", "ratchet_data": {...}}` - Send Double Ratchet encrypted message
- `{"type": "get_messages"}` - Retrieve stored messages
- `{"type": "list_users"}` - Get list of all registered users

### Server to Client Messages

- `{"type": "welcome", "message": "Connected to Cryptic server"}` - Connection confirmation
- `{"type": "success", "message": "Operation completed"}` - Operation success
- `{"type": "prekey", "user": "bob", "prekey": "base64_public_key"}` - X3DH prekey bundle response
- `{"type": "users", "users": ["alice", "bob", "charlie"]}` - Users list response
- `{"type": "message", "from": "alice", "ephemeral": "...", "nonce": "...", "cipher": "..."}` - Incoming X3DH encrypted message
- `{"type": "ratchet_message", "from": "alice", "ratchet_data": {...}}` - Incoming Double Ratchet encrypted message
- `{"type": "error", "message": "Error description"}` - Error response

## Building and Development

### Prerequisites

- Erlang/OTP 27+
- Libsodium development libraries
- Rebar3 build tool
- cecho (Erlang ncurses library) - automatically installed via rebar3

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

## Security Considerations

### Current Limitations

- **In-memory storage**: Messages and ratchet states stored in ETS (not persistent)
- **Certificate-based identity**: mTLS provides authentication but not username verification
- **Single prekey bundle**: Users have one prekey bundle for X3DH initialization
- **Session state cleanup**: Ratchet sessions persist until client disconnect

### Production Enhancements

- **Certificate-Username Binding**: Map client certificates to specific usernames
- **Persistent Ratchet State**: Database backend for Double Ratchet session persistence
- **Multiple Prekey Bundles**: Key rotation and multiple prekeys per user
- **Session Lifecycle Management**: Automatic cleanup and state archival
- **Message Ordering**: Enhanced out-of-order handling for high-latency networks

## API Documentation

For detailed API documentation of individual modules, see:

- `cryptic_server` - Server lifecycle and WebSocket management
- `cryptic_ws_handler` - WebSocket connection handling, message routing, and ratchet state management
- `cryptic_double_ratchet` - Complete Double Ratchet protocol implementation
- `cryptic_ws_client` - WebSocket client API for messaging operations
- `cryptic_ws_ui` - Terminal user interface with Double Ratchet session management
- `cryptic_lib` - High-level cryptographic operations, X3DH, and storage
- `cryptic_nif` - High-performance cryptographic primitives via NIFs

## License

Mozilla Public License Version 2.0
