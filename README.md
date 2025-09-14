# Cryptic - End-to-End Encrypted Chat System

A professional implementation of an end-to-end encrypted chat system built in Erlang/OTP, featuring WebSocket mTLS communication, real-time messaging, and demonstrating modern cryptographic protocols for secure message exchange.

## Overview

Cryptic implements a secure messaging system using:
- **WebSocket mTLS** communication for real-time, certificate-authenticated messaging
- **X25519** key agreement for establishing shared secrets
- **ChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **HKDF-SHA256** key derivation with ephemeral-based salts
- **Automatic keypair generation** and prekey exchange on connect
- **Perfect forward secrecy** through ephemeral keys for each message exchange
- **Professional Terminal UI** with real-time chat capabilities and inbox functionality
- **Color-coded interface** with interactive chat mode and command processing

## Quick Start

### WebSocket mTLS Mode (Current Implementation)
```bash
# Start the server with WebSocket support
$ ./scripts/start-server.sh

# In another terminal, start the UI client
$ ./scripts/start-client.sh bob

# Follow the on-screen instructions:
# 1. Connect to server: connect
# 2. Send messages: send <user> <message>
# 3. Enter chat mode: chat <user>
# 4. Check inbox: inbox
# 5. List users: list_users
# 6. Use help command for more options
```

### UI Commands
- **`help`** - Show available commands
- **`connect`** - Connect to WebSocket server with certificate authentication
- **`send <user> <message>`** - Send encrypted message to user
- **`chat <user>`** - Enter real-time chat mode with automatic message polling
- **`inbox`** - View message counts by sender (inbox summary)
- **`inbox <user>`** - View all messages from specific user with timestamps
- **`auto_display on`** - Enable automatic message display (default)
- **`auto_display off`** - Disable automatic display; messages stored in inbox
- **`auto_display`** - Show current auto-display status
- **`list_users`** - Show all users registered on the server
- **`quit`** - Exit the application

### Chat Mode Commands
Once in chat mode with `chat <username>`:
- **Type any message** - Sends encrypted message directly to chat target
- **`:exit`** - Leave chat mode and return to command mode
- **`:help`** - Show chat-specific help

## Certificate handling

The Cryptic system uses the [`myca`](https://github.com/etnt/myca.git) Certificate Authority framework for managing X.509 certificates required for WebSocket mTLS authentication. This section explains how to set up the CA infrastructure and manage client certificates.

### CA Infrastructure Setup

The certificate infrastructure is based on the `myca` framework located in the `CA/` directory. This provides a complete Certificate Authority with modern elliptic curve cryptography (secp384r1) for enhanced security and performance.

#### Initial CA and Server Certificate Creation

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

#### Pre-defined Client Certificates

The system comes with several pre-configured client certificates for immediate testing:

- **alice** - `CA/client_keys/alice.{crt,key,pem}`
- **bob** - `CA/client_keys/bob.{crt,key,pem}`
- **charlie** - `CA/client_keys/charlie.{crt,key,pem}`
- **admin** - `CA/client_keys/admin.{crt,key,pem}`

Each client has three files:
- `.crt` - Certificate only
- `.key` - Private key only  
- `.pem` - Combined certificate and private key (used by Erlang SSL)

### Creating New Client Certificates

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

### Certificate Verification and Management

#### Verify Certificate Validity
```bash
cd CA/
./scripts/verify-crt.sh client_keys/alice.crt
# Output: client_keys/alice.crt: OK
```

#### Generate Certificate Fingerprint
```bash
cd CA/
./scripts/fingerprint.sh client_keys/alice.crt
# Output: sha256 Fingerprint=A1:B2:C3:D4:E5:F6:...
```

#### View Certificate Details
```bash
cd CA/
openssl x509 -in client_keys/alice.crt -text -noout
```

### Certificate Revocation

To revoke a compromised or no longer valid certificate:

```bash
cd CA/
./scripts/revoke-cert.sh certs/02.pem  # Revoke certificate with serial 02
```

This updates:
- `index.txt` - Marks certificate as revoked (status flag changes from 'V' to 'R')
- `crl/rootca.crl` - Certificate Revocation List for the Erlang SSL application

#### Check Revocation Status
```bash
cd CA/
./scripts/print-crl.sh  # View all revoked certificates
```

### Using Certificates with Cryptic

#### Starting the Server with Certificates
```bash
# Use the provided script that sets up certificate paths
./scripts/start-server.sh
```

#### Starting Clients with Specific Certificates
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

#### Manual Certificate Configuration

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

### Certificate Security Features

#### Modern Cryptography
- **Algorithm**: Elliptic Curve (secp384r1) instead of RSA for better security/performance
- **Validity**: 10-year certificate lifetime (3652 days) for production stability
- **Key Size**: 384-bit EC keys provide equivalent security to 7680-bit RSA keys

#### Subject Alternative Names (SAN) Support
Client certificates can include multiple identity types:
- **DNS names**: For domain-based authentication
- **IP addresses**: For IP-based connections
- **Email addresses**: For email-based identity verification  
- **URIs**: For service endpoint authentication

#### Certificate Revocation List (CRL)
- Real-time revocation checking during WebSocket mTLS handshake
- Automatic CRL updates when certificates are revoked
- Proper CRL formatting for Erlang SSL application compatibility

### Production Certificate Management

#### Certificate Rotation Strategy
```bash
# Generate new server certificate (keeping same CA)
cd CA/
./scripts/gen-server-cert.sh

# Generate new client certificate for existing user
make client  # Enter same user details to replace old certificate
```

#### Backup and Recovery
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

#### Monitoring Certificate Expiration
```bash
# Check certificate expiration dates
cd CA/
for cert in client_keys/*.crt; do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -noout -dates
done
```

This certificate infrastructure provides enterprise-grade security for the Cryptic messaging system, ensuring strong authentication and secure transport for all WebSocket mTLS communications.


## Features

### WebSocket mTLS Communication
- **Real-time WebSocket messaging** with persistent connections for instant delivery
- **Mutual TLS authentication** using client certificates for strong identity verification
- **Automatic connection management** with reconnection handling and error recovery
- **Message type handling** for users, prekey exchange, success/error responses, and encrypted messages
- **Asynchronous command processing** with queued responses for smooth user experience

### Terminal User Interface
- **Full-screen terminal UI** with ncurses-based interface using professional layout
- **Real-time chat mode** for one-on-one conversations with automatic message polling
- **Command-based interface** with comprehensive help system and auto-completion
- **Inbox functionality** for viewing all received messages with timestamps
- **Status display** showing connection state, current user, and available commands
- **Interactive chat experience** with dedicated chat mode and command mode separation

### Cryptographic Security
- **End-to-end encryption** using industry-standard X25519 + ChaCha20-Poly1305
- **Perfect forward secrecy** with ephemeral keys generated for each message
- **Automatic keypair generation** and prekey upload on WebSocket connection
- **Authenticated encryption** preventing tampering and ensuring confidentiality
- **Libsodium integration** for battle-tested cryptographic implementations
- **Secure prekey exchange** flow with proper key derivation using ephemeral-based HKDF

### User Experience
- **Automatic connection** to WebSocket server with certificate authentication
- **Real-time message delivery** with instant notification in chat mode
- **Message history** with inbox functionality showing all received messages
- **User discovery** with list_users command to find available contacts
- **Graceful error handling** with user-friendly messages and recovery options
- **Context-sensitive help** that changes based on current mode (command vs chat)

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

Message Flow:
1. Alice generates ephemeral keypair for message
2. Alice fetches Bob's prekey via WebSocket
3. Alice computes shared secret: X25519(alice_ephemeral_private, bob_prekey_public)
4. Alice derives AEAD key: HKDF-SHA256(shared_secret, SHA256(ephemeral_public), "encryption")
5. Alice encrypts message: ChaCha20-Poly1305(message, aead_key)
6. Alice sends encrypted blob via WebSocket
7. Server forwards message to Bob's WebSocket connection
8. Bob decrypts message using same shared secret derivation
```

## Cryptographic Protocol

### 1. WebSocket mTLS Authentication
- Client connects to WebSocket server using mutual TLS authentication
- Client certificate provides cryptographic identity verification
- Secure channel established for all subsequent communication

### 2. Automatic Key Setup
- Upon WebSocket connection, client automatically generates X25519 keypair
- Client uploads public key (prekey) to server via WebSocket message
- Server stores prekey and associates it with client connection

### 3. Key Exchange per Message
- Alice generates fresh ephemeral X25519 keypair for each message
- Alice fetches Bob's prekey via WebSocket: `{"type": "get_prekey", "user": "bob"}`
- Alice computes: `shared_secret = X25519(alice_ephemeral_private, bob_prekey_public)`
- Bob computes same shared secret: `shared_secret = X25519(bob_prekey_private, alice_ephemeral_public)`

### 4. Key Derivation
- Both parties derive AEAD encryption key using HKDF-SHA256:
  ```
  salt = SHA256(ephemeral_public_key)
  aead_key = HKDF-SHA256(shared_secret, salt, "encryption", 32)
  ```
- Ephemeral public key as salt ensures unique keys per message exchange

### 5. Message Encryption & Transmission
- Alice encrypts: `{ciphertext, nonce} = ChaCha20-Poly1305-Encrypt(message, aead_key)`
- Alice sends encrypted blob via WebSocket to server
- Server forwards encrypted message to Bob's WebSocket connection in real-time
- Bob receives and decrypts using same derived AEAD key

### 6. Real-time Delivery
- WebSocket connections enable instant message delivery
- No polling required - messages pushed immediately to recipients
- Inbox functionality stores all received messages with timestamps

## Security Features

### Real-time WebSocket mTLS
- **Certificate-based authentication**: Client certificates provide cryptographic identity
- **Mutual TLS**: Both client and server authenticate each other
- **Secure transport**: All communication encrypted at transport layer
- **Connection persistence**: Maintains secure channel for real-time messaging

### Forward Secrecy
- **Ephemeral keys**: Each message uses a fresh ephemeral keypair
- **Unique AEAD keys**: Different ephemeral keys produce different encryption keys
- **Past message security**: Compromise of current keys doesn't affect previous messages
- **No key reuse**: Every message exchange uses completely fresh cryptographic material

### Cryptographic Strength
- **X25519**: Elliptic curve Diffie-Hellman with Curve25519 (128-bit security)
- **ChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **HKDF-SHA256**: Cryptographically strong key derivation
- **Libsodium**: Battle-tested cryptographic library via NIF

### Enhanced Key Derivation
- **Ephemeral-based salt**: Uses `SHA256(ephemeral_public_key)` as HKDF salt
- **Deterministic**: Both parties derive identical keys without coordination
- **Unique per exchange**: Different ephemeral keys → different AEAD keys
- **No protocol overhead**: Salt derivation requires no additional data transmission

## Cryptographic Analysis

### Core Algorithms and Security Levels

#### X25519 Key Agreement
- **Algorithm**: Elliptic Curve Diffie-Hellman over Curve25519
- **Key Size**: 32 bytes (256 bits)
- **Security Level**: ~128-bit security
- **Resistance**: 
  - Quantum resistance: No (vulnerable to Shor's algorithm)
  - Classical attacks: Secure against all known attacks
  - Side-channel resistance: Designed to be constant-time
- **Standards**: RFC 7748, widely adopted in modern protocols (Signal, WireGuard, TLS 1.3)

#### ChaCha20-Poly1305 AEAD
- **Encryption**: ChaCha20 stream cipher
- **Authentication**: Poly1305 MAC
- **Key Size**: 32 bytes (256 bits)
- **Nonce Size**: 12 bytes (96 bits) - internally generated
- **Security Level**: 256-bit security
- **Properties**:
  - Authenticated encryption with associated data (AEAD)
  - Resistance to timing attacks
  - No block cipher weaknesses (stream cipher)
  - Large nonce space prevents reuse concerns
- **Standards**: RFC 8439, ChaCha20-Poly1305 is used in TLS 1.3, SSH, WireGuard

#### HKDF-SHA256 Key Derivation
- **Hash Function**: SHA-256
- **Output**: Configurable (we use 32 bytes for AEAD keys)
- **Security Level**: 256-bit pre-image resistance, 128-bit collision resistance
- **Properties**:
  - Extract-and-expand paradigm
  - Cryptographically strong key stretching
  - Deterministic output for same inputs
  - Info parameter provides domain separation
- **Standards**: RFC 5869, used in TLS 1.3, Signal Protocol, WireGuard

### Security Assessment

#### Overall Security Level
The system provides **128-bit security** (limited by X25519), which is:
- ✅ **Sufficient** for current threat models (2024-2040+ timeframe)
- ✅ **Recommended** by NIST, NSA, and other security agencies
- ✅ **Future-resistant** against classical computers
- ❌ **Quantum-vulnerable** (Grover's algorithm reduces to ~64-bit effective security)

#### Algorithm Security Ratings

| Algorithm | Security Level | Quantum Resistance | Standards Adoption | Status |
|-----------|----------------|-------------------|-------------------|---------|
| X25519 | 128-bit | ❌ No | ✅ High (RFC 7748) | Excellent |
| ChaCha20-Poly1305 | 256-bit | 🟡 Partial* | ✅ High (RFC 8439) | Excellent |
| HKDF-SHA256 | 256-bit | 🟡 Partial* | ✅ High (RFC 5869) | Excellent |

*Symmetric algorithms have some quantum resistance (Grover's algorithm only provides quadratic speedup)

#### Key Strengths
1. **Battle-tested algorithms**: All algorithms are extensively analyzed and widely deployed
2. **Conservative choices**: No experimental or bleeding-edge cryptography
3. **Constant-time implementations**: Libsodium provides side-channel resistant implementations
4. **Forward secrecy**: Ephemeral keys ensure past message security
5. **Authenticated encryption**: Prevents tampering and provides confidentiality

#### Known Limitations
1. **Quantum vulnerability**: X25519 will be broken by sufficiently large quantum computers
2. **Single prekey**: No key rotation mechanism (production systems should implement X3DH)
3. **No post-quantum algorithms**: Not resistant to future quantum attacks
4. **Replay protection**: Messages could theoretically be replayed (lack of ordering)

### Post-Quantum Considerations

For quantum-resistant messaging, consider upgrading to:
- **Key Exchange**: Kyber768 or other NIST PQC winners
- **Signatures**: Dilithium3 for authentication (not currently used)
- **Hybrid approach**: Combine classical (X25519) with post-quantum algorithms

### Comparison with Industry Standards

#### Signal Protocol
- ✅ **Key Agreement**: Both use X25519
- ✅ **Encryption**: Both use ChaCha20-Poly1305 family
- ❌ **Key Management**: Signal uses X3DH + Double Ratchet (more sophisticated)
- ❌ **Authentication**: Signal includes identity verification

#### TLS 1.3
- ✅ **Key Agreement**: Both support X25519
- ✅ **Encryption**: Both support ChaCha20-Poly1305
- ✅ **Key Derivation**: Both use HKDF-SHA256
- ✅ **Forward Secrecy**: Both use ephemeral keys

#### WireGuard VPN
- ✅ **Key Agreement**: Both use X25519
- ✅ **Encryption**: Both use ChaCha20-Poly1305
- ✅ **Key Derivation**: Both use HKDF
- ❌ **Transport**: WireGuard is UDP-based, we use HTTP

### Implementation Security Notes

#### Libsodium Advantages
- **Audited implementation**: Extensively reviewed cryptographic library
- **Side-channel protection**: Constant-time implementations
- **Memory safety**: Secure memory handling and clearing
- **API safety**: Difficult to misuse interfaces

#### NIF Security Considerations
- **Memory management**: Proper cleanup of sensitive data
- **Error handling**: Secure failure modes
- **Resource limits**: Bounded input sizes to prevent DoS

The cryptographic foundation of this system is **solid and production-ready** for current threat models, with the main limitation being eventual quantum computer threats.

## Project Structure

```
cryptic/
├── README.md                    # This comprehensive documentation
├── rebar.config                 # Erlang build configuration  
├── docs/
│   └── CRYPTIC_PLAN.md         # Original design document
├── src/
│   ├── cryptic.app.src         # OTP application metadata
│   ├── cryptic_server.erl      # WebSocket mTLS server with Cowboy
│   ├── cryptic_handlers.erl    # WebSocket message handlers  
│   ├── cryptic_lib.erl         # Core cryptographic functions and storage
│   ├── cryptic_ws_client.erl   # WebSocket client with mTLS authentication
│   ├── cryptic_ws_ui.erl       # Professional terminal UI with ncurses
│   └── cryptic_event_manager.erl # Event handling and logging system
├── test/
│   └── cryptic_e2e_test.erl    # End-to-end test suite
├── c_src/
│   ├── cryptic_nif.c           # Libsodium NIF implementation
│   └── Makefile                # NIF compilation rules
├── priv/
│   └── cryptic_nif.so          # Compiled NIF shared library
└── scripts/
    └── cryptic_client_example.erl # Legacy HTTP client example
```

## WebSocket Message Protocol

### Client to Server Messages
- `{"type": "upload_prekey", "user": "alice", "prekey": "base64_public_key"}` - Upload user's public key
- `{"type": "get_prekey", "user": "bob"}` - Request another user's public key
- `{"type": "send_message", "from": "alice", "to": "bob", "ephemeral": "base64_ephemeral_public", "nonce": "base64_nonce", "cipher": "base64_ciphertext"}` - Send encrypted message
- `{"type": "list_users"}` - Get list of all registered users

### Server to Client Messages  
- `{"type": "welcome", "message": "Connected to Cryptic server"}` - Connection confirmation
- `{"type": "success", "operation": "upload_prekey", "message": "Prekey uploaded for alice"}` - Operation success
- `{"type": "prekey", "user": "bob", "prekey": "base64_public_key"}` - Prekey response
- `{"type": "users", "users": ["alice", "bob", "charlie"]}` - Users list response
- `{"type": "message", "from": "alice", "ephemeral": "...", "nonce": "...", "cipher": "..."}` - Incoming encrypted message
- `{"type": "error", "message": "User not found"}` - Error response

### Message Encryption Format
```json
{
  "type": "send_message",
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
- cecho (Erlang ncurses library) - automatically installed via rebar3

### Build
```bash
# Install libsodium (macOS)
brew install libsodium

# Clone and build
git clone <repository>
cd cryptic
rebar3 compile
```

### Start WebSocket Server
```bash
# Terminal 1: Start the WebSocket mTLS server
erl -pa _build/default/lib/*/ebin
1> cryptic_server:start().
```

### Start Terminal UI Client
```bash
# Terminal 2: Start the interactive WebSocket UI
erl -pa _build/default/lib/*/ebin
1> cryptic_ws_ui:start().

# Or connect to a remote server
1> cryptic_ws_ui:start("wss://example.com:8443").
```

### Terminal UI Usage
Once the UI starts, you'll see a clean interface with:
- **Command prompt** for entering commands
- **Message display area** showing conversation history and system messages
- **Status indicators** for connection state and current mode

**Basic workflow:**
1. Connect to server: `connect`
2. Send message: `send bob Hello there!`
3. Enter chat mode: `chat bob`
4. In chat mode, type messages directly (they're automatically encrypted and sent)
5. Check inbox: `inbox` (to see all received messages with timestamps)
6. List users: `list_users`
7. Exit chat mode: `:exit`
8. Quit application: `quit`

### Run Legacy Client Demo
```bash
# Terminal 3: Run the legacy HTTP client example (for comparison)
erl -pa _build/default/lib/*/ebin -s cryptic_client_example test -s init stop -noshell
```

### Run Tests
```bash
# Run comprehensive EUnit test suite
rebar3 eunit
```

## WebSocket Client Library Usage

The WebSocket client provides real-time encrypted messaging with automatic certificate authentication. The UI (`cryptic_ws_ui`) demonstrates the complete implementation.

### Quick Start

```erlang
%% Start the WebSocket UI for interactive messaging
cryptic_ws_ui:start().

%% Or programmatically use the WebSocket client
{ok, ClientPid} = cryptic_ws_client:start_link(),
cryptic_ws_client:connect(ClientPid),
cryptic_ws_client:send_message(ClientPid, "bob", <<"Hello!">>).
```

### WebSocket Client API Reference

#### Connection Management

**`start_link/0`**
```erlang
{ok, Pid} = cryptic_ws_client:start_link().
```
Starts a new WebSocket client process.

**`connect/1`**
```erlang
ok = cryptic_ws_client:connect(ClientPid).
```
Connects to the WebSocket server using mTLS authentication. Automatically generates keypair and uploads prekey.

**`set_ui_pid/2`**
```erlang
ok = cryptic_ws_client:set_ui_pid(ClientPid, UIPid).
```
Sets the UI process that will receive forwarded server messages.

#### Messaging Operations

**`send_message/3`**
```erlang
ok = cryptic_ws_client:send_message(ClientPid, "bob", <<"Hello Bob!">>).
```
Sends an encrypted message to the specified user. Automatically handles:
- Fetching recipient's prekey
- Generating ephemeral keypair
- Encrypting message with ChaCha20-Poly1305
- Sending via WebSocket

**`get_prekey/2`**
```erlang
ok = cryptic_ws_client:get_prekey(ClientPid, "bob").
```
Requests a user's public prekey from the server.

**`list_users/1`**
```erlang
ok = cryptic_ws_client:list_users(ClientPid).
```
Requests the list of all registered users.

### Message Flow Example

```erlang
%% Start client and UI
{ok, ClientPid} = cryptic_ws_client:start_link(),
{ok, UIPid} = cryptic_ws_ui:start_link(),

%% Link client to UI for message forwarding
cryptic_ws_client:set_ui_pid(ClientPid, UIPid),

%% Connect with certificate authentication
cryptic_ws_client:connect(ClientPid),

%% Send encrypted message
cryptic_ws_client:send_message(ClientPid, "alice", <<"Hello Alice!">>),

%% UI will automatically receive and decrypt incoming messages
```

### Terminal UI Integration

The `cryptic_ws_ui` module provides a complete terminal interface:

```erlang
%% Start the terminal UI (includes client management)
cryptic_ws_ui:start().

%% UI commands:
%% connect          - Connect to WebSocket server
%% send bob hello   - Send encrypted message to bob  
%% chat alice       - Enter real-time chat with alice
%% inbox            - View all received messages
%% list_users       - Show registered users
%% help             - Show command help
%% quit             - Exit application
```

### Message Handling

The WebSocket client receives various message types from the server:

```erlang
%% Server message examples:
#{type => welcome, message => <<"Connected to server">>}
#{type => success, operation => upload_prekey, message => <<"Prekey uploaded">>}
#{type => prekey, user => <<"bob">>, prekey => <<"base64_pubkey">>}
#{type => users, users => [<<"alice">>, <<"bob">>, <<"charlie">>]}
#{type => message, from => <<"alice">>, ephemeral => <<"...">>, nonce => <<"...">>, cipher => <<"...">>}
#{type => error, message => <<"User not found">>}
```

All incoming messages are automatically forwarded to the registered UI process for display and user interaction.

### Expected Output
```
Starting WebSocket UI...
Connecting to wss://localhost:8443...
Connected! Type 'help' for commands.

> connect
Generating keypair...
Uploading prekey...
Connected and ready!

> send bob Hello from the new WebSocket system!
Fetching prekey for bob...
Encrypting message...
Message sent to bob!

> chat alice
Entering chat mode with alice. Type ':exit' to leave.
[Chat] alice: Hey! How's the new WebSocket implementation?
> It's working great! Real-time messaging is so much better.
[Chat] You -> alice: It's working great! Real-time messaging is so much better.
[Chat] alice: I love the instant delivery!
> :exit
Left chat mode.

> inbox
=== INBOX ===
[2024-09-13 14:23:15] alice: Hey! How's the new WebSocket implementation?
[2024-09-13 14:23:45] alice: I love the instant delivery!
[2024-09-13 14:24:12] bob: Thanks for the message! This is much faster than HTTP polling.

> quit
Goodbye!
```

## Implementation Details

### WebSocket mTLS Communication
The system uses Cowboy WebSocket handlers for real-time communication:
- **Certificate-based authentication** with mutual TLS verification
- **Persistent connections** for instant message delivery without polling
- **JSON message protocol** with typed messages for different operations
- **Automatic reconnection** handling with graceful error recovery

### Custom NIF (Native Implemented Functions)
The system uses a custom C NIF that wraps libsodium functions:
- `gen_keypair/0` - Generate X25519 keypair
- `scalarmult/2` - X25519 scalar multiplication  
- `aead_encrypt/3` - ChaCha20-Poly1305 encryption
- `aead_decrypt/4` - ChaCha20-Poly1305 decryption
- `rand_bytes/1` - Cryptographically secure random bytes

### Terminal UI Architecture
The WebSocket UI uses a clean command-based architecture:
- **Command processor** handles user input and dispatches operations
- **WebSocket client** manages server communication and message forwarding
- **Message handler** processes incoming server messages and updates display
- **Inbox storage** maintains message history with timestamps
- **Chat mode** provides real-time messaging with automatic message polling

### HKDF Implementation
Pure Erlang implementation of HKDF-SHA256:
```erlang
hkdf_sha256(IKM, Salt, Info, L) ->
    PRK = crypto:mac(hmac, sha256, Salt, IKM),
    T1 = crypto:mac(hmac, sha256, PRK, <<Info/binary, 1:8>>),
    binary:part(T1, 0, L).
```

### Error Handling
- Comprehensive WebSocket error handling with reconnection logic
- JSON parsing validation with descriptive error messages
- Cryptographic operation failure detection and recovery
- User-friendly error display without technical implementation details

## Security Considerations

### Current Limitations
- **In-memory storage**: Messages and prekeys stored in ETS (not persistent across restarts)
- **⚠️ Certificate-based identity**: WebSocket mTLS provides authentication but not user identity verification
- **No replay protection**: Messages could theoretically be replayed (no sequence numbers)
- **Single prekey**: Users have one prekey for all conversations (no key rotation)

### Certificate Authentication vs User Identity

**Important**: While WebSocket mTLS provides strong transport authentication, the current system doesn't link certificates to specific usernames. This means:

```bash
# Anyone with a valid certificate can claim any username
connect
send alice "impersonation message"  # Could claim to be from alice
```

For production deployment, consider implementing certificate-to-username mapping or additional identity verification layers.

### Recommended Security Enhancements

For production deployment, consider implementing:

1. **Certificate-Username Binding**
   - Map client certificates to specific usernames
   - Prevent username impersonation with valid certificates
   - Certificate revocation and rotation mechanisms

2. **Enhanced Authentication**
   - Username/password registration with certificate generation
   - Digital signature verification for message authenticity
   - Multi-factor authentication with hardware security keys

3. **Message Integrity**
   - Sequence numbers for replay protection
   - Message ordering and duplicate detection
   - Delivery receipts and read confirmations

4. **Key Management**
   - Multiple prekeys per user (X3DH protocol)
   - Automatic key rotation mechanisms
   - Perfect forward secrecy with Double Ratchet algorithm

### Production Considerations
For production use, implementing proper identity verification is **essential**. Additionally consider:
- **Persistent storage** with proper database backend and key management
- **Message ordering** and replay protection with sequence numbers
- **User registration** with certificate generation and identity verification
- **Key rotation** mechanisms and multiple prekeys per user (X3DH protocol)
- **Perfect forward secrecy** with Double Ratchet for ongoing conversations
- **Group messaging** capabilities with efficient key distribution
- **File transfer** support with chunked encryption
- **Rate limiting** and abuse prevention at WebSocket level
- **Audit logging** and monitoring of security events
- **High availability** with server clustering and load balancing

## UI Interface

The WebSocket terminal interface provides a clean, professional messaging experience:

```
=== CRYPTIC WEBSOCKET CLIENT ===
Server: wss://localhost:8443
Status: Connected | User: alice

> connect
Generating keypair...
Uploading prekey...
Connected and ready for secure messaging!

> send bob Hello from the encrypted world!
Fetching prekey for bob...
Encrypting message...
Message sent to bob!

> chat alice
Entering chat mode with alice. Type ':exit' to leave chat mode.
[Chat] alice: Hey! How's the new WebSocket implementation working?
> It's fantastic! Real-time messaging feels so much more natural.
[Chat] You -> alice: It's fantastic! Real-time messaging feels so much more natural.
[Chat] alice: I agree! The instant delivery makes a huge difference.
> The encryption is completely transparent to the user experience.
[Chat] You -> alice: The encryption is completely transparent to the user experience.
> :exit
Left chat mode. Back to command mode.

> inbox
=== INBOX ===
[2024-09-13 14:23:15] alice: Hey! How's the new WebSocket implementation working?
[2024-09-13 14:23:45] alice: I agree! The instant delivery makes a huge difference.
[2024-09-13 14:24:12] bob: Thanks for the message! This WebSocket system is so much better.
[2024-09-13 14:24:18] charlie: The real-time updates are game-changing for user experience.

> list_users
=== REGISTERED USERS ===
- alice (online)
- bob (online)  
- charlie (online)
- dave (online)

> help
=== AVAILABLE COMMANDS ===
connect                    - Connect to WebSocket server
send <user> <message>      - Send encrypted message to user
chat <user>                - Enter real-time chat mode
inbox                      - View all received messages
list_users                 - Show all registered users
help                       - Show this help message  
quit                       - Exit application

> quit
Disconnecting from server...
Goodbye!
```

**Key Interface Features:**
- **Clean command-line interface** with clear prompts and feedback
- **Real-time chat mode** with automatic message polling and instant delivery
- **Message history** via inbox command showing all conversations with timestamps
- **User discovery** with online status indicators
- **Context-sensitive help** showing available commands
- **Seamless encryption** - all cryptographic operations are transparent to the user

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
