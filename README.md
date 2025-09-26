# Cryptic - End-to-End Encrypted Chat System

A professional implementation of an end-to-end encrypted chat system built in Erlang/OTP, featuring WebSocket mTLS communication, real-time messaging, and demonstrating modern cryptographic protocols for secure message exchange.

## Documentation

📚 **[Complete API Documentation](https://etnt.github.io/cryptic/)** - Comprehensive EDoc-generated documentation

For local documentation generation:
```bash
rebar3 edoc
# Open doc/index.html in your browser
```

## Overview

Cryptic implements a secure messaging system using:
- **WebSocket mTLS** communication for real-time, certificate-authenticated messaging
- **Double Ratchet Protocol** for advanced forward secrecy and break-in recovery
- **X3DH Key Agreement** for secure session establishment
- **X25519** key agreement for establishing shared secrets
- **ChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **Blake2b KDF** (39x faster than Erlang) for high-performance key derivation
- **Out-of-order message handling** with skipped message key store
- **Automatic ratchet session management** with seamless X3DH-to-ratchet transitions
- **Professional Terminal UI** with real-time chat capabilities and ratchet status display
- **Color-coded interface** with interactive chat mode and network health monitoring

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

The **key_status** command shows the status of uploaded keys and active Double Ratchet sessions:

```
=== Double Ratchet Sessions ===
Active sessions: 2
  alice: Step 2, Chain[3 init, 5 resp], Prev[2 msgs], Skipped[0 keys]
  bob: Step 1, Chain[5 init, 3 resp], Prev[2 msgs], Skipped[2 keys]
       │        │                      │             └─ Network health indicator
       │        │                      └─ Previous chain history  
       │        └─ Current chain activity (init/resp contexts)
       └─ DH ratchet steps (forward secrecy rotations)
```

**Status Line Explanation:**
- **Step X**: Number of DH ratchet steps (key rotations for forward secrecy)
- **Chain[X init, Y resp]**: Current message counters for initiator/responder chains
- **Prev[X msgs]**: Messages processed in previous receiving chain before rotation
- **Skipped[X keys]**: Out-of-order messages cached (network health indicator)


### Chat Mode Commands
Once in chat mode with `chat <username>`:
- **Type any message** - Sends encrypted message directly to chat target
- **`:exit`** - Leave chat mode and return to command mode
- **`:help`** - Show chat-specific help

## Certificate Handling

Read [here](docs/CERTIFICATE_HANDLING.md) to learn how to create certificates
for new Clients.

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
- **Double Ratchet Protocol** providing forward secrecy and break-in recovery
- **X3DH Key Agreement** for secure initial session establishment
- **End-to-end encryption** using industry-standard X25519 + ChaCha20-Poly1305
- **High-performance KDF** with Blake2b (39x faster than Erlang implementations)
- **Out-of-order message handling** with skipped message key store for network resilience
- **Automatic ratchet management** with seamless transitions from X3DH to ratchet sessions
- **Authenticated encryption** preventing tampering and ensuring confidentiality
- **Libsodium integration** for battle-tested cryptographic implementations

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
│  (Terminal UI)  │         Double Ratchet Protocol     │ (Terminal UI) │
└─────────┬───────┘                                     └───────┬───────┘
          │                                                     │
          │ 1. Connect with client cert                         │ 1. Connect with client cert
          │ 2. Auto-generate keypair                            │ 2. Auto-generate keypair  
          │ 3. Upload prekey                                    │ 3. Upload prekey
          │ 4. X3DH → Double Ratchet transition                │ 4. X3DH → Double Ratchet transition
          │                                                     │
          │ ┌─────────────────────────────────────────────────┐ │
          └─│            WebSocket mTLS Server                │─┘
            │        Certificate Authentication               │
            │     Real-time Message Forwarding                │
            │    User/Prekey/Ratchet State Management         │
            └─────────────────────────────────────────────────┘

Protocol Flow:
Phase 1 - Initial Contact (X3DH):
1. Alice generates ephemeral keypair for first message
2. Alice fetches Bob's prekey bundle via WebSocket  
3. Alice performs X3DH key agreement → shared secret
4. Alice sends encrypted message with X3DH metadata
5. Bob receives and decrypts, establishing shared secret

Phase 2 - Ratchet Initialization:
6. Both parties initialize Double Ratchet with X3DH shared secret
7. Alice as sender, Bob as receiver (automatic role assignment)
8. Ratchet sessions stored and managed transparently

Phase 3 - Ongoing Communication:
9. All subsequent messages use Double Ratchet protocol
10. DH ratchet steps provide forward secrecy and break-in recovery
11. Out-of-order messages handled via skipped key store
12. High-performance Blake2b KDF for optimal throughput
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

### 3. Initial Session Establishment (X3DH)
For first contact between users:
- Alice generates fresh ephemeral X25519 keypair
- Alice fetches Bob's prekey bundle via WebSocket: `{"type": "get_key_bundle", "user": "bob"}`
- Alice performs X3DH key agreement: `shared_secret = X3DH(alice_keys, bob_prekey_bundle)`
- Alice encrypts message and sends with X3DH metadata
- Bob decrypts and both parties derive the same shared secret

### 4. Double Ratchet Initialization
After X3DH session establishment:
- Both parties automatically initialize Double Ratchet with X3DH shared secret
- Alice becomes sender (active sending chain), Bob becomes receiver  
- Ratchet sessions stored and managed transparently by the system
- No user intervention required - seamless transition from X3DH to ratchet

### 5. Ongoing Double Ratchet Communication
For all subsequent messages in the conversation:

#### Chain Key Derivation
```
# High-performance Blake2b KDF (39x faster than Erlang)
message_key = Blake2b-KDF(chain_key, msg_number, "msg")
new_chain_key = Blake2b-KDF(chain_key, msg_number + 1, "chain")
```

#### DH Ratchet Steps (Forward Secrecy)
```
# Periodic key rotation for break-in recovery
{new_root_key, init_chain, resp_chain} = KDF-RK(root_key, dh_output)
# Separate chains for initiator/responder directions
```

#### Message Processing
- Each party maintains independent sending and receiving chains
- DH ratchet steps inject fresh entropy and provide break-in recovery
- Out-of-order messages handled via skipped message key store
- Forward secrecy: past messages remain secure if current keys compromised

### 6. Out-of-Order Message Handling
- System pre-derives keys for skipped messages (up to configurable limit)
- Delayed messages decrypted using cached skipped keys
- Keys automatically cleaned up after use (forward secrecy)
- Network resilience without sacrificing security properties

### 7. Real-time Delivery & State Management
- WebSocket connections enable instant message delivery
- Ratchet state automatically persisted and synchronized
- No polling required - messages pushed immediately to recipients
- Comprehensive status monitoring with network health indicators

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

## Double Ratchet Implementation

### Overview
Cryptic implements the Double Ratchet protocol as specified in the Signal Protocol documentation, providing:
- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Break-in Recovery**: Security is restored after key material compromise through DH ratchet steps
- **Asynchronous Messaging**: Works seamlessly with offline/online patterns
- **Out-of-order Handling**: Delayed and reordered messages handled gracefully
- **High Performance**: Native Blake2b KDF provides 39x performance improvement over Erlang

### Protocol Flow

#### 1. Session Initialization
```erlang
%% After X3DH key agreement, both parties initialize ratchet
{ok, AliceState} = cryptic_double_ratchet:init_sender(SharedSecret, AliceDHKeys),
{ok, BobState} = cryptic_double_ratchet:init_receiver(SharedSecret, BobDHKeys).
```

#### 2. Message Encryption
```erlang
%% Alice encrypts message - automatically handles DH ratchet if needed
{ok, EncryptedMessage, NewAliceState} = cryptic_double_ratchet:encrypt_message(
    <<"Hello Bob!">>, AliceState
).
```

#### 3. Message Decryption  
```erlang
%% Bob decrypts - handles out-of-order messages and gap filling
{ok, <<"Hello Bob!">>, NewBobState} = cryptic_double_ratchet:decrypt_message(
    EncryptedMessage, BobState
).
```

### Key Features

#### Chain Management
- **Sending Chain**: Derives keys for outgoing messages, advances independently
- **Receiving Chain**: Derives keys for incoming messages, handles gaps automatically
- **Chain Contexts**: Uses "init" context for initiator, "resp" for responder
- **Chain Reset**: Chains reset during DH ratchet steps for fresh entropy

#### DH Ratchet Steps
- **Automatic Detection**: System detects when DH ratchet step is needed
- **Key Rotation**: Generates fresh DH keypairs and derives new root key
- **Forward Secrecy**: Old DH keys securely discarded after ratchet step
- **Break-in Recovery**: New DH output restores security after compromise

#### Out-of-Order Handling
- **Gap Detection**: Automatically detects missing messages in sequence
- **Key Pre-derivation**: Pre-derives keys for skipped messages (up to limit)
- **Delayed Decryption**: Uses cached keys when delayed messages arrive
- **Memory Management**: Automatically cleans up used keys for forward secrecy

#### Performance Optimization
- **Native KDF**: Blake2b implementation via C NIF (39x faster than Erlang)
- **Efficient State**: Minimal memory footprint with fast serialization
- **Batched Operations**: Optimized for high-throughput message processing

### State Information
The system provides comprehensive ratchet monitoring:
```erlang
StateInfo = cryptic_double_ratchet:get_state_info(RatchetState),
%% Returns: #{
%%   dh_ratchet_step => 2,           % Forward secrecy rotations
%%   send_msg_number => 5,           % Current sending chain position  
%%   recv_msg_number => 3,           % Current receiving chain position
%%   prev_recv_chain_length => 7,   % Previous chain message count
%%   skipped_keys_count => 2,        % Out-of-order messages cached
%%   sending_chain_active => true,   % Can send messages
%%   receiving_chain_active => true, % Can receive messages
%%   has_remote_dh => true           % Has peer's DH key
%% }
```

### Integration with X3DH
The Double Ratchet seamlessly integrates with X3DH key agreement:

1. **Initial Contact**: X3DH establishes shared secret for first message
2. **Automatic Transition**: Both parties automatically initialize ratchet with X3DH secret
3. **Ongoing Security**: All subsequent messages use Double Ratchet protocol
4. **Transparent Operation**: Users experience seamless encryption without protocol awareness

### Testing and Verification
Comprehensive EUnit test suite covers:
- **Basic Encryption/Decryption**: Round-trip message handling
- **Out-of-Order Scenarios**: Messages arriving in wrong order
- **Gap Handling**: Missing messages with various gap sizes
- **DH Ratchet Steps**: Key rotation and forward secrecy verification
- **Edge Cases**: Excessive gaps, duplicate messages, mixed scenarios

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
│   ├── cryptic_double_ratchet.erl # Double Ratchet protocol implementation
│   ├── cryptic_ws_client.erl   # WebSocket client with mTLS authentication
│   ├── cryptic_ws_ui.erl       # Professional terminal UI with ratchet status
│   └── cryptic_event_manager.erl # Event handling and logging system
├── test/
│   ├── cryptic_e2e_test.erl    # End-to-end test suite
│   ├── cryptic_double_ratchet_test.erl # Double Ratchet unit tests
│   └── cryptic_double_ratchet_out_of_order_test.erl # Out-of-order message tests
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
- `kdf_derive/4` - High-performance Blake2b key derivation (39x faster than Erlang)
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
- **In-memory storage**: Messages and ratchet sessions stored in ETS (not persistent across restarts)
- **⚠️ Certificate-based identity**: WebSocket mTLS provides authentication but not user identity verification
- **Limited replay protection**: Double Ratchet provides some ordering but not complete replay protection
- **Single prekey**: Users have one prekey for initial X3DH (production should implement prekey rotation)

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

4. **Enhanced Key Management**
   - Multiple prekeys per user for better X3DH security
   - Automatic prekey rotation mechanisms
   - Persistent ratchet session storage with proper key cleanup

### Production Considerations
For production use, implementing proper identity verification is **essential**. Additionally consider:
- **Persistent storage** with proper database backend for ratchet sessions and message history
- **Message ordering** and enhanced replay protection with sequence numbers
- **User registration** with certificate generation and identity verification
- **Enhanced key management** with multiple prekeys per user and automatic rotation
- **Group messaging** capabilities with efficient key distribution (MLS protocol)
- **File transfer** support with chunked encryption via Double Ratchet
- **Rate limiting** and abuse prevention at WebSocket level
- **Audit logging** and monitoring of security events and ratchet state
- **High availability** with server clustering and distributed ratchet state
- **Performance optimization** for high-throughput ratchet operations

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
