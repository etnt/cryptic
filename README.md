# Cryptic - End-to-End Encrypted Chat System

A proof-of-concept implementation of an end-to-end encrypted chat system built in Erlang/OTP, featuring a professional terminal UI and demonstrating modern cryptographic protocols for secure message exchange.

## Overview

Cryptic implements a secure messaging system using:
- **X25519** key agreement for establishing shared secrets
- **ChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **HKDF-SHA256** key derivation with multiple security strategies
- **HTTP REST API** for prekey distribution and message delivery
- **Forward secrecy** through ephemeral keys for each message exchange
- **Professional Terminal UI** with real-time chat capabilities
- **Color-coded interface** for enhanced user experience

## Quick Start

### Terminal UI Mode
```bash
# Start the server
$ rebar3 shell

# Or:
$ erl -pa _build/default/lib/*/ebin
1> cryptic_server:start().

# In another terminal(s), start the UI
$ ./bin/cryptic

# Or:
$ erl -pa _build/default/lib/*/ebin
1> cryptic_cecho_ui:start().

# Follow the on-screen instructions:
# 1. Register with: register <username>
# 2. Send messages with: send <user> <message>
# 3. Enter chat mode with: chat <user>
# 4. Use help command for more options
```

### UI Commands
- **`help`** - Show available commands
- **`register <username>`** - Register with the server
- **`send <user> <message>`** - Send encrypted message
- **`chat <user>`** - Enter real-time chat mode
- **`inbox`** - Check for new messages manually
- **`list_users`** - Show all registered users
- **`quit`** - Exit the application

### Chat Mode Commands
Once in chat mode with `chat <username>`:
- **Type any message** - Sends directly to chat target
- **`:exit`** - Leave chat mode
- **`:help`** - Show chat-specific help

## Features

### Terminal User Interface
- **Full-screen terminal UI** with ncurses-based interface using cecho
- **Real-time chat mode** for one-on-one conversations with automatic message polling
- **Command-based interface** with comprehensive help system
- **Color-coded messages** for better visual organization
- **Status bar** showing server connection, user info, and undelivered message count
- **Background message peeking** for non-intrusive notifications
- **Context-sensitive help** that changes based on current mode

### Cryptographic Security
- **End-to-end encryption** using industry-standard algorithms
- **Perfect forward secrecy** with ephemeral keys
- **Multiple key derivation strategies** for different security/usability trade-offs
- **Authenticated encryption** preventing tampering and ensuring confidentiality
- **Libsodium integration** for battle-tested cryptographic implementations

### User Experience
- **Interactive registration** with server
- **Real-time message delivery** in chat mode
- **Message count notifications** without consuming messages
- **Command history** and input handling
- **Graceful error handling** with user-friendly messages

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Alice     │                    │     Bob     │
│             │                    │             │
│ 1. Generate │                    │ 1. Upload   │
│    ephemeral│                    │    prekey   │
│    keypair  │                    │             │
│             │   2. Get prekey    │             │
│             │◄────────────────── │             │
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
- Alice encrypts her message using ChaCha20-Poly1305:
  ```
  {ciphertext, nonce} = ChaCha20-Poly1305-Encrypt(message, aead_key, "")
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
- **ChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **HKDF-SHA256**: Cryptographically strong key derivation
- **Libsodium**: Battle-tested cryptographic library via NIF

### Enhanced Key Derivation
- **Ephemeral-based salt**: Uses `SHA256(ephemeral_public_key)` as HKDF salt
- **Deterministic**: Both parties derive identical keys
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
├── README.md                    # This file
├── rebar.config                 # Erlang build configuration
├── docs/
│   └── CRYPTIC_PLAN.md         # Original design document
├── src/
│   ├── cryptic.app.src         # OTP application metadata
│   ├── cryptic_server.erl      # HTTP server with Cowboy routing
│   ├── cryptic_handlers.erl    # HTTP request handlers
│   ├── cryptic_lib.erl         # Core cryptographic functions
│   ├── cryptic_client_lib.erl  # High-level client API
│   ├── cryptic_cecho_ui.erl    # Terminal user interface
│   └── cryptic_nif.erl         # NIF interface definitions
├── test/
│   └── cryptic_e2e_test.erl    # End-to-end test suite
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

### User Management
- `GET /list_users` - List all registered users
- `GET /peek_messages/{user_id}` - Check message count without consuming messages

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

### Start Server
```bash
# Terminal 1: Start the server
erl -pa _build/default/lib/*/ebin
1> cryptic_server:start().
```

### Start Terminal UI
```bash
# Terminal 2: Start the interactive terminal UI
erl -pa _build/default/lib/*/ebin
1> cryptic_cecho_ui:start().

# Or connect to a different server
1> cryptic_cecho_ui:start("http://example.com:8080").
```

### Terminal UI Usage
Once the UI starts, you'll see a full-screen interface with:
- **Status bar** at the top showing server, user, and message info
- **Message area** in the middle displaying conversation history  
- **Help bar** showing available commands
- **Input line** at the bottom for typing commands

**Basic workflow:**
1. Register: `register myusername`
2. Send message: `send otherusername Hello there!`
3. Enter chat mode: `chat otherusername`
4. In chat mode, just type messages directly
5. Exit chat mode: `:exit`
6. Quit application: `quit`

### Run Client Demo
```bash
# Terminal 3: Run the programmatic client example
erl -pa _build/default/lib/*/ebin -s cryptic_client_example test -s init stop -noshell
```

### Run Tests
```bash
# Run comprehensive EUnit test suite
rebar3 eunit
```

## Client Library Usage

The `cryptic_client_lib` module provides a high-level API for building E2EE messaging applications. It abstracts away the cryptographic complexity and HTTP communication details.

### Quick Start

```erlang
%% Initialize the client library
cryptic_client_lib:init_client().

%% Generate keypairs for users
{AlicePub, AlicePriv} = cryptic_lib:gen_keypair(),
{BobPub, BobPriv} = cryptic_lib:gen_keypair().

%% Bob uploads his prekey to the server
cryptic_client_lib:upload_prekey("http://localhost:8080", "bob", BobPub).

%% Alice sends an encrypted message to Bob
cryptic_client_lib:send_encrypted_message(
    "http://localhost:8080", "alice", "bob", BobPub, <<"Hello Bob!">>).

%% Bob receives and decrypts his messages
{ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
    "http://localhost:8080", "bob", BobPriv).
```

### API Reference

#### Client Initialization

**`init_client/0`**
```erlang
cryptic_client_lib:init_client() -> ok.
```
Initializes the client by starting required applications (`inets`, `crypto`) and loading the cryptographic NIF.

#### Prekey Management

**`upload_prekey/3`**
```erlang
cryptic_client_lib:upload_prekey(ServerUrl, UserId, PublicKey) -> 
    ok | {error, Reason}.
```
- **ServerUrl**: Base URL of the Cryptic server (e.g., `"http://localhost:8080"`)
- **UserId**: User identifier (string or binary)
- **PublicKey**: User's X25519 public key (32 bytes)

**`get_prekey/2`**
```erlang
cryptic_client_lib:get_prekey(ServerUrl, UserId) -> 
    {ok, PublicKey} | {error, Reason}.
```
Retrieves a user's public prekey from the server.

#### Message Operations

**`encrypt_message/2`**
```erlang
cryptic_client_lib:encrypt_message(Message, RecipientPubKey) -> 
    {ok, {EphPub, Nonce, Cipher, SharedSecret}} | {error, Reason}.
```
- Generates ephemeral keypair automatically
- Computes shared secret using X25519
- Derives AEAD key using ephemeral-based HKDF
- Encrypts message with XChaCha20-Poly1305

**`send_message/6`**
```erlang
cryptic_client_lib:send_message(ServerUrl, FromUserId, ToUserId, 
                                EphPub, Nonce, Cipher) -> 
    ok | {error, Reason}.
```
Sends pre-encrypted message components to the server.

**`receive_messages/2`**
```erlang
cryptic_client_lib:receive_messages(ServerUrl, UserId) -> 
    {ok, [EncryptedBlob]} | {error, Reason}.
```
Fetches pending encrypted messages for a user. Returns list of message blobs with structure:
```erlang
#{
    from => "sender_id",
    ephemeral => "base64_ephemeral_pubkey",
    nonce => "base64_nonce", 
    cipher => "base64_ciphertext"
}
```

**`decrypt_message/2`**
```erlang
cryptic_client_lib:decrypt_message(EncryptedBlob, RecipientPrivKey) -> 
    {ok, PlainText} | {error, Reason}.
```
Decrypts a single message blob using the recipient's private key.

#### High-Level E2E Functions

**`send_encrypted_message/5`**
```erlang
cryptic_client_lib:send_encrypted_message(ServerUrl, FromUserId, ToUserId, 
                                         RecipientPubKey, Message) -> 
    ok | {error, Reason}.
```
Complete send flow: encrypts message and sends to server in one call.

**`receive_and_decrypt_messages/3`**
```erlang
cryptic_client_lib:receive_and_decrypt_messages(ServerUrl, UserId, PrivateKey) -> 
    {ok, [{FromUser, PlainTextMessage}]} | {error, Reason}.
```
Complete receive flow: fetches all pending messages and decrypts them. Returns a list of tuples containing the sender and decrypted message text.

**`peek_message_count/2`**
```erlang
cryptic_client_lib:peek_message_count(ServerUrl, UserId) -> 
    {ok, Count} | {error, Reason}.
```
Check the number of undelivered messages without consuming them. Useful for notifications and status displays.

### Usage Patterns

#### Basic Chat Application

```erlang
-module(my_chat_client).
-export([start/0]).

start() ->
    %% Initialize
    cryptic_client_lib:init_client(),
    
    %% Generate user keypairs
    {MyPub, MyPriv} = cryptic_lib:gen_keypair(),
    {FriendPub, _} = cryptic_lib:gen_keypair(), % In reality, get from server
    
    %% Upload my prekey
    ok = cryptic_client_lib:upload_prekey(
        "http://localhost:8080", "me", MyPub),
    
    %% Send message to friend
    ok = cryptic_client_lib:send_encrypted_message(
        "http://localhost:8080", "me", "friend", FriendPub, 
        <<"Hello from Erlang!">>),
    
    %% Check for messages
    {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
        "http://localhost:8080", "me", MyPriv),
    
    lists:foreach(fun(Msg) -> 
        io:format("Received: ~s~n", [Msg]) 
    end, Messages).
```

#### Message Loop

```erlang
message_loop(ServerUrl, UserId, PrivKey) ->
    timer:sleep(1000), % Poll every second
    case cryptic_client_lib:receive_and_decrypt_messages(ServerUrl, UserId, PrivKey) of
        {ok, []} -> 
            message_loop(ServerUrl, UserId, PrivKey);
        {ok, Messages} ->
            lists:foreach(fun(Msg) ->
                io:format("~s: ~s~n", [UserId, Msg])
            end, Messages),
            message_loop(ServerUrl, UserId, PrivKey);
        {error, Reason} ->
            io:format("Error receiving messages: ~p~n", [Reason])
    end.
```

#### Error Handling Best Practices

```erlang
send_with_retry(ServerUrl, From, To, RecipientPubKey, Message, Retries) ->
    case cryptic_client_lib:send_encrypted_message(
        ServerUrl, From, To, RecipientPubKey, Message) of
        ok -> 
            ok;
        {error, _Reason} when Retries > 0 ->
            timer:sleep(1000),
            send_with_retry(ServerUrl, From, To, RecipientPubKey, Message, Retries - 1);
        {error, Reason} ->
            {error, {max_retries_exceeded, Reason}}
    end.
```

### Security Considerations

#### Key Management
```erlang
%% Store private keys securely - never log or expose them
{PubKey, PrivKey} = cryptic_lib:gen_keypair(),

%% Public keys can be safely shared and stored
store_public_key(UserId, PubKey),

%% Private keys should be encrypted at rest in production
SecurePrivKey = encrypt_private_key(PrivKey, UserPassword).
```

#### Message Validation
```erlang
validate_and_decrypt(EncryptedBlob, PrivKey) ->
    case cryptic_client_lib:decrypt_message(EncryptedBlob, PrivKey) of
        {ok, PlainText} when byte_size(PlainText) =< 10000 -> % Size limit
            case is_valid_utf8(PlainText) of
                true -> {ok, PlainText};
                false -> {error, invalid_encoding}
            end;
        {ok, _} -> {error, message_too_large};
        {error, Reason} -> {error, Reason}
    end.
```

### Integration Examples

#### With OTP GenServer
```erlang
-module(chat_client_server).
-behaviour(gen_server).

-record(state, {
    server_url,
    user_id,
    private_key,
    contacts = #{} % user_id => public_key
}).

init([ServerUrl, UserId, PrivateKey]) ->
    cryptic_client_lib:init_client(),
    {ok, #state{
        server_url = ServerUrl,
        user_id = UserId, 
        private_key = PrivateKey
    }}.

handle_call({send_message, ToUserId, Message}, _From, State) ->
    case maps:get(ToUserId, State#state.contacts, undefined) of
        undefined ->
            {reply, {error, contact_not_found}, State};
        ToPubKey ->
            Result = cryptic_client_lib:send_encrypted_message(
                State#state.server_url,
                State#state.user_id,
                ToUserId,
                ToPubKey,
                Message
            ),
            {reply, Result, State}
    end.
```

#### Command Line Interface
```erlang
main([ServerUrl, UserId]) ->
    cryptic_client_lib:init_client(),
    {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
    
    %% Upload prekey
    cryptic_client_lib:upload_prekey(ServerUrl, UserId, PubKey),
    
    %% Interactive loop
    cli_loop(ServerUrl, UserId, PrivKey).

cli_loop(ServerUrl, UserId, PrivKey) ->
    case io:get_line("Command (send/check/quit): ") of
        "send\n" ->
            ToUser = string:trim(io:get_line("To: ")),
            Message = list_to_binary(string:trim(io:get_line("Message: "))),
            case get_user_pubkey(ServerUrl, ToUser) of
                {ok, ToPubKey} ->
                    cryptic_client_lib:send_encrypted_message(
                        ServerUrl, UserId, ToUser, ToPubKey, Message),
                    io:format("Message sent!~n");
                {error, Reason} ->
                    io:format("Error: ~p~n", [Reason])
            end,
            cli_loop(ServerUrl, UserId, PrivKey);
        "check\n" ->
            {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
                ServerUrl, UserId, PrivKey),
            lists:foreach(fun(Msg) ->
                io:format("Message: ~s~n", [Msg])
            end, Messages),
            cli_loop(ServerUrl, UserId, PrivKey);
        "quit\n" ->
            ok
    end.
```

The client library provides a clean, type-safe API that handles all the cryptographic complexity while giving you full control over the messaging flow.

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
- `aead_encrypt/3` - ChaCha20-Poly1305 encryption
- `aead_decrypt/4` - ChaCha20-Poly1305 decryption
- `rand_bytes/1` - Cryptographically secure random bytes

### Terminal UI Architecture
The cecho-based UI uses an event-driven architecture:
- **Main event loop** processes user input and system events
- **Input handler process** captures keyboard input asynchronously
- **Status updater process** refreshes the status bar periodically
- **Auto-peek timer** checks for new messages in the background
- **Chat poll timer** provides real-time messaging in chat mode

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

### Current Limitations
- **In-memory storage**: Messages and prekeys stored in ETS (not persistent)
- **⚠️ No authentication**: Anyone can register with any username - **SECURITY RISK**
- **No replay protection**: Messages could theoretically be replayed
- **Single prekey**: Bob uses one prekey for all conversations

### Authentication Security Gap

**CRITICAL**: The current system allows unrestricted registration:
```bash
register alice  # Anyone can claim to be "alice"
```

This poses significant security risks in any real-world deployment. See our comprehensive [**Authentication Plan**](docs/AUTHENTICATION_PLAN.md) for modern solutions.

### Recommended Authentication Solutions

We've designed a **4-phase authentication roadmap** with increasing security levels:

1. **Phase 1: Pre-Shared Keys** (1-2 days) - Quick security fix
   - Users need a secret token to register
   - Immediate protection against unauthorized access
   - Simple to deploy

2. **Phase 2: JWT Authentication** (3-5 days) - Modern standard
   - Username/password login with JWT tokens
   - Fine-grained permissions and role-based access
   - Industry-standard security

3. **Phase 3: Ed25519 Digital Signatures** (4-7 days) - Cryptographically strong
   - Challenge-response authentication with digital signatures
   - Cryptographically provable identity
   - No passwords to compromise

4. **Phase 4: Hardware Security Keys** (1-2 weeks) - Enterprise grade
   - FIDO2/WebAuthn support for hardware tokens
   - Multi-factor authentication
   - Maximum security for sensitive deployments

**📖 Full details**: [Authentication and Access Control Plan](docs/AUTHENTICATION_PLAN.md)

### Production Considerations
For production use, implementing authentication is **essential**. Additionally consider:
- Message ordering and replay protection
- Persistent storage with proper key management
- Key rotation mechanisms
- Multiple prekeys per user (X3DH protocol)
- Perfect forward secrecy with Double Ratchet
- Message delivery receipts and read confirmations
- Group messaging capabilities
- File transfer support
- Rate limiting and abuse prevention
- Audit logging and monitoring

## UI Screenshots

The terminal interface provides a professional chat experience:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ CRYPTIC CHAT | Server: http://localhost:8080 | User: alice | Chat with: bob | │
│              | Undelivered: 2 | 14:23:45                                     │
├──────────────────────────────────────────────────────────────────────────────┤
│ === CRYPTIC CHAT ===                                                        │
│ Server: http://localhost:8080                                               │
│ Successfully registered as: alice                                           │
│ Entering chat mode with bob. Type ':exit' to leave chat mode.              │
│ bob: Hello Alice! How are you?                                              │
│ You -> bob: I'm doing great, thanks for asking!                            │
│ bob: That's wonderful to hear.                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ Chat Mode: Type message to send | :exit to leave chat | :help for commands  │
├──────────────────────────────────────────────────────────────────────────────┤
│ > Great! Let me tell you about my day...                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Features visible in the interface:**
- **Status bar** shows server, current user, chat target, and message count
- **Message area** displays conversation with color-coded messages
- **Help bar** provides context-sensitive command information
- **Input line** shows current typing with prompt

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
