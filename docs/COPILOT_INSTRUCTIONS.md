# Cryptic Project - AI Assistant Instructions

## Project Overview

**Cryptic** is a proof-of-concept end-to-end encrypted messaging system implemented in Erlang/OTP. It demonstrates modern cryptographic protocols for secure real-time message exchange with forward secrecy using WebSocket mTLS authentication.

### Core Technology Stack
- **Language**: Erlang/OTP 27+
- **Transport**: WebSocket with mutual TLS (mTLS) client certificate authentication
- **Cryptography**: Libsodium via NIF (X25519 + ChaCha20-Poly1305 + HKDF-SHA256)
- **WebSocket Server**: Cowboy WebSocket handlers
- **Terminal UI**: Professional ncurses-based interface (cecho)
- **Testing**: EUnit with comprehensive test suite
- **Build Tool**: Rebar3
- **Documentation**: EDoc with comprehensive module coverage

## Security Architecture

### Cryptographic Protocol
1. **Authentication**: X.509 client certificate-based identity verification via mTLS
2. **Key Exchange**: X25519 elliptic curve Diffie-Hellman with ephemeral keys per message
3. **Encryption**: ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
4. **Key Derivation**: HKDF-SHA256 with ephemeral public key as salt for enhanced security
5. **Forward Secrecy**: Each message uses fresh ephemeral keypairs
6. **Transport Security**: Mutual TLS provides authenticated and encrypted WebSocket channels

### Security Level
- **Overall Security**: 128-bit (limited by X25519)
- **Authentication**: Strong cryptographic identity via X.509 client certificates
- **Transport**: Mutual TLS 1.2+ with certificate verification
- **Standards Compliance**: RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF)
- **Quantum Resistance**: None (classical cryptography, will need post-quantum upgrade)
- **Industry Comparison**: Similar to Signal Protocol's crypto primitives, TLS 1.3, WireGuard

## Project Structure

```
cryptic/
├── src/                          # Erlang source code
│   ├── cryptic_server.erl       # Main server (gen_server + WebSocket mTLS)
│   ├── cryptic_ws_handler.erl   # WebSocket connection handlers with mTLS auth
│   ├── cryptic_ws_client.erl    # WebSocket client with certificate authentication
│   ├── cryptic_ws_ui.erl        # Professional terminal UI with ncurses
│   ├── cryptic_lib.erl          # High-level crypto API and storage
│   ├── cryptic_nif.erl          # NIF interface definitions
│   ├── cryptic_event_manager.erl # Event handling and logging system
│   ├── cryptic_console_logger.erl # Console-based event logger
│   ├── cryptic_file_logger.erl  # File-based event logger
│   ├── cryptic_app.erl          # OTP application behavior
│   └── cryptic_sup.erl          # OTP supervisor
├── test/                         # EUnit test suite
│   └── cryptic_e2e_test.erl     # End-to-end integration tests
├── c_src/                        # C NIF implementation
│   ├── cryptic_nif.c            # Libsodium wrapper
│   └── Makefile                 # NIF build configuration
├── CA/                           # Certificate Authority infrastructure
│   ├── certs/                   # CA and server certificates
│   ├── private/                 # Private keys (CA and server)
│   ├── client_keys/             # Client certificates and keys
│   └── scripts/                 # Certificate management scripts
├── doc/                          # EDoc documentation
│   ├── overview.edoc            # Main application overview
│   └── README.md                # Documentation guide
├── scripts/                      # Utility scripts
│   ├── start-server.sh          # Server startup with certificates
│   ├── start-client.sh          # Client startup with certificates
│   └── build-docs.sh            # Documentation build script
├── docs/                         # Project documentation
│   ├── CRYPTIC_PLAN.md          # Original design document
│   └── COPILOT_INSTRUCTIONS.md  # This file
└── README.md                     # Comprehensive project documentation
```

## Key Modules and Their Responsibilities

### Core Modules

**`cryptic_server.erl`** - Main Server Process
- OTP gen_server behavior for application lifecycle management
- Manages ETS tables for user connections, prekeys, and message blobs
- Starts Cowboy WebSocket mTLS server on port 8443
- Environment-based configuration for SSL certificates and server settings
- Graceful shutdown with proper resource cleanup

**`cryptic_ws_handler.erl`** - WebSocket Connection Handler
- Cowboy WebSocket handler for individual client connections
- mTLS authentication using X.509 client certificates
- Extracts username from certificate Common Name (CN) field
- JSON-based command protocol for messaging operations
- Real-time message routing between authenticated users

**`cryptic_ws_client.erl`** - WebSocket Client
- WebSocket client with mTLS certificate authentication
- Automatic keypair generation and prekey upload on connection
- Message encryption/decryption with ephemeral key management
- Clean API for messaging operations and server communication
- Integration with terminal UI for user interaction

**`cryptic_ws_ui.erl`** - Terminal User Interface
- Professional ncurses-based terminal interface using cecho
- Real-time chat mode with automatic message polling
- Command-based interface with comprehensive help system
- Inbox functionality for message history and management
- Advanced command line editing with cursor movement and history

**`cryptic_lib.erl`** - Cryptographic Library
- High-level wrapper around libsodium NIF functions
- Key functions: `gen_keypair/0`, `scalarmult/2`, `aead_encrypt/3`, `aead_decrypt/4`
- HKDF implementations with ephemeral-based salt strategy
- ETS-based storage for user prekeys and message blobs
- Message encryption/decryption with automatic key derivation

**`cryptic_nif.erl`** - NIF Interface
- Erlang interface to C NIF functions for cryptographic operations
- Bridges Erlang to libsodium cryptographic primitives
- Functions: key generation, scalar multiplication, AEAD encryption, random bytes
- Memory-safe implementations with proper error handling

### WebSocket Client API Categories

1. **Connection Management**: `start_link/0`, `connect/1`, `set_ui_pid/2`
2. **Messaging Operations**: `send_message/3`, `get_prekey/2`, `list_users/1`
3. **Real-time Communication**: WebSocket-based instant message delivery
4. **Certificate Authentication**: Automatic mTLS setup with client certificates
5. **UI Integration**: Message forwarding to terminal interface

### Terminal UI Features

1. **Command Interface**: `connect`, `send <user> <message>`, `chat <user>`, `inbox`, `list_users`, `help`, `quit`
2. **Real-time Chat Mode**: Direct messaging with automatic polling and instant delivery
3. **Advanced Editing**: Cursor movement, command history, text insertion/deletion
4. **Message Management**: Inbox with timestamps, user filtering, auto-display options
5. **Professional Display**: Clean ncurses interface with status indicators

### Supporting Modules

**Event Management System**: 
- `cryptic_event_manager.erl` - Structured event handling
- `cryptic_console_logger.erl` - Terminal logging
- `cryptic_file_logger.erl` - File-based audit trails

**OTP Infrastructure**:
- `cryptic_app.erl` - Application behavior
- `cryptic_sup.erl` - Supervision tree

## Message Flow Protocol

### Setup Phase
1. **Certificate Authentication**: Client connects to WebSocket server using X.509 client certificate
2. **Identity Extraction**: Server extracts username from certificate Common Name (CN) field  
3. **Connection Registration**: Server registers WebSocket connection in ETS table for user
4. **Automatic Prekey Upload**: Client generates X25519 keypair and uploads public key via WebSocket

### Real-time Message Exchange
1. **Message Initiation**: Alice wants to send message to Bob
2. **Prekey Request**: Alice requests Bob's prekey via WebSocket: `{"type": "get_prekey", "user": "bob"}`
3. **Alice encrypts message**:
   - Generate ephemeral X25519 keypair
   - Compute shared secret: `X25519(alice_ephemeral_private, bob_prekey_public)`
   - Derive AEAD key: `HKDF-SHA256(shared_secret, SHA256(ephemeral_public), "encryption")`
   - Encrypt: `ChaCha20-Poly1305(message, aead_key, nonce)`
4. **Message Transmission**: Alice sends encrypted blob via WebSocket: `{"type": "send_message", "to": "bob", "ephemeral": "...", "nonce": "...", "cipher": "..."}`
5. **Real-time Delivery**: Server immediately forwards message to Bob's WebSocket connection (if online)
6. **Bob decrypts**:
   - Extract ephemeral public key from message blob
   - Compute same shared secret: `X25519(bob_prekey_private, alice_ephemeral_public)`
   - Derive same AEAD key using ephemeral public key
   - Decrypt: `ChaCha20-Poly1305_decrypt(cipher, aead_key, nonce)`

### Certificate Infrastructure
- **CA Management**: Complete Certificate Authority in `CA/` directory
- **Client Certificates**: Pre-configured certificates for alice, bob, charlie, admin
- **Certificate Generation**: `make client` to create new user certificates
- **Revocation Support**: Certificate revocation lists (CRL) for security

## Development Context

### Build and Test Commands
```bash
rebar3 compile              # Build project (compiles NIF automatically)
rebar3 eunit               # Run all tests
rebar3 edoc                # Generate EDoc documentation
./scripts/build-docs.sh    # Clean build and documentation generation
```

### Server and Client Operations
```bash
# Start WebSocket mTLS server
./scripts/start-server.sh

# Start terminal UI client
./scripts/start-client.sh alice    # Connects with alice's certificate
./scripts/start-client.sh bob      # Connects with bob's certificate

# Or manually:
erl -pa _build/default/lib/*/ebin
1> cryptic_server:start_websocket_mtls().    % Server on wss://localhost:8443
1> cryptic_ws_ui:start().                    % Interactive terminal client
```

### Certificate Management
```bash
cd CA/
make all           # Generate CA and server certificates
make client        # Generate new client certificate
./scripts/verify-crt.sh client_keys/alice.crt  # Verify certificate
./scripts/revoke-cert.sh certs/02.pem          # Revoke certificate
```

### Common Development Patterns

**Error Handling**: All functions return `{ok, Result} | {error, Reason}` tuples
**Unicode Support**: Messages handled as binaries with automatic UTF-8 encoding
**JSON Protocol**: WebSocket messages use structured JSON command format
**ETS Storage**: In-memory tables for connections, prekeys, and message blobs
**Real-time Delivery**: WebSocket connections enable instant message forwarding
**Certificate-based Identity**: Username extracted from X.509 certificate CN field
**Forward Secrecy**: Fresh ephemeral keypairs generated for each message exchange

## AI Assistant Guidelines

### When Working on This Project

1. **Security First**: Always consider cryptographic implications of changes
2. **Test Coverage**: Maintain comprehensive test coverage for all new functions
3. **Documentation**: Add EDoc comments for all public functions
4. **Error Handling**: Follow `{ok, Result} | {error, Reason}` pattern consistently
5. **Type Safety**: Use proper type specs (`-spec`) for all functions

### Key Files to Understand

- **`cryptic_ws_ui.erl`**: Terminal UI and user experience - start here for UI questions
- **`cryptic_ws_client.erl`**: WebSocket client API - core messaging functionality  
- **`cryptic_ws_handler.erl`**: Server-side WebSocket handling and authentication
- **`cryptic_server.erl`**: Application lifecycle and WebSocket server management
- **`cryptic_lib.erl`**: Core crypto operations and storage management
- **`README.md`**: Comprehensive documentation with security analysis
- **`doc/overview.edoc`**: EDoc application overview and user guide

### Common Tasks

**Adding New WebSocket Commands**:
1. Add command handling to `cryptic_ws_handler.erl` in `handle_command/3`
2. Add client-side API to `cryptic_ws_client.erl` 
3. Update terminal UI commands in `cryptic_ws_ui.erl` if needed
4. Add corresponding tests to verify functionality
5. Follow JSON message protocol patterns

**Adding New UI Features**:
1. Modify command processing in `cryptic_ws_ui.erl`
2. Update help system and command documentation
3. Test cursor positioning and screen refresh behavior
4. Ensure proper integration with WebSocket client

**Modifying Crypto**:
1. Changes likely needed in `cryptic_lib.erl` or `cryptic_nif.c`
2. Consider security implications carefully
3. Update security analysis in README if needed
4. Test with different message sizes and Unicode content

**Server Configuration**:
1. Modify server startup in `cryptic_server.erl`
2. Update certificate handling in `cryptic_ws_handler.erl`
3. Test with different certificate configurations
4. Verify mTLS authentication behavior

### Testing Strategy

- **Unit Tests**: Individual module functionality (cryptographic operations, UI components)
- **Integration Tests**: Full WebSocket connection and message flow testing
- **UI Tests**: Terminal interface and command processing verification
- **Certificate Tests**: mTLS authentication and certificate validation
- **Error Cases**: Network failures, malformed messages, invalid certificates
- **Edge Cases**: Unicode messages, large data, connection drops
- **Real-time Tests**: WebSocket message delivery and connection management

### Current Status

✅ **Production Ready Features**:
- Complete WebSocket mTLS server with certificate authentication
- Professional terminal UI with real-time chat capabilities
- Comprehensive EDoc documentation for all modules
- Advanced command line editing with cursor movement and history
- Forward secrecy with ephemeral keys per message
- Robust error handling and connection management
- Certificate Authority infrastructure with management tools

🔄 **Possible Enhancements**:
- Message persistence (currently in-memory ETS)
- Key rotation mechanisms
- Post-quantum cryptography
- Group messaging capabilities
- File transfer support
- Mobile client applications
- Web-based client interface
- High availability server clustering

### Security Considerations for AI Assistants

1. **Never log or expose private keys** in debug output or suggestions
2. **Validate all inputs** especially in crypto functions and WebSocket handlers
3. **Consider timing attacks** when adding crypto operations
4. **Use constant-time comparisons** for sensitive data
5. **Clear sensitive memory** when possible
6. **Follow libsodium best practices** for the NIF layer
7. **Validate certificates properly** in mTLS authentication
8. **Protect against WebSocket injection** in message handling
9. **Consider replay attacks** in protocol design
10. **Maintain forward secrecy** in key management

This instruction file should give any AI assistant a comprehensive understanding of the Cryptic project's current WebSocket mTLS architecture, security model, and development practices for effective assistance.
