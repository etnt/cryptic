# Cryptic Project - AI Assistant Instructions

## Project Overview

**Cryptic** is a proof-of-concept end-to-end encrypted messaging system implemented in Erlang/OTP. It demonstrates modern cryptographic protocols for secure message exchange with forward secrecy.

### Core Technology Stack
- **Language**: Erlang/OTP 27+
- **Cryptography**: Libsodium via NIF (X25519 + XChaCha20-Poly1305 + HKDF-SHA256)
- **HTTP Server**: Cowboy web server
- **Testing**: EUnit with comprehensive test suite
- **Build Tool**: Rebar3
- **Documentation**: EDoc

## Security Architecture

### Cryptographic Protocol
1. **Key Exchange**: X25519 elliptic curve Diffie-Hellman
2. **Encryption**: XChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
3. **Key Derivation**: HKDF-SHA256 with ephemeral-based salt for enhanced security
4. **Forward Secrecy**: Each message uses fresh ephemeral keypairs

### Security Level
- **Overall Security**: 128-bit (limited by X25519)
- **Standards Compliance**: RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF)
- **Quantum Resistance**: None (classical cryptography, will need post-quantum upgrade)
- **Industry Comparison**: Similar to Signal Protocol's crypto primitives, TLS 1.3, WireGuard

## Project Structure

```
cryptic/
├── src/                          # Erlang source code
│   ├── cryptic_server.erl       # HTTP server (Cowboy + gen_server)
│   ├── cryptic_handlers.erl     # HTTP request handlers
│   ├── cryptic_lib.erl          # High-level crypto API
│   ├── cryptic_nif.erl          # NIF interface definitions
│   ├── cryptic_client_lib.erl   # Client library with comprehensive API
│   └── cryptic_client_example.erl # Usage demonstration
├── test/                         # EUnit test suite
│   ├── cryptic_client_lib_test.erl        # Client library tests (18 tests)
│   ├── cryptic_client_lib_test_handler.erl # Test HTTP handlers
│   └── cryptic_e2e_test.erl     # End-to-end integration tests
├── c_src/                        # C NIF implementation
│   ├── cryptic_nif.c            # Libsodium wrapper
│   └── Makefile                 # NIF build configuration
├── docs/                         # Documentation
│   ├── CRYPTIC_PLAN.md          # Original design document
│   └── COPILOT_INSTRUCTIONS.md  # This file
└── README.md                     # Comprehensive project documentation
```

## Key Modules and Their Responsibilities

### Core Modules

**`cryptic_server.erl`** - HTTP Server
- OTP gen_server behavior
- Manages ETS tables for prekeys and message blobs
- Starts Cowboy HTTP server on port 8080
- Routes: `/upload_prekey/:user_id`, `/get_prekey/:user_id`, `/send_blob`, `/recv_blobs/:user_id`

**`cryptic_handlers.erl`** - HTTP Request Handlers
- Cowboy HTTP handlers for REST endpoints
- Handles prekey upload/retrieval and message blob operations
- Uses ETS for data storage (in-memory, non-persistent)

**`cryptic_lib.erl`** - Cryptographic Library
- High-level wrapper around libsodium NIF
- Key functions: `gen_keypair/0`, `scalarmult/2`, `aead_encrypt/3`, `aead_decrypt/4`
- HKDF implementations with different salt strategies
- Three key derivation modes: random, ephemeral-based, simple

**`cryptic_nif.erl`** - NIF Interface
- Erlang interface to C NIF functions
- Bridges Erlang to libsodium cryptographic operations
- Functions map directly to libsodium primitives

**`cryptic_client_lib.erl`** - Client Library (Main Module)
- **780 lines** of comprehensive client API with full EDoc documentation
- **Complete E2E messaging workflow** implementation
- **18 exported functions** covering all use cases
- **Type definitions**: `user_id()`, `server_url()`, `message()`, `encrypted_blob()`

### Client Library API Categories

1. **Client Setup**: `init_client/0`
2. **Prekey Management**: `upload_prekey/3`, `get_prekey/2`
3. **Message Operations**: `encrypt_message/2`, `send_message/6`, `receive_messages/2`, `decrypt_message/2`
4. **High-Level E2E Flows**: `send_encrypted_message/5`, `receive_and_decrypt_messages/3`
5. **Utility Functions**: JSON parsing, formatting, response handling

### Test Suite

**`cryptic_client_lib_test.erl`** - Primary Test Module
- **18 comprehensive EUnit tests** covering all client library functions
- Test categories: initialization, prekey management, message crypto, E2E flows, utilities, error handling, edge cases
- **100% function coverage** of client library
- Includes test HTTP server on port 8082

**`cryptic_e2e_test.erl`** - Integration Tests
- **13 tests** for cryptographic primitives and HTTP API
- Tests NIF functions, HKDF, HTTP endpoints, full E2E message flow

## Message Flow Protocol

### Setup Phase
1. **Bob uploads prekey**: `POST /upload_prekey/bob` with X25519 public key
2. **Server stores**: ETS table maps `bob -> public_key`

### Message Exchange
1. **Alice gets Bob's prekey**: `GET /get_prekey/bob`
2. **Alice encrypts message**:
   - Generate ephemeral X25519 keypair
   - Compute shared secret: `X25519(alice_ephemeral_private, bob_public)`
   - Derive AEAD key: `HKDF-SHA256(shared_secret, SHA256(ephemeral_public), "encryption")`
   - Encrypt: `XChaCha20-Poly1305(message, aead_key)`
3. **Alice sends blob**: `POST /send_blob` with `{from, to, ephemeral, nonce, cipher}`
4. **Bob retrieves messages**: `GET /recv_blobs/bob`
5. **Bob decrypts**:
   - Extract ephemeral public key from blob
   - Compute same shared secret: `X25519(bob_private, alice_ephemeral_public)`
   - Derive same AEAD key using ephemeral public key
   - Decrypt: `XChaCha20-Poly1305_decrypt(cipher, aead_key, nonce)`

## Development Context

### Build and Test Commands
```bash
rebar3 compile              # Build project
rebar3 eunit               # Run all tests (31 tests total)
rebar3 eunit --module=cryptic_client_lib_test  # Run client lib tests only
rebar3 edoc                # Generate EDoc documentation
```

### Server Operations
```erlang
% Start server
cryptic_server:start_link().

% Server runs on http://localhost:8080
% Test server runs on http://localhost:8082 (during tests)
```

### Common Development Patterns

**Error Handling**: All functions return `{ok, Result} | {error, Reason}` tuples
**Unicode Support**: Messages automatically converted between binary/string as needed
**Base64 Encoding**: All binary crypto data base64-encoded for JSON transmission
**ETS Storage**: In-memory tables for prekeys and message blobs (non-persistent)

## AI Assistant Guidelines

### When Working on This Project

1. **Security First**: Always consider cryptographic implications of changes
2. **Test Coverage**: Maintain comprehensive test coverage for all new functions
3. **Documentation**: Add EDoc comments for all public functions
4. **Error Handling**: Follow `{ok, Result} | {error, Reason}` pattern consistently
5. **Type Safety**: Use proper type specs (`-spec`) for all functions

### Key Files to Understand

- **`cryptic_client_lib.erl`**: Main API - start here for most questions
- **`README.md`**: Comprehensive documentation with security analysis
- **`cryptic_lib.erl`**: Core crypto operations
- **Test files**: Excellent examples of API usage

### Common Tasks

**Adding New API Functions**:
1. Add to `cryptic_client_lib.erl` with proper EDoc
2. Add corresponding tests to `cryptic_client_lib_test.erl`
3. Update exports list
4. Follow existing patterns for error handling

**Modifying Crypto**:
1. Changes likely needed in `cryptic_lib.erl` or `cryptic_nif.c`
2. Consider security implications carefully
3. Update security analysis in README if needed

**Server Changes**:
1. Modify handlers in `cryptic_handlers.erl`
2. Update routing in `cryptic_server.erl`
3. Add corresponding tests

### Testing Strategy

- **Unit Tests**: Each function tested individually
- **Integration Tests**: Full E2E message flows
- **Error Cases**: Malformed input, network failures, crypto failures
- **Edge Cases**: Unicode, empty data, large messages
- **HTTP Tests**: Actual HTTP server testing with dedicated handlers

### Current Status

✅ **Production Ready Features**:
- Complete client library with 18 functions
- Comprehensive test suite (31 tests passing)
- Full EDoc documentation
- Robust error handling
- Unicode support

🔄 **Possible Enhancements**:
- Message persistence (currently in-memory ETS)
- Key rotation mechanisms
- Post-quantum cryptography
- WebSocket support for real-time messaging
- Multi-device support per user

### Security Considerations for AI Assistants

1. **Never log or expose private keys** in debug output
2. **Validate all inputs** especially in crypto functions
3. **Consider timing attacks** when adding crypto operations
4. **Use constant-time comparisons** for sensitive data
5. **Clear sensitive memory** when possible
6. **Follow libsodium best practices** for the NIF layer

This instruction file should give any AI assistant a comprehensive understanding of the Cryptic project structure, security model, and development practices for effective assistance.
