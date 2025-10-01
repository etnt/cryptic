# Cryptic Double Ratchet Console Interface

This directory contains a simple console-based interface for testing the Double Ratchet state engine. The interface is designed to be easily testable with Lux and provides a command-line way to interact with the protocol.

## Architecture

### Core Components

1. **cryptic_ratchet_engine.erl** - The main reusable state engine with callback support
2. **cryptic_console_simple.erl** - Simple console interface implementing the callback behavior  
3. **cryptic_console_ui_callback.erl** - Rich console UI with colors and detailed logging

### Callback System

The engine uses a callback behavior pattern:
```erlang
-callback handle_state_change(EngineRef, FromState, ToState, Context) -> ok | {error, term()}.
-callback handle_message_event(EngineRef, Event, Data, Context) -> ok | {error, term()}.
-callback handle_error(EngineRef, ErrorType, Error, Context) -> ok | {error, term()}.
-callback handle_debug_event(EngineRef, Event, Data, Context) -> ok | {error, term()}.
-callback handle_lifecycle_event(EngineRef, Event, Context) -> ok | {error, term()}.
```

This allows different UI implementations (console, ncurses, web, embedded) to reuse the same core engine.

## Usage

### Interactive Console

```bash
# Start interactive console
cd /Users/ttornkvi/git/cryptic
erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start

# Or use the escript
./scripts/cryptic_console
```

### Commands

```
generate_root_key                    - Generate a random root key
generate_keys                        - Generate DH keypair  
start_alice <root_key> <pub> <priv>  - Initialize as Alice (sender)
start_bob <root_key> <pub> <priv>    - Initialize as Bob (receiver)
encrypt <message>                    - Encrypt a message
decrypt <encrypted_hex>              - Decrypt a message
status                               - Show engine status
debug                                - Show debug information
verbose                              - Toggle verbose logging
help                                 - Show help
quit                                 - Exit
```

### Example Session

```
cryptic> generate_root_key
ROOT_KEY: a1b2c3d4e5f6...

cryptic> generate_keys
PUBLIC_KEY: 1a2b3c4d...
PRIVATE_KEY: 9f8e7d6c...

cryptic> start_alice a1b2c3d4e5f6... 1a2b3c4d... 9f8e7d6c...
SUCCESS: Alice initialized

cryptic> encrypt Hello World!
SUCCESS: 4a5b6c7d8e9f...

cryptic> status
ENGINE: Running (<0.123.0>)
ROLE: alice
STATE: sending_active
MESSAGES: 1
ERRORS: 0
```

## Testing

### Manual Demo

```bash
./scripts/demo_console.sh
```

This script demonstrates a complete Alice->Bob message flow.

### LUX Tests

The `test/lux/` directory contains automated LUX tests:

- `console_basic_flow.lux` - Complete Alice->Bob bidirectional message flow
- `console_error_handling.lux` - Error condition testing

Run LUX tests:
```bash
lux test/lux/console_basic_flow.lux
lux test/lux/console_error_handling.lux
```

### Test Features Covered

1. **State Transitions**: uninitialized → sender_init → sending_active → bidirectional
2. **Error Handling**: Invalid inputs, uninitialized operations, malformed data
3. **Message Flow**: Encryption, decryption, multiple messages
4. **Debugging**: Status info, debug output, verbose logging
5. **Key Management**: Generation, validation, format conversion

## Benefits for Different Contexts

### Console Context (Current)
- Simple command-line interface
- Perfect for automated testing
- Easy integration with shell scripts
- Minimal dependencies

### Future Contexts

**NCurses UI Context:**
- Real-time status display
- Interactive key management
- Visual state transitions
- Message history view

**Web UI Context:**
- Browser-based interface
- WebSocket real-time updates
- File upload/download for keys
- Multi-session management

**Embedded Context:**
- Minimal resource usage
- Event-driven notifications
- Serial/UART interface
- Hardware integration

## Implementation Notes

### Callback Design Patterns

1. **Non-blocking Callbacks**: Callbacks never block the engine
2. **Error Isolation**: Callback failures don't crash the engine  
3. **Context Passing**: Rich context information for UI decisions
4. **Event Subscription**: Selective event listening for efficiency

### State Engine Features

1. **Explicit State Management**: Clear state transitions with history
2. **Error Recovery**: Graceful error handling and recovery
3. **Debug Support**: Comprehensive debugging and monitoring
4. **Event Tracking**: Full audit trail of operations
5. **Performance Metrics**: Built-in timing and statistics

### Testing Strategy

1. **Unit Tests**: EUnit tests for state engine logic
2. **Integration Tests**: LUX tests for end-to-end scenarios  
3. **Error Tests**: Comprehensive error condition coverage
4. **Performance Tests**: Load and timing validation
5. **Manual Tests**: Interactive demo and validation scripts

This architecture provides a solid foundation for building different types of user interfaces while maintaining the integrity and testability of the core Double Ratchet protocol implementation.