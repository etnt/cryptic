# Double Ratchet Implementation Plan

## Overview

This document outlines the plan to implement the **Double Ratchet algorithm** in the Cryptic messaging system to replace the current inefficient approach of using a new OTPK (One-Time Prekey) for every message.

The Double Ratchet provides **forward secrecy** and **break-in recovery** while being highly efficient for ongoing message exchanges between two parties.

## Current Problem

**Inefficient OTPK Usage:**
- Currently generating/using new OTPK for every message
- Requires continuous prekey generation and distribution
- High computational and bandwidth overhead
- Not scalable for high-frequency messaging

## Double Ratchet Benefits

1. **Forward Secrecy**: Past messages remain secure even if current keys are compromised
2. **Break-in Recovery**: Security is restored after key material compromise
3. **Efficiency**: No need for new prekeys after initial key agreement
4. **Asynchronous**: Works with offline/online messaging patterns
5. **Proven Security**: Used in Signal, WhatsApp, and other secure messengers

---

## Architecture Overview

### Key Components

1. **Root Key (RK)**: Master secret derived from X3DH initial key agreement
2. **Chain Keys (CK)**: Evolving keys for each direction of communication
3. **Message Keys (MK)**: Individual keys for encrypting/decrypting messages
4. **Ratchet Keys**: Ephemeral ECDH keypairs that advance the ratchet

### Ratchet Types

**Symmetric Ratchet** (per-message):
- Derives message keys from chain keys
- Advances chain key after each message
- Provides forward secrecy for message encryption

**Asymmetric Ratchet** (per-response):
- Uses ECDH with new ephemeral keys
- Mixes new entropy into the system
- Provides break-in recovery

---

## Implementation Phases

### Phase 1: Core Ratchet State Management

#### 1.1 Ratchet State Structure
```erlang
-record(ratchet_state, {
    % Root chain
    root_key :: binary(),           % Current root key (32 bytes)
    
    % Sending chain  
    send_chain_key :: binary(),     % Current sending chain key (32 bytes)
    send_msg_number :: non_neg_integer(), % Message number in current sending chain
    
    % Receiving chain
    recv_chain_key :: binary(),     % Current receiving chain key (32 bytes) 
    recv_msg_number :: non_neg_integer(), % Message number in current receiving chain
    
    % ECDH ratchet keys
    dh_self :: {binary(), binary()}, % Own ECDH keypair (pub, priv)
    dh_remote :: binary(),           % Remote ECDH public key
    
    % Skipped message keys (for out-of-order delivery)
    skipped_keys :: #{integer() => binary()}, % MsgNum -> MessageKey
    
    % Configuration
    max_skip :: pos_integer(),       % Maximum messages to skip
    max_cache :: pos_integer()       % Maximum skipped keys to cache
}).
```

#### 1.2 State Management Module
Create `src/cryptic_double_ratchet.erl` with functions:
- `init_alice/2` - Initialize Alice's ratchet state (sender)
- `init_bob/3` - Initialize Bob's ratchet state (receiver)  
- `encrypt_message/2` - Encrypt outgoing message
- `decrypt_message/3` - Decrypt incoming message
- `serialize_state/1` - Serialize state for persistence
- `deserialize_state/1` - Deserialize state from storage

### Phase 2: Key Derivation Integration

#### 2.1 Leverage Existing HKDF NIFs
Utilize the recently implemented native HKDF functions:
- `cryptic_nif:kdf_derive/4` - For high-performance chain key advancement
- `cryptic_nif:hkdf_sha256/4` - For root key expansion (X3DH compatibility)

#### 2.2 Key Derivation Functions
```erlang
% Root key progression with new DH output
kdf_rk(root_key, dh_output) -> {new_root_key, chain_key}

% Chain key advancement 
kdf_ck(chain_key) -> {new_chain_key, message_key}

% Message key derivation
kdf_mk(message_key) -> {encrypt_key, auth_key, iv}
```

### Phase 3: Message Processing

#### 3.1 Sending Messages
```erlang
encrypt_message(PlainText, State) ->
    % 1. Derive message key from current sending chain key
    {NewSendChainKey, MessageKey} = kdf_ck(State#ratchet_state.send_chain_key),
    
    % 2. Derive encryption keys from message key
    {EncKey, AuthKey, IV} = kdf_mk(MessageKey),
    
    % 3. Encrypt message with ChaCha20-Poly1305
    {CipherText, Nonce} = cryptic_nif:aead_encrypt(PlainText, EncKey, <<>>),
    
    % 4. Create message with header
    Message = #{
        dh_public => element(1, State#ratchet_state.dh_self),
        prev_chain_length => State#ratchet_state.send_msg_number,
        msg_number => State#ratchet_state.send_msg_number + 1,
        ciphertext => CipherText,
        nonce => Nonce
    },
    
    % 5. Update state
    NewState = State#ratchet_state{
        send_chain_key = NewSendChainKey,
        send_msg_number = State#ratchet_state.send_msg_number + 1
    },
    
    {Message, NewState}.
```

#### 3.2 Receiving Messages
```erlang
decrypt_message(Message, State) ->
    % 1. Check if DH ratchet step is needed
    case Message.dh_public =:= State#ratchet_state.dh_remote of
        true ->
            % Same DH key - just advance symmetric ratchet
            decrypt_with_current_chain(Message, State);
        false ->
            % New DH key - perform DH ratchet step then decrypt
            {NewState, _} = dh_ratchet_step(Message, State),
            decrypt_with_current_chain(Message, NewState)
    end.
```

### Phase 4: Out-of-Order Message Handling

#### 4.1 Skipped Message Keys
Handle messages arriving out of order by:
- Caching derived message keys for skipped message numbers
- Limiting cache size to prevent DoS attacks
- Efficiently looking up keys for delayed messages

#### 4.2 Message Gap Handling
```erlang
handle_message_gap(ExpectedMsgNum, ActualMsgNum, ChainKey) ->
    % Derive and cache keys for skipped messages
    SkippedKeys = derive_skipped_keys(ChainKey, ExpectedMsgNum, ActualMsgNum),
    % Advance chain key to current message
    FinalChainKey = advance_chain_key(ChainKey, ActualMsgNum - ExpectedMsgNum),
    {FinalChainKey, SkippedKeys}.
```

### Phase 5: Integration with Existing System

#### 5.1 WebSocket Handler Integration
Modify `cryptic_ws_handler.erl`:
- Replace OTPK generation with ratchet state management
- Initialize ratchet after X3DH key agreement
- Route messages through ratchet encrypt/decrypt

#### 5.2 Storage Integration  
Update `cryptic_chat_storage.erl`:
- Store ratchet states per conversation
- Persist state after each message
- Handle state recovery and migration

#### 5.3 Client UI Updates
Update `cryptic_ws_ui.erl`:
- Remove OTPK management commands
- Add ratchet state inspection commands (for debugging)
- Maintain transparent user experience

---

## Security Considerations

### Key Management
- **Secure Deletion**: Zero out old keys after use
- **State Persistence**: Encrypt ratchet state when storing
- **Key Rotation**: Automatic DH ratchet on each response

### Attack Resistance
- **Replay Protection**: Message numbers prevent replay attacks
- **Out-of-Order Limits**: Bounded skipped message cache
- **Break-in Recovery**: New DH keys restore security

### Implementation Security
- **Constant-Time Ops**: Use native NIFs for timing attack resistance  
- **Memory Safety**: Proper cleanup of sensitive data
- **Input Validation**: Robust parsing of message headers

---

## Performance Optimizations

### Native Operations
Leverage existing high-performance NIFs:
- Blake2b KDF for chain key advancement (39x faster than Erlang)
- ChaCha20-Poly1305 for message encryption/decryption
- X25519 for ECDH operations

### State Management
- **Lazy Loading**: Only load ratchet state when needed
- **Batched Updates**: Batch state persistence for high-throughput scenarios
- **Memory Pools**: Reuse key derivation buffers

### Message Processing
- **Pipeline Processing**: Overlap encryption with network I/O
- **Async Operations**: Non-blocking message processing
- **Key Caching**: Cache frequently used derived keys

---

## Testing Strategy

### Unit Tests
- **Key Derivation**: Test all KDF functions with known vectors
- **Ratchet Logic**: Test symmetric and asymmetric ratchet advancement
- **Message Processing**: Test encrypt/decrypt with various scenarios

### Integration Tests
- **End-to-End**: Full Alice-Bob message exchange scenarios
- **Out-of-Order**: Messages arriving in different orders
- **Performance**: Throughput and latency under load

### Security Tests  
- **Forward Secrecy**: Verify past messages stay secure
- **Break-in Recovery**: Test recovery after key compromise
- **Attack Vectors**: DoS, replay, and timing attack resistance

---

## Migration Strategy

### Backward Compatibility
1. **Version Negotiation**: Support both OTPK and Double Ratchet modes
2. **Graceful Upgrade**: Migrate conversations to ratchet after X3DH
3. **Fallback Support**: OTPK mode for legacy clients

### Deployment Plan
1. **Phase 1**: Deploy ratchet code without activation
2. **Phase 2**: Enable ratchet for new conversations  
3. **Phase 3**: Migrate existing conversations
4. **Phase 4**: Remove OTPK code after migration complete

---

## Success Criteria

### Functional Requirements
- ✅ Replace OTPK-per-message with efficient ratchet
- ✅ Maintain forward secrecy and break-in recovery
- ✅ Support asynchronous and out-of-order messaging
- ✅ Transparent user experience (no UI changes needed)

### Performance Requirements  
- ✅ >10,000 messages/second throughput per conversation
- ✅ <1ms message encryption/decryption latency
- ✅ <1MB memory per conversation state
- ✅ Minimal state storage overhead

### Security Requirements
- ✅ Forward secrecy for all messages
- ✅ Break-in recovery within one round-trip  
- ✅ Resistance to replay and DoS attacks
- ✅ Secure key deletion and state management

---

## Timeline Estimate

| Phase | Duration | Description |
|-------|----------|-------------|
| **Phase 1** | 1 week | Core ratchet state management |
| **Phase 2** | 3 days | Key derivation integration |  
| **Phase 3** | 1 week | Message encrypt/decrypt |
| **Phase 4** | 4 days | Out-of-order handling |
| **Phase 5** | 1 week | System integration |
| **Testing** | 1 week | Comprehensive testing |
| **Migration** | 3 days | Deployment and migration |

**Total: ~4-5 weeks**

---

## References

- [Double Ratchet Algorithm Specification](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [RFC 5869: HKDF](https://tools.ietf.org/rfc/rfc5869.txt)
- [ChaCha20-Poly1305 AEAD](https://tools.ietf.org/rfc/rfc8439.txt)

---

## Implementation Notes

This plan leverages the recently implemented native HKDF functions to ensure optimal performance for the high-frequency key derivation operations required by the Double Ratchet algorithm. The modular design allows for incremental implementation and testing while maintaining backward compatibility during migration.