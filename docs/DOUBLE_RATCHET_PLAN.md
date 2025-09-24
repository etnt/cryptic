# Double Ratchet Implementation Plan

## Overview

This document outlines the plan to implement the **Double Ratchet algorithm**
in the Cryptic messaging system to replace the current inefficient approach of
using a new OTPK (One-Time Prekey) for every message.

The Double Ratchet provides **forward secrecy** and **break-in recovery**
while being highly efficient for ongoing message exchanges between two parties.

## Current Problem

**Inefficient OTPK Usage:**
- Currently generating/using new OTPK for every message
- Requires continuous prekey generation and distribution
- High computational and bandwidth overhead
- Not scalable for high-frequency messaging

## Double Ratchet Benefits

1. **Forward Secrecy**: Past messages remain secure even if current keys
   are compromised
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

**Asymmetric Ratchet** (per-response) a.k.a DH-ratchet:
- Uses ECDH with new ephemeral keys
- Mixes new entropy into the system
- Provides break-in recovery

DH-ratchet put another way:

1. Start:
   Both parties already have an initial shared secret from X3DH (or some initial DH).
   Each has an initial DH key pair.

2. When you receive a message from your partner:
   Before sending your next message, you:
   * generate a fresh DH key pair (ephemeral),
   * compute a new shared secret with your partner’s latest DH public key,
   * feed that into HKDF to create a new root key and new sending/receiving chain keys.

3. You then keep using that same DH key pair for all your outgoing messages
   until you next receive a message from the peer. When that happens, you
   repeat the process—create a new DH key pair, etc.

So each turn-taking event triggers a new DH key pair.

### Two separate chains

Each party keeps **two independent hash chains** of keys:

  * **Sending chain**: Derives one-time keys for messages you send.
  * **Receiving chain**: Derives one-time keys for messages you receive.

Only the receiving chain is affected if messages get lost.

### The “skipped message key” store

To avoid losing the ability to decrypt late messages, the receiver:

 1. Derives the intermediate message keys (#7, #8) in order as soon as it notices a gap.
 2. Stores those keys (encrypted in memory) in a “skipped-message-key” cache.
 3. When the missing messages eventually show up, it looks up their key in the cache and decrypts.

These saved keys are discarded as soon as they are used, or if they get too old.

---

## Implementation Phases

### Phase 1: Core Ratchet State Management

#### 1.1 Ratchet State Structure
```erlang
-record(ratchet_state, {
    % Root chain (shared between both parties)
    root_key :: binary(),           % Current root key (32 bytes)
    
    % Sending chain (independent per party)
    send_chain_key :: binary(),     % Current sending chain key (32 bytes)
    send_msg_number :: non_neg_integer(), % Message number in current sending chain
    
    % Receiving chain (independent per party)
    recv_chain_key :: binary(),     % Current receiving chain key (32 bytes) 
    recv_msg_number :: non_neg_integer(), % Expected next message number in receiving chain
    prev_recv_chain_length :: non_neg_integer(), % Messages in previous receiving chain
    
    % ECDH ratchet keys (for DH-ratchet steps)
    dh_self :: {binary(), binary()}, % Own ECDH keypair (pub, priv)
    dh_remote :: binary(),           % Remote ECDH public key
    dh_ratchet_step :: non_neg_integer(), % Current DH ratchet step number
    
    % Skipped message key store (for out-of-order delivery)
    skipped_keys :: #{
        {dh_step, msg_num} => #{
            message_key => binary(),     % The derived message key
            timestamp => integer(),      % When key was derived (for cleanup)
            chain_key => binary()       % Chain key that derived this (for verification)
        }
    },
    
    % Configuration and limits
    max_skip :: pos_integer(),       % Maximum messages to skip in sequence
    max_cache_size :: pos_integer(), % Maximum skipped keys to cache  
    max_cache_age :: pos_integer(),  % Maximum age (ms) for cached keys
    
    % Chain state tracking
    sending_chain_active :: boolean(),   % True if we can send messages
    receiving_chain_active :: boolean()  % True if we can receive messages
}).
```

#### 1.2 State Management Module
Create `src/cryptic_double_ratchet.erl` with functions:
- `init_sender/2` - Initialize Alice's ratchet state (sender)
- `init_receiver/3` - Initialize Bob's ratchet state (receiver)  
- `encrypt_message/2` - Encrypt outgoing message
- `decrypt_message/3` - Decrypt incoming message
- `serialize_state/1` - Serialize state for persistence
- `deserialize_state/1` - Deserialize state from storage

### Phase 2: Key Derivation Integration

#### 2.1 Leverage Existing High-Performance HKDF NIFs
Utilize the recently implemented native HKDF functions with optimal performance strategy:

**Primary KDF (Recommended):**
- `cryptic_nif:kdf_derive/4` - Blake2b-based KDF (39x faster than Erlang, 6.8x faster than native HKDF-SHA256)
  - Use for all chain key advancement and message key derivation
  - Optimal for high-frequency Double Ratchet operations
  - Provides excellent security with superior performance

**Compatibility KDF (When Required):**
- `cryptic_nif:hkdf_sha256/4` - RFC 5869 HKDF-SHA256 (5.7x faster than Erlang)
  - Use only when strict X3DH specification compliance is required
  - Interoperability with systems expecting standard HKDF-SHA256

#### 2.2 Separate Chain Management
Implement independent key derivation for the two separate chains:

**Sending Chain Operations:**
```erlang
% Advance sending chain key and derive message key for outgoing message
advance_sending_chain(SendChainKey, MsgNumber) ->
    MessageKey = cryptic_nif:kdf_derive(32, MsgNumber, <<"msg_send">>, SendChainKey),
    NewChainKey = cryptic_nif:kdf_derive(32, MsgNumber + 1, <<"chain_send">>, SendChainKey),
    {NewChainKey, MessageKey}.
```

**Receiving Chain Operations:**
```erlang
% Advance receiving chain key and derive message key for incoming message
advance_receiving_chain(RecvChainKey, MsgNumber) ->
    MessageKey = cryptic_nif:kdf_derive(32, MsgNumber, <<"msg_recv">>, RecvChainKey),
    NewChainKey = cryptic_nif:kdf_derive(32, MsgNumber + 1, <<"chain_recv">>, RecvChainKey),
    {NewChainKey, MessageKey}.

% Derive skipped message keys when messages arrive out of order
derive_skipped_keys(ChainKey, StartMsgNum, EndMsgNum) ->
    lists:foldl(fun(MsgNum, Acc) ->
        SkippedKey = cryptic_nif:kdf_derive(32, MsgNum, <<"msg_recv">>, ChainKey),
        TempChainKey = cryptic_nif:kdf_derive(32, MsgNum + 1, <<"chain_recv">>, ChainKey),
        maps:put({current_dh_step(), MsgNum}, #{
            message_key => SkippedKey,
            timestamp => erlang:system_time(millisecond),
            chain_key => TempChainKey
        }, Acc)
    end, #{}, lists:seq(StartMsgNum, EndMsgNum - 1)).
```

#### 2.3 Root Chain and DH-Ratchet Key Derivation
```erlang
% Root key progression with new DH output (when DH-ratchet advances)
kdf_rk(RootKey, DhOutput) -> 
    % Use high-performance Blake2b KDF directly (39x faster than Erlang)
    % The KDF handles input mixing internally - no need for pre-hashing
    % Use DhOutput as master key and RootKey as context for domain separation
    
    NewRootKey = cryptic_nif:kdf_derive(32, 0, RootKey, DhOutput),
    SendChainKey = cryptic_nif:kdf_derive(32, 1, RootKey, DhOutput),
    RecvChainKey = cryptic_nif:kdf_derive(32, 2, RootKey, DhOutput),
    {NewRootKey, SendChainKey, RecvChainKey}.

% Alternative: Use HKDF-SHA256 only when X3DH compatibility is explicitly required
kdf_rk_x3dh_compat(RootKey, DhOutput) -> 
    % Use HKDF-SHA256 for strict X3DH specification compliance
    NewRootKey = cryptic_nif:hkdf_sha256(DhOutput, RootKey, <<"root_key">>, 32),
    SendChainKey = cryptic_nif:hkdf_sha256(DhOutput, RootKey, <<"send_chain">>, 32),
    RecvChainKey = cryptic_nif:hkdf_sha256(DhOutput, RootKey, <<"recv_chain">>, 32),
    {NewRootKey, SendChainKey, RecvChainKey}.

% Performance Note: The kdf_derive approach avoids crypto:hash/2 calls entirely:
% - No Erlang crypto module dependency for basic operations
% - Single native function call instead of hash + multiple KDF calls  
% - Blake2b handles input mixing more efficiently than SHA256 + Blake2b
% - Reduces function call overhead in high-frequency ratchet operations

dh_ratchet_step(State, ReceivedDhKey) ->
    % Generate new DH key pair
    {NewPublicKey, NewPrivateKey} = cryptic_nif:keypair(),
    
    % Compute DH output
    DhOutput = cryptic_nif:scalarmult(NewPrivateKey, ReceivedDhKey),
    
    % Root key expansion using high-performance Blake2b KDF (39x faster)  
    % Use the existing kdf_rk function for consistent key derivation
    {NewRootKey, SendChainKey, RecvChainKey} = kdf_rk(
        State#ratchet_state.root_key, DhOutput),
    
    State#{
        root_key => NewRootKey,
        send_chain => #{key => SendChainKey, n => 0},
        recv_chain => #{key => RecvChainKey, n => 0},
        dh_key => {NewPublicKey, NewPrivateKey},
        pn => maps:get(n, State#{send_chain}, 0)
    }.

% Message key expansion for encryption/decryption (high-performance path)
kdf_mk(MessageKey) -> 
    EncKey = cryptic_nif:kdf_derive(32, 0, <<"enc">>, MessageKey),
    AuthKey = cryptic_nif:kdf_derive(32, 1, <<"auth">>, MessageKey), 
    IV = cryptic_nif:kdf_derive(12, 2, <<"iv">>, MessageKey),
    {EncKey, AuthKey, IV}.
```

### Phase 3: Message Processing with Separate Chains

#### 3.1 Sending Messages (Using Sending Chain)
```erlang
encrypt_message(PlainText, State) ->
    % 1. Use the independent sending chain for outgoing messages
    CurrentSendingChain = State#ratchet_state.send_chain_key,
    CurrentMsgNum = State#ratchet_state.send_msg_number,
    
    % 2. Derive message key from sending chain (does NOT affect receiving chain)
    {NewSendChainKey, MessageKey} = advance_sending_chain(CurrentSendingChain, CurrentMsgNum),
    
    % 3. Derive encryption components from message key
    {EncKey, AuthKey, IV} = kdf_mk(MessageKey),
    
    % 4. Encrypt message with ChaCha20-Poly1305
    {CipherText, Nonce} = cryptic_nif:aead_encrypt(PlainText, EncKey, <<>>),
    
    % 5. Create message with Double Ratchet header
    Message = #{
        % DH ratchet information
        dh_public => element(1, State#ratchet_state.dh_self),
        dh_step => State#ratchet_state.dh_ratchet_step,
        
        % Sending chain information  
        prev_chain_length => State#ratchet_state.prev_recv_chain_length,
        msg_number => CurrentMsgNum,
        
        % Encrypted payload
        ciphertext => CipherText,
        nonce => Nonce
    },
    
    % 6. Update ONLY sending chain state (receiving chain unchanged)
    NewState = State#ratchet_state{
        send_chain_key = NewSendChainKey,
        send_msg_number = CurrentMsgNum + 1,
        % Note: receiving chain and DH keys stay the same
        sending_chain_active = true
    },
    
    % 7. Clear the used message key from memory
    sodium_memzero(MessageKey),
    
    {Message, NewState}.
```

#### 3.2 Receiving Messages (Using Receiving Chain + Gap Handling)
```erlang
decrypt_message(Message, State) ->
    IncomingDHPub = Message.dh_public,
    IncomingDHStep = Message.dh_step,
    IncomingMsgNum = Message.msg_number,
    
    % 1. Determine if DH-ratchet step is needed
    DHRatchetNeeded = (IncomingDHPub =/= State#ratchet_state.dh_remote),
    
    % 2. Handle DH ratchet if needed
    StateAfterDH = case DHRatchetNeeded of
        true ->
            % Perform DH ratchet step - creates new receiving chain
            perform_dh_ratchet_step(Message, State);
        false ->
            % Same DH step - continue with current receiving chain
            State
    end,
    
    % 3. Check for message gaps in the receiving chain
    case handle_message_gap(StateAfterDH, IncomingMsgNum, IncomingDHStep) of
        {ok, StateAfterGap} ->
            % 4. Decrypt the message (either current or from skipped store)
            decrypt_with_receiving_chain(Message, StateAfterGap);
        
        {error, Reason} ->
            {error, Reason}
    end.

decrypt_with_receiving_chain(Message, State) ->
    MsgNum = Message.msg_number,
    ExpectedMsgNum = State#ratchet_state.recv_msg_number,
    
    case MsgNum of
        ExpectedMsgNum ->
            % Current message - use receiving chain directly
            {NewRecvChainKey, MessageKey} = advance_receiving_chain(
                State#ratchet_state.recv_chain_key, MsgNum),
            
            case decrypt_with_key(Message.ciphertext, MessageKey, Message.nonce) of
                {ok, Plaintext} ->
                    % Update receiving chain state
                    NewState = State#ratchet_state{
                        recv_chain_key = NewRecvChainKey,
                        recv_msg_number = ExpectedMsgNum + 1,
                        receiving_chain_active = true
                    },
                    
                    % Clear message key from memory
                    sodium_memzero(MessageKey),
                    {ok, Plaintext, NewState};
                
                {error, Reason} ->
                    {error, {decrypt_failed, Reason}}
            end;
        
        _ when MsgNum < ExpectedMsgNum ->
            % Delayed message - look up from skipped message key store
            process_delayed_message(Message, State);
        
        _ ->
            % Future message - should have been handled by gap processing
            {error, {unexpected_future_message, MsgNum, ExpectedMsgNum}}
    end.
```

#### 3.3 DH-Ratchet Step Implementation
```erlang
perform_dh_ratchet_step(Message, State) ->
    % 1. Extract new remote DH public key
    NewRemoteDHPub = Message.dh_public,
    {OwnDHPub, OwnDHPriv} = State#ratchet_state.dh_self,
    
    % 2. Compute new DH shared secret
    DHOutput = cryptic_nif:scalarmult(OwnDHPriv, NewRemoteDHPub),
    
    % 3. Derive new root key and receiving chain key (using high-performance KDF)
    {NewRootKey, _NewSendChainKey, NewRecvChainKey} = kdf_rk(
        State#ratchet_state.root_key, DHOutput),
    
    % 4. Generate new DH keypair for future sending
    {NewOwnDHPub, NewOwnDHPriv} = cryptic_nif:gen_keypair(),
    
    % 5. Update state with new DH step and receiving chain
    NewState = State#ratchet_state{
        root_key = NewRootKey,
        dh_self = {NewOwnDHPub, NewOwnDHPriv},
        dh_remote = NewRemoteDHPub, 
        dh_ratchet_step = State#ratchet_state.dh_ratchet_step + 1,
        
        % Reset receiving chain for new DH step
        recv_chain_key = NewRecvChainKey,
        recv_msg_number = 0,
        prev_recv_chain_length = Message.prev_chain_length,
        
        % Sending chain remains active until we send next message
        receiving_chain_active = true
    },
    
    % 6. Clear old DH private key from memory
    sodium_memzero(OwnDHPriv),
    
    NewState.
```

### Phase 4: Out-of-Order Message Handling & Skipped Message Key Store

#### 4.1 Skipped Message Key Store Implementation

The skipped message key store is crucial for handling messages that arrive out of order while maintaining the security properties of forward secrecy.

**Core Principle:**
When message #10 arrives but messages #7, #8, #9 are missing, we must:
1. **Immediately derive** the keys for #7, #8, #9 from the current receiving chain
2. **Store these keys** in encrypted memory for later use  
3. **Advance** the receiving chain to handle message #10
4. **Use stored keys** when #7, #8, #9 eventually arrive
5. **Delete keys** immediately after use for forward secrecy

**Storage Structure:**
```erlang
% Key: {DH_step, MessageNumber} -> Value: Key info
-type skipped_key_id() :: {non_neg_integer(), non_neg_integer()}.
-type skipped_key_info() :: #{
    message_key => binary(),        % The actual message decryption key
    timestamp => integer(),         % When this key was derived (for cleanup)
    chain_key => binary(),          % Chain key state for verification
    dh_public => binary()           % DH public key active when derived
}.

-type skipped_key_store() :: #{skipped_key_id() => skipped_key_info()}.
```

#### 4.2 Gap Detection and Key Pre-derivation
```erlang
handle_message_gap(State, IncomingMsgNum, CurrentDHStep) ->
    ExpectedMsgNum = State#ratchet_state.recv_msg_number,
    
    case IncomingMsgNum > ExpectedMsgNum of
        true ->
            % Gap detected - pre-derive keys for missing messages
            GapSize = IncomingMsgNum - ExpectedMsgNum,
            
            % Security check: prevent DoS by limiting gap size
            case GapSize =< State#ratchet_state.max_skip of
                true ->
                    derive_and_store_skipped_keys(State, ExpectedMsgNum, 
                                                  IncomingMsgNum, CurrentDHStep);
                false ->
                    {error, {gap_too_large, GapSize, State#ratchet_state.max_skip}}
            end;
        false ->
            % No gap or duplicate message
            {ok, State}
    end.

derive_and_store_skipped_keys(State, StartNum, EndNum, DHStep) ->
    ChainKey = State#ratchet_state.recv_chain_key,
    DhPublic = State#ratchet_state.dh_remote,
    CurrentTime = erlang:system_time(millisecond),
    
    % Derive keys for each missing message
    {FinalChainKey, NewSkippedKeys} = lists:foldl(
        fun(MsgNum, {TempChainKey, SkippedAcc}) ->
            % Derive message key for this number
            MsgKey = cryptic_nif:kdf_derive(32, MsgNum, <<"msg_recv">>, TempChainKey),
            
            % Advance chain key for next iteration  
            NextChainKey = cryptic_nif:kdf_derive(32, MsgNum + 1, <<"chain_recv">>, TempChainKey),
            
            % Store the skipped key info
            KeyId = {DHStep, MsgNum},
            KeyInfo = #{
                message_key => MsgKey,
                timestamp => CurrentTime, 
                chain_key => TempChainKey,
                dh_public => DhPublic
            },
            
            {NextChainKey, maps:put(KeyId, KeyInfo, SkippedAcc)}
        end,
        {ChainKey, State#ratchet_state.skipped_keys},
        lists:seq(StartNum, EndNum - 1)
    ),
    
    % Update state with new chain key and skipped keys
    NewState = State#ratchet_state{
        recv_chain_key = FinalChainKey,
        skipped_keys = NewSkippedKeys
    },
    
    {ok, NewState}.
```

#### 4.3 Delayed Message Processing
```erlang
process_delayed_message(Message, State) ->
    MsgNum = Message.msg_number,
    DHStep = Message.dh_step,
    KeyId = {DHStep, MsgNum},
    
    case maps:get(KeyId, State#ratchet_state.skipped_keys, undefined) of
        undefined ->
            {error, {no_skipped_key, KeyId}};
        
        KeyInfo ->
            % Found the pre-derived key - use it for decryption
            MessageKey = maps:get(message_key, KeyInfo),
            
            % Decrypt the message
            case decrypt_with_key(Message.ciphertext, MessageKey, Message.nonce) of
                {ok, Plaintext} ->
                    % SUCCESS: Remove the used key (forward secrecy)
                    CleanedSkippedKeys = maps:remove(KeyId, State#ratchet_state.skipped_keys),
                    NewState = State#ratchet_state{skipped_keys = CleanedSkippedKeys},
                    
                    {ok, Plaintext, NewState};
                
                {error, Reason} ->
                    {error, {decrypt_failed, Reason}}
            end
    end.
```

#### 4.4 Cache Management and DoS Prevention
```erlang
% Periodic cleanup of old skipped keys
cleanup_expired_skipped_keys(State) ->
    CurrentTime = erlang:system_time(millisecond),
    MaxAge = State#ratchet_state.max_cache_age,
    
    CleanedKeys = maps:filter(
        fun(_KeyId, KeyInfo) ->
            Age = CurrentTime - maps:get(timestamp, KeyInfo),
            Age =< MaxAge
        end,
        State#ratchet_state.skipped_keys
    ),
    
    State#ratchet_state{skipped_keys = CleanedKeys}.

% Enforce cache size limits
enforce_cache_limits(State) ->
    SkippedKeys = State#ratchet_state.skipped_keys,
    MaxSize = State#ratchet_state.max_cache_size,
    
    case maps:size(SkippedKeys) > MaxSize of
        true ->
            % Remove oldest keys to stay within limit
            SortedKeys = lists:sort(fun({_K1, V1}, {_K2, V2}) ->
                maps:get(timestamp, V1) =< maps:get(timestamp, V2)
            end, maps:to_list(SkippedKeys)),
            
            % Keep only the newest MaxSize keys
            {_OldKeys, KeptKeys} = lists:split(
                maps:size(SkippedKeys) - MaxSize, 
                SortedKeys
            ),
            
            State#ratchet_state{skipped_keys = maps:from_list(KeptKeys)};
        
        false ->
            State
    end.
```

#### 4.5 Security Considerations for Skipped Keys

**Forward Secrecy Protection:**
- Keys are deleted immediately after successful use
- Failed decryption attempts also remove keys (prevent retry attacks)
- Periodic cleanup removes stale keys

**DoS Attack Prevention:**
- `max_skip`: Limits gap size to prevent excessive key derivation
- `max_cache_size`: Bounds memory usage for skipped keys  
- `max_cache_age`: Prevents indefinite key accumulation
- Rate limiting on gap processing per sender

**Memory Security:**
- Use `sodium_memzero()` when deleting sensitive key material
- Store skipped keys in protected memory regions if available
- Consider encrypting skipped key store with a separate key

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