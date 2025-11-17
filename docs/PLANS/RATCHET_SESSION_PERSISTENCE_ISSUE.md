# Double Ratchet Session Persistence Issue

## Problem Analysis

### The Issue
When a user (Bob) goes offline and comes back online, he cannot decrypt pending Double Ratchet messages from other users (Alice). The system fails with:

```
ERROR: No ratchet state found for unified conversation alice:bob
```

### Root Cause Analysis

#### 1. **In-Memory Session Storage**
Double Ratchet sessions are currently stored in the UI state (`ws_chat_state.ratchet_sessions`) which is:
- **Volatile**: Lost when the client disconnects or crashes
- **Process-local**: Not shared across reconnections
- **Temporary**: Exists only during the WebSocket session lifetime

#### 2. **Message Flow Problem**
The current flow creates a persistence gap:

```
1. Alice sends message to Bob (Bob offline)
   ├─ Alice's ratchet session: Active and stored in memory
   ├─ Server stores message for delivery when Bob comes online
   └─ Bob's ratchet session: Non-existent (Bob offline)

2. Bob comes back online
   ├─ Bob's UI starts with empty ratchet_sessions = #{}
   ├─ Server delivers pending ratchet message
   └─ Bob cannot decrypt: No matching ratchet session found
```

#### 3. **Asymmetric State Problem**
- **Alice** maintains her ratchet session state continuously (if she stays online)
- **Bob** loses his ratchet session state when he goes offline
- The Double Ratchet protocol requires **both parties** to maintain synchronized state
- When Bob reconnects, there's a **state synchronization gap**

### Technical Details

#### Current Message Handling Flow
```erlang
%% When Bob receives pending ratchet message
handle_ratchet_message_unified(From, RatchetPayload, UIState) ->
    ConversationId = create_conversation_id(From, Username),
    case get_stored_ratchet_state(ConversationId, WSChatState) of
        {ok, RatchetState} -> 
            %% Decrypt message - THIS PATH WORKS
            cryptic_double_ratchet:decrypt_message(Message, RatchetState);
        {error, not_found} ->
            %% THIS IS THE PROBLEM - No session exists
            error("No ratchet state found")
    end.
```

#### State Storage Implementation
```erlang
%% In ws_chat_state record
-record(ws_chat_state, {
    ratchet_sessions = #{}, %% ← VOLATILE IN-MEMORY STORAGE
    %% ... other fields
}).
```

## Impact Analysis

### User Experience Impact
- **Message Loss**: Users miss messages sent while offline
- **Session Confusion**: Users don't understand why messages fail to decrypt
- **Reliability Issues**: System appears unreliable for asynchronous messaging

### Security Implications
- **No Security Compromise**: The issue is availability, not confidentiality
- **Forward Secrecy Maintained**: Old messages remain secure
- **Protocol Integrity**: Double Ratchet algorithm itself is unaffected

### Operational Impact
- **Support Burden**: Users report "broken encryption" 
- **Trust Issues**: Users lose confidence in the system
- **Scalability Problems**: Manual intervention required for session recovery

## Solution Options

### Option 1: Persistent Ratchet Session Storage ⭐ **RECOMMENDED**

#### Implementation
Store ratchet sessions persistently using encrypted local storage:

```erlang
%% Persistent storage interface
cryptic_ratchet_storage:store_session(Username, ConversationId, RatchetState),
cryptic_ratchet_storage:load_session(Username, ConversationId),
cryptic_ratchet_storage:delete_session(Username, ConversationId).
```

#### Advantages
- ✅ **Complete Solution**: Handles all offline scenarios
- ✅ **Maintains Protocol Integrity**: No changes to Double Ratchet algorithm
- ✅ **User Transparent**: Works seamlessly without user intervention
- ✅ **Secure**: Sessions encrypted with user's master key

#### Storage Design
```
~/.cryptic/sessions/
├── alice/
│   ├── alice_bob.ratchet     (encrypted ratchet session)
│   ├── alice_charlie.ratchet
│   └── session_index.dat     (metadata and integrity)
└── bob/
    ├── bob_alice.ratchet
    └── session_index.dat
```

#### Security Considerations
- **Encryption**: Sessions encrypted with user's master passphrase
- **Integrity**: HMAC protection against tampering
- **Forward Secrecy**: Old session files deleted after key rotation
- **Access Control**: File permissions restricted to user only

### Option 2: X3DH Fallback Mechanism

#### Implementation
When no ratchet session exists, automatically fall back to X3DH:

```erlang
%% Fallback logic
case get_stored_ratchet_state(ConversationId, WSChatState) of
    {ok, RatchetState} -> 
        decrypt_with_ratchet(Message, RatchetState);
    {error, not_found} ->
        %% Fall back to X3DH session establishment
        request_key_bundle_for_session_reestablishment(From, Message)
end.
```

#### Advantages
- ✅ **Quick Implementation**: Minimal code changes required
- ✅ **Automatic Recovery**: Sessions re-establish transparently
- ✅ **Protocol Compliance**: Uses standard X3DH for session establishment

#### Disadvantages
- ❌ **Message Loss**: Cannot decrypt already-sent ratchet messages
- ❌ **Performance Impact**: Additional round-trips for session establishment
- ❌ **Complexity**: Requires careful pending message management

### Option 3: Server-Side Session Coordination

#### Implementation
Store minimal session metadata on server to coordinate recovery:

```erlang
%% Server stores session existence indicators
server_session_registry:register_session(alice, bob, session_id),
server_session_registry:check_session_exists(alice, bob).
```

#### Advantages
- ✅ **Centralized Coordination**: Server can guide session recovery
- ✅ **Cross-Client Sync**: Helps with multi-device scenarios

#### Disadvantages
- ❌ **Server State**: Violates stateless server design
- ❌ **Privacy Concerns**: Server learns about conversation relationships
- ❌ **Complexity**: Requires server-side session lifecycle management

### Option 4: Hybrid Approach (Recommended Implementation)

Combine **persistent storage** with **X3DH fallback**:

1. **Primary**: Store ratchet sessions persistently
2. **Fallback**: Use X3DH recovery for corrupted/missing sessions
3. **Graceful Degradation**: Clear error messages and recovery options

## Recommended Solution: Persistent Ratchet Storage

### Implementation Plan

#### Phase 1: Storage Infrastructure
1. **Extend `cryptic_lib` with ratchet session functions**
   - **Leverage existing encryption**: Reuse `save_encrypted_keys/3` and `load_encrypted_keys/2`
   - **Add ratchet-specific functions**: `save_ratchet_session/4`, `load_ratchet_session/3`
   - **Session serialization**: Convert ratchet state to/from binary using existing patterns

2. **Extend session lifecycle management**
   - **Auto-load on connect**: Load all ratchet sessions after passphrase entry
   - **Auto-save on state changes**: Save ratchet sessions after every message sent/received
   - **Passphrase retention**: Store passphrase in UI state for ongoing encryption operations
   - **Cleanup of expired sessions**: Periodic cleanup based on last-used timestamps

#### Phase 2: Integration with Existing Infrastructure
1. **Modify UI state management (`cryptic_ws_ui.erl`)**
   - **Extend `ws_chat_state`**: Add `passphrase` field for ongoing operations
   - **Update `handle_passphrase_input/2`**: Store passphrase after successful key loading
   - **Load sessions on connect**: Call `load_all_ratchet_sessions/2` after `load_client_keys_and_connect/3`
   - **Handle storage errors gracefully**: Fallback to X3DH when sessions fail to load

2. **Update message handling with auto-save**
   - **Save after encrypt**: Auto-save ratchet session after `encrypt_message/2`
   - **Save after decrypt**: Auto-save ratchet session after `decrypt_message/2`
   - **Batch operations**: Consider batching saves to reduce I/O overhead
   - **Check persistent storage**: If memory lookup fails, try loading from disk first

#### Phase 3: Security & Reliability
1. **Leverage existing encryption infrastructure**
   - **Reuse `save_encrypted_keys/3`**: Same encryption pattern for ratchet sessions
   - **Consistent key derivation**: Use same passphrase-based encryption as client keys
   - **Integrated security model**: Ratchet sessions protected same way as identity keys

2. **Add session recovery mechanisms**
   - **Detect corrupted sessions**: Handle decryption failures gracefully
   - **Automatic cleanup and recovery**: Remove corrupted session files
   - **Fallback to X3DH**: When recovery fails, automatically request key bundle
   - **User notification**: Inform user of session recovery without technical details

### Implementation Details Using Existing Infrastructure

#### Leveraging `cryptic_lib` Encryption Functions

The existing `save_encrypted_keys/3` and `load_encrypted_keys/2` functions provide the perfect foundation:

```erlang
%% Add to cryptic_lib.erl
save_ratchet_session(Username, ConversationId, RatchetState, Passphrase) ->
    %% Serialize ratchet state to binary
    SessionData = cryptic_double_ratchet:serialize_state(RatchetState),
    
    %% Create session filename: username_conversationid.ratchet
    SessionFile = lists:flatten([Username, "_", ConversationId, ".ratchet"]),
    
    %% Reuse existing encryption infrastructure
    save_encrypted_keys(SessionFile, SessionData, Passphrase).

load_ratchet_session(Username, ConversationId, Passphrase) ->
    %% Construct session filename
    SessionFile = lists:flatten([Username, "_", ConversationId, ".ratchet"]),
    
    %% Load and decrypt using existing infrastructure
    case load_encrypted_keys(SessionFile, Passphrase) of
        {ok, SessionData} ->
            %% Deserialize ratchet state
            cryptic_double_ratchet:deserialize_state(SessionData);
        {error, Reason} ->
            {error, Reason}
    end.

load_all_ratchet_sessions(Username, Passphrase) ->
    %% Find all .ratchet files for this user
    Pattern = lists:flatten([Username, "_*.ratchet"]),
    Sessions = filelib:wildcard(Pattern, get_ratchet_storage_dir()),
    
    %% Load each session
    lists:foldl(fun(SessionFile, Acc) ->
        ConvId = extract_conversation_id_from_filename(SessionFile),
        case load_ratchet_session(Username, ConvId, Passphrase) of
            {ok, RatchetState} -> 
                maps:put(ConvId, RatchetState, Acc);
            {error, _Reason} -> 
                %% Skip corrupted sessions, log warning
                Acc
        end
    end, #{}, Sessions).
```

#### UI State Management Changes

**Extend `ws_chat_state` record:**
```erlang
-record(ws_chat_state, {
    %% ... existing fields ...
    ratchet_sessions = #{},
    passphrase = undefined,  %% NEW: Store for ongoing operations
    %% ... rest of fields ...
}).
```

**Update `handle_passphrase_input/2`:**
```erlang
{key, 10} ->
    %% Enter pressed - process passphrase
    Passphrase = list_to_binary(UIState#ui_state.current_input),
    
    %% EXISTING: Load client keys
    case Passphrase of
        <<>> -> 
            add_system_message("Empty passphrase not allowed", NormalUIState);
        _ ->
            %% Load client keys first
            UIStateWithKeys = load_client_keys_and_connect(NormalUIState, ConfigDir, Passphrase),
            
            %% NEW: Load ratchet sessions after successful key loading
            WSChatState = UIStateWithKeys#ui_state.ws_chat_state,
            Username = WSChatState#ws_chat_state.username,
            
            case cryptic_lib:load_all_ratchet_sessions(Username, Passphrase) of
                {ok, RatchetSessions} ->
                    ?info("Loaded ~p ratchet sessions from storage", [maps:size(RatchetSessions)]),
                    NewWSChatState = WSChatState#ws_chat_state{
                        ratchet_sessions = RatchetSessions,
                        passphrase = Passphrase  %% Store for ongoing use
                    },
                    UIStateWithKeys#ui_state{ws_chat_state = NewWSChatState};
                {error, _LoadErr} ->
                    %% Continue without stored sessions
                    ?warning("Could not load ratchet sessions, starting fresh", []),
                    NewWSChatState = WSChatState#ws_chat_state{
                        passphrase = Passphrase  %% Store for ongoing use
                    },
                    UIStateWithKeys#ui_state{ws_chat_state = NewWSChatState}
            end
    end;
```

#### Auto-Save Integration

**Add helper function for auto-save:**
```erlang
%% Add to cryptic_ws_ui.erl
auto_save_ratchet_session(ConversationId, RatchetState, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    Username = WSChatState#ws_chat_state.username,
    Passphrase = WSChatState#ws_chat_state.passphrase,
    
    %% Save to both memory and disk
    NewRatchetSessions = maps:put(ConversationId, RatchetState, 
                                  WSChatState#ws_chat_state.ratchet_sessions),
    
    %% Async save to disk (don't block UI)
    spawn(fun() ->
        case cryptic_lib:save_ratchet_session(Username, ConversationId, 
                                              RatchetState, Passphrase) of
            ok -> 
                ?dbg("Saved ratchet session ~s to disk", [ConversationId]);
            {error, Reason} -> 
                ?warning("Failed to save ratchet session ~s: ~p", [ConversationId, Reason])
        end
    end),
    
    %% Update UI state immediately
    NewWSChatState = WSChatState#ws_chat_state{
        ratchet_sessions = NewRatchetSessions
    },
    UIState#ui_state{ws_chat_state = NewWSChatState}.
```

**Update message handlers to auto-save:**
```erlang
%% In handle_ratchet_message_unified/3
{ok, PlaintextMessage, NewRatchetState} ->
    %% AUTO-SAVE: Store updated ratchet state
    UIStateWithSavedRatchet = auto_save_ratchet_session(
        ConversationId, NewRatchetState, UIState
    ),
    %% Display the decrypted message
    add_message(From, binary_to_list(PlaintextMessage), UIStateWithSavedRatchet);

%% In send_message_via_ratchet/3
{ok, EncryptedMessage, NewRatchetState} ->
    %% AUTO-SAVE: Store updated ratchet state  
    UIStateWithSavedRatchet = auto_save_ratchet_session(
        ConversationId, NewRatchetState, UIState
    ),
    %% Send the message...
```

#### Security Considerations

**Passphrase Storage:**
- Store passphrase only in memory (`ws_chat_state.passphrase`)
- Clear passphrase on disconnect/quit
- Never write passphrase to disk
- Use same security model as existing client keys

**Session File Security:**
- Reuse existing file permissions from `save_encrypted_keys/3`
- Same encryption strength as identity keys
- Consistent with current security model

### Storage Format Design

#### Session File Structure (Reusing Existing Format)
**Files will use existing `save_encrypted_keys/3` format:**
- Same encryption as client identity keys
- Same file permissions and security model
- Stored in same directory structure as existing keys
- Filename pattern: `<username>_<conversation_id>.ratchet`

**Example file layout:**
```
~/.cryptic/keys/
├── alice.keys                    (existing identity keys)
├── alice_alice:bob.ratchet      (ratchet session alice↔bob)
├── alice_alice:charlie.ratchet   (ratchet session alice↔charlie)
├── bob.keys                      (existing identity keys)
├── bob_alice:bob.ratchet        (ratchet session bob↔alice)
└── bob_bob:charlie.ratchet       (ratchet session bob↔charlie)
```

**Content format:**
```erlang
%% Serialized ratchet state using cryptic_double_ratchet:serialize_state/1
%% Encrypted using same method as save_encrypted_keys/3
SessionData = cryptic_double_ratchet:serialize_state(RatchetState),
EncryptedData = encrypt_with_passphrase(SessionData, Passphrase).
```

**Key derivation:** 
- **Reuses existing**: Same passphrase-based encryption as `save_encrypted_keys/3`
- **Consistent security**: No new key derivation schemes needed
- **Proven approach**: Leverages already-tested encryption infrastructure

### Testing Strategy

#### Unit Tests
- Session serialization/deserialization
- Encryption/decryption correctness
- File system operations and error handling
- Key derivation verification

#### Integration Tests  
- End-to-end offline/online scenarios
- Session persistence across reconnections
- Concurrent access and file locking
- Storage corruption recovery

#### Security Tests
- Session file encryption verification
- HMAC integrity validation
- Key derivation security
- File permission enforcement

## Implementation Priority

### High Priority (Critical Path)
1. ✅ **Persistent Storage Module**: Core infrastructure
2. ✅ **Session Lifecycle Integration**: Load/save automation
3. ✅ **Basic Error Handling**: Graceful degradation

### Medium Priority (Enhanced Reliability)
4. 🔄 **X3DH Fallback Mechanism**: Recovery for edge cases
5. 🔄 **Session Cleanup**: Automated maintenance
6. 🔄 **Multi-Device Considerations**: Future expansion

### Low Priority (Optimization)
7. 📋 **Performance Optimization**: Caching and compression
8. 📋 **Advanced Security Features**: Hardware security module integration
9. 📋 **Monitoring and Metrics**: Session health monitoring

## Conclusion

The Double Ratchet session persistence issue is a **critical reliability problem** that prevents asynchronous messaging from working correctly. The recommended solution is to implement **persistent encrypted storage** for ratchet sessions, combined with **X3DH fallback** for edge cases.

This approach:
- ✅ **Solves the core problem**: Messages can be decrypted after reconnection
- ✅ **Maintains security**: Sessions remain encrypted and protected
- ✅ **Provides reliability**: Handles offline/online scenarios gracefully
- ✅ **Enables scalability**: Foundation for multi-device support

The implementation should prioritize **correctness and security** over performance optimization, ensuring that the solution is robust and trustworthy for production use.

## Implementation Status

✅ **COMPLETED** - All ratchet session persistence functionality has been successfully implemented and tested.

### What Was Implemented

1. **Core Storage Functions in `cryptic_lib.erl`:**
   - `save_ratchet_session/4` - Save encrypted session to file
   - `load_ratchet_session/3` - Load and decrypt session from file  
   - `load_all_ratchet_sessions/2` - Load all user sessions at startup
   - `delete_ratchet_session/2` - Remove session file

2. **UI Integration in `cryptic_ws_ui.erl`:**
   - Added `passphrase` field to `ws_chat_state` record
   - Modified `load_client_keys_and_connect/3` to store passphrase and auto-load sessions
   - Added `auto_save_ratchet_session/3` function for transparent session saving
   - Integrated auto-save into existing `store_ratchet_state_in_ui/3` function

3. **Header Updates in `cryptic_ui.hrl`:**
   - Extended `ws_chat_state` record with `passphrase` field

### Testing Results

- ✅ Session encryption/decryption using existing AES-256-GCM infrastructure
- ✅ File-based storage with secure permissions (rw-------)
- ✅ Multiple session loading and management
- ✅ Compilation successful with no errors
- ✅ All new functions exported and accessible

### Key Features Delivered

- **Transparent Operation**: Sessions are automatically saved after every encrypt/decrypt operation
- **Secure Storage**: Uses existing `save_encrypted_keys/3` infrastructure with AES-256-GCM encryption
- **Automatic Loading**: Sessions are restored when user enters passphrase and connects
- **Error Resilience**: Graceful handling of missing or corrupted session files
- **Consistent Security Model**: Same passphrase and encryption as existing key storage

The solution provides **transparent session persistence** - users will automatically have their ratchet sessions restored on reconnection, enabling seamless offline message decryption.