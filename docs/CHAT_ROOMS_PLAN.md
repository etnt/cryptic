# Cryptic Chat Rooms - Implementation Plan

## Overview

This document outlines the design and implementation plan for adding **chat room** functionality to the Cryptic end-to-end encrypted messaging system. Chat rooms will enable group messaging while maintaining the same security properties as one-to-one messaging.

## Current Architecture Analysis

### Existing Infrastructure
- **WebSocket mTLS**: Real-time communication with certificate authentication
- **X25519 + ChaCha20-Poly1305**: End-to-end encryption with forward secrecy
- **ETS Storage**: In-memory storage for connections, prekeys, and messages
- **Terminal UI**: Professional ncurses interface with command processing
- **Certificate-based Identity**: Username extraction from X.509 certificate CN

### Current Message Flow
1. Alice requests Bob's prekey via WebSocket
2. Alice generates ephemeral keypair for message
3. Alice computes shared secret using ECDH
4. Alice encrypts message with derived AEAD key
5. Server forwards encrypted message to Bob in real-time

## Chat Room Requirements

### Functional Requirements

#### FR1: Room Management
- **Create Room**: Users can create new chat rooms with custom names
- **Join Room**: Users can join existing rooms (with appropriate permissions)
- **Leave Room**: Users can leave rooms they've joined
- **List Rooms**: Users can discover available rooms
- **Room Metadata**: Display room info (members, creation date, description)

#### FR2: Membership Management
- **Public Rooms**: Anyone can join
- **Private Rooms**: Invitation-only or password-protected
- **Room Owners**: Creator has administrative privileges
- **Member List**: View current room participants
- **Presence**: Show online/offline status of room members

#### FR3: Group Messaging
- **Broadcast Messages**: Send message to all room members
- **Message History**: Room-specific message storage and retrieval
- **Real-time Delivery**: Instant message delivery to online members
- **Offline Storage**: Store messages for offline members

#### FR4: User Interface
- **Room Commands**: Terminal UI commands for room operations
- **Room Chat Mode**: Dedicated chat mode for room conversations
- **Room Switching**: Easy switching between rooms and direct messages
- **Notifications**: Visual indicators for new room messages

### Security Requirements

#### SR1: End-to-End Encryption (Phase 1 - Simplified)
- **Individual Message Encryption**: Encrypt each message per recipient using existing 1-to-1 pattern
- **No Shared Room Keys**: Leverage existing user keypairs, no additional key management
- **Member Authentication**: Verify all room members via certificates
- **Future Enhancement**: Phase 2 will introduce per-room keys for larger group efficiency

#### SR2: Message Distribution (Simplified)
- **Broadcast Encryption**: Server forwards individually encrypted messages to each room member
- **Existing Crypto Stack**: Reuse X25519+ChaCha20-Poly1305 encryption from current implementation
- **No Key Rotation**: Avoid complexity of key distribution and rotation in Phase 1

#### SR3: Access Control
- **Room Permissions**: Control who can join, send messages, manage room
- **Certificate Validation**: Ensure only authenticated users access rooms
- **Audit Trail**: Log room operations for security monitoring

## Technical Design

### 1. Data Structures

#### Room Definition (Simplified)
```erlang
-record(room, {
    id :: binary(),                    % Unique room identifier
    name :: binary(),                  % Human-readable room name
    description :: binary(),           % Room description
    type :: public | private,          % Room access type
    owner :: binary(),                 % Room creator username
    created_at :: integer(),           % Creation timestamp
    members :: [binary()],             % List of member usernames
    password_hash :: binary() | undefined  % For private rooms
}).

-record(room_message, {
    id :: binary(),                    % Unique message ID
    room_id :: binary(),               % Target room
    from :: binary(),                  % Sender username
    timestamp :: integer(),            % Message timestamp
    recipients :: [{binary(), binary(), binary()}]  % [{Username, Nonce, Ciphertext}]
}).
```

#### ETS Tables (Simplified)
```erlang
% Room registry
ets:new(rooms, [named_table, set, public, {keypos, #room.id}]).

% Room messages
ets:new(room_messages, [named_table, bag, public, {keypos, #room_message.room_id}]).

% User room memberships (for quick lookup)
ets:new(user_rooms, [named_table, bag, public]).
```

### 2. Cryptographic Design (Phase 1 - Simplified)

#### Message Encryption Approach
**No Group Keys**: Reuse existing 1-to-1 encryption pattern
- Sender encrypts message individually for each room member
- Uses existing `encrypt_for_user/2` pattern from current codebase
- Each recipient gets individually encrypted copy
- No key distribution or rotation complexity

**Encryption Flow**:
```erlang
% Encrypt room message for all members
encrypt_room_message(Message, RoomMembers) ->
    EncryptedCopies = [
        {Username, encrypt_for_user(Message, Username)} 
        || Username <- RoomMembers
    ],
    EncryptedCopies.
```

### 3. Protocol Extensions

#### WebSocket Commands

**Room Management**:
```json
// Create room
{"type": "create_room", "name": "general", "description": "General discussion", "room_type": "public"}

// Join room
{"type": "join_room", "room_id": "room-uuid-123", "password": "optional"}

// Leave room
{"type": "leave_room", "room_id": "room-uuid-123"}

// List rooms
{"type": "list_rooms", "filter": "public|private|joined"}
```

**Room Messaging** (Simplified):
```json
// Send room message
{"type": "send_room_message", "room_id": "room-uuid-123", "message": "plaintext message"}

// Get room messages
{"type": "get_room_messages", "room_id": "room-uuid-123", "since": 1694700000}

// Room member list
{"type": "get_room_members", "room_id": "room-uuid-123"}
```

**Server Responses**:
```json
// Room created
{"type": "room_created", "room_id": "room-uuid-123", "name": "general"}

// Room message broadcast
{"type": "room_message", "room_id": "room-uuid-123", "from": "alice", "timestamp": 1694700000, "key_id": "key-v1", "nonce": "base64", "ciphertext": "base64", "signature": "base64"}

// Key distribution
{"type": "room_key", "room_id": "room-uuid-123", "key_id": "key-v1", "encrypted_key": "base64"}
```

### 4. Implementation Plan (Simplified)

#### Phase 1: Core Infrastructure (Week 1-2) - Simplified Approach
1. **Data Structures**: Implement room and message records (no room_key record needed)
2. **ETS Tables**: Create room storage and indexing (remove room_keys table)
3. **WebSocket Protocol**: Extend handler for room commands
4. **Basic Room Operations**: Create, join, leave, list rooms

#### Phase 2: Messaging System (Week 3-4) - Reuse Existing Crypto
1. **Message Encryption**: Reuse existing 1-to-1 encryption for each room member
2. **Message Broadcasting**: Encrypt message individually per recipient, broadcast to room members
3. **Message Storage**: Simple room message history with encrypted payloads per user
4. **No Key Management**: Skip complex key distribution, use existing user keypairs

#### Phase 3: User Interface (Week 5-6)
1. **Terminal Commands**: Room management commands in UI
2. **Room Chat Mode**: Dedicated room conversation interface
3. **Room Switching**: Navigate between rooms and direct messages
4. **Status Indicators**: Show room activity and member presence

#### Phase 4: Advanced Features (Week 7-8)
1. **Private Rooms**: Password protection and invitation system
2. **Room Administration**: Owner privileges and member management
3. **Optimization**: Consider per-room keys for larger groups (Phase 2 crypto enhancement)
4. **Presence System**: Online/offline status for room members

### 5. File Modifications (Simplified)

#### New Modules
```erlang
% Room management and operations
src/cryptic_room_manager.erl

% Room-related WebSocket commands (no separate crypto module needed)
src/cryptic_room_handlers.erl
```

#### Modified Modules
```erlang
% Add room command handling
src/cryptic_ws_handler.erl

% Add room-related client API
src/cryptic_ws_client.erl

% Add room UI commands and chat mode
src/cryptic_ws_ui.erl

% Extend with room key operations
src/cryptic_lib.erl

% Add room ETS table management
src/cryptic_server.erl
```

### 6. Security Considerations (Simplified)

#### Threat Model
- **Passive Eavesdropping**: Room messages encrypted individually per recipient
- **Active Tampering**: Certificate-based authentication prevents spoofing
- **Room Infiltration**: Certificate-based membership verification
- **Message Replay**: Timestamp-based replay protection from existing system
- **Scalability**: Individual encryption may not scale to very large rooms

#### Security Properties (Phase 1)
- **Confidentiality**: Room messages encrypted with same cryptography as 1-to-1 messages
- **Authenticity**: Certificate-based user authentication
- **Integrity**: ChaCha20-Poly1305 AEAD prevents message tampering
- **Simplicity**: No additional key management complexity
- **Proven Security**: Reuses well-tested existing cryptographic code

#### Limitations & Future Enhancements
- **Efficiency**: N-times encryption for N room members (Phase 2 will optimize)
- **Trust Model**: Message encryption relies on existing user keypair infrastructure
- **Metadata Leakage**: Room membership and timing visible to server
- **Scalability**: Phase 2 will introduce per-room keys for larger groups

### 7. User Experience Design

#### Terminal UI Commands
```bash
# Room management
create_room <name> [description] [public|private] [password]
join_room <room_name_or_id> [password]
leave_room <room_name_or_id>
list_rooms [public|private|joined]
room_info <room_name_or_id>

# Room messaging
room_chat <room_name_or_id>     # Enter room chat mode
send_room <room_name> <message> # Send message to room
room_history <room_name> [count] # Show recent room messages

# Room administration (owners only)
add_member <room_name> <username>
remove_member <room_name> <username>
set_room_description <room_name> <description>
rotate_room_key <room_name>
```

#### Chat Mode Enhancements
```bash
# In room chat mode
:members                    # Show room members
:info                      # Show room information
:history [count]           # Show message history
:switch <room_or_user>     # Switch to different room/user
:exit                      # Leave room chat mode
```

#### Status Indicators
```
[#general] alice: Hello everyone!     # Room message
[alice] Hey there!                    # Direct message
[#general] *bob joined the room*      # Room event
[#general] (5 members, 3 online)     # Room status
```

### 8. Testing Strategy (Simplified)

#### Unit Tests
- Room creation, joining, leaving operations
- Message encryption reusing existing 1-to-1 crypto functions
- WebSocket command parsing and handling
- Room membership management

#### Integration Tests
- Full room workflow: create → join → message → leave
- Multi-user room scenarios with real WebSocket connections
- Broadcast message delivery to multiple recipients
- UI command processing and display

#### Security Tests
- Message encryption using existing cryptographic functions
- Certificate validation for room access
- Individual message encryption per recipient
- Basic replay protection via timestamps

### 9. Future Enhancements

#### Phase 2 Crypto Optimization
- **Per-Room Keys**: Introduce shared room encryption keys for efficiency
- **Key Rotation**: Automatic key updates when membership changes
- **Forward Secrecy**: Enhanced protection through key rotation

#### Advanced Cryptography
- **Signal Protocol Integration**: Double Ratchet for room messaging
- **Post-Quantum**: Upgrade to post-quantum key exchange
- **Distributed Key Management**: Remove single point of failure

#### Scalability
- **Message Persistence**: Database backend for large message history
- **Server Clustering**: Distributed room management
- **Message Pagination**: Efficient large room message handling

#### User Features
- **File Sharing**: Encrypted file upload/download in rooms
- **Voice Messages**: Audio message support
- **Rich Text**: Formatting and emoji support
- **Mobile Clients**: iOS/Android applications

## Conclusion

This simplified chat room implementation provides secure group messaging while reusing Cryptic's existing proven cryptographic infrastructure. **Phase 1 prioritizes simplicity and rapid development** by extending the current 1-to-1 encryption pattern to group scenarios. This approach minimizes complexity, reduces implementation risk, and allows for faster delivery of core chat room functionality.

**Phase 2 enhancements** will introduce per-room keys for improved efficiency with larger groups, but Phase 1 establishes a solid foundation that maintains security while being achievable in the near term.

The design prioritizes:
- **Security**: End-to-end encryption with forward secrecy
- **Usability**: Intuitive terminal interface and commands
- **Scalability**: Extensible architecture for future enhancements
- **Compatibility**: Seamless integration with existing codebase

The implementation will demonstrate that secure group messaging is achievable with modern cryptographic primitives and careful protocol design.
