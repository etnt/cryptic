# Cryptic Chat Shell Implementation Plan

## Overview

This document outlines the implementation plan for a simple chat shell interface for the Cryptic messaging system, along with future enhancements for encrypted chat rooms. The chat shell will provide an interactive command-line interface for end-to-end encrypted messaging directly from the Erlang shell.

## Phase 1: Simple Chat Shell

### 1.1 Core Requirements

The chat shell should provide the following commands from the Erlang shell:

- **Prekey Management**: Publish user's public key to the server
- **Messaging**: Send encrypted messages to other users
- **User Discovery**: List available members (users with published prekeys)
- **Help System**: Display available commands and usage instructions
- **Session Management**: Initialize user session with keypair

### 1.2 User Interface Design

#### Command Structure
```erlang
%% Start chat shell
cryptic_chat:start().

%% Core commands (from within chat shell)
> help
> register alice
> list_users
> send bob "Hello Bob, this is a secret message!"
> inbox
> quit
```

#### Alternative API Design (Function-based)
```erlang
%% Direct function calls (no shell mode)
cryptic_chat:register("alice").
cryptic_chat:list_users().
cryptic_chat:send("alice", "bob", "Hello Bob!").
cryptic_chat:inbox("alice").
```

### 1.3 Module Structure

#### `cryptic_chat.erl` - Main Chat Interface
```erlang
-module(cryptic_chat).

%% Public API
-export([
    start/0,              % Start interactive chat shell
    start/1,              % Start with server URL
    register/1,           % Register user with generated keypair
    register/3,           % Register with existing keypair
    list_users/0,         % List available users
    send/2,               % Send message: send(To, Message)
    send/3,               % Send message: send(From, To, Message)
    inbox/0,              % Check messages for current user
    inbox/1,              % Check messages for specific user
    help/0,               % Display help
    quit/0                % Exit chat shell
]).

%% Internal state management
-export([
    shell_loop/1,         % Main shell loop
    parse_command/1,      % Command parser
    format_message/2      % Message formatting
]).

%% State record
-record(chat_state, {
    server_url = "http://localhost:8080" :: string(),
    current_user :: string() | undefined,
    keypair :: {binary(), binary()} | undefined,
    user_cache = #{} :: #{string() => binary()}  % Username -> PubKey cache
}).
```

#### `cryptic_chat_storage.erl` - Local Storage Management
```erlang
-module(cryptic_chat_storage).

%% Key storage and retrieval
-export([
    store_keypair/2,      % Store user's keypair securely
    load_keypair/1,       % Load user's keypair
    store_contact/2,      % Cache contact's public key
    load_contact/1,       % Retrieve contact's public key
    list_contacts/0,      % List cached contacts
    clear_storage/0       % Clear all local data
]).

%% File-based storage in ~/.cryptic/
%% Structure:
%% ~/.cryptic/
%% ├── keys/
%% │   └── alice.key     % User's encrypted private key
%% ├── contacts/
%% │   ├── bob.pub       % Contact public keys
%% │   └── charlie.pub
%% └── config.json       % Configuration
```

### 1.4 Implementation Details

#### 1.4.1 Chat Shell Initialization
```erlang
start() ->
    start("http://localhost:8080").

start(ServerUrl) ->
    %% Initialize client library
    cryptic_client_lib:init_client(),
    
    %% Display welcome message
    io:format("~n=== Cryptic Chat Shell ===~n"),
    io:format("Server: ~s~n", [ServerUrl]),
    io:format("Type 'help' for available commands~n~n"),
    
    %% Initialize state
    State = #chat_state{server_url = ServerUrl},
    
    %% Start interactive shell loop
    shell_loop(State).
```

#### 1.4.2 Command Processing
```erlang
shell_loop(State) ->
    %% Display prompt with current user
    Prompt = case State#chat_state.current_user of
        undefined -> "> ";
        User -> io_lib:format("~s> ", [User])
    end,
    
    %% Read user input
    case io:get_line(Prompt) of
        eof -> 
            io:format("Goodbye!~n"),
            ok;
        Line ->
            Command = string:trim(Line),
            NewState = handle_command(Command, State),
            shell_loop(NewState)
    end.

handle_command("help", State) ->
    display_help(),
    State;
handle_command("register " ++ Username, State) ->
    register_user(Username, State);
handle_command("list_users", State) ->
    list_users(State);
handle_command("send " ++ Args, State) ->
    parse_send_command(Args, State);
handle_command("inbox", State) ->
    check_inbox(State);
handle_command("quit", _State) ->
    io:format("Goodbye!~n"),
    exit(normal);
handle_command(Unknown, State) ->
    io:format("Unknown command: ~s~n", [Unknown]),
    io:format("Type 'help' for available commands~n"),
    State.
```

#### 1.4.3 User Registration
```erlang
register_user(Username, State) ->
    case State#chat_state.current_user of
        undefined ->
            %% Check if user already has stored keys
            case cryptic_chat_storage:load_keypair(Username) of
                {ok, {PubKey, PrivKey}} ->
                    %% Use existing keypair
                    upload_and_set_user(Username, PubKey, PrivKey, State);
                {error, not_found} ->
                    %% Generate new keypair
                    {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
                    cryptic_chat_storage:store_keypair(Username, {PubKey, PrivKey}),
                    upload_and_set_user(Username, PubKey, PrivKey, State)
            end;
        CurrentUser ->
            io:format("Already registered as ~s. Use 'quit' to exit.~n", [CurrentUser]),
            State
    end.

upload_and_set_user(Username, PubKey, PrivKey, State) ->
    case cryptic_client_lib:upload_prekey(State#chat_state.server_url, Username, PubKey) of
        ok ->
            io:format("Successfully registered as ~s~n", [Username]),
            State#chat_state{
                current_user = Username,
                keypair = {PubKey, PrivKey}
            };
        {error, Reason} ->
            io:format("Failed to register: ~p~n", [Reason]),
            State
    end.
```

#### 1.4.4 Message Sending
```erlang
parse_send_command(Args, State) ->
    case State#chat_state.current_user of
        undefined ->
            io:format("Please register first using 'register <username>'~n"),
            State;
        FromUser ->
            case parse_send_args(Args) of
                {ok, {ToUser, Message}} ->
                    send_message(FromUser, ToUser, Message, State);
                {error, Reason} ->
                    io:format("Invalid send command: ~p~n", [Reason]),
                    io:format("Usage: send <username> \"<message>\"~n"),
                    State
            end
    end.

send_message(FromUser, ToUser, Message, State) ->
    {_PubKey, PrivKey} = State#chat_state.keypair,
    
    case cryptic_client_lib:send_encrypted_message(
        State#chat_state.server_url, FromUser, ToUser, Message, PrivKey) of
        ok ->
            io:format("Message sent to ~s~n", [ToUser]);
        {error, Reason} ->
            io:format("Failed to send message: ~p~n", [Reason])
    end,
    State.
```

#### 1.4.5 Message Reception
```erlang
check_inbox(State) ->
    case State#chat_state.current_user of
        undefined ->
            io:format("Please register first~n"),
            State;
        Username ->
            {_PubKey, PrivKey} = State#chat_state.keypair,
            case cryptic_client_lib:receive_and_decrypt_messages(
                State#chat_state.server_url, Username, PrivKey) of
                {ok, []} ->
                    io:format("No new messages~n");
                {ok, Messages} ->
                    display_messages(Messages);
                {error, Reason} ->
                    io:format("Failed to check inbox: ~p~n", [Reason])
            end,
            State
    end.

display_messages(Messages) ->
    io:format("~n=== New Messages ===~n"),
    lists:foreach(fun({From, Message}) ->
        Timestamp = calendar:system_time_to_rfc3339(erlang:system_time(second)),
        io:format("[~s] ~s: ~s~n", [Timestamp, From, Message])
    end, Messages),
    io:format("====================~n~n").
```

### 1.5 Help System

```erlang
display_help() ->
    io:format("~n=== Cryptic Chat Commands ===~n"),
    io:format("register <username>     - Register with a new or existing keypair~n"),
    io:format("list_users              - Show all users with published prekeys~n"),
    io:format("send <user> \"<msg>\"     - Send encrypted message to user~n"),
    io:format("inbox                   - Check for new messages~n"),
    io:format("help                    - Show this help message~n"),
    io:format("quit                    - Exit chat shell~n"),
    io:format("=============================~n~n").
```

### 1.6 Configuration and Storage

#### Local Storage Structure
```
~/.cryptic/
├── config.json          # Server URL, preferences
├── keys/
│   ├── alice.key        # Encrypted private keys
│   └── bob.key
├── contacts/
│   ├── charlie.pub      # Cached public keys
│   └── diana.pub
└── logs/
    └── chat.log         # Optional: encrypted chat history
```

#### Configuration Format
```json
{
    "server_url": "http://localhost:8080",
    "auto_check_interval": 5000,
    "message_history": true,
    "key_derivation": {
        "iterations": 100000,
        "salt_size": 32
    }
}
```

## Phase 2: Enhanced Features

### 2.1 Polling Mode
```erlang
%% Auto-check for messages every N seconds
cryptic_chat:start_polling(5).  % Check every 5 seconds

%% In shell_loop, add timer for automatic inbox checking
```

### 2.2 Message History
```erlang
%% Store encrypted message history locally
cryptic_chat:history().         % Show recent messages
cryptic_chat:history(bob).      % Show conversation with bob
```

### 2.3 Contact Management
```erlang
%% Enhanced contact management
cryptic_chat:add_contact(bob, "Bob Smith").
cryptic_chat:contacts().
cryptic_chat:contact_info(bob).
```

## Phase 3: Chat Rooms (Future Enhancement)

### 3.1 Chat Room Architecture

#### Group Key Management
Chat rooms will use a hybrid approach combining:
1. **Room Master Key**: Symmetric key for the chat room
2. **Member Key Exchange**: Each member's access to the room key
3. **Forward Secrecy**: Periodic room key rotation

#### Protocol Design
```
1. Room Creation:
   - Admin generates room master key (AES-256)
   - Admin encrypts room key for each member using their public key
   - Server stores encrypted room keys per member

2. Message Sending:
   - Encrypt message with current room master key
   - Send to room endpoint with room_id
   - Server broadcasts to all room members

3. Message Reception:
   - Retrieve encrypted room messages
   - Decrypt room key using member's private key
   - Decrypt messages using room key

4. Key Rotation:
   - Admin generates new room key
   - Re-encrypt for all current members
   - Messages use versioned keys for backward compatibility
```

### 3.2 Chat Room Data Structures

#### Room Metadata
```erlang
-record(chat_room, {
    room_id :: binary(),
    name :: string(),
    admin :: string(),
    members :: [string()],
    created_at :: integer(),
    key_version :: integer()
}).

-record(room_key, {
    room_id :: binary(),
    version :: integer(),
    encrypted_key :: binary(),  % Room key encrypted for this member
    member :: string()
}).

-record(room_message, {
    room_id :: binary(),
    from :: string(),
    key_version :: integer(),
    nonce :: binary(),
    cipher :: binary(),
    timestamp :: integer()
}).
```

### 3.3 Chat Room API Design

#### Room Management Commands
```erlang
%% Create new chat room
> create_room "SecretProject" alice bob charlie

%% Join existing room (invitation-based)
> join_room room_abc123 invitation_token

%% List available rooms for current user
> list_rooms

%% Send message to room
> room_send "SecretProject" "Meeting at 3pm tomorrow"

%% Check room messages
> room_inbox "SecretProject"

%% Room administration
> room_add_member "SecretProject" diana
> room_remove_member "SecretProject" bob
> room_rotate_key "SecretProject"
```

#### Implementation Modules
```erlang
%% cryptic_chat_rooms.erl - Room management
-export([
    create_room/3,        % create_room(Name, Admin, Members)
    join_room/2,          % join_room(RoomId, InvitationToken)
    send_room_message/3,  % send_room_message(RoomId, From, Message)
    get_room_messages/2,  % get_room_messages(RoomId, Member)
    add_member/3,         % add_member(RoomId, Admin, NewMember)
    remove_member/3,      % remove_member(RoomId, Admin, Member)
    rotate_room_key/2     % rotate_room_key(RoomId, Admin)
]).

%% cryptic_room_crypto.erl - Room cryptography
-export([
    generate_room_key/0,
    encrypt_room_key_for_member/2,
    decrypt_room_key/2,
    encrypt_room_message/2,
    decrypt_room_message/3
]).
```

### 3.4 Server-Side Changes for Rooms

#### New HTTP Endpoints
```erlang
%% Room management
POST /create_room                 % Create new room
POST /join_room/:room_id         % Join room with invitation
GET  /list_rooms/:user_id        % List user's rooms

%% Room messaging
POST /room_send/:room_id         % Send message to room
GET  /room_messages/:room_id/:user_id  % Get room messages

%% Room administration
POST /room_add_member/:room_id   % Add member to room
POST /room_remove_member/:room_id % Remove member
POST /room_rotate_key/:room_id   % Rotate room encryption key
```

#### Database Schema Extensions
```erlang
%% New ETS tables for rooms
ets:new(chat_rooms, [named_table, public, set]),      % room_id -> room_record
ets:new(room_keys, [named_table, public, bag]),       % {room_id, member} -> encrypted_key
ets:new(room_messages, [named_table, public, bag]),   % room_id -> message_record
ets:new(room_members, [named_table, public, bag]).    % room_id -> member_list
```

### 3.5 Security Considerations for Rooms

#### Forward Secrecy in Rooms
- **Key Rotation**: Periodic automatic room key changes
- **Member Changes**: Key rotation when members join/leave
- **Message Versioning**: Support multiple key versions simultaneously

#### Access Control
- **Admin Privileges**: Only room admin can add/remove members
- **Invitation System**: Secure invitation tokens for joining
- **Member Verification**: Verify member identity before key sharing

#### Scalability Considerations
- **Large Rooms**: Efficient key distribution for many members
- **Message History**: Handling encrypted history for new members
- **Key Storage**: Efficient server-side encrypted key storage

## Implementation Phases

### Phase 1: Basic Chat Shell (Weeks 1-2)
- [ ] Implement `cryptic_chat.erl` with core commands
- [ ] Add local key storage in `cryptic_chat_storage.erl`
- [ ] Create interactive shell loop
- [ ] Add help system and error handling
- [ ] Write comprehensive tests

### Phase 2: Enhanced Chat Features (Weeks 3-4)
- [ ] Add polling mode for auto-message checking
- [ ] Implement message history storage
- [ ] Add contact management features
- [ ] Improve user experience and error messages

### Phase 3: Chat Rooms Foundation (Weeks 5-8)
- [ ] Design and implement room crypto primitives
- [ ] Add server-side room support
- [ ] Implement basic room operations
- [ ] Add room key management and rotation

### Phase 4: Advanced Room Features (Weeks 9-12)
- [ ] Add invitation system
- [ ] Implement member management
- [ ] Add room administration features
- [ ] Optimize for larger rooms

## Testing Strategy

### Unit Tests
- Command parsing and validation
- Cryptographic operations for rooms
- Local storage operations
- Message formatting and display

### Integration Tests
- Full chat workflows
- Room creation and messaging
- Key rotation scenarios
- Member management operations

### Security Tests
- Key isolation between rooms
- Forward secrecy verification
- Access control validation
- Crypto primitive correctness

## Future Enhancements

### Advanced Features
- **File Sharing**: Encrypted file transfer through rooms
- **Voice Messages**: Support for encrypted audio messages
- **Message Reactions**: Encrypted reactions and acknowledgments
- **Typing Indicators**: Real-time encrypted typing status

### Protocol Improvements
- **Double Ratchet**: Advanced forward secrecy like Signal
- **Post-Quantum**: Upgrade to quantum-resistant algorithms
- **Metadata Privacy**: Enhanced metadata protection
- **Offline Support**: Store-and-forward for offline users

### User Experience
- **GUI Client**: Desktop/mobile applications
- **Web Interface**: Browser-based chat interface
- **Notifications**: Encrypted push notifications
- **Search**: Encrypted message search functionality

This implementation plan provides a comprehensive roadmap for building a robust, secure chat system on top of the existing Cryptic infrastructure, with clear phases for development and testing.
