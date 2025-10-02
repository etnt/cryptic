# CRYPTIC ENGINE PLAN

This is a plan for how to implement the Cryptic Engine.

The Cryptic Engine is a state machine implemented with the
help of the `gen_statem` Erlang library. It deals with the
exchange of encrypted messages from a particuler users point
of view using the X3DH and Double-Ratchet protocols.

By using a callback API it can be used as a drop-in component
in various contexts.

Here is a summary of the features it implements:

1. When it is started, it is provided with the `Username` it should
   should impersonate, the name of a `Callback Module` and an opaque
   datastructure that is passed along to the callback module functions
   when they are invoked.

2. The `Callback Module` must implement an API for:
  * Retrieving the (encrypted) X3DH keys (e.g from file)
  * Saving the (encrypted) X3DH keys (e.g to file)
  * Retrieving the (encrypted) session data (e.g from file)
  * Saving the (encrypted) session data (e.g to file)
  * Sending a message to the server.
  * Deliver a received message.
  * Log messages
  * Live cycle info

3. It has a function API for:
  * Sending a message to another User.

4. It is using the various existing Cryptic libraries to run the initial
   X3DH protocol for calculating an initial Session Key (SK) whereafter
   it initiates the `cryptic_ratchet_engine` to run and maintain the
   two sender/receiver ratchet chains.

## States of the Cryptic Engine

The state engine handles everything that has to do with
the exchanging of messages with other Users. Hence it must
maintain multiple `cryptic_ratchet_engines`, one for each
peer session. It must also handle various corner cases, for
example when a peer has created new public keys etc.

### Core State Machine

The states of the Cryptic Engine state machine are:

| Action          | Old State    | New State      | Description |
|-----------------|--------------|----------------|-------------|
| starting        | -            | init           | Engine process started, needs initialization |
| load_keys       | init         | started        | Successfully loaded X3DH keys from storage |
| no_keys_found   | init         | create_keys    | No keys found, need to generate new identity |
| save_keys       | create_keys  | started        | New keys generated and saved |
| peer_message    | started      | started        | Handle incoming message from peer |
| send_to_peer    | started      | started        | Send message to specific peer |
| key_rotation    | started      | rotating_keys  | Periodic key rotation in progress |
| rotation_done   | rotating_keys| started        | Key rotation completed |
| shutdown        | any          | stopping       | Graceful shutdown requested |

### State Data Structure

```erlang
-record(cryptic_engine_state, {
    username :: binary(),                              % Our username
    identity_key :: {binary(), binary()},              % Long-term identity keypair
    signed_prekey :: {integer(), binary(), binary()},  % Signed prekey (ID, Pub, Priv)
    one_time_prekeys :: #{integer() => {binary(), binary()}}, % Available one-time prekeys
    
    % Active ratchet sessions
    sessions :: #{binary() => pid()},                  % peer_username -> ratchet_engine_pid
    session_states :: #{binary() => session_info()},  % peer_username -> session metadata
    
    % Callback system
    callback_module :: atom(),                         % Callback module implementing behavior
    callback_context :: map(),                         % Opaque data passed to callbacks
    
    % Configuration
    storage_config :: map(),                           % Storage backend configuration
    network_config :: map(),                           % Network backend configuration
    
    % Statistics
    message_count :: non_neg_integer(),
    error_count :: non_neg_integer(),
    start_time :: erlang:timestamp()
}).

-record(session_info, {
    peer_username :: binary(),
    session_id :: binary(),                            % Unique session identifier
    state :: initiating | active | expired,
    last_activity :: erlang:timestamp(),
    message_count :: non_neg_integer(),
    x3dh_completed :: boolean()
}).
```

## Callback Module Behavior

The Cryptic Engine uses callback modules to handle storage, network operations, and UI notifications. Each callback module must implement the `cryptic_engine` behavior:

```erlang
-module(cryptic_engine).

%% Storage Operations
-callback load_identity_keys(Username, Context) -> 
    {ok, IdentityKeys, Context} | 
    {error, not_found, Context}.

-callback save_identity_keys(Username, IdentityKeys, Context) ->
    {ok, Context} | {error, Reason, Context}.

-callback load_session_state(Username, PeerUsername, Context) ->
    {ok, SessionState, Context} | {error, not_found, Context}.

-callback save_session_state(Username, PeerUsername, SessionState, Context) ->
    {ok, Context} | {error, Reason, Context}.

%% Network Operations  
-callback send_message_to_server(FromUser, ToUser, Message, Context) ->
    {ok, Context} | {error, Reason, Context}.

%% UI Notifications
-callback deliver_message(FromUser, Message, Timestamp, Context) ->
    {ok, Context}.

-callback log_message(Level, Message, Context) ->
    {ok, Context}.

%% Lifecycle Events
-callback life_cycle(Event, Reason, Username, Context) -> {ok, Context}.
```

## Public API Functions

The Cryptic Engine provides a simple API for message exchange:

```erlang
%% Engine Management
start_link(Username, CallbackModule, CallbackContext) -> {ok, pid()} | {error, term()}.
stop(EnginePid) -> ok.

%% Primary Operations
send_message(EnginePid, ToUsername, Message) -> ok | {error, term()}.
process_incoming_message(EnginePid, FromUsername, EncryptedMessage) -> ok | {error, term()}.

%% Session Management
get_active_sessions(EnginePid) -> {ok, [SessionInfo]}.
terminate_session(EnginePid, PeerUsername) -> ok | {error, term()}.

%% Status and Debug
get_engine_status(EnginePid) -> {ok, EngineStatus}.
```

## Detailed State Implementations

### State: `init`

**Purpose**: Load existing keys or determine if new keys need to be generated.

```erlang
init(enter, _OldState, StateData) ->
    Username = StateData#cryptic_engine_state.username,
    Context = StateData#cryptic_engine_state.callback_context,
    CallbackModule = StateData#cryptic_engine_state.callback_module,
    
    case CallbackModule:load_identity_keys(Username, Context) of
        {ok, IdentityKey, SignedPreKey, OneTimePreKeys, NewContext} ->
            NewStateData = StateData#cryptic_engine_state{
                identity_key = IdentityKey,
                signed_prekey = SignedPreKey, 
                one_time_prekeys = OneTimePreKeys,
                callback_context = NewContext
            },
            {next_state, started, NewStateData};
        {error, not_found, NewContext} ->
            NewStateData = StateData#cryptic_engine_state{
                callback_context = NewContext
            },
            {next_state, create_keys, NewStateData}
    end.
```

### State: `create_keys`

**Purpose**: Generate new X3DH identity keys and save them.

```erlang
create_keys(enter, _OldState, StateData) ->
    % Generate new identity key
    IdentityKey = cryptic_nif:gen_keypair(),
    
    % Generate signed prekey
    SignedPreKey = generate_signed_prekey(IdentityKey),
    
    % Generate initial set of one-time prekeys
    OneTimePreKeys = generate_one_time_prekeys(100),
    
    Username = StateData#cryptic_engine_state.username,
    CallbackModule = StateData#cryptic_engine_state.callback_module,
    Context = StateData#cryptic_engine_state.callback_context,
    
    case CallbackModule:save_identity_keys(Username, IdentityKey, SignedPreKey, 
                                           OneTimePreKeys, Context) of
        {ok, NewContext} ->
            NewStateData = StateData#cryptic_engine_state{
                identity_key = IdentityKey,
                signed_prekey = SignedPreKey,
                one_time_prekeys = OneTimePreKeys,
                callback_context = NewContext
            },
            {next_state, started, NewStateData};
        {error, Reason, NewContext} ->
            NewStateData = StateData#cryptic_engine_state{
                callback_context = NewContext
            },
            {keep_state, NewStateData}  % Retry or handle error
    end.
```

### State: `started`

**Purpose**: Main operational state - handle sending and receiving messages.

```erlang
started({call, From}, {send_message, ToUsername, Message}, StateData) ->
    case get_or_create_session(ToUsername, StateData) of
        {ok, RatchetEnginePid, NewStateData} ->
            case cryptic_ratchet_engine:encrypt_message(RatchetEnginePid, Message) of
                {ok, EncryptedMessage} ->
                    CallbackModule = StateData#cryptic_engine_state.callback_module,
                    Username = StateData#cryptic_engine_state.username,
                    Context = NewStateData#cryptic_engine_state.callback_context,
                    
                    case CallbackModule:send_message_to_server(Username, ToUsername, 
                                                             EncryptedMessage, Context) of
                        {ok, UpdatedContext} ->
                            FinalStateData = NewStateData#cryptic_engine_state{
                                callback_context = UpdatedContext,
                                message_count = NewStateData#cryptic_engine_state.message_count + 1
                            },
                            {keep_state, FinalStateData, [{reply, From, ok}]};
                        {error, Reason, UpdatedContext} ->
                            FinalStateData = NewStateData#cryptic_engine_state{
                                callback_context = UpdatedContext
                            },
                            {keep_state, FinalStateData, [{reply, From, {error, Reason}}]}
                    end;
                {error, RatchetError} ->
                    {keep_state, NewStateData, [{reply, From, {error, RatchetError}}]}
            end;
        {error, Reason} ->
            {keep_state, StateData, [{reply, From, {error, Reason}}]}
    end;

started({call, From}, {process_incoming_message, FromUsername, EncryptedMessage}, StateData) ->
    case get_existing_session(FromUsername, StateData) of
        {ok, RatchetEnginePid} ->
            case cryptic_ratchet_engine:decrypt_message(RatchetEnginePid, EncryptedMessage) of
                {ok, DecryptedMessage} ->
                    CallbackModule = StateData#cryptic_engine_state.callback_module,
                    Context = StateData#cryptic_engine_state.callback_context,
                    
                    case CallbackModule:deliver_message(FromUsername, DecryptedMessage, 
                                                       erlang:timestamp(), Context) of
                        {ok, UpdatedContext} ->
                            NewStateData = StateData#cryptic_engine_state{
                                callback_context = UpdatedContext
                            },
                            {keep_state, NewStateData, [{reply, From, ok}]};
                        {error, Reason, UpdatedContext} ->
                            NewStateData = StateData#cryptic_engine_state{
                                callback_context = UpdatedContext
                            },
                            {keep_state, NewStateData, [{reply, From, {error, Reason}}]}
                    end;
                {error, DecryptError} ->
                    {keep_state, StateData, [{reply, From, {error, DecryptError}}]}
            end;
        {error, no_session} ->
            % Handle new session initialization from incoming message
            case initialize_session_from_message(FromUsername, EncryptedMessage, StateData) of
                {ok, DecryptedMessage, NewStateData} ->
                    CallbackModule = StateData#cryptic_engine_state.callback_module,
                    Context = NewStateData#cryptic_engine_state.callback_context,
                    
                    CallbackModule:deliver_message(FromUsername, DecryptedMessage, 
                                                 erlang:timestamp(), Context),
                    {keep_state, NewStateData, [{reply, From, ok}]};
                {error, InitError} ->
                    {keep_state, StateData, [{reply, From, {error, InitError}}]}
            end
    end.
```

## Session Management Functions

### X3DH Session Initiation

```erlang
get_or_create_session(ToUsername, StateData) ->
    Sessions = StateData#cryptic_engine_state.sessions,
    case maps:get(ToUsername, Sessions, undefined) of
        undefined ->
            % Need to create new session with X3DH
            create_new_session(ToUsername, StateData);
        RatchetEnginePid ->
            {ok, RatchetEnginePid, StateData}
    end.

create_new_session(ToUsername, StateData) ->
    CallbackModule = StateData#cryptic_engine_state.callback_module,
    Context = StateData#cryptic_engine_state.callback_context,
    
    % Fetch peer's key bundle from server
    case CallbackModule:fetch_user_keys(ToUsername, Context) of
        {ok, PeerKeyBundle, UpdatedContext} ->
            % Perform X3DH calculation
            case perform_x3dh_sender(PeerKeyBundle, StateData) of
                {ok, SharedSecret, EphemeralKey} ->
                    % Create new ratchet engine session
                    {ok, RatchetEnginePid} = cryptic_ratchet_engine:start_link(
                        ratchet_callback_module, #{}, #{}),
                    
                    ok = cryptic_ratchet_engine:init_as_sender(RatchetEnginePid, 
                                                             SharedSecret, EphemeralKey),
                    
                    % Update state with new session
                    NewSessions = maps:put(ToUsername, RatchetEnginePid, 
                                         StateData#cryptic_engine_state.sessions),
                    SessionInfo = #session_info{
                        peer_username = ToUsername,
                        session_id = generate_session_id(),
                        state = active,
                        last_activity = erlang:timestamp(),
                        message_count = 0,
                        x3dh_completed = true
                    },
                    NewSessionStates = maps:put(ToUsername, SessionInfo,
                                              StateData#cryptic_engine_state.session_states),
                    
                    NewStateData = StateData#cryptic_engine_state{
                        sessions = NewSessions,
                        session_states = NewSessionStates,
                        callback_context = UpdatedContext
                    },
                    {ok, RatchetEnginePid, NewStateData};
                {error, X3DHError} ->
                    {error, X3DHError}
            end;
        {error, FetchError, UpdatedContext} ->
            NewStateData = StateData#cryptic_engine_state{
                callback_context = UpdatedContext
            },
            {error, FetchError}
    end.
```

### X3DH Cryptographic Operations

```erlang
perform_x3dh_sender(PeerKeyBundle, StateData) ->
    IdentityKey = StateData#cryptic_engine_state.identity_key,
    
    % Generate ephemeral key for this session
    EphemeralKey = cryptic_nif:gen_keypair(),
    
    try
        % X3DH key agreement calculation
        % DH1 = DH(IK_A, SPK_B)
        % DH2 = DH(EK_A, IK_B)  
        % DH3 = DH(EK_A, SPK_B)
        % DH4 = DH(EK_A, OPK_B) [if one-time prekey available]
        
        {ok, SharedSecret} = cryptic_x3dh:calculate_shared_secret(
            IdentityKey, EphemeralKey, PeerKeyBundle),
            
        {ok, SharedSecret, EphemeralKey}
    catch
        Class:Reason:Stack ->
            {error, {x3dh_failed, Class, Reason}}
    end.

initialize_session_from_message(FromUsername, EncryptedMessage, StateData) ->
    % Extract X3DH header from incoming message
    case parse_x3dh_message(EncryptedMessage) of
        {ok, X3DHHeader, RatchetMessage} ->
            % Perform X3DH as receiver
            case perform_x3dh_receiver(X3DHHeader, StateData) of
                {ok, SharedSecret, DHKeyPair} ->
                    % Create ratchet engine as receiver
                    {ok, RatchetEnginePid} = cryptic_ratchet_engine:start_link(
                        ratchet_callback_module, #{}, #{}),
                    
                    ok = cryptic_ratchet_engine:init_as_receiver(RatchetEnginePid,
                                                               SharedSecret, DHKeyPair),
                    
                    % Decrypt the first message
                    case cryptic_ratchet_engine:decrypt_message(RatchetEnginePid, RatchetMessage) of
                        {ok, Plaintext} ->
                            % Update state with new session
                            NewSessions = maps:put(FromUsername, RatchetEnginePid,
                                                 StateData#cryptic_engine_state.sessions),
                            SessionInfo = #session_info{
                                peer_username = FromUsername,
                                session_id = generate_session_id(),
                                state = active,
                                last_activity = erlang:timestamp(),
                                message_count = 1,
                                x3dh_completed = true
                            },
                            NewSessionStates = maps:put(FromUsername, SessionInfo,
                                                      StateData#cryptic_engine_state.session_states),
                            
                            NewStateData = StateData#cryptic_engine_state{
                                sessions = NewSessions,
                                session_states = NewSessionStates
                            },
                            {ok, Plaintext, NewStateData};
                        {error, DecryptError} ->
                            {error, DecryptError}
                    end;
                {error, X3DHError} ->
                    {error, X3DHError}
            end;
        {error, ParseError} ->
            {error, ParseError}
    end.
```

## Integration with Existing Components

The Cryptic Engine builds on the existing `cryptic_ratchet_engine` implementation:

- **Reuses**: The complete `cryptic_ratchet_engine.erl` for individual session cryptography
- **Adds**: Multi-session management, X3DH initialization, persistent storage
- **Coordinates**: Multiple ratchet engines for different peer conversations
- **Provides**: Higher-level API focused on user-to-user messaging

This design keeps the Double Ratchet engine focused on its core cryptographic responsibilities while the Cryptic Engine handles the multi-user, persistent session aspects of a complete messaging system.

### Example of the Callback Module

```erlang
-module(cryptic_engine_callbacks).

load_identity_keys(Username, Context) when is_binary(Username) andalso
                                           is_map(Context) ->
   UIMod = maps:get(ui_module, Context),
   maybe
       {ok, Passphrase} ?= UIMod:get_passphrase(Username, Context),
       {ok, ConfigDir} ?= UIMod:get_config_dir(Username, Context),
       {ok, IdentityKeys} ?= cryptic_lib:initialize_client_keys(ConfigDir, Passphrase),
       {ok, IdentityKeys, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end.
   
save_identity_keys(Username, IdentityKeys, Context)
  when is_binary(Username) andalso is_map(IdentityKeys) andalso is_map(Context) ->
   UIMod = maps:get(ui_module, Context),
   maybe
       {ok, Passphrase} ?= UIMod:get_passphrase(Username, Context),
       {ok, ConfigDir} ?= UIMod:get_config_dir(Username, Context),
       ok ?= cryptic_lib:save_encrypted_keys(IdentityKeys, Passphrase, ConfigDir)
       {ok, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end

load_session_state(Username, PeerUsername, Context) ->
  when is_binary(Username) andalso is_binary(PeerUsername) andalso
       is_map(Context) ->
   UIMod = maps:get(ui_module, Context),
   maybe
       {ok, Passphrase} ?= UIMod:get_passphrase(Username, Context),
       {ok, ConfigDir} ?= UIMod:get_config_dir(Username, Context),
       SessionDir = filename:join([ConfigDir, Username]),
       {ok, SessionMap} ?= cryptic_lib:load_ratchet_session(PeerUsername,
                                                            Passphrase,
                                                            SessionDir),
       {ok, SessionMap, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end

save_session_state(Username, PeerUsername, SessionMap, Context)
  when is_binary(Username) andalso is_binary(PeerUsername) andalso
       is_map(SessionMap) andalso is_map(Context) ->
   UIMod = maps:get(ui_module, Context),
   maybe
       {ok, Passphrase} ?= UIMod:get_passphrase(Username, Context),
       {ok, ConfigDir} ?= UIMod:get_config_dir(Username, Context),
       SessionFilename = filename:join([ConfigDir, Username),
       {ok, SessionMap} ?= cryptic_lib:save_ratchet_session(PeerUsername,
                                                            SessionMap
                                                            Passphrase,
                                                            SessionDir),
       {ok, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end

send_message_to_server(FromUsername, ToUsername, CrypticMessage, Context)
  when is_binary(FromUsername) andalso is_binary(ToUsername) andalso
       is_map(CrypticMessage) andalso is_map(Context) ->
   maybe
       %% NYI: cryptic_ws_client:send_message/3
       ok ?= cryptic_ws_client:send_message(FromUsername, ToUsername, CrypticMessage),
       {ok, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end

deliver_message(FromUserName, Message, Timestamp, Context)
  when is_binary(FromUsername) andalso is_binary(Message) andalso
       %% Timestamp is of type: erlang:timestamp()
       andalso is_map(Context) ->
   UIMod = maps:get(ui_module, Context),
   UIMod:deliver_message(FromUserName, Message, Timestamp),
   {ok, Context}.

log_message(Level, {FormatString, Args} = LogMessage, Context)
  when is_atom(Level) andalso is_list(FormatString) andalso
       is_list(Args) andalso is_map(Context) ->
    UIMod = maps:get(ui_module, Context),
    UIMod:log(Level, LogMessage),
    {ok, Context}.

life_cycle(Event, Reason, Username, Context) ->
  when is_atom(Event) andalso is_list(Reason) andalso
       is_binary(Username) andalso is_map(Context) ->
    UIMod = maps:get(ui_module, Context),
    UIMod:life_cycle(Event, Reason, Username),
    {ok, Context}.

```
