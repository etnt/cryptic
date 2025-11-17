# CRYPTIC ENGINE PLAN

This is a plan for how to implement the Cryptic Engine.

The Cryptic Engine is a server process implemented with the
`gen_server` Erlang library. It deals with the exchange of 
encrypted messages from a particular user's point of view 
using the X3DH and Double-Ratchet protocols.

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
    
    % Pending asynchronous operations
    pending_key_requests :: #{binary() => [pending_request()]}, % username -> list of pending requests
    pending_messages :: #{binary() => [pending_message()]},     % username -> queued messages for session creation
    
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

-record(pending_request, {
    request_id :: binary(),                            % Unique request identifier
    from :: gen_server:from(),                         % gen_server From for reply
    request_type :: key_bundle | message_send,         % Type of pending request
    timestamp :: erlang:timestamp(),                   % When request was initiated
    timeout_ref :: reference()                         % Timer reference for timeout
}).

-record(pending_message, {
    message_id :: binary(),                            % Unique message identifier
    from :: gen_server:from(),                         % gen_server From for reply
    plaintext :: binary(),                             % Message to send after session creation
    timestamp :: erlang:timestamp()                    % When message was queued
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
-callback send_message_to_peer(FromUser, ToUser, Message, Context) ->
    {ok, Context} | {error, Reason, Context}.

-callback send_message_to_server(FromUser, Message, Context) ->
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
start_link(Config) -> {ok, pid()} | {error, term()}.
stop(EnginePid) -> ok.

%% Primary Operations
send_message(EnginePid, ToUsername, Message) -> ok | {error, term()}.
process_incoming_message(EnginePid, FromUsername, EncryptedMessage) -> ok | {error, term()}.

%% Session Management
get_active_sessions(EnginePid) -> {ok, [SessionInfo]}.
terminate_session(EnginePid, PeerUsername) -> ok | {error, term()}.

%% Status and Debug
get_engine_status(EnginePid) -> {ok, EngineStatus}.

%% API Implementation
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

stop(EnginePid) ->
    gen_server:stop(EnginePid).

send_message(EnginePid, ToUsername, Message) ->
    gen_server:call(EnginePid, {send_message, ToUsername, Message}).

process_incoming_message(EnginePid, FromUsername, EncryptedMessage) ->
    gen_server:call(EnginePid, {process_incoming_message, FromUsername, EncryptedMessage}).

get_engine_status(EnginePid) ->
    gen_server:call(EnginePid, get_engine_status).
```

## gen_server Implementation

### Initialization

**Purpose**: Initialize the engine, load identity keys and upload prekey bundle to server.

```erlang
init(Config) ->
    process_flag(trap_exit, true),  % Handle ratchet engine crashes gracefully

    % Extract configuration
    CallbackModule = maps:get(callback_mod, Config),
    Username = maps:get(username, Config),

    InitialState = #cryptic_engine_state{
        username = Username,
        sessions = #{},
        session_states = #{},
        pending_key_requests = #{},
        pending_messages = #{},
        callback_module = CallbackModule,
        callback_context = Config,
        message_count = 0,
        error_count = 0,
        start_time = erlang:timestamp()
    },

    % Load identity keys using callback (callback handles key creation if needed)
    case CallbackModule:load_identity_keys(Username, Config) of
        {ok, IdentityKeys, NewContext} ->
            StateWithKeys = InitialState#cryptic_engine_state{
                identity_key = maps:get(identity_key, IdentityKeys),
                signed_prekey = maps:get(signed_prekey, IdentityKeys),
                one_time_prekeys = maps:get(one_time_prekeys, IdentityKeys),
                callback_context = NewContext
            },

            % Upload prekey bundle to server
            case upload_prekey_bundle(StateWithKeys) of
                {ok, FinalState} ->
                    {ok, FinalState};
                {error, Reason} ->
                    {stop, {upload_failed, Reason}}
            end;

        {error, Reason, _Context} ->
            {stop, {load_keys_failed, Reason}}
    end.

upload_prekey_bundle(State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,

    % Construct prekey bundle message using cryptic_messages
    OneTimePrekeys = State#cryptic_engine_state.one_time_prekeys,
    SignedPrekey = State#cryptic_engine_state.signed_prekey,
    IdentityKey = State#cryptic_engine_state.identity_key,

    PrekeyData = #{
        identity_key => IdentityKey,
        signed_prekey => SignedPrekey,
        one_time_prekeys => OneTimePrekeys
    },

    {ok, BundleMessage} = cryptic_messages:upload_prekey_bundle(PrekeyData),

    % Send to server via callback (callback handles JSON encoding)
    case CallbackModule:send_message_to_server(
        State#cryptic_engine_state.username,
        BundleMessage,
        Context
    ) of
        {ok, UpdatedContext} ->
            {ok, State#cryptic_engine_state{callback_context = UpdatedContext}};
        {error, Reason} ->
            {error, Reason}
    end.
```


### Message Handling

**Purpose**: Handle synchronous calls for sending messages and processing incoming messages.

```erlang
handle_call({send_message, ToUsername, Message}, From, State) ->
    case get_or_create_session(ToUsername, State) of
        {ok, RatchetEnginePid, NewState} ->
            case cryptic_ratchet_engine:encrypt_message(RatchetEnginePid, Message) of
                {ok, EncryptedMessage} ->
                    send_encrypted_message_to_peer(ToUsername, EncryptedMessage, NewState);
                {error, RatchetError} ->
                    {reply, {error, RatchetError}, NewState}
            end;
        {pending, NewState} ->
            % Session creation in progress, queue the message
            FinalState = queue_pending_message(ToUsername, Message, From, NewState),
            {noreply, FinalState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({process_incoming_message, FromUsername, EncryptedMessage}, _From, State) ->
    case get_existing_session(FromUsername, State) of
        {ok, RatchetEnginePid} ->
            case cryptic_ratchet_engine:decrypt_message(RatchetEnginePid, EncryptedMessage) of
                {ok, DecryptedMessage} ->
                    deliver_message_to_ui(FromUsername, DecryptedMessage, State);
                {error, DecryptError} ->
                    {reply, {error, DecryptError}, State}
            end;
        {error, no_session} ->
            % Handle new session initialization from incoming message
            case initialize_session_from_message(FromUsername, EncryptedMessage, State) of
                {ok, DecryptedMessage, NewState} ->
                    deliver_message_to_ui(FromUsername, DecryptedMessage, NewState);
                {error, InitError} ->
                    {reply, {error, InitError}, State}
            end
    end;

handle_call(get_engine_status, _From, State) ->
    Status = #{
        username => State#cryptic_engine_state.username,
        active_sessions => maps:size(State#cryptic_engine_state.sessions),
        message_count => State#cryptic_engine_state.message_count,
        error_count => State#cryptic_engine_state.error_count,
        uptime => timer:now_diff(erlang:timestamp(), State#cryptic_engine_state.start_time)
    },
    {reply, {ok, Status}, State}.

%% Handle asynchronous WebSocket messages (already JSON decoded by cryptic_ws_client)
handle_info({websocket_message, Message}, State) ->
    case cryptic_messages:validate_message(Message) of
        {ok, ValidatedMessage} ->
            handle_websocket_message(ValidatedMessage, State);
        {error, ValidationError} ->
            log_error("Invalid WebSocket message: ~p", [ValidationError], State),
            {noreply, State}
    end;

%% Handle key request timeouts
handle_info({key_request_timeout, RequestId}, State) ->
    handle_key_request_timeout(RequestId, State);

%% Handle ratchet engine crashes
handle_info({'EXIT', RatchetEnginePid, Reason}, State) ->
    handle_ratchet_engine_crash(RatchetEnginePid, Reason, State).

handle_websocket_message(Message, State) ->
    MessageType = maps:get(<<"type">>, Message),
    case MessageType of
        <<"key_bundle">> ->
            handle_key_bundle_response(Message, State);
        <<"encrypted_message_received">> ->
            handle_encrypted_message_received(Message, State);
        <<"success">> ->
            handle_success_response(Message, State);
        <<"error">> ->
            handle_error_response(Message, State);
        _ ->
            log_error("Unknown message type: ~p", [MessageType], State),
            {noreply, State}
    end.

handle_key_bundle_response(Message, State) ->
    Username = maps:get(<<"user">>, Message),
    
    % Find pending request for this user
    PendingRequests = State#cryptic_engine_state.pending_key_requests,
    case maps:get(Username, PendingRequests, []) of
        [] ->
            log_error("Unexpected key bundle response from user: ~p", [Username], State),
            {noreply, State};
        [PendingRequest | RemainingRequests] ->
            % Cancel timeout
            erlang:cancel_timer(PendingRequest#pending_request.timeout_ref),
            
            % Extract key bundle and create session
            case extract_key_bundle_from_message(Message) of
                {ok, KeyBundle} ->
                    case create_session_from_key_bundle(Username, KeyBundle, State) of
                        {ok, RatchetEnginePid, UpdatedState} ->
                            % Update pending requests
                            NewPendingRequests = case RemainingRequests of
                                [] -> maps:remove(Username, PendingRequests);
                                _ -> maps:put(Username, RemainingRequests, PendingRequests)
                            end,
                            
                            FinalState = UpdatedState#cryptic_engine_state{
                                pending_key_requests = NewPendingRequests
                            },
                            
                            % Process any pending messages for this user
                            process_pending_messages(Username, RatchetEnginePid, FinalState);
                        {error, Reason} ->
                            log_error("Session creation failed for user ~p: ~p", [Username, Reason], State),
                            {noreply, State}
                    end;
                {error, ParseError} ->
                    log_error("Key bundle parse failed for user ~p: ~p", [Username, ParseError], State),
                    {noreply, State}
            end
    end.

handle_key_request_timeout(RequestId, State) ->
    % Find and remove timed out request
    PendingRequests = State#cryptic_engine_state.pending_key_requests,
    UpdatedRequests = maps:map(
        fun(_Username, Requests) ->
            lists:filter(
                fun(#pending_request{request_id = Id}) ->
                    Id =/= RequestId
                end,
                Requests
            )
        end,
        PendingRequests
    ),
    
    NewState = State#cryptic_engine_state{
        pending_key_requests = UpdatedRequests
    },
    {noreply, NewState}.

%% Helper functions for message handling
send_encrypted_message_to_peer(ToUsername, EncryptedMessage, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Username = State#cryptic_engine_state.username,
    Context = State#cryptic_engine_state.callback_context,
    
    % Construct encrypted message using cryptic_messages
    MessageData = determine_message_format(EncryptedMessage),
    {ok, WSMessage} = case MessageData of
        {x3dh, MsgData} -> cryptic_messages:send_message_x3dh(MsgData);
        {ratchet, MsgData} -> cryptic_messages:send_message_ratchet(MsgData)
    end,
    {ok, JsonMessage} = cryptic_messages:encode_message(WSMessage),
    
    case CallbackModule:send_message_to_server(Username, ToUsername, JsonMessage, Context) of
        {ok, UpdatedContext} ->
            FinalState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                message_count = State#cryptic_engine_state.message_count + 1
            },
            {reply, ok, FinalState};
        {error, Reason, UpdatedContext} ->
            FinalState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                error_count = State#cryptic_engine_state.error_count + 1
            },
            {reply, {error, Reason}, FinalState}
    end.

deliver_message_to_ui(FromUsername, DecryptedMessage, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,
    
    case CallbackModule:deliver_message(FromUsername, DecryptedMessage, 
                                       erlang:timestamp(), Context) of
        {ok, UpdatedContext} ->
            NewState = State#cryptic_engine_state{
                callback_context = UpdatedContext
            },
            {reply, ok, NewState};
        {error, Reason, UpdatedContext} ->
            NewState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                error_count = State#cryptic_engine_state.error_count + 1
            },
            {reply, {error, Reason}, NewState}
    end.

queue_pending_message(ToUsername, Message, From, State) ->
    MessageId = generate_message_id(),
    
    PendingMessage = #pending_message{
        message_id = MessageId,
        from = From,
        plaintext = Message,
        timestamp = erlang:timestamp()
    },
    
    PendingMessages = State#cryptic_engine_state.pending_messages,
    ExistingMessages = maps:get(ToUsername, PendingMessages, []),
    NewPendingMessages = maps:put(ToUsername, [PendingMessage | ExistingMessages], 
                                PendingMessages),
    
    State#cryptic_engine_state{
        pending_messages = NewPendingMessages
    }.

process_pending_messages(ToUsername, RatchetEnginePid, State) ->
    PendingMessages = State#cryptic_engine_state.pending_messages,
    case maps:get(ToUsername, PendingMessages, []) of
        [] ->
            {noreply, State};
        Messages ->
            % Process all pending messages for this user
            NewState = lists:foldl(
                fun(#pending_message{from = From, plaintext = Message}, AccState) ->
                    case cryptic_ratchet_engine:encrypt_message(RatchetEnginePid, Message) of
                        {ok, EncryptedMessage} ->
                            case send_encrypted_message_to_peer(ToUsername, EncryptedMessage, AccState) of
                                {reply, ok, UpdatedState} ->
                                    gen_server:reply(From, ok),
                                    UpdatedState;
                                {reply, {error, Reason}, UpdatedState} ->
                                    gen_server:reply(From, {error, Reason}),
                                    UpdatedState
                            end;
                        {error, RatchetError} ->
                            gen_server:reply(From, {error, RatchetError}),
                            AccState
                    end
                end,
                State,
                Messages
            ),
            
            % Remove processed messages
            UpdatedPendingMessages = maps:remove(ToUsername, PendingMessages),
            FinalState = NewState#cryptic_engine_state{
                pending_messages = UpdatedPendingMessages
            },
            {noreply, FinalState}
    end.

extract_key_bundle_from_message(Message) ->
    try
        KeyBundle = #{
            user => maps:get(<<"user">>, Message),
            key_id => base64:decode(maps:get(<<"key_id">>, Message)),
            identity_sign_public => base64:decode(
                maps:get(<<"identity_sign_public">>, Message)
            ),
            identity_dh_public => base64:decode(
                maps:get(<<"identity_dh_public">>, Message)
            ),
            signed_prekey => base64:decode(
                maps:get(<<"signed_prekey">>, Message)
            ),
            signed_prekey_signature => base64:decode(
                maps:get(<<"signed_prekey_signature">>, Message)
            ),
            one_time_prekey => case maps:get(<<"one_time_prekey">>, Message) of
                null -> null;
                OTPKMap -> #{
                    id => base64:decode(maps:get(<<"id">>, OTPKMap)),
                    public => base64:decode(maps:get(<<"public_key">>, OTPKMap))
                }
            end,
            remaining_otpks => maps:get(<<"remaining_otpks">>, Message)
        },
        {ok, KeyBundle}
    catch
        _:Reason ->
            {error, {key_bundle_parse_failed, Reason}}
    end.

generate_request_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

generate_message_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

log_error(FormatString, Args, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,
    CallbackModule:log_message(error, {FormatString, Args}, Context).
```

## Session Management Functions

### X3DH Session Initiation

```erlang
get_or_create_session(ToUsername, State) ->
    Sessions = State#cryptic_engine_state.sessions,
    case maps:get(ToUsername, Sessions, undefined) of
        undefined ->
            % Check if session creation already in progress
            PendingRequests = State#cryptic_engine_state.pending_key_requests,
            case maps:get(ToUsername, PendingRequests, []) of
                [] ->
                    % Start new session creation
                    initiate_key_bundle_request(ToUsername, State);
                _ExistingRequests ->
                    % Session creation already in progress
                    {pending, State}
            end;
        RatchetEnginePid ->
            {ok, RatchetEnginePid, State}
    end.

initiate_key_bundle_request(ToUsername, State) ->
    % Generate request ID for tracking
    RequestId = generate_request_id(),
    
    % Construct key bundle request using cryptic_messages
    {ok, KeyBundleRequest} = cryptic_messages:get_key_bundle(#{user => ToUsername}),
    
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,
    
    % Send request to server asynchronously
    case CallbackModule:send_message_to_server(
        State#cryptic_engine_state.username,
        KeyBundleRequest,
        Context
    ) of
        {ok, UpdatedContext} ->
            % Set up timeout for this request
            TimeoutRef = erlang:send_after(30000, self(), {key_request_timeout, RequestId}),
            
            % Track pending request
            PendingRequest = #pending_request{
                request_id = RequestId,
                from = undefined,  % Will be set when message send is requested
                request_type = key_bundle,
                timestamp = erlang:timestamp(),
                timeout_ref = TimeoutRef
            },
            
            PendingRequests = State#cryptic_engine_state.pending_key_requests,
            NewPendingRequests = maps:put(ToUsername, [PendingRequest], PendingRequests),
            
            UpdatedState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                pending_key_requests = NewPendingRequests
            },
            {pending, UpdatedState};
        {error, Reason} ->
            {error, Reason}
    end.

create_session_from_key_bundle(ToUsername, KeyBundle, State) ->
    %% Perform X3DH calculation
    case perform_x3dh_sender(KeyBundle, State) of
        {ok, SharedSecret, EphemeralKey} ->
            %% Create new ratchet engine session
            {ok, RatchetEnginePid} = cryptic_ratchet_engine:start_link(
                ratchet_callback_module, #{}, #{}),

            ok = cryptic_ratchet_engine:init_as_sender(RatchetEnginePid, 
                                                     SharedSecret, EphemeralKey),

            %% Update state with new session
            NewSessions = maps:put(ToUsername, RatchetEnginePid, 
                                 State#cryptic_engine_state.sessions),
            SessionInfo = #session_info{
                peer_username = ToUsername,
                session_id = generate_session_id(),
                state = active,
                last_activity = erlang:timestamp(),
                message_count = 0,
                x3dh_completed = true
            },
            NewSessionStates = maps:put(ToUsername, SessionInfo,
                                      State#cryptic_engine_state.session_states),

            NewState = State#cryptic_engine_state{
                sessions = NewSessions,
                session_states = NewSessionStates
            },
            {ok, RatchetEnginePid, NewState};
        {error, X3DHError} ->
            {error, X3DHError}
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

send_message_to_peer(FromUsername, ToUsername, CrypticMessage, Context)
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

send_message_to_server(FromUsername, CrypticMessage, Context)
  when is_binary(FromUsername) andalso
       is_map(CrypticMessage) andalso is_map(Context) ->
   maybe
       %% NYI: cryptic_ws_client:send_message/3
       ok ?= cryptic_ws_client:send_message(FromUsername, CrypticMessage),
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
