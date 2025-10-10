%%% @doc Cryptic Engine - Main messaging engine using gen_server
%%%
%%% The Cryptic Engine is a server process implemented with the
%%% gen_server Erlang library. It deals with the exchange of
%%% encrypted messages from a particular user's point of view
%%% using the X3DH and Double-Ratchet protocols.
%%%
%%% By using a callback API it can be used as a drop-in component
%%% in various contexts.
%%%
%%% == Callback API ==
%%%
%%% Modules implementing the cryptic_engine callback behavior must implement
%%% the following functions for storage, network, and UI operations:
%%%
%%% === Storage Operations ===
%%% - `load_identity_keys/2' - Load user's identity keys
%%% - `save_identity_keys/3' - Save user's identity keys
%%% - `load_session_state/3' - Load session state for a peer
%%% - `save_session_state/4' - Save session state for a peer
%%%
%%% === Network Operations ===
%%% - `send_message_to_peer/4' - Send message directly to a peer
%%% - `send_message_to_server/3' - Send message to server
%%%
%%% === UI/Notification Operations ===
%%% - `deliver_message/4' - Deliver decrypted message to user
%%% - `system_message/2' - Display system/status message
%%% - `message_undeliverable/5' - Notify about undeliverable messages
%%% - `log_message/3' - Log messages at various levels
%%%
%%% === Lifecycle Operations ===
%%% - `life_cycle/4' - Handle lifecycle events
%%%
%%% @author Cryptic Team
%%% @version 0.2.0
%%% @since 0.1.0
%%% @end

-module(cryptic_engine).

-behaviour(gen_server).
-behaviour(cryptic_ratchet_engine).

%%%===================================================================
%%% Callback Definitions
%%%===================================================================

%% Load identity keys for a user
%%
%% This callback should load or create the user's long-term identity keys,
%% signed prekey, and one-time prekeys. If keys don't exist, they should be
%% generated and stored.
%%
%% @param Username The username to load keys for
%% @param Context Opaque context data
%% @returns `{ok, IdentityKeys, UpdatedContext}' where IdentityKeys is a map with:
%%   - `identity_sign_key' => `{PublicKey, PrivateKey}'
%%   - `identity_dh_key' => `{PublicKey, PrivateKey}'
%%   - `signed_prekey' => `{KeyId, PublicKey, PrivateKey}'
%%   - `signed_prekey_signature' => `Signature'
%%   - `one_time_prekeys' => `#{KeyId => {PublicKey, PrivateKey}}'
%% `{error, Reason, Context}' on failure
-callback load_identity_keys(
    Username :: binary(),
    Context :: map()
) ->
    {ok, IdentityKeys :: map(), UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Save identity keys for a user
-callback save_identity_keys(
    Username :: binary(),
    IdentityKeys :: map(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Load session state for a peer
-callback load_session_state(
    Username :: binary(),
    PeerUsername :: binary(),
    Context :: map()
) ->
    {ok, SessionState :: map(), UpdatedContext :: map()}
    | {error, not_found | term(), Context :: map()}.

%% Save session state for a peer
-callback save_session_state(
    Username :: binary(),
    PeerUsername :: binary(),
    SessionState :: map(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Send a message directly to a peer
-callback send_message_to_peer(
    FromUsername :: binary(),
    ToUsername :: binary(),
    Message :: term(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Send a message to the server
%%
%% This is the primary network operation for sending messages through the
%% server infrastructure (e.g., via WebSocket).
-callback send_message_to_server(
    Username :: binary(),
    Message :: map(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Deliver a decrypted message to the user
%%
%% Called when a message has been successfully decrypted and is ready
%% to be displayed to the user.
-callback deliver_message(
    FromUsername :: binary(),
    Message :: binary(),
    Timestamp :: erlang:timestamp(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Display a system message to the user
%%
%% System messages include status updates, error notifications, and
%% informational messages from the engine.
-callback system_message(
    Message :: binary(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Notify about an undeliverable message
%%
%% Called when a queued message cannot be delivered (e.g., recipient not found).
%% This allows the application to log or notify the user about the failure.
-callback message_undeliverable(
    ToUsername :: binary(),
    MessageId :: binary(),
    MessageText :: binary(),
    Reason :: term(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Log a message at the specified level
%%
%% Levels: debug, info, warning, error
-callback log_message(
    Level :: atom(),
    Message :: {FormatString :: string(), Args :: list()},
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%% Handle lifecycle events
-callback life_cycle(
    Event :: atom(),
    Reason :: term(),
    Username :: binary(),
    Context :: map()
) ->
    {ok, UpdatedContext :: map()}
    | {error, Reason :: term(), Context :: map()}.

%%%===================================================================
%%% API
%%%===================================================================

%% API
-export([
    start_link/1,
    stop/1,
    send_message/3,
    get_active_sessions/1,
    terminate_session/2,
    get_engine_status/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

%% cryptic_ratchet_engine callbacks
-export([
    handle_state_change/4,
    handle_message_event/4,
    handle_error/4,
    handle_debug_event/4,
    handle_lifecycle_event/3
]).

-include("cryptic.hrl").

%% Records
-record(cryptic_engine_state, {
    % Our username
    username :: binary(),
    % Long-term identity signing keypair (Ed25519)
    identity_sign_key :: {binary(), binary()},
    % Long-term identity DH keypair (X25519)
    identity_dh_key :: {binary(), binary()},
    % Signed prekey (ID, Pub, Priv)
    signed_prekey :: {integer(), binary(), binary()},
    % Signed prekey signature
    signed_prekey_signature :: binary(),
    % Available one-time prekeys
    one_time_prekeys :: #{integer() => {binary(), binary()}},

    % Active ratchet sessions

    % peer_username -> ratchet_engine_pid
    sessions :: #{binary() => pid()},
    % peer_username -> session metadata
    session_states :: #{binary() => session_info()},

    % Pending asynchronous operations

    % username -> list of pending requests
    pending_key_requests :: #{binary() => [pending_request()]},
    % username -> queued messages for session creation
    pending_messages :: #{binary() => [pending_message()]},
    % username -> key bundle (for X3DH initialization with first message)
    key_bundles :: #{binary() => map()},

    % Callback system

    % Callback module implementing behavior
    callback_module :: atom(),
    % Opaque data passed to callbacks
    callback_context :: map(),

    % Configuration

    % Storage backend configuration
    storage_config :: map(),
    % Network backend configuration
    network_config :: map(),

    % Statistics
    message_count :: non_neg_integer(),
    error_count :: non_neg_integer(),
    start_time :: erlang:timestamp()
}).

-record(pending_request, {
    % Unique request identifier
    request_id :: binary(),
    % gen_server From for reply
    from :: gen_server:from(),
    % Type of pending request
    request_type :: key_bundle | message_send,
    % When request was initiated
    timestamp :: erlang:timestamp(),
    % Timer reference for timeout
    timeout_ref :: reference()
}).

-record(pending_message, {
    % Unique message identifier
    message_id :: binary(),
    % gen_server From for reply
    from :: gen_server:from(),
    % Message to send after session creation
    plaintext :: binary(),
    % When message was queued
    timestamp :: erlang:timestamp()
}).

-record(session_info, {
    peer_username :: binary(),
    % Unique session identifier
    session_id :: binary(),
    state :: initiating | active | expired,
    last_activity :: erlang:timestamp(),
    message_count :: non_neg_integer(),
    x3dh_completed :: boolean()
}).

-type session_info() :: #session_info{}.
-type pending_request() :: #pending_request{}.
-type pending_message() :: #pending_message{}.

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Start the Cryptic Engine server
-spec start_link(Config :: map()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

%% @doc Stop the Cryptic Engine server
-spec stop(EnginePid :: pid()) -> ok.
stop(EnginePid) ->
    gen_server:stop(EnginePid).

%% @doc Send a message to another user
-spec send_message(
    EnginePid :: pid(), ToUsername :: binary(), Message :: binary()
) ->
    ok | {error, term()}.
send_message(EnginePid, ToUsername, Message) ->
    gen_server:call(EnginePid, {send_message, ToUsername, Message}).

%% @doc Get list of active sessions
-spec get_active_sessions(EnginePid :: pid()) -> {ok, [session_info()]}.
get_active_sessions(EnginePid) ->
    gen_server:call(EnginePid, get_active_sessions).

%% @doc Terminate a session with a peer
-spec terminate_session(EnginePid :: pid(), PeerUsername :: binary()) ->
    ok | {error, term()}.
terminate_session(EnginePid, PeerUsername) ->
    gen_server:call(EnginePid, {terminate_session, PeerUsername}).

%% @doc Get engine status and statistics
-spec get_engine_status(EnginePid :: pid()) -> {ok, map()}.
get_engine_status(EnginePid) ->
    gen_server:call(EnginePid, get_engine_status).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init(Config) ->
    % Handle ratchet engine crashes gracefully
    process_flag(trap_exit, true),

    % Extract configuration
    CallbackModule = maps:get(callback_mod, Config),
    Username = maps:get(username, Config),

    InitialState = #cryptic_engine_state{
        username = Username,
        sessions = #{},
        session_states = #{},
        pending_key_requests = #{},
        pending_messages = #{},
        key_bundles = #{},
        callback_module = CallbackModule,
        callback_context = Config,
        storage_config = maps:get(storage_config, Config, #{}),
        network_config = maps:get(network_config, Config, #{}),
        message_count = 0,
        error_count = 0,
        start_time = erlang:timestamp()
    },

    log_info("Cryptic Engine starting...", [], InitialState),

    % Load identity keys using callback (callback handles key creation if needed)
    case CallbackModule:load_identity_keys(Username, Config) of
        {ok, IdentityKeys, NewContext} ->
            ?dbg("Loaded identity keys: ~p~n", [IdentityKeys]),
            StateWithKeys = InitialState#cryptic_engine_state{
                identity_sign_key = maps:get(identity_sign_key, IdentityKeys),
                identity_dh_key = maps:get(identity_dh_key, IdentityKeys),
                signed_prekey = maps:get(signed_prekey, IdentityKeys),
                signed_prekey_signature = maps:get(signed_prekey_signature, IdentityKeys),
                one_time_prekeys = maps:get(one_time_prekeys, IdentityKeys),
                callback_context = NewContext
            },

            %% Upload key bundles to server
            maybe
                {ok, IdentityKeysState} ?= upload_identity_keys(StateWithKeys),
                {ok, FinalState} ?= upload_prekey_bundle(IdentityKeysState),
                {ok, FinalState}
            else
                {error, Reason} ->
                    log_error(
                        "Key upload failed: ~p",
                        [Reason],
                        StateWithKeys
                    ),
                    {stop, {upload_failed, Reason}}
            end;
        {error, Reason, _Context} ->
            log_error(
                "Loading identity keys failed: ~p",
                [Reason],
                InitialState
            ),
            {stop, {load_keys_failed, Reason}}
    end.

%% @private
handle_call({send_message, ToUsername, Message}, From, State) ->
    case get_or_create_session(ToUsername, State) of
        {ok, RatchetEnginePid, NewState} ->
            % We have an active session, encrypt and send the message
            send_encrypted_message_to_peer(
                ToUsername, Message, RatchetEnginePid, NewState
            );
        {pending, NewState} ->
            % Session creation in progress, queue the message
            FinalState = queue_pending_message(
                ToUsername, Message, From, NewState
            ),
            {reply, ok, FinalState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call(get_active_sessions, _From, State) ->
    Sessions = [
        SessionInfo
     || SessionInfo <- maps:values(State#cryptic_engine_state.session_states)
    ],
    {reply, {ok, Sessions}, State};
handle_call({terminate_session, _PeerUsername}, _From, State) ->
    % TODO: Implement session termination
    {reply, {error, not_implemented}, State};
handle_call(get_engine_status, _From, State) ->
    Status = #{
        username => State#cryptic_engine_state.username,
        active_sessions => maps:size(State#cryptic_engine_state.sessions),
        message_count => State#cryptic_engine_state.message_count,
        error_count => State#cryptic_engine_state.error_count,
        uptime => timer:now_diff(
            erlang:timestamp(), State#cryptic_engine_state.start_time
        )
    },
    {reply, {ok, Status}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%%% ----------------------
%%% H A N D L E _ I N F O
%%% ----------------------
%% @private
handle_info(
    {websocket_message,
        #{
            <<"type">> := <<"error">>,
            <<"message">> := <<"key-bundle-not-found">>
        } = Message},
    State
) ->
    % Handle key bundle not found error - need to find which user this is for
    % by matching against pending requests
    case find_user_for_key_bundle_error(State) of
        {ok, Username, UpdatedState} ->
            % Inform user through callback system that recipient was not found
            CallbackModule = UpdatedState#cryptic_engine_state.callback_module,
            Context = UpdatedState#cryptic_engine_state.callback_context,

            SystemMessage =
                <<"User '", Username/binary,
                    "' not found - message could not be delivered">>,
            FinalState =
                case CallbackModule:system_message(SystemMessage, Context) of
                    {ok, UpdatedContext} ->
                        UpdatedState#cryptic_engine_state{
                            callback_context = UpdatedContext
                        };
                    {error, _Reason} ->
                        % Continue even if system message fails
                        UpdatedState
                end,

            % Clean up any pending messages for this user (reply OK since they were queued successfully)
            CleanedState = cleanup_pending_messages_for_user(
                Username, FinalState
            ),

            log_info(
                "User ~s not found, informed user via system message",
                [Username],
                CleanedState
            ),
            {noreply, CleanedState};
        not_found ->
            log_error(
                "Received key-bundle-not-found but no pending requests found: ~p",
                [Message],
                State
            ),
            {noreply, State}
    end;
handle_info(
    {websocket_message, #{<<"type">> := <<"key_bundle">>} = KeyBundleMsg},
    State
) ->
    %% Handle key bundle response
    handle_key_bundle_response(KeyBundleMsg, State);
handle_info(
    {websocket_message, #{<<"type">> := <<"message">>} = MessageData},
    State
) ->
    % Extract sender and message payload
    FromUsername = maps:get(<<"from">>, MessageData),
    MessagePayload = maps:get(<<"message">>, MessageData),

    ?dbg("Received message from ~s: ~p", [FromUsername, MessagePayload]),

    % Process the incoming encrypted message
    case
        handle_incoming_encrypted_message(FromUsername, MessagePayload, State)
    of
        {ok, UpdatedState} ->
            {noreply, UpdatedState};
        {error, Reason, UpdatedState} ->
            log_error(
                "Failed to process message from ~s: ~p",
                [FromUsername, Reason],
                UpdatedState
            ),
            {noreply, UpdatedState}
    end;
handle_info(
    {websocket_message, #{<<"type">> := _Type} = _Message},
    State
) ->
    % Handle other WebSocket message types
    ?dbg("Received unhandled websocket message type: ~p", [_Type]),
    {noreply, State};
handle_info({key_request_timeout, _RequestId}, State) ->
    % TODO: Handle key request timeouts
    {noreply, State};
handle_info({'EXIT', _RatchetEnginePid, _Reason}, State) ->
    % TODO: Handle ratchet engine crashes
    {noreply, State};
handle_info(_Info, State) ->
    ?dbg("Unhandled info msg: ~p~n", [_Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_key_bundle_response(Message, State) ->
    Username = maps:get(<<"user">>, Message),

    %% Find pending request for this user
    PendingRequests = State#cryptic_engine_state.pending_key_requests,
    case maps:get(Username, PendingRequests, []) of
        [] ->
            log_error(
                "Unexpected key bundle response for user: ~p",
                [Username],
                State
            ),
            {noreply, State};
        [PendingRequest | _] ->
            %% Cancel timeout for this pending request
            erlang:cancel_timer(PendingRequest#pending_request.timeout_ref),

            %% Extract key bundle and create session
            case extract_key_bundle_from_message(Message) of
                {ok, KeyBundle} ->
                    ?dbg("DEBUG: Successfully extracted KeyBundle: ~p~n", [
                        KeyBundle
                    ]),
                    handle_session_creation(
                        Username, KeyBundle, PendingRequests, State
                    );
                {error, ParseError} ->
                    log_error(
                        "Key bundle parse failed for user ~p: ~p",
                        [Username, ParseError],
                        State
                    ),
                    {noreply, State}
            end
    end.

%% @private
%% @doc Handle session creation from key bundle with proper error handling
%%
%% This stores the key bundle and marks the session as ready for X3DH initialization.
%% The actual X3DH exchange and ratchet initialization happens when the first message is sent.
handle_session_creation(Username, KeyBundle, PendingRequests, State) ->
    try
        % Store the key bundle - don't initialize ratchet yet
        % The ratchet will be initialized when we send the first message using X3DH
        SessionInfo = #session_info{
            peer_username = Username,
            session_id = generate_session_id(),
            state = key_bundle_received,
            last_activity = erlang:timestamp(),
            message_count = 0,
            x3dh_completed = false
        },

        NewSessionStates = maps:put(
            Username,
            SessionInfo,
            State#cryptic_engine_state.session_states
        ),

        % Store key bundle for later use when sending first message
        NewKeyBundles = maps:put(
            Username,
            KeyBundle,
            State#cryptic_engine_state.key_bundles
        ),

        % Clear the pending request for this user
        NewPendingRequests = maps:remove(Username, PendingRequests),

        UpdatedState = State#cryptic_engine_state{
            session_states = NewSessionStates,
            key_bundles = NewKeyBundles,
            pending_key_requests = NewPendingRequests
        },

        % Now process pending messages - first message will trigger X3DH + ratchet init
        process_pending_messages(Username, UpdatedState)
    catch
        ErrorClass:ErrorReason:Stacktrace ->
            log_error(
                "Exception during session creation for user ~p: ~p:~p~nStacktrace: ~p",
                [Username, ErrorClass, ErrorReason, Stacktrace],
                State
            ),
            {noreply, State}
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
            one_time_prekey =>
                case maps:get(<<"one_time_prekey">>, Message) of
                    null ->
                        null;
                    OTPKMap ->
                        #{
                            id => base64:decode(maps:get(<<"id">>, OTPKMap)),
                            public => base64:decode(
                                maps:get(<<"public">>, OTPKMap)
                            )
                        }
                end,
            remaining_otpks => maps:get(<<"remaining_otpks">>, Message)
        },
        {ok, KeyBundle}
    catch
        _:Reason ->
            {error, {key_bundle_parse_failed, Reason}}
    end.

%% @private
upload_identity_keys(State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,

    % Extract keys from state
    {IdentitySignPub, _IdentitySignPriv} =
        State#cryptic_engine_state.identity_sign_key,
    {IdentityDHPub, _IdentityDHPriv} =
        State#cryptic_engine_state.identity_dh_key,
    {_SignedPrekeyId, SignedPrekeyPub, _SignedPrekeyPriv} =
        State#cryptic_engine_state.signed_prekey,
    SignedPrekeySignature = State#cryptic_engine_state.signed_prekey_signature,

    % Construct identity keys message using cryptic_messages
    IdentityData = #{
        identity_sign_public => IdentitySignPub,
        identity_dh_public => IdentityDHPub,
        signed_prekey_public => SignedPrekeyPub,
        signed_prekey_signature => SignedPrekeySignature
    },

    {ok, IdentityMessage} = cryptic_messages:upload_identity_keys(IdentityData),

    % Send identity keys to server via callback
    case
        CallbackModule:send_message_to_server(
            State#cryptic_engine_state.username,
            IdentityMessage,
            Context
        )
    of
        {ok, UpdatedContext} ->
            log_info("Identity keys uploaded successfully", [], State),
            {ok, State#cryptic_engine_state{callback_context = UpdatedContext}};
        {error, Reason, _UpdatedContext} ->
            log_error("Failed to upload identity keys: ~p", [Reason], State),
            {error, Reason};
        {error, Reason} ->
            log_error("Failed to upload identity keys: ~p", [Reason], State),
            {error, Reason}
    end.

%% @private
upload_prekey_bundle(State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,

    % Extract one-time prekeys from state
    OneTimePrekeys = State#cryptic_engine_state.one_time_prekeys,

    % Check if one_time_prekeys is already in the right format or needs conversion
    OTPKList =
        case OneTimePrekeys of
            % If it's already a list of maps with id and public fields
            List when is_list(List) ->
                List;
            % If it's a map with integer keys mapping to {PubKey, PrivKey} tuples
            Map when is_map(Map) ->
                maps:fold(
                    fun(_KeyId, {PubKey, _PrivKey}, Acc) ->
                        [
                            #{
                                id => crypto:strong_rand_bytes(8),
                                public => PubKey
                            }
                            | Acc
                        ]
                    end,
                    [],
                    Map
                );
            % Fallback - empty list
            _ ->
                []
        end,

    % Construct prekey bundle message using cryptic_messages
    PrekeyData = #{
        one_time_prekeys => OTPKList
    },

    {ok, BundleMessage} = cryptic_messages:upload_prekey_bundle(PrekeyData),

    % Send to server via callback (callback handles JSON encoding)
    case
        CallbackModule:send_message_to_server(
            State#cryptic_engine_state.username,
            BundleMessage,
            Context
        )
    of
        {ok, UpdatedContext} ->
            log_info("Prekey bundle uploaded successfully", [], State),
            {ok, State#cryptic_engine_state{callback_context = UpdatedContext}};
        {error, Reason, _UpdatedContext} ->
            log_error("Failed to upload prekey bundle: ~p", [Reason], State),
            {error, Reason};
        {error, Reason} ->
            log_error("Failed to upload prekey bundle: ~p", [Reason], State),
            {error, Reason}
    end.

%% @private
log_error(FormatString, Args, State) ->
    log(error, FormatString, Args, State).

%% @private
log_info(FormatString, Args, State) ->
    log(info, FormatString, Args, State).

%% @private
log(Level, FormatString, Args, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,
    case CallbackModule:log_message(Level, {FormatString, Args}, Context) of
        {ok, _UpdatedContext} ->
            ok;
        {error, _Reason} ->
            % Ignore logging errors to prevent cascading failures
            ok
    end.

%% @private
get_or_create_session(ToUsername, State) ->
    Sessions = State#cryptic_engine_state.sessions,
    case maps:get(ToUsername, Sessions, undefined) of
        undefined ->
            % Check if session creation already in progress
            PendingRequests = State#cryptic_engine_state.pending_key_requests,
            case maps:get(ToUsername, PendingRequests, []) of
                [] ->
                    % No existing session or pending request, initiate key bundle request
                    initiate_key_bundle_request(ToUsername, State);
                _Requests ->
                    % Session creation already in progress
                    {pending, State}
            end;
        RatchetEnginePid ->
            {ok, RatchetEnginePid, State}
    end.

%% @private
initiate_key_bundle_request(ToUsername, State) ->
    % Generate request ID for tracking
    RequestId = generate_request_id(),

    % Construct key bundle request using cryptic_messages
    {ok, KeyBundleRequest} = cryptic_messages:get_key_bundle(#{
        user => ToUsername
    }),

    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,

    % Send request to server asynchronously
    case
        CallbackModule:send_message_to_server(
            State#cryptic_engine_state.username,
            KeyBundleRequest,
            Context
        )
    of
        {ok, UpdatedContext} ->
            % Set up timeout for this request
            TimeoutRef = erlang:send_after(
                30000, self(), {key_request_timeout, RequestId}
            ),

            % Track pending request
            PendingRequest = #pending_request{
                request_id = RequestId,
                % No gen_server:from() for async request
                from = undefined,
                request_type = key_bundle,
                timestamp = erlang:timestamp(),
                timeout_ref = TimeoutRef
            },

            PendingRequests = State#cryptic_engine_state.pending_key_requests,
            %% Store single pending request for this user (we only allow one at a time)
            %% This replaces any existing request (though get_or_create_session prevents that)
            NewPendingRequests = maps:put(
                ToUsername, [PendingRequest], PendingRequests
            ),

            UpdatedState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                pending_key_requests = NewPendingRequests
            },
            {pending, UpdatedState};
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
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
    %% Append to preserve FIFO order (first message sent should be first processed)
    NewPendingMessages = maps:put(
        ToUsername,
        ExistingMessages ++ [PendingMessage],
        PendingMessages
    ),

    State#cryptic_engine_state{
        pending_messages = NewPendingMessages
    }.

%% @private
%% @doc Process all pending messages for a user once their key bundle is received
%%
%% The first message will use X3DH encryption and initialize the ratchet session.
%% Subsequent messages will use the ratchet for encryption.
process_pending_messages(ToUsername, State) ->
    PendingMessages = State#cryptic_engine_state.pending_messages,
    case maps:get(ToUsername, PendingMessages, []) of
        [] ->
            {noreply, State};
        [FirstMessage | RestMessages] ->
            % Process the first message with X3DH
            case
                send_first_message_with_x3dh(ToUsername, FirstMessage, State)
            of
                {ok, UpdatedState} ->
                    % Reply to the caller
                    gen_server:reply(
                        FirstMessage#pending_message.from, ok
                    ),

                    % Now we have an active ratchet session, process remaining messages
                    FinalState = lists:foldl(
                        fun(
                            #pending_message{from = From, plaintext = Msg},
                            AccState
                        ) ->
                            Sessions = AccState#cryptic_engine_state.sessions,
                            case maps:get(ToUsername, Sessions, undefined) of
                                undefined ->
                                    gen_server:reply(
                                        From, {error, session_lost}
                                    ),
                                    AccState;
                                RatchetEnginePid ->
                                    case
                                        send_encrypted_message_to_peer(
                                            ToUsername,
                                            Msg,
                                            RatchetEnginePid,
                                            AccState
                                        )
                                    of
                                        {reply, ok, NewState} ->
                                            gen_server:reply(From, ok),
                                            NewState;
                                        {reply, {error, Reason}, NewState} ->
                                            gen_server:reply(
                                                From, {error, Reason}
                                            ),
                                            NewState
                                    end
                            end
                        end,
                        UpdatedState,
                        RestMessages
                    ),

                    % Remove processed messages
                    UpdatedPendingMessages = maps:remove(
                        ToUsername, PendingMessages
                    ),
                    FinalestState = FinalState#cryptic_engine_state{
                        pending_messages = UpdatedPendingMessages
                    },
                    {noreply, FinalestState};
                {error, Reason} ->
                    % X3DH failed, reply with error and keep other messages pending
                    gen_server:reply(
                        FirstMessage#pending_message.from, {error, Reason}
                    ),
                    % Remove only the failed first message
                    UpdatedPendingMessages = maps:put(
                        ToUsername, RestMessages, PendingMessages
                    ),
                    UpdatedState = State#cryptic_engine_state{
                        pending_messages = UpdatedPendingMessages
                    },
                    {noreply, UpdatedState}
            end
    end.

%% @private
%% @doc Send encrypted message to peer using Double Ratchet
%%
%% This function uses the cryptic_ratchet_engine to encrypt messages after
%% the session has been established via X3DH. The ratchet engine handles
%% forward secrecy and self-healing properties of the Double Ratchet algorithm.
send_encrypted_message_to_peer(ToUsername, Message, RatchetEnginePid, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Username = State#cryptic_engine_state.username,
    Context = State#cryptic_engine_state.callback_context,

    % Use the ratchet engine to encrypt the message
    case cryptic_ratchet_engine:encrypt_message(RatchetEnginePid, Message) of
        {ok, EncryptedData} ->
            % Generate message ID
            MessageId = cryptic_lib:rand_bytes(16),

            % EncryptedData contains: #{dh_public, dh_step, prev_chain_length,
            %                           msg_number, ciphertext, nonce}
            % These fields need to be base64-encoded for transmission
            MessageData = #{
                from => Username,
                to => ToUsername,
                message_id => base64:encode(MessageId),
                dh_public => base64:encode(maps:get(dh_public, EncryptedData)),
                dh_step => maps:get(dh_step, EncryptedData),
                prev_chain_length => maps:get(prev_chain_length, EncryptedData),
                msg_number => maps:get(msg_number, EncryptedData),
                ciphertext => base64:encode(
                    maps:get(ciphertext, EncryptedData)
                ),
                nonce => base64:encode(maps:get(nonce, EncryptedData))
            },

            % Use send_message_ratchet to create proper message structure
            {ok, WSMessage} = cryptic_messages:send_message_ratchet(
                MessageData
            ),
            ?dbg("Sending ratchet-encrypted message: ~p~n", [WSMessage]),
            case
                CallbackModule:send_message_to_server(
                    Username, WSMessage, Context
                )
            of
                {ok, UpdatedContext} ->
                    FinalState = State#cryptic_engine_state{
                        callback_context = UpdatedContext,
                        message_count =
                            State#cryptic_engine_state.message_count + 1
                    },
                    log_info(
                        "Ratchet-encrypted message sent to ~s",
                        [
                            ToUsername
                        ],
                        FinalState
                    ),
                    {reply, ok, FinalState};
                {error, Reason, UpdatedContext} ->
                    FinalState = State#cryptic_engine_state{
                        callback_context = UpdatedContext,
                        error_count = State#cryptic_engine_state.error_count + 1
                    },
                    log_error(
                        "Failed to send message to ~s: ~p",
                        [ToUsername, Reason],
                        FinalState
                    ),
                    {reply, {error, Reason}, FinalState};
                {error, Reason} ->
                    FinalState = State#cryptic_engine_state{
                        error_count = State#cryptic_engine_state.error_count + 1
                    },
                    log_error(
                        "Failed to send message to ~s: ~p",
                        [ToUsername, Reason],
                        FinalState
                    ),
                    {reply, {error, Reason}, FinalState}
            end;
        {error, RatchetError} ->
            FinalState = State#cryptic_engine_state{
                error_count = State#cryptic_engine_state.error_count + 1
            },
            log_error(
                "Failed to encrypt message for ~s: ~p",
                [ToUsername, RatchetError],
                FinalState
            ),
            {reply, {error, {ratchet_encryption_failed, RatchetError}},
                FinalState}
    end.

%% @private
%% @doc Send the first message to a peer using X3DH encryption and initialize ratchet
%%
%% This function:
%% 1. Retrieves the stored key bundle for the peer
%% 2. Uses X3DH to encrypt the first message and get the session key
%% 3. Sends the X3DH-encrypted message to the server
%% 4. Initializes the Double Ratchet with the session key from X3DH
%% 5. Subsequent messages will use the ratchet for encryption
send_first_message_with_x3dh(ToUsername, PendingMessage, State) ->
    % Get the stored key bundle
    KeyBundles = State#cryptic_engine_state.key_bundles,
    case maps:get(ToUsername, KeyBundles, undefined) of
        undefined ->
            {error, key_bundle_not_found};
        KeyBundle ->
            % Perform X3DH with the actual first message
            Message = PendingMessage#pending_message.plaintext,
            case perform_x3dh_with_message(KeyBundle, Message, State) of
                {ok, MessageBlob, MessageId, SessionKey} ->
                    % Send the X3DH-encrypted message to server
                    case
                        send_x3dh_message_to_server(
                            ToUsername, MessageBlob, MessageId, State
                        )
                    of
                        {ok, UpdatedState} ->
                            % Now initialize the ratchet with the session key
                            case
                                initialize_ratchet_session(
                                    ToUsername, SessionKey, UpdatedState
                                )
                            of
                                {ok, FinalState} ->
                                    % Remove key bundle (no longer needed)
                                    NewKeyBundles = maps:remove(
                                        ToUsername, KeyBundles
                                    ),
                                    {ok, FinalState#cryptic_engine_state{
                                        key_bundles = NewKeyBundles
                                    }};
                                {error, RatchetError} ->
                                    {error, {ratchet_init_failed, RatchetError}}
                            end;
                        {error, SendError} ->
                            {error, {send_failed, SendError}}
                    end;
                {error, X3DHError} ->
                    {error, {x3dh_failed, X3DHError}}
            end
    end.

%% @private
%% @doc Perform X3DH key agreement with an actual message to encrypt
%%
%% This calls cryptic_lib:x3dh_sender_init_with_session_key with the actual message
%% and returns both the encrypted message blob and the session key for ratchet initialization.
perform_x3dh_with_message(PeerKeyBundle, Message, StateData) ->
    SenderKeys = #{
        identity_dh_private => element(
            2, StateData#cryptic_engine_state.identity_dh_key
        ),
        identity_dh_public => element(
            1, StateData#cryptic_engine_state.identity_dh_key
        ),
        identity_sign_private => element(
            2, StateData#cryptic_engine_state.identity_sign_key
        ),
        identity_sign_public => element(
            1, StateData#cryptic_engine_state.identity_sign_key
        ),
        % TODO: Get actual key ID from state
        key_id => <<"sender_key_id">>
    },

    %% Transform the key bundle to match cryptic_lib's expected format
    TransformedBundle = #{
        user => maps:get(user, PeerKeyBundle),
        key_id => maps:get(key_id, PeerKeyBundle),
        identity_sign_public => maps:get(identity_sign_public, PeerKeyBundle),
        identity_dh_public => maps:get(identity_dh_public, PeerKeyBundle),
        signed_prekey => #{
            public => maps:get(signed_prekey, PeerKeyBundle),
            signature => maps:get(signed_prekey_signature, PeerKeyBundle)
        },
        one_time_prekey => maps:get(one_time_prekey, PeerKeyBundle, null)
    },

    try
        %% Use cryptic_lib for X3DH with the actual message
        case
            cryptic_lib:x3dh_sender_init_with_session_key(
                SenderKeys, TransformedBundle, Message
            )
        of
            {ok, {MessageBlob, MessageId, SessionKey}} ->
                log_info(
                    "X3DH encryption successful, session key size: ~p bytes",
                    [byte_size(SessionKey)],
                    StateData
                ),
                {ok, MessageBlob, MessageId, SessionKey};
            {error, ErrorReason} ->
                {error, {x3dh_failed, error, ErrorReason}}
        end
    catch
        Class:CatchReason ->
            {error, {x3dh_failed, Class, CatchReason}}
    end.

%% @private
%% @doc Send X3DH-encrypted message blob to server via WebSocket
send_x3dh_message_to_server(ToUsername, MessageBlob, MessageId, State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Username = State#cryptic_engine_state.username,
    Context = State#cryptic_engine_state.callback_context,

    %% Unpack MessageBlob to match server's expected format
    #{
        metadata := Metadata,
        signature := MessageSignature,
        ciphertext := Ciphertext,
        nonce := Nonce
    } = MessageBlob,

    #{
        ephemeral_public := EphemeralPub,
        otpk_id := OtpkId
    } = Metadata,

    %% Construct X3DH message for server (without 'type', send_message_x3dh adds it)
    OtpkIdEncoded =
        case OtpkId of
            undefined -> null;
            _ -> base64:encode(OtpkId)
        end,

    X3DHMessageData = #{
        from => Username,
        to => ToUsername,
        message_id => base64:encode(MessageId),
        ephemeral_public => base64:encode(EphemeralPub),
        otpk_id => OtpkIdEncoded,
        ciphertext => base64:encode(Ciphertext),
        nonce => base64:encode(Nonce),
        signature => base64:encode(MessageSignature),
        metadata => base64:encode(erlang:term_to_binary(Metadata))
    },
    ?dbg("Sending X3DH message data: ~p~n", [X3DHMessageData]),
    {ok, WSMessage} = cryptic_messages:send_message_x3dh(X3DHMessageData),
    ?dbg("WebSocket X3DH message: ~p~n", [WSMessage]),
    case
        CallbackModule:send_message_to_server(
            Username, WSMessage, Context
        )
    of
        {ok, UpdatedContext} ->
            FinalState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                message_count = State#cryptic_engine_state.message_count + 1
            },
            log_info("X3DH message sent to ~s", [ToUsername], FinalState),
            {ok, FinalState};
        {error, Reason, UpdatedContext} ->
            FinalState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                error_count = State#cryptic_engine_state.error_count + 1
            },
            log_error(
                "Failed to send X3DH message to ~s: ~p",
                [ToUsername, Reason],
                FinalState
            ),
            {error, Reason};
        {error, Reason} ->
            FinalState = State#cryptic_engine_state{
                error_count = State#cryptic_engine_state.error_count + 1
            },
            log_error(
                "Failed to send X3DH message to ~s: ~p",
                [ToUsername, Reason],
                FinalState
            ),
            {error, Reason}
    end.

%% @private
%% @doc Initialize Double Ratchet session with session key from X3DH
initialize_ratchet_session(ToUsername, SessionKey, State) ->
    try
        %% Generate a NEW ephemeral keypair for the Double Ratchet
        %% This is separate from the X3DH ephemeral key
        {RatchetEphemeralPub, RatchetEphemeralPriv} = cryptic_lib:gen_keypair(),

        log_info(
            "Initializing ratchet with session key (~p bytes) for ~s",
            [byte_size(SessionKey), ToUsername],
            State
        ),

        %% Create new ratchet engine session with cryptic_engine as callback
        {ok, RatchetEnginePid} = cryptic_ratchet_engine:start_link(
            ?MODULE, #{}, #{peer_username => ToUsername}
        ),

        ok = cryptic_ratchet_engine:init_as_sender(
            RatchetEnginePid,
            SessionKey,
            {RatchetEphemeralPub, RatchetEphemeralPriv}
        ),

        %% Update state with active ratchet session
        NewSessions = maps:put(
            ToUsername,
            RatchetEnginePid,
            State#cryptic_engine_state.sessions
        ),

        %% Update session info to mark X3DH as completed and session as active
        SessionStates = State#cryptic_engine_state.session_states,
        SessionInfo = maps:get(ToUsername, SessionStates),
        UpdatedSessionInfo = SessionInfo#session_info{
            state = active,
            x3dh_completed = true,
            last_activity = erlang:timestamp(),
            % First message was the X3DH one
            message_count = 1
        },
        NewSessionStates = maps:put(
            ToUsername,
            UpdatedSessionInfo,
            SessionStates
        ),

        FinalState = State#cryptic_engine_state{
            sessions = NewSessions,
            session_states = NewSessionStates
        },

        {ok, FinalState}
    catch
        ErrorClass:ErrorReason:Stacktrace ->
            log_error(
                "Ratchet initialization failed for ~s: ~p:~p~n~p",
                [ToUsername, ErrorClass, ErrorReason, Stacktrace],
                State
            ),
            {error, {ratchet_init_exception, ErrorClass, ErrorReason}}
    end.

%% @private
generate_request_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

%% @private
generate_message_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

%% @private
generate_session_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

%% @private
find_user_for_key_bundle_error(State) ->
    % Find the user with the most recent pending key bundle request
    % This assumes key-bundle-not-found errors are for the most recent request
    PendingRequests = State#cryptic_engine_state.pending_key_requests,
    case find_most_recent_key_request(PendingRequests) of
        {ok, Username, RequestId} ->
            % Remove this pending request and return the username
            UpdatedRequests = remove_pending_request(
                Username, RequestId, PendingRequests
            ),
            UpdatedState = State#cryptic_engine_state{
                pending_key_requests = UpdatedRequests
            },
            {ok, Username, UpdatedState};
        not_found ->
            not_found
    end.

%% @private
find_most_recent_key_request(PendingRequests) ->
    % Find the most recent key_bundle request across all users
    AllRequests = maps:fold(
        fun(Username, Requests, Acc) ->
            KeyBundleRequests = [
                {Username, R}
             || R <- Requests,
                R#pending_request.request_type =:= key_bundle
            ],
            KeyBundleRequests ++ Acc
        end,
        [],
        PendingRequests
    ),

    case AllRequests of
        [] ->
            not_found;
        _ ->
            % Sort by timestamp (most recent first)
            Sorted = lists:sort(
                fun({_, R1}, {_, R2}) ->
                    R1#pending_request.timestamp >= R2#pending_request.timestamp
                end,
                AllRequests
            ),
            [{Username, Request} | _] = Sorted,
            {ok, Username, Request#pending_request.request_id}
    end.

%% @private
remove_pending_request(Username, RequestId, PendingRequests) ->
    case maps:get(Username, PendingRequests, []) of
        [] ->
            PendingRequests;
        Requests ->
            FilteredRequests = [
                R
             || R <- Requests,
                R#pending_request.request_id =/= RequestId
            ],
            case FilteredRequests of
                [] ->
                    maps:remove(Username, PendingRequests);
                _ ->
                    maps:put(Username, FilteredRequests, PendingRequests)
            end
    end.

%% @private
cleanup_pending_messages_for_user(Username, State) ->
    PendingMessages = State#cryptic_engine_state.pending_messages,
    case maps:get(Username, PendingMessages, []) of
        [] ->
            State;
        Messages ->
            % Log that these messages couldn't be delivered
            % (they were already queued successfully, so we already replied OK to the callers)
            CallbackModule = State#cryptic_engine_state.callback_module,
            Context = State#cryptic_engine_state.callback_context,

            MessageCount = length(Messages),
            log_info(
                "Cleaning up ~p pending message(s) for non-existent user ~s",
                [MessageCount, Username],
                State
            ),

            % Optionally notify via callback about undeliverable messages
            lists:foreach(
                fun(#pending_message{message_id = MsgId, plaintext = Msg}) ->
                    case
                        CallbackModule:message_undeliverable(
                            Username, MsgId, Msg, user_not_found, Context
                        )
                    of
                        {ok, _} -> ok;
                        % Ignore callback errors
                        {error, _} -> ok
                    end
                end,
                Messages
            ),

            % Remove pending messages for this user
            UpdatedPendingMessages = maps:remove(Username, PendingMessages),
            State#cryptic_engine_state{
                pending_messages = UpdatedPendingMessages,
                error_count =
                    State#cryptic_engine_state.error_count + MessageCount
            }
    end.

%% @private
%% @doc Handle incoming encrypted message (called from async websocket handler)
handle_incoming_encrypted_message(FromUsername, MessagePayload, State) when
    is_list(FromUsername)
->
    % Check message type to determine how to decrypt
    case maps:get(<<"message_type">>, MessagePayload, undefined) of
        <<"x3dh">> ->
            % X3DH message - may be initializing a new session
            case
                handle_x3dh_message_async(FromUsername, MessagePayload, State)
            of
                {ok, UpdatedState} ->
                    {ok, UpdatedState};
                {error, Reason} ->
                    {error, Reason, State}
            end;
        <<"ratchet">> ->
            % Double Ratchet message - existing session
            case
                handle_ratchet_message_async(
                    FromUsername, MessagePayload, State
                )
            of
                {ok, UpdatedState} ->
                    {ok, UpdatedState};
                {error, Reason} ->
                    {error, Reason, State}
            end;
        undefined ->
            log_error(
                "Message from ~s missing message_type field",
                [FromUsername],
                State
            ),
            {error, missing_message_type, State};
        Other ->
            log_error(
                "Unknown message type from ~s: ~p",
                [FromUsername, Other],
                State
            ),
            {error, unknown_message_type, State}
    end.

%% @private
%% @doc Handle Double Ratchet message - decrypt using existing session
handle_x3dh_message_async(FromUsername, MessagePayload, State) when
    is_list(FromUsername)
->
    % Check if we already have a session with this user
    Sessions = State#cryptic_engine_state.sessions,
    case maps:get(FromUsername, Sessions, undefined) of
        undefined ->
            % No existing session - initialize from X3DH message
            case
                initialize_receiver_session_from_x3dh(
                    FromUsername, MessagePayload, State
                )
            of
                {ok, Plaintext, UpdatedState} ->
                    % Deliver decrypted message to UI
                    deliver_message_to_ui_async(
                        FromUsername, Plaintext, UpdatedState
                    );
                {error, Reason} ->
                    log_error(
                        "Failed to initialize session from X3DH for ~s: ~p",
                        [FromUsername, Reason],
                        State
                    ),
                    {error, Reason}
            end;
        _RatchetEnginePid ->
            % We already have a session - this shouldn't happen with X3DH
            log_error(
                "Received X3DH message from ~s but session already exists",
                [FromUsername],
                State
            ),
            {error, session_already_exists}
    end.

%% @private
%% @doc Handle Double Ratchet message - decrypt using existing session
handle_ratchet_message_async(FromUsername, MessagePayload, State) ->
    Sessions = State#cryptic_engine_state.sessions,
    case maps:get(FromUsername, Sessions, undefined) of
        undefined ->
            log_error(
                "Received ratchet message from ~s but no session exists",
                [FromUsername],
                State
            ),
            {error, no_session};
        RatchetEnginePid ->
            % Decrypt using the ratchet engine
            case decrypt_ratchet_message(RatchetEnginePid, MessagePayload) of
                {ok, Plaintext} ->
                    % Update session activity timestamp
                    UpdatedState = update_session_activity(FromUsername, State),
                    % Deliver decrypted message to UI
                    deliver_message_to_ui_async(
                        FromUsername, Plaintext, UpdatedState
                    );
                {error, Reason} ->
                    log_error(
                        "Failed to decrypt ratchet message from ~s: ~p",
                        [FromUsername, Reason],
                        State
                    ),
                    {error, Reason}
            end
    end.

%% @private
%% @doc Initialize receiver session from incoming X3DH message
initialize_receiver_session_from_x3dh(FromUsername, MessagePayload, State) ->
    try
        % Extract X3DH components from message
        Ciphertext = base64:decode(maps:get(<<"ciphertext">>, MessagePayload)),
        Nonce = base64:decode(maps:get(<<"nonce">>, MessagePayload)),
        Signature = base64:decode(maps:get(<<"signature">>, MessagePayload)),
        EncodedMetadata = base64:decode(
            maps:get(<<"metadata">>, MessagePayload)
        ),

        % Decode metadata to extract sender identity and other info
        Metadata = erlang:binary_to_term(EncodedMetadata),
        SenderIdPub = maps:get(sender_identity_sign_public, Metadata),

        % Extract receiver keys from state
        {_IdentityDhPub, IdentityDhPriv} =
            State#cryptic_engine_state.identity_dh_key,
        {_SignedPrekeyId, _SignedPrekeyPub, SignedPrekeyPriv} =
            State#cryptic_engine_state.signed_prekey,
        OneTimePrekeys = State#cryptic_engine_state.one_time_prekeys,

        % Find the one-time prekey that was used
        OtpkId = base64:decode(maps:get(<<"otpk_id">>, MessagePayload)),
        ?dbg("Received X3DH message from ~s using OTPK ID: ~p~n", [
            FromUsername, OtpkId
        ]),
        ?dbg("Available one-time prekeys: ~p~n", [OneTimePrekeys]),

        % OneTimePrekeys is a list of maps: [#{id => KeyId, public => PubKey, private => PrivKey}]
        % Find the matching key by ID
        MatchingKey = lists:filter(
            fun(KeyMap) ->
                case KeyMap of
                    #{id := KeyId} -> KeyId =:= OtpkId;
                    _ -> false
                end
            end,
            OneTimePrekeys
        ),

        case MatchingKey of
            [] ->
                ?dbg("No matching one-time prekey found for ID: ~p~n", [OtpkId]),
                {error, one_time_prekey_not_found};
            [#{private := OtpkPriv} | _] ->
                % Found key with private field
                ?dbg("Found matching one-time prekey with private key~n", []),
                % Construct parameters for cryptic_lib function
                ReceiverKeys = #{
                    identity_dh_private => IdentityDhPriv,
                    signed_prekey_private => SignedPrekeyPriv
                },

                MessageBlob = #{
                    metadata => Metadata,
                    signature => Signature,
                    ciphertext => Ciphertext,
                    nonce => Nonce
                },

                % Perform X3DH receiver operation with correct parameters
                case
                    cryptic_lib:x3dh_receiver_decrypt_with_session_key(
                        ReceiverKeys,
                        MessageBlob,
                        SenderIdPub,
                        OtpkPriv
                    )
                of
                    {ok, {Plaintext, _MessageId, SessionKey}} ->
                        % Initialize ratchet engine as receiver
                        case
                            initialize_receiver_ratchet_session(
                                FromUsername, SessionKey, State
                            )
                        of
                            {ok, UpdatedState} ->
                                log_info(
                                    "Initialized receiver session with ~s via X3DH",
                                    [FromUsername],
                                    UpdatedState
                                ),
                                {ok, Plaintext, UpdatedState};
                            {error, Reason} ->
                                {error, {ratchet_init_failed, Reason}}
                        end;
                    {error, Reason} ->
                        {error, {x3dh_decrypt_failed, Reason}}
                end;
            [KeyWithoutPrivate | _] ->
                ?dbg("Found matching key but it has no private field: ~p~n", [
                    KeyWithoutPrivate
                ]),
                {error, one_time_prekey_missing_private}
        end
    catch
        ErrorClass:ErrorReason:Stacktrace ->
            log_error(
                "Exception during X3DH receiver initialization from ~s: ~p:~p~nStacktrace: ~p",
                [FromUsername, ErrorClass, ErrorReason, Stacktrace],
                State
            ),
            {error, {exception, ErrorClass, ErrorReason}}
    end.

%% @private
%% @doc Initialize ratchet session as receiver after X3DH
initialize_receiver_ratchet_session(PeerUsername, SessionKey, State) ->
    try
        % Start ratchet engine with our callback
        CallbackModule = State#cryptic_engine_state.callback_module,
        CallbackContext = State#cryptic_engine_state.callback_context,

        RatchetContext = CallbackContext#{
            peer_username => PeerUsername,
            callback_mod => CallbackModule
        },

        {ok, RatchetEnginePid} = cryptic_ratchet_engine:start_link(
            ?MODULE,
            #{},
            RatchetContext
        ),

        % Generate our DH keypair for receiving
        DHKeyPair = cryptic_nif:gen_keypair(),

        % Initialize as receiver with the session key from X3DH
        case
            cryptic_ratchet_engine:init_as_receiver(
                RatchetEnginePid, SessionKey, DHKeyPair
            )
        of
            ok ->
                % Create session info
                SessionInfo = #session_info{
                    peer_username = PeerUsername,
                    session_id = generate_session_id(),
                    state = active,
                    last_activity = erlang:timestamp(),
                    % Received first message
                    message_count = 1,
                    x3dh_completed = true
                },

                % Update state with new session
                NewSessions = maps:put(
                    PeerUsername,
                    RatchetEnginePid,
                    State#cryptic_engine_state.sessions
                ),
                NewSessionStates = maps:put(
                    PeerUsername,
                    SessionInfo,
                    State#cryptic_engine_state.session_states
                ),

                UpdatedState = State#cryptic_engine_state{
                    sessions = NewSessions,
                    session_states = NewSessionStates
                },

                {ok, UpdatedState};
            {error, Reason} ->
                % Clean up the ratchet engine
                cryptic_ratchet_engine:stop(RatchetEnginePid),
                {error, Reason}
        end
    catch
        ErrorClass:ErrorReason:Stacktrace ->
            log_error(
                "Exception during receiver ratchet initialization for ~s: ~p:~p~nStacktrace: ~p",
                [PeerUsername, ErrorClass, ErrorReason, Stacktrace],
                State
            ),
            {error, {exception, ErrorClass, ErrorReason}}
    end.

%% @private
%% @doc Decrypt a Double Ratchet message
decrypt_ratchet_message(RatchetEnginePid, MessagePayload) ->
    try
        % Extract ratchet message components
        DhPublic = base64:decode(maps:get(<<"dh_public">>, MessagePayload)),
        DhStep = maps:get(<<"dh_step">>, MessagePayload),
        PrevChainLength = maps:get(<<"prev_chain_length">>, MessagePayload),
        MsgNumber = maps:get(<<"msg_number">>, MessagePayload),
        Ciphertext = base64:decode(maps:get(<<"ciphertext">>, MessagePayload)),
        Nonce = base64:decode(maps:get(<<"nonce">>, MessagePayload)),

        % Construct message structure for ratchet engine
        RatchetMessage = #{
            dh_public => DhPublic,
            dh_step => DhStep,
            prev_chain_length => PrevChainLength,
            msg_number => MsgNumber,
            ciphertext => Ciphertext,
            nonce => Nonce
        },

        % Decrypt using ratchet engine
        case
            cryptic_ratchet_engine:decrypt_message(
                RatchetEnginePid, RatchetMessage
            )
        of
            {ok, Plaintext} ->
                {ok, Plaintext};
            {error, Reason} ->
                {error, Reason}
        end
    catch
        ErrorClass:ErrorReason ->
            {error, {exception, ErrorClass, ErrorReason}}
    end.

%% @private
%% @doc Deliver message to UI (async version)
deliver_message_to_ui_async(FromUsername, DecryptedMessage, State) when
    is_list(FromUsername)
->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,
    Timestamp = erlang:timestamp(),
    ?dbg("Delivering message from ~s to UI: ~p~n", [
        FromUsername, DecryptedMessage
    ]),
    try
        CallbackModule:deliver_message(
            FromUsername, DecryptedMessage, Timestamp, Context
        )
    of
        {ok, UpdatedContext} ->
            NewState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                message_count = State#cryptic_engine_state.message_count + 1
            },
            {ok, NewState};
        {error, Reason, UpdatedContext} ->
            NewState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                error_count = State#cryptic_engine_state.error_count + 1
            },
            {error, {delivery_failed, Reason}, NewState};
        {error, Reason} ->
            NewState = State#cryptic_engine_state{
                error_count = State#cryptic_engine_state.error_count + 1
            },
            {error, {delivery_failed, Reason}, NewState}
    catch
        ErrorClass:ErrorReason ->
            NewState = State#cryptic_engine_state{
                error_count = State#cryptic_engine_state.error_count + 1
            },
            {error, {exception, ErrorClass, ErrorReason}, NewState}
    end.

%% @private
%% @doc Update session activity timestamp
update_session_activity(PeerUsername, State) ->
    SessionStates = State#cryptic_engine_state.session_states,
    case maps:get(PeerUsername, SessionStates, undefined) of
        undefined ->
            State;
        SessionInfo ->
            UpdatedSessionInfo = SessionInfo#session_info{
                last_activity = erlang:timestamp(),
                message_count = SessionInfo#session_info.message_count + 1
            },
            NewSessionStates = maps:put(
                PeerUsername, UpdatedSessionInfo, SessionStates
            ),
            State#cryptic_engine_state{
                session_states = NewSessionStates
            }
    end.

%%%===================================================================
%%% Ratchet Engine Callback Implementation
%%%===================================================================

%% @doc Handle state changes in ratchet engine sessions
handle_state_change(_EngineRef, FromState, ToState, Context) ->
    PeerUsername = maps:get(peer_username, Context, <<"unknown">>),
    ?dbg("Ratchet session ~p: ~p -> ~p", [PeerUsername, FromState, ToState]),
    ok.

%% @doc Handle message encryption/decryption events
handle_message_event(_EngineRef, Event, Data, Context) ->
    CallbackMod = maps:get(callback_mod, Context),
    PeerUsername = maps:get(peer_username, Context, <<"unknown">>),
    case Event of
        encrypt_success ->
            ?dbg("Message encrypted for ~p", [PeerUsername]);
        decrypt_success ->
            Message = maps:get(plaintext, Data),
            ?dbg("Message from ~p: ~p~n", [PeerUsername, Message]),
            Timestamp = erlang:timestamp(),
            CallbackMod:deliver_message(PeerUsername, Data, Timestamp, Context);
        encrypt_error ->
            Reason = maps:get(reason, Data, unknown),
            ?dbg("Encryption failed for ~p: ~p", [PeerUsername, Reason]);
        decrypt_error ->
            Reason = maps:get(reason, Data, unknown),
            ?dbg("Decryption failed for ~p: ~p", [PeerUsername, Reason])
    end,
    ok.

%% @doc Handle errors in ratchet engine
handle_error(_EngineRef, ErrorType, Error, Context) ->
    PeerUsername = maps:get(peer_username, Context, <<"unknown">>),
    ?dbg("Ratchet error for ~p (~p): ~p", [PeerUsername, ErrorType, Error]),
    ok.

%% @doc Handle debug events from ratchet engine
handle_debug_event(_EngineRef, Event, Data, Context) ->
    PeerUsername = maps:get(peer_username, Context, <<"unknown">>),
    ?dbg("Ratchet debug for ~p (~p): ~p", [PeerUsername, Event, Data]),
    ok.

%% @doc Handle lifecycle events from ratchet engine
handle_lifecycle_event(_EngineRef, Event, Context) ->
    PeerUsername = maps:get(peer_username, Context, <<"unknown">>),
    ?dbg("Ratchet lifecycle for ~p: ~p", [PeerUsername, Event]),
    ok.
