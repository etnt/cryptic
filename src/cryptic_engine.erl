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
-module(cryptic_engine).

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    stop/1,
    send_message/3,
    process_incoming_message/3,
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

-include("cryptic.hrl").

%% Records
-record(cryptic_engine_state, {
    % Our username
    username :: binary(),
    % Long-term identity keypair
    identity_key :: {binary(), binary()},
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

%% @doc Process an incoming encrypted message
-spec process_incoming_message(
    EnginePid :: pid(),
    FromUsername :: binary(),
    EncryptedMessage :: binary()
) -> ok | {error, term()}.
process_incoming_message(EnginePid, FromUsername, EncryptedMessage) ->
    gen_server:call(
        EnginePid, {process_incoming_message, FromUsername, EncryptedMessage}
    ).

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
                identity_key = maps:get(identity_key, IdentityKeys),
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
handle_call(
    {process_incoming_message, _FromUsername, _EncryptedMessage}, _From, State
) ->
    % TODO: Implement message processing
    {reply, {error, not_implemented}, State};
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
    {websocket_message, #{
        <<"type">> := _Type,
        <<"message">> := _Message
    }},
    State
) ->
    % TODO: Handle asynchronous WebSocket messages
    {noreply, State};
handle_info({key_request_timeout, _RequestId}, State) ->
    % TODO: Handle key request timeouts
    {noreply, State};
handle_info({'EXIT', _RatchetEnginePid, _Reason}, State) ->
    % TODO: Handle ratchet engine crashes
    {noreply, State};
handle_info(_Info, State) ->
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

%% @private
upload_identity_keys(State) ->
    CallbackModule = State#cryptic_engine_state.callback_module,
    Context = State#cryptic_engine_state.callback_context,

    % Extract keys from state
    {IdentitySignPub, _IdentitySignPriv} =
        State#cryptic_engine_state.identity_key,
    {_SignedPrekeyId, SignedPrekeyPub, _SignedPrekeyPriv} =
        State#cryptic_engine_state.signed_prekey,
    SignedPrekeySignature = State#cryptic_engine_state.signed_prekey_signature,

    % Construct identity keys message using cryptic_messages
    IdentityData = #{
        identity_sign_public => IdentitySignPub,
        % TODO: Need separate DH key
        identity_dh_public => IdentitySignPub,
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
    NewPendingMessages = maps:put(
        ToUsername,
        [PendingMessage | ExistingMessages],
        PendingMessages
    ),

    State#cryptic_engine_state{
        pending_messages = NewPendingMessages
    }.

%% @private
send_encrypted_message_to_peer(ToUsername, Message, _RatchetEnginePid, State) ->
    % TODO: Encrypt message using ratchet engine (when cryptic_ratchet_engine is implemented)
    % For now, we'll send the message as plaintext wrapped in a simple format

    CallbackModule = State#cryptic_engine_state.callback_module,
    Username = State#cryptic_engine_state.username,
    Context = State#cryptic_engine_state.callback_context,

    % Create a simple message structure (will be replaced with actual ratchet encryption)
    MessageData = #{
        to => ToUsername,
        message => #{
            % Temporary - will be ratchet message
            type => <<"plaintext">>,
            content => Message,
            timestamp => erlang:system_time(millisecond)
        }
    },

    % Use send_encrypted message type for now
    {ok, WSMessage} = cryptic_messages:send_encrypted(MessageData),

    case CallbackModule:send_message_to_server(Username, WSMessage, Context) of
        {ok, UpdatedContext} ->
            FinalState = State#cryptic_engine_state{
                callback_context = UpdatedContext,
                message_count = State#cryptic_engine_state.message_count + 1
            },
            log_info("Message sent to ~s", [ToUsername], FinalState),
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
    end.

%% @private
generate_request_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

%% @private
generate_message_id() ->
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
            % Reply OK to all pending message calls (they were queued successfully)
            lists:foreach(
                fun(#pending_message{from = From}) ->
                    case From of
                        undefined ->
                            % No one to reply to
                            ok;
                        _ ->
                            gen_server:reply(From, ok)
                    end
                end,
                Messages
            ),

            % Remove pending messages for this user
            UpdatedPendingMessages = maps:remove(Username, PendingMessages),
            State#cryptic_engine_state{
                pending_messages = UpdatedPendingMessages,
                error_count =
                    State#cryptic_engine_state.error_count + length(Messages)
            }
    end.
