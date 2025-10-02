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

%% Records
-record(cryptic_engine_state, {
    % Our username
    username :: binary(),
    % Long-term identity keypair
    identity_key :: {binary(), binary()},
    % Signed prekey (ID, Pub, Priv)
    signed_prekey :: {integer(), binary(), binary()},
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
                    log_error("Prekey bundle upload failed: ~p",
                             [Reason], StateWithKeys),
                    {stop, {upload_failed, Reason}}
            end;
        {error, Reason, _Context} ->
            log_error("Loading identity keys failed: ~p",
                     [Reason], InitialState),
            {stop, {load_keys_failed, Reason}}
    end.

%% @private
handle_call({send_message, _ToUsername, _Message}, _From, State) ->
    % TODO: Implement message sending
    {reply, {error, not_implemented}, State};
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
handle_info({websocket_message, _Message}, State) ->
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
    case
        CallbackModule:send_message_to_server(
            State#cryptic_engine_state.username,
            BundleMessage,
            Context
        )
    of
        {ok, UpdatedContext} ->
            {ok, State#cryptic_engine_state{callback_context = UpdatedContext}};
        {error, Reason} ->
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
    CallbackModule:log_message(Level, {FormatString, Args}, Context).
