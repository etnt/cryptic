%%% @doc Cryptic Console Callbacks - Callback implementation for console interface
%%%
%%% This module implements the cryptic_engine callback behavior for the console.
%%% It provides simple implementations for storage, network, and UI operations.
%%%
-module(cryptic_console_callbacks).

-behaviour(cryptic_engine).

%% Callback exports for cryptic_engine behavior
-export([
    load_identity_keys/2,
    save_identity_keys/3,
    load_session_state/3,
    save_session_state/4,
    send_message_to_peer/4,
    send_message_to_server/3,
    deliver_message/4,
    system_message/2,
    message_undeliverable/5,
    log_message/3,
    life_cycle/4
]).

-include("cryptic.hrl").

%%%===================================================================
%%% Storage Operations
%%%===================================================================

%% @doc Load identity keys for a user
load_identity_keys(Username, Context) when is_binary(Username) andalso
                                           is_map(Context) ->
   Passphrase = maps:get(passphrase, Context),
   ServerHost = maps:get(server_host, Context, "localhost"),
   ServerPort = maps:get(server_port, Context, 8443),
   maybe
       ConfigDir = cryptic_lib:get_cryptic_dir(Username, ServerHost, ServerPort),
       {ok, RawKeys} ?= cryptic_lib:initialize_client_keys(ConfigDir, Passphrase),

       % Transform the format to what cryptic_engine expects
       EngineKeys = #{
           identity_sign_key => {
               maps:get(identity_sign_public, RawKeys),
               maps:get(identity_sign_private, RawKeys)
           },
           identity_dh_key => {
               maps:get(identity_dh_public, RawKeys),
               maps:get(identity_dh_private, RawKeys)
           },
           signed_prekey => {
               maps:get(key_id, RawKeys),
               maps:get(signed_prekey_public, RawKeys),
               maps:get(signed_prekey_private, RawKeys)
           },
           signed_prekey_signature => maps:get(signed_prekey_signature, RawKeys),
           one_time_prekeys => transform_one_time_prekeys(maps:get(one_time_prekeys, RawKeys))
       },

       {ok, EngineKeys, Context}
   else
       {error, Error} ->
           {error, Error, Context}
   end.

%% @doc Save identity keys for a user
save_identity_keys(Username, _IdentityKeys, Context) when
    is_binary(Username), is_map(Context)
->
    {ok, UpdatedContext} = log_message(
        debug, {"Saving identity keys for ~s (no-op)", [Username]}, Context
    ),
    {ok, UpdatedContext}.

%% @doc Load session state for a peer
load_session_state(Username, PeerUsername, Context) when
    is_binary(Username), is_binary(PeerUsername), is_map(Context)
->
    Passphrase = maps:get(passphrase, Context),
    ServerHost = maps:get(server_host, Context, "localhost"),
    ServerPort = maps:get(server_port, Context, 8443),
    
    % Build sessions directory path
    ConfigDir = cryptic_lib:get_cryptic_dir(Username, ServerHost, ServerPort),
    SessionsDir = filename:join(ConfigDir, "sessions"),
    
    % Try to load session for this peer
    PeerUsernameStr = binary_to_list(PeerUsername),
    case cryptic_lib:load_ratchet_session(PeerUsernameStr, Passphrase, SessionsDir) of
        {ok, SessionState} ->
            {ok, UpdatedContext} = log_message(
                info,
                {"Loaded session state for ~s <-> ~s", [
                    Username, PeerUsername
                ]},
                Context
            ),
            {ok, SessionState, UpdatedContext};
        {error, _Reason} ->
            {ok, UpdatedContext} = log_message(
                debug,
                {"No existing session state for ~s <-> ~s", [
                    Username, PeerUsername
                ]},
                Context
            ),
            {error, not_found, UpdatedContext}
    end.

%% @doc Save session state for a peer
save_session_state(Username, PeerUsername, SessionState, Context) when
    is_binary(Username), is_binary(PeerUsername), is_map(Context)
->
    Passphrase = maps:get(passphrase, Context),
    ServerHost = maps:get(server_host, Context, "localhost"),
    ServerPort = maps:get(server_port, Context, 8443),

    % Build sessions directory path
    ConfigDir = cryptic_lib:get_cryptic_dir(Username, ServerHost, ServerPort),
    SessionsDir = filename:join(ConfigDir, "sessions"),

    % Save session for this peer
    PeerUsernameStr = binary_to_list(PeerUsername),
    case cryptic_lib:save_ratchet_session(PeerUsernameStr, SessionState, Passphrase, SessionsDir) of
        ok ->
            {ok, UpdatedContext} = log_message(
                debug,
                {"Saved session state for ~s <-> ~s", [
                    Username, PeerUsername
                ]},
                Context
            ),
            {ok, UpdatedContext};
        {error, Reason} ->
            {ok, UpdatedContext} = log_message(
                error,
                {"Failed to save session state for ~s <-> ~s: ~p", [
                    Username, PeerUsername, Reason
                ]},
                Context
            ),
            {error, Reason, UpdatedContext}
    end.

%%%===================================================================
%%% Network Operations
%%%===================================================================

%% @doc Send message to a specific peer
send_message_to_peer(FromUsername, ToUsername, Message, Context) when
    is_binary(FromUsername), is_binary(ToUsername), is_map(Context)
->
    {ok, UpdatedContext1} = log_message(
        info,
        {"Sending message from ~s to ~s (no-op)", [
            FromUsername, ToUsername
        ]},
        Context
    ),
    {ok, UpdatedContext2} = log_message(
        debug, {"Message: ~p", [Message]}, UpdatedContext1
    ),
    {ok, UpdatedContext2}.

%% @doc Send message to server
send_message_to_server(FromUsername, Message, Context) when
    is_binary(FromUsername), is_map(Context)
->
    {ok, UpdatedContext1} = log_message(
        info, {"Sending message from ~s to server", [FromUsername]}, Context
    ),
    {ok, UpdatedContext2} = log_message(
        debug, {"Message: ~p", [Message]}, UpdatedContext1
    ),

    case maps:get(ws_client_pid, UpdatedContext2, undefined) of
        undefined ->
            {ok, UpdatedContext3} = log_message(
                error, {"No WebSocket client available", []}, UpdatedContext2
            ),
            {error, no_ws_client, UpdatedContext3};
        WSClientPid when is_pid(WSClientPid) ->
            case cryptic_ws_client:send_message(WSClientPid, Message) of
                ok ->
                    log_message(
                        debug,
                        {"Message sent successfully", []},
                        UpdatedContext2
                    );
                {error, Reason} ->
                    {ok, UpdatedContext3} = log_message(
                        error,
                        {"Failed to send message: ~p", [Reason]},
                        UpdatedContext2
                    ),
                    {error, Reason, UpdatedContext3}
            end
    end.

%%%===================================================================
%%% UI Operations
%%%===================================================================

%% @doc Deliver message to UI
deliver_message(FromUsername, Message, Timestamp, Context)
  when is_list(FromUsername) andalso is_binary(Message) andalso
       is_map(Context) ->
    ConsolePid = maps:get(console_pid, Context),
    ConsolePid ! {deliver_message, FromUsername, Message, Timestamp},
    {ok, Context}.

system_message(Message, Context) when is_binary(Message), is_map(Context) ->
    % Send message to console process for proper handling
    case maps:get(console_pid, Context, undefined) of
        undefined ->
            % Fallback: print directly if no console PID
            io:format("\r\n"),
            cryptic_shell:print_info(binary_to_list(Message));
        ConsolePid when is_pid(ConsolePid) ->
            % Send to console process for async handling
            ConsolePid ! {system_message, Message}
    end,
    {ok, Context}.

%% @doc Handle undeliverable messages
message_undeliverable(ToUsername, MessageId, MessageText, Reason, Context) when
    is_binary(ToUsername), is_binary(MessageId), is_binary(MessageText),
    is_map(Context)
->
    % Log the undeliverable message
    {ok, UpdatedContext1} = log_message(
        warning,
        {"Message ~s to ~s undeliverable: ~p", [MessageId, ToUsername, Reason]},
        Context
    ),
    
    % Optionally notify user via system message
    SystemMsg = iolist_to_binary([
        <<"Message to ">>, ToUsername,
        <<" could not be delivered: ">>,
        format_undeliverable_reason(Reason),
        <<" (\"">>, MessageText, <<"\")">>
    ]),
    
    case maps:get(console_pid, UpdatedContext1, undefined) of
        undefined ->
            io:format("\r\n[UNDELIVERABLE] ~s~n", [SystemMsg]);
        ConsolePid when is_pid(ConsolePid) ->
            ConsolePid ! {system_message, SystemMsg}
    end,
    
    {ok, UpdatedContext1}.

%% @doc Log message
log_message(Level, {_FormatString, _Args} = Msg, Context) when
    is_atom(Level) andalso is_list(_FormatString) andalso
        is_list(_Args) andalso is_map(Context)
->
    log(Level, Msg),
    {ok, Context}.

%% @private
log(Level, {_FormatString, _Args} = Msg) when
    is_atom(Level) andalso is_list(_FormatString) andalso
        is_list(_Args)
->
    cryptic_event_manager:notify(Level, Msg),
    ok.

%% @doc Lifecycle events
life_cycle(Event, Reason, Username, Context) when
    is_atom(Event), is_binary(Username), is_map(Context)
->
    {ok, UpdatedContext} = log_message(
        info, {"~s: ~p (reason: ~p)", [Username, Event, Reason]}, Context
    ),
    {ok, UpdatedContext}.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @doc Format undeliverable message reason for user display
format_undeliverable_reason(user_not_found) ->
    <<"user not found">>;
format_undeliverable_reason({x3dh_failed, _}) ->
    <<"encryption failed">>;
format_undeliverable_reason({ratchet_init_failed, _}) ->
    <<"session initialization failed">>;
format_undeliverable_reason({send_failed, _}) ->
    <<"network error">>;
format_undeliverable_reason(Reason) ->
    iolist_to_binary(io_lib:format("~p", [Reason])).

%% @doc Transform one-time prekeys from cryptic_lib format to engine format
transform_one_time_prekeys(OTPKeys) ->
    lists:map(
        fun(#{id := Id, public := Public, private := Private}) ->
            #{
                id => Id,
                public => Public,
                private => Private
            }
        end,
        OTPKeys
    ).
