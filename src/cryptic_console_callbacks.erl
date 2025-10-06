%%% @doc Cryptic Console Callbacks - Callback implementation for console interface
%%%
%%% This module implements the cryptic_engine callback behavior for the console.
%%% It provides simple implementations for storage, network, and UI operations.
%%%
-module(cryptic_console_callbacks).

%% Callback exports for cryptic_engine behavior
-export([
    load_identity_keys/2,
    save_identity_keys/3,
    load_session_state/3,
    save_session_state/4,
    send_message_to_peer/4,
    send_message_to_server/3,
    deliver_message/4,
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
   maybe
       ConfigDir = cryptic_lib:get_cryptic_dir(Username),
       {ok, RawKeys} ?= cryptic_lib:initialize_client_keys(ConfigDir, Passphrase),

       % Transform the format to what cryptic_engine expects
       EngineKeys = #{
           identity_key => {
               maps:get(identity_dh_public, RawKeys),
               maps:get(identity_dh_private, RawKeys)
           },
           signed_prekey => {
               maps:get(key_id, RawKeys),
               maps:get(signed_prekey_public, RawKeys),
               maps:get(signed_prekey_private, RawKeys)
           },
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
    io:format("[CALLBACK] Saving identity keys for ~s (no-op)~n", [Username]),
    {ok, Context}.

%% @doc Load session state for a peer
load_session_state(Username, PeerUsername, Context) when
    is_binary(Username), is_binary(PeerUsername), is_map(Context)
->
    io:format("[CALLBACK] Loading session state ~s <-> ~s (not found)~n", [
        Username, PeerUsername
    ]),
    {error, not_found, Context}.

%% @doc Save session state for a peer
save_session_state(Username, PeerUsername, _SessionState, Context) when
    is_binary(Username), is_binary(PeerUsername), is_map(Context)
->
    io:format("[CALLBACK] Saving session state ~s <-> ~s (no-op)~n", [
        Username, PeerUsername
    ]),
    {ok, Context}.

%%%===================================================================
%%% Network Operations
%%%===================================================================

%% @doc Send message to a specific peer
send_message_to_peer(FromUsername, ToUsername, Message, Context) when
    is_binary(FromUsername), is_binary(ToUsername), is_map(Context)
->
    io:format("[CALLBACK] Sending message from ~s to ~s (no-op)~n", [
        FromUsername, ToUsername
    ]),
    io:format("[CALLBACK] Message: ~p~n", [Message]),
    {ok, Context}.

%% @doc Send message to server
send_message_to_server(FromUsername, Message, Context) when
    is_binary(FromUsername), is_map(Context)
->
    
    {ok, Context}.

%%%===================================================================
%%% UI Operations
%%%===================================================================

%% @doc Deliver message to UI
deliver_message(FromUsername, Message, Timestamp, Context) when
    is_binary(FromUsername), is_binary(Message), is_map(Context)
->
    io:format("[MESSAGE] From ~s at ~p: ~s~n", [
        FromUsername, Timestamp, Message
    ]),
    {ok, Context}.

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
    io:format("[LIFECYCLE] ~s: ~p (reason: ~p)~n", [Username, Event, Reason]),
    {ok, Context}.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @doc Transform one-time prekeys from cryptic_lib format to engine format
transform_one_time_prekeys(OTPKeys) ->
    lists:map(
        fun(#{id := Id, public := Public, private := _Private}) ->
            #{
                id => Id,
                public => Public
            }
        end,
        OTPKeys
    ).
