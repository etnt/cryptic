-module(cryptic_rpc).

-include("cryptic.hrl").

-export([admin_register/2,
         admin_register/3,
         admin_suspend/1,
         admin_reactivate/1,
         admin_revoke/1,
         admin_list_certificates/1,
         create_admin/2,
         create_admin/3,
         count_admins/0,
         engine_status/0,
         list_users/0,
         online_users/0,
         renew_certificate/0,
         send_message/1,
         send_to_bus/1,
         load_recent_messages/3,
         load_messages_before/4,
         load_messages_range/4
        ]).



-spec renew_certificate() -> ok.
renew_certificate() ->
    cryptic_cert_renewal:renew_now().


%% @doc Bootstrap: create a web-admin account with a plaintext password.
%%
%% Intended to be invoked against a running server node (e.g. via
%% `rpc:call/4' or a remote shell) to seed the first administrator.
%% Idempotency is the caller's responsibility; an existing username
%% returns `{error, already_exists}'.
-spec create_admin(binary(), binary()) -> ok | {error, term()}.
create_admin(Username, Password) when is_binary(Username), is_binary(Password) ->
    cryptic_admin_auth:create_account(Username, Password).

%% @doc Bootstrap: create a web-admin account, optionally flagging it so the
%% UI forces a password change on first login (`MustChange :: boolean()').
-spec create_admin(binary(), binary(), boolean()) -> ok | {error, term()}.
create_admin(Username, Password, MustChange) when
    is_binary(Username), is_binary(Password), is_boolean(MustChange)
->
    cryptic_admin_auth:create_account(
        Username, Password, #{must_change_password => MustChange}
    ).

%% @doc Bootstrap helper: number of existing web-admin accounts.
-spec count_admins() -> {ok, non_neg_integer()} | {error, term()}.
count_admins() ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} -> cryptic_ca_store:count_admin_accounts(DbRef);
        _ -> {error, ca_db_ref_not_configured}
    end.


%%@doc Send register_user command via event bus
-spec admin_register(binary(), binary()) -> ok | {error, term()}.
admin_register(Fingerprint, KeyFilename) when is_binary(Fingerprint) andalso
                                              is_binary(KeyFilename) ->
    admin_register(Fingerprint, KeyFilename, _Metadata = <<"">>).

%%@doc Send register_user command via event bus
-spec admin_register(binary(), binary(), binary()) -> ok | {error, term()}.
admin_register(Fingerprint, KeyFilename, Metadata)
  when is_binary(Fingerprint) andalso
       is_binary(KeyFilename) andalso
       is_binary(Metadata) ->

    case file:read_file(KeyFilename) of
        {ok, GpgPubKey} ->
            Mtoks = string:tokens(binary_to_list(Metadata), " "),
            Opts = cryptic_console:parse_admin_register_opts(Mtoks, #{}),
            {ok, Msg} =
                cryptic_messages:register_user(
                  Fingerprint,
                  GpgPubKey,
                  Opts),

            cryptic_event_bus:publish(
              #{type => websocket_outbound,
                message => Msg
               }),
            ok;

        {error, _Reason} = Error ->
            Error
    end.


%%@doc Send suspend_user command via event bus
-spec admin_suspend(binary()) -> ok | {error, term()}.
admin_suspend(Fingerprint) when is_binary(Fingerprint) ->
    {ok, Msg} = cryptic_messages:suspend_user(Fingerprint),

    cryptic_event_bus:publish(
      #{type => websocket_outbound,
        message => Msg
       }),
    ok.

%%@doc Send reactivate_user command via event bus
-spec admin_reactivate(binary()) -> ok | {error, term()}.
admin_reactivate(Fingerprint) when is_binary(Fingerprint) ->
    {ok, Msg} = cryptic_messages:reactivate_user(Fingerprint),

    cryptic_event_bus:publish(
      #{type => websocket_outbound,
        message => Msg
       }),
    ok.

%%@doc Send revoke_user command via event bus
-spec admin_revoke(binary()) -> ok | {error, term()}.
admin_revoke(Fingerprint) when is_binary(Fingerprint) ->
    {ok, Msg} = cryptic_messages:revoke_user(Fingerprint),

    cryptic_event_bus:publish(
      #{type => websocket_outbound,
        message => Msg
       }),
    ok.

%%@doc Send list_certificates command via event bus
-spec admin_list_certificates(binary()) -> ok | {error, term()}.
admin_list_certificates(Fingerprint) when is_binary(Fingerprint) ->
    {ok, Msg} = cryptic_messages:list_certificates(Fingerprint),

    cryptic_event_bus:publish(
      #{type => websocket_outbound,
        message => Msg
       }),
    ok.



load_recent_messages(CurrentUser, Peer, Limit) ->
    cryptic_tui_bridge:get_recent_messages(CurrentUser, Peer, Limit).

load_messages_before(_CurrentUser, _Peer, _BeforeTimestamp, _Limit) ->
    tbd.

load_messages_range(_CurrentUser, _Peer, _StartTimestamp, _EndTimestamp) ->
    tbd.    

%% Send encrypted outbound message
send_message(JsonMsg) ->
    ?info("~p:send_message: JsonMsg: ~p~n", [?MODULE, JsonMsg]),
    Msg = jsx:decode(JsonMsg, [return_maps]),
    ?info("~p:send_message: Payload: ~p~n", [?MODULE, Msg]),

    ToUser = maps:get(<<"to_user">>, Msg),
    Plaintext = maps:get(<<"plaintext">>, Msg),

    case get_engine_pid() of
        undefined ->
            ?error("~p: Cannot send message, Engine PID unknown~n", [?MODULE]),
            {error, no_engine_pid};

        EnginePid when is_pid(EnginePid) ->
            ?dbg("~p: Sending message to Engine PID: ~p~n", [?MODULE, EnginePid]),
            case cryptic_engine:send_message(EnginePid,
                                             ToUser,
                                             Plaintext)
            of
                ok ->
                    ?dbg("~p: Message sent to Engine successfully~n", [?MODULE]),
                    cryptic_tui_bridge:save_outgoing_message(ToUser, Plaintext),
                    ok;
                {error, Reason} ->
                    ?error("~p: Failed to send message to Engine: ~p~n", [?MODULE, Reason]),
                    {error, Reason}
            end
    end.

-spec engine_status() -> {ok, binary()} | {error, term()}.
engine_status() ->
    case get_engine_pid() of
        undefined ->
            ?error("~p: Cannot get engine status, Engine PID unknown~n", [?MODULE]),
            {error, no_engine_pid};

        EnginePid when is_pid(EnginePid) ->
            ?dbg("~p: Returning engine status~n", [?MODULE]),
            maybe
                {ok, EngineStatus} ?= cryptic_engine:get_engine_status(EnginePid),
                CertStatus = cryptic_cert_renewal:get_status(),
                {ok, jsx:encode(maps:merge(EngineStatus, CertStatus))}
            else
                {error, _Reason} = Error ->
                    Error
            end
    end.


list_users() ->
    {ok, Msg} = cryptic_messages:list_users(),
    cryptic_event_bus:publish(#{
        type => websocket_outbound,
        message => Msg
    }),
    ok.


online_users() ->
    {ok, Msg} = cryptic_messages:online_users(),
    cryptic_event_bus:publish(#{
        type => websocket_outbound,
        message => Msg
    }),
    ok.


send_to_bus(JsonMsg) ->
    ?info("~p:send_to_bus: JsonMsg: ~p~n", [?MODULE, JsonMsg]),
    Msg = jsx:decode(JsonMsg, [return_maps]),
    ?info("~p:send_to_bus: Payload: ~p~n", [?MODULE, Msg]),

    cryptic_event_bus:publish(#{
        type => websocket_outbound,
        message => Msg
    }),
    ok.

get_engine_pid() ->
    cryptic_console ! {get_console_data, self()},
    receive
        {console_data, ConsoleData} ->
            maps:get(engine_pid, ConsoleData)
    after 3000 ->
        ?error("~p: could not get the Engine Pid!~n", [?MODULE]),
        undefined
    end.
