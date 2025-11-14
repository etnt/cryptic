-module(cryptic_rpc).

-include("cryptic.hrl").

-export([engine_status/0,
         list_users/0,
         online_users/0,
         send_message/1,
         send_to_bus/1,
         load_recent_messages/3,
         load_messages_before/4,
         load_messages_range/4
        ]).


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
                    ?info("~p: Message sent to Engine successfully~n", [?MODULE]),
                    ok;
                {error, Reason} ->
                    ?error("~p: Failed to send message to Engine: ~p~n", [?MODULE, Reason]),
                    {error, Reason}
            end
    end.


engine_status() ->
    case get_engine_pid() of
        undefined ->
            ?error("~p: Cannot get engine status, Engine PID unknown~n", [?MODULE]),
            {error, no_engine_pid};

        EnginePid when is_pid(EnginePid) ->
            ?dbg("~p: Returning engine status~n", [?MODULE]),
            case cryptic_engine:get_engine_status(EnginePid) of
                {ok, Status} ->
                    {ok, jsx:encode(Status)};
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
    cryptic_console ! {get_engine_pid, self()},
    receive
        {engine_pid, Pid} ->
            Pid
    after 3000 ->
        ?error("~p: could not get the Engine Pid!~n", [?MODULE]),
        undefined
    end.
