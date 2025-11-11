-module(cryptic_rpc).

-include("cryptic.hrl").

-export([history/1, send_message/1, subscribe/1]).

%% Get message history with PeerId
history(_Peer) ->
    %% SQLite query here
    {ok, _Messages = []}.

%% Send encrypted outbound message
send_message(JsonMsg) ->
    %%cryptic_event_bus:publish(Payload),
    MsgMap = jsx:decode(JsonMsg, [return_maps]),
    ?info("~p:send_message: Payload: ~p~n", [?MODULE, MsgMap]),
    ok.

%% Subscribe Rust client to events
subscribe(Pid) ->
    cryptic_event_bus:subscribe(Pid),
    ok.
