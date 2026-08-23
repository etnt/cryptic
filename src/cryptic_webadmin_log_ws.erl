%% @doc Cryptic Web Admin - live server log WebSocket.
%%
%% A session-authenticated `cowboy_websocket' handler that streams the server
%% log to the browser. On connect it sends the last N lines (`?tail='), then
%% polls the log file and pushes newly appended lines as they arrive.
%%
%% Authentication reuses the admin session cookie: the HTTP upgrade request
%% must carry a valid `cryptic_admin_sid'. Unauthenticated upgrades are
%% rejected with `401' before the socket is established. No CSRF token is
%% required (the WebSocket is read-only and same-origin).
%%
%% Wire protocol (server → client, JSON text frames):
%% <ul>
%%   <li>`{"type":"backfill","lines":[{"n":Int,"text":Str}],"total":Int}'</li>
%%   <li>`{"type":"append","lines":[{"n":Int,"text":Str}]}'</li>
%%   <li>`{"type":"error","message":Str}'</li>
%% </ul>
%% Client → server: any text frame acts as a keep-alive; `{"type":"ping"}' is
%% the conventional heartbeat.
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_webadmin_log_ws).

-behaviour(cowboy_websocket).

-export([init/2,
         websocket_init/1,
         websocket_handle/2,
         websocket_info/2,
         terminate/3]).

-define(DEFAULT_TAIL, 200).
-define(MAX_TAIL, 2000).
-define(POLL_INTERVAL_MS, 1500).
-define(IDLE_TIMEOUT_MS, 120000).

%%====================================================================
%% HTTP upgrade: authenticate before establishing the socket
%%====================================================================

init(Req, _State) ->
    CookieValue = session_cookie(Req),
    case cryptic_admin_session:validate(CookieValue) of
        {ok, User, _Csrf} ->
            Tail = tail_param(Req),
            State = #{user => User, tail => Tail, offset => 0, next_n => 1},
            {cowboy_websocket, Req, State,
             #{idle_timeout => ?IDLE_TIMEOUT_MS}};
        {error, _} ->
            Reply = cowboy_req:reply(
                401,
                #{<<"content-type">> => <<"application/json">>},
                jsx:encode(#{status => <<"error">>,
                             message => <<"unauthorized">>}),
                Req),
            {ok, Reply, undefined}
    end.

%%====================================================================
%% WebSocket lifecycle
%%====================================================================

websocket_init(#{tail := Tail} = State) ->
    case cryptic_webadmin_log:read_last_lines(Tail) of
        {ok, Lines, Total, Offset} ->
            Frame = jsx:encode(#{type => <<"backfill">>,
                                 lines => Lines,
                                 total => Total}),
            schedule_poll(),
            NextN = Total + 1,
            {[{text, Frame}], State#{offset => Offset, next_n => NextN}};
        {error, Reason} ->
            Frame = jsx:encode(#{type => <<"error">>,
                                 message => reason_text(Reason)}),
            schedule_poll(),
            {[{text, Frame}], State}
    end.

%% Client frames are keep-alives; nothing to process, just stay connected.
websocket_handle({text, _Msg}, State) ->
    {ok, State};
websocket_handle({ping, _}, State) ->
    {ok, State};
websocket_handle(_Frame, State) ->
    {ok, State}.

websocket_info(poll, #{offset := Offset, next_n := NextN} = State) ->
    case cryptic_webadmin_log:read_delta(Offset, NextN) of
        {ok, [], NewOffset, NewNextN} ->
            schedule_poll(),
            {ok, State#{offset => NewOffset, next_n => NewNextN}};
        {ok, Lines, NewOffset, NewNextN} ->
            Frame = jsx:encode(#{type => <<"append">>, lines => Lines}),
            schedule_poll(),
            {[{text, Frame}], State#{offset => NewOffset, next_n => NewNextN}};
        {error, _Reason} ->
            %% Transient read error (e.g. mid-rotation): keep polling quietly.
            schedule_poll(),
            {ok, State}
    end;
websocket_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, _Req, _State) ->
    ok.

%%====================================================================
%% Helpers
%%====================================================================

schedule_poll() ->
    erlang:send_after(?POLL_INTERVAL_MS, self(), poll).

session_cookie(Req) ->
    Cookies = cowboy_req:parse_cookies(Req),
    proplists:get_value(cryptic_admin_session:cookie_name(), Cookies).

tail_param(Req) ->
    Qs = cowboy_req:parse_qs(Req),
    case proplists:get_value(<<"tail">>, Qs) of
        undefined -> ?DEFAULT_TAIL;
        Bin ->
            try binary_to_integer(Bin) of
                N when N > 0, N =< ?MAX_TAIL -> N;
                N when N > ?MAX_TAIL -> ?MAX_TAIL;
                _ -> ?DEFAULT_TAIL
            catch
                _:_ -> ?DEFAULT_TAIL
            end
    end.

reason_text(Reason) when is_atom(Reason) -> atom_to_binary(Reason, utf8);
reason_text(Reason) -> iolist_to_binary(io_lib:format("~p", [Reason])).
