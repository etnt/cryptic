-module(cryptic_server).

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
    % create ETS stores
    ets:new(prekeys, [named_table, public, set]),
    ets:new(blobs, [named_table, public, bag]),
    start_http(),
    {ok, self()}.

stop(_State) ->
    ok.

start_http() ->
    Dispatch =
        cowboy_router:compile([{'_',
                                [{"/upload_prekey/:user_id", cryptic_handlers, upload_prekey},
                                 {"/get_prekey/:user_id", cryptic_handlers, get_prekey},
                                 {"/send_blob", cryptic_handlers, send_blob},
                                 {"/recv_blobs/:user_id", cryptic_handlers, recv_blobs}]}]),
    {ok, _} =
        cowboy:start_clear(http_listener,
                           [{port, 8080}],
                           #{env => #{dispatch => Dispatch}}),
    io:format("Server running at http://localhost:8080~n"),
    ok.
