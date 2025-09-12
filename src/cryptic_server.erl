-module(cryptic_server).

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1
    , handle_call/3
    , handle_cast/2
    , handle_continue/2
    , handle_info/2
    , terminate/2
    , code_change/3]).

-include("cryptic.hrl").

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Starts the server
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @doc Initializes the server
init([]) ->
     process_flag(trap_exit, true),
    {ok, #{}, {continue, start_server}}.

handle_continue(start_server, CfgMap) ->
    %% Setup event handlers for Cryptic events
    cryptic_event_manager:setup_event_handlers(),
    % Allow time for event manager setup
    sleep(1),

    continue(
        cryptic_app:get_config(
            [
                server_port
            ],
            CfgMap
        )
    ).

sleep(T) ->
    receive
    after T -> ok
    end.

continue(CfgMap) ->
    %% Create ETS stores
    ets:new(prekeys, [named_table, public, set]),
    ets:new(blobs, [named_table, public, bag]),

    %% Start HTTP server
    start_http(CfgMap),

    {noreply, CfgMap}.

%% @doc Handling call messages
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @doc Handling cast messages
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @doc Handling all non call/cast messages
handle_info(_Info, State) ->
    {noreply, State}.

%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up.
terminate(_Reason, _State) ->
    %% Stop HTTP server
    cowboy:stop_listener(http_listener),

    %% Clean up ETS tables
    catch ets:delete(prekeys),
    catch ets:delete(blobs),

    ok.

%% @doc Convert process state when code is changed
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

start_http(CfgMap) ->
    Port = maps:get(server_port, CfgMap, 8080),
    Dispatch =
        cowboy_router:compile([{'_',
                                [{"/upload_prekey/:user_id", cryptic_handlers, upload_prekey},
                                 {"/get_prekey/:user_id", cryptic_handlers, get_prekey},
                                 {"/send_blob", cryptic_handlers, send_blob},
                                 {"/recv_blobs/:user_id", cryptic_handlers, recv_blobs},
                                 {"/list_users", cryptic_handlers, list_users}]}]),
    {ok, _} =
        cowboy:start_clear(http_listener,
                           [{port, Port}],
                           #{env => #{dispatch => Dispatch}}),
    ?dbg("Server running at http://localhost:~p~n", [Port]),
    ok.
