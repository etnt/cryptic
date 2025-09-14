-module(cryptic_server).

-behaviour(gen_server).

%% API
-export([start_link/0, start_websocket_mtls/0, start_websocket_mtls/1]).

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

%% @doc Start WebSocket mTLS server
start_websocket_mtls() ->
    start_websocket_mtls(#{}).

start_websocket_mtls(Config) ->
    application:ensure_all_started(cowboy),
    application:ensure_all_started(ssl),
    
    %% Clean up any existing tables first
    catch ets:delete(user_connections),
    catch ets:delete(prekeys),
    catch ets:delete(blobs),
    
    %% Create user connections ETS table
    ets:new(user_connections, [named_table, set, public]),
    
    %% Create ETS stores for prekeys and blobs
    ets:new(prekeys, [named_table, public, set]),
    ets:new(blobs, [named_table, public, bag]),
    
    Port = maps:get(port, Config, 8443),
    
    %% Get certificate paths from environment variables or defaults
    PrivDir = code:priv_dir(cryptic),
    CertFile = case os:getenv("CRYPTIC_SERVER_CERT") of
        false -> maps:get(certfile, Config, filename:join([PrivDir, "ssl", "server.crt"]));
        EnvCert -> EnvCert
    end,
    KeyFile = case os:getenv("CRYPTIC_SERVER_KEY") of
        false -> maps:get(keyfile, Config, filename:join([PrivDir, "ssl", "server.key"]));
        EnvKey -> EnvKey
    end,
    CACertFile = case os:getenv("CRYPTIC_CA_CERT") of
        false -> maps:get(cacertfile, Config, filename:join([PrivDir, "ssl", "ca.crt"]));
        EnvCA -> EnvCA
    end,
    
    %% WebSocket route
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/ws", cryptic_ws_handler, []},
            {"/", cowboy_static, {priv_file, cryptic, "index.html"}}
        ]}
    ]),
    
    %% TLS options with client certificate verification
    TLSOptions = [
        {verify, verify_peer},
        {fail_if_no_peer_cert, true},
        {log_level, info},
        {versions, ['tlsv1.2']},
        {cacertfile, CACertFile},
        {certfile, CertFile},
        {keyfile, KeyFile}
    ],
    
    io:format("Starting WebSocket mTLS server on port ~p~n", [Port]),
    io:format("Using certificates:~n"),
    io:format("  CA: ~s~n", [CACertFile]),
    io:format("  Cert: ~s~n", [CertFile]),
    io:format("  Key: ~s~n", [KeyFile]),
    
    {ok, _} = cowboy:start_tls(cryptic_ws_listener, 
                               [{port, Port}] ++ TLSOptions, 
                               #{env => #{dispatch => Dispatch},
                                 websocket_timeout => 300000,  % 5 minute WebSocket timeout
                                 websocket_max_frame_size => 65536  % 64KB max frame
                               }),
    
    io:format("Cryptic WebSocket server with mTLS started on port ~p~n", [Port]),
    {ok, started}.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @doc Initializes the server
init([]) ->
     process_flag(trap_exit, true),
    {ok, #{}, {continue, start_server}}.

handle_continue(start_server, CfgMap) ->
    %% Setup event handlers for Cryptic events with server configuration
    cryptic_event_manager:setup_event_handlers(#{log_type => server, log_dir => "logs"}),
    % Allow time for event manager setup
    sleep(1),

    continue(CfgMap).

sleep(T) ->
    receive
    after T -> ok
    end.

continue(CfgMap) ->
    %% Create ETS stores
    ets:new(prekeys, [named_table, public, set]),
    ets:new(blobs, [named_table, public, bag]),

    %% Give time for application environment to be fully available
    timer:sleep(100),
    
    %% Optionally start WebSocket mTLS server
    io:format("Checking WebSocket mTLS configuration...~n"),
    WSEnabled = case application:get_env(cryptic, websocket_mtls_enabled) of
        {ok, true} -> 
            io:format("WebSocket mTLS enabled in config~n"),
            true;
        {ok, false} ->
            io:format("WebSocket mTLS explicitly disabled in config~n"),
            false;
        undefined ->
            io:format("WebSocket mTLS not configured, defaulting to disabled~n"),
            false;
        Other ->
            io:format("WebSocket mTLS config value: ~p~n", [Other]),
            false
    end,
    case WSEnabled of
        true ->
            WSPort = case application:get_env(cryptic, websocket_mtls_port) of
                {ok, Port} -> Port;
                undefined -> 8443
            end,
            io:format("Starting WebSocket mTLS server on port ~p~n", [WSPort]),
            start_websocket_mtls(#{port => WSPort});
        false ->
            io:format("WebSocket mTLS server disabled~n")
    end,

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
    %% Stop WebSocket mTLS server (if it was started)
    catch cowboy:stop_listener(cryptic_ws_listener),

    %% Clean up ETS tables
    catch ets:delete(user_connections),
    catch ets:delete(prekeys),
    catch ets:delete(blobs),

    ok.

%% @doc Convert process state when code is changed
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
