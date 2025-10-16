%%% @doc Cryptic Server
%%%
%%% This module implements the main server for the Cryptic chat application
%%% using the gen_server behavior. It provides server lifecycle management,
%%% WebSocket mTLS server initialization, and ETS table management for
%%% user connections and message storage.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Gen_server-based server lifecycle management</li>
%%%   <li>WebSocket mTLS server startup and configuration</li>
%%%   <li>ETS table creation and cleanup for data storage</li>
%%%   <li>Environment-based configuration management</li>
%%%   <li>SSL certificate path resolution</li>
%%%   <li>Cowboy HTTP/WebSocket server management</li>
%%%   <li>Event management system integration</li>
%%% </ul>
%%%
%%% == Configuration ==
%%%
%%% The server supports configuration through application environment variables:
%%% <ul>
%%%   <li>`websocket_mtls_enabled' - Enable/disable WebSocket mTLS server</li>
%%%   <li>`websocket_mtls_port' - Port for WebSocket server (default: 8443)</li>
%%% </ul>
%%%
%%% SSL certificate paths can be configured via environment variables:
%%% <ul>
%%%   <li>`CRYPTIC_SERVER_CERT' - Server certificate file path</li>
%%%   <li>`CRYPTIC_SERVER_KEY' - Server private key file path</li>
%%%   <li>`CRYPTIC_CA_CERT' - Certificate Authority certificate file path</li>
%%% </ul>
%%%
%%% == ETS Tables ==
%%%
%%% The server manages several ETS tables for runtime data:
%%% <ul>
%%%   <li>`user_connections' - Active WebSocket connections (set, public)</li>
%%%   <li>`blobs' - Stored messages and data (bag, public)</li>
%%% </ul>
%%%
%%% == WebSocket Server ==
%%%
%%% When enabled, starts a Cowboy-based WebSocket server with:
%%% <ul>
%%%   <li>Mutual TLS (mTLS) client certificate authentication</li>
%%%   <li>WebSocket upgrade endpoint at `/ws'</li>
%%%   <li>Static file serving for web interface</li>
%%%   <li>Configurable timeouts and frame size limits</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_server).

-behaviour(gen_server).

%% API
-export([start_link/0, start_websocket_mtls/0, start_websocket_mtls/1]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_continue/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("cryptic.hrl").

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Starts the server
%%
%% Starts the Cryptic server as a gen_server process registered locally
%% under the module name. This function is typically called by a supervisor
%% as part of the application startup sequence.
%%
%% @returns {ok, Pid} if successful, {error, Reason} if startup fails
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Start WebSocket mTLS server with default configuration
%%
%% Convenience function to start the WebSocket server with default
%% settings. Equivalent to calling start_websocket_mtls(#{}).
%%
%% @returns {ok, started} if successful, {error, Reason} if startup fails
%% @see start_websocket_mtls/1
start_websocket_mtls() ->
    start_websocket_mtls(#{}).

%% @doc Start WebSocket mTLS server with custom configuration
%%
%% Starts a Cowboy-based WebSocket server with mutual TLS authentication.
%% The server supports client certificate authentication and provides
%% WebSocket endpoints for real-time messaging. Configuration options
%% include port settings and SSL certificate paths.
%%
%% == Configuration Options ==
%%%
%% <ul>
%%%   <li>`port' - Server port (default: 8443)</li>
%%%   <li>`certfile' - Server certificate file path</li>
%%%   <li>`keyfile' - Server private key file path</li>
%%%   <li>`cacertfile' - CA certificate file path</li>
%% </ul>
%%
%% == Environment Variables ==
%%
%% SSL certificate paths can be overridden with environment variables:
%% <ul>
%%%   <li>`CRYPTIC_SERVER_CERT' - Server certificate path</li>
%%%   <li>`CRYPTIC_SERVER_KEY' - Server private key path</li>
%%%   <li>`CRYPTIC_CA_CERT' - CA certificate path</li>
%% </ul>
%%
%% == ETS Tables ==
%%
%% Creates and manages ETS tables for runtime data storage:
%% <ul>
%%%   <li>`user_connections' - WebSocket connection tracking</li>
%%%   <li>`blobs' - Message and data blob storage</li>
%% </ul>
%%
%% @param Config Configuration map with optional settings
%% @returns {ok, started} if successful, {error, Reason} if startup fails

start_websocket_mtls(Config) ->
    application:ensure_all_started(cowboy),
    application:ensure_all_started(ssl),

    %% Get port from environment variable or config or default
    Port =
        case os:getenv("CRYPTIC_SERVER_PORT") of
            false ->
                maps:get(port, Config, 8443);
            PortStr ->
                list_to_integer(PortStr)
        end,

    %% Get certificate paths from environment variables or defaults
    PrivDir = code:priv_dir(cryptic),
    CertFile =
        case os:getenv("CRYPTIC_SERVER_CERT") of
            false ->
                maps:get(
                    certfile,
                    Config,
                    filename:join([PrivDir, "ssl", "server.crt"])
                );
            EnvCert ->
                EnvCert
        end,
    KeyFile =
        case os:getenv("CRYPTIC_SERVER_KEY") of
            false ->
                maps:get(
                    keyfile,
                    Config,
                    filename:join([PrivDir, "ssl", "server.key"])
                );
            EnvKey ->
                EnvKey
        end,
    CACertFile =
        case os:getenv("CRYPTIC_CA_CERT") of
            false ->
                maps:get(
                    cacertfile,
                    Config,
                    filename:join([PrivDir, "ssl", "ca.crt"])
                );
            EnvCA ->
                EnvCA
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

    {ok, _} = cowboy:start_tls(
        cryptic_ws_listener,
        [{port, Port}] ++ TLSOptions,
        #{
            env => #{dispatch => Dispatch},
            % 5 minute WebSocket timeout
            websocket_timeout => 300000,
            % 64KB max frame
            websocket_max_frame_size => 65536
        }
    ),

    io:format("Cryptic WebSocket server with mTLS started on port ~p~n", [Port]),
    {ok, started}.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @doc Initializes the server
%%
%% Called by gen_server when the server process is started. Sets up
%% process flags for proper termination handling and schedules
%% continuation for server startup logic.
%%
%% @param Args Initialization arguments (empty list)
%% @returns {ok, State, {continue, start_server}} to continue initialization
init([]) ->
    process_flag(trap_exit, true),
    {ok, #{}, {continue, start_server}}.

%% @doc Handle continuation after initialization
%%
%% Called after init/1 to complete server startup. Sets up event
%% handlers and proceeds with the main server configuration.
%%
%% @param start_server Continuation atom indicating startup phase
%% @param CfgMap Current configuration map
%% @returns {noreply, State, {continue, continue}} to proceed with startup
handle_continue(start_server, CfgMap) ->
    %% Setup event handlers for Cryptic events with server configuration
    cryptic_event_manager:setup_event_handlers(#{
        log_type => server,
        log_dir => "logs"
    }),
    % Allow time for event manager setup
    sleep(10),

    continue(CfgMap).

%% @doc Internal sleep function
%%
%% Simple sleep implementation using selective receive with timeout.
%% Used for timing delays during server initialization.
%%
%% @param T Sleep time in milliseconds
%% @returns ok

sleep(T) ->
    receive
    after T -> ok
    end.

%% @doc Continue server initialization
%%
%% Completes the server startup process by creating ETS tables,
%% checking configuration, and optionally starting the WebSocket
%% mTLS server based on application environment settings.
%%
%% == ETS Tables Created ==
%%
%% <ul>
%%%   <li>`blobs' - Named bag table for message storage</li>
%% </ul>
%%
%% == WebSocket Server Startup ==
%%
%% Checks application environment for `websocket_mtls_enabled' setting
%% and starts the WebSocket server if enabled. Port configuration
%% is read from `websocket_mtls_port' (default: 8443).
%%
%% @param CfgMap Configuration map
%% @returns {noreply, State} after completing initialization

continue(CfgMap) ->

    %% Create user connections ETS table
    [ets:new(Table, [named_table, set, public]) || Table <- ets_tables()],

    %% FIXME ugly !
    %% Give time for application environment to be fully available
    sleep(100),

    %% Optionally start WebSocket mTLS server
    io:format("Checking WebSocket mTLS configuration...~n"),
    WSEnabled =
        case application:get_env(cryptic, websocket_mtls_enabled) of
            {ok, true} ->
                ?info("WebSocket mTLS enabled in config~n", []),
                true;
            {ok, false} ->
                ?info("WebSocket mTLS explicitly disabled in config~n", []),
                false;
            undefined ->
                ?info(
                    "WebSocket mTLS not configured, defaulting to disabled~n",
                    []
                ),
                false;
            Other ->
                ?info("WebSocket mTLS config value: ~p~n", [Other]),
                false
        end,
    case WSEnabled of
        true ->
            WSPort =
                case application:get_env(cryptic, websocket_mtls_port) of
                    {ok, Port} -> Port;
                    undefined -> 8443
                end,
            ?info("Starting WebSocket mTLS server on port ~p~n", [WSPort]),
            start_websocket_mtls(#{port => WSPort});
        false ->
            ?info("WebSocket mTLS server disabled~n", [])
    end,

    {noreply, CfgMap}.

ets_tables() ->
    [user_connections, cryptic_users, cryptic_messages, cryptic_prekeys].

%% @doc Handling call messages
%%
%% Processes synchronous gen_server calls. Currently returns a default
%% response as no specific call handling is implemented.
%%
%% @param Request The call request (ignored)
%% @param From The caller's identifier (ignored)
%% @param State Current server state
%% @returns {reply, Reply, State} with ok reply
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @doc Handling cast messages
%%
%% Processes asynchronous gen_server casts. Currently no specific
%% cast handling is implemented.
%%
%% @param Msg The cast message (ignored)
%% @param State Current server state
%% @returns {noreply, State}
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @doc Handling all non call/cast messages
%%
%% Processes other types of messages sent to the gen_server process.
%% Currently no specific message handling is implemented.
%%
%% @param Info The info message (ignored)
%% @param State Current server state
%% @returns {noreply, State}
handle_info(_Info, State) ->
    {noreply, State}.

%% @doc Server termination cleanup
%%
%% Called by gen_server when the server is about to terminate.
%% Performs cleanup operations including stopping the WebSocket
%% server and deleting ETS tables to ensure proper resource cleanup.
%%
%% == Cleanup Operations ==
%%
%% <ul>
%%%   <li>Stop Cowboy WebSocket listener</li>
%%%   <li>Delete user_connections ETS table</li>
%%%   <li>Delete blobs ETS table</li>
%% </ul>
%%
%% @param Reason Termination reason (ignored)
%% @param State Final server state (ignored)
%% @returns ok
terminate(_Reason, _State) ->
    %% Stop WebSocket mTLS server (if it was started)
    catch cowboy:stop_listener(cryptic_ws_listener),

    %% Clean up ETS tables
    catch ets:delete(user_connections),
    catch ets:delete(blobs),

    ok.

%% @doc Convert process state when code is changed
%%
%% Called during hot code upgrades to convert the server state
%% from the old version to the new version. Currently performs
%% no state transformation.
%%
%% @param OldVsn Previous version identifier (ignored)
%% @param State Current server state
%% @param Extra Additional upgrade information (ignored)
%% @returns {ok, State} with unchanged state
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
