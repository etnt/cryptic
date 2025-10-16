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
%%%   <li>`server_host' - Server host/IP to bind to (default: "localhost")</li>
%%% </ul>
%%%
%%% SSL certificate paths can be configured via system environment variables:
%%% <ul>
%%%   <li>`CRYPTIC_SERVER_CERT' - Server certificate file path (default: CA/certs/server.crt)</li>
%%%   <li>`CRYPTIC_SERVER_KEY' - Server private key file path (default: CA/private/server.key)</li>
%%%   <li>`CRYPTIC_CA_CERT' - Certificate Authority certificate file path (default: CA/certs/ca.crt)</li>
%%%   <li>`CRYPTIC_EVENT_HANDLERS' - Event handlers to load (default: cryptic_file_logger)</li>
%%% </ul>
%%%
%%% == ETS Tables ==
%%%
%%% The server creates and manages the following ETS tables during initialization.
%%% All tables are created with `[named_table, set, public]' options:
%%%
%%% <ul>
%%%   <li>`user_connections' - Tracks active WebSocket connections
%%%       <ul>
%%%         <li>Key: Username (string)</li>
%%%         <li>Value: WebSocket connection PID</li>
%%%         <li>Purpose: Maps authenticated users to their active WebSocket connections</li>
%%%       </ul>
%%%   </li>
%%%   <li>`cryptic_users' - Stores registered user information
%%%       <ul>
%%%         <li>Key: Username (string)</li>
%%%         <li>Value: Registration timestamp (system_time in seconds)</li>
%%%         <li>Purpose: Tracks registered users and their registration times</li>
%%%       </ul>
%%%   </li>
%%%   <li>`cryptic_messages' - Message queue for offline/undelivered messages
%%%       <ul>
%%%         <li>Key: MessageId (unique identifier)</li>
%%%         <li>Value: {ToUser, MessageBlob}</li>
%%%         <li>Purpose: Stores messages for users who are offline or disconnected</li>
%%%       </ul>
%%%   </li>
%%%   <li>`cryptic_prekeys' - X3DH prekey bundles and cryptographic keys
%%%       <ul>
%%%         <li>Key formats:</li>
%%%         <ul>
%%%           <li>`{Username, identity}' - Identity key pair</li>
%%%           <li>`{Username, signed_prekey, KeyId}' - Signed prekey</li>
%%%           <li>`{Username, one_time_prekey, KeyId}' - One-time prekey (OTPK)</li>
%%%           <li>`{Username, otpk_usage, SenderUsername}' - OTPK usage tracking</li>
%%%         </ul>
%%%         <li>Purpose: Stores X3DH key material for end-to-end encryption setup</li>
%%%       </ul>
%%%   </li>
%%% </ul>
%%%
%%% Note: These tables are also used by `cryptic_lib' which provides helper
%%% functions for key management, message storage, and user operations.
%%%
%%% == WebSocket Server ==
%%%
%%% When enabled via `websocket_mtls_enabled', starts a Cowboy-based WebSocket server with:
%%% <ul>
%%%   <li>Mutual TLS (mTLS) client certificate authentication</li>
%%%   <li>WebSocket upgrade endpoint at `/ws'</li>
%%%   <li>Static file serving for web interface at `/static/[...]'</li>
%%%   <li>Configurable idle timeout (default: 600000ms = 10 minutes)</li>
%%%   <li>Maximum WebSocket frame size: 10MB (10485760 bytes)</li>
%%%   <li>TLS options: verify_peer, fail_if_no_peer_cert</li>
%%% </ul>
%%%
%%% The WebSocket handler (`cryptic_ws_handler') manages:
%%% <ul>
%%%   <li>Client authentication via mTLS certificates</li>
%%%   <li>User registration and prekey bundle upload</li>
%%%   <li>Message routing between connected users</li>
%%%   <li>Offline message queuing and delivery</li>
%%%   <li>Connection state management in `user_connections' table</li>
%%% </ul>
%%%
%%% == Server Lifecycle ==
%%%
%%% The server follows this initialization sequence:
%%% <ol>
%%%   <li>`init/1' - Sets process flags and returns continue tuple</li>
%%%   <li>`handle_continue/2' with `start_server' - Sets up event handlers</li>
%%%   <li>`continue/1' - Creates ETS tables and optionally starts WebSocket server</li>
%%% </ol>
%%%
%%% == Dependencies ==
%%%
%%% This module depends on:
%%% <ul>
%%%   <li>`cryptic_lib' - Cryptographic operations and key management</li>
%%%   <li>`cryptic_event_manager' - Event logging and monitoring</li>
%%%   <li>`cryptic_ws_handler' - WebSocket connection handling</li>
%%%   <li>`cowboy' - HTTP/WebSocket server framework</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_server).

-behaviour(gen_server).

%% API
-export([start_link/0]).

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

-include("cryptic_server.hrl").

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
%% This function:
%% <ul>
%%   <li>Creates all required ETS tables via `ets_tables/0'</li>
%%   <li>Checks the `websocket_mtls_enabled' application environment setting</li>
%%   <li>Starts the WebSocket server if enabled (default port: 8443)</li>
%%   <li>Configures Cowboy HTTP server with TLS and WebSocket routes</li>
%% </ul>
%%
%% The WebSocket server is configured with:
%% <ul>
%%   <li>Server host from `server_host' env (default: "localhost")</li>
%%   <li>Server port from `websocket_mtls_port' env (default: 8443)</li>
%%   <li>Certificate paths from environment variables or defaults</li>
%%   <li>Routes: `/ws' for WebSocket, `/static/[...]' for static files</li>
%%% </ul>
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
    ?debug("Checking WebSocket mTLS configuration...~n", []),
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

%% @doc Returns the list of ETS table names to create
%%
%% Defines all ETS tables that the Cryptic server needs for operation.
%% These tables are created during server initialization with options
%% `[named_table, set, public]'.
%%
%% Tables returned:
%% <ul>
%%   <li>`user_connections' - Maps usernames to WebSocket connection PIDs</li>
%%   <li>`cryptic_users' - Stores user registration data with timestamps</li>
%%   <li>`cryptic_messages' - Queue for offline/undelivered messages</li>
%%   <li>`cryptic_prekeys' - X3DH key bundles (identity, signed prekey, OTPKs)</li>
%% </ul>
%%
%% Note: The same tables are also accessed by `cryptic_lib' for key and
%% message management operations. The `cryptic_lib:ensure_tables/0' function
%% can also create these tables if they don't exist.
%%
%% @returns List of table names (atoms)
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

%% @doc Start WebSocket mTLS server with custom configuration
%%
%% Starts a Cowboy-based WebSocket server with mutual TLS (mTLS) authentication.
%% The server requires client certificate authentication and provides WebSocket
%% endpoints for real-time encrypted messaging.
%%
%% == Server Configuration ==
%%
%% Port Configuration (checked in order):
%% <ol>
%%   <li>System environment variable `CRYPTIC_SERVER_PORT'</li>
%%   <li>Config map `port' parameter</li>
%%   <li>Default: 8443</li>
%% </ol>
%%
%% Certificate paths are resolved from:
%% <ul>
%%   <li>System env `CRYPTIC_SERVER_CERT' or config `certfile' (default: priv/ssl/server.crt)</li>
%%   <li>System env `CRYPTIC_SERVER_KEY' or config `keyfile' (default: priv/ssl/server.key)</li>
%%   <li>System env `CRYPTIC_CA_CERT' or config `cacertfile' (default: priv/ssl/ca.crt)</li>
%%% </ul>
%%
%% == TLS Options ==
%%
%% The server is configured with:
%% <ul>
%%   <li>`verify_peer' - Requires client certificate validation</li>
%%   <li>`fail_if_no_peer_cert' - Rejects connections without client cert</li>
%%   <li>`cacertfile' - CA certificate for validating client certificates</li>
%%   <li>TLS versions: TLS 1.2 and 1.3</li>
%% </ul>
%%
%% == HTTP Routes ==
%%
%% <ul>
%%   <li>`/ws' - WebSocket upgrade endpoint (handled by `cryptic_ws_handler')</li>
%%   <li>`/static/[...]' - Static file serving from `priv/static' directory</li>
%% </ul>
%%
%% == Protocol Options ==
%%
%% <ul>
%%   <li>Idle timeout: 600000ms (10 minutes)</li>
%%   <li>Max frame size: 10485760 bytes (10MB)</li>
%%   <li>Compression enabled for WebSocket frames</li>
%% </ul>
%%
%% @param Config Configuration map with optional `port', `certfile', `keyfile', `cacertfile'
%% @returns {ok, started} on success, {error, Reason} on failure

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

    ?info("Starting WebSocket mTLS server on port ~p~n", [Port]),
    ?info(
        "Using certificates:~n"
        "  CA: ~s~n"
        "  Cert: ~s~n"
        "  Key: ~s~n",
        [CACertFile, CertFile, KeyFile]
    ),

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

    ?info("Cryptic WebSocket server with mTLS started on port ~p~n", [Port]),
    {ok, started}.
