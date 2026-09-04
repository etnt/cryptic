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
%%% == Process Architecture ==
%%%
%%% Understanding the processes created when a client connects:
%%%
%%% <h4>Server Startup (One-time)</h4>
%%% <ol>
%%%   <li>`cryptic_server' - Gen_server process (registered name), manages server lifecycle</li>
%%%   <li>`cowboy' listener processes - Created by `cowboy:start_tls/3':
%%%       <ul>
%%%         <li>`ranch_listener_sup' - Supervisor for the listener</li>
%%%         <li>`ranch_acceptors_sup' - Supervisor for acceptor processes</li>
%%%         <li>Multiple acceptor processes - Wait for incoming connections</li>
%%%         <li>`ranch_conns_sup' - Supervisor for connection processes</li>
%%%       </ul>
%%%   </li>
%%% </ol>
%%%
%%% <h4>Per-Client Connection</h4>
%%%
%%% When a client connects to the server, the following happens:
%%%
%%% <ol>
%%%   <li>TCP/TLS Handshake - An acceptor process accepts the connection and
%%%       performs the TLS handshake with mTLS client certificate validation</li>
%%%
%%%   <li>HTTP Process - Ranch/Cowboy creates a new process to handle the HTTP request:
%%%       <ul>
%%%         <li>This process is supervised by `ranch_conns_sup'</li>
%%%         <li>Initially handles HTTP protocol</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>WebSocket Upgrade - When client requests WebSocket upgrade to `/ws':
%%%       <ul>
%%%         <li>`cryptic_ws_handler:init/2' is called in the HTTP process</li>
%%%         <li>Extracts client certificate and authenticates user (CN field)</li>
%%%         <li>Returns `{cowboy_websocket, Req, State}' to approve upgrade</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>WebSocket Handler Process - The HTTP process transforms into a WebSocket handler:
%%%       <ul>
%%%         <li>SAME process continues (not a new process)</li>
%%%         <li>`cryptic_ws_handler:websocket_init/1' is called</li>
%%%         <li>Registers user in `user_connections' ETS table: `{Username, Pid}'</li>
%%%         <li>This Pid is the WebSocket handler process itself</li>
%%%       </ul>
%%%   </li>
%%% </ol>
%%%
%%% <h4>Process Communication</h4>
%%%
%%% <ul>
%%%   <li>Incoming messages - WebSocket frames trigger `websocket_handle/2' callbacks</li>
%%%   <li>Outgoing messages - Return tuples like `{[{text, Json}], State}' send frames</li>
%%%   <li>Inter-user messages - Uses Erlang messaging:
%%%       <pre>
%%%       %% User A wants to send to User B:
%%%       1. A's handler sends command via WebSocket
%%%       2. Handler looks up B's Pid in user_connections ETS
%%%       3. Sends Erlang message: B_Pid ! {message, FromUser, MessageData}
%%%       4. B's handler receives in websocket_info/2
%%%       5. B's handler sends WebSocket frame to B's client
%%%       </pre>
%%%   </li>
%%%   <li>Process cleanup - When WebSocket closes:
%%%       <ul>
%%%         <li>`terminate/3' is called</li>
%%%         <li>User entry removed from `user_connections' ETS</li>
%%%         <li>Handler process terminates</li>
%%%       </ul>
%%%   </li>
%%% </ul>
%%%
%%% Connection flow:
%%%
%%% <pre>
%%%   Client Connect
%%%       ↓
%%%   [Ranch Acceptor] accepts TCP connection
%%%       ↓
%%%   [TLS Handshake] validates client certificate (mTLS)
%%%       ↓
%%%   [HTTP Process] created by Ranch
%%%       ↓
%%%   init/2 called → authenticates user from certificate
%%%       ↓
%%%   [WebSocket Upgrade] same process continues
%%%       ↓
%%%   websocket_init/1 → registers in user_connections ETS
%%%       ↓
%%%   [Active WebSocket Handler Process]
%%%       ├─ websocket_handle/2 ← WebSocket frames from client
%%%       └─ websocket_info/2   ← Erlang messages from other users
%%%       ↓
%%%   [Connection Close]
%%%       ↓
%%%   terminate/3 → cleanup from ETS
%%%       ↓
%%%   Process exits
%%% </pre>
%%%
%%% <h4>Process Supervision Tree</h4>
%%%
%%% <pre>
%%% cryptic_sup
%%%   |
%%%   +-- cryptic_server (gen_server, this module)
%%%   |
%%%   +-- cryptic_event_manager (gen_event)
%%%   |
%%%   +-- ranch_listener_sup (created by cowboy:start_tls)
%%%         |
%%%         +-- ranch_acceptors_sup
%%%         |     |
%%%         |     +-- acceptor_1
%%%         |     +-- acceptor_2
%%%         |     +-- ... (multiple acceptors)
%%%         |
%%%         +-- ranch_conns_sup
%%%               |
%%%               +-- conn_process_1 (WebSocket handler for user Alice)
%%%               +-- conn_process_2 (WebSocket handler for user Bob)
%%%               +-- ... (one per connected client)
%%% </pre>
%%%
%%% <h4>Key Points</h4>
%%%
%%% <ul>
%%%   <li>ONE `cryptic_server' gen_server for the entire application</li>
%%%   <li>ONE WebSocket handler process PER connected client</li>
%%%   <li>ETS table `user_connections' maps usernames to handler Pids</li>
%%%   <li>Message routing uses direct Erlang messaging (Pid ! Message)</li>
%%%   <li>Each handler is supervised by Ranch/Cowboy infrastructure</li>
%%%   <li>No gen_server for individual connections - just callback module behavior</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_server).

-behaviour(gen_server).

%% API
-export([start_link/0, start_mcp/1]).

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
-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

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

%% @doc Start the MCP admin HTTP endpoint on localhost.
%% Can be called after the server has booted, e.g. from the shell or a startup script.
-spec start_mcp(non_neg_integer()) -> {ok, started} | {error, term()}.
start_mcp(Port) when is_integer(Port) ->
    application:set_env(cryptic, mcp_tcp_enabled, true),
    application:set_env(cryptic, mcp_tcp_port, Port),
    start_mcp_localhost_tcp(#{port => Port}).

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
%% handlers and completes the server startup process by creating ETS tables,
%% checking configuration, and start the WebSocket mTLS server.
%%
%% @param start_server Continuation atom indicating startup phase
%% @param CfgMap Current configuration map
%% @returns {noreply, State, {continue, continue}} to proceed with startup
handle_continue(start_server, CfgMap) ->
    %% Event handlers are already set up by cryptic_ca_init
    %% No need to set up again here
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
            start_websocket_mtls(#{port => WSPort});
        false ->
            ?info("WebSocket mTLS server disabled~n", [])
    end,

    %% Optional localhost-only MCP admin HTTP endpoint (plain TCP)
    MCPEnabled =
        case application:get_env(cryptic, mcp_tcp_enabled) of
            {ok, true} -> true;
            undefined -> false;
            _ -> false
        end,
    case MCPEnabled of
        true ->
            MCPPort =
                case application:get_env(cryptic, mcp_tcp_port) of
                    {ok, MCPPort0} -> MCPPort0;
                    undefined -> 8081
                end,
            start_mcp_localhost_tcp(#{port => MCPPort});
        false ->
            ?info("MCP localhost TCP endpoint disabled~n", [])
    end,

    %% Optional web administration HTTPS endpoint (server cert, no client cert).
    %% Enabled by the CRYPTIC_WEBADMIN_ENABLED env var (containers) or the
    %% `webadmin_enabled' app env; the env var takes precedence when set.
    WebAdminEnabled =
        case os:getenv("CRYPTIC_WEBADMIN_ENABLED") of
            false ->
                case application:get_env(cryptic, webadmin_enabled) of
                    {ok, true} -> true;
                    _ -> false
                end;
            EnvStr ->
                lists:member(string:lowercase(EnvStr),
                             ["1", "true", "yes", "on"])
        end,
    case WebAdminEnabled of
        true ->
            WebAdminPort =
                case application:get_env(cryptic, webadmin_port) of
                    {ok, WAPort0} -> WAPort0;
                    undefined -> 8444
                end,
            start_webadmin_https(#{port => WebAdminPort});
        false ->
            ?info("Web admin HTTPS endpoint disabled~n", [])
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
    [?CONNECTION_TABLE, ?USER_TABLE, ?MESSAGE_TABLE, ?PREKEY_TABLE].

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
%%%   <li>Delete the ETS tables</li>
%% </ul>
%%
%% @param Reason Termination reason (ignored)
%% @param State Final server state (ignored)
%% @returns ok
terminate(_Reason, _State) ->
    %% Stop WebSocket mTLS server (if it was started)
    catch cowboy:stop_listener(cryptic_ws_listener),
    catch cowboy:stop_listener(cryptic_mcp_listener),

    %% Clean up ETS tables
    [ets:delete(Table) || Table <- ets_tables()],

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
    CertFile = cryptic_lib:get_server_file("CRYPTIC_SERVER_CERT",
                                           server_cert_file),
    KeyFile = cryptic_lib:get_server_file("CRYPTIC_SERVER_KEY",
                                           server_key_file),
    CACertFile =cryptic_lib:get_server_file("CRYPTIC_CA_CERT",
                                            ca_cert_file),

    %% WebSocket and CA API routes
    Dispatch = cowboy_router:compile([
        {'_', [
            %% WebSocket for general messaging
            {"/ws", cryptic_ws_handler, []},

            %% CA WebSocket for invite management (authenticated clients)
            {"/ca/ws", cryptic_ca_ws_handler, []},

            %% CA REST API for public operations
            {"/ca/v1/ca-cert", cryptic_ca_rest_handler, #{
                operation => ca_cert
            }},
            {"/ca/v1/register-gpg", cryptic_ca_rest_handler, #{
                operation => register_gpg
            }},
            {"/ca/v1/csr", cryptic_ca_rest_handler, #{operation => csr}},
            {"/ca/v1/status/:fingerprint", cryptic_ca_rest_handler, #{
                operation => status
            }},

            %% Mobile enrollment endpoints
            {"/ca/v1/mobile-csr", cryptic_ca_mobile_handler, #{
                operation => mobile_csr
            }},
            {"/ca/v1/admin/register-enrollment", cryptic_ca_admin_handler, #{
                operation => register_enrollment
            }},

            %% Static files
            {"/", cowboy_static, {priv_file, cryptic, "index.html"}}
        ]}
    ]),

    %% TLS options with client certificate verification
    %% Note: We use verify_peer but set fail_if_no_peer_cert to false to allow
    %% public CA endpoints (/ca/v1/csr) to work without mTLS for initial cert requests.
    %% Protected endpoints (WebSocket) will verify certificates in their handlers.
    TLSOptions = [
        {verify, verify_peer},
        {verify_fun, {fun verify_peer/4, []}},
        {fail_if_no_peer_cert, false},  % Allow connections without client certs for /ca/v1/csr
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

start_mcp_localhost_tcp(Config) ->
    application:ensure_all_started(cowboy),

    Port =
        case os:getenv("CRYPTIC_MCP_PORT") of
            false ->
                maps:get(port, Config, 8081);
            PortStr ->
                list_to_integer(PortStr)
        end,

    Dispatch = cowboy_router:compile([
        {'_', [
            {"/mcp/v1/admin/list_users", cryptic_mcp_admin_handler, #{
                operation => <<"list_users">>
            }},
            {"/mcp/v1/admin/user/:gpg_fp", cryptic_mcp_admin_handler, #{
                operation => <<"get_user_info">>
            }},
            {"/mcp/v1/admin/user/:gpg_fp/certificates", cryptic_mcp_admin_handler, #{
                operation => <<"list_certificates">>
            }},
            {"/mcp/v1/admin/register_user", cryptic_mcp_admin_handler, #{
                operation => <<"register_user">>
            }},
            {"/mcp/v1/admin/suspend_user", cryptic_mcp_admin_handler, #{
                operation => <<"suspend_user">>
            }},
            {"/mcp/v1/admin/revoke_user", cryptic_mcp_admin_handler, #{
                operation => <<"revoke_user">>
            }},
            {"/mcp/v1/admin/reactivate_user", cryptic_mcp_admin_handler, #{
                operation => <<"reactivate_user">>
            }},
            {"/mcp/v1/admin/revoke_certificate", cryptic_mcp_admin_handler, #{
                operation => <<"revoke_certificate">>
            }},
            %% New admin endpoints
            {"/mcp/v1/admin/status", cryptic_mcp_admin_handler, #{
                operation => <<"status">>
            }},
            {"/mcp/v1/admin/online", cryptic_mcp_admin_handler, #{
                operation => <<"online">>
            }},
            {"/mcp/v1/admin/connections", cryptic_mcp_admin_handler, #{
                operation => <<"connections">>
            }},
            {"/mcp/v1/admin/pending", cryptic_mcp_admin_handler, #{
                operation => <<"pending">>
            }},
            {"/mcp/v1/admin/pending/:user", cryptic_mcp_admin_handler, #{
                operation => <<"pending_for_user">>
            }},
            {"/mcp/v1/admin/keys", cryptic_mcp_admin_handler, #{
                operation => <<"keys">>
            }},
            {"/mcp/v1/admin/keys/:user", cryptic_mcp_admin_handler, #{
                operation => <<"keys_for_user">>
            }},
            {"/mcp/v1/admin/audit", cryptic_mcp_admin_handler, #{
                operation => <<"audit">>
            }},
            {"/mcp/v1/admin/enrollments", cryptic_mcp_admin_handler, #{
                operation => <<"list_enrollments">>
            }},
            {"/mcp/v1/admin/enrollment/:enrollment_fp", cryptic_mcp_admin_handler, #{
                operation => <<"get_enrollment_info">>
            }},
            {"/mcp/v1/admin/register_enrollment", cryptic_mcp_admin_handler, #{
                operation => <<"register_enrollment">>
            }},
            {"/mcp/v1/admin/suspend_enrollment", cryptic_mcp_admin_handler, #{
                operation => <<"suspend_enrollment">>
            }},
            {"/mcp/v1/admin/revoke_enrollment", cryptic_mcp_admin_handler, #{
                operation => <<"revoke_enrollment">>
            }},
            {"/mcp/v1/admin/reactivate_enrollment", cryptic_mcp_admin_handler, #{
                operation => <<"reactivate_enrollment">>
            }},
            {"/mcp/v1/admin/delete_enrollment", cryptic_mcp_admin_handler, #{
                operation => <<"delete_enrollment">>
            }},
            {"/mcp/v1/admin/server_log", cryptic_mcp_admin_handler, #{
                operation => <<"server_log">>
            }}
        ]}
    ]),

    ?info("Starting MCP localhost TCP endpoint on 127.0.0.1:~p~n", [Port]),
    {ok, _} = cowboy:start_clear(
        cryptic_mcp_listener,
        [
            %% Security boundary: bind admin MCP endpoint to localhost only.
            {ip, {127, 0, 0, 1}},
            {port, Port}
        ],
        #{env => #{dispatch => Dispatch}}
    ),
    ?info("MCP localhost TCP endpoint started on 127.0.0.1:~p~n", [Port]),
    {ok, started}.

%% @doc Start the web administration HTTPS endpoint.
%%
%% Serves the web admin single-page shell and its JSON API over TLS using the
%% server certificate only (no client-certificate/mTLS verification), unlike
%% the messaging listener. Authentication is handled at the application layer
%% by {@link cryptic_webadmin_auth_handler} (password login + session cookie).
start_webadmin_https(Config) ->
    application:ensure_all_started(cowboy),
    application:ensure_all_started(ssl),

    Port =
        case os:getenv("CRYPTIC_WEBADMIN_PORT") of
            false ->
                maps:get(port, Config, 8444);
            PortStr ->
                list_to_integer(PortStr)
        end,

    CertFile = cryptic_lib:get_server_file("CRYPTIC_SERVER_CERT",
                                           server_cert_file),
    KeyFile = cryptic_lib:get_server_file("CRYPTIC_SERVER_KEY",
                                          server_key_file),

    Dispatch = cowboy_router:compile([
        {'_', [
            %% Authentication API (must precede the static catch-all)
            {"/admin/api/login", cryptic_webadmin_auth_handler, #{
                operation => login
            }},
            {"/admin/api/logout", cryptic_webadmin_auth_handler, #{
                operation => logout
            }},
            {"/admin/api/session", cryptic_webadmin_auth_handler, #{
                operation => session
            }},

            %% Admin REST API (session + CSRF authenticated). Order matters:
            %% more specific routes precede parameterised ones.
            {"/admin/api/users", cryptic_webadmin_api_handler, #{
                operation => users
            }},
            {"/admin/api/users/:fp/certs", cryptic_webadmin_api_handler, #{
                operation => user_certs
            }},
            {"/admin/api/users/:fp/suspend", cryptic_webadmin_api_handler, #{
                operation => user_suspend
            }},
            {"/admin/api/users/:fp/reactivate", cryptic_webadmin_api_handler, #{
                operation => user_reactivate
            }},
            {"/admin/api/users/:fp/revoke", cryptic_webadmin_api_handler, #{
                operation => user_revoke
            }},
            {"/admin/api/users/:fp", cryptic_webadmin_api_handler, #{
                operation => user
            }},
            {"/admin/api/enrollments", cryptic_webadmin_api_handler, #{
                operation => enrollments
            }},
            {"/admin/api/enrollments/:fp", cryptic_webadmin_api_handler, #{
                operation => enrollment
            }},
            {"/admin/api/server-hosts", cryptic_webadmin_api_handler, #{
                operation => server_hosts
            }},
            {"/admin/api/audit", cryptic_webadmin_api_handler, #{
                operation => audit
            }},
            {"/admin/api/status", cryptic_webadmin_api_handler, #{
                operation => status
            }},
            {"/admin/api/logs", cryptic_webadmin_api_handler, #{
                operation => logs
            }},

            %% Live log stream (session-authenticated WebSocket)
            {"/admin/ws/logs", cryptic_webadmin_log_ws, #{}},

            %% Single-page shell + static assets
            {"/admin", cowboy_static, {priv_file, cryptic, "webadmin/index.html"}},
            {"/admin/", cowboy_static, {priv_file, cryptic, "webadmin/index.html"}},
            {"/admin/[...]", cowboy_static, {priv_dir, cryptic, "webadmin"}}
        ]}
    ]),

    %% Server-certificate TLS only. No CA cert, no peer verification: the web
    %% admin authenticates users with passwords, not client certificates.
    TLSOptions = [
        {port, Port},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {certfile, CertFile},
        {keyfile, KeyFile}
    ],

    ?info("Starting web admin HTTPS endpoint on port ~p~n", [Port]),
    {ok, _} = cowboy:start_tls(
        cryptic_webadmin_listener,
        TLSOptions,
        #{env => #{dispatch => Dispatch}}
    ),
    ?info("Web admin HTTPS endpoint started on port ~p~n", [Port]),
    {ok, started}.


verify_peer(_OtpCert, _DerCert, {bad_cert, _} = Reason, _UserState) ->
    ?debug("VERIFY_PEER: bad_cert - ~p", [Reason]),
    {fail, Reason};

verify_peer(_OtpCert, _DerCert, {extension, Extension}, UserState) ->
    %% Check if this is the Subject Alternative Name extension with GPG fingerprint
    case Extension of
        {'Extension', {2,5,29,17}, _Critical, SANValues} ->
            %% This is a SAN extension, check for GPG fingerprint
            case extract_gpg_from_san(SANValues) of
                {ok, GpgFp} ->
                    ?debug("VERIFY_PEER: Found GPG fingerprint in SAN: ~s", [GpgFp]),
                    %% Verify the GPG fingerprint is registered and certificate is valid
                    case verify_gpg_and_cert(GpgFp, _OtpCert) of
                        {ok, active} ->
                            ?debug("VERIFY_PEER: GPG fingerprint ~s is registered with active cert", [GpgFp]),
                            {valid, UserState};
                        {error, unregistered} ->
                            ?warning("VERIFY_PEER: GPG fingerprint ~s is NOT registered - rejecting", [GpgFp]),
                            {fail, {bad_cert, unregistered_gpg_fingerprint}};
                        {error, suspended} ->
                            ?warning("VERIFY_PEER: User ~s is suspended - rejecting", [GpgFp]),
                            {fail, {bad_cert, user_suspended}};
                        {error, revoked} ->
                            ?warning("VERIFY_PEER: User ~s is revoked - rejecting", [GpgFp]),
                            {fail, {bad_cert, user_revoked}};
                        {error, cert_revoked} ->
                            ?warning("VERIFY_PEER: Certificate for ~s is revoked - rejecting", [GpgFp]),
                            {fail, {bad_cert, certificate_revoked}};
                        {error, cert_expired} ->
                            ?warning("VERIFY_PEER: Certificate for ~s is expired - rejecting", [GpgFp]),
                            {fail, {bad_cert, certificate_expired}};
                        {error, Reason} ->
                            ?error("VERIFY_PEER: Error verifying GPG fingerprint ~s: ~p", [GpgFp, Reason]),
                            %% On error, reject to be safe
                            {fail, {bad_cert, gpg_verification_error}}
                    end;
                {error, _Reason} ->
                    ?debug("VERIFY_PEER: No GPG fingerprint in SAN extension", []),
                    {unknown, UserState}
            end;
        _OtherExtension ->
            ?debug("VERIFY_PEER: Unknown extension - ~p", [Extension]),
            {unknown, UserState}
    end;

verify_peer(_OtpCert, _DerCert, valid = Reason, UserState) ->
    ?debug("VERIFY_PEER: valid - ~p", [Reason]),
    {valid, UserState};

verify_peer(_OtpCert, _DerCert, valid_peer = Reason, UserState) ->
    ?debug("VERIFY_PEER: valid_peer - ~p", [Reason]),
    {valid, UserState};

verify_peer(_OtpCert, _DerCert, Reason, UserState) ->
    ?debug("VERIFY_PEER: Unknown reason - ~p", [Reason]),
    {unknown, UserState}.

%% @doc Extract GPG fingerprint from Subject Alternative Name values
-spec extract_gpg_from_san(list()) -> {ok, binary()} | {error, term()}.
extract_gpg_from_san(SANValues) ->
    %% Look for DNS name matching pattern: <fingerprint>.gpg.cryptic.local
    case lists:foldl(
        fun
            ({dNSName, DNSName}, Acc) ->
                case binary:split(list_to_binary(DNSName), <<".">>, [global]) of
                    [GpgFp, <<"gpg">>, <<"cryptic">>, <<"local">>] 
                        when byte_size(GpgFp) =:= 40 ->
                        %% Found it! GPG fingerprint is 40 hex characters
                        {ok, GpgFp};
                    _ ->
                        Acc
                end;
            (_, Acc) ->
                Acc
        end,
        {error, not_found},
        SANValues
    ) of
        {ok, _} = Result -> Result;
        {error, _} = Error -> Error
    end.

%% @doc Verify GPG fingerprint is registered and certificate is valid.
%%
%% Checks both user status and certificate status:
%% - User must be 'active' (not suspended/revoked)
%% - Certificate must be 'active' (not expired/revoked)
-spec verify_gpg_and_cert(binary(), term()) -> 
    {ok, active} | {error, unregistered | suspended | revoked | cert_revoked | cert_expired | term()}.
verify_gpg_and_cert(GpgFp, OtpCert) ->
    try
        %% Look up the database reference from the ETS table
        case ets:lookup(cryptic_ca_storage, db_ref) of
            [{db_ref, DbRef}] ->
                %% Step 1: Check if the GPG fingerprint is registered
                case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
                    {ok, Identity} ->
                        %% Step 2: Check user status
                        case Identity#gpg_identity.status of
                            <<"active">> ->
                                %% Step 3: Extract serial from certificate and check cert status
                                Serial = extract_serial_from_otp_cert(OtpCert),
                                case cryptic_ca_store:get_certificate(DbRef, Serial) of
                                    {ok, Cert} ->
                                        %% Check certificate status
                                        case Cert#certificate.status of
                                            <<"active">> ->
                                                {ok, active};
                                            <<"revoked">> ->
                                                {error, cert_revoked};
                                            <<"expired">> ->
                                                {error, cert_expired};
                                            _Other ->
                                                {error, {unknown_cert_status, _Other}}
                                        end;
                                    {error, not_found} ->
                                        %% Certificate not in database - reject connection
                                        %% All certificates issued by our CA should be in the database
                                        ?error("Certificate ~s not found in database for user ~s - rejecting connection", 
                                                [Serial, GpgFp]),
                                        {error, cert_not_in_database};
                                    {error, CertError} ->
                                        {error, {cert_lookup_failed, CertError}}
                                end;
                            <<"suspended">> ->
                                {error, suspended};
                            <<"revoked">> ->
                                {error, revoked};
                            _Other ->
                                {error, {unknown_status, _Other}}
                        end;
                    {error, not_found} -> 
                        {error, unregistered};
                    {error, _Reason} = Error ->
                        Error
                end;
            [] ->
                %% ETS table not found or empty - CA not initialized yet
                {error, ca_not_initialized}
        end
    catch
        error:badarg ->
            %% ETS table doesn't exist
            {error, ca_storage_not_available};
        ErrorClass:ErrorReason ->
            {error, {ErrorClass, ErrorReason}}
    end.

%% @doc Extract serial number from OTP certificate structure.
-spec extract_serial_from_otp_cert(term()) -> binary().
extract_serial_from_otp_cert(OtpCert) ->
    try
        TbsCert = OtpCert#'OTPCertificate'.tbsCertificate,
        Serial = TbsCert#'OTPTBSCertificate'.serialNumber,
        integer_to_binary(Serial, 16)
    catch
        _:Error ->
            ?error("Failed to extract serial from OTP cert: ~p", [Error]),
            <<"unknown">>
    end.
