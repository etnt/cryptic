%%% @doc Cryptic WebSocket mTLS Client
%%%
%%% This module provides a WebSocket client for the Cryptic chat application
%%% that uses mutual TLS (mTLS) authentication for secure connections. It acts
%%% as a bridge between the terminal UI and the WebSocket server, handling
%%% connection management, message forwarding, and keepalive functionality.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>mTLS WebSocket connections with client certificate authentication</li>
%%%   <li>Automatic connection establishment and reconnection handling</li>
%%%   <li>Command queuing when disconnected</li>
%%%   <li>Bidirectional message forwarding between UI and server</li>
%%%   <li>WebSocket keepalive with ping/pong mechanism</li>
%%%   <li>Certificate-based user authentication</li>
%%%   <li>JSON message encoding/decoding</li>
%%% </ul>
%%%
%%% == Message Flow ==
%%%
%%% The client handles several types of messages:
%%% <ul>
%%%   <li>`welcome' - Server welcome message on connection</li>
%%%   <li>`success' - Operation success confirmations</li>
%%%   <li>`prekey' - User public keys for message encryption</li>
%%%   <li>`users' - List of registered users</li>
%%%   <li>`user_status' - User online/offline status</li>
%%%   <li>`message' - Encrypted messages from other users</li>
%%%   <li>`error' - Error messages from server</li>
%%% </ul>
%%%
%%% == Configuration ==
%%%
%%% The client requires certificate files for mTLS authentication:
%%% <ul>
%%%   <li>`CRYPTIC_CLIENT_CERT' - Environment variable for client certificate</li>
%%%   <li>`CRYPTIC_CLIENT_KEY' - Environment variable for client private key</li>
%%%   <li>`CRYPTIC_CA_CERT' - Environment variable for CA certificate</li>
%%% </ul>
%%%
%%% Alternatively, certificate paths can be provided in the config map
%%% passed to {@link start_link/3}.
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_ws_client).
-behaviour(gen_server).

-export([start_link/2, start_link/3, send_command/2, stop/1, set_ui_pid/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, handle_continue/2]).

-include("cryptic.hrl").

%% Internal state record for the WebSocket client gen_server.
%%
%% Fields:
%% <ul>
%%   <li>`username' - The authenticated username from client certificate</li>
%%   <li>`server_host' - WebSocket server hostname</li>
%%   <li>`server_port' - WebSocket server port (default: 8443)</li>
%%   <li>`conn_pid' - Gun connection process PID</li>
%%   <li>`stream_ref' - WebSocket stream reference</li>
%%   <li>`cert_file' - Path to client certificate file</li>
%%   <li>`key_file' - Path to client private key file</li>
%%   <li>`ca_file' - Path to CA certificate file</li>
%%   <li>`connected' - Boolean indicating connection status</li>
%%   <li>`pending_commands' - Commands queued while disconnected</li>
%%   <li>`ui_pid' - PID of the UI process for message forwarding</li>
%%   <li>`ping_timer_ref' - Timer reference for WebSocket keepalive</li>
%% </ul>
-record(state, {
    username,
    server_host,
    server_port = 8443,
    conn_pid,
    stream_ref,
    cert_file,
    key_file,
    ca_file,
    connected = false,
    pending_commands = [],
    ui_pid,
    ping_timer_ref
}).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Start a WebSocket client with default configuration.
%%
%% Starts a WebSocket client process that connects to the specified server
%% using mTLS authentication. Certificate paths are read from environment
%% variables or default locations.
%%
%% @param Username The username for authentication (extracted from client cert)
%% @param ServerHost The WebSocket server hostname to connect to
%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
%% @see start_link/3
start_link(Username, ServerHost) ->
    start_link(Username, ServerHost, #{}).

%% @doc Start a WebSocket client with custom configuration.
%%
%% Starts a WebSocket client process with the ability to override default
%% settings through the configuration map. This is the main entry point
%% for creating WebSocket client connections.
%%
%% == Configuration Options ==
%%
%% The Config map may contain:
%% <ul>
%%   <li>`port' - Server port (default: 8443)</li>
%%   <li>`cert_file' - Path to client certificate file</li>
%%   <li>`key_file' - Path to client private key file</li>
%%   <li>`ca_file' - Path to CA certificate file</li>
%% </ul>
%%
%% If certificate paths are not provided in the config, they will be
%% read from environment variables:
%% <ul>
%%   <li>`CRYPTIC_CLIENT_CERT' - Client certificate file</li>
%%   <li>`CRYPTIC_CLIENT_KEY' - Client private key file</li>
%%   <li>`CRYPTIC_CA_CERT' - CA certificate file</li>
%% </ul>
%%
%% @param Username The username for authentication
%% @param ServerHost The WebSocket server hostname
%% @param Config Configuration map with optional overrides
%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
start_link(Username, ServerHost, Config) ->
    gen_server:start_link(?MODULE, {Username, ServerHost, Config}, []).

%% @doc Send a command to the WebSocket server.
%%
%% Sends a command (as an Erlang map) to the connected WebSocket server.
%% The command will be JSON-encoded before transmission. If the client
%% is not currently connected, the command will be queued and sent when
%% the connection is established.
%%
%% == Command Format ==
%%
%% Commands should be Erlang maps that will be JSON-encoded. Common
%% command types include:
%% <ul>
%%   <li>`#{type => <<"upload_prekey">>, prekey => PrekeyB64}' - Upload public key</li>
%%   <li>`#{type => <<"get_prekey">>, user => UserBin}' - Request user's public key</li>
%%   <li>`#{type => <<"send_message">>, ...}' - Send encrypted message</li>
%%   <li>`#{type => <<"list_users">>}' - Request list of registered users</li>
%% </ul>
%%
%% @param Pid The client process PID
%% @param Command The command map to send
%% @returns `ok' if sent immediately, `queued' if queued for later sending
send_command(Pid, Command) ->
    gen_server:call(Pid, {send_command, Command}).

%% @doc Stop the WebSocket client.
%%
%% Gracefully stops the WebSocket client process, closing any active
%% connections and cleaning up resources.
%%
%% @param Pid The client process PID
%% @returns `ok'
stop(Pid) ->
    gen_server:call(Pid, stop).

%% @doc Set the UI process PID for message forwarding.
%%
%% Registers the UI process PID so that incoming messages from the server
%% can be forwarded to the user interface. This creates the communication
%% bridge between the WebSocket client and the terminal UI.
%%
%% == Forwarded Messages ==
%%
%% The following message types are forwarded to the UI:
%% <ul>
%%   <li>`{prekey_received, User, Prekey}' - Public key for encryption</li>
%%   <li>`{users_list_received, Users}' - List of registered users</li>
%%   <li>`{websocket_message, {text, JsonData}}' - User status and errors</li>
%%   <li>`{encrypted_message_received, Message}' - Encrypted chat messages</li>
%% </ul>
%%
%% @param Pid The client process PID
%% @param UiPid The UI process PID to forward messages to
%% @returns `ok'
set_ui_pid(Pid, UiPid) ->
    gen_server:call(Pid, {set_ui_pid, UiPid}).

%%%===================================================================
%%% gen_server Callbacks
%%%===================================================================

%% @private
%% @doc Initialize the WebSocket client gen_server.
%%
%% Validates certificate configuration and prepares for WebSocket connection.
%% The actual connection is established in the handle_continue callback to
%% avoid blocking the supervisor during startup.
%%
%% @param {Username, ServerHost, Config} Initialization parameters
%% @returns `{ok, State, {continue, connect}}' on success, `{stop, Reason}' on error
init({Username, ServerHost, Config}) ->
    %% Get certificate paths from environment variables or config
    CertFile = case os:getenv("CRYPTIC_CLIENT_CERT") of
        false -> maps:get(cert_file, Config, error_no_cert);
        EnvCert -> EnvCert
    end,
    KeyFile = case os:getenv("CRYPTIC_CLIENT_KEY") of
        false -> maps:get(key_file, Config, error_no_key);
        EnvKey -> EnvKey
    end,
    CAFile = case os:getenv("CRYPTIC_CA_CERT") of
        false -> maps:get(ca_file, Config, error_no_ca);
        EnvCA -> EnvCA
    end,
    
    %% Validate that we have all required certificates
    case {CertFile, KeyFile, CAFile} of
        {error_no_cert, _, _} ->
            {stop, {missing_cert, "Set CRYPTIC_CLIENT_CERT environment variable or provide cert_file in config"}};
        {_, error_no_key, _} ->
            {stop, {missing_key, "Set CRYPTIC_CLIENT_KEY environment variable or provide key_file in config"}};
        {_, _, error_no_ca} ->
            {stop, {missing_ca, "Set CRYPTIC_CA_CERT environment variable or provide ca_file in config"}};
        {Cert, Key, CA} ->
            State = #state{
                username = Username,
                server_host = ServerHost,
                server_port = maps:get(port, Config, 8443),
                cert_file = Cert,
                key_file = Key,
                ca_file = CA
            },
        {ok, State, {continue, connect}}
    end.

%% @private
%% @doc Handle the continue callback to establish WebSocket connection.
%%
%% This callback is triggered after successful initialization to establish
%% the actual WebSocket connection. Using continue prevents blocking the
%% supervisor during potentially slow connection establishment.
%%
%% @param connect The continue message
%% @param State Current gen_server state
%% @returns `{noreply, NewState}' on success, `{stop, Reason, State}' on failure
handle_continue(connect, State) ->
    case connect_websocket(State) of
        {ok, NewState} ->
            {noreply, NewState};
        {error, Reason} ->
            ?error("Failed to connect: ~p", [Reason]),
            {stop, {connection_failed, Reason}, State}
    end.

%% @private
%% @doc Handle synchronous calls to the gen_server.
%%
%% Processes various client operations including command sending,
%% UI PID registration, and shutdown requests.
%%
%% @param Request The call request
%% @param From The caller's reference
%% @param State Current gen_server state
%% @returns `{reply, Reply, NewState}' or `{stop, Reason, Reply, State}'
handle_call({send_command, Command}, _From, State = #state{connected = true}) ->
    JsonCommand = jsx:encode(Command),
    gun:ws_send(State#state.conn_pid, State#state.stream_ref, {text, JsonCommand}),
    {reply, ok, State};

handle_call({send_command, Command}, _From, State = #state{connected = false}) ->
    %% Queue command until connected
    NewState = State#state{
        pending_commands = [Command | State#state.pending_commands]
    },
    {reply, queued, NewState};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call({set_ui_pid, UiPid}, _From, State) ->
    {reply, ok, State#state{ui_pid = UiPid}};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%% @private
%% @doc Handle asynchronous cast messages.
%%
%% Currently no cast messages are processed by this gen_server.
%%
%% @param Msg The cast message
%% @param State Current gen_server state
%% @returns `{noreply, State}'
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
%% @doc Handle asynchronous info messages.
%%
%% Processes various WebSocket-related events including:
%% <ul>
%%   <li>WebSocket upgrade completion</li>
%%   <li>Incoming WebSocket messages</li>
%%   <li>Connection errors and disconnections</li>
%%   <li>Keepalive ping/pong mechanism</li>
%% </ul>
%%
%% @param Info The info message
%% @param State Current gen_server state
%% @returns `{noreply, NewState}' or `{stop, Reason, State}'
handle_info({gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _Headers}, 
            State = #state{conn_pid = ConnPid, stream_ref = StreamRef}) ->
    ?info("WebSocket connection established for ~s", [State#state.username]),
    
    %% Send any pending commands
    lists:foreach(fun(Command) ->
        JsonCommand = jsx:encode(Command),
        gun:ws_send(ConnPid, StreamRef, {text, JsonCommand})
    end, lists:reverse(State#state.pending_commands)),
    
    %% Start ping timer to keep connection alive (ping every 30 seconds)
    PingTimerRef = erlang:send_after(30000, self(), send_ping),
    
    {noreply, State#state{connected = true, pending_commands = [], ping_timer_ref = PingTimerRef}};

handle_info({gun_ws, _ConnPid, _StreamRef, {text, Data}}, State) ->
    case jsx:decode(Data, [return_maps]) of
        Message = #{<<"type">> := Type} ->
            handle_server_message(Type, Message, State);
        _ ->
            ?warning("Invalid message format: ~s", [Data]),
            {noreply, State}
    end;

handle_info({gun_ws, _ConnPid, _StreamRef, {close, Code, Reason}}, State) ->
    ?info("WebSocket closed: ~p ~s", [Code, Reason]),
    {noreply, State#state{connected = false}};

handle_info({gun_error, _ConnPid, _StreamRef, Reason}, State) ->
    ?error("WebSocket error: ~p", [Reason]),
    {noreply, State#state{connected = false}};

handle_info({gun_down, ConnPid, _Protocol, Reason, _KilledStreams}, 
            State = #state{conn_pid = ConnPid}) ->
                ?warning("Connection down: ~p", [Reason]),
    %% Cancel ping timer if connection is down
    case State#state.ping_timer_ref of
        undefined -> ok;
        TimerRef -> erlang:cancel_timer(TimerRef)
    end,
    {noreply, State#state{connected = false, ping_timer_ref = undefined}};

%% Handle ping timer - send ping to keep connection alive
handle_info(send_ping, State = #state{connected = true, conn_pid = ConnPid, stream_ref = StreamRef}) ->
    %% Send WebSocket ping frame
    gun:ws_send(ConnPid, StreamRef, ping),
    ?dbg("Sent WebSocket ping", []),
    %% Schedule next ping in 30 seconds
    PingTimerRef = erlang:send_after(30000, self(), send_ping),
    {noreply, State#state{ping_timer_ref = PingTimerRef}};

handle_info(send_ping, State = #state{connected = false}) ->
    %% Don't send ping if not connected
    {noreply, State};

%% Handle pong response from server
handle_info({gun_ws, _ConnPid, _StreamRef, pong}, State) ->
    ?dbg("Received WebSocket pong", []),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
%% @doc Clean up resources when the gen_server terminates.
%%
%% Ensures proper cleanup of WebSocket connections and timers when
%% the client process is shutting down.
%%
%% @param Reason Termination reason
%% @param State Final gen_server state
%% @returns `ok'
terminate(_Reason, #state{conn_pid = ConnPid, ping_timer_ref = TimerRef}) when ConnPid =/= undefined ->
    %% Cancel ping timer
    case TimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(TimerRef)
    end,
    gun:close(ConnPid);
terminate(_Reason, _State) ->
    ok.

%% @private
%% @doc Handle code change during hot code loading.
%%
%% @param OldVsn Previous version
%% @param State Current state
%% @param Extra Additional data
%% @returns `{ok, NewState}'
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @private
%% @doc Establish a WebSocket connection with mTLS authentication.
%%
%% Creates a TLS connection using the Gun HTTP client library with
%% client certificate authentication, then upgrades to WebSocket.
%%
%% == TLS Configuration ==
%%
%% The connection uses:
%% <ul>
%%   <li>TLS 1.2 with peer verification</li>
%%   <li>Client certificate authentication</li>
%%   <li>CA certificate verification</li>
%%   <li>HTTP/1.1 protocol (no HTTP/2)</li>
%% </ul>
%%
%% @param State Current client state with certificate paths
%% @returns `{ok, NewState}' on success, `{error, Reason}' on failure
connect_websocket(State) ->
    application:ensure_all_started(gun),
    
    %% TLS options with client certificate (following gunsmoke pattern)
    TLSOptions = [
        {verify, verify_peer},
        {log_level, info},
        {versions, ['tlsv1.2']},
        {server_name_indication, disable},
        {cacertfile, State#state.ca_file},
        {certfile, State#state.cert_file},
        {keyfile, State#state.key_file}
    ],
    
    ConnOpts = #{
        transport => tls,
        protocols => [http],  % Use http instead of http2 for simplicity
        tls_opts => TLSOptions
    },
    
    ?info("Connecting to ~s:~p with TLS", [State#state.server_host, State#state.server_port]),
    ?info("Using certificates", []),
    ?info("  CA: ~s", [State#state.ca_file]),
    ?info("  Client cert: ~s", [State#state.cert_file]),
    ?info("  Client key: ~s", [State#state.key_file]),
    
    case gun:open(State#state.server_host, State#state.server_port, ConnOpts) of
        {ok, ConnPid} ->
            case gun:await_up(ConnPid, 5000) of
                {ok, _Protocol} ->
                    ?dbg("TLS connection established, upgrading to WebSocket", []),
                    StreamRef = gun:ws_upgrade(ConnPid, "/ws"),
                    NewState = State#state{
                        conn_pid = ConnPid,
                        stream_ref = StreamRef
                    },
                    {ok, NewState};
                {error, Reason} ->
                    gun:close(ConnPid),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
%% @doc Handle incoming messages from the WebSocket server.
%%
%% Processes different types of server messages and forwards relevant
%% information to the UI process. Each message type has specific handling
%% logic and appropriate logging.
%%
%% @param Type The message type as a binary
%% @param Message The complete message map
%% @param State Current client state
%% @returns `{noreply, State}'
handle_server_message(<<"welcome">>, Message, State) ->
    ?info("Server welcome: ~s", [maps:get(<<"message">>, Message, <<"Unknown">>)]),
    {noreply, State};

handle_server_message(<<"success">>, Message, State) ->
    SuccessMsg = maps:get(<<"message">>, Message, <<"Operation successful">>),
    ?info("Server success: ~s", [SuccessMsg]),
    {noreply, State};

handle_server_message(<<"prekey">>, Message, State) ->
    User = maps:get(<<"user">>, Message),
    Prekey = maps:get(<<"prekey">>, Message),
    ?info("Received prekey for user ~s: ~s", [User, Prekey]),
    %% Forward prekey to UI so it can encrypt and send the pending message
    case State#state.ui_pid of
        undefined ->
            ?warning("No UI PID set, cannot forward prekey", []);
        UIPid ->
            UIPid ! {prekey_received, User, Prekey}
    end,
    {noreply, State};

handle_server_message(<<"users">>, Message, State) ->
    Users = maps:get(<<"users">>, Message, []),
    ?info("Received user list: ~p", [Users]),
    %% Forward users list to UI for display
    case State#state.ui_pid of
        undefined ->
            ?warning("No UI PID set, cannot forward users list", []);
        UIPid ->
            UIPid ! {users_list_received, Users}
    end,
    {noreply, State};

handle_server_message(<<"user_status">>, Message, State) ->
    User = maps:get(<<"user">>, Message),
    Status = maps:get(<<"status">>, Message),
    ?info("User ~s status: ~s", [User, Status]),
    %% Forward user status to UI for handling
    case State#state.ui_pid of
        undefined ->
            ?warning("No UI PID set, cannot forward user status", []);
        UIPid ->
            UIPid ! {websocket_message, {text, jsx:encode(Message)}}
    end,
    {noreply, State};

handle_server_message(<<"message">>, Message, State) ->
    From = maps:get(<<"from">>, Message),
    ?info("Message from ~s", [From]),
    %% Forward encrypted message to UI for decryption and display
    case State#state.ui_pid of
        undefined ->
            ?warning("No UI PID set, cannot forward message", []);
        UIPid ->
            UIPid ! {encrypted_message_received, Message}
    end,
    {noreply, State};

handle_server_message(<<"error">>, Message, State) ->
    ErrorMsg = maps:get(<<"message">>, Message, <<"Unknown error">>),
    ?error("Server error: ~s", [ErrorMsg]),
    %% Forward error to UI for proper handling
    case State#state.ui_pid of
        undefined ->
            ?warning("No UI PID set, cannot forward error message", []);
        UIPid ->
            UIPid ! {websocket_message, {text, jsx:encode(Message)}}
    end,
    {noreply, State};

handle_server_message(Type, Message, State) ->
    ?warning("Unknown message type ~s: ~p", [Type, Message]),
    {noreply, State}.
