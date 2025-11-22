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
%%%   <li>Automatic reconnection on connection loss (VPN changes, host suspend, etc.)</li>
%%%   <li>Reliable message delivery with acknowledgment tracking and retries</li>
%%%   <li>Command queuing when disconnected</li>
%%%   <li>Bidirectional message forwarding between UI and server</li>
%%%   <li>WebSocket keepalive with ping/pong mechanism</li>
%%%   <li>Certificate-based user authentication</li>
%%%   <li>JSON message encoding/decoding</li>
%%% </ul>
%%%
%%% == Connection Management ==
%%%
%%% The client automatically handles connection failures and reconnection:
%%% <ul>
%%%   <li>Detects connection loss (network issues, VPN changes, host suspend)</li>
%%%   <li>Automatically attempts reconnection every 30 seconds</li>
%%%   <li>Continues reconnection attempts until successful</li>
%%%   <li>Resends pending unacknowledged messages after reconnection</li>
%%%   <li>Maintains WebSocket keepalive with periodic ping frames</li>
%%% </ul>
%%%
%%% == Message Reliability ==
%%%
%%% For critical message types (x3dh, ratchet), the client ensures delivery:
%%% <ul>
%%%   <li>Assigns unique message_id to each message</li>
%%%   <li>Waits for server acknowledgment (message_sent response)</li>
%%%   <li>Retries unacknowledged messages up to 5 times (while connected)</li>
%%%   <li>Pauses retries during disconnection without counting against limit</li>
%%%   <li>Automatically resends all pending messages on reconnection</li>
%%% </ul>
%%%
%%% == Message Flow ==
%%%
%%% The client handles several types of messages:
%%% <ul>
%%%   <li>`welcome' - Server welcome message on connection</li>
%%%   <li>`success' - Operation success confirmations</li>
%%%   <li>`message_sent' - Acknowledgment for x3dh/ratchet messages</li>
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

-export([
    start_link/1, start_link/2, start_link/3,
    send_message/2,
    stop/1,
    set_engine_pid/2,
    reload_certificate_and_reconnect/1
]).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("cryptic.hrl").

% 30 seconds
-define(RECONNECT_TIMEOUT, 30000).
% 30 seconds
-define(PING_TIMEOUT, 30000).
% 30 seconds
-define(MSG_RETRY_TIMEOUT, 30000).

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
%%   <li>`reconnect_timer_ref' - Timer reference for reconnection attempts</li>
%%   <li>`pending_acks' - Map of message_id to {Command, TimerRef, RetryCount}</li>
%% </ul>
-record(state, {
    username,
    server_host,
    server_port = 8443,
    ws_path = "/ws",  % WebSocket endpoint path: "/ws" for chat, "/ca/ws" for admin
    conn_pid,
    stream_ref,
    cert_file,
    key_file,
    ca_file,
    connected = false,
    pending_commands = [],
    ui_pid,
    engine_pid :: pid(),
    ping_timer_ref,
    reconnect_timer_ref,
    pending_acks = #{}
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

start_link(CfgMap) when is_map(CfgMap) ->
    start_link(
        maps:get(username, CfgMap),
        maps:get(server_host, CfgMap),
        CfgMap
    ).

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
    gen_server:start_link(?MODULE, {self(), Username, ServerHost, Config}, []).

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
send_message(Pid, Command) ->
    gen_server:call(Pid, {send_message, Command}).

%% @doc Stop the WebSocket client.
%%
%% Gracefully stops the WebSocket client process, closing any active
%% connections and cleaning up resources.
%%
%% @param Pid The client process PID
%% @returns `ok'
stop(Pid) ->
    gen_server:call(Pid, stop).

%% @doc Set the Engine process PID for message forwarding.
%%
%% Registers the Engine process PID so that incoming messages from the server
%% can be forwarded to the engine. This creates the communication
%% bridge between the WebSocket client and the Cryptic Engine.
%%
%% == Forwarded Messages ==
%%
%% The following message types are forwarded to the Engine:
%% <ul>
%%   <li>`{prekey_received, User, Prekey}' - Public key for encryption</li>
%%   <li>`{users_list_received, Users}' - List of registered users</li>
%%   <li>`{websocket_message, {text, JsonData}}' - User status and errors</li>
%%   <li>`{encrypted_message_received, Message}' - Encrypted chat messages</li>
%% </ul>
%%
%% @param Pid The client process PID
%% @param EnginePid The engine process PID to forward messages to
%% @returns `ok'
set_engine_pid(Pid, EnginePid) ->
    gen_server:call(Pid, {set_engine_pid, EnginePid}).

%% @doc Reload client certificate and reconnect to server.
%%
%% Triggers a graceful reload of the client certificate and reconnection
%% to the WebSocket server. This is used during automatic certificate renewal.
%%
%% == Process ==
%%
%% The reload process:
%% <ol>
%%   <li>Gracefully closes existing WebSocket connection</li>
%%   <li>Closes gun HTTP connection</li>
%%   <li>Re-reads certificate files from disk (new certificate must already be saved)</li>
%%   <li>Re-establishes TLS connection with new certificate</li>
%%   <li>Upgrades to WebSocket</li>
%%   <li>Resends any pending messages</li>
%% </ol>
%%
%% == Prerequisites ==
%%
%% Before calling this function:
%% <ul>
%%   <li>New certificate must already be saved to disk</li>
%%   <li>Certificate file paths remain the same</li>
%%   <li>Private key remains unchanged (only certificate is replaced)</li>
%% </ul>
%%
%% == Behavior ==
%%
%% The function returns immediately with `ok'. The actual reconnection
%% happens asynchronously. Monitor the connection status via logging
%% or by observing incoming messages.
%%
%% == Example ==
%%
%% ```
%% %% Certificate renewal has saved new cert to disk
%% ok = cryptic_cert_renewal:install_new_certificate(NewCertPem, CertFile),
%%
%% %% Trigger reload and reconnection
%% ok = cryptic_ws_client:reload_certificate_and_reconnect(WsClientPid),
%%
%% %% Connection will be reestablished with new certificate
%% %% Pending messages will be automatically resent
%% '''
%%
%% @param Pid The client process PID
%% @returns `ok'
reload_certificate_and_reconnect(Pid) ->
    gen_server:cast(Pid, reload_certificate_and_reconnect).

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
init({UIPid, Username, ServerHost, Config}) ->
    %% Get certificate paths from environment variables or config
    CertFile =
        case os:getenv("CRYPTIC_CLIENT_CERT") of
            false -> maps:get(cert_file, Config, error_no_cert);
            EnvCert -> EnvCert
        end,
    KeyFile =
        case os:getenv("CRYPTIC_CLIENT_KEY") of
            false -> maps:get(key_file, Config, error_no_key);
            EnvKey -> EnvKey
        end,
    CAFile =
        case os:getenv("CRYPTIC_CA_CERT") of
            false -> maps:get(ca_file, Config, error_no_ca);
            EnvCA -> EnvCA
        end,

    %% Validate that we have all required certificates
    case {CertFile, KeyFile, CAFile} of
        {error_no_cert, _, _} ->
            {stop,
                {missing_cert,
                    "Set CRYPTIC_CLIENT_CERT environment variable or provide cert_file in config"}};
        {_, error_no_key, _} ->
            {stop,
                {missing_key,
                    "Set CRYPTIC_CLIENT_KEY environment variable or provide key_file in config"}};
        {_, _, error_no_ca} ->
            {stop,
                {missing_ca,
                    "Set CRYPTIC_CA_CERT environment variable or provide ca_file in config"}};
        {Cert, Key, CA} ->
            %% Subscribe to event bus for websocket_outbound messages
            WsOutboundFilter = fun(Event) ->
                case Event of
                    #{type := websocket_outbound} -> true;
                    _ -> false
                end
            end,
            ok = cryptic_event_bus:subscribe(self(), WsOutboundFilter),

            State = #state{
                ui_pid = UIPid,
                username = Username,
                server_host = ServerHost,
                server_port = maps:get(
                    server_port, Config, maps:get(port, Config, 8443)
                ),
                cert_file = Cert,
                key_file = Key,
                ca_file = CA
            },
            try connect_websocket(State) of
                {ok, NewState} ->
                    {ok, NewState};
                {error, Reason} ->
                    ?error("Failed to connect: ~p", [Reason]),
                    %% Return {stop, Reason} (not {stop, Reason, State}) to avoid crash report
                    {stop, {connection_failed, Reason}}
            catch
                Class:Error ->
                    ?error("Exception during connect_websocket: ~p:~p", [Class, Error]),
                    {stop, {connection_failed, {Class, Error}}}
            end
    end.

%%%===================================================================
%%% Internal helper functions
%%%===================================================================

%% @private
%% @doc Send a command message via WebSocket.
%%
%% Handles message tracking for critical message types (x3dh, ratchet)
%% and sends the message over the WebSocket connection.
%%
%% @param Command The command map to send
%% @param State Current state
%% @returns {Reply, NewState}
do_send_message(Command, State) ->
    %% Check if WebSocket connection is established
    case State#state.connected of
        true ->
            %% Add message_id if this is a message that needs acknowledgment
            {CommandWithId, NewState} =
                case maps:get(<<"type">>, Command, undefined) of
                    <<"x3dh">> ->
                        add_message_tracking(Command, State);
                    <<"ratchet">> ->
                        add_message_tracking(Command, State);
                    _ ->
                        %% Other commands don't need acknowledgment tracking
                        {Command, State}
                end,

            JsonCommand = jsx:encode(CommandWithId),
            ?msg_out("~s~n", [maps:get(<<"type">>, CommandWithId, <<"unknown...">>)]),
            ?dbg(
                "send_message: ConnPid=~p, StreamRef=~p , Command=~p~n",
                [NewState#state.conn_pid, NewState#state.stream_ref, CommandWithId]
            ),
            ok = gun:ws_send(
                NewState#state.conn_pid,
                NewState#state.stream_ref,
                {text, JsonCommand}
            ),
            {ok, NewState};
        false ->
            %% Not connected yet, queue the command
            ?dbg("WebSocket not connected yet, queuing command: ~p~n", [Command]),
            NewState = State#state{
                pending_commands = [Command | State#state.pending_commands]
            },
            {ok, NewState}
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
handle_call({send_message, Command}, _From, State) ->
    {Reply, NewState} = do_send_message(Command, State),
    {reply, Reply, NewState};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call({set_engine_pid, EnginePid}, _From, State) ->
    {reply, ok, State#state{engine_pid = EnginePid}};
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
handle_cast(reload_certificate_and_reconnect, State) ->
    ?info("Reloading certificate and reconnecting...", []),
    
    %% Close existing connection gracefully
    NewState = close_connection_gracefully(State),
    
    %% Trigger immediate reconnection with new certificate
    %% The connect_websocket/1 function will re-read certificate files
    self() ! attempt_reconnect,
    
    {noreply, NewState};

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
handle_info(
    {gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _Headers},
    State = #state{conn_pid = ConnPid, stream_ref = StreamRef}
) ->
    ?info("WebSocket connection established for ~s", [State#state.username]),

    %% Cancel reconnect timer if one is active
    case State#state.reconnect_timer_ref of
        undefined -> ok;
        ReconnectTimer -> erlang:cancel_timer(ReconnectTimer)
    end,

    %% Send any pending commands
    lists:foreach(
        fun(Command) ->
            JsonCommand = jsx:encode(Command),
            ?msg_out("~s", [maps:get(<<"type">>, Command, <<"unknown...">>)]),
            gun:ws_send(ConnPid, StreamRef, {text, JsonCommand})
        end,
        lists:reverse(State#state.pending_commands)
    ),

    %% Resend any pending acknowledged messages
    %% (messages that were sent but not yet acknowledged)
    PendingCount = maps:size(State#state.pending_acks),
    case PendingCount of
        0 ->
            ok;
        _ ->
            ?info("Resending ~p pending messages after reconnection", [
                PendingCount
            ]),
            maps:foreach(
                fun(_MessageId, {Command, _TimerRef, _RetryCount}) ->
                    JsonCommand = jsx:encode(Command),
                    gun:ws_send(ConnPid, StreamRef, {text, JsonCommand})
                end,
                State#state.pending_acks
            )
    end,

    %% Start ping timer to keep connection alive
    PingTimerRef = erlang:send_after(?PING_TIMEOUT, self(), send_ping),

    {noreply, State#state{
        connected = true,
        pending_commands = [],
        ping_timer_ref = PingTimerRef,
        reconnect_timer_ref = undefined
    }};
handle_info({gun_ws, _ConnPid, _StreamRef, {text, Data}}, State) ->
    ?dbg("Received WebSocket message: ~p~n", [Data]),
    case jsx:decode(Data, [return_maps]) of
        DecodedMessage when is_map(DecodedMessage) ->
            %% Check if this is a message_sent acknowledgment
            case maps:get(<<"type">>, DecodedMessage, undefined) of
                <<"message_sent">> ->
                    %% Handle acknowledgment
                    handle_message_ack(DecodedMessage, State);
                _ ->
                    %% 2. Verify message follows cryptic_messages module definitions
                    case cryptic_messages:validate_message(DecodedMessage) of
                        {ok, ValidatedMessage} ->
                            %% Log message type for debugging
                            MessageType = maps:get(
                                <<"type">>, ValidatedMessage, <<"unknown">>
                            ),
                            ?msg_in("Incoming message: ~s~n", [MessageType]),

                            %% 3. Dispatch valid message to ui_pid
                            dispatch_to_engine(ValidatedMessage, State);
                        {error, ValidationError} ->
                            %% 4. Drop invalid message and log the fact
                            ?warning(
                                "Message validation failed: ~p, Original: ~s", [
                                    ValidationError, Data
                                ]
                            ),
                            {noreply, State}
                    end
            end;
        _ ->
            %% JSON decode failed
            ?warning("Invalid JSON format: ~s", [Data]),
            {noreply, State}
    end;
%%
handle_info({gun_ws, _ConnPid, _StreamRef, {close, Code, Reason}}, State) ->
    ?info("WebSocket closed: ~p ~s", [Code, Reason]),
    {noreply, State#state{connected = false}};
%%
handle_info({gun_error, _ConnPid, _StreamRef, Reason}, State) ->
    ?error("WebSocket error: ~p", [Reason]),
    {noreply, State#state{connected = false}};
%%
handle_info(
    {gun_down, ConnPid, _Protocol, Reason, _KilledStreams},
    State = #state{conn_pid = ConnPid}
) ->
    ?warning("Connection down: ~p", [Reason]),
    Event = #{type => system_message,
              sys_code => server_connection_down,
              message => <<"Server connection lost!">>},
    cryptic_event_bus:publish(Event),
    %% Cancel ping timer if connection is down
    case State#state.ping_timer_ref of
        undefined -> ok;
        TimerRef -> erlang:cancel_timer(TimerRef)
    end,
    %% Start reconnection timer
    ?info("Will attempt to reconnect in ~p seconds", [?RECONNECT_TIMEOUT / 1000]),
    ReconnectTimerRef =
        erlang:send_after(?RECONNECT_TIMEOUT, self(), attempt_reconnect),
    {noreply, State#state{
        connected = false,
        ping_timer_ref = undefined,
        reconnect_timer_ref = ReconnectTimerRef
    }};
%%
handle_info(
    send_ping,
    State = #state{
        connected = true,
        conn_pid = ConnPid,
        stream_ref = StreamRef
    }
) ->
    %% Handle ping timer - send ping to keep connection alive
    gun:ws_send(ConnPid, StreamRef, ping),
    %% Schedule next ping
    PingTimerRef = erlang:send_after(?PING_TIMEOUT, self(), send_ping),
    {noreply, State#state{ping_timer_ref = PingTimerRef}};
handle_info(send_ping, State = #state{connected = false}) ->
    %% Don't send ping if not connected
    {noreply, State};
%% Handle pong response from server
handle_info({gun_ws, _ConnPid, _StreamRef, pong}, State) ->
    %%?msg_in("Received WebSocket pong", []),
    {noreply, State};
%% Handle reconnection attempt
handle_info(attempt_reconnect, State = #state{connected = false}) ->
    ?info("Attempting to reconnect to ~s:~p", [
        State#state.server_host, State#state.server_port
    ]),
    %% Close old connection if it exists
    case State#state.conn_pid of
        undefined -> ok;
        OldConnPid -> gun:close(OldConnPid)
    end,
    %% Attempt to reconnect
    case
        connect_websocket(State#state{
            conn_pid = undefined, stream_ref = undefined
        })
    of
        {ok, NewState} ->
            ?info("Reconnection successful", []),
            Event = #{type => system_message,
                      sys_code => server_connection_up,
                      message => <<"Server reconnected!">>},
            cryptic_event_bus:publish(Event),
            {noreply, NewState#state{reconnect_timer_ref = undefined}};
        {error, Reason} ->
            ?warning("Reconnection failed: ~p, will retry in 60 seconds", [
                Reason
            ]),
            Event = #{type => system_message,
                      sys_code => server_connection_down,
                      message => <<"Failed to reconnect to Server!">>},
            cryptic_event_bus:publish(Event),
            %% Schedule another reconnection attempt
            ReconnectTimerRef = erlang:send_after(
                ?RECONNECT_TIMEOUT, self(), attempt_reconnect
            ),
            {noreply, State#state{reconnect_timer_ref = ReconnectTimerRef}}
    end;
handle_info(attempt_reconnect, State = #state{connected = true}) ->
    %% Already connected, ignore
    {noreply, State#state{reconnect_timer_ref = undefined}};
%% Handle message retry timeout
handle_info({retry_message, MessageId}, State) ->
    case maps:get(MessageId, State#state.pending_acks, undefined) of
        undefined ->
            %% Message was already acknowledged or removed
            {noreply, State};
        {Command, _OldTimerRef, RetryCount} ->
            MaxRetries = 5,
            case State#state.connected of
                false ->
                    %% Not connected, don't count this as a retry attempt
                    %% Just reschedule for later (30 seconds)
                    ?dbg(
                        "Message ~s waiting for connection, will retry when connected",
                        [MessageId]
                    ),
                    NewTimerRef = erlang:send_after(
                        ?MSG_RETRY_TIMEOUT, self(), {retry_message, MessageId}
                    ),
                    NewPendingAcks = maps:put(
                        MessageId,
                        {Command, NewTimerRef, RetryCount},
                        State#state.pending_acks
                    ),
                    {noreply, State#state{pending_acks = NewPendingAcks}};
                true when RetryCount >= MaxRetries ->
                    %% Give up after max retries while connected
                    ?error(
                        "Message ~s failed after ~p retries, giving up",
                        [MessageId, MaxRetries]
                    ),
                    NewPendingAcks = maps:remove(
                        MessageId, State#state.pending_acks
                    ),
                    {noreply, State#state{pending_acks = NewPendingAcks}};
                true ->
                    %% Connected - retry sending the message
                    ?warning(
                        "Retrying message ~s (attempt ~p/~p)",
                        [MessageId, RetryCount + 1, MaxRetries]
                    ),
                    JsonCommand = jsx:encode(Command),
                    gun:ws_send(
                        State#state.conn_pid,
                        State#state.stream_ref,
                        {text, JsonCommand}
                    ),
                    %% Schedule another retry
                    NewTimerRef = erlang:send_after(
                        ?MSG_RETRY_TIMEOUT, self(), {retry_message, MessageId}
                    ),
                    NewPendingAcks = maps:put(
                        MessageId,
                        {Command, NewTimerRef, RetryCount + 1},
                        State#state.pending_acks
                    ),
                    {noreply, State#state{pending_acks = NewPendingAcks}}
            end
    end;
%% Handle events from the event bus
handle_info({event, #{type := websocket_outbound, message := Message}}, State) ->
    ?dbg("Received websocket_outbound event from bus: ~p", [Message]),
    %% Send the message via WebSocket
    {_Reply, NewState} = do_send_message(Message, State),
    {noreply, NewState};
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
terminate(_Reason, #state{
    conn_pid = ConnPid,
    ping_timer_ref = PingTimerRef,
    reconnect_timer_ref = ReconnectTimerRef,
    pending_acks = PendingAcks
}) when ConnPid =/= undefined ->
    %% Cancel ping timer
    case PingTimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(PingTimerRef)
    end,
    %% Cancel reconnect timer
    case ReconnectTimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(ReconnectTimerRef)
    end,
    %% Cancel all pending message retry timers
    maps:foreach(
        fun(_MessageId, {_Command, TimerRef, _RetryCount}) ->
            erlang:cancel_timer(TimerRef)
        end,
        PendingAcks
    ),
    gun:close(ConnPid);
terminate(_Reason, #state{
    ping_timer_ref = PingTimerRef,
    reconnect_timer_ref = ReconnectTimerRef,
    pending_acks = PendingAcks
}) ->
    %% Cancel timers even if no connection
    case PingTimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(PingTimerRef)
    end,
    case ReconnectTimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(ReconnectTimerRef)
    end,
    %% Cancel all pending message retry timers
    maps:foreach(
        fun(_MessageId, {_Command, TimerRef, _RetryCount}) ->
            erlang:cancel_timer(TimerRef)
        end,
        PendingAcks
    ),
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
%% @doc Gracefully close the WebSocket and gun connection.
%%
%% Performs an orderly shutdown of the connection without triggering
%% automatic reconnection. This is used during certificate reload.
%%
%% == Process ==
%%
%% <ol>
%%   <li>Send WebSocket close frame (if WebSocket is open)</li>
%%   <li>Wait briefly for clean closure</li>
%%   <li>Close gun connection</li>
%%   <li>Cancel reconnect timer if active</li>
%%   <li>Reset connection state</li>
%% </ol>
%%
%% @param State Current client state
%% @returns Updated state with connection closed
-spec close_connection_gracefully(#state{}) -> #state{}.
close_connection_gracefully(State) ->
    %% Send WebSocket close frame if connection is active
    case {State#state.conn_pid, State#state.stream_ref, State#state.connected} of
        {Conn, Stream, true} when Conn =/= undefined, Stream =/= undefined ->
            ?info("Sending WebSocket close frame", []),
            try
                gun:ws_send(Conn, Stream, close),
                %% Give it a moment to close cleanly
                timer:sleep(100)
            catch
                _:_ -> ok  %% Connection might already be dead
            end;
        _ ->
            ok
    end,
    
    %% Close gun connection
    case State#state.conn_pid of
        undefined -> ok;
        ConnPid ->
            ?info("Closing gun connection", []),
            try
                gun:close(ConnPid)
            catch
                _:_ -> ok
            end
    end,
    
    %% Cancel reconnect timer if one is active
    case State#state.reconnect_timer_ref of
        undefined -> ok;
        ReconnectTimer -> erlang:cancel_timer(ReconnectTimer)
    end,
    
    %% Reset connection state
    State#state{
        conn_pid = undefined,
        stream_ref = undefined,
        connected = false,
        reconnect_timer_ref = undefined
    }.

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

    %% TLS options with client certificate authentication
    %%
    %% Uses OTP 28 compatible certificates with proper Extended Key Usage (EKU) extensions:
    %% - Server certificates have "TLS Web Server Authentication" (1.3.6.1.5.5.7.3.1)
    %% - Client certificates have "TLS Web Client Authentication" (1.3.6.1.5.5.7.3.2)
    %% - All extensions use explicit OID format for maximum compatibility
    %%
    %% The certificates are generated using OpenSSL with specific configurations
    %% that ensure compatibility with Erlang/OTP 28's stricter certificate validation.

    %% Ensure server_host is a string (charlist) for gun:open and TLS options
    ServerHost =
        case is_list(State#state.server_host) of
            true -> State#state.server_host;
            false -> binary_to_list(State#state.server_host)
        end,

    TLSOptions = [
        {verify, verify_peer},
        {log_level, info},
        {versions, ['tlsv1.2']},
        %% Enable SNI with the server hostname for proper certificate validation
        {server_name_indication, ServerHost},
        {cacertfile, State#state.ca_file},
        {certfile, State#state.cert_file},
        {keyfile, State#state.key_file}
    ],

    ConnOpts = #{
        transport => tls,
        % Use http instead of http2 for simplicity
        protocols => [http],
        tls_opts => TLSOptions,
        % Increase connect timeout for slower networks/DNS resolution
        connect_timeout => 30000,
        % Increase TLS handshake timeout
        tls_handshake_timeout => 30000,
        % Retry configuration
        retry => 0,
        retry_timeout => 1000
    },

    ?info("Connecting to ~s:~p with TLS", [
        State#state.server_host, State#state.server_port
    ]),
    ?info("Using certificates", []),
    ?info("  CA: ~s", [State#state.ca_file]),
    ?info("  Client cert: ~s", [State#state.cert_file]),
    ?info("  Client key: ~s", [State#state.key_file]),

    ?info("Attempting to open gun connection to ~s:~p", [
        ServerHost, State#state.server_port
    ]),

    try gun:open(ServerHost, State#state.server_port, ConnOpts) of
        {ok, ConnPid} ->
            ?info(
                "Gun connection opened, awaiting TLS handshake (30s timeout)...",
                []
            ),
            case gun:await_up(ConnPid, 30000) of
                {ok, _Protocol} ->
                    ?info("TLS connection established successfully", []),
                    ?dbg(
                        "TLS connection established, upgrading to WebSocket~n",
                        []
                    ),
                    %% Connect to WebSocket endpoint (configurable: /ws for chat, /ca/ws for admin)
                    StreamRef = gun:ws_upgrade(ConnPid, State#state.ws_path),
                    NewState = State#state{
                        conn_pid = ConnPid,
                        stream_ref = StreamRef
                    },
                    {ok, NewState};
                {error, Reason} ->
                    ?error("TLS handshake failed: ~p", [Reason]),
                    gun:close(ConnPid),
                    {error, Reason}
            end;
        {error, Reason} ->
            ?error("Failed to open gun connection: ~p", [Reason]),
            {error, Reason}
        catch
            Class:Error ->
                ?error("Exception during gun connection: ~p:~p", [Class, Error]),
                {error, {Class, Error}}
    end.

%% @private
%% @doc Dispatch a validated message to the Engine process.
%%
%% Forwards all validated messages to the Engine process using a standardized
%% {websocket_message, Message} format. The Engine process is responsible for handling
%% the specific message types according to the cryptic_messages definitions.
%%
%% @param ValidatedMessage The validated message map from cryptic_messages
%% @param State Current client state
%% @returns `{noreply, State}'
dispatch_to_engine(ValidatedMessage, State) ->
    MessageType = maps:get(<<"type">>, ValidatedMessage, undefined),
    
    %% CA response messages should go to the console (ui_pid), not the engine
    %% The engine handles chat/ratchet messages, console handles CA operations
    IsCAResponse = case MessageType of
        %% Legacy invite responses
        <<"invite_create_response">> -> true;
        <<"invite_list_response">> -> true;
        <<"invite_revoke_response">> -> true;
        <<"invite_show_response">> -> true;
        %% Admin user management responses
        <<"register_user_response">> -> true;
        <<"list_users_response">> -> true;
        <<"get_user_info_response">> -> true;
        <<"suspend_user_response">> -> true;
        <<"revoke_user_response">> -> true;
        <<"reactivate_user_response">> -> true;
        %% Certificate management responses
        <<"list_certificates_response">> -> true;
        <<"revoke_certificate_response">> -> true;
        <<"csr_response">> -> true;
        _ -> false
    end,

    case IsCAResponse of
        true ->
            %% Publish CA response to event bus for console
            ?dbg("Publishing CA response event to bus: ~p~n", [ValidatedMessage]),
            cryptic_event_bus:publish(#{
                type => ca_response,
                response => ValidatedMessage
            });
        false ->
            %% Publish websocket message to event bus for engine
            ?dbg("Publishing websocket_message event to bus: ~p~n", [ValidatedMessage]),
            cryptic_event_bus:publish(#{
                type => websocket_message,
                message => ValidatedMessage
            })
    end,
    {noreply, State}.

%% @private
%% @doc Add message tracking for messages that need acknowledgment.
%%
%% Generates a unique message_id (if not present), adds it to the command,
%% and starts tracking the message for acknowledgment.
%%
%% @param Command The command to send
%% @param State Current client state
%% @returns {CommandWithId, NewState}
add_message_tracking(Command, State) ->
    %% Use existing message_id or generate a new one
    MessageId =
        case maps:get(<<"message_id">>, Command, undefined) of
            undefined ->
                %% Generate unique ID using timestamp and random bytes
                Timestamp = erlang:system_time(microsecond),
                RandomBytes = crypto:strong_rand_bytes(8),
                base64:encode(<<Timestamp:64, RandomBytes/binary>>);
            ExistingId ->
                ExistingId
        end,

    %% Add message_id to command
    CommandWithId = Command#{<<"message_id">> => MessageId},

    %% Start retry timer
    TimerRef =
        erlang:send_after(
            ?MSG_RETRY_TIMEOUT, self(), {retry_message, MessageId}
        ),

    %% Track this message
    NewPendingAcks = maps:put(
        MessageId, {CommandWithId, TimerRef, 0}, State#state.pending_acks
    ),

    {CommandWithId, State#state{pending_acks = NewPendingAcks}}.

%% @private
%% @doc Handle message acknowledgment from the server.
%%
%% Removes the message from pending acknowledgments and cancels the retry timer.
%%
%% @param AckMessage The message_sent acknowledgment from server
%% @param State Current client state
%% @returns {noreply, NewState}
handle_message_ack(AckMessage, State) ->
    case maps:get(<<"message_id">>, AckMessage, undefined) of
        undefined ->
            ?warning("Received message_sent without message_id: ~p", [
                AckMessage
            ]),
            {noreply, State};
        MessageId ->
            case maps:get(MessageId, State#state.pending_acks, undefined) of
                undefined ->
                    %% Unknown message_id, might be a duplicate ack
                    ?dbg("Received ack for unknown message: ~s", [MessageId]),
                    {noreply, State};
                {_Command, TimerRef, _RetryCount} ->
                    %% Cancel the retry timer
                    erlang:cancel_timer(TimerRef),
                    %% Remove from pending acks
                    NewPendingAcks = maps:remove(
                        MessageId, State#state.pending_acks
                    ),
                    ?dbg("Message ~s acknowledged by server", [MessageId]),
                    {noreply, State#state{pending_acks = NewPendingAcks}}
            end
    end.
