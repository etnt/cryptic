-module(cryptic_ws_client).
-behaviour(gen_server).

-export([start_link/2, start_link/3, send_command/2, stop/1, set_ui_pid/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, handle_continue/2]).

-include("cryptic.hrl").

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

%% API
start_link(Username, ServerHost) ->
    start_link(Username, ServerHost, #{}).

start_link(Username, ServerHost, Config) ->
    gen_server:start_link(?MODULE, {Username, ServerHost, Config}, []).

send_command(Pid, Command) ->
    gen_server:call(Pid, {send_command, Command}).

stop(Pid) ->
    gen_server:call(Pid, stop).

set_ui_pid(Pid, UiPid) ->
    gen_server:call(Pid, {set_ui_pid, UiPid}).

%% Callbacks
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

handle_continue(connect, State) ->
    case connect_websocket(State) of
        {ok, NewState} ->
            {noreply, NewState};
        {error, Reason} ->
            ?error("Failed to connect: ~p", [Reason]),
            {stop, {connection_failed, Reason}, State}
    end.

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

handle_cast(_Msg, State) ->
    {noreply, State}.

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

terminate(_Reason, #state{conn_pid = ConnPid, ping_timer_ref = TimerRef}) when ConnPid =/= undefined ->
    %% Cancel ping timer
    case TimerRef of
        undefined -> ok;
        _ -> erlang:cancel_timer(TimerRef)
    end,
    gun:close(ConnPid);
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal functions
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
