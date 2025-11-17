%%% @doc Cryptic Console - Interactive terminal interface for the Cryptic Engine
%%%
%%% This module provides a sophisticated console interface for the Cryptic messaging engine
%%% with support for asynchronous message handling, input buffer preservation across
%%% interruptions, and command history.
%%%
%%% == Features ==
%%% <ul>
%%%   <li>Non-blocking async message delivery while waiting for user input</li>
%%%   <li>Input buffer preservation when interrupted by system messages</li>
%%%   <li>Command history navigation with Up/Down arrows and Ctrl+P/Ctrl+N</li>
%%%   <li>Line editing with Emacs-style keybindings</li>
%%%   <li>ANSI colored output for better readability</li>
%%%   <li>Secure passphrase input with character masking</li>
%%% </ul>
%%%
%%% == Architecture ==
%%% The console uses a two-process design to handle asynchronous events:
%%%
%%% <ul>
%%%   <li><b>Console Process</b>: Main loop that manages state and handles messages</li>
%%%   <li><b>Input Process</b>: Spawned per-prompt to wait for user input (can be killed)</li>
%%% </ul>
%%%
%%% This design allows the console to respond to async messages (like incoming chat messages)
%%% while blocking on user input. When a message arrives, the input process is killed,
%%% the message is displayed, and a new input process is spawned.
%%%
%%% == Process Flow ==
%%% <pre>
%%% ┌─────────────────────────────────────────────────────────────┐
%%% │ Console Process (main loop)                                 │
%%% └─────────────────────────────────────────────────────────────┘
%%%                            │
%%%                            ▼
%%%                    command_loop(State)
%%%                            │
%%%                            ├─ check_messages() (handle any pending async messages)
%%%                            │
%%%                            ├─ spawn_input_process() → Input Process
%%%                            │                               │
%%%                            │                               ├─ display prompt
%%%                            │                               ├─ cryptic_shell:get_line()
%%%                            │                               └─ wait for user input...
%%%                            │
%%%                            ▼
%%%          wait_for_input_or_messages(InputPid, MonitorRef, State)
%%%                            │
%%%                            ├─ Waiting for one of:
%%%                            │  • {input_result, Line}    ← Input arrived
%%%                            │  • {system_message, Msg}   ← Async message
%%%                            │  • {'DOWN', ...}           ← Input process died
%%%                            │
%%%                            ▼
%%%             ┌──────────────┴──────────────┐
%%%             │                             │
%%%     User typed something         Async message arrived
%%%             │                             │
%%%             ▼                             ▼
%%% {input_result, Line}          {system_message, Msg}
%%%             │                             │
%%%             ├─ parse_command()            ├─ exit(InputPid, kill)
%%%             ├─ execute_command()          ├─ display_async_message()
%%%             │                             ├─ wait for {'DOWN', ...}
%%%             ▼                             │
%%%     command_loop(NewState) ───────────────┘
%%%     (spawn new Input process)
%%% </pre>
%%%
%%% == Input Buffer Preservation ==
%%% When an async message interrupts user input, any partially typed text is preserved
%%% in an ETS table (`cryptic_console_input_buffer') and restored when the prompt returns.
%%% This prevents data loss and improves user experience.
%%%
%%% == Command History ==
%%% The console maintains a history of up to 100 commands in the same ETS table,
%%% accessible via Up/Down arrows or Ctrl+P/Ctrl+N keybindings.
%%%
%%% @see cryptic_shell
%%% @see cryptic_engine
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_console).

%% API
-export([main/1]).

%% Used by cryptic_rpc
-export([parse_admin_register_opts/2]).

%% Include ANSI escape sequence macros for terminal formatting
-include("cryptic_ansi.hrl").
-include("cryptic.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Internal state record
-record(console_state, {
    ws_client_pid :: pid() | undefined,
    engine_pid :: pid() | undefined,
    username :: binary(),
    server_host :: string(),
    server_port :: non_neg_integer(),
    verbose :: boolean(),
    console_pid :: pid() | undefined,
    input_buffer_table :: ets:tid() | undefined,
    notifier :: string() | undefined,
    passphrase :: binary() | undefined,
    %% Whether encrypted message storage is enabled
    db_enabled :: boolean(),
    %% Are we using an external TUI?
    tui_mode = false :: boolean()
}).

%%%===================================================================
%%% Api Functions
%%%===================================================================


%% @doc Main entry point for the console
-spec main(Config :: map()) -> ok.
main(InitCfg) ->
    process_flag(trap_exit, true),

     %% Initialize the enhanced shell only if not in TUI mode
    case is_tui_mode(InitCfg) of
        true ->
            %% In TUI mode, skip shell initialization
            %% The external cryptic-tui will handle all UI
            ok;
        false ->
            %% Initialize the enhanced shell for interactive mode
            case cryptic_shell:start_shell(InitCfg) of
                ok ->
                    ok;
                {error, _ShellError} ->
                    ?error("Failed to start cryptic shell, stopping...~n",[]),
                    init:stop(1)
            end
    end,

    %% Prompt for passphrase early
    Passphrase = get_passphrase(maps:get(tui_mode, InitCfg, false)),

    %% Initialize alias storage
    case cryptic_alias:initialize() of
        ok ->
            ok;
        {error, already_exists} ->
            %% Table already exists, which is fine
            ok
    end,

    %% Start the Event bus
    cryptic_event_bus:start_link(),

    %% Now continue with initialization
    CertCfg = get_cert_config(InitCfg),

    %% Start WebSocket client
    %% Temporarily suppress crash reports to avoid ugly output for connection errors
    %% We suppress both SASL and the logger to prevent crash dumps
    OldSASL = application:get_env(sasl, sasl_error_logger, tty),
    application:set_env(sasl, sasl_error_logger, false),

    %% Get current logger level and set to emergency (suppresses most output)
    OldLoggerLevel = logger:get_primary_config(),
    OldLevel = maps:get(level, OldLoggerLevel, notice),
    logger:set_primary_config(level, emergency),

    WsCfg = CertCfg#{callback_mod => ?MODULE},
    WsClientPid =
        try cryptic_ws_client:start_link(WsCfg) of
            {ok, _WsClientPid} ->
                %% Restore logging
                application:set_env(sasl, sasl_error_logger, OldSASL),
                logger:set_primary_config(level, OldLevel),
                _WsClientPid;
            {error, {connection_failed, Reason}} ->
                %% Restore logging
                application:set_env(sasl, sasl_error_logger, OldSASL),
                logger:set_primary_config(level, OldLevel),
                %% Connection failed during init - format error nicely
                ErrorMsg = format_connection_error(Reason),
                cryptic_shell:print_error(ErrorMsg),
                halt(1);
            {error, {bad_return_value, {stop, {connection_failed, Reason}}}} ->
                %% Restore logging
                application:set_env(sasl, sasl_error_logger, OldSASL),
                logger:set_primary_config(level, OldLevel),
                %% Format TLS/connection errors nicely (older format)
                ErrorMsg = format_connection_error(Reason),
                cryptic_shell:print_error(ErrorMsg),
                halt(1);
            _Error ->
                %% Restore logging
                application:set_env(sasl, sasl_error_logger, OldSASL),
                logger:set_primary_config(level, OldLevel),
                cryptic_shell:print_error(
                    "Failed to start WebSocket client: " ++
                        lists:flatten(io_lib:format("~p~n", [_Error]))
                ),
                halt(1)
        catch
            error:Reason ->
                %% Restore logging
                application:set_env(sasl, sasl_error_logger, OldSASL),
                logger:set_primary_config(level, OldLevel),
                cryptic_shell:print_error(
                    "Failed to start WebSocket client: " ++
                        lists:flatten(io_lib:format("~p~n", [Reason]))
                ),
                halt(1)
        end,

    %% Check if database storage is enabled (from config map or application env)
    DbEnabled = maps:get(
        enable_db, InitCfg, application:get_env(cryptic, enable_db, false)
    ),
    %% Initialize message storage only if enabled
    Username = maps:get(username, InitCfg),
    case DbEnabled of
        true ->
            case
                cryptic_chat_storage:init_storage(
                    binary_to_list(Username), Passphrase
                )
            of
                ok ->
                    cryptic_shell:print_info("Message storage initialized");
                {error, StorageReason} ->
                    cryptic_shell:print_warning(
                        "Failed to initialize message storage: " ++
                            lists:flatten(io_lib:format("~p", [StorageReason]))
                    )
            end;
        false ->
            cryptic_shell:print_info(
                "Message storage disabled (enable_db=false in config)"
            )
    end,

    %% Get console PID to pass to callbacks
    ConsolePid = self(),

    %% Subscribe to event bus for console-relevant messages
    %% Filter for: deliver_message, system_message, ca_response events
    ConsoleFilter = fun(Event) ->
        case Event of
            #{type := deliver_message} -> true;
            #{type := system_message} -> true;
            #{type := ca_response} -> true;
            #{type := websocket_message} -> true;
            _ -> false
        end
    end,
    ok = cryptic_event_bus:subscribe(ConsolePid, ConsoleFilter),

    %% Start cryptic engine with passphrase and WebSocket client PID
    %% In TUI mode, pass the flag so engine knows to defer key loading
    EngineCfg = CertCfg#{
        callback_mod => cryptic_console_callbacks,
        username => Username,
        passphrase => Passphrase,
        ws_client_pid => WsClientPid,
        console_pid => ConsolePid,
        tui_mode => maps:get(tui_mode, InitCfg, false)
    },
    {ok, EnginePid} = cryptic_engine:start_link(EngineCfg),

    %% Create named ETS table for input buffer preservation
    %% Use named table so cryptic_shell can access it directly
    InputBufferTable = ets:new(cryptic_console_input_buffer, [
        set, public, named_table
    ]),

    %% Extract server host and port from config
    ServerHostRaw = maps:get(server_host, InitCfg, <<"localhost">>),
    ServerHost =
        case ServerHostRaw of
            S when is_binary(S) -> binary_to_list(S);
            S when is_list(S) -> S;
            _ -> "localhost"
        end,
    ServerPort = maps:get(server_port, InitCfg, 8443),

    %% Initialize console state with self() PID and passphrase
    State = #console_state{
        ws_client_pid = WsClientPid,
        engine_pid = EnginePid,
        username = Username,
        server_host = ServerHost,
        server_port = ServerPort,
        verbose = maps:get(verbose, CertCfg, false),
        console_pid = ConsolePid,
        input_buffer_table = InputBufferTable,
        notifier = maps:get(notifier, InitCfg, undefined),
        passphrase = Passphrase,
        db_enabled = DbEnabled,
        tui_mode = maps:get(tui_mode, InitCfg, false)
    },

    %% Start command loop or wait in TUI mode
    case is_tui_mode(InitCfg) of
        true ->
            %% In TUI mode, don't start the command loop
            %% Just wait for messages and keep the process alive
            tui_wait_loop(State);
        false ->
            %% Interactive mode - start command loop
            cryptic_shell:print_success(
                "Cryptic Console ready. Type 'help' for commands."
            ),
            command_loop(State)
    end.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Send message to server via event bus
%% Publishes a websocket_outbound event that will be picked up by cryptic_ws_client
-spec send_to_server(Message :: map()) -> ok.
send_to_server(Message) ->
    cryptic_event_bus:publish(#{
        type => websocket_outbound,
        message => Message
    }),
    ok.

%% @doc Prompt for and get the passphrase securely
-spec get_passphrase(boolean()) -> binary().
get_passphrase(true = _TUImode) ->
    receive
        {set_passphrase, Passphrase} ->
            Passphrase
    after 30000 ->
        ?error("~p: No passphrase received, stopping...~ n",[?MODULE]),
        init:stop(1)
    end;
get_passphrase(false = TUImode) ->
    case cryptic_shell:get_password("Enter passphrase: ") of
        eof ->
            cryptic_shell:print_error("Passphrase required. Exiting..."),
            halt(1);
        Passphrase when is_list(Passphrase) ->
            case length(Passphrase) of
                0 ->
                    io:format(
                        "Empty passphrase not allowed. Please try again.\r\n"
                    ),
                    get_passphrase(TUImode);
                _ ->
                    list_to_binary(Passphrase)
            end;
        {error, Reason} ->
            cryptic_shell:print_error(
                "Error reading passphrase: " ++
                    lists:flatten(io_lib:format("~p", [Reason]))
            ),
            halt(1)
    end.

%% @doc Format connection errors in a user-friendly way
-spec format_connection_error(term()) -> string().
format_connection_error({down, {shutdown, {tls_alert, {handshake_failure, Msg}}}}) ->
    %% TLS handshake failure - likely certificate rejected
    case string:find(Msg, "Handshake Failure") of
        nomatch -> 
            "Connection failed: TLS handshake error - " ++ Msg;
        _ ->
            "Connection rejected: Your certificate has been revoked or is invalid.\n\r" ++
            "Request a new certificate via the cryptic-onboarding script,\n\r" ++
            "or contact your administrator for a new certificate."
    end;
format_connection_error({down, {shutdown, {tls_alert, {Alert, Msg}}}}) ->
    %% Other TLS alerts
    AlertStr = atom_to_list(Alert),
    "Connection failed: TLS alert (" ++ AlertStr ++ "): " ++ Msg ++ "\n\r";
format_connection_error({down, {shutdown, Reason}}) ->
    "Connection failed during TLS handshake: " ++ 
    lists:flatten(io_lib:format("~p", [Reason])) ++ "\n\r";
format_connection_error(Reason) ->
    "Connection failed: " ++ lists:flatten(io_lib:format("~p", [Reason])).


%%% @doc Get certificate configuration
-spec get_cert_config(Cfg :: map()) -> map().
get_cert_config(Cfg) ->
    Username = binary_to_list(maps:get(username, Cfg)),
    CrypticDir = maps:get(cryptic_dir, Cfg),

    ServerHost =
        case maps:get(server_host, Cfg) of
            S when is_binary(S) -> binary_to_list(S);
            S when is_list(S) -> S;
            _ -> "localhost"
        end,
    ServerPort = maps:get(server_port, Cfg, 8443),

    %% Create certificate configuration using environment variables
    CertFile =
        case os:getenv("CRYPTIC_CLIENT_CERT") of
            false -> CrypticDir ++ "/certificates/" ++ Username ++ ".crt";
            EnvCert -> EnvCert
        end,
    KeyFile =
        case os:getenv("CRYPTIC_CLIENT_KEY") of
            false -> CrypticDir ++ "/certificates/" ++ Username ++ ".key";
            EnvKey -> EnvKey
        end,
    CAFile =
        case os:getenv("CRYPTIC_CA_CERT") of
            false -> CrypticDir ++ "/certificates/ca.crt";
            EnvCA -> EnvCA
        end,

    Cfg#{
        cert_file => CertFile,
        key_file => KeyFile,
        ca_file => CAFile,
        server_host => ServerHost,
        server_port => ServerPort
    }.

%% @doc Main command loop with async message handling
command_loop(State) ->
    %% Check for any pending system messages before prompting
    check_messages_with_state(State),

    %% Spawn a process to get input asynchronously with monitoring
    {InputPid, MonitorRef} = spawn_input_process(),

    %% Wait for either input or messages
    wait_for_input_or_messages(InputPid, MonitorRef, State).


%% @doc Spawn an input process to get user input asynchronously
%% The input process will wait for user input and send the result back
%% to the console process, then terminate.
-spec spawn_input_process() -> {pid(), reference()}.
spawn_input_process() ->
    ConsolePid = self(),
    spawn_opt(
        fun() ->
            %% cryptic_shell:get_line() will automatically restore any saved
            %% input from the ETS table if present
            Result = cryptic_shell:get_line(),
            ConsolePid ! {input_result, Result}
        end,
        [monitor]
    ).

%% @doc Wait for input result or handle incoming messages
wait_for_input_or_messages(InputPid, MonitorRef, State) ->
    receive
        {input_result, eof} ->
            demonitor(MonitorRef, [flush]),
            io:format("Exiting...\r\n"),
            cleanup(State),
            ok;
        {input_result, {error, Reason}} ->
            demonitor(MonitorRef, [flush]),
            io:format("Input error: ~p\r\n", [Reason]),
            cleanup(State),
            error;
        {input_result, Line} ->
            demonitor(MonitorRef, [flush]),
            Command = string:trim(Line),
            case parse_command(Command) of
                {quit} ->
                    cryptic_shell:print_highlight("Goodbye!"),
                    cleanup(State);
                {help} ->
                    cryptic_shell:print_help(),
                    command_loop(State);
                {help, Topic} ->
                    cryptic_shell:print_help(Topic),
                    command_loop(State);
                ParsedCmd ->
                    NewState = execute_command(ParsedCmd, State),
                    command_loop(NewState)
            end;
        {'DOWN', MonitorRef, process, InputPid, _Reason} ->
            %% Input process died (we killed it), restart command loop
            command_loop(State);
        {event, #{type := ca_response, response := Response}} ->
            %% CA operation response arrived while waiting for input
            exit(InputPid, kill),
            %% Display the CA response
            display_ca_response(Response),
            %% Continue waiting - the DOWN message will trigger restart
            wait_for_input_or_messages(InputPid, MonitorRef, State);
        {event, #{type := system_message, message := Message}} ->
            %% A message arrived while waiting for input
            %% Note: We can't retrieve the actual input buffer from the blocked process
            %% A future enhancement would be to modify cryptic_shell to support this
            %% For now, we just interrupt and restart
            exit(InputPid, kill),
            %% Display the system message
            display_system_message(Message),
            %% Continue waiting - the DOWN message will trigger restart
            wait_for_input_or_messages(InputPid, MonitorRef, State);
        {event, #{type := deliver_message, from := FromUsername, message := Message, timestamp := Timestamp}} ->
            %% A chat message arrived while waiting for input
            %% Note: We can't retrieve the actual input buffer from the blocked process
            %% A future enhancement would be to modify cryptic_shell to support this
            %% For now, we just interrupt and restart
            exit(InputPid, kill),
            %% Display the user message
            display_user_message(FromUsername, Message, Timestamp),
            notify_user(
                FromUsername,
                Message,
                Timestamp,
                State#console_state.notifier
            ),

            %% Save message to storage if database is enabled
            case State of
                #console_state{
                    username = ToUsername,
                    server_host = ServerHost,
                    server_port = ServerPort,
                    passphrase = Passphrase,
                    db_enabled = true
                } when Passphrase =/= undefined ->
                    % Message is already a binary, no need to convert
                    % Convert erlang:timestamp() to calendar:datetime()
                    DateTime = calendar:now_to_datetime(Timestamp),
                    case
                        cryptic_chat_storage:save_encrypted_message(
                            FromUsername,
                            binary_to_list(ToUsername),
                            ServerHost,
                            ServerPort,
                            Message,
                            DateTime,
                            Passphrase
                        )
                    of
                        ok ->
                            ok;
                        {error, Reason} ->
                            io:format(
                                "~n[ERROR] Failed to save message: ~p~n", [
                                    Reason
                                ]
                            )
                    end;
                _ ->
                    % Skip storage if no state, passphrase, or database disabled
                    ok
            end,

            %% Continue waiting - the DOWN message will trigger restart
            wait_for_input_or_messages(InputPid, MonitorRef, State);
        {event, #{type := websocket_message, message := Message}} ->
            %% WebSocket message arrived while waiting for input
            exit(InputPid, kill),
            %% Display the websocket message response
            display_websocket_message(Message),
            %% Continue waiting - the DOWN message will trigger restart
            wait_for_input_or_messages(InputPid, MonitorRef, State);

        {get_engine_pid, From}  ->
            %% For example, from the TUI bridge process
            From ! {engine_pid, State#console_state.engine_pid},
            wait_for_input_or_messages(InputPid, MonitorRef, State);

        Other ->
            ?dbg("cryptic_console received unknown message: ~p~n", [Other]),
            wait_for_input_or_messages(InputPid, MonitorRef, State)

    end.

%% @doc Wait loop for TUI mode - just handle messages, no input
%% In TUI mode, the external cryptic-tui handles all user interaction
%% This loop keeps the backend alive and processes events
tui_wait_loop(State) ->
    receive
        {event, #{type := system_message, message := Message}} ->
            ?dbg("TUI backend received system message: ~s~n", [Message]),
            tui_wait_loop(State);
        {event, #{type := deliver_message, from := FromUsername, message := Message, timestamp := Timestamp}} ->
            ?dbg("TUI backend received message from ~s~n", [FromUsername]),
            %% Save message to storage if database is enabled
            case State of
                #console_state{
                    username = ToUsername,
                    server_host = ServerHost,
                    server_port = ServerPort,
                    passphrase = Passphrase,
                    db_enabled = true
                } when Passphrase =/= undefined, Passphrase =/= <<"tui-mode-placeholder">> ->
                    DateTime = calendar:now_to_datetime(Timestamp),
                    case
                        cryptic_chat_storage:save_encrypted_message(
                            FromUsername,
                            binary_to_list(ToUsername),
                            ServerHost,
                            ServerPort,
                            Message,
                            DateTime,
                            Passphrase
                        )
                    of
                        ok ->
                            ?dbg("Message saved to storage~n", []);
                        {error, Reason} ->
                            ?dbg("Failed to save message: ~p~n", [Reason])
                    end;
                _ ->
                    ok
            end,
            tui_wait_loop(State);
        {event, #{type := websocket_message, message := _Message}} ->
            ?dbg("TUI backend received websocket message (ignoring - TUI subscribes directly)~n", []),
            %% TUI already subscribes to event bus directly, no need to re-publish
            tui_wait_loop(State);
        {get_engine_pid, From}  ->
            %% For the TUI bridge process to get engine PID
            From ! {engine_pid, State#console_state.engine_pid},
            tui_wait_loop(State);
        {set_passphrase, From, Passphrase} ->
            %% TUI has received passphrase from user, initialize engine with it
            ?dbg("TUI backend received passphrase, initializing engine...~n", []),
            EnginePid = State#console_state.engine_pid,
            case cryptic_engine:initialize_with_passphrase(EnginePid, Passphrase) of
                ok ->
                    ?dbg("Engine initialized successfully~n", []),
                    %% Update state with real passphrase
                    NewState = State#console_state{passphrase = Passphrase},
                    %% Initialize database with real passphrase if enabled
                    case State#console_state.db_enabled of
                        true ->
                            Username = State#console_state.username,
                            case cryptic_chat_storage:init_storage(
                                binary_to_list(Username), Passphrase
                            ) of
                                ok ->
                                    ?dbg("Message storage initialized~n", []);
                                {error, StorageReason} ->
                                    ?dbg("Failed to initialize message storage: ~p~n", [StorageReason])
                            end;
                        false ->
                            ok
                    end,
                    From ! {passphrase_set, ok},
                    tui_wait_loop(NewState);
                {error, Reason} ->
                    ?dbg("Failed to initialize engine: ~p~n", [Reason]),
                    From ! {passphrase_set, {error, Reason}},
                    tui_wait_loop(State)
            end;

        {'EXIT', _Pid, Reason} ->
            ?dbg("TUI backend exiting: ~p~n", [Reason]),
            ok;

        {tui_node_down, TuiNode} ->
            ?info("cryptic_console: TUI node down: ~p , stopping...~n",[TuiNode]),
            init:stop();

        Other ->
            ?dbg("cryptic_console (tui)  received unknown message: ~p~n", [Other]),
            tui_wait_loop(State)
    end.

%% @doc Parse user commands
%% Supports both full commands and shortcut commands (prefixed with ':')
parse_command("") ->
    {noop};
%% Shortcut commands (colon-prefixed)
parse_command(":h") ->
    {help};
parse_command(":q") ->
    {quit};
parse_command(":st") ->
    {status};
parse_command(":es") ->
    {engine_status};
parse_command(":v") ->
    {verbose, toggle};
%% Alias shortcut commands
parse_command(":a") ->
    {alias_cmd, list};
parse_command(":al") ->
    {alias_cmd, list};
%% History shortcut commands
parse_command(":hi") ->
    {history_cmd, {last_n, 10}};
parse_command(":hi " ++ Args) ->
    parse_history_command(Args);
%% Admin shortcut commands
parse_command(":ar " ++ Args) ->
    parse_admin_register(Args);
parse_command(":au") ->
    {admin_cmd, list};
%% Cert shortcut commands
parse_command(":cs") ->
    {cert_cmd, status};
parse_command(":cr") ->
    {cert_cmd, renew, #{}};
parse_command(":on") ->
    {online_cmd};
%% Full commands
parse_command("help") ->
    {help};
parse_command("quit") ->
    {quit};
parse_command("exit") ->
    {quit};
parse_command("status") ->
    {status};
parse_command("engine_status") ->
    {engine_status};
parse_command("verbose") ->
    {verbose, toggle};
parse_command("alias") ->
    {alias_cmd, list};
parse_command("db enable") ->
    {db_cmd, enable};
parse_command("db disable") ->
    {db_cmd, disable};
parse_command("db status") ->
    {db_cmd, status};
parse_command("db") ->
    {db_cmd, status};
parse_command("history") ->
    {history_cmd, {last_n, 10}};
parse_command("history " ++ Args) ->
    parse_history_command(Args);
%% Online users command
parse_command("online") ->
    {online_cmd};
%% Admin commands
parse_command("admin") ->
    {admin_cmd, list};
parse_command("admin register " ++ Args) ->
    parse_admin_register(Args);
parse_command("admin list") ->
    {admin_cmd, list};
parse_command("admin status " ++ GpgFp) ->
    {admin_cmd, status, string:trim(GpgFp)};
parse_command("admin suspend " ++ GpgFp) ->
    {admin_cmd, suspend, string:trim(GpgFp)};
parse_command("admin revoke " ++ GpgFp) ->
    {admin_cmd, revoke, string:trim(GpgFp)};
parse_command("admin reactivate " ++ GpgFp) ->
    {admin_cmd, reactivate, string:trim(GpgFp)};
parse_command("admin certs " ++ GpgFp) ->
    {admin_cmd, list_certs, string:trim(GpgFp)};
parse_command("admin revoke-cert " ++ Serial) ->
    {admin_cmd, revoke_cert, string:trim(Serial)};
%% Cert commands
parse_command("cert") ->
    {cert_cmd, status};
parse_command("cert status") ->
    {cert_cmd, status};
parse_command("cert renew") ->
    {cert_cmd, renew, #{}};
parse_command("cert renew " ++ Options) ->
    parse_cert_renew_options(Options);
%% Check for shortcut send command ":s <username> <message>"
%% Check for shortcut alias commands ":an/:ad/:aa/:ar <...>"
parse_command(Line) ->
    case string:prefix(Line, ":s ") of
        nomatch ->
            case check_alias_shortcuts(Line) of
                nomatch ->
                    %% Not a shortcut, parse as regular command
                    Parts = string:tokens(Line, " "),
                    parse_command_parts(Parts);
                AliasCmd ->
                    AliasCmd
            end;
        Rest ->
            %% Shortcut send command
            Parts = string:tokens(Rest, " "),
            parse_command_parts(["send" | Parts])
    end.

parse_command_parts(["send", ToUsername | MessageParts]) ->
    Message = string:join(MessageParts, " "),
    %% Check if ToUsername starts with @
    case ToUsername of
        [$@ | AliasName] ->
            %% Expand alias to multiple send commands
            case cryptic_alias:list(AliasName) of
                {ok, Members} ->
                    {send_to_alias, AliasName, Members,
                        unicode:characters_to_binary(Message)};
                {error, not_found} ->
                    {error, "Alias '@" ++ AliasName ++ "' not found"}
            end;
        _ ->
            {send_message, unicode:characters_to_binary(ToUsername),
                unicode:characters_to_binary(Message)}
    end;
parse_command_parts(["alias"]) ->
    {alias_cmd, list};
parse_command_parts(["alias", "list"]) ->
    {alias_cmd, list};
parse_command_parts(["alias", "new", AliasName | Members]) when
    length(Members) > 0
->
    {alias_cmd, new, AliasName, Members};
parse_command_parts(["alias", "delete", AliasName]) ->
    {alias_cmd, delete, AliasName};
parse_command_parts(["alias", "add", AliasName | Members]) when
    length(Members) > 0
->
    {alias_cmd, add, AliasName, Members};
parse_command_parts(["alias", "rm", AliasName | Members]) when
    length(Members) > 0
->
    {alias_cmd, rm, AliasName, Members};
parse_command_parts(["help"]) ->
    {help};
parse_command_parts(["help", Topic]) ->
    {help, Topic};
parse_command_parts(_) ->
    {error, "Unknown command"}.

%% @doc Check for alias shortcut commands
check_alias_shortcuts(Line) ->
    case string:prefix(Line, ":an ") of
        nomatch ->
            case string:prefix(Line, ":ad ") of
                nomatch ->
                    case string:prefix(Line, ":aa ") of
                        nomatch ->
                            case string:prefix(Line, ":ar ") of
                                nomatch -> nomatch;
                                Rest -> parse_alias_rm_shortcut(Rest)
                            end;
                        Rest ->
                            parse_alias_add_shortcut(Rest)
                    end;
                Rest ->
                    {alias_cmd, delete, string:trim(Rest)}
            end;
        Rest ->
            parse_alias_new_shortcut(Rest)
    end.

%% Parse alias new shortcut: ":an <name> <member1> <member2> ..."
parse_alias_new_shortcut(Rest) ->
    case string:tokens(Rest, " ") of
        [AliasName | Members] when length(Members) > 0 ->
            {alias_cmd, new, AliasName, Members};
        _ ->
            {error, "Usage: :an <alias_name> <member1> [member2 ...]"}
    end.

%% Parse alias add shortcut: ":aa <name> <member1> <member2> ..."
parse_alias_add_shortcut(Rest) ->
    case string:tokens(Rest, " ") of
        [AliasName | Members] when length(Members) > 0 ->
            {alias_cmd, add, AliasName, Members};
        _ ->
            {error, "Usage: :aa <alias_name> <member1> [member2 ...]"}
    end.

%% Parse alias rm shortcut: ":ar <name> <member1> <member2> ..."
parse_alias_rm_shortcut(Rest) ->
    case string:tokens(Rest, " ") of
        [AliasName | Members] when length(Members) > 0 ->
            {alias_cmd, rm, AliasName, Members};
        _ ->
            {error, "Usage: :ar <alias_name> <member1> [member2 ...]"}
    end.

%% @doc Parse history command arguments
%% Examples:
%%   "from bob yesterday"  -> {from, "bob", yesterday}
%%   "from alice last 10"  -> {from_last_n, "alice", 10}
%%   "last 10"             -> {last_n, 10}
%%   "with bob last 20"    -> {conversation, "bob", 20}
%%   ""                    -> {last_n, 10} (default)
parse_history_command("") ->
    {history_cmd, {last_n, 10}};
parse_history_command(Args) ->
    Tokens = string:tokens(Args, " "),
    Result =
        case Tokens of
            ["from", User, "yesterday"] ->
                {from_yesterday, User};
            ["from", User, "last", NStr] ->
                try_parse_last_n(NStr, fun(N) -> {from_last_n, User, N} end);
            ["last", NStr] ->
                try_parse_last_n(NStr, fun(N) -> {last_n, N} end);
            ["with", User, "last", NStr] ->
                try_parse_last_n(NStr, fun(N) -> {conversation, User, N} end);
            ["with", User] ->
                % Default to last 20 messages
                {conversation, User, 20};
            _ ->
                {error,
                    "Usage: history [from <user> yesterday|last N] | [last N] | [with <user> [last N]]"}
        end,
    {history_cmd, Result}.

%% @doc Parse admin register command
%% Format: admin register &lt;gpg_fp> &lt;key_file> [--note "description"]
parse_admin_register(ArgsStr) ->
    Parts = string:tokens(ArgsStr, " "),
    case Parts of
        [GpgFp, KeyFile | Rest] ->
            Opts = parse_admin_register_opts(Rest, #{}),
            {admin_cmd, register, string:trim(GpgFp), string:trim(KeyFile), Opts};
        _ ->
            {error, "Usage: admin register <gpg_fp> <key_file> [--note \"description\"]"}
    end.

%% @doc Parse admin register options
%% Examples:
%%   "--name John Doe --team DevOps --note Admin user"
%%   "--name John Doe --birthday 24 Dec --team Engineering"
%%
parse_admin_register_opts([], Acc) ->
    Acc;
parse_admin_register_opts(["--" ++ SwitchName | Rest], Acc) ->
    {Value, Remaining} = collect_value_until_switch(Rest),
    Key = list_to_binary(SwitchName),
    parse_admin_register_opts(Remaining, Acc#{Key => list_to_binary(Value)});
parse_admin_register_opts([_Unknown | Rest], Acc) ->
    %% Skip tokens that don't start with --
    parse_admin_register_opts(Rest, Acc).

%% @doc Collect tokens until the next switch (starting with "--") or end of list
collect_value_until_switch(Tokens) ->
    collect_value_until_switch(Tokens, []).

collect_value_until_switch([], Acc) ->
    {string:join(lists:reverse(Acc), " "), []};
collect_value_until_switch(["--" ++ _ | _] = Rest, Acc) ->
    {string:join(lists:reverse(Acc), " "), Rest};
collect_value_until_switch([Token | Rest], Acc) ->
    collect_value_until_switch(Rest, [Token | Acc]).

-ifdef(EUNIT).
%% EUnit tests for parse_admin_register_opts/2
parse_admin_register_opts_test_() ->
    {"parse_admin_register_opts/2 tests",
     [
         ?_assertEqual(
             #{<<"name">> => <<"John Doe">>,
               <<"team">> => <<"DevOps">>,
               <<"note">> => <<"Admin user">>},
             parse_admin_register_opts(
                 ["--name", "John", "Doe", "--team", "DevOps", "--note", "Admin", "user"],
                 #{}
             )
         ),
         ?_assertEqual(
             #{<<"name">> => <<"John Doe">>,
               <<"birthday">> => <<"24 Dec">>,
               <<"team">> => <<"Engineering">>},
             parse_admin_register_opts(
                 ["--name", "John", "Doe", "--birthday", "24", "Dec", "--team", "Engineering"],
                 #{}
             )
         )
     ]}.

-endif.



%% @doc Parse cert renew options
%% Examples:
%%   "--force"
%%   "--new-key"
%%   "--force --new-key"
parse_cert_renew_options(OptionsStr) ->
    Opts = parse_options(OptionsStr, #{
        force => false,
        new_key => false
    }),
    {cert_cmd, renew, Opts}.

%% @doc Parse command-line options
%% Simple parser that handles --key value and --flag formats
parse_options(Str, Defaults) ->
    Tokens = string:tokens(Str, " "),
    parse_options_loop(Tokens, Defaults).

parse_options_loop([], Acc) ->
    Acc;
parse_options_loop(["--expires", Value | Rest], Acc) ->
    parse_options_loop(Rest, Acc#{expires => Value});
parse_options_loop(["--note" | Rest], Acc) ->
    %% Note takes all remaining words as value
    Note = string:join(Rest, " "),
    Acc#{note => Note};
parse_options_loop(["--force" | Rest], Acc) ->
    parse_options_loop(Rest, Acc#{force => true});
parse_options_loop(["--new-key" | Rest], Acc) ->
    parse_options_loop(Rest, Acc#{new_key => true});
parse_options_loop([_Unknown | Rest], Acc) ->
    %% Skip unknown options
    parse_options_loop(Rest, Acc).

%% Helper to try parsing a number string
try_parse_last_n(NStr, SuccessFun) ->
    try list_to_integer(NStr) of
        N when N > 0, N =< 1000 ->
            SuccessFun(N);
        _ ->
            {error, "Number must be between 1 and 1000"}
    catch
        _:_ ->
            {error, "Invalid number: " ++ NStr}
    end.

%% @doc Execute parsed commands
execute_command({noop}, State) ->
    State;
execute_command({error, Msg}, State) ->
    cryptic_shell:print_error(Msg),
    State;
execute_command({status}, State) ->
    show_status(State),
    State;
execute_command({engine_status}, State) ->
    show_engine_status(State),
    State;
execute_command({verbose, toggle}, State) ->
    NewVerbose = not State#console_state.verbose,
    io:format("Verbose mode: ~p~n", [NewVerbose]),
    State#console_state{verbose = NewVerbose};
execute_command({alias_cmd, list}, State) ->
    case cryptic_alias:list_all() of
        [] ->
            cryptic_shell:print_info("No aliases defined");
        Aliases ->
            cryptic_shell:print_info("Aliases:"),
            lists:foreach(
                fun({Name, Members}) ->
                    MemberStr = string:join(Members, ", "),
                    io:format("  ~s: ~s\r\n", [
                        ?FG_CYAN(Name),
                        ?FG_YELLOW(MemberStr)
                    ])
                end,
                Aliases
            )
    end,
    State;
execute_command({alias_cmd, new, AliasName, Members}, State) ->
    case cryptic_alias:new(AliasName, Members) of
        ok ->
            MemberStr = string:join(Members, ", "),
            cryptic_shell:print_info(
                "Created alias '" ++ AliasName ++ "' with members: " ++
                    MemberStr
            );
        {error, Reason} ->
            cryptic_shell:print_error(
                "Failed to create alias: " ++
                    lists:flatten(io_lib:format("~p", [Reason]))
            )
    end,
    State;
execute_command({alias_cmd, delete, AliasName}, State) ->
    case cryptic_alias:delete(AliasName) of
        ok ->
            cryptic_shell:print_info("Deleted alias '" ++ AliasName ++ "'");
        {error, not_found} ->
            cryptic_shell:print_warning("Alias '" ++ AliasName ++ "' not found")
    end,
    State;
execute_command({alias_cmd, add, AliasName, Members}, State) ->
    case cryptic_alias:add(AliasName, Members) of
        ok ->
            MemberStr = string:join(Members, ", "),
            cryptic_shell:print_info(
                "Added to alias '" ++ AliasName ++ "': " ++ MemberStr
            );
        {error, not_found} ->
            cryptic_shell:print_warning("Alias '" ++ AliasName ++ "' not found")
    end,
    State;
execute_command({alias_cmd, rm, AliasName, Members}, State) ->
    case cryptic_alias:rm(AliasName, Members) of
        ok ->
            MemberStr = string:join(Members, ", "),
            cryptic_shell:print_info(
                "Removed from alias '" ++ AliasName ++ "': " ++ MemberStr
            );
        {error, not_found} ->
            cryptic_shell:print_warning("Alias '" ++ AliasName ++ "' not found")
    end,
    State;
execute_command({send_to_alias, _AliasName, Members, Message}, State) ->
    %% Clear the command line once
    clear_command_line(Message),

    %% Send to all members and collect results
    Timestamp = erlang:timestamp(),
    lists:foreach(
        fun(Member) ->
            case State#console_state.engine_pid of
                undefined ->
                    ok;
                EnginePid ->
                    case
                        cryptic_engine:send_message(
                            EnginePid, list_to_binary(Member), Message
                        )
                    of
                        ok ->
                            %% Print simple confirmation without clearing lines
                            print_alias_send_confirmation(
                                Member, Message, Timestamp
                            );
                        {error, _Reason} ->
                            ok
                    end
            end
        end,
        Members
    ),
    State;
execute_command({db_cmd, enable}, State) ->
    case State#console_state.db_enabled of
        true ->
            cryptic_shell:print_info("Database storage is already enabled");
        false ->
            %% Initialize storage
            Username = binary_to_list(State#console_state.username),
            ServerHost = State#console_state.server_host,
            ServerPort = State#console_state.server_port,
            Passphrase = State#console_state.passphrase,

            case
                cryptic_chat_storage:init_storage(
                    Username, ServerHost, ServerPort, Passphrase
                )
            of
                ok ->
                    cryptic_shell:print_success("Database storage enabled"),
                    %% Return updated state with db_enabled = true
                    State#console_state{db_enabled = true};
                {error, Reason} ->
                    cryptic_shell:print_error(
                        "Failed to enable database: " ++
                            lists:flatten(io_lib:format("~p", [Reason]))
                    ),
                    State
            end
    end;
execute_command({db_cmd, disable}, State) ->
    case State#console_state.db_enabled of
        false ->
            cryptic_shell:print_info("Database storage is already disabled");
        true ->
            cryptic_shell:print_warning(
                "Database storage disabled. New messages will not be saved."
            ),
            %% Return updated state with db_enabled = false
            State#console_state{db_enabled = false}
    end;
execute_command({db_cmd, status}, State) ->
    case State#console_state.db_enabled of
        true ->
            cryptic_shell:print_info(
                "Database storage: ENABLED (messages are being saved)"
            );
        false ->
            cryptic_shell:print_info(
                "Database storage: DISABLED (messages are NOT saved)"
            )
    end,
    State;
execute_command({history_cmd, {error, Msg}}, State) ->
    cryptic_shell:print_error(Msg),
    State;
execute_command({history_cmd, Query}, State) ->
    execute_history_query(Query, State),
    State;
execute_command({online_cmd}, State) ->
    execute_online_users(State),
    State;
execute_command({admin_cmd, register, GpgFp, KeyFile, Opts}, State) ->
    execute_admin_register(GpgFp, KeyFile, Opts, State),
    State;
execute_command({admin_cmd, list}, State) ->
    execute_admin_list(State),
    State;
execute_command({admin_cmd, status, GpgFp}, State) ->
    execute_admin_status(GpgFp, State),
    State;
execute_command({admin_cmd, suspend, GpgFp}, State) ->
    execute_admin_suspend(GpgFp, State),
    State;
execute_command({admin_cmd, revoke, GpgFp}, State) ->
    execute_admin_revoke(GpgFp, State),
    State;
execute_command({admin_cmd, reactivate, GpgFp}, State) ->
    execute_admin_reactivate(GpgFp, State),
    State;
execute_command({admin_cmd, list_certs, GpgFp}, State) ->
    execute_admin_list_certs(GpgFp, State),
    State;
execute_command({admin_cmd, revoke_cert, Serial}, State) ->
    execute_admin_revoke_cert(Serial, State),
    State;
execute_command({cert_cmd, status}, State) ->
    execute_cert_status(State),
    State;
execute_command({cert_cmd, renew, Opts}, State) ->
    execute_cert_renew(Opts, State),
    State;
execute_command({send_message, ToUsername, Message}, State) ->
    send_message_to_user(ToUsername, Message, State),
    State.

%% @doc Show console status
show_status(State) ->
    %% Build status map
    Username = binary_to_list(State#console_state.username),
    Status = #{
        username => Username,
        server_host => State#console_state.server_host,
        server_port => State#console_state.server_port,
        verbose => State#console_state.verbose,
        ws_client_connected => State#console_state.ws_client_pid =/= undefined,
        engine_running => State#console_state.engine_pid =/= undefined,
        db_enabled => State#console_state.db_enabled
    },
    cryptic_shell:print_console_status(Status).

%% @doc Show engine status
show_engine_status(State) ->
    case State#console_state.engine_pid of
        undefined ->
            cryptic_shell:print_warning("No engine running");
        EnginePid ->
            case cryptic_engine:get_engine_status(EnginePid) of
                {ok, Status} ->
                    ?dbg("Engine status: ~p~n", [Status]),
                    cryptic_shell:print_engine_status(Status);
                {error, Reason} ->
                    cryptic_shell:print_error(
                        "Failed to get engine status: " ++
                            lists:flatten(io_lib:format("~p", [Reason]))
                    )
            end
    end.

%% @doc Execute history query
execute_history_query(Query, State) ->
    Username = binary_to_list(State#console_state.username),
    Passphrase = State#console_state.passphrase,

    case Passphrase of
        undefined ->
            cryptic_shell:print_error(
                "No passphrase available for message history"
            );
        _ ->
            Result =
                case Query of
                    {from_yesterday, FromUser} ->
                        cryptic_chat_storage:get_messages_from_yesterday(
                            Username, FromUser, Passphrase
                        );
                    {from_last_n, FromUser, N} ->
                        %% Get messages from specific user
                        cryptic_chat_storage:get_conversation(
                            Username, FromUser, N, Passphrase
                        );
                    {last_n, N} ->
                        cryptic_chat_storage:get_last_n_messages(
                            Username, N, Passphrase
                        );
                    {conversation, PeerUser, N} ->
                        cryptic_chat_storage:get_conversation(
                            Username, PeerUser, N, Passphrase
                        );
                    _ ->
                        {error, unsupported_query}
                end,

            case Result of
                {ok, Messages} when length(Messages) > 0 ->
                    display_message_history(Messages);
                {ok, []} ->
                    cryptic_shell:print_info("No messages found");
                {error, Reason} ->
                    cryptic_shell:print_error(
                        "Failed to retrieve history: " ++
                            lists:flatten(io_lib:format("~p", [Reason]))
                    )
            end
    end.

%% @doc Display message history grouped by server
display_message_history(Messages) ->
    %% Group messages by server host and port
    Grouped = group_messages_by_server(Messages),

    %% Display each server group
    lists:foreach(
        fun({ServerHost, ServerPort, ServerMessages}) ->
            %% Print server header
            ServerStr =
                binary_to_list(ServerHost) ++ ":" ++
                    integer_to_list(ServerPort),
            cryptic_shell:print_info(
                "=== Message History (" ++ ServerStr ++ ") ==="
            ),
            %% Print messages for this server
            lists:foreach(
                fun({FromUser, ToUser, Message, Timestamp, _SH, _SP}) ->
                    cryptic_shell:print_history_message(
                        FromUser,
                        ToUser,
                        Message,
                        Timestamp,
                        undefined,
                        undefined
                    )
                end,
                ServerMessages
            )
        end,
        Grouped
    ),

    %% Print total count
    Count = length(Messages),
    cryptic_shell:print_info(
        io_lib:format("=== Total: ~p message(s) ===", [Count])
    ).

%% @doc Group messages by server host and port
%% Returns list of {ServerHost, ServerPort, Messages} tuples
group_messages_by_server(Messages) ->
    %% Build a map of {ServerHost, ServerPort} -> [Messages]
    Grouped = lists:foldl(
        fun(
            {_FromUser, _ToUser, _Message, _Timestamp, ServerHost, ServerPort} =
                Msg,
            Acc
        ) ->
            Key = {ServerHost, ServerPort},
            Existing = maps:get(Key, Acc, []),
            maps:put(Key, [Msg | Existing], Acc)
        end,
        #{},
        Messages
    ),

    %% Convert map to sorted list of {ServerHost, ServerPort, Messages}
    %% Reverse each message list to restore chronological order
    lists:sort(
        fun({H1, P1, _}, {H2, P2, _}) ->
            {H1, P1} =< {H2, P2}
        end,
        [{H, P, lists:reverse(Msgs)} || {{H, P}, Msgs} <- maps:to_list(Grouped)]
    ).

%% @doc Send message to another user
send_message_to_user(ToUsername, Message, State) ->
    send_message_to_user(ToUsername, Message, State, true).

%% @doc Send message to another user with optional display
send_message_to_user(ToUsername, Message, State, ShowConfirmation) ->
    case State#console_state.engine_pid of
        undefined ->
            ?error("No engine running~n", []);
        EnginePid ->
            ?dbg("Sending message to ~s: ~s~n", [ToUsername, Message]),
            case cryptic_engine:send_message(EnginePid, ToUsername, Message) of
                ok ->
                    Timestamp = erlang:timestamp(),
                    
                    %% Save outgoing message to storage if database is enabled
                    case State of
                        #console_state{
                            username = FromUsername,
                            server_host = ServerHost,
                            server_port = ServerPort,
                            passphrase = Passphrase,
                            db_enabled = true
                        } when Passphrase =/= undefined ->
                            DateTime = calendar:now_to_datetime(Timestamp),
                            case
                                cryptic_chat_storage:save_encrypted_message(
                                    binary_to_list(FromUsername),
                                    binary_to_list(ToUsername),
                                    ServerHost,
                                    ServerPort,
                                    Message,
                                    DateTime,
                                    Passphrase
                                )
                            of
                                ok ->
                                    ?dbg("Outgoing message saved to storage~n", []);
                                {error, SaveReason} ->
                                    ?error(
                                        "Failed to save outgoing message: ~p~n",
                                        [SaveReason]
                                    )
                            end;
                        _ ->
                            ok
                    end,
                    
                    %% Display sent message confirmation with timestamp if requested
                    case ShowConfirmation of
                        true ->
                            cryptic_shell:print_sent_message(
                                ToUsername, Message, Timestamp
                            );
                        false ->
                            ok
                    end,
                    ?dbg("Message sent successfully~n", []);
                {error, Reason} ->
                    ?error("Failed to send message: ~p~n", [Reason])
            end
    end.

%% @doc Print alias send confirmation without clearing command line
%% Used when sending to multiple recipients via alias to avoid overwriting
print_alias_send_confirmation(ToUser, Message, Timestamp) ->
    {{_Year, _Month, _Day}, {Hour, Minute, Second}} =
        calendar:now_to_universal_time(Timestamp),
    TimeStr = io_lib:format("~2..0B:~2..0B:~2..0B", [Hour, Minute, Second]),
    io:format(
        "~s ~s (~s)\r\n",
        [
            ?FG_GREEN("<You => " ++ ToUser ++ ">"),
            ?FG_WHITE(binary_to_list(Message)),
            ?FG_YELLOW(TimeStr)
        ]
    ).

%% @doc Clear the command line once (for alias sends)
clear_command_line(Message) ->
    Prompt = cryptic_shell:make_prompt(),

    %% Get terminal width (default to 80 if we can't determine it)
    TermWidth =
        case io:columns() of
            {ok, Cols} -> Cols;
            _ -> 80
        end,

    %% Reconstruct the command line that was just executed
    %% The command was something like ":s @alias message"
    CommandLine = Prompt ++ ":s @work " ++ binary_to_list(Message),

    %% Calculate how many lines this wrapped to
    LinesToClear = cryptic_shell:calculate_wrapped_lines(
        CommandLine, TermWidth
    ),

    %% Move up and clear all those lines
    cryptic_shell:clear_lines_up(LinesToClear).

%% @doc Check for and handle any pending messages
check_messages_with_state(State) ->
    receive
        {event, #{type := system_message, message := Message}} ->
            %% Clear line and print system message
            display_system_message(Message),
            %% Recursively check for more messages
            check_messages_with_state(State);
        {event, #{type := deliver_message, from := FromUsername, message := Message, timestamp := Timestamp}} ->
            %% Clear line and print delivered message
            display_user_message(FromUsername, Message, Timestamp),

            %% Save message to storage if State is provided and database is enabled
            case State of
                #console_state{
                    username = ToUsername,
                    server_host = ServerHost,
                    server_port = ServerPort,
                    passphrase = Passphrase,
                    db_enabled = true
                } when Passphrase =/= undefined ->
                    % Message is already a binary, no need to convert
                    % Convert erlang:timestamp() to calendar:datetime()
                    DateTime = calendar:now_to_datetime(Timestamp),
                    case
                        cryptic_chat_storage:save_encrypted_message(
                            FromUsername,
                            binary_to_list(ToUsername),
                            ServerHost,
                            ServerPort,
                            Message,
                            DateTime,
                            Passphrase
                        )
                    of
                        ok ->
                            ok;
                        {error, Reason} ->
                            io:format(
                                "~n[ERROR] Failed to save message: ~p~n", [
                                    Reason
                                ]
                            )
                    end;
                _ ->
                    % Skip storage if no state, passphrase, or database disabled
                    ok
            end,

            %% Recursively check for more messages
            check_messages_with_state(State)
    after 0 ->
        %% No messages, continue
        ok
    end.

display_user_message(FromUsername, Message, Timestamp) ->
    %% Print the user message (cryptic_shell handles line clearing)
    %% Convert binary username to list for cryptic_shell:print_user_message/3
    FromUser = case FromUsername of
        Bin when is_binary(Bin) -> binary_to_list(Bin);
        List when is_list(List) -> List
    end,
    cryptic_shell:print_user_message(FromUser, Message, Timestamp),
    %% Force flush output streams
    io:format("~s", [""]),
    %% Longer delay to ensure terminal has processed all ANSI sequences
    timer:sleep(100).

%% @doc Display an async message without disrupting the prompt
display_system_message(Message) ->
    %% Suppress certain expected error messages
    ShouldSuppress = case binary:match(Message, <<"user not found">>) of
        nomatch -> false;
        _ -> true
    end,

    case ShouldSuppress of
        true ->
            %% Silently ignore "user not found" - expected when recipient isn't registered
            ok;
        false ->
            %% Clear current line and print system message
            io:format("\r\n"),
            cryptic_shell:print_info(binary_to_list(Message)),
            %% Force flush output streams
            io:format("~s", [""]),
            %% Longer delay to ensure terminal has processed all ANSI sequences
            timer:sleep(100)
    end.

display_ca_response(Response) ->
    %% Delegate to cryptic_shell for proper formatting
    cryptic_shell:print_ca_response(Response).

%% @doc Display websocket message responses
display_websocket_message(#{<<"type">> := <<"users">>, <<"users">> := Users}) ->
    %% Handle user list response from admin list command
    io:format("\r\n"),
    cryptic_shell:print_info("Registered users:"),
    lists:foreach(
        fun(Username) ->
            io:format("  " ++ ?FG_CYAN(binary_to_list(Username)) ++ "\r\n")
        end,
        Users
    ),
    io:format("~s", [""]),
    timer:sleep(100);
display_websocket_message(#{<<"type">> := <<"online_users">>, <<"users">> := Users}) ->
    %% Handle online users response
    io:format("\r\n"),
    case Users of
        [] ->
            cryptic_shell:print_info("No users currently online");
        _ ->
            cryptic_shell:print_info(
                "Online users (" ++ integer_to_list(length(Users)) ++ "):"
            ),
            lists:foreach(
                fun(Username) ->
                    io:format("  " ++ ?FG_GREEN(binary_to_list(Username)) ++ "\r\n")
                end,
                Users
            )
    end,
    io:format("~s", [""]),
    timer:sleep(100);
display_websocket_message(#{<<"type">> := <<"pending_messages_delivered">>, <<"count">> := Count}) ->
    %% Handle pending messages notification
    case Count of
        0 ->
            io:format("\r\n"),
            cryptic_shell:print_info("No pending messages found at the server."),
            io:format("~s", [""]),
            timer:sleep(100);
        1 ->
            io:format("\r\n"),
            cryptic_shell:print_success("1 pending message delivered from server."),
            io:format("~s", [""]),
            timer:sleep(100);
        N ->
            io:format("\r\n"),
            cryptic_shell:print_success(
                integer_to_list(N) ++ " pending messages delivered from server."
            ),
            io:format("~s", [""]),
            timer:sleep(100)
    end;
display_websocket_message(#{<<"type">> := <<"success">>}) ->
    %% Suppress generic success messages - they're not interesting for the user
    ok;
display_websocket_message(#{<<"type">> := <<"message">>}) ->
    %% Suppress encrypted message details - the decrypted message is displayed via deliver_message event
    ok;
display_websocket_message(#{<<"type">> := <<"key_bundle">>}) ->
    %% Suppress key bundle messages - internal protocol data for key exchange
    ok;
display_websocket_message(#{<<"type">> := <<"error">>, <<"message">> := <<"key-bundle-not-found">>}) ->
    %% Silently ignore key-bundle-not-found - recipient hasn't uploaded keys yet
    %% Message will be queued and delivered when they come online
    ok;
display_websocket_message(#{<<"type">> := <<"error">>, <<"message">> := ErrorMsg, <<"success">> := false}) ->
    %% Handle error messages from server
    io:format("\r\n"),
    cryptic_shell:print_error("Server error: " ++ binary_to_list(ErrorMsg)),
    io:format("~s", [""]),
    timer:sleep(100);
display_websocket_message(#{<<"type">> := <<"error">>, <<"message">> := ErrorMsg}) ->
    %% Handle error messages without success field
    io:format("\r\n"),
    cryptic_shell:print_error("Server error: " ++ binary_to_list(ErrorMsg)),
    io:format("~s", [""]),
    timer:sleep(100);
display_websocket_message(#{<<"type">> := <<"user_registered">>, <<"gpg_fp">> := GpgFp, <<"registered_by">> := RegisteredBy}) ->
    %% Handle user registration confirmation
    io:format("\r\n"),
    cryptic_shell:print_success("User registered successfully!"),
    io:format("  GPG Fingerprint: " ++ ?FG_CYAN(binary_to_list(GpgFp)) ++ "\r\n"),
    io:format("  Registered by:   " ++ ?FG_YELLOW(binary_to_list(RegisteredBy)) ++ "\r\n"),
    io:format("~s", [""]),
    timer:sleep(100);
display_websocket_message(#{<<"type">> := <<"welcome">>}) ->
    %% Silently handle welcome message - already shown during connection
    ok;
display_websocket_message(Message) ->
    %% Generic handler for other websocket messages
    io:format("\r\n"),
    cryptic_shell:print_info("WebSocket message: " ++ 
        lists:flatten(io_lib:format("~p", [Message]))),
    io:format("~s", [""]),
    timer:sleep(100).

notify_user(FromUsername, _Message, _Timestamp, Notifier) ->
    F = fun() ->
        case Notifier of
            undefined ->
                ok;
            NotifierPath when is_list(NotifierPath) ->
                %% Call the notifier script with FromUsername as argument
                Command = lists:flatten(
                    io_lib:format(
                        "~s ~s",
                        [NotifierPath, FromUsername]
                    )
                ),
                ?dbg("Running notifier command: ~s~n", [Command]),
                os:cmd(Command),
                ok;
            _ ->
                ok
        end
    end,
    %% Run notifier in a separate process to avoid blocking
    spawn(F).


%%====================================================================
%% Online Users Command Execution
%%====================================================================

%% @doc Execute online users command
%% Requests the list of currently online users from the server
execute_online_users(_State) ->
    Msg = #{<<"type">> => <<"online_users">>},
    send_to_server(Msg),
    cryptic_shell:print_info("Fetching online users...").

%%====================================================================
%% Admin Command Execution
%%====================================================================

%% @doc Execute admin register command
execute_admin_register(GpgFp, KeyFile, Opts, _State) ->
    %% Read the GPG public key file
    case file:read_file(KeyFile) of
        {ok, GpgPubKey} ->
            %% Send register_user command via event bus
            {ok, Msg} =
                cryptic_messages:register_user(
                  list_to_binary(GpgFp),
                  GpgPubKey,
                  Opts),
            send_to_server(Msg),
            cryptic_shell:print_info("User registration request sent...");

        {error, Reason} ->
            cryptic_shell:print_error(
              "Failed to read key file: " ++
                  lists:flatten(io_lib:format("~p", [Reason]))
             )
    end.


%% @doc Execute admin list command
execute_admin_list(_State) ->
    Msg = #{<<"type">> => <<"list_users">>},
    send_to_server(Msg),
    cryptic_shell:print_info("Fetching user list...").


%% @doc Execute admin status command
execute_admin_status(GpgFp, _State) ->
    Msg =
        #{<<"type">> => <<"get_user_info">>,
          <<"gpg_fp">> => list_to_binary(GpgFp)
         },
    send_to_server(Msg),
    cryptic_shell:print_info("Fetching user status...").


%% @doc Execute admin suspend command
execute_admin_suspend(GpgFp, _State) ->
    {ok, Msg} = cryptic_messages:suspend_user(list_to_binary(GpgFp)),
    send_to_server(Msg),
    cryptic_shell:print_success("User suspend request sent").


%% @doc Execute admin revoke command  
execute_admin_revoke(GpgFp, _State) ->
    {ok, Msg} = cryptic_messages:revoke_user(list_to_binary(GpgFp)),
    send_to_server(Msg),
    cryptic_shell:print_success("User revoke request sent").


%% @doc Execute admin reactivate command
execute_admin_reactivate(GpgFp, _State) ->
    {ok, Msg} = cryptic_messages:reactivate_user(list_to_binary(GpgFp)),
    send_to_server(Msg),
    cryptic_shell:print_success("User reactivate request sent").


%% @doc Execute admin list certificates command
execute_admin_list_certs(GpgFp, _State) ->
    {ok, Msg} = cryptic_messages:list_certificates(list_to_binary(GpgFp)),
    send_to_server(Msg),
    cryptic_shell:print_info("Fetching certificates...").


%% @doc Execute admin revoke certificate command
execute_admin_revoke_cert(Serial, _State) ->
    %% Prompt for reason
    Reason = cryptic_shell:get_line("Revocation reason: "),
    Msg =
        #{<<"type">> => <<"revoke_certificate">>,
          <<"serial">> => list_to_binary(Serial),
          <<"reason">> => list_to_binary(Reason)
         },
    send_to_server(Msg),
    cryptic_shell:print_success("Certificate revoke request sent").



%%%===================================================================
%%% Certificate Command Implementations
%%%===================================================================

%% @doc Execute cert status command
execute_cert_status(State) ->
    %% Get certificate file path from config
    Username = binary_to_list(State#console_state.username),
    ServerHost = State#console_state.server_host,
    ServerPort = State#console_state.server_port,
    CrypticDir = cryptic_lib:get_cryptic_dir(Username, ServerHost, ServerPort),

    CertFile = CrypticDir ++ "/certificates/" ++ Username ++ ".crt",
    KeyFile = CrypticDir ++ "/certificates/" ++ Username ++ ".key",

    %% Check if files exist
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            display_certificate_status(CertFile, KeyFile, State);
        {false, _} ->
            cryptic_shell:print_error("Certificate file not found: " ++ CertFile);
        {_, false} ->
            cryptic_shell:print_error("Private key file not found: " ++ KeyFile)
    end.

%% @doc Display certificate status information
display_certificate_status(CertFile, KeyFile, _State) ->
    %% Read certificate using OpenSSL command
    SerialCmd = "openssl x509 -in " ++ CertFile ++ " -noout -serial 2>/dev/null",
    ExpiryCmd = "openssl x509 -in " ++ CertFile ++ " -noout -enddate 2>/dev/null",
    SubjectCmd = "openssl x509 -in " ++ CertFile ++ " -noout -subject 2>/dev/null",
    SANCmd = "openssl x509 -in " ++ CertFile ++ " -noout -ext subjectAltName 2>/dev/null",

    Serial = string:trim(os:cmd(SerialCmd)),
    Expiry = string:trim(os:cmd(ExpiryCmd)),
    Subject = string:trim(os:cmd(SubjectCmd)),
    SANRaw = string:trim(os:cmd(SANCmd)),

    %% Parse SAN output to extract DNS names
    SAN = case SANRaw of
        "" -> undefined;
        _ ->
            %% SAN format: "X509v3 Subject Alternative Name: \n    DNS:example.com, DNS:www.example.com"
            Lines = string:split(SANRaw, "\n", all),
            case Lines of
                [_Header | [DNSLine | _]] ->
                    string:trim(DNSLine);
                _ -> undefined
            end
    end,

    cryptic_shell:print_cert_status(Serial, Expiry, Subject, SAN, {CertFile, KeyFile}).


%% @doc Execute cert renew command
execute_cert_renew(Opts, State) ->
    Force = maps:get(force, Opts, false),
    NewKey = maps:get(new_key, Opts, false),

    cryptic_shell:print_info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
    cryptic_shell:print_info("Certificate Renewal"),
    cryptic_shell:print_info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),

    %% Get paths
    Username = binary_to_list(State#console_state.username),
    ServerHost = State#console_state.server_host,
    ServerPort = State#console_state.server_port,
    CrypticDir = cryptic_lib:get_cryptic_dir(Username, ServerHost, ServerPort),

    KeyFile = CrypticDir ++ "/certificates/" ++ Username ++ ".key",
    CSRFile = CrypticDir ++ "/certificates/" ++ Username ++ ".csr",

    %% Step 1: Generate new key if requested
    case NewKey of
        true ->
            cryptic_shell:print_info("[1/4] Generating new TLS key pair..."),
            GenKeyCmd = "openssl ecparam -genkey -name secp384r1 -out " ++ KeyFile ++ " 2>/dev/null",
            os:cmd(GenKeyCmd),
            os:cmd("chmod 600 " ++ KeyFile),
            cryptic_shell:print_success("New TLS key generated");
        false ->
            cryptic_shell:print_info("[1/4] Reusing existing TLS key..."),
            case filelib:is_file(KeyFile) of
                true -> 
                    cryptic_shell:print_success("Using existing key");
                false ->
                    cryptic_shell:print_error("Key file not found: " ++ KeyFile),
                    throw({error, key_not_found})
            end
    end,

    %% Step 2: Create CSR
    cryptic_shell:print_info("[2/4] Creating Certificate Signing Request..."),

    %% Get GPG fingerprint from config (would need to be stored)
    GPG_FP = "PLACEHOLDER_FP",  %% TODO: Store this during registration
    SubjectStr = "/CN=" ++ GPG_FP ++ "@" ++ ServerHost,

    GenCSRCmd = "openssl req -new -key " ++ KeyFile ++ 
                " -subj \"" ++ SubjectStr ++ "\" -out " ++ CSRFile ++ " 2>/dev/null",
    os:cmd(GenCSRCmd),
    cryptic_shell:print_success("CSR created"),

    %% Step 3: Sign CSR with GPG
    cryptic_shell:print_info("[3/4] Signing CSR with GPG key..."),
    cryptic_shell:print_warning("GPG signing not yet implemented"),
    %% TODO: Sign CSR with GPG key

    %% Step 4: Send renewal request
    cryptic_shell:print_info("[4/4] Requesting certificate renewal..."),

    MsgData =
        #{force => Force,
          new_key => NewKey,
          csr => <<"PLACEHOLDER_CSR">>,  %% TODO: Read actual CSR
          gpg_sig => <<"PLACEHOLDER_SIG">>  %% TODO: Actual GPG signature
         },
    case cryptic_messages:cert_renew(MsgData) of
        {ok, Msg} ->
            send_to_server(Msg),
            cryptic_shell:print_success("Renewal request sent");
        {error, Reason} ->
            cryptic_shell:print_error(
              "Invalid cert renew parameters: " ++
                  lists:flatten(io_lib:format("~p", [Reason]))
             )
    end,

    cryptic_shell:print_info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").

%% @doc Cleanup resources
cleanup(State) ->
    %% Clean up the enhanced shell
    cryptic_shell:cleanup(),

    %% Clean up ETS table if it exists
    case State#console_state.input_buffer_table of
        undefined -> ok;
        Table -> ets:delete(Table)
    end.


is_tui_mode(#{tui_mode := TuiMode}) ->
    TuiMode.
