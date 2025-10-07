%%% @doc Cryptic Console - Console interface for the Cryptic Engine
%%%
%%% This module provides a console interface for the Cryptic messaging engine.
%%% It handles initialization, event management, and basic user interaction.
%%%
-module(cryptic_console).

%% Include ANSI escape sequence macros for terminal formatting
-include("cryptic_ansi.hrl").
-include("cryptic.hrl").

%% API
-export([main/1]).

%% Internal state record
-record(console_state, {
    ws_client_pid :: pid() | undefined,
    engine_pid :: pid() | undefined,
    username :: binary(),
    verbose :: boolean(),
    console_pid :: pid() | undefined,
    input_buffer_table :: ets:tid() | undefined
}).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Main entry point for the console
-spec main(Config :: map()) -> ok.
main(InitCfg) ->
    cryptic_shell:print_info("Cryptic Console starting..."),
    ok = application:load(cryptic),

    Username = maps:get(username, InitCfg),

    %% Initialize the enhanced shell first
    case
        cryptic_shell:start_shell(#{
            verbose => maps:get(verbose, InitCfg, false)
        })
    of
        ok ->
            ok;
        {error, ShellError} ->
            cryptic_shell:print_warning(
                "Enhanced shell unavailable, using basic mode: " ++
                    lists:flatten(io_lib:format("~p", [ShellError]))
            )
    end,

    %% Now continue with initialization
    setup_event_management(InitCfg),
    CertCfg = get_cert_config(InitCfg),

    %% Start WebSocket client
    WsCfg = CertCfg#{callback_mod => ?MODULE},
    {ok, WsClientPid} = cryptic_ws_client:start_link(WsCfg),

    %% Prompt for passphrase early, before initializing cryptic engine
    Passphrase = get_passphrase(),

    % Get console PID to pass to callbacks
    ConsolePid = self(),

    % Start cryptic engine with passphrase and WebSocket client PID
    EngineCfg = CertCfg#{
        callback_mod => cryptic_console_callbacks,
        username => Username,
        passphrase => Passphrase,
        ws_client_pid => WsClientPid,
        console_pid => ConsolePid
    },
    {ok, EnginePid} = cryptic_engine:start_link(EngineCfg),

    ok = cryptic_ws_client:set_engine_pid(WsClientPid, EnginePid),

    % Create named ETS table for input buffer preservation
    % Use named table so cryptic_shell can access it directly
    InputBufferTable = ets:new(cryptic_console_input_buffer, [
        set, public, named_table
    ]),

    % Initialize console state with self() PID
    State = #console_state{
        ws_client_pid = WsClientPid,
        engine_pid = EnginePid,
        username = Username,
        verbose = maps:get(verbose, CertCfg, false),
        console_pid = ConsolePid,
        input_buffer_table = InputBufferTable
    },

    cryptic_shell:print_success(
        "Cryptic Console ready. Type 'help' for commands."
    ),

    % Start command loop
    command_loop(State).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Prompt for and get the passphrase securely
-spec get_passphrase() -> binary().
get_passphrase() ->
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
                    get_passphrase();
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

%% @doc Setup event management
-spec setup_event_management(Config :: map()) -> ok.
setup_event_management(Config) ->
    Username = maps:get(username, Config),

    % Start the event manager for logging
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} ->
            ok;
        {error, {already_started, _}} ->
            ok;
        {error, Reason} ->
            io:format("Failed to start event manager: ~p~n", [Reason]),
            throw(event_manager)
    end,

    % Set up event handlers for UI client with client configuration
    EventCfg = Config#{
        log_type => client,
        log_dir => "logs",
        username => Username
    },
    case cryptic_event_manager:setup_event_handlers(EventCfg) of
        ok ->
            ok;
        {error, SetupReason} ->
            io:format("Failed to setup event handlers: ~p~n", [SetupReason])
    end.

%%% @doc Get certificate configuration
-spec get_cert_config(Cfg :: map()) -> map().
get_cert_config(Cfg) ->
    Username = binary_to_list(maps:get(username, Cfg)),
    CrypticDir = cryptic_lib:get_cryptic_dir(Username),
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
        ca_file => CAFile
    }.

%% @doc Main command loop with async message handling
command_loop(State) ->
    % Check for any pending system messages before prompting
    check_messages(),

    % Check if there was interrupted input to restore
    BufferTable = State#console_state.input_buffer_table,
    RestoredInput =
        case ets:lookup(BufferTable, current_input) of
            [{current_input, Buffer}] ->
                ets:delete(BufferTable, current_input),
                Buffer;
            [] ->
                ""
        end,

    % Spawn a process to get input asynchronously with monitoring
    ConsolePid = self(),
    % Capture for closure
    RestoredInputCopy = RestoredInput,
    {InputPid, MonitorRef} = spawn_opt(
        fun() ->
            % If we have restored input, display it with a notification
            if
                RestoredInputCopy =/= "" ->
                    io:format("[Input restored: ~s] ", [RestoredInputCopy]);
                true ->
                    ok
            end,
            Result = cryptic_shell:get_line("cryptic> "),
            % Prepend restored input if any
            FinalResult =
                if
                    RestoredInputCopy =:= "" ->
                        Result;
                    Result =:= eof ->
                        eof;
                    element(1, Result) =:= error ->
                        Result;
                    true ->
                        RestoredInputCopy ++ Result
                end,
            ConsolePid ! {input_result, FinalResult}
        end,
        [monitor]
    ),

    % Wait for either input or messages
    wait_for_input_or_messages(InputPid, MonitorRef, State).

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
                    show_help(),
                    command_loop(State);
                ParsedCmd ->
                    NewState = execute_command(ParsedCmd, State),
                    command_loop(NewState)
            end;
        {'DOWN', MonitorRef, process, InputPid, _Reason} ->
            % Input process died (we killed it), restart command loop
            command_loop(State);
        {system_message, Message} ->
            % A message arrived while waiting for input
            % Note: We can't retrieve the actual input buffer from the blocked process
            % A future enhancement would be to modify cryptic_shell to support this
            % For now, we just interrupt and restart
            exit(InputPid, kill),
            % Display the async message
            display_async_message(Message),
            % Continue waiting - the DOWN message will trigger restart
            wait_for_input_or_messages(InputPid, MonitorRef, State)
    end.

%% @doc Parse user commands
parse_command("") ->
    {noop};
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
parse_command(Line) ->
    Parts = string:tokens(Line, " "),
    parse_command_parts(Parts).

parse_command_parts(["send", ToUsername | MessageParts]) ->
    Message = string:join(MessageParts, " "),
    {send_message, list_to_binary(ToUsername), list_to_binary(Message)};
parse_command_parts(_) ->
    {error, "Unknown command"}.

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
execute_command({send_message, ToUsername, Message}, State) ->
    send_message_to_user(ToUsername, Message, State),
    State.

%% @doc Show console status
show_status(State) ->
    io:format("Console Status:~n"),
    io:format("  Username: ~s~n", [State#console_state.username]),
    io:format("  WS Client: ~p~n", [State#console_state.ws_client_pid]),
    io:format("  Engine: ~p~n", [State#console_state.engine_pid]),
    io:format("  Verbose: ~p~n", [State#console_state.verbose]).

%% @doc Show engine status
show_engine_status(State) ->
    case State#console_state.engine_pid of
        undefined ->
            io:format("No engine running~n");
        EnginePid ->
            case cryptic_engine:get_engine_status(EnginePid) of
                {ok, Status} ->
                    io:format("Engine Status:~n"),
                    maps:fold(
                        fun(K, V, _) ->
                            io:format("  ~p: ~p~n", [K, V])
                        end,
                        ok,
                        Status
                    );
                {error, Reason} ->
                    io:format("Failed to get engine status: ~p~n", [Reason])
            end
    end.

%% @doc Send message to another user
send_message_to_user(ToUsername, Message, State) ->
    case State#console_state.engine_pid of
        undefined ->
            ?error("No engine running~n", []);
        EnginePid ->
            ?dbg("Sending message to ~s: ~s~n", [ToUsername, Message]),
            case cryptic_engine:send_message(EnginePid, ToUsername, Message) of
                ok ->
                    ?dbg("Message sent successfully~n", []);
                {error, Reason} ->
                    ?error("Failed to send message: ~p~n", [Reason])
            end
    end.

%% @doc Show help
show_help() ->
    io:format("Available commands:\r\n"),
    io:format("  status                     - Show console status\r\n"),
    io:format("  engine_status              - Show engine status\r\n"),
    io:format("  send <username> <message>  - Send message to user\r\n"),
    io:format("  verbose                    - Toggle verbose mode\r\n"),
    io:format("  help                       - Show this help\r\n"),
    io:format("  quit                       - Exit console\r\n"),
    io:format("\r\nLine editing keys:\r\n"),
    io:format("  Ctrl+A                     - Beginning of line\r\n"),
    io:format("  Ctrl+E                     - End of line\r\n"),
    io:format("  Ctrl+F / Right Arrow       - Forward one character\r\n"),
    io:format("  Ctrl+B / Left Arrow        - Back one character\r\n"),
    io:format("  Ctrl+D                     - Delete character\r\n"),
    io:format("  Ctrl+H / Backspace         - Delete previous character\r\n"),
    io:format("  Ctrl+K                     - Kill to end of line\r\n"),
    io:format("  Ctrl+U                     - Kill entire line\r\n").

%% @doc Check for and handle any pending messages
check_messages() ->
    receive
        {system_message, Message} ->
            % Clear line and print system message
            display_async_message(Message),
            % Recursively check for more messages
            check_messages()
    after 0 ->
        % No messages, continue
        ok
    end.

%% @doc Display an async message without disrupting the prompt
display_async_message(Message) ->
    % Clear current line and print system message
    io:format("\r\n"),
    cryptic_shell:print_info(binary_to_list(Message)).

%% @doc Cleanup resources
cleanup(State) ->
    % Clean up the enhanced shell
    cryptic_shell:cleanup(),

    % Clean up ETS table if it exists
    case State#console_state.input_buffer_table of
        undefined -> ok;
        Table -> ets:delete(Table)
    end,

    % Note: We don't stop the engine or ws_client here as they might be shared
    % or managed by the parent process
    case State#console_state.verbose of
        true ->
            io:format("Cleanup complete\r\n");
        false ->
            ok
    end.
