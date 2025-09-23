%%% @doc Cryptic WebSocket mTLS Terminal User Interface
%%%
%%% This module provides a full-screen terminal-based user interface for the
%%% Cryptic chat application using WebSocket mTLS authentication. It implements
%%% a modern chat interface with certificate-based authentication, real-time
%%% messaging, and secure bidirectional communication.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Certificate-based mTLS authentication for secure connections</li>
%%%   <li>Real-time WebSocket communication with the server</li>
%%%   <li>Full-screen terminal UI with status bar, message area, and input line</li>
%%%   <li>Interactive chat mode for one-on-one conversations</li>
%%%   <li>Color-coded message display for better readability</li>
%%%   <li>Command-based interface with help system</li>
%%%   <li>Automatic user identification via client certificates</li>
%%%   <li>Bidirectional secure message exchange</li>
%%% </ul>
%%%
%%% == Architecture ==
%%%
%%% The UI integrates with the WebSocket mTLS client infrastructure:
%%% <ul>
%%%   <li>`ui_main_loop/1' - Main event processing loop</li>
%%%   <li>`input_handler/1' - Dedicated process for keyboard input</li>
%%%   <li>`status_updater/1' - Timer-based status bar updates</li>
%%%   <li>`cryptic_ws_client' - WebSocket client with mTLS authentication</li>
%%%   <li>`cryptic_ws_client_lib' - High-level API for WebSocket operations</li>
%%% </ul>
%%%
%%% == Screen Layout ==
%%%
%%% ```
%%% +--------------------------------------------------+
%%% | Status Bar (server, user cert, chat mode)       |
%%% +--------------------------------------------------+
%%% |                                                  |
%%% |            Message Display Area                  |
%%% |         (scrollable message history)            |
%%% |                                                  |
%%% +--------------------------------------------------+
%%% | Help Bar (context-sensitive commands)           |
%%% +--------------------------------------------------+
%%% | > Input Line                                     |
%%% +--------------------------------------------------+
%%% '''
%%%
%%% == Usage ==
%%%
%%% ```
%%% %% Start with alice certificate (default server)
%%% cryptic_ws_ui:start("alice").
%%%
%%% %% Start with specific certificate and server
%%% cryptic_ws_ui:start("bob", "example.com").
%%% '''
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-13
-module(cryptic_ws_ui).

%% Public API
-export([start/1, start/2]).

%% Internal exports for processes
-export([input_handler/1, status_updater/1]).

-import(
    cryptic_ui_screen,
    [
        draw_screen/1,
        draw_status_bar/1,
        position_cursor/1,
        format_message/4,
        format_line/2,
        get_visible_messages/3,
        cleanup_ui/0
    ]
).

-include_lib("cecho/include/cecho.hrl").
-include("cryptic.hrl").
-include("cryptic_ui.hrl").

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Start the WebSocket mTLS UI with specified username certificate.
%%
%% Initializes the terminal UI with WebSocket mTLS authentication using
%% the specified username's certificate. The certificate files are expected
%% to be in the standard locations:
%% <ul>
%%   <li>`priv/ssl/client_<username>.crt' - Client certificate</li>
%%   <li>`priv/ssl/client_<username>.key' - Client private key</li>
%%   <li>`priv/ssl/ca.crt' - Certificate Authority</li>
%% </ul>
%%
%% @param Username The username whose certificate to use (e.g., "alice", "bob")
%% @returns `ok' when the UI exits normally.
start(Username) ->
    start(Username, "localhost").

%% @doc Start the WebSocket mTLS UI with specified certificate and server.
%%
%% Initializes the full-screen terminal interface with WebSocket mTLS including:
%% <ul>
%%   <li>Certificate-based authentication configuration</li>
%%   <li>WebSocket client connection to mTLS server</li>
%%   <li>ncurses/cecho initialization with color support</li>
%%   <li>Screen layout setup (status, message, help, input areas)</li>
%%   <li>Background processes for input handling and status updates</li>
%%   <li>Main event loop for user interaction</li>
%% </ul>
%%
%% The UI will attempt to connect to the WebSocket mTLS server and display
%% connection status. Once connected, users can send messages, enter chat mode,
%% and perform other operations through the secure WebSocket connection.
%%
%% @param Username The username whose certificate to use
%% @param ServerHost Hostname of the WebSocket mTLS server
%% @returns `ok' when the UI exits normally.
%% @throws any()
-spec start(string(), string()) -> ok.
start(Username, ServerHost) ->
    %% Start cecho first (handles ncurses initialization)
    ok = application:start(cecho),

    %% Start other required applications
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(gun),

    ok = cryptic_lib:initialize(),

    %% Start the event manager for logging
    {ok, _} = gen_event:start_link({local, cryptic_event_manager}),

    %% Set up event handlers for UI client with client configuration
    cryptic_event_manager:setup_event_handlers(#{
        log_type => client, log_dir => "logs", username => Username
    }),

    %% Configure cecho settings
    ok = cecho:start_color(),
    ok = cecho:noecho(),
    ok = cecho:cbreak(),
    ok = cecho:keypad(?ceSTDSCR, true),
    % Make cursor visible
    ok = cecho:curs_set(?ceCURS_NORMAL),

    %% Initialize color pairs
    init_colors(),

    %% Get screen dimensions
    {Height, Width} = cecho:getmaxyx(),

    %% Create certificate configuration using environment variables
    CertFile =
        case os:getenv("CRYPTIC_CLIENT_CERT") of
            false -> "CA/client_keys/" ++ Username ++ ".crt";
            EnvCert -> EnvCert
        end,
    KeyFile =
        case os:getenv("CRYPTIC_CLIENT_KEY") of
            false -> "CA/client_keys/" ++ Username ++ ".key";
            EnvKey -> EnvKey
        end,
    CAFile =
        case os:getenv("CRYPTIC_CA_CERT") of
            false -> "CA/certs/ca.crt";
            EnvCA -> EnvCA
        end,

    CertConfig = #{
        cert_file => CertFile,
        key_file => KeyFile,
        ca_file => CAFile
    },

    %% Create initial WebSocket chat state
    WSChatState = #ws_chat_state{
        server_host = ServerHost,
        server_port = 8443,
        username = Username,
        cert_config = CertConfig,
        connection_status = disconnected,
        keypair = undefined,
        client_keys = undefined
    },

    %% Create initial UI state
    UIState = #ui_state{
        ws_chat_state = WSChatState,
        screen_height = Height,
        screen_width = Width
    },

    %% Start helper processes
    InputPid = spawn_link(?MODULE, input_handler, [self()]),
    StatusPid = spawn_link(?MODULE, status_updater, [self()]),

    UpdatedUIState = UIState#ui_state{
        input_pid = InputPid,
        status_pid = StatusPid
    },

    %% Draw initial screen
    draw_screen(UpdatedUIState),

    %% Add welcome messages
    WelcomeState = add_system_message(
        "=== CRYPTIC WEBSOCKET mTLS CHAT ===", UpdatedUIState
    ),
    WelcomeState2 = add_system_message(
        "Server: " ++ ServerHost ++ ":8443", WelcomeState
    ),
    WelcomeState3 = add_system_message(
        "Certificate: " ++ Username, WelcomeState2
    ),
    WelcomeState4 = add_system_message(
        "Type 'connect' to establish connection and initialize keys",
        WelcomeState3
    ),
    WelcomeState5 = add_system_message(
        "Type 'help' for commands", WelcomeState4
    ),

    %% Redraw screen with welcome messages
    draw_screen(WelcomeState5),

    %% Start main UI loop
    try
        ui_main_loop(WelcomeState5)
    after
        cleanup_ui()
    end.

%%%===================================================================
%%% Main UI Loop
%%%===================================================================

%% @private
%% Main UI event loop handling user interactions and background tasks.
%%
%% This is the central event processing loop that handles:
%% <ul>
%%   <li>`{input, Input}' - User keyboard input from input_handler process</li>
%%   <li>`{status_update}' - Periodic status bar refresh from status_updater</li>
%%   <li>`{websocket_message, Message}' - Messages received from WebSocket server</li>
%%   <li>`quit' - Graceful shutdown request</li>
%% </ul>
%%
%% The loop ensures the UI remains responsive while handling WebSocket
%% communication and maintaining the secure mTLS connection.
%%
%% @param UIState Current UI state record
%% @returns `ok' when the loop exits gracefully.
ui_main_loop(UIState) ->
    receive
        {input, Input} ->
            %% Handle user input
            NewUIState = handle_input(Input, UIState),
            draw_screen(NewUIState),
            ui_main_loop(NewUIState);
        {status_update} ->
            %% Update status bar
            draw_status_bar(UIState),

            %% Position cursor before refresh to avoid flickering
            position_cursor(UIState),
            cecho:refresh(),

            ui_main_loop(UIState);
        {websocket_message, Message} ->
            %% Handle incoming WebSocket message
            MessageUIState = handle_websocket_message(Message, UIState),
            draw_screen(MessageUIState),
            ui_main_loop(MessageUIState);
        {prekey_received, User, Prekey} ->
            %% Handle prekey received from server for message encryption
            PrekeyUIState = handle_prekey_received(User, Prekey, UIState),
            draw_screen(PrekeyUIState),
            ui_main_loop(PrekeyUIState);
        {encrypted_message_received, Message} ->
            %% Handle encrypted message received from server
            DecryptUIState = handle_encrypted_message_received(
                Message, UIState
            ),
            draw_screen(DecryptUIState),
            ui_main_loop(DecryptUIState);
        {users_list_received, Users} ->
            %% Handle users list received from server
            UsersUIState = handle_users_list_received(Users, UIState),
            draw_screen(UsersUIState),
            ui_main_loop(UsersUIState);
        quit ->
            %% Exit gracefully and stop the node
            cleanup_ui(),
            init:stop(),
            ok;
        _Other ->
            %% Ignore unknown messages
            ui_main_loop(UIState)
    end.

%%%===================================================================
%%% Screen Drawing Functions
%%%===================================================================

%%%===================================================================
%%% Input Handling
%%%===================================================================

%% @private
%% Handle user input events from the input handler process.
%%
%% Processes different types of input with enhanced editing capabilities:
%% <ul>
%%   <li>`quit' - Initiates graceful shutdown</li>
%%   <li>`{char, Char}' - Inserts printable characters at cursor position</li>
%%   <li>`{key, 10}' - Enter key processes current command and adds to history</li>
%%   <li>`{key, backspace}' - Removes character before cursor</li>
%%   <li>`{key, delete}' - Removes character after cursor</li>
%%   <li>`{key, left}' - Moves cursor left</li>
%%   <li>`{key, right}' - Moves cursor right</li>
%%   <li>`{key, home}' - Moves cursor to beginning of line</li>
%%   <li>`{key, end_key}' - Moves cursor to end of line</li>
%%   <li>`{key, up}' - Navigate up in command history</li>
%%   <li>`{key, down}' - Navigate down in command history</li>
%% </ul>
%%
%% Features:
%% - Full cursor movement and text editing
%% - Command history with up/down arrow navigation
%% - Insert/delete at any position in the input line
%% - Automatic command history management (up to 50 commands)
%% - Horizontal scrolling for long input lines
%%
%% The function updates the UI state appropriately and triggers command
%% processing when Enter is pressed.
%%
%% @param Input Input event from the input handler process
%% @param UIState Current UI state
%% @returns Updated UI state after processing the input.
handle_input(Input, UIState) ->
    case UIState#ui_state.passphrase_mode of
        true ->
            %% Handle passphrase input mode
            handle_passphrase_input(Input, UIState);
        false ->
            %% Normal input handling
            handle_normal_input(Input, UIState)
    end.

%% @private
%% Handle input when in passphrase mode.
handle_passphrase_input(Input, UIState) ->
    case Input of
        quit ->
            %% Cancel passphrase input
            NewUIState = UIState#ui_state{
                passphrase_mode = false,
                passphrase_config_dir = undefined,
                current_input = "",
                cursor_position = 0
            },
            add_system_message(
                "Connection cancelled - passphrase required", NewUIState
            );
        {char, Char} when Char >= 32, Char =< 126 ->
            %% Add character to passphrase (don't display it)
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            {Before, After} = lists:split(CursorPos, CurrentInput),
            NewInput = Before ++ [Char] ++ After,
            NewCursorPos = CursorPos + 1,
            UIState#ui_state{
                current_input = NewInput,
                cursor_position = NewCursorPos
            };
        {key, 10} ->
            %% Enter pressed - process passphrase
            Passphrase = list_to_binary(UIState#ui_state.current_input),
            ConfigDir = UIState#ui_state.passphrase_config_dir,

            %% Exit passphrase mode
            NormalUIState = UIState#ui_state{
                passphrase_mode = false,
                passphrase_config_dir = undefined,
                current_input = "",
                cursor_position = 0
            },

            %% Process the key loading and connection
            case Passphrase of
                <<>> ->
                    %% Empty passphrase not allowed
                    add_system_message(
                        "Empty passphrase not allowed", NormalUIState
                    );
                _ ->
                    load_client_keys_and_connect(
                        NormalUIState, ConfigDir, Passphrase
                    )
            end;
        {key, ?ceKEY_BACKSPACE} ->
            %% Handle backspace in passphrase mode
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            case CursorPos > 0 of
                true ->
                    {Before, After} = lists:split(CursorPos, CurrentInput),
                    NewBefore = lists:droplast(Before),
                    NewInput = NewBefore ++ After,
                    NewCursorPos = CursorPos - 1,
                    UIState#ui_state{
                        current_input = NewInput,
                        cursor_position = NewCursorPos
                    };
                false ->
                    UIState
            end;
        _ ->
            %% Ignore other keys in passphrase mode
            UIState
    end.

%% @private
%% Handle normal input (not in passphrase mode).
handle_normal_input(Input, UIState) ->
    case Input of
        quit ->
            %% Send quit message to main loop
            self() ! quit,
            UIState;
        {char, Char} ->
            %% Insert character at cursor position
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            {Before, After} = lists:split(CursorPos, CurrentInput),
            NewInput = Before ++ [Char] ++ After,
            NewCursorPos = CursorPos + 1,
            %% Reset history position when typing
            UIState#ui_state{
                current_input = NewInput,
                cursor_position = NewCursorPos,
                history_position = 0
            };
        % Enter key (ASCII 10)
        {key, 10} ->
            %% Process command and clear input
            Command = UIState#ui_state.current_input,
            %% Trim whitespace from command for processing
            TrimmedCommand = string:strip(Command),
            %% Add non-empty commands to history
            NewHistory =
                case TrimmedCommand of
                    "" ->
                        UIState#ui_state.command_history;
                    CleanCommand ->
                        %% Add to front, limit to 50 commands
                        lists:sublist(
                            [CleanCommand | UIState#ui_state.command_history],
                            50
                        )
                end,
            ProcessedUIState = process_command(TrimmedCommand, UIState),
            ProcessedUIState#ui_state{
                current_input = "",
                cursor_position = 0,
                history_position = 0,
                command_history = NewHistory
            };
        {key, ?ceKEY_BACKSPACE} ->
            %% Remove character before cursor
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            if
                CursorPos > 0 ->
                    {Before, After} = lists:split(CursorPos, CurrentInput),
                    NewBefore = lists:sublist(Before, length(Before) - 1),
                    NewInput = NewBefore ++ After,
                    UIState#ui_state{
                        current_input = NewInput,
                        cursor_position = CursorPos - 1,
                        history_position = 0
                    };
                true ->
                    UIState
            end;
        {key, delete} ->
            %% Remove character after cursor
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            if
                CursorPos < length(CurrentInput) ->
                    {Before, After} = lists:split(CursorPos, CurrentInput),
                    NewAfter =
                        case After of
                            [] -> [];
                            [_ | Rest] -> Rest
                        end,
                    NewInput = Before ++ NewAfter,
                    UIState#ui_state{
                        current_input = NewInput,
                        history_position = 0
                    };
                true ->
                    UIState
            end;
        {key, left} ->
            %% Move cursor left
            CursorPos = UIState#ui_state.cursor_position,
            NewCursorPos = max(0, CursorPos - 1),
            UIState#ui_state{cursor_position = NewCursorPos};
        {key, right} ->
            %% Move cursor right
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            NewCursorPos = min(length(CurrentInput), CursorPos + 1),
            UIState#ui_state{cursor_position = NewCursorPos};
        {key, home} ->
            %% Move cursor to beginning
            UIState#ui_state{cursor_position = 0};
        {key, end_key} ->
            %% Move cursor to end
            CurrentInput = UIState#ui_state.current_input,
            UIState#ui_state{cursor_position = length(CurrentInput)};
        {key, up} ->
            %% Navigate up in command history
            History = UIState#ui_state.command_history,
            HistoryPos = UIState#ui_state.history_position,
            if
                HistoryPos < length(History) ->
                    NewHistoryPos = HistoryPos + 1,
                    HistoryCommand = lists:nth(NewHistoryPos, History),
                    UIState#ui_state{
                        current_input = HistoryCommand,
                        cursor_position = length(HistoryCommand),
                        history_position = NewHistoryPos
                    };
                true ->
                    UIState
            end;
        {key, down} ->
            %% Navigate down in command history
            HistoryPos = UIState#ui_state.history_position,
            if
                HistoryPos > 1 ->
                    NewHistoryPos = HistoryPos - 1,
                    History = UIState#ui_state.command_history,
                    HistoryCommand = lists:nth(NewHistoryPos, History),
                    UIState#ui_state{
                        current_input = HistoryCommand,
                        cursor_position = length(HistoryCommand),
                        history_position = NewHistoryPos
                    };
                HistoryPos == 1 ->
                    %% Return to empty input
                    UIState#ui_state{
                        current_input = "",
                        cursor_position = 0,
                        history_position = 0
                    };
                true ->
                    UIState
            end;
        %% Emacs-style control key bindings
        {ctrl, ctrl_a} ->
            %% Ctrl+A - Move cursor to beginning of line
            UIState#ui_state{cursor_position = 0};
        {ctrl, ctrl_e} ->
            %% Ctrl+E - Move cursor to end of line
            CurrentInput = UIState#ui_state.current_input,
            UIState#ui_state{cursor_position = length(CurrentInput)};
        {ctrl, ctrl_b} ->
            %% Ctrl+B - Move cursor backward one character
            CursorPos = UIState#ui_state.cursor_position,
            NewCursorPos = max(0, CursorPos - 1),
            UIState#ui_state{cursor_position = NewCursorPos};
        {ctrl, ctrl_f} ->
            %% Ctrl+F - Move cursor forward one character
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            NewCursorPos = min(length(CurrentInput), CursorPos + 1),
            UIState#ui_state{cursor_position = NewCursorPos};
        {ctrl, ctrl_d} ->
            %% Ctrl+D - Delete character at cursor (like Delete key)
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            if
                CursorPos < length(CurrentInput) ->
                    {Before, After} = lists:split(CursorPos, CurrentInput),
                    NewAfter =
                        case After of
                            [] -> [];
                            [_ | Rest] -> Rest
                        end,
                    NewInput = Before ++ NewAfter,
                    UIState#ui_state{
                        current_input = NewInput,
                        history_position = 0
                    };
                true ->
                    UIState
            end;
        {ctrl, ctrl_k} ->
            %% Ctrl+K - Kill from cursor to end of line
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            {Before, After} = lists:split(CursorPos, CurrentInput),
            %% Add killed text to kill ring if not empty
            NewKillRing =
                case After of
                    [] ->
                        UIState#ui_state.kill_ring;
                    _ ->
                        [After | lists:sublist(UIState#ui_state.kill_ring, 9)]
                end,
            UIState#ui_state{
                current_input = Before,
                kill_ring = NewKillRing,
                history_position = 0
            };
        {ctrl, ctrl_u} ->
            %% Ctrl+U - Kill entire line
            CurrentInput = UIState#ui_state.current_input,
            %% Add killed text to kill ring if not empty
            NewKillRing =
                case CurrentInput of
                    [] ->
                        UIState#ui_state.kill_ring;
                    _ ->
                        [
                            CurrentInput
                            | lists:sublist(UIState#ui_state.kill_ring, 9)
                        ]
                end,
            UIState#ui_state{
                current_input = [],
                cursor_position = 0,
                kill_ring = NewKillRing,
                history_position = 0
            };
        {ctrl, ctrl_w} ->
            %% Ctrl+W - Kill word backward
            CurrentInput = UIState#ui_state.current_input,
            CursorPos = UIState#ui_state.cursor_position,
            {Before, After} = lists:split(CursorPos, CurrentInput),
            %% Find start of word to kill
            {_WordStart, KilledWord, NewBefore} = find_word_backward(Before),
            NewInput = NewBefore ++ After,
            NewCursorPos = length(NewBefore),
            %% Add killed word to kill ring if not empty
            NewKillRing =
                case KilledWord of
                    [] ->
                        UIState#ui_state.kill_ring;
                    _ ->
                        [
                            KilledWord
                            | lists:sublist(UIState#ui_state.kill_ring, 9)
                        ]
                end,
            UIState#ui_state{
                current_input = NewInput,
                cursor_position = NewCursorPos,
                kill_ring = NewKillRing,
                history_position = 0
            };
        {ctrl, ctrl_y} ->
            %% Ctrl+Y - Yank (paste) from kill ring
            case UIState#ui_state.kill_ring of
                [] ->
                    %% Nothing to yank
                    UIState;
                [LastKilled | _] ->
                    %% Insert at cursor position
                    CurrentInput = UIState#ui_state.current_input,
                    CursorPos = UIState#ui_state.cursor_position,
                    {Before, After} = lists:split(CursorPos, CurrentInput),
                    NewInput = Before ++ LastKilled ++ After,
                    NewCursorPos = CursorPos + length(LastKilled),
                    UIState#ui_state{
                        current_input = NewInput,
                        cursor_position = NewCursorPos,
                        history_position = 0
                    }
            end;
        {key, page_up} ->
            %% Page Up - Scroll up in message history (show older messages)
            CurrentScrollPos = UIState#ui_state.scroll_position,
            Messages = UIState#ui_state.message_history,
            TotalMessages = length(Messages),

            %% Calculate message area height
            ScreenHeight = UIState#ui_state.screen_height,
            % Status bar, help bar, input line, separator
            AreaHeight = ScreenHeight - 4,

            %% Calculate max scroll position (prevent scrolling beyond available messages)
            MaxScrollPos = max(0, TotalMessages - AreaHeight),

            %% Scroll up by area height, but don't exceed max
            NewScrollPos = min(MaxScrollPos, CurrentScrollPos + AreaHeight),
            UIState#ui_state{scroll_position = NewScrollPos};
        {key, page_down} ->
            %% Page Down - Scroll down in message history (show newer messages)
            CurrentScrollPos = UIState#ui_state.scroll_position,
            ScreenHeight = UIState#ui_state.screen_height,
            % Status bar, help bar, input line, separator
            AreaHeight = ScreenHeight - 4,

            %% Scroll down by area height, but don't go below 0
            NewScrollPos = max(0, CurrentScrollPos - AreaHeight),
            UIState#ui_state{scroll_position = NewScrollPos};
        _ ->
            %% Ignore other input
            UIState
    end.

%% @private
%% Process a user command and return updated UI state.
%%
%% This is the main command dispatcher that handles all user commands for
%% WebSocket mTLS operations:
%%
%% === Connection Commands ===
%% <ul>
%%   <li>`connect' - Establish WebSocket mTLS connection</li>
%%   <li>`disconnect' - Close WebSocket connection</li>
%%   <li>`help' - Display available commands</li>
%%   <li>`quit' - Exit the application</li>
%% </ul>
%%
%% === Messaging Commands (when connected) ===
%% <ul>
%%   <li>`send <user> <message>' - Send encrypted message</li>
%%   <li>`chat <user>' - Enter real-time chat mode</li>
%%   <li>`list_users' - Show registered users</li>
%% </ul>
%%
%% === Chat Mode Commands ===
%% When in chat mode, commands are processed differently:
%% <ul>
%%   <li>`:exit' - Leave chat mode</li>
%%   <li>`:help' - Show chat-specific help</li>
%%   <li>Any other text - Send as message to chat target</li>
%% </ul>
%%
%% The function handles connection state validation and provides appropriate
%% feedback through system messages.
%%
%% @param Command The command string entered by the user
%% @param UIState Current UI state
%% @returns Updated UI state with command results displayed.
process_command("", UIState) ->
    %% Empty command, do nothing
    UIState;
process_command("quit", UIState) ->
    %% Disconnect WebSocket if connected and send quit message
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.ws_client_state of
        undefined ->
            ok;
        {ok, ClientState} ->
            cryptic_ws_client:stop(ClientState#client_state.ws_client_pid);
        _ ->
            ok
    end,
    self() ! quit,
    UIState;
process_command("help", UIState) ->
    handle_help_command("", UIState);
process_command("help " ++ Rest, UIState) ->
    handle_help_command(Rest, UIState);
process_command("connect", UIState) ->
    %% Implement 5-step authentication flow per SESSION-MESSAGE-FLOW.md
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            add_system_message(
                "Already connected to WebSocket server", UIState
            );
        connecting ->
            add_system_message("Connection already in progress", UIState);
        disconnected ->
            %% Step 1: Switch to passphrase input mode
            case os:getenv("CRYPTIC_CONFIG_DIR") of
                false ->
                    ?error(
                        "CRYPTIC_CONFIG_DIR environment variable not set~n", []
                    ),
                    UIState;
                ConfigDir ->
                    NewState =
                        foldf(
                            UIState,
                            [
                                add_sys_msg_f("Starting secure connection..."),
                                add_sys_msg_f(
                                    "Enter passphrase for key decryption:"
                                )
                            ]
                        ),

                    %% Switch to passphrase input mode
                    PassphraseState = NewState#ui_state{
                        passphrase_mode = true,
                        passphrase_config_dir = ConfigDir,
                        current_input = "",
                        cursor_position = 0
                    },

                    PassphraseState
            end
    end;
process_command("disconnect", UIState) ->
    %% Disconnect from WebSocket server
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        disconnected ->
            add_system_message("Not connected to WebSocket server", UIState);
        connecting ->
            add_system_message("Cannot disconnect while connecting", UIState);
        connected ->
            %% Disconnect from server
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    %% Stop WebSocket client
                    cryptic_ws_client:stop(
                        ClientState#client_state.ws_client_pid
                    ),

                    %% Update state
                    NewWSChatState = WSChatState#ws_chat_state{
                        connection_status = disconnected,
                        ws_client_state = undefined
                    },
                    DisconnectedUIState = UIState#ui_state{
                        ws_chat_state = NewWSChatState
                    },
                    add_system_message(
                        "Disconnected from WebSocket server",
                        DisconnectedUIState
                    );
                _ ->
                    %% Invalid state, reset
                    NewWSChatState = WSChatState#ws_chat_state{
                        connection_status = disconnected,
                        ws_client_state = undefined
                    },
                    ResetUIState = UIState#ui_state{
                        ws_chat_state = NewWSChatState
                    },
                    add_system_message("Connection reset", ResetUIState)
            end
    end;
process_command("list_users", UIState) ->
    %% List users via WebSocket
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    ListUsersCmd = #{type => <<"list_users">>},
                    ?msg_out("UI sending list_users command: ~p", [ListUsersCmd]),
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid, ListUsersCmd
                        )
                    of
                        ok ->
                            add_system_message(
                                "Requesting user list...", UIState
                            );
                        queued ->
                            add_system_message(
                                "User list request queued...", UIState
                            );
                        {error, Reason} ->
                            ErrMsg = io_lib:format(
                                "Failed to request user list: ~p", [Reason]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message(
                        "WebSocket client not available", UIState
                    )
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("fetch_messages", UIState) ->
    %% Manually fetch messages from server (for troubleshooting)
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    GetMessagesCmd = #{type => <<"get_messages">>},
                    ?msg_out("UI sending get_messages command: ~p", [
                        GetMessagesCmd
                    ]),
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid,
                            GetMessagesCmd
                        )
                    of
                        ok ->
                            add_system_message(
                                "Checking server for pending messages...",
                                UIState
                            );
                        queued ->
                            add_system_message(
                                "Get messages request queued...", UIState
                            );
                        {error, Reason} ->
                            ErrMsg = io_lib:format(
                                "Failed to fetch messages: ~p", [Reason]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message(
                        "WebSocket client not available", UIState
                    )
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("key_status", UIState) ->
    %% Get key status from server
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    KeyStatusCmd = #{type => <<"key_status">>},
                    ?msg_out("UI sending key_status command: ~p", [KeyStatusCmd]),
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid, KeyStatusCmd
                        )
                    of
                        ok ->
                            add_system_message(
                                "Requesting key status...", UIState
                            );
                        queued ->
                            add_system_message(
                                "Key status request queued...", UIState
                            );
                        {error, Reason} ->
                            ErrMsg = io_lib:format(
                                "Failed to request key status: ~p", [Reason]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message(
                        "WebSocket client not available", UIState
                    )
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("send " ++ Rest, UIState) ->
    %% Send message via WebSocket
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            case string:split(Rest, " ", leading) of
                [ToUser, Message] ->
                    case WSChatState#ws_chat_state.ws_client_state of
                        {ok, ClientState} ->
                            FromUser = WSChatState#ws_chat_state.username,
                            TrimmedToUser = string:trim(ToUser),
                            TrimmedMessage = string:trim(Message),

                            %% Start the secure send process: get prekey, then encrypt and send
                            %% Don't show status message, will show "You -> user: message" on success

                            %% First, get the recipient's prekey
                            GetKeyBundleCmd = #{
                                type => <<"get_key_bundle">>,
                                user => list_to_binary(TrimmedToUser)
                            },
                            ?msg_out("UI requesting key bundle for ~s: ~p", [
                                TrimmedToUser, GetKeyBundleCmd
                            ]),
                            case
                                cryptic_ws_client:send_command(
                                    ClientState#client_state.ws_client_pid,
                                    GetKeyBundleCmd
                                )
                            of
                                ok ->
                                    %% Store the pending message for when we get the prekey response
                                    PendingMsg = #{
                                        type => send_encrypted,
                                        to_user => TrimmedToUser,
                                        message => TrimmedMessage,
                                        from_user => FromUser
                                    },
                                    NewWSChatState = WSChatState#ws_chat_state{
                                        pending_operation = PendingMsg
                                    },
                                    UIState#ui_state{
                                        ws_chat_state = NewWSChatState
                                    };
                                {error, Reason} ->
                                    ErrMsg = io_lib:format(
                                        "Failed to get prekey for ~s: ~p", [
                                            TrimmedToUser, Reason
                                        ]
                                    ),
                                    ?error("~s~n", [ErrMsg]),
                                    add_system_message(
                                        lists:flatten(ErrMsg), UIState
                                    )
                            end;
                        _ ->
                            add_system_message(
                                "WebSocket client not available", UIState
                            )
                    end;
                _ ->
                    add_system_message(
                        "Usage: send <username> <message>", UIState
                    )
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("chat " ++ Username, UIState) ->
    %% Enter chat mode via WebSocket
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            TrimmedUser = string:trim(Username),
            case TrimmedUser of
                "" ->
                    add_system_message("Usage: chat <username>", UIState);
                _ ->
                    NewUIState = UIState#ui_state{
                        chat_mode = true,
                        chat_target = TrimmedUser
                    },
                    Msg = io_lib:format(
                        "Entering chat mode with ~s. Type ':exit' to leave chat mode.",
                        [TrimmedUser]
                    ),
                    add_system_message(lists:flatten(Msg), NewUIState)
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("auto_display on", UIState) ->
    NewState = UIState#ui_state{auto_display = true},

    %% Check if there are any pending messages to display
    case UIState#ui_state.pending_messages of
        Empty when Empty =:= #{} ->
            %% No pending messages
            NewState;
        PendingMessages ->
            %% Show all pending messages and clear the pending counts
            TotalPending = maps:fold(
                fun(_, Count, Acc) -> Acc + Count end, 0, PendingMessages
            ),
            case TotalPending > 0 of
                true ->
                    %% Show pending messages notification
                    NotifyState = add_system_message(
                        "=== DISPLAYING PENDING MESSAGES ===", NewState
                    ),

                    %% Display messages from inbox for each sender with pending count > 0
                    FinalState = maps:fold(
                        fun(From, Count, AccState) ->
                            case Count > 0 of
                                true ->
                                    %% Get messages from this sender
                                    SenderMessages = [
                                        Msg
                                     || {MsgFrom, _, _} = Msg <-
                                            UIState#ui_state.inbox,
                                        MsgFrom =:= From
                                    ],
                                    %% Display the most recent messages up to the pending count
                                    RecentMessages = lists:sublist(
                                        lists:reverse(SenderMessages), Count
                                    ),
                                    lists:foldl(
                                        fun(
                                            {MsgFrom, Message, _Timestamp},
                                            State
                                        ) ->
                                            add_message(MsgFrom, Message, State)
                                        end,
                                        AccState,
                                        lists:reverse(RecentMessages)
                                    );
                                false ->
                                    AccState
                            end
                        end,
                        NotifyState,
                        PendingMessages
                    ),

                    %% Clear all pending message counts
                    FinalState#ui_state{pending_messages = #{}};
                false ->
                    NewState
            end
    end;
process_command("auto_display off", UIState) ->
    UIState#ui_state{auto_display = false};
process_command("auto_display", UIState) ->
    Status =
        case UIState#ui_state.auto_display of
            true -> "enabled";
            false -> "disabled"
        end,
    add_system_message("Auto-display is currently " ++ Status, UIState);
process_command("inbox" ++ Rest, UIState) ->
    case string:trim(Rest) of
        [] ->
            %% Show inbox summary with message counts by sender
            case UIState#ui_state.pending_messages of
                Empty when Empty =:= #{} ->
                    add_system_message("Inbox is empty", UIState);
                PendingMessages ->
                    %% Filter to only show senders with messages (count > 0)
                    PendingWithMessages = maps:filter(
                        fun(_, Count) -> Count > 0 end, PendingMessages
                    ),
                    case maps:size(PendingWithMessages) of
                        0 ->
                            add_system_message("Inbox is empty", UIState);
                        _ ->
                            InboxState = add_system_message(
                                "=== INBOX SUMMARY ===", UIState
                            ),
                            InboxState2 = add_system_message(
                                "From                 Messages", InboxState
                            ),
                            InboxState3 = add_system_message(
                                "----                 --------", InboxState2
                            ),
                            FinalState = lists:foldl(
                                fun({From, Count}, AccState) ->
                                    Line = io_lib:format("~-20s ~w", [
                                        From, Count
                                    ]),
                                    add_system_message(
                                        lists:flatten(Line), AccState
                                    )
                                end,
                                InboxState3,
                                lists:sort(maps:to_list(PendingWithMessages))
                            ),
                            %% Don't clear pending counts - only clear when actually reading messages
                            FinalState
                    end
            end;
        Sender ->
            %% Show messages from specific sender
            case UIState#ui_state.inbox of
                [] ->
                    add_system_message("No messages from " ++ Sender, UIState);
                Messages ->
                    SenderMessages = [
                        Msg
                     || {From, _, _} = Msg <- Messages, From =:= Sender
                    ],
                    case SenderMessages of
                        [] ->
                            add_system_message(
                                "No messages from " ++ Sender, UIState
                            );
                        _ ->
                            InboxState = add_system_message(
                                "=== MESSAGES FROM " ++ string:uppercase(Sender) ++
                                    " ===",
                                UIState
                            ),
                            FinalState = lists:foldl(
                                fun({_From, Message, Timestamp}, AccState) ->
                                    TimeStr = format_timestamp(Timestamp),
                                    MsgText = io_lib:format("[~s] ~s", [
                                        TimeStr, Message
                                    ]),
                                    add_system_message(
                                        lists:flatten(MsgText), AccState
                                    )
                                end,
                                InboxState,
                                SenderMessages
                            ),
                            %% Clear pending message count for this sender
                            UpdatedPendingMessages = maps:put(
                                Sender, 0, UIState#ui_state.pending_messages
                            ),
                            FinalState#ui_state{
                                pending_messages = UpdatedPendingMessages
                            }
                    end
            end
    end;
%% Room management commands
process_command("create_room " ++ Rest, UIState) ->
    handle_create_room_command(Rest, UIState);
process_command("join_room " ++ Rest, UIState) ->
    handle_join_room_command(Rest, UIState);
process_command("leave_room " ++ Rest, UIState) ->
    handle_leave_room_command(Rest, UIState);
process_command("list_rooms" ++ Rest, UIState) ->
    handle_list_rooms_command(Rest, UIState);
process_command("room_info " ++ Rest, UIState) ->
    handle_room_info_command(Rest, UIState);
process_command("room_chat " ++ Rest, UIState) ->
    handle_room_chat_command(Rest, UIState);
process_command("send_room " ++ Rest, UIState) ->
    handle_send_room_command(Rest, UIState);
process_command("room_history " ++ Rest, UIState) ->
    handle_room_history_command(Rest, UIState);
process_command(Command, UIState) ->
    %% Check if we're in chat mode
    case UIState#ui_state.chat_mode of
        true ->
            process_chat_command(Command, UIState);
        false ->
            %% Unknown command
            add_system_message(
                "Unknown command: " ++ Command ++
                    " (type 'help' for available commands)",
                UIState
            )
    end.

%% @private
%% Process commands while in chat mode via WebSocket.
%%
%% Chat mode provides a streamlined interface for real-time conversations
%% over the WebSocket mTLS connection. It handles special chat commands that
%% start with ":" and treats all other input as messages to send to the chat target.
%%
%% === Chat Commands ===
%% <ul>
%%   <li>`:exit' - Leave chat mode</li>
%%   <li>`:help' - Show chat mode specific help</li>
%%   <li>`:<unknown>' - Display error for unknown chat commands</li>
%% </ul>
%%
%% === Message Sending ===
%% Any text that doesn't start with ":" is treated as a message to send
%% to the current chat target via WebSocket. Messages are sent immediately
%% and displayed in the chat format "You -> target: message".
%%
%% @param Command The command or message entered in chat mode
%% @param UIState Current UI state in chat mode
%% @returns Updated UI state after processing the chat command.
process_chat_command(":exit", UIState) ->
    %% Exit chat mode
    NewUIState = UIState#ui_state{
        chat_mode = false,
        chat_target = undefined
    },
    add_system_message("Exited chat mode", NewUIState);
process_chat_command(":help", UIState) ->
    %% Show chat mode help
    HelpState = add_system_message("=== CHAT MODE COMMANDS ===", UIState),
    HelpState2 = add_system_message(":exit - Leave chat mode", HelpState),
    HelpState3 = add_system_message(":help - Show this help", HelpState2),
    HelpState4 = add_system_message(
        "Any other text - Send as message", HelpState3
    ),
    HelpState4;
process_chat_command(":" ++ Command, UIState) ->
    %% Unknown chat command
    add_system_message("Unknown chat command: :" ++ Command, UIState);
process_chat_command(Message, UIState) ->
    %% Send encrypted message to chat target via WebSocket
    WSChatState = UIState#ui_state.ws_chat_state,
    case
        {
            WSChatState#ws_chat_state.connection_status,
            UIState#ui_state.chat_target
        }
    of
        {connected, undefined} ->
            add_system_message("Error: No chat target set", UIState);
        {connected, ToUser} ->
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    FromUser = WSChatState#ws_chat_state.username,
                    TrimmedMessage = string:trim(Message),

                    %% Start the secure send process: get prekey, then encrypt and send
                    %% Don't show status message, will show "You -> user: message" on success

                    %% First, get the recipient's prekey
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid, #{
                                type => <<"get_key_bundle">>,
                                user => list_to_binary(ToUser)
                            }
                        )
                    of
                        ok ->
                            %% Store the pending message for when we get the prekey response
                            PendingMsg = #{
                                type => send_encrypted,
                                to_user => ToUser,
                                message => TrimmedMessage,
                                from_user => FromUser
                            },
                            NewWSChatState = WSChatState#ws_chat_state{
                                pending_operation = PendingMsg
                            },
                            UIState#ui_state{ws_chat_state = NewWSChatState};
                        queued ->
                            %% Prekey request queued
                            PendingMsg = #{
                                type => send_encrypted,
                                to_user => ToUser,
                                message => TrimmedMessage,
                                from_user => FromUser
                            },
                            NewWSChatState = WSChatState#ws_chat_state{
                                pending_operation = PendingMsg
                            },
                            QueuedState = add_system_message(
                                "Message queued for encryption...", UIState
                            ),
                            QueuedState#ui_state{
                                ws_chat_state = NewWSChatState
                            };
                        {error, Reason} ->
                            ErrMsg = io_lib:format(
                                "Failed to get prekey for ~s: ~p", [
                                    ToUser, Reason
                                ]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message(
                        "WebSocket client not available", UIState
                    )
            end;
        _ ->
            add_system_message("Not connected. Cannot send message.", UIState)
    end.

%% @private
%% Handle incoming WebSocket messages from the server.
%%
%% Processes different types of WebSocket messages:
%% <ul>
%%   <li>Incoming chat messages from other users</li>
%%   <li>System notifications and status updates</li>
%%   <li>Command responses and acknowledgments</li>
%%   <li>Connection status changes</li>
%% </ul>
%%
%% Messages are displayed in the message area with appropriate formatting
%% and color coding based on the message type and sender.
%%
%% @param Message The WebSocket message received from the server
%% @param UIState Current UI state
%% @returns Updated UI state with the message displayed.
handle_websocket_message(Message, UIState) ->
    case Message of
        {text, JsonText} ->
            ?dbg("Attempting to decode JSON: ~p", [JsonText]),
            ?msg_in("UI received WebSocket message: ~s", [JsonText]),
            try
                Data = jsx:decode(JsonText),
                ?dbg("Successfully decoded JSON: ~p", [Data]),
                case maps:get(<<"type">>, Data, undefined) of
                    <<"message">> ->
                        %% Incoming chat message
                        From = binary_to_list(
                            maps:get(<<"from">>, Data, <<"unknown">>)
                        ),
                        Content = binary_to_list(
                            maps:get(<<"message">>, Data, <<"">>)
                        ),
                        add_message(From, Content, UIState);
                    <<"users">> ->
                        %% User list response
                        Users = maps:get(<<"users">>, Data, []),
                        UsersState = add_system_message(
                            "Available users:", UIState
                        ),
                        lists:foldl(
                            fun(User, AccState) ->
                                add_system_message(
                                    "  - " ++ binary_to_list(User), AccState
                                )
                            end,
                            UsersState,
                            Users
                        );
                    <<"key_status">> ->
                        %% Key status response
                        handle_key_status_response(Data, UIState);
                    <<"key_bundle">> ->
                        %% Key bundle response - handle X3DH session establishment
                        handle_key_bundle_response(Data, UIState);
                    <<"user_status">> ->
                        %% User status response (e.g., user offline) - handle pending send
                        handle_user_status_response(Data, UIState);
                    <<"success">> ->
                        %% Success response
                        Content = binary_to_list(
                            maps:get(
                                <<"message">>, Data, <<"Operation successful">>
                            )
                        ),
                        add_system_message("Success: " ++ Content, UIState);
                    <<"error">> ->
                        %% Error response - now only for actual errors (like user not found)
                        WSChatState = UIState#ui_state.ws_chat_state,
                        Content = binary_to_list(
                            maps:get(<<"message">>, Data, <<"Unknown error">>)
                        ),

                        case WSChatState#ws_chat_state.pending_operation of
                            #{type := send_encrypted, to_user := ToUser} ->
                                %% This error is related to our pending message send
                                %% Clear the pending operation and provide specific feedback
                                NewWSChatState = WSChatState#ws_chat_state{
                                    pending_operation = undefined
                                },
                                UpdatedUIState = UIState#ui_state{
                                    ws_chat_state = NewWSChatState
                                },
                                UserFeedback =
                                    "Cannot send message to '" ++ ToUser ++
                                        "': " ++ Content,
                                add_system_message(
                                    UserFeedback, UpdatedUIState
                                );
                            _ ->
                                %% Generic error not related to pending operations
                                add_system_message(
                                    "Error: " ++ Content, UIState
                                )
                        end;
                    <<"system">> ->
                        %% System message
                        Content = binary_to_list(
                            maps:get(<<"message">>, Data, <<"System message">>)
                        ),
                        add_system_message(Content, UIState);
                    <<"room_created">> ->
                        %% Room creation response
                        handle_room_created_response(Data, UIState);
                    <<"rooms_list">> ->
                        %% Room list response
                        handle_rooms_list_response(Data, UIState);
                    <<"room_joined">> ->
                        %% Room join response
                        handle_room_joined_response(Data, UIState);
                    <<"room_left">> ->
                        %% Room leave response
                        handle_room_left_response(Data, UIState);
                    <<"room_members">> ->
                        %% Room members/info response
                        handle_room_members_response(Data, UIState);
                    <<"room_messages">> ->
                        %% Room message history response
                        handle_room_messages_response(Data, UIState);
                    <<"room_message">> ->
                        %% Incoming room message
                        handle_room_message(Data, UIState);
                    <<"room_message_sent">> ->
                        %% Room message sent confirmation
                        handle_room_message_sent_response(Data, UIState);
                    _ ->
                        %% Unknown message type
                        add_system_message(
                            "Received unknown message type", UIState
                        )
                end
            catch
                Error:Reason:StackTrace ->
                    ?dbg(
                        "Failed to decode JSON: ~p Reason: ~p Error: ~p~n~p~n",
                        [
                            JsonText, Reason, Error, StackTrace
                        ]
                    ),
                    add_system_message("Received invalid JSON message", UIState)
            end;
        {binary, _Data} ->
            add_system_message("Received binary WebSocket message", UIState);
        _What ->
            ?dbg("Received unknown WebSocket message: ~p~n", [_What]),
            add_system_message(
                "Received unknown WebSocket message format", UIState
            )
    end.

%% @doc Handle key bundle response and complete the X3DH session establishment.
%%
%% When we receive a key bundle response from the server, we can now perform
%% X3DH key agreement and send the encrypted message securely.
handle_key_bundle_response(Data, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    ?dbg("handle_key_bundle_response called with Data: ~p", [Data]),
    ?dbg("Current pending_operation: ~p", [
        WSChatState#ws_chat_state.pending_operation
    ]),
    case WSChatState#ws_chat_state.pending_operation of
        #{type := send_encrypted} = SendOp ->
            handle_key_bundle_for_sending(Data, SendOp, UIState);
        #{type := decrypt_x3dh_message} = DecryptOp ->
            handle_key_bundle_for_decryption(Data, DecryptOp, UIState);
        _ ->
            handle_unexpected_key_bundle_response(WSChatState, UIState)
    end.

%% @private
%% Handle key bundle response for sending encrypted messages (X3DH sender role).
handle_key_bundle_for_sending(Data, SendOp, UIState) ->
    #{to_user := ToUser, message := Message} = SendOp,
    try
        RecipientBundle = extract_and_build_recipient_bundle(Data),
        send_x3dh_encrypted_message(RecipientBundle, ToUser, Message, UIState)
    catch
        _:Error:StackTrace ->
            ErrStr =
                lists:flatten(
                    io_lib:format("Error processing key bundle: ~p", [Error])
                ),
            ?error("~s~n~p~n", [ErrStr, StackTrace]),
            add_system_message(ErrStr, UIState)
    end.

%% @private
%% Handle key bundle response for decrypting X3DH messages (X3DH receiver role).
handle_key_bundle_for_decryption(Data, DecryptOp, UIState) ->
    #{sender := From, recipient_blob := RecipientBlob} = DecryptOp,
    ?dbg("MATCHED decrypt_x3dh_message case for sender: ~s", [From]),
    try
        ?dbg("Processing key bundle response for X3DH decryption from ~s", [
            From
        ]),

        %% Extract and cache the sender's identity keys (for caching only)
        {_SenderIdSignPub, _SenderKeyId} = extract_and_cache_identity_key(
            Data, From
        ),

        %% Perform X3DH decryption (function gets signing key from message metadata)
        decrypt_x3dh_message_with_key(
            undefined, RecipientBlob, From, UIState
        )
    catch
        _:DecryptError:Stacktrace ->
            ?dbg(
                "Error processing key bundle for decryption: ~p~n~p~n",
                [DecryptError, Stacktrace]
            ),
            clear_pending_operation_and_add_error(
                lists:flatten(
                    io_lib:format(
                        "Error processing key bundle for decryption: ~p", [
                            DecryptError
                        ]
                    )
                ),
                UIState
            )
    end.

%% @private
%% Handle unexpected key bundle response when no matching pending operation.
handle_unexpected_key_bundle_response(WSChatState, UIState) ->
    ?dbg(
        "UNEXPECTED: No matching pending operation for key bundle response", []
    ),
    ?dbg("Pending operation was: ~p", [
        WSChatState#ws_chat_state.pending_operation
    ]),
    add_system_message("Received unexpected key bundle response", UIState).

%% @private
%% Extract key bundle data from response and build recipient bundle for X3DH.
extract_and_build_recipient_bundle(Data) ->
    %% Extract key bundle data from response
    #{
        <<"identity_sign_public">> := IdentitySignKeyB64,
        <<"identity_dh_public">> := IdentityDHKeyB64,
        <<"signed_prekey">> := SignedPrekeyB64,
        <<"signed_prekey_signature">> := SignatureB64,
        <<"key_id">> := KeyIdB64,
        <<"one_time_prekey">> := OTPKData
    } = Data,

    %% Decode the key bundle components
    IdentitySignKey = base64:decode(IdentitySignKeyB64),
    IdentityDHKey = base64:decode(IdentityDHKeyB64),
    SignedPrekey = base64:decode(SignedPrekeyB64),
    Signature = base64:decode(SignatureB64),
    KeyId = base64:decode(KeyIdB64),

    %% Handle one-time prekey (could be null)
    {OTPK, OTPKId} =
        case OTPKData of
            null ->
                {undefined, undefined};
            #{<<"public">> := OTPKPubB64, <<"id">> := IdB64} ->
                {base64:decode(OTPKPubB64), base64:decode(IdB64)}
        end,

    %% Build recipient key bundle for X3DH
    %% Server now sends both identity keys separately
    RecipientBundle = #{
        identity_sign_public => IdentitySignKey,
        identity_dh_public => IdentityDHKey,
        signed_prekey => #{
            public => SignedPrekey,
            signature => Signature
        },
        key_id => KeyId,
        one_time_prekey =>
            case OTPK of
                undefined -> null;
                _ -> #{id => OTPKId, public => OTPK}
            end
    },
    ?dbg("Recipient bundle: ~p~n", [RecipientBundle]),
    RecipientBundle.

%% @private
%% Send X3DH encrypted message using the recipient's key bundle.
send_x3dh_encrypted_message(RecipientBundle, ToUser, Message, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.ws_client_state of
        {ok, ClientState} ->
            SenderKeys = WSChatState#ws_chat_state.client_keys,

            %% Perform X3DH and encrypt message
            case
                cryptic_lib:x3dh_sender_init(
                    SenderKeys, RecipientBundle, list_to_binary(Message)
                )
            of
                {ok, {MessageBlob, MessageId}} ->
                    ?dbg("X3DH encryption successful: ~p", [MessageId]),
                    send_x3dh_message_to_server(
                        MessageBlob,
                        MessageId,
                        ToUser,
                        ClientState,
                        UIState,
                        Message
                    );
                {error, X3DHErr} ->
                    ErrStr =
                        lists:flatten(
                            io_lib:format("X3DH key agreement failed: ~p", [
                                X3DHErr
                            ])
                        ),
                    ?error("~s~n", [ErrStr]),
                    add_system_message(ErrStr, UIState)
            end;
        {error, ClientErr} ->
            ClientErrStr =
                lists:flatten(
                    io_lib:format("Client state error: ~p", [ClientErr])
                ),
            ?error("~s~n", [ClientErrStr]),
            add_system_message(ClientErrStr, UIState)
    end.

%% @private
%% Send the X3DH encrypted message to the server via WebSocket.
send_x3dh_message_to_server(
    MessageBlob, MessageId, ToUser, ClientState, UIState, OriginalMessage
) ->
    %% Unpack MessageBlob to match existing handler format
    #{
        metadata := Metadata,
        signature := MessageSignature,
        ciphertext := Ciphertext,
        nonce := Nonce
    } = MessageBlob,

    #{
        ephemeral_public := EphemeralPub,
        otpk_id := OtpkId
    } = Metadata,

    %% Send the X3DH encrypted message with complete metadata
    X3DHSendCmd = #{
        type => <<"send_message_x3dh">>,
        to => list_to_binary(ToUser),
        message_id => base64:encode(MessageId),
        ephemeral_public => base64:encode(EphemeralPub),
        otpk_id =>
            case OtpkId of
                undefined -> null;
                _ -> base64:encode(OtpkId)
            end,
        ciphertext => base64:encode(Ciphertext),
        nonce => base64:encode(Nonce),
        signature => base64:encode(MessageSignature),
        %% Include complete metadata for proper X3DH signature verification
        metadata => base64:encode(erlang:term_to_binary(Metadata))
    },
    ?msg_out("UI sending X3DH message to ~s: ~p", [ToUser, X3DHSendCmd]),

    %% Add warning if no OTPK was available for this message
    UIStateWithWarning =
        case OtpkId of
            undefined ->
                Warning = lists:flatten(
                    io_lib:format(
                        "WARNING: Message to ~s sent with reduced forward secrecy (no one-time prekey available)",
                        [ToUser]
                    )
                ),
                add_system_message(Warning, UIState);
            _ ->
                UIState
        end,

    case
        cryptic_ws_client:send_command(
            ClientState#client_state.ws_client_pid, X3DHSendCmd
        )
    of
        ok ->
            clear_pending_operation_and_show_success(
                ToUser, OriginalMessage, UIStateWithWarning
            );
        {error, SendErr} ->
            add_system_message(
                lists:flatten(
                    io_lib:format("Failed to send encrypted message: ~p", [
                        SendErr
                    ])
                ),
                UIStateWithWarning
            )
    end.

%% @private
%% Extract sender's identity key from key bundle response and cache it.
extract_and_cache_identity_key(Data, From) ->
    %% Extract both identity keys from the response
    #{
        <<"identity_sign_public">> := IdentitySignKeyB64,
        <<"identity_dh_public">> := IdentityDHKeyB64
    } = Data,
    SenderIdSignPub = base64:decode(IdentitySignKeyB64),
    SenderIdDHPub = base64:decode(IdentityDHKeyB64),

    %% Extract the full key bundle data to match store_key_bundle format
    #{
        <<"signed_prekey">> := SignedPrekeyB64,
        <<"signed_prekey_signature">> := SignatureB64,
        <<"key_id">> := KeyIdB64,
        <<"one_time_prekey">> := OTPKData
    } = Data,

    %% Decode the key bundle components
    SignedPrekey = base64:decode(SignedPrekeyB64),
    Signature = base64:decode(SignatureB64),
    KeyId = base64:decode(KeyIdB64),

    %% Handle one-time prekey (could be null)
    OneTimePrekeys =
        case OTPKData of
            null ->
                [];
            #{<<"public">> := OTPKPubB64, <<"id">> := IdB64} ->
                OTPKPub = base64:decode(OTPKPubB64),
                OTPKId = base64:decode(IdB64),
                [#{id => OTPKId, public => OTPKPub}]
        end,

    %% Build the complete key bundle in the format expected by store_key_bundle
    User = maps:get(<<"user">>, Data, list_to_binary(From)),
    KeyBundle = #{
        identity_sign_public => SenderIdSignPub,
        identity_dh_public => SenderIdDHPub,
        signed_prekey_public => SignedPrekey,
        signed_prekey_signature => Signature,
        one_time_prekeys => OneTimePrekeys,
        key_id => KeyId
    },

    %% Cache the key bundle
    cryptic_lib:store_key_bundle(binary_to_list(User), KeyBundle),
    ?dbg("Cached key bundle for ~s", [binary_to_list(User)]),
    {SenderIdSignPub, KeyId}.

%% @private
%% Decrypt X3DH message using the sender's identity key.
decrypt_x3dh_message_with_key(
    _SenderIdPub, RecipientBlob, From, UIState
) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.client_keys of
        undefined ->
            clear_pending_operation_and_add_error(
                "No client keys available for X3DH decryption",
                UIState
            );
        ClientKeys ->
            %% Get the private key for the OTPK ID used
            OtpkPrivateKey = find_otpk_private_key(RecipientBlob, ClientKeys),

            %% Extract Alice's signing key from message metadata for signature verification
            %% (not from cached key bundle which contains her DH key)
            #{metadata := MessageMetadata} = RecipientBlob,
            #{sender_identity_sign_public := AliceSigningKey} = MessageMetadata,

            ?dbg(
                "About to call x3dh_receiver_decrypt with:~n  AliceSigningKey (for sig verification): ~p~n  RecipientBlob: ~p~n  OtpkPrivateKey: ~p",
                [
                    AliceSigningKey,
                    RecipientBlob,
                    OtpkPrivateKey
                ]
            ),

            case
                cryptic_lib:x3dh_receiver_decrypt(
                    ClientKeys,
                    RecipientBlob,
                    AliceSigningKey,
                    OtpkPrivateKey
                )
            of
                {ok, {PlaintextMessage, _MessageId}} ->
                    ?dbg("Successfully decrypted X3DH message from ~s", [From]),

                    %% Track OTPK usage for forward secrecy management
                    UIStateAfterTracking = handle_otpk_tracking(
                        From, RecipientBlob, UIState
                    ),

                    DecryptedText = binary_to_list(PlaintextMessage),
                    clear_pending_operation_and_add_message_from_user(
                        From, DecryptedText, UIStateAfterTracking
                    );
                {error, DecryptReason} ->
                    ?dbg("Failed to decrypt X3DH message from ~s: ~p", [
                        From, DecryptReason
                    ]),
                    clear_pending_operation_and_add_error(
                        lists:flatten(
                            io_lib:format(
                                "Failed to decrypt message from ~s: ~p", [
                                    From, DecryptReason
                                ]
                            )
                        ),
                        UIState
                    )
            end
    end.

%% @private
%% Find the OTPK private key for the given recipient blob.
find_otpk_private_key(RecipientBlob, ClientKeys) ->
    OtpkId = maps:get(
        otpk_id, maps:get(metadata, RecipientBlob, #{}), undefined
    ),
    case OtpkId of
        undefined ->
            ?dbg("No OTPK ID in message, using null", []),
            null;
        OtpkIdVal ->
            case cryptic_lib:find_otpk_private_key(ClientKeys, OtpkIdVal) of
                {ok, PrivKey} ->
                    ?dbg("Found OTPK private key for ID ~p", [OtpkIdVal]),
                    PrivKey;
                {error, OtpkReason} ->
                    ?dbg(
                        "Warning: Could not find OTPK private key for ID ~p: ~p",
                        [OtpkIdVal, OtpkReason]
                    ),
                    null
            end
    end.

%% @private
%% Handle OTPK usage tracking for forward secrecy management.
%%
%% This function manages OTPK (One-Time Prekey) usage tracking to maintain
%% forward secrecy and detect potential security issues:
%% <ul>
%%   <li>Tracks the last OTPK used by each sender</li>
%%   <li>Detects OTPK reuse (security concern)</li>
%%   <li>Detects OTPK rotation and cleans up old keys</li>
%%   <li>Provides user notifications about key management events</li>
%% </ul>
%%
%% @param From The sender's username
%% @param RecipientBlob The encrypted message blob containing metadata
%% @param UIState Current UI state
%% @returns Updated UI state with tracking information and any user notifications
-spec handle_otpk_tracking(string(), map(), #ui_state{}) -> #ui_state{}.
handle_otpk_tracking(From, RecipientBlob, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    MyUsername = WSChatState#ws_chat_state.username,
    #{metadata := MessageMetadata} = RecipientBlob,
    CurrentOtpkId = maps:get(otpk_id, MessageMetadata, undefined),

    %% Check for OTPK rotation and cleanup
    UIStateAfterTracking =
        case cryptic_lib:check_otpk_usage(MyUsername, From) of
            {ok, {LastOtpkId, _LastTimestamp}} ->
                case {LastOtpkId, CurrentOtpkId} of
                    {Same, Same} when Same =/= undefined ->
                        %% OTPK reuse detected - log security warning
                        ?warning(
                            "WARNING: OTPK reuse detected from ~s (security concern)",
                            [From]
                        ),
                        add_system_message(
                            lists:flatten(
                                io_lib:format(
                                    "SECURITY WARNING: ~s is reusing the same one-time prekey. "
                                    "This reduces forward secrecy.",
                                    [From]
                                )
                            ),
                            UIState
                        );
                    {OldId, NewId} when
                        OldId =/= undefined,
                        NewId =/= undefined,
                        OldId =/= NewId
                    ->
                        %% OTPK rotation detected - clean up old key
                        cryptic_lib:cleanup_old_otpk(MyUsername, From),
                        ?dbg(
                            "Cleaned up old OTPK from ~s (key rotation)~n",
                            [From]
                        ),
                        UIState;
                    _ ->
                        %% Other cases (undefined transitions) - normal
                        ?dbg("No OTPK rotation detected from ~s~n", [From]),
                        UIState
                end;
            {error, not_found} ->
                %% First message from this sender
                UIState
        end,

    %% Update OTPK usage tracking
    cryptic_lib:track_otpk_usage(MyUsername, From, CurrentOtpkId),

    UIStateAfterTracking.

%% @private
%% Clear pending operation and add a system message.
clear_pending_operation_and_add_message(Message, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    ClearedChatState = WSChatState#ws_chat_state{pending_operation = undefined},
    ClearedState = UIState#ui_state{ws_chat_state = ClearedChatState},
    add_system_message(Message, ClearedState).

%% @private
%% Clear pending operation and add an error message.
clear_pending_operation_and_add_error(ErrorMessage, UIState) ->
    clear_pending_operation_and_add_message(ErrorMessage, UIState).

%% @private
%% Clear pending operation and add a message from a user.
clear_pending_operation_and_add_message_from_user(From, DecryptedText, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    ClearedChatState = WSChatState#ws_chat_state{pending_operation = undefined},
    ClearedUIState = UIState#ui_state{ws_chat_state = ClearedChatState},
    add_message(From, DecryptedText, ClearedUIState).

%% @private
%% Clear pending operation and show success message.
clear_pending_operation_and_show_success(ToUser, Message, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    ClearedChatState = WSChatState#ws_chat_state{
        pending_operation = undefined
    },
    ClearedUIState = UIState#ui_state{ws_chat_state = ClearedChatState},
    FromField = "You -> " ++ ToUser,
    add_message(FromField, Message, ClearedUIState).

%% @doc Handle user status response from the server.
%%
%% This function handles user status responses (online/offline) that may be
%% received when attempting to send messages to users.
handle_user_status_response(Data, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{type := send_encrypted, to_user := ToUser} ->
            Status = maps:get(<<"status">>, Data, <<"unknown">>),
            case Status of
                <<"offline">> ->
                    %% Clear pending operation and show user-friendly message
                    ClearWSChatState = WSChatState#ws_chat_state{
                        pending_operation = undefined
                    },
                    ClearUIState = UIState#ui_state{
                        ws_chat_state = ClearWSChatState
                    },
                    StatusMsg = io_lib:format("User ~s is currently offline", [
                        ToUser
                    ]),
                    add_system_message(lists:flatten(StatusMsg), ClearUIState);
                <<"online">> ->
                    %% This shouldn't happen since online users would get prekey response
                    add_system_message(
                        "User is online but no prekey received", UIState
                    );
                _ ->
                    StatusMsg = io_lib:format("User ~s status: ~s", [
                        ToUser, Status
                    ]),
                    add_system_message(lists:flatten(StatusMsg), UIState)
            end;
        _ ->
            %% No pending operation or wrong type
            add_system_message(
                "Received unexpected user status response", UIState
            )
    end.

%% @doc Handle key status response from server.
%%
%% This function displays key information for the current user including:
%% - Identity key status
%% - Signed prekey information
%% - One-time prekeys count
%% - Key bundle creation timestamp
handle_key_status_response(Data, UIState) ->
    case maps:get(<<"status">>, Data, undefined) of
        undefined ->
            add_system_message("Invalid key status response", UIState);
        Status ->
            %% Format and display key status information
            Username = maps:get(<<"username">>, Status, "unknown"),
            HasIdentityKeys = maps:get(<<"has_identity_keys">>, Status, false),
            HasSignedPrekey = maps:get(<<"has_signed_prekey">>, Status, false),
            OtpkCount = maps:get(<<"otpk_count">>, Status, 0),

            %% Build status message
            StatusLines = [
                "=== Key Status for " ++ Username ++ " ===",
                "Identity Keys: " ++
                    case HasIdentityKeys of
                        true -> "[OK] Present";
                        false -> "[NO] Missing"
                    end,
                "Signed Prekey: " ++
                    case HasSignedPrekey of
                        true -> "[OK] Present";
                        false -> "[NO] Missing"
                    end,
                "One-time Prekeys: " ++ integer_to_list(OtpkCount) ++
                    " available"
            ],

            %% Add timestamp information if available
            TimestampLines =
                case maps:get(<<"created_at">>, Status, undefined) of
                    undefined ->
                        [];
                    CreatedAt when is_integer(CreatedAt) ->
                        DateTime = calendar:system_time_to_rfc3339(CreatedAt),
                        ["Key Bundle Created: " ++ DateTime];
                    _ ->
                        []
                end,

            %% Add signed prekey timestamp if available
            SignedPrekeyLines =
                case
                    maps:get(<<"signed_prekey_timestamp">>, Status, undefined)
                of
                    undefined ->
                        [];
                    SPTimestamp when is_integer(SPTimestamp) ->
                        SPDateTime = calendar:system_time_to_rfc3339(
                            SPTimestamp
                        ),
                        ["Signed Prekey Created: " ++ SPDateTime];
                    _ ->
                        []
                end,

            %% Add status warnings if needed
            WarningLines =
                case {HasIdentityKeys, HasSignedPrekey, OtpkCount} of
                    {false, false, 0} ->
                        [
                            "WARNING: No keys found - run key setup to enable encryption"
                        ];
                    {false, _, _} ->
                        [
                            "WARNING: Missing identity keys - encryption may not work"
                        ];
                    {_, false, _} ->
                        [
                            "WARNING: Missing signed prekey - encryption may not work"
                        ];
                    {true, true, 0} ->
                        [
                            "WARNING: No one-time prekeys available - consider uploading more"
                        ];
                    _ ->
                        ["[OK] All keys present and ready for encryption"]
                end,

            AllLines =
                StatusLines ++ TimestampLines ++ SignedPrekeyLines ++
                    WarningLines,

            %% Display all status lines
            lists:foldl(
                fun(Line, AccState) ->
                    add_system_message(Line, AccState)
                end,
                UIState,
                AllLines
            )
    end.

%% @doc Handle prekey received from WebSocket client for immediate encryption.
%%
%% This function handles prekeys received asynchronously from the server
%% when another user's public key is needed for message encryption.
handle_prekey_received(User, PrekeyB64, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{type := send_encrypted} = SendOp ->
            handle_prekey_for_send_encrypted(User, PrekeyB64, SendOp, UIState);
        #{type := decrypt_room_message} = _DecryptOp ->
            %% Legacy room message decryption no longer supported
            UserStr = binary_to_list(User),
            ErrMsg = io_lib:format(
                "Legacy room message decryption from ~s no longer supported. "
                "Room messages must use X3DH protocol.",
                [UserStr]
            ),
            add_system_message(lists:flatten(ErrMsg), UIState);
        _ ->
            %% No pending operation - just acknowledge
            UserStr = binary_to_list(User),
            MsgText = io_lib:format("Received prekey for user ~s", [UserStr]),
            add_system_message(lists:flatten(MsgText), UIState)
    end.

%% @private
%% Handle prekey received for pending send_encrypted operation.
%% Redirect to X3DH key bundle flow for consistency.
handle_prekey_for_send_encrypted(User, _PrekeyB64, SendOp, UIState) ->
    #{
        to_user := ToUser
    } = SendOp,
    UserStr = binary_to_list(User),
    case ToUser =:= UserStr of
        true ->
            %% Redirect to X3DH flow - request full key bundle instead of single prekey
            WSChatState = UIState#ui_state.ws_chat_state,
            case WSChatState#ws_chat_state.ws_client_state of
                {ok, ClientState} ->
                    %% Request key bundle for X3DH protocol
                    KeyBundleCmd = #{
                        type => <<"get_key_bundle">>,
                        user => list_to_binary(ToUser)
                    },
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid, KeyBundleCmd
                        )
                    of
                        ok ->
                            add_system_message(
                                "Requesting X3DH key bundle for " ++ ToUser,
                                UIState
                            );
                        {error, Reason} ->
                            ErrMsg = io_lib:format(
                                "Failed to request key bundle: ~p", [Reason]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message(
                        "WebSocket client not available", UIState
                    )
            end;
        false ->
            %% User mismatch - just acknowledge
            MsgText = io_lib:format(
                "Received prekey for user ~s (not waiting for this user)",
                [UserStr]
            ),
            add_system_message(lists:flatten(MsgText), UIState)
    end.

%% @doc Handle encrypted message received from server.
%%
%% This function decrypts incoming encrypted messages and adds them to the inbox.
handle_encrypted_message_received(Message, UIState) ->
    try
        From = binary_to_list(maps:get(<<"from">>, Message)),

        %% Extract the nested message content
        case maps:get(<<"message">>, Message, undefined) of
            undefined ->
                add_system_message(
                    "Received message without message field", UIState
                );
            NestedMessage ->
                %% Check if this is an X3DH encrypted message
                case maps:get(<<"message_type">>, NestedMessage, undefined) of
                    <<"x3dh">> ->
                        %% Handle X3DH message with correct field names
                        case
                            {
                                maps:get(
                                    <<"ephemeral_public">>,
                                    NestedMessage,
                                    undefined
                                ),
                                maps:get(<<"nonce">>, NestedMessage, undefined),
                                maps:get(
                                    <<"ciphertext">>, NestedMessage, undefined
                                )
                            }
                        of
                            {undefined, _, _} ->
                                add_system_message(
                                    "Received X3DH message missing ephemeral_public",
                                    UIState
                                );
                            {_, undefined, _} ->
                                add_system_message(
                                    "Received X3DH message missing nonce",
                                    UIState
                                );
                            {_, _, undefined} ->
                                add_system_message(
                                    "Received X3DH message missing ciphertext",
                                    UIState
                                );
                            {EphemeralPubB64, NonceB64, CiphertextB64} ->
                                handle_x3dh_message(
                                    From,
                                    NestedMessage,
                                    EphemeralPubB64,
                                    NonceB64,
                                    CiphertextB64,
                                    UIState
                                )
                        end;
                    _ ->
                        %% Check if this is a legacy encrypted message with the old field names
                        case
                            {
                                maps:get(
                                    <<"ephemeral">>, NestedMessage, undefined
                                ),
                                maps:get(<<"nonce">>, NestedMessage, undefined),
                                maps:get(<<"cipher">>, NestedMessage, undefined)
                            }
                        of
                            {undefined, _, _} ->
                                add_system_message(
                                    "Received message missing ephemeral key",
                                    UIState
                                );
                            {_, undefined, _} ->
                                add_system_message(
                                    "Received message missing nonce", UIState
                                );
                            {_, _, undefined} ->
                                add_system_message(
                                    "Received message missing cipher", UIState
                                );
                            {EphemeralB64, NonceB64, CipherB64} ->
                                handle_legacy_encrypted_message(
                                    From,
                                    NestedMessage,
                                    EphemeralB64,
                                    NonceB64,
                                    CipherB64,
                                    UIState
                                )
                        end
                end
        end
    catch
        _:Error ->
            %% Log the actual message structure for debugging
            ProcessErrMsg = io_lib:format(
                "Failed to process encrypted message: ~p. Message was: ~p", [
                    Error, Message
                ]
            ),
            add_system_message(lists:flatten(ProcessErrMsg), UIState)
    end.

%% @doc Handle users list received from server.
%%
%% This function displays the list of available users.
handle_users_list_received(Users, UIState) ->
    case Users of
        [] ->
            add_system_message("No users found", UIState);
        _ ->
            UsersState = add_system_message("Available users:", UIState),
            lists:foldl(
                fun(User, AccState) ->
                    UserStr =
                        case is_binary(User) of
                            true -> binary_to_list(User);
                            false -> User
                        end,
                    add_system_message("  - " ++ UserStr, AccState)
                end,
                UsersState,
                Users
            )
    end.

%% @doc Format timestamp for display.
format_timestamp(Timestamp) ->
    {{Year, Month, Day}, {Hour, Minute, Second}} =
        calendar:gregorian_seconds_to_datetime(Timestamp + 719528 * 24 * 3600),
    io_lib:format(
        "~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w",
        [Year, Month, Day, Hour, Minute, Second]
    ).

%%%===================================================================
%%% Helper Processes
%%%===================================================================

%% @private
%% Input handler process for keyboard input capture.
%%
%% This dedicated process continuously reads keyboard input using cecho
%% and forwards it to the main UI process. It handles:
%% <ul>
%%   <li>Ctrl+C (ASCII 3) - Graceful quit signal</li>
%%   <li>Enter (ASCII 10) - Command execution</li>
%%   <li>Backspace (ASCII 127 or cecho backspace) - Character deletion</li>
%%   <li>Delete key - Forward character deletion</li>
%%   <li>Arrow keys (left/right) - Cursor movement</li>
%%   <li>Arrow keys (up/down) - Command history navigation</li>
%%   <li>Home/End keys - Beginning/end of line navigation</li>
%%   <li>Printable characters (32-126) - Text input</li>
%%   <li>Other keys - Ignored</li>
%% </ul>
%%
%% Enhanced input handling features:
%% - Full cursor movement within the input line
%% - Command history browsing with up/down arrows
%% - Insert and delete operations at any cursor position
%% - Home/End for quick line navigation
%%
%% The process runs in an infinite loop and is linked to the main process
%% for automatic cleanup on exit.
%%
%% @param MainPid PID of the main UI process to send input events to.
input_handler(MainPid) ->
    case cecho:getch() of
        % Ctrl+A - Beginning of line
        1 ->
            MainPid ! {input, {ctrl, ctrl_a}};
        % Ctrl+B - Backward char
        2 ->
            MainPid ! {input, {ctrl, ctrl_b}};
        % Ctrl+C - Quit (existing)
        3 ->
            MainPid ! {input, quit};
        % Ctrl+D - Delete char forward
        4 ->
            MainPid ! {input, {ctrl, ctrl_d}};
        % Ctrl+E - End of line
        5 ->
            MainPid ! {input, {ctrl, ctrl_e}};
        % Ctrl+F - Forward char
        6 ->
            MainPid ! {input, {ctrl, ctrl_f}};
        % Ctrl+K - Kill to end of line
        11 ->
            MainPid ! {input, {ctrl, ctrl_k}};
        % Ctrl+U - Kill whole line
        21 ->
            MainPid ! {input, {ctrl, ctrl_u}};
        % Ctrl+W - Kill word backward
        23 ->
            MainPid ! {input, {ctrl, ctrl_w}};
        % Ctrl+Y - Yank (paste)
        25 ->
            MainPid ! {input, {ctrl, ctrl_y}};
        % Enter
        10 ->
            MainPid ! {input, {key, 10}};
        ?ceKEY_BACKSPACE ->
            MainPid ! {input, {key, ?ceKEY_BACKSPACE}};
        % Sometimes backspace is 127
        127 ->
            MainPid ! {input, {key, ?ceKEY_BACKSPACE}};
        % Delete key
        ?ceKEY_DEL ->
            MainPid ! {input, {key, delete}};
        % Left arrow
        ?ceKEY_LEFT ->
            MainPid ! {input, {key, left}};
        % Right arrow
        ?ceKEY_RIGHT ->
            MainPid ! {input, {key, right}};
        % Up arrow (command history)
        ?ceKEY_UP ->
            MainPid ! {input, {key, up}};
        % Down arrow (command history)
        ?ceKEY_DOWN ->
            MainPid ! {input, {key, down}};
        % Home key
        ?ceKEY_HOME ->
            MainPid ! {input, {key, home}};
        % End key
        ?ceKEY_END ->
            MainPid ! {input, {key, end_key}};
        % Page Up - Scroll up in message history
        ?ceKEY_PGUP ->
            MainPid ! {input, {key, page_up}};
        % Page Down - Scroll down in message history
        ?ceKEY_PGDOWN ->
            MainPid ! {input, {key, page_down}};
        Char when Char >= 32, Char =< 126 ->
            %% Printable character
            MainPid ! {input, {char, Char}};
        _ ->
            %% Ignore other keys
            ok
    end,
    %% Small delay to prevent busy looping
    timer:sleep(50),
    input_handler(MainPid).

%% @private
%% Status updater process for periodic status bar refresh.
%%
%% This process sends status update messages to the main UI process
%% every second to ensure the status bar displays current time and
%% other dynamic information including WebSocket connection status.
%%
%% @param MainPid PID of the main UI process to send update signals to.
status_updater(MainPid) ->
    timer:sleep(1000),
    MainPid ! {status_update},
    status_updater(MainPid).

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @private
%% Initialize color pairs for the terminal display.
%%
%% Sets up color combinations used throughout the interface:
%% <ul>
%%   <li>Status bar: White text on blue background</li>
%%   <li>Help bar: White text on black background</li>
%%   <li>System messages: Yellow text on black background</li>
%%   <li>Other messages: Cyan text on black background</li>
%%   <li>Own messages: Green text on black background</li>
%%   <li>Input line: White text on black background</li>
%% </ul>
%%
%% Colors enhance readability and provide visual organization of
%% different UI elements and message types.
init_colors() ->
    cecho:init_pair(?COLOR_STATUS_BAR, ?ceCOLOR_WHITE, ?ceCOLOR_BLUE),
    cecho:init_pair(?COLOR_HELP_BAR, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_OWN_MESSAGE, ?ceCOLOR_GREEN, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_OTHER_MESSAGE, ?ceCOLOR_CYAN, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_SYSTEM_MESSAGE, ?ceCOLOR_YELLOW, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_TIMESTAMP, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_INPUT, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_SENT_MESSAGE, ?ceCOLOR_MAGENTA, ?ceCOLOR_BLACK).

%% @private
%% Add a user message to the message history.
%%
%% Adds a message from a specific user (not a system message) to the
%% message history with automatic timestamping. User messages are
%% displayed with sender information and are color-coded based on
%% whether they are from the current user or other users.
%%
%% @param From The username of the message sender
%% @param Message The message content text
%% @param UIState Current UI state
%% @returns Updated UI state with the new message added to history.
add_message(From, Message, UIState) ->
    {{_Year, _Month, _Day}, {Hour, Min, Sec}} = calendar:local_time(),
    Timestamp = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),

    NewMessage = {From, Message, lists:flatten(Timestamp)},
    CurrentMessages = UIState#ui_state.message_history,

    UIState#ui_state{
        message_history = CurrentMessages ++ [NewMessage],
        % Reset scroll to show newest messages
        scroll_position = 0
    }.

%% @private
%% Handle room_created response from server.
handle_room_created_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            RoomName = binary_to_list(
                maps:get(<<"name">>, Data, <<"unknown">>)
            ),
            RoomId = binary_to_list(
                maps:get(<<"room_id">>, Data, <<"unknown">>)
            ),
            RoomType = binary_to_list(
                maps:get(<<"room_type">>, Data, <<"unknown">>)
            ),
            SuccessState = add_system_message(
                "[OK] Room '" ++ RoomName ++ "' created successfully!", UIState
            ),
            InfoState = add_system_message(
                "  Room ID: " ++ RoomId, SuccessState
            ),
            TypeState = add_system_message("  Type: " ++ RoomType, InfoState),

            %% Add room to cache for easy joining
            NewCache = (UIState#ui_state.room_cache)#{RoomName => RoomId},
            UpdatedUIState = TypeState#ui_state{room_cache = NewCache},

            add_system_message("  Use: join_room " ++ RoomName, UpdatedUIState);
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),
            add_system_message(
                "[ERROR] Failed to create room: " ++ ErrorMsg, UIState
            )
    end.

%% @private
%% Handle rooms_list response from server.
handle_rooms_list_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            Rooms = maps:get(<<"rooms">>, Data, []),
            Filter = binary_to_list(maps:get(<<"filter">>, Data, <<"all">>)),
            case Rooms of
                [] ->
                    add_system_message(
                        "No " ++ Filter ++ " rooms found.", UIState
                    );
                _ ->
                    HeaderState = add_system_message(
                        "=== " ++ string:to_upper(Filter) ++ " ROOMS ===",
                        UIState
                    ),
                    %% Build room cache and display rooms
                    {FinalState, Cache} = lists:foldl(
                        fun(Room, {AccState, RoomCache}) ->
                            RoomName = binary_to_list(
                                maps:get(<<"name">>, Room, <<"unnamed">>)
                            ),
                            RoomId = binary_to_list(
                                maps:get(<<"id">>, Room, <<"unknown">>)
                            ),
                            RoomType = binary_to_list(
                                maps:get(<<"type">>, Room, <<"public">>)
                            ),
                            MemberCount = maps:get(<<"member_count">>, Room, 0),
                            Owner = maps:get(<<"owner">>, Room, "unknown"),
                            Description = binary_to_list(
                                maps:get(<<"description">>, Room, <<"">>)
                            ),

                            %% Add to room cache
                            NewCache = RoomCache#{RoomName => RoomId},

                            RoomLine = io_lib:format(
                                "- ~s (~s) - ~w members [~s]",
                                [RoomName, RoomType, MemberCount, Owner]
                            ),
                            RoomState = add_system_message(
                                lists:flatten(RoomLine), AccState
                            ),

                            %% Show room ID for joining
                            IdState = add_system_message(
                                "  ID: " ++ RoomId, RoomState
                            ),

                            FinalRoomState =
                                case Description of
                                    "" ->
                                        IdState;
                                    _ ->
                                        add_system_message(
                                            "  " ++ Description, IdState
                                        )
                                end,

                            {FinalRoomState, NewCache}
                        end,
                        {HeaderState, UIState#ui_state.room_cache},
                        Rooms
                    ),
                    %% Update UI state with new room cache
                    FinalState#ui_state{room_cache = Cache}
            end;
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),
            add_system_message(
                "[ERROR] Failed to list rooms: " ++ ErrorMsg, UIState
            )
    end.

%% @private
%% Handle room_joined response from server.
handle_room_joined_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            RoomName = binary_to_list(
                maps:get(<<"room_name">>, Data, <<"unknown">>)
            ),
            RoomId = binary_to_list(
                maps:get(<<"room_id">>, Data, <<"unknown">>)
            ),

            %% Update room cache with the room name → ID mapping
            NewCache = (UIState#ui_state.room_cache)#{RoomName => RoomId},
            UpdatedUIState = UIState#ui_state{room_cache = NewCache},

            SuccessState = add_system_message(
                "[OK] Joined room '" ++ RoomName ++ "'", UpdatedUIState
            ),
            add_system_message("  Room ID: " ++ RoomId, SuccessState);
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),

            %% If we got "room not found" and the original request might have been a room name,
            %% suggest using list_rooms to refresh the cache
            case ErrorMsg of
                "room_not_found" ->
                    ErrorState = add_system_message(
                        "[ERROR] Room not found. Try 'list_rooms' to refresh room list, then retry join.",
                        UIState
                    ),
                    add_system_message(
                        "Tip: Newly created rooms may take a moment to become visible to other users.",
                        ErrorState
                    );
                _ ->
                    add_system_message(
                        "[ERROR] Failed to join room: " ++ ErrorMsg, UIState
                    )
            end
    end.

%% @private
%% Handle room_left response from server.
handle_room_left_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            RoomName = binary_to_list(
                maps:get(<<"room_name">>, Data, <<"unknown">>)
            ),
            add_system_message("[OK] Left room '" ++ RoomName ++ "'", UIState);
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),
            add_system_message(
                "[ERROR] Failed to leave room: " ++ ErrorMsg, UIState
            )
    end.

%% @private
%% Handle room_members response from server.
handle_room_members_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            RoomName = binary_to_list(
                maps:get(<<"room_name">>, Data, <<"unknown">>)
            ),
            Members = maps:get(<<"members">>, Data, []),
            RoomType = binary_to_list(
                maps:get(<<"room_type">>, Data, <<"unknown">>)
            ),
            Owner = maps:get(<<"owner">>, Data, "unknown"),
            Description = binary_to_list(
                maps:get(<<"description">>, Data, <<"">>)
            ),

            HeaderState = add_system_message(
                "=== ROOM INFO: " ++ RoomName ++ " ===", UIState
            ),
            TypeState = add_system_message("Type: " ++ RoomType, HeaderState),
            OwnerState = add_system_message("Owner: " ++ Owner, TypeState),

            DescState =
                case Description of
                    "" ->
                        OwnerState;
                    _ ->
                        add_system_message(
                            "Description: " ++ Description, OwnerState
                        )
                end,

            MemberState = add_system_message(
                "Members (" ++ integer_to_list(length(Members)) ++ "):",
                DescState
            ),
            lists:foldl(
                fun(Member, AccState) ->
                    MemberName = binary_to_list(Member),
                    add_system_message("  - " ++ MemberName, AccState)
                end,
                MemberState,
                Members
            );
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),
            add_system_message(
                "[ERROR] Failed to get room info: " ++ ErrorMsg, UIState
            )
    end.

%% @private
%% Handle room_messages response from server.
handle_room_messages_response(Data, UIState) ->
    ?dbg("Handle Room messages response: ~p", [Data]),
    case maps:get(<<"success">>, Data, false) of
        true ->
            RoomName = binary_to_list(
                maps:get(<<"room_name">>, Data, <<"unknown">>)
            ),
            Messages = maps:get(<<"messages">>, Data, []),
            case Messages of
                [] ->
                    add_system_message(
                        "No messages in room '" ++ RoomName ++ "'", UIState
                    );
                _ ->
                    HeaderState = add_system_message(
                        "=== " ++ RoomName ++ " HISTORY ===", UIState
                    ),
                    lists:foldl(
                        fun(Msg, AccState) ->
                            From = binary_to_list(
                                maps:get(<<"from">>, Msg, <<"unknown">>)
                            ),
                            Content = binary_to_list(
                                maps:get(<<"message">>, Msg, <<"">>)
                            ),
                            Timestamp = maps:get(<<"timestamp">>, Msg, 0),

                            %% Format timestamp (simple conversion)
                            {{_Y, _M, _D}, {H, Min, S}} = calendar:gregorian_seconds_to_datetime(
                                Timestamp
                            ),
                            TimeStr = io_lib:format("~2..0w:~2..0w:~2..0w", [
                                H, Min, S
                            ]),

                            MsgLine = io_lib:format("[~s] ~s: ~s", [
                                TimeStr, From, Content
                            ]),
                            add_system_message(lists:flatten(MsgLine), AccState)
                        end,
                        HeaderState,
                        Messages
                    )
            end;
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Unknown error">>)
            ),
            add_system_message(
                "[ERROR] Failed to get room history: " ++ ErrorMsg, UIState
            )
    end.

%% @private
%% Handle incoming room message.
handle_room_message(Data, UIState) ->
    ?dbg("Handle room message: ~p", [Data]),
    RoomName = binary_to_list(maps:get(<<"room_id">>, Data, <<"unknown">>)),
    From = binary_to_list(maps:get(<<"from">>, Data, <<"unknown">>)),

    %% Check if this is an encrypted room message
    case
        {
            maps:get(<<"ephemeral">>, Data, undefined),
            maps:get(<<"cipher">>, Data, undefined),
            maps:get(<<"nonce">>, Data, undefined)
        }
    of
        {undefined, undefined, undefined} ->
            %% Plain text message (legacy)
            Content = binary_to_list(maps:get(<<"message">>, Data, <<"">>)),
            SenderText = io_lib:format("~s@~s", [From, RoomName]),
            add_message(lists:flatten(SenderText), Content, UIState);
        {_EphemeralB64, CipherB64, _NonceB64} ->
            %% Encrypted room message - decrypt it
            ?dbg("Decrypting room message: cipher=~p", [CipherB64]),
            WSChatState = UIState#ui_state.ws_chat_state,
            ?dbg("WebSocket chat state keypair: ~p~n", [
                WSChatState#ws_chat_state.keypair
            ]),
            case WSChatState#ws_chat_state.keypair of
                undefined ->
                    ErrMsg = "No keypair available for room message decryption",
                    add_system_message(ErrMsg, UIState);
                {_PrivateKey, _PublicKey} ->
                    %% For sender-key encryption, we need the sender's public key to decrypt
                    %% Request sender's public key from server
                    WSChatState = UIState#ui_state.ws_chat_state,
                    case WSChatState#ws_chat_state.ws_client_state of
                        {ok, _ClientState} ->
                            %% Legacy room message format not supported - room messages should use X3DH
                            ErrMsg = io_lib:format(
                                "Room message from ~s uses legacy encryption format. "
                                "Room messages must be migrated to use X3DH protocol.",
                                [From]
                            ),
                            add_system_message(lists:flatten(ErrMsg), UIState);
                        error ->
                            add_system_message(
                                "No WebSocket connection for key retrieval",
                                UIState
                            )
                    end
            end
    end.

%% @private
%% Handle room message sent confirmation.
handle_room_message_sent_response(Data, UIState) ->
    case maps:get(<<"success">>, Data, false) of
        true ->
            MessageId = maps:get(<<"message_id">>, Data, <<"unknown">>),
            RoomId = maps:get(<<"room_id">>, Data, <<"unknown">>),
            ConfirmationMsg = io_lib:format(
                "Message sent to room (ID: ~s, MsgID: ~s)",
                [binary_to_list(RoomId), binary_to_list(MessageId)]
            ),
            add_system_message(lists:flatten(ConfirmationMsg), UIState);
        false ->
            ErrorMsg = binary_to_list(
                maps:get(<<"message">>, Data, <<"Failed to send room message">>)
            ),
            add_system_message(
                "Failed to send room message: " ++ ErrorMsg, UIState
            )
    end.

%%% Room Command Handlers

%% @private
%% Handle create_room command.
%% Format: create_room <name> [description] [public|private] [password]
handle_create_room_command(Rest, UIState) ->
    %% Check if connected
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            Parts = string:tokens(string:strip(Rest), " "),
            case Parts of
                [] ->
                    HelpState = add_system_message(
                        "Usage: create_room <name> [description] [public|private] [password]",
                        UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  create_room general", HelpState2
                    ),
                    HelpState4 = add_system_message(
                        "  create_room team \"Team chat\" private", HelpState3
                    ),
                    add_system_message(
                        "  create_room secure \"Private room\" private mypassword",
                        HelpState4
                    );
                [Name | OptionalParts] ->
                    {Description, RoomType, Password} = parse_create_room_options(
                        OptionalParts
                    ),

                    %% Create room command
                    Command = #{
                        <<"type">> => <<"create_room">>,
                        <<"name">> => list_to_binary(Name),
                        <<"description">> => list_to_binary(Description),
                        <<"room_type">> => list_to_binary(RoomType)
                    },

                    %% Add password if provided
                    FinalCommand =
                        case Password of
                            "" ->
                                Command;
                            _ ->
                                Command#{
                                    <<"password">> => list_to_binary(Password)
                                }
                        end,

                    %% Send WebSocket message
                    {ok, ClientState} =
                        WSChatState#ws_chat_state.ws_client_state,
                    cryptic_ws_client:send_command(
                        ClientState#client_state.ws_client_pid, FinalCommand
                    ),

                    add_system_message(
                        "Creating room '" ++ Name ++ "'...", UIState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to create rooms. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle join_room command.
%% Format: join_room <room_name_or_id> [password]
handle_join_room_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            Parts = string:tokens(string:strip(Rest), " "),
            case Parts of
                [] ->
                    HelpState = add_system_message(
                        "Usage: join_room <room_name_or_id> [password]", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  join_room general", HelpState2
                    ),
                    add_system_message(
                        "  join_room room-abc123 mypassword", HelpState3
                    );
                [RoomNameOrId | PasswordParts] ->
                    Password =
                        case PasswordParts of
                            [] -> "";
                            [P] -> P;
                            _ -> string:join(PasswordParts, " ")
                        end,

                    %% Resolve room name to ID if needed
                    RoomCache = UIState#ui_state.room_cache,
                    ActualRoomId =
                        case maps:get(RoomNameOrId, RoomCache, undefined) of
                            undefined ->
                                %% Not found in cache, assume it's already a room ID
                                RoomNameOrId;
                            CachedId ->
                                %% Found in cache, use the cached ID
                                CachedId
                        end,

                    Command = #{
                        <<"type">> => <<"join_room">>,
                        <<"room_id">> => list_to_binary(ActualRoomId)
                    },

                    FinalCommand =
                        case Password of
                            "" ->
                                Command;
                            _ ->
                                Command#{
                                    <<"password">> => list_to_binary(Password)
                                }
                        end,

                    {ok, ClientState} =
                        WSChatState#ws_chat_state.ws_client_state,

                    cryptic_ws_client:send_command(
                        ClientState#client_state.ws_client_pid, FinalCommand
                    ),

                    add_system_message(
                        "Joining room '" ++ RoomNameOrId ++ "'...", UIState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to join rooms. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle leave_room command.
%% Format: leave_room <room_name_or_id>
handle_leave_room_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            RoomId = string:strip(Rest),
            case RoomId of
                "" ->
                    HelpState = add_system_message(
                        "Usage: leave_room <room_name_or_id>", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    add_system_message("  leave_room general", HelpState2);
                _ ->
                    Command = #{
                        <<"type">> => <<"leave_room">>,
                        <<"room_id">> => list_to_binary(RoomId)
                    },

                    {ok, ClientState} =
                        WSChatState#ws_chat_state.ws_client_state,

                    cryptic_ws_client:send_command(
                        ClientState#client_state.ws_client_pid, Command
                    ),

                    add_system_message(
                        "Leaving room '" ++ RoomId ++ "'...", UIState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to leave rooms. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle list_rooms command.
%% Format: list_rooms [public|private|joined|all]
handle_list_rooms_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            Filter =
                case string:strip(Rest) of
                    "" -> "public";
                    F -> F
                end,

            case Filter of
                "public" ->
                    ok;
                "private" ->
                    ok;
                "joined" ->
                    ok;
                "all" ->
                    ok;
                _ ->
                    HelpState = add_system_message(
                        "Usage: list_rooms [public|private|joined|all]", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  list_rooms          (shows public rooms)", HelpState2
                    ),
                    HelpState4 = add_system_message(
                        "  list_rooms joined   (shows your rooms)", HelpState3
                    ),
                    add_system_message(
                        "  list_rooms all      (shows all visible rooms)",
                        HelpState4
                    )
            end,

            Command = #{
                <<"type">> => <<"list_rooms">>,
                <<"filter">> => list_to_binary(Filter)
            },

            {ok, ClientState} = WSChatState#ws_chat_state.ws_client_state,

            cryptic_ws_client:send_command(
                ClientState#client_state.ws_client_pid, Command
            ),

            add_system_message("Listing " ++ Filter ++ " rooms...", UIState);
        _ ->
            add_system_message(
                "Must be connected to list rooms. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle room_info command.
%% Format: room_info <room_name_or_id>
handle_room_info_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            RoomId = string:strip(Rest),
            case RoomId of
                "" ->
                    HelpState = add_system_message(
                        "Usage: room_info <room_name_or_id>", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    add_system_message("  room_info general", HelpState2);
                _ ->
                    %% Resolve room name to ID if needed
                    RoomCache = UIState#ui_state.room_cache,
                    ActualRoomId =
                        case maps:get(RoomId, RoomCache, undefined) of
                            undefined ->
                                %% Not found in cache, assume it's already a room ID
                                RoomId;
                            CachedId ->
                                %% Found in cache, use the cached ID
                                CachedId
                        end,

                    Command = #{
                        <<"type">> => <<"get_room_members">>,
                        <<"room_id">> => list_to_binary(ActualRoomId)
                    },

                    {ok, ClientState} =
                        WSChatState#ws_chat_state.ws_client_state,

                    cryptic_ws_client:send_command(
                        ClientState#client_state.ws_client_pid, Command
                    ),

                    add_system_message(
                        "Getting info for room '" ++ RoomId ++ "'...", UIState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to get room info. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle room_chat command.
%% Format: room_chat <room_name_or_id>
handle_room_chat_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            RoomId = string:strip(Rest),
            case RoomId of
                "" ->
                    HelpState = add_system_message(
                        "Usage: room_chat <room_name_or_id>", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  room_chat general", HelpState2
                    ),
                    HelpState4 = add_system_message(
                        "Once in room chat mode:", HelpState3
                    ),
                    HelpState5 = add_system_message(
                        "  - Type messages directly to send to room", HelpState4
                    ),
                    HelpState6 = add_system_message(
                        "  - Type :exit to leave room chat mode", HelpState5
                    ),
                    add_system_message(
                        "  - Type :help for room chat commands", HelpState6
                    );
                _ ->
                    %% Enter room chat mode
                    ChatModeState = UIState#ui_state{
                        chat_mode = true,
                        chat_target = RoomId
                    },
                    add_system_message(
                        "Entering room chat mode with '" ++ RoomId ++
                            "' (type :exit to leave)",
                        ChatModeState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to enter room chat. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle send_room command.
%% Format: send_room <room_name_or_id> <message>
handle_send_room_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            case string:tokens(Rest, " ") of
                [] ->
                    HelpState = add_system_message(
                        "Usage: send_room <room_name_or_id> <message>", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  send_room general Hello everyone!", HelpState2
                    ),
                    add_system_message(
                        "  send_room team-chat \"Meeting at 3pm\"", HelpState3
                    );
                [RoomId | MessageParts] ->
                    Message = string:join(MessageParts, " "),
                    case Message of
                        "" ->
                            add_system_message(
                                "Please provide a message to send", UIState
                            );
                        _ ->
                            %% Resolve room name to ID if needed
                            RoomCache = UIState#ui_state.room_cache,
                            ActualRoomId =
                                case maps:get(RoomId, RoomCache, undefined) of
                                    undefined ->
                                        %% Not found in cache, assume it's already a room ID
                                        RoomId;
                                    CachedId ->
                                        %% Found in cache, use the cached ID
                                        CachedId
                                end,

                            {ok, ClientState} =
                                WSChatState#ws_chat_state.ws_client_state,

                            %% Send encrypted room message (proper E2EE implementation)
                            case
                                send_encrypted_room_message(
                                    ClientState, ActualRoomId, Message
                                )
                            of
                                ok ->
                                    %% Show message in UI on success
                                    SenderText = io_lib:format(
                                        "You -> room#~s", [
                                            RoomId
                                        ]
                                    ),
                                    add_message(
                                        lists:flatten(SenderText),
                                        Message,
                                        UIState
                                    );
                                {error, Reason} ->
                                    ErrorMsg = io_lib:format(
                                        "Failed to send room message: ~p", [
                                            Reason
                                        ]
                                    ),
                                    add_system_message(
                                        lists:flatten(ErrorMsg), UIState
                                    )
                            end
                    end
            end;
        _ ->
            add_system_message(
                "Must be connected to send room messages. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Handle room_history command.
%% Format: room_history <room_name_or_id> [count]
handle_room_history_command(Rest, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            Parts = string:tokens(string:strip(Rest), " "),
            case Parts of
                [] ->
                    HelpState = add_system_message(
                        "Usage: room_history <room_name_or_id> [count]", UIState
                    ),
                    HelpState2 = add_system_message("Examples:", HelpState),
                    HelpState3 = add_system_message(
                        "  room_history general", HelpState2
                    ),
                    add_system_message(
                        "  room_history team-chat 20", HelpState3
                    );
                [RoomId | CountParts] ->
                    %% Resolve room name to ID if needed
                    RoomCache = UIState#ui_state.room_cache,
                    ActualRoomId =
                        case maps:get(RoomId, RoomCache, undefined) of
                            undefined ->
                                %% Not found in cache, assume it's already a room ID
                                RoomId;
                            CachedId ->
                                %% Found in cache, use the cached ID
                                CachedId
                        end,

                    Since =
                        case CountParts of
                            [] ->
                                0;
                            [CountStr] ->
                                try list_to_integer(CountStr) of
                                    N when N > 0 ->
                                        %% Convert count to "since" timestamp (approximate)
                                        Now = calendar:datetime_to_gregorian_seconds(
                                            calendar:local_time()
                                        ),
                                        % Assume 1 hour per message count
                                        Now - (N * 3600);
                                    _ ->
                                        0
                                catch
                                    _:_ -> 0
                                end
                        end,

                    Command = #{
                        <<"type">> => <<"get_room_messages">>,
                        <<"room_id">> => list_to_binary(ActualRoomId),
                        <<"since">> => Since
                    },

                    {ok, ClientState} =
                        WSChatState#ws_chat_state.ws_client_state,

                    cryptic_ws_client:send_command(
                        ClientState#client_state.ws_client_pid, Command
                    ),

                    add_system_message(
                        "Getting history for room '" ++ RoomId ++ "'...",
                        UIState
                    )
            end;
        _ ->
            add_system_message(
                "Must be connected to get room history. Type 'connect' first.",
                UIState
            )
    end.

%% @private
%% Parse optional arguments for create_room command.
parse_create_room_options(Parts) ->
    parse_create_room_options(Parts, "", "public", "").

parse_create_room_options([], Description, RoomType, Password) ->
    {Description, RoomType, Password};
parse_create_room_options([Part | Rest], Description, RoomType, Password) ->
    case Part of
        "public" ->
            parse_create_room_options(Rest, Description, "public", Password);
        "private" ->
            parse_create_room_options(Rest, Description, "private", Password);
        _ ->
            %% If we don't have a description yet, this is the description
            %% Otherwise, it's part of the password
            case Description of
                "" ->
                    parse_create_room_options(Rest, Part, RoomType, Password);
                _ ->
                    %% This and remaining parts form the password
                    NewPassword =
                        case Password of
                            "" -> Part;
                            _ -> Password ++ " " ++ Part
                        end,
                    parse_create_room_options(
                        Rest, Description, RoomType, NewPassword
                    )
            end
    end.

foldf(InitAcc, FunList) ->
    lists:foldl(fun(Fun, Acc) -> Fun(Acc) end, InitAcc, FunList).

%% @private
%% Handle help command with comprehensive command documentation.
%% Format: help [command_name] or help [category]
handle_help_command(Rest, UIState) ->
    HelpTopic = string:strip(Rest),
    case HelpTopic of
        "" ->
            foldf(
                UIState,
                [
                    %% General help overview
                    add_sys_msg_f("=== CRYPTIC CHAT CLIENT HELP ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f(
                        "Type 'help <command>' for detailed command help"
                    ),
                    add_sys_msg_f(
                        "Type 'help <category>' for category help"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("COMMAND CATEGORIES:"),
                    add_sys_msg_f(
                        "  connection  - Server connection commands"
                    ),
                    add_sys_msg_f(
                        "  messaging   - Direct messaging commands"
                    ),
                    add_sys_msg_f("  rooms       - Chat room commands"),
                    add_sys_msg_f(
                        "  utilities   - Utility and info commands"
                    ),
                    add_sys_msg_f(
                        "  editing     - Emacs-style line editing keys"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("QUICK REFERENCE:"),
                    add_sys_msg_f(
                        "  connect                    - Connect to server"
                    ),
                    add_sys_msg_f(
                        "  send <user> <message>      - Send direct message"
                    ),
                    add_sys_msg_f(
                        "  create_room <name>         - Create new room"
                    ),
                    add_sys_msg_f(
                        "  join_room <room>           - Join existing room"
                    ),
                    add_sys_msg_f(
                        "  room_chat <room>           - Enter room chat mode"
                    ),
                    add_sys_msg_f(
                        "  list_rooms                 - List available rooms"
                    ),
                    add_sys_msg_f(
                        "  list_users                 - List online users"
                    ),
                    add_sys_msg_f(
                        "  help <topic>               - Get detailed help"
                    )
                ]
            );
        "connection" ->
            %% Connection commands help
            foldf(
                UIState,
                [
                    add_sys_msg_f("=== CONNECTION COMMANDS ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f("connect"),
                    add_sys_msg_f(
                        "  Purpose: Connect to the Cryptic chat server"
                    ),
                    add_sys_msg_f("  Usage:   connect"),
                    add_sys_msg_f("  Example: connect"),
                    add_sys_msg_f(
                        "  Note:    Uses mTLS authentication with client certificates"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("disconnect"),
                    add_sys_msg_f("  Purpose: Disconnect from the chat server"),
                    add_sys_msg_f("  Usage:   disconnect"),
                    add_sys_msg_f("  Example: disconnect"),
                    add_sys_msg_f(
                        "  Note:    Cleanly closes connection and exits chat modes"
                    )
                ]
            );
        "messaging" ->
            %% Direct messaging help
            foldf(
                UIState,
                [
                    add_sys_msg_f("=== DIRECT MESSAGING COMMANDS ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f("send <user> <message>"),
                    add_sys_msg_f(
                        "  Purpose: Send a direct message to another user"
                    ),
                    add_sys_msg_f("  Usage:   send <username> <message_text>"),
                    add_sys_msg_f("  Example: send alice Hello, how are you?"),
                    add_sys_msg_f(
                        "  Example: send bob \"Message with spaces\""
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("chat <user>"),
                    add_sys_msg_f(
                        "  Purpose: Enter direct chat mode with a user"
                    ),
                    add_sys_msg_f("  Usage:   chat <username>"),
                    add_sys_msg_f("  Example: chat alice"),
                    add_sys_msg_f(
                        "  Note:    In chat mode, type messages directly"
                    ),
                    add_sys_msg_f("           Type :exit to leave chat mode"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("inbox [count]"),
                    add_sys_msg_f("  Purpose: View recent direct messages"),
                    add_sys_msg_f("  Usage:   inbox [number_of_messages]"),
                    add_sys_msg_f("  Example: inbox"),
                    add_sys_msg_f("  Example: inbox 20"),
                    add_sys_msg_f("  Note:    Default count is 10 messages")
                ]
            );
        "rooms" ->
            %% Room commands help
            foldf(
                UIState,
                [
                    add_sys_msg_f("=== CHAT ROOM COMMANDS ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f(
                        "create_room <name> [description] [public|private] [password]"
                    ),
                    add_sys_msg_f("  Purpose: Create a new chat room"),
                    add_sys_msg_f(
                        "  Usage:   create_room <room_name> [description] [type] [password]"
                    ),
                    add_sys_msg_f("  Example: create_room general"),
                    add_sys_msg_f(
                        "  Example: create_room team \"Team discussions\" private"
                    ),
                    add_sys_msg_f(
                        "  Example: create_room secure \"Secret room\" private mypass123"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("join_room <room> [password]"),
                    add_sys_msg_f("  Purpose: Join an existing room"),
                    add_sys_msg_f(
                        "  Usage:   join_room <room_name_or_id> [password]"
                    ),
                    add_sys_msg_f("  Example: join_room general"),
                    add_sys_msg_f(
                        "  Example: join_room room-abc123 mypassword"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("leave_room <room>"),
                    add_sys_msg_f("  Purpose: Leave a joined room"),
                    add_sys_msg_f("  Usage:   leave_room <room_name_or_id>"),
                    add_sys_msg_f("  Example: leave_room general"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("list_rooms [filter]"),
                    add_sys_msg_f("  Purpose: List available rooms"),
                    add_sys_msg_f(
                        "  Usage:   list_rooms [public|private|joined|all]"
                    ),
                    add_sys_msg_f("  Example: list_rooms"),
                    add_sys_msg_f("  Example: list_rooms joined"),
                    add_sys_msg_f("  Note:    Default filter is 'public'"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("room_info <room>"),
                    add_sys_msg_f("  Purpose: Get detailed room information"),
                    add_sys_msg_f("  Usage:   room_info <room_name_or_id>"),
                    add_sys_msg_f("  Example: room_info general"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("room_chat <room>"),
                    add_sys_msg_f("  Purpose: Enter room chat mode"),
                    add_sys_msg_f("  Usage:   room_chat <room_name_or_id>"),
                    add_sys_msg_f("  Example: room_chat general"),
                    add_sys_msg_f(
                        "  Note:    Type messages directly, :exit to leave"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("send_room <room> <message>"),
                    add_sys_msg_f("  Purpose: Send a message to a room"),
                    add_sys_msg_f(
                        "  Usage:   send_room <room_name_or_id> <message>"
                    ),
                    add_sys_msg_f(
                        "  Example: send_room general Hello everyone!"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("room_history <room> [count]"),
                    add_sys_msg_f("  Purpose: View room message history"),
                    add_sys_msg_f(
                        "  Usage:   room_history <room_name_or_id> [message_count]"
                    ),
                    add_sys_msg_f("  Example: room_history general"),
                    add_sys_msg_f("  Example: room_history team-chat 20")
                ]
            );
        "utilities" ->
            %% Utility commands help
            foldf(
                UIState,
                [
                    add_sys_msg_f("=== UTILITY COMMANDS ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f("list_users"),
                    add_sys_msg_f("  Purpose: List all online users"),
                    add_sys_msg_f("  Usage:   list_users"),
                    add_sys_msg_f("  Example: list_users"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("key_status"),
                    add_sys_msg_f("  Purpose: Display encryption key status"),
                    add_sys_msg_f("  Usage:   key_status"),
                    add_sys_msg_f("  Example: key_status"),
                    add_sys_msg_f(
                        "  Note:    Shows identity keys, prekeys, and OTPK count"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("fetch_messages"),
                    add_sys_msg_f(
                        "  Purpose: Manually fetch pending messages from server"
                    ),
                    add_sys_msg_f("  Usage:   fetch_messages"),
                    add_sys_msg_f("  Example: fetch_messages"),
                    add_sys_msg_f(
                        "  Note:    Messages are automatically fetched on connect"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("auto_display [on|off]"),
                    add_sys_msg_f(
                        "  Purpose: Toggle automatic message display"
                    ),
                    add_sys_msg_f("  Usage:   auto_display [on|off]"),
                    add_sys_msg_f("  Example: auto_display on"),
                    add_sys_msg_f("  Example: auto_display off"),
                    add_sys_msg_f(
                        "  Note:    Controls real-time message display"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("help [topic]"),
                    add_sys_msg_f("  Purpose: Display help information"),
                    add_sys_msg_f("  Usage:   help [command_name|category]"),
                    add_sys_msg_f("  Example: help"),
                    add_sys_msg_f("  Example: help send"),
                    add_sys_msg_f("  Example: help rooms")
                ]
            );
        "editing" ->
            %% Emacs-style editing commands help
            foldf(
                UIState,
                [
                    add_sys_msg_f("=== EMACS-STYLE EDITING KEYS ==="),
                    add_sys_msg_f(""),
                    add_sys_msg_f("CURSOR MOVEMENT:"),
                    add_sys_msg_f("  Ctrl+A  - Move to beginning of line"),
                    add_sys_msg_f("  Ctrl+E  - Move to end of line"),
                    add_sys_msg_f("  Ctrl+B  - Move backward one character"),
                    add_sys_msg_f("  Ctrl+F  - Move forward one character"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("EDITING OPERATIONS:"),
                    add_sys_msg_f("  Ctrl+D  - Delete character at cursor"),
                    add_sys_msg_f(
                        "  Ctrl+K  - Kill from cursor to end of line"
                    ),
                    add_sys_msg_f("  Ctrl+U  - Kill entire line"),
                    add_sys_msg_f("  Ctrl+W  - Kill word backward"),
                    add_sys_msg_f("  Ctrl+Y  - Yank (paste) from kill ring"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("TRADITIONAL KEYS (still work):"),
                    add_sys_msg_f("  Home    - Move to beginning of line"),
                    add_sys_msg_f("  End     - Move to end of line"),
                    add_sys_msg_f("  Left    - Move backward one character"),
                    add_sys_msg_f("  Right   - Move forward one character"),
                    add_sys_msg_f("  Delete  - Delete character at cursor"),
                    add_sys_msg_f("  Up/Down - Navigate command history"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("MESSAGE SCROLLING:"),
                    add_sys_msg_f(
                        "  Page Up   - Scroll up through message history"
                    ),
                    add_sys_msg_f(
                        "  Page Down - Scroll down through message history"
                    ),
                    add_sys_msg_f("")
                ]
            );
        %% Individual command help
        "connect" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: connect"),
                    add_sys_msg_f(
                        "  Purpose: Connect to the Cryptic chat server using mTLS"
                    ),
                    add_sys_msg_f("  Usage:   connect"),
                    add_sys_msg_f("  Example: connect"),
                    add_sys_msg_f(
                        "  Details: Uses client certificates for authentication"
                    ),
                    add_sys_msg_f(
                        "  Note:    Must be connected before using other commands"
                    )
                ]
            );
        "disconnect" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: disconnect"),
                    add_sys_msg_f("  Purpose: Disconnect from the chat server"),
                    add_sys_msg_f("  Usage:   disconnect"),
                    add_sys_msg_f("  Example: disconnect"),
                    add_sys_msg_f(
                        "  Note:    Automatically exits any active chat modes"
                    )
                ]
            );
        "send" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: send"),
                    add_sys_msg_f(
                        "  Purpose: Send a direct message to another user"
                    ),
                    add_sys_msg_f("  Usage:   send <username> <message>"),
                    add_sys_msg_f("  Examples:"),
                    add_sys_msg_f("    send alice Hello there!"),
                    add_sys_msg_f("    send bob \"Message with spaces\""),
                    add_sys_msg_f("    send charlie How's the project going?"),
                    add_sys_msg_f(
                        "  Note:    Use quotes for messages with multiple words"
                    )
                ]
            );
        "chat" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: chat"),
                    add_sys_msg_f(
                        "  Purpose: Enter direct chat mode with a specific user"
                    ),
                    add_sys_msg_f("  Usage:   chat <username>"),
                    add_sys_msg_f("  Example: chat alice"),
                    add_sys_msg_f("  In chat mode:"),
                    add_sys_msg_f("    - Type messages directly to send"),
                    add_sys_msg_f("    - Type :exit to leave chat mode"),
                    add_sys_msg_f("    - Type :help for chat mode commands")
                ]
            );
        "create_room" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: create_room"),
                    add_sys_msg_f("  Purpose: Create a new chat room"),
                    add_sys_msg_f(
                        "  Usage:   create_room <name> [description] [public|private] [password]"
                    ),
                    add_sys_msg_f("  Examples:"),
                    add_sys_msg_f("    create_room general"),
                    add_sys_msg_f("    create_room team \"Team discussions\""),
                    add_sys_msg_f(
                        "    create_room project \"Project chat\" private"
                    ),
                    add_sys_msg_f(
                        "    create_room secure \"Secret room\" private mypass123"
                    ),
                    add_sys_msg_f("  Parameters:"),
                    add_sys_msg_f("    name        - Room name (required)"),
                    add_sys_msg_f(
                        "    description - Room description (optional)"
                    ),
                    add_sys_msg_f(
                        "    type        - 'public' or 'private' (default: public)"
                    ),
                    add_sys_msg_f(
                        "    password    - Room password for private rooms (optional)"
                    )
                ]
            );
        "join_room" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: join_room"),
                    add_sys_msg_f("  Purpose: Join an existing chat room"),
                    add_sys_msg_f(
                        "  Usage:   join_room <room_name_or_id> [password]"
                    ),
                    add_sys_msg_f("  Examples:"),
                    add_sys_msg_f("    join_room general"),
                    add_sys_msg_f("    join_room work"),
                    add_sys_msg_f("    join_room private-room mypassword"),
                    add_sys_msg_f(
                        "  Note:    Can use room name or ID; password required for private rooms"
                    )
                ]
            );
        "key_status" ->
            foldf(
                UIState,
                [
                    add_sys_msg_f("COMMAND: key_status"),
                    add_sys_msg_f(
                        "  Purpose: Display encryption key status information"
                    ),
                    add_sys_msg_f("  Usage:   key_status"),
                    add_sys_msg_f("  Example: key_status"),
                    add_sys_msg_f("  Details:"),
                    add_sys_msg_f("    - Shows if identity keys are present"),
                    add_sys_msg_f(
                        "    - Displays signed prekey status and timestamp"
                    ),
                    add_sys_msg_f(
                        "    - Reports number of available one-time prekeys"
                    ),
                    add_sys_msg_f("    - Shows key bundle creation timestamp"),
                    add_sys_msg_f(
                        "    - Provides warnings for missing or low keys"
                    ),
                    add_sys_msg_f(
                        "  Note:    Helps verify encryption readiness"
                    )
                ]
            );
        _ ->
            %% Unknown help topic
            foldf(
                UIState,
                [
                    add_sys_msg_f("Unknown help topic: '" ++ HelpTopic ++ "'"),
                    add_sys_msg_f(""),
                    add_sys_msg_f("Available help topics:"),
                    add_sys_msg_f(
                        "  Categories: connection, messaging, rooms, utilities, editing"
                    ),
                    add_sys_msg_f(
                        "  Commands: connect, disconnect, send, chat, inbox"
                    ),
                    add_sys_msg_f(
                        "            create_room, join_room, leave_room, list_rooms"
                    ),
                    add_sys_msg_f(
                        "            room_info, room_chat, send_room, room_history"
                    ),
                    add_sys_msg_f(
                        "            list_users, key_status, auto_display, help"
                    ),
                    add_sys_msg_f(""),
                    add_sys_msg_f("Type 'help' for general overview")
                ]
            )
    end.

%% @private
%% Send an encrypted room message following proper E2EE architecture.
%%
%% This function implements the efficient sender-key encryption flow for room messages:
%% 1. Encrypts the message with sender's private key
%% 2. Sends one encrypted message to the room
%% 3. Server broadcasts to all room members
%% 4. Recipients decrypt with sender's public key
%%
%% This is much more efficient than individual encryption per member (O(1) vs O(N)).
%% The server never sees the plaintext message, only the encrypted version.
%%
%% @param ClientState The WebSocket client state
%% @param RoomId The room identifier
%% @param Message The plaintext message to encrypt and send
%% @returns ok on success, {error, Reason} on failure
send_encrypted_room_message(ClientState, RoomId, Message) ->
    try
        ?dbg("Encrypting room message for room ~s using sender-key approach", [
            RoomId
        ]),

        %% Step 1: Encrypt message with sender's private key
        case encrypt_with_sender_key(ClientState, Message) of
            {ok, EncryptedData} ->
                ?dbg("Successfully encrypted message with sender key", []),

                %% Step 2: Send single encrypted message to room
                Command = #{
                    <<"type">> => <<"send_encrypted_room_message">>,
                    <<"room_id">> => list_to_binary(RoomId),
                    <<"ephemeral">> => maps:get(<<"ephemeral">>, EncryptedData),
                    <<"nonce">> => maps:get(<<"nonce">>, EncryptedData),
                    <<"cipher">> => maps:get(<<"cipher">>, EncryptedData)
                },

                ?dbg("Sending encrypted room message command: ~p", [Command]),
                ?msg_out("UI sending encrypted room message: ~p", [Command]),
                cryptic_ws_client:send_command(
                    ClientState#client_state.ws_client_pid, Command
                ),
                ok;
            {error, EncryptError} ->
                ?dbg("Failed to encrypt message with sender key: ~p", [
                    EncryptError
                ]),
                {error, {sender_encryption_failed, EncryptError}}
        end
    catch
        error:Reason ->
            ?dbg("Exception in send_encrypted_room_message: ~p", [Reason]),
            {error, {exception, Reason}}
    end.

%% @private
%% Encrypt message with sender's private key for room broadcasting.
%%
%% This implements the efficient sender-key encryption approach where:
%% 1. Sender encrypts message with their private key
%% 2. Recipients decrypt with sender's public key
%% 3. Only one encrypted message needs to be sent/stored
%%
%% @param ClientState The WebSocket client state
%% @param Message The plaintext message to encrypt
%% @returns {ok, EncryptedData} on success, {error, Reason} on failure
encrypt_with_sender_key(ClientState, Message) ->
    try
        ?dbg("Encrypting message with sender's private key", []),

        %% Get our private key for signing/encryption
        case get_our_private_key(ClientState) of
            {ok, OurPrivKey} ->
                %% Generate ephemeral keypair for this message
                {EphPub, _EphPriv} = cryptic_lib:gen_keypair(),

                %% Use our private key with ephemeral public key to create shared secret
                Shared = cryptic_lib:scalarmult(OurPrivKey, EphPub),

                %% Derive AEAD key using ephemeral-based salt
                AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, EphPub),

                %% Encrypt the message
                %% Encrypt the message
                {Cipher, Nonce} = cryptic_lib:aead_encrypt(
                    list_to_binary(Message), AeadKey, <<>>
                ),
                %% Package encrypted data
                EncryptedData = #{
                    <<"ephemeral">> => base64:encode(EphPub),
                    <<"nonce">> => base64:encode(Nonce),
                    <<"cipher">> => base64:encode(Cipher)
                },
                {ok, EncryptedData};
            {error, PrivKeyError} ->
                {error, {private_key_failed, PrivKeyError}}
        end
    catch
        error:Reason ->
            {error, {exception, Reason}}
    end.

%% @private
%% Get our private key for encryption.
get_our_private_key(ClientState) ->
    %% Extract private key from client state keypair
    case ClientState#client_state.keypair of
        {_PubKey, PrivKey} ->
            ?dbg("Retrieved private key from client state", []),
            {ok, PrivKey};
        undefined ->
            ?dbg("No keypair available in client state", []),
            {error, no_keypair_available}
    end.

%% @private
%% Complete the client key loading and connection process.
%%
%% Implements steps 2-5 of the authentication flow:
%% Step 2: Load/generate encrypted keys
%% Step 3: Establish WebSocket mTLS connection
%% Step 4: Upload identity keys to server
%% Step 5: Send prekey bundle per SESSION-MESSAGE-FLOW.md protocol
%%
%% @param UIState Current UI state
%% @param ConfigDir Configuration directory path
%% @param Passphrase User-provided passphrase for key decryption
%% @returns Updated UI state with connection results
load_client_keys_and_connect(UIState, ConfigDir, Passphrase) ->
    WSChatState = UIState#ui_state.ws_chat_state,

    %% Step 2: Load/generate encrypted keys
    case cryptic_lib:initialize_client_keys(ConfigDir, Passphrase) of
        {ok, ClientKeys} ->
            KeysState = add_system_message(
                "Keys loaded successfully", UIState
            ),

            %% Update status to connecting
            NewWSChatState = WSChatState#ws_chat_state{
                connection_status = connecting,
                client_keys = ClientKeys,
                keypair = {
                    maps:get(identity_dh_private, ClientKeys),
                    maps:get(identity_dh_public, ClientKeys)
                }
            },
            ConnectingUIState = KeysState#ui_state{
                ws_chat_state = NewWSChatState
            },
            ConnectingState = add_system_message(
                "Establishing WebSocket mTLS connection...", ConnectingUIState
            ),

            %% Step 3: Establish WebSocket mTLS connection
            Username = WSChatState#ws_chat_state.username,
            ServerHost = WSChatState#ws_chat_state.server_host,
            CertConfig = WSChatState#ws_chat_state.cert_config,

            case
                cryptic_ws_client:start_link(Username, ServerHost, CertConfig)
            of
                {ok, ClientPid} ->
                    %% Create client state record
                    ClientState = #client_state{
                        ws_client_pid = ClientPid,
                        username = Username,
                        keypair = {
                            maps:get(identity_dh_private, ClientKeys),
                            maps:get(identity_dh_public, ClientKeys)
                        }
                    },

                    %% Set UI PID for message forwarding
                    cryptic_ws_client:set_ui_pid(ClientPid, self()),

                    %% Step 4: Upload identity keys to server
                    %% Use identity_sign_public for signature verification (Ed25519)
                    IdentitySignPublicKey = maps:get(
                        identity_sign_public, ClientKeys
                    ),
                    IdentityDHPublicKey = maps:get(
                        identity_dh_public, ClientKeys
                    ),
                    SignedPrekeyPublic = maps:get(
                        signed_prekey_public, ClientKeys
                    ),
                    SignedPrekeySignature = maps:get(
                        signed_prekey_signature, ClientKeys
                    ),

                    UploadKeysCmd = #{
                        type => <<"upload_identity_keys">>,
                        identity_sign_public => base64:encode(
                            IdentitySignPublicKey
                        ),
                        identity_dh_public => base64:encode(
                            IdentityDHPublicKey
                        ),
                        signed_prekey_public => base64:encode(
                            SignedPrekeyPublic
                        ),
                        signed_prekey_signature => base64:encode(
                            SignedPrekeySignature
                        )
                    },
                    ?msg_out("UI uploading identity keys: ~p", [UploadKeysCmd]),
                    case
                        cryptic_ws_client:send_command(ClientPid, UploadKeysCmd)
                    of
                        ok ->
                            %% Step 5: Send prekey bundle per SESSION-MESSAGE-FLOW.md
                            upload_prekey_bundle_and_finalize(
                                ConnectingState,
                                ClientPid,
                                ClientState,
                                NewWSChatState,
                                ClientKeys
                            );
                        queued ->
                            %% Identity upload queued, continue with prekey bundle
                            upload_prekey_bundle_and_finalize(
                                ConnectingState,
                                ClientPid,
                                ClientState,
                                NewWSChatState,
                                ClientKeys
                            );
                        {error, UploadReason} ->
                            ErrMsg = io_lib:format(
                                "Failed to upload identity keys: ~p", [
                                    UploadReason
                                ]
                            ),
                            add_system_message(
                                lists:flatten(ErrMsg), ConnectingState
                            )
                    end;
                {error, ConnectionReason} ->
                    %% Connection failed
                    FailWSChatState = NewWSChatState#ws_chat_state{
                        connection_status = disconnected
                    },
                    FailUIState = ConnectingState#ui_state{
                        ws_chat_state = FailWSChatState
                    },
                    ErrMsg = io_lib:format("WebSocket connection failed: ~p", [
                        ConnectionReason
                    ]),
                    add_system_message(lists:flatten(ErrMsg), FailUIState)
            end;
        {error, KeyReason} ->
            ErrMsg = io_lib:format("ERROR: Key initialization failed: ~p", [
                KeyReason
            ]),
            add_system_message(lists:flatten(ErrMsg), UIState)
    end.

%% @private
%% Upload prekey bundle and finalize connection.
%%
%% Implements Step 5 of the authentication flow by uploading the complete
%% prekey bundle (one-time prekeys) as specified in SESSION-MESSAGE-FLOW.md.
%%
%% @param UIState Current UI state
%% @param ClientPid WebSocket client PID
%% @param ClientState Client state record
%% @param WSChatState WebSocket chat state
%% @param ClientKeys Complete client key set
%% @returns Updated UI state with final connection status
upload_prekey_bundle_and_finalize(
    UIState, ClientPid, ClientState, WSChatState, ClientKeys
) ->
    %% Step 5: Upload one-time prekeys (prekey bundle)
    OneTimePrekeys = maps:get(one_time_prekeys, ClientKeys),
    PrekeyBundle = lists:map(
        fun(#{public := PubKey, id := KeyId}) ->
            #{
                id => base64:encode(KeyId),
                public_key => base64:encode(PubKey)
            }
        end,
        OneTimePrekeys
    ),

    PrekeyBundleCmd = #{
        type => <<"upload_prekey_bundle">>,
        one_time_prekeys => PrekeyBundle
    },
    ?msg_out("UI uploading prekey bundle: ~p", [PrekeyBundleCmd]),
    case cryptic_ws_client:send_command(ClientPid, PrekeyBundleCmd) of
        ok ->
            %% All steps completed successfully
            SuccessWSChatState = WSChatState#ws_chat_state{
                connection_status = connected,
                ws_client_state = {ok, ClientState}
            },
            SuccessUIState = UIState#ui_state{
                ws_chat_state = SuccessWSChatState
            },
            SuccessState = add_system_message(
                "Secure connection established!", SuccessUIState
            ),
            SuccessState2 = add_system_message(
                "Identity keys uploaded", SuccessState
            ),
            SuccessState3 = add_system_message(
                "Prekey bundle uploaded (" ++
                    integer_to_list(length(OneTimePrekeys)) ++ " keys)",
                SuccessState2
            ),
            SuccessState4 = add_system_message(
                "Ready for secure messaging!", SuccessState3
            ),
            SuccessState4;
        queued ->
            %% Prekey bundle upload queued
            SuccessWSChatState = WSChatState#ws_chat_state{
                connection_status = connected,
                ws_client_state = {ok, ClientState}
            },
            SuccessUIState = UIState#ui_state{
                ws_chat_state = SuccessWSChatState
            },
            SuccessState = add_system_message(
                "Secure connection established!", SuccessUIState
            ),
            SuccessState2 = add_system_message(
                "Identity keys uploaded", SuccessState
            ),
            SuccessState3 = add_system_message(
                "Prekey bundle upload queued...", SuccessState2
            ),
            SuccessState3;
        {error, BundleReason} ->
            %% Prekey bundle upload failed, but connection is still valid
            SuccessWSChatState = WSChatState#ws_chat_state{
                connection_status = connected,
                ws_client_state = {ok, ClientState}
            },
            SuccessUIState = UIState#ui_state{
                ws_chat_state = SuccessWSChatState
            },
            SuccessState = add_system_message(
                "Connection established with warnings", SuccessUIState
            ),
            ErrMsg = io_lib:format("Prekey bundle upload failed: ~p", [
                BundleReason
            ]),
            add_system_message(lists:flatten(ErrMsg), SuccessState)
    end.

%% @private
%% Add a system message to the message history.
%%
%% System messages are used for:
%% <ul>
%%   <li>Command feedback and status updates</li>
%%   <li>Error messages and warnings</li>
%%   <li>Help text and instructions</li>
%%   <li>WebSocket connection status notifications</li>
%% </ul>
%%
%% The message is automatically timestamped with the current local time
%% and added to the message history. System messages are displayed in
%% yellow color to distinguish them from user messages.
%%
%% @param Message The system message text to display
%% @param UIState Current UI state
%% @returns Updated UI state with the new message added to history.
add_system_message(Message, UIState) ->
    {{_Year, _Month, _Day}, {Hour, Min, Sec}} = calendar:local_time(),
    Timestamp = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),

    NewMessage = {"SYSTEM", Message, lists:flatten(Timestamp)},
    CurrentMessages = UIState#ui_state.message_history,

    UIState#ui_state{
        message_history = CurrentMessages ++ [NewMessage],
        % Reset scroll to show newest messages
        scroll_position = 0
    }.

%% @private
%% Return a function that adds a specific system message to UI state.
%% This is useful for passing as a callback.
%% @param Msg The system message text
%% @returns Function that takes UIState and returns updated UIState
add_sys_msg_f(Msg) ->
    fun(UIState) -> add_system_message(Msg, UIState) end.

%% @private
%% Handle X3DH encrypted message with proper field names.
handle_x3dh_message(
    From, NestedMessage, EphemeralPubB64, NonceB64, CiphertextB64, UIState
) ->
    try
        ?dbg("Handling X3DH message from ~s", [From]),
        case validate_x3dh_message_components(NestedMessage) of
            {ok, Components} ->
                process_x3dh_message_with_components(
                    From,
                    NestedMessage,
                    EphemeralPubB64,
                    NonceB64,
                    CiphertextB64,
                    Components,
                    UIState
                );
            {error, ErrorMsg} ->
                add_system_message(ErrorMsg, UIState)
        end
    catch
        _:Error ->
            add_system_message(
                lists:flatten(
                    io_lib:format("Error handling X3DH message: ~p", [Error])
                ),
                UIState
            )
    end.

%% @private
%% Validate that all required X3DH message components are present.
validate_x3dh_message_components(NestedMessage) ->
    SignatureB64 = maps:get(<<"signature">>, NestedMessage, undefined),
    MessageIdB64 = maps:get(<<"message_id">>, NestedMessage, undefined),
    MetadataB64 = maps:get(<<"metadata">>, NestedMessage, undefined),
    OtpkId = maps:get(<<"otpk_id">>, NestedMessage, undefined),

    case {SignatureB64, MessageIdB64, MetadataB64} of
        {undefined, _, _} ->
            {error, "X3DH message missing signature"};
        {_, undefined, _} ->
            {error, "X3DH message missing message_id"};
        {_, _, undefined} ->
            {error, "X3DH message missing metadata"};
        {SignatureB64, MessageIdB64, MetadataB64} ->
            {ok, #{
                signature_b64 => SignatureB64,
                message_id_b64 => MessageIdB64,
                metadata_b64 => MetadataB64,
                otpk_id => OtpkId
            }}
    end.

%% @private
%% Process X3DH message with validated components.
process_x3dh_message_with_components(
    From,
    NestedMessage,
    EphemeralPubB64,
    NonceB64,
    CiphertextB64,
    Components,
    UIState
) ->
    #{
        signature_b64 := SignatureB64,
        message_id_b64 := MessageIdB64,
        metadata_b64 := MetadataB64,
        otpk_id := OtpkId
    } = Components,

    %% Decode components
    DecodedComponents = decode_x3dh_components(
        EphemeralPubB64,
        NonceB64,
        CiphertextB64,
        SignatureB64,
        MessageIdB64,
        MetadataB64
    ),

    ?dbg(
        "Decoded X3DH components: EphemeralPub(~p), Nonce(~p), Ciphertext(~p), Signature(~p), MessageId(~p), OtpkId(~p)",
        [
            maps:get(ephemeral_pub, DecodedComponents),
            maps:get(nonce, DecodedComponents),
            maps:get(ciphertext, DecodedComponents),
            maps:get(signature, DecodedComponents),
            maps:get(message_id, DecodedComponents),
            OtpkId
        ]
    ),
    ?dbg("Alice's transmitted metadata: ~p", [
        maps:get(metadata, DecodedComponents)
    ]),

    %% Check if we have client keys
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.client_keys of
        undefined ->
            add_system_message(
                "No client keys available for X3DH decryption",
                UIState
            );
        ClientKeys ->
            process_x3dh_with_client_keys(
                From, NestedMessage, DecodedComponents, ClientKeys, UIState
            )
    end.

%% @private
%% Decode all X3DH message components from base64.
decode_x3dh_components(
    EphemeralPubB64,
    NonceB64,
    CiphertextB64,
    SignatureB64,
    MessageIdB64,
    MetadataB64
) ->
    #{
        ephemeral_pub => base64:decode(EphemeralPubB64),
        nonce => base64:decode(NonceB64),
        ciphertext => base64:decode(CiphertextB64),
        signature => base64:decode(SignatureB64),
        message_id => base64:decode(MessageIdB64),
        metadata => erlang:binary_to_term(base64:decode(MetadataB64))
    }.

%% @private
%% Process X3DH message when we have client keys available.
process_x3dh_with_client_keys(
    From, NestedMessage, DecodedComponents, ClientKeys, UIState
) ->
    ?dbg("Using client keys for X3DH decryption~n", []),

    %% Build recipient blob from decoded components
    RecipientBlob = build_recipient_blob(DecodedComponents),

    ?dbg("Attempting X3DH decryption with RecipientBlob: ~p", [RecipientBlob]),

    %% Extract sender's identity keys from metadata (sent by Alice)
    #{metadata := Metadata} = RecipientBlob,
    case
        {
            maps:get(sender_identity_dh_public, Metadata, undefined),
            maps:get(sender_identity_sign_public, Metadata, undefined)
        }
    of
        {SenderIdDHPub, SenderIdPub} when
            SenderIdDHPub == undefined orelse
                SenderIdPub == undefined
        ->
            ?error("No sender_identity in metadata, exiting!~n", []),
            throw(no_sender_id_in_metadata);
        %%
        {SenderIdDHPub, SenderIdPub} ->
            ?info(
                "Found sender identity keys in metadata (DH: ~p, Sign: ~p), proceeding with direct decrypt",
                [SenderIdDHPub, SenderIdPub]
            ),
            %% Proceed directly with X3DH decryption using Bob's own keys
            proceed_with_x3dh_decrypt_direct(
                SenderIdPub,
                RecipientBlob,
                ClientKeys,
                From,
                UIState,
                NestedMessage
            )
    end.

%% @private
%% Build recipient blob from decoded X3DH components.
build_recipient_blob(DecodedComponents) ->
    #{
        metadata => maps:get(metadata, DecodedComponents),
        signature => maps:get(signature, DecodedComponents),
        ciphertext => maps:get(ciphertext, DecodedComponents),
        nonce => maps:get(nonce, DecodedComponents)
    }.

%% @private
%% Proceed with X3DH decryption directly using sender's identity key from metadata.
%% This avoids the need to request the sender's key bundle from the server.
proceed_with_x3dh_decrypt_direct(
    SenderIdPub, RecipientBlob, ClientKeys, From, UIState, NestedMessage
) ->
    ?info("Starting proceed_with_x3dh_decrypt_direct for message from ~p", [
        From
    ]),
    %% Get the private key for the OTPK ID used (from Bob's own keys)
    OtpkId = maps:get(
        otpk_id,
        maps:get(metadata, RecipientBlob, #{}),
        undefined
    ),
    OtpkPrivateKey =
        case OtpkId of
            undefined ->
                ?dbg("No OTPK ID in message, using null", []),
                null;
            OtpkIdVal ->
                %% Look up Bob's private key for this OTPK ID
                case
                    cryptic_lib:find_otpk_private_key(
                        ClientKeys, OtpkIdVal
                    )
                of
                    {ok, PrivKey} ->
                        ?info(
                            "Found OTPK private key for ID ~p",
                            [OtpkIdVal]
                        ),
                        PrivKey;
                    {error, Reason} ->
                        ?dbg(
                            "Warning: Could not find OTPK private key for ID ~p: ~p",
                            [OtpkIdVal, Reason]
                        ),
                        null
                end
        end,

    %% Get sender key ID from metadata (no need to fetch from server)
    #{metadata := OriginalMetadata} = RecipientBlob,
    SenderKeyId = maps:get(sender_id, OriginalMetadata, <<>>),

    %% Sender's DH key should already be in metadata, no need to convert
    SenderIdDHPub = maps:get(sender_identity_dh_public, OriginalMetadata, <<>>),
    UpdatedMetadata = OriginalMetadata#{
        sender_identity_dh_public => SenderIdDHPub,
        sender_id => SenderKeyId
    },
    UpdatedRecipientBlob = RecipientBlob#{metadata := UpdatedMetadata},

    ?info(
        "About to call x3dh_receiver_decrypt with OTPK key: ~p, sender key ID: ~p",
        [OtpkPrivateKey, SenderKeyId]
    ),

    case
        cryptic_lib:x3dh_receiver_decrypt(
            ClientKeys,
            UpdatedRecipientBlob,
            SenderIdPub,
            OtpkPrivateKey
        )
    of
        {ok, {PlainBin, _MessageId}} ->
            ?info(
                "X3DH decryption successful, plaintext: ~p",
                [PlainBin]
            ),

            %% Handle OTPK tracking for forward secrecy management
            UIStateAfterTracking = handle_otpk_tracking(
                From, UpdatedRecipientBlob, UIState
            ),

            %% Convert to string
            PlainText =
                case unicode:characters_to_list(PlainBin) of
                    {error, _, _} -> PlainBin;
                    {incomplete, _, _} -> PlainBin;
                    List -> List
                end,

            %% Add to inbox
            Timestamp = maps:get(
                <<"server_timestamp">>,
                NestedMessage,
                erlang:system_time(second)
            ),
            NewInbox =
                UIStateAfterTracking#ui_state.inbox ++
                    [{From, PlainText, Timestamp}],

            %% Update pending messages
            PendingMessages =
                UIStateAfterTracking#ui_state.pending_messages,
            CurrentCount = maps:get(
                From, PendingMessages, 0
            ),
            NewPendingMessages = maps:put(
                From, CurrentCount + 1, PendingMessages
            ),
            %% Clear pending operation
            WSChatState = UIStateAfterTracking#ui_state.ws_chat_state,
            ClearedWSChatState = WSChatState#ws_chat_state{
                pending_operation = undefined
            },
            TempUIState = UIStateAfterTracking#ui_state{
                inbox = NewInbox,
                message_count = length(NewInbox),
                pending_messages = NewPendingMessages,
                ws_chat_state = ClearedWSChatState
            },
            %% Auto-display if enabled
            case UIStateAfterTracking#ui_state.auto_display of
                true ->
                    ClearedPendingMessages = maps:put(
                        From, 0, NewPendingMessages
                    ),
                    NewUIState = TempUIState#ui_state{
                        pending_messages =
                            ClearedPendingMessages
                    },
                    add_message(
                        From, PlainText, NewUIState
                    );
                false ->
                    TempUIState
            end;
        {error, X3DHError} ->
            ?info("X3DH decryption failed with error: ~p", [X3DHError]),
            %% Clear pending operation on error
            WSChatState = UIState#ui_state.ws_chat_state,
            ClearedWSChatState = WSChatState#ws_chat_state{
                pending_operation = undefined
            },
            ErrorUIState = UIState#ui_state{
                ws_chat_state = ClearedWSChatState
            },
            add_system_message(
                lists:flatten(
                    io_lib:format(
                        "X3DH decryption failed: ~p", [
                            X3DHError
                        ]
                    )
                ),
                ErrorUIState
            )
    end.

%% @private
%% Handle legacy encrypted message with old field names.
handle_legacy_encrypted_message(
    From, NestedMessage, EphemeralB64, NonceB64, CipherB64, UIState
) ->
    Timestamp = maps:get(
        <<"timestamp">>, NestedMessage, erlang:system_time(seconds)
    ),

    %% Get our private key
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.keypair of
        {_PubKey, PrivKey} ->
            %% Decode encrypted components
            EphemeralPub = base64:decode(EphemeralB64),
            Nonce = base64:decode(NonceB64),
            Cipher = base64:decode(CipherB64),

            %% Decrypt using cryptic_lib functions directly
            try
                %% Compute shared secret
                SharedSecret = cryptic_lib:scalarmult(PrivKey, EphemeralPub),

                %% Derive AEAD key using ephemeral public key as salt
                AeadKey = cryptic_lib:derive_aead_key_ephemeral(
                    SharedSecret, EphemeralPub
                ),

                %% Decrypt message
                case cryptic_lib:aead_decrypt(Cipher, AeadKey, Nonce, <<>>) of
                    error ->
                        CryptoErrMsg = io_lib:format(
                            "Failed to decrypt legacy message from ~s: decryption_failed",
                            [From]
                        ),
                        add_system_message(
                            lists:flatten(CryptoErrMsg), UIState
                        );
                    PlainBin ->
                        %% Convert back to string if possible
                        PlainText =
                            case unicode:characters_to_list(PlainBin) of
                                {error, _, _} -> PlainBin;
                                {incomplete, _, _} -> PlainBin;
                                List -> List
                            end,

                        %% Add to inbox and update message count
                        NewInbox =
                            UIState#ui_state.inbox ++
                                [{From, PlainText, Timestamp}],
                        MessageCount = length(NewInbox),

                        %% Update pending message count for sender
                        PendingMessages = UIState#ui_state.pending_messages,
                        CurrentCount = maps:get(From, PendingMessages, 0),
                        NewPendingMessages = maps:put(
                            From, CurrentCount + 1, PendingMessages
                        ),

                        TempUIState = UIState#ui_state{
                            inbox = NewInbox,
                            message_count = MessageCount,
                            pending_messages = NewPendingMessages
                        },

                        %% Check auto_display setting
                        case UIState#ui_state.auto_display of
                            true ->
                                %% Show message immediately and clear pending count
                                ClearedPendingMessages = maps:put(
                                    From, 0, NewPendingMessages
                                ),
                                NewUIState = TempUIState#ui_state{
                                    pending_messages = ClearedPendingMessages
                                },
                                add_message(From, PlainText, NewUIState);
                            false ->
                                %% Just store in inbox, no notification needed
                                TempUIState
                        end
                end
            catch
                error:CryptoReason ->
                    CatchErrMsg = io_lib:format(
                        "Failed to decrypt legacy message from ~s: ~p",
                        [From, CryptoReason]
                    ),
                    add_system_message(lists:flatten(CatchErrMsg), UIState)
            end;
        undefined ->
            add_system_message("No keypair available for decryption", UIState)
    end.

%% @private
%% Find the start of a word backward from the current position.
%%
%% This function implements word boundary detection for Ctrl+W (kill word backward).
%% It finds the beginning of the current word or the previous word if the cursor
%% is at word boundary or whitespace.
%%
%% Word boundaries are defined as:
%% - Whitespace characters (space, tab)
%% - Beginning of line
%%
%% @param Before List of characters before the cursor position
%% @returns {WordStart, KilledWord, NewBefore} where:
%%   - WordStart: Position where the word starts (unused but kept for consistency)
%%   - KilledWord: The word that was killed
%%   - NewBefore: The remaining text before cursor after killing the word
find_word_backward(Before) ->
    %% Reverse the list to work from cursor backward
    Reversed = lists:reverse(Before),

    %% Skip any trailing whitespace first
    {SkippedWS, RestAfterWS} = skip_whitespace(Reversed),

    %% Find the word to kill
    {Word, RestAfterWord} = take_word(RestAfterWS),

    %% The killed text includes any skipped whitespace plus the word
    KilledWord = lists:reverse(SkippedWS ++ Word),

    %% What remains before cursor
    NewBefore = lists:reverse(RestAfterWord),

    %% WordStart would be the position, but we don't actually need it
    WordStart = length(NewBefore),

    {WordStart, KilledWord, NewBefore}.

%% @private
%% Skip whitespace characters from the beginning of a reversed string.
skip_whitespace([]) ->
    {[], []};
skip_whitespace([C | Rest]) when C =:= $\s; C =:= $\t ->
    {Skipped, Remaining} = skip_whitespace(Rest),
    {[C | Skipped], Remaining};
skip_whitespace(String) ->
    {[], String}.

%% @private
%% Take a word (non-whitespace characters) from the beginning of a reversed string.
take_word([]) ->
    {[], []};
take_word([C | Rest]) when C =:= $\s; C =:= $\t ->
    {[], [C | Rest]};
take_word([C | Rest]) ->
    {Word, Remaining} = take_word(Rest),
    {[C | Word], Remaining}.
