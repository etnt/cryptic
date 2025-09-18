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

-include_lib("cecho/include/cecho.hrl").
-include("cryptic.hrl").

%% Client state record from cryptic_ws_client_lib
-record(client_state, {
    ws_client_pid,
    username,
    keypair
}).

%% WebSocket chat state record containing connection and user information.
%%
%% This record maintains the core state for WebSocket mTLS operations including
%% certificate configuration, server connection details, and message monitoring.
-record(ws_chat_state, {
    server_host = "localhost" :: string(),
    server_port = 8443 :: pos_integer(),
    username :: string() | undefined,
    cert_config :: #{atom() => string()},
    ws_client_state :: term() | undefined,
    keypair :: {binary(), binary()} | undefined,
    % Full client key set
    client_keys :: #{} | undefined,
    connection_status = disconnected :: connected | disconnected | connecting,
    pending_operation :: map() | undefined
}).

%% UI state record containing screen layout and interaction state.
%%
%% This record manages all UI-specific state including screen dimensions,
%% message display, input handling, and WebSocket communication.
-record(ui_state, {
    ws_chat_state :: #ws_chat_state{},
    screen_height :: integer(),
    screen_width :: integer(),
    % {From, Message, Timestamp}
    message_history = [] :: [{string(), string(), string()}],
    scroll_position = 0 :: integer(),
    command_history = [] :: [string()],
    current_input = "" :: string(),
    % Cursor position in current_input
    cursor_position = 0 :: integer(),
    % Position in command history (0 = not browsing)
    history_position = 0 :: integer(),
    input_pid :: pid(),
    status_pid :: pid(),

    %% Chat mode state

    % Whether in chat mode
    chat_mode = false :: boolean(),
    % Username being chatted with
    chat_target :: string() | undefined,

    %% Room cache for name-to-ID mapping
    room_cache = #{} :: #{string() => string()},

    %% Inbox for encrypted messages

    % {From, Message, Timestamp}
    inbox = [] :: [{string(), string(), integer()}],
    % Number of messages in inbox
    message_count = 0 :: integer(),

    %% Auto-display control

    % Whether to auto-display incoming messages
    auto_display = true :: boolean(),
    % Count of pending messages per user
    pending_messages = #{} :: #{string() => integer()}
}).

%% Color pairs
-define(COLOR_STATUS_BAR, 1).
-define(COLOR_HELP_BAR, 2).
-define(COLOR_OWN_MESSAGE, 3).
-define(COLOR_OTHER_MESSAGE, 4).
-define(COLOR_SYSTEM_MESSAGE, 5).
-define(COLOR_TIMESTAMP, 6).
-define(COLOR_INPUT, 7).
-define(COLOR_SENT_MESSAGE, 8).

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

    %% Initialize client cryptographic keys
    io:format("🔐 Initializing cryptographic keys for ~s...~n", [Username]),
    ConfigDir =
        case os:getenv("CRYPTIC_CONFIG_DIR") of
            false ->
                error(
                    {missing_config_dir,
                        "CRYPTIC_CONFIG_DIR environment variable not set"}
                );
            Dir ->
                Dir
        end,
    ClientKeys =
        %% TODO: In production, implement proper passphrase prompting here
        %% For example:
        %% - Check for CRYPTIC_PASSPHRASE environment variable
        %% - Or prompt user via terminal input with disabled echo
        %% - Or use GUI password dialog
        %% - Or read from secure keystore
        case cryptic_lib:initialize_client_keys(ConfigDir, <<"qwe123">>) of
            {ok, Keys} ->
                io:format("✅ Keys loaded successfully~n"),
                Keys;
            {error, Reason} ->
                io:format("❌ Key initialization failed: ~p~n", [Reason]),
                error({key_init_failed, Reason})
        end,

    %% Start the event manager for logging
    {ok, _} = gen_event:start_link({local, cryptic_event_manager}),

    %% Set up event handlers for UI client with client configuration
    cryptic_event_manager:setup_event_handlers(#{
        log_type => client, log_dir => "logs"
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
        keypair = {
            maps:get(identity_dh_private, ClientKeys),
            maps:get(identity_dh_public, ClientKeys)
        },
        client_keys = ClientKeys
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
        "Type 'connect' to establish WebSocket mTLS connection", WelcomeState3
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
%% @doc Main UI event loop handling user interactions and background tasks.
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

%% @private
%% @doc Position cursor in the input area at the end of current input.
%%
%% Calculates the correct cursor position based on the prompt length
%% and current input text, then moves the terminal cursor there.
%% This ensures the cursor appears at the natural typing position.
%%
%% @param UIState Current UI state containing input text and screen dimensions.
position_cursor(UIState) ->
    #ui_state{
        current_input = Input,
        cursor_position = CursorPos,
        screen_height = Height,
        screen_width = Width
    } = UIState,

    Prompt = "> ",
    PromptLen = length(Prompt),
    InputLine = Prompt ++ Input,

    %% Calculate cursor screen position
    CursorScreenPos = PromptLen + CursorPos,

    %% Handle horizontal scrolling if line is too long
    FinalCursorPos =
        case length(InputLine) of
            Len when Len > Width ->
                %% Need to scroll - center cursor if possible
                ScrollOffset = max(0, CursorScreenPos - (Width div 2)),
                ScrollOffset2 = min(ScrollOffset, Len - Width),
                CursorScreenPos - ScrollOffset2;
            _ ->
                CursorScreenPos
        end,

    %% Position cursor correctly
    cecho:move(Height - 1, min(FinalCursorPos, Width - 1)).

%% @private
%% @doc Draw the complete screen layout with all UI components.
%%
%% Renders the full terminal interface in the correct order:
%% <ol>
%%   <li>Clear the entire screen</li>
%%   <li>Draw status bar at the top</li>
%%   <li>Draw scrollable message area</li>
%%   <li>Draw context-sensitive help bar</li>
%%   <li>Draw input line with current text</li>
%%   <li>Refresh the display</li>
%%   <li>Position cursor for typing</li>
%% </ol>
%%
%% @param UIState Current UI state containing all display information.
draw_screen(UIState) ->
    %% Clear screen
    cecho:erase(),

    %% Draw status bar (line 0)
    draw_status_bar(UIState),

    %% Draw message area (lines 1 to Height-4)
    draw_message_area(UIState),

    %% Draw help bar (line Height-3)
    draw_help_bar(UIState),

    %% Draw input line (line Height-1)
    draw_input_line(UIState),

    %% Position cursor BEFORE refresh to avoid flickering
    position_cursor(UIState),

    %% Refresh screen to update physical display
    cecho:refresh().

%% @private
%% @doc Draw the status bar at the top showing WebSocket connection and user info.
%%
%% The status bar displays:
%% <ul>
%%   <li>Application name and auto_display status (Auto:on/Auto:off)</li>
%%   <li>Current certificate user and connection status</li>
%%   <li>Chat mode status and target user</li>
%%   <li>Pending message count when available</li>
%%   <li>Current time</li>
%% </ul>
%%
%% The status bar uses blue background with white text and automatically
%% truncates content to fit the screen width.
%%
%% @param UIState Current UI state containing WebSocket and display information.
draw_status_bar(UIState) ->
    #ui_state{
        ws_chat_state = WSChatState,
        screen_width = Width
    } = UIState,

    %% Get current time
    {_, {Hour, Min, Sec}} = calendar:local_time(),
    TimeStr = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),

    %% Get user info and connection status
    UserStr =
        case WSChatState#ws_chat_state.username of
            undefined -> "No cert";
            User -> "Cert: " ++ User
        end,

    %% Get connection status
    ConnStatusStr =
        case WSChatState#ws_chat_state.connection_status of
            connected -> " | Connected";
            connecting -> " | Connecting...";
            disconnected -> " | Disconnected"
        end,

    %% Get chat mode status and message count
    ChatModeStr =
        case UIState#ui_state.chat_mode of
            false ->
                "";
            true ->
                case UIState#ui_state.chat_target of
                    undefined -> " | Chat mode";
                    Target -> " | Chat with: " ++ Target
                end
        end,

    %% Get pending message count
    PendingCount = maps:fold(
        fun(_, Count, Acc) -> Acc + Count end,
        0,
        UIState#ui_state.pending_messages
    ),
    MessageCountStr =
        case PendingCount of
            0 -> "";
            N -> " | Msgs: " ++ integer_to_list(N)
        end,

    %% Get auto_display status
    AutoDisplayStr =
        case UIState#ui_state.auto_display of
            true -> "Auto:on";
            false -> "Auto:off"
        end,

    %% Create status line
    StatusLine = io_lib:format(
        "CRYPTIC WS mTLS | ~s | ~s~s~s~s | ~s",
        [
            AutoDisplayStr,
            UserStr,
            ConnStatusStr,
            ChatModeStr,
            MessageCountStr,
            TimeStr
        ]
    ),

    %% Truncate or pad to screen width
    StatusLineFmt = format_line(lists:flatten(StatusLine), Width),

    %% Draw with status bar colors
    cecho:attron(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)),
    cecho:mvaddstr(0, 0, StatusLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)).

%% @private
%% @doc Draw the scrollable message display area.
%%
%% Renders the message history in the central area of the screen.
%% Messages are displayed with color coding:
%% <ul>
%%   <li>Yellow for system messages</li>
%%   <li>Cyan for messages from other users</li>
%%   <li>Green for own messages</li>
%% </ul>
%%
%% The message area supports scrolling to view message history.
%%
%% @param UIState Current UI state containing message history and screen info.
draw_message_area(UIState) ->
    #ui_state{
        message_history = Messages,
        screen_height = Height,
        screen_width = Width,
        scroll_position = ScrollPos
    } = UIState,

    %% Calculate message area bounds
    StartLine = 1,
    EndLine = Height - 4,
    AreaHeight = EndLine - StartLine + 1,

    %% Get visible messages (with scrolling)
    VisibleMessages = get_visible_messages(Messages, ScrollPos, AreaHeight),

    %% Draw each message
    draw_messages(VisibleMessages, StartLine, Width, UIState).

%% @private
%% @doc Draw individual messages with appropriate color coding.
%%
%% Iterates through the visible message list and renders each message
%% with the appropriate color scheme based on the sender type.
%% System messages get special formatting without sender name.
%%
%% @param Messages List of {From, Message, Timestamp} tuples to display
%% @param Line Starting line number for drawing
%% @param Width Screen width for text formatting
%% @param UIState Current UI state for user context
draw_messages([], _Line, _Width, _UIState) ->
    ok;
draw_messages([{From, Message, Timestamp} | Rest], Line, Width, UIState) ->
    %% Format message line
    FormattedMsg = format_message(From, Message, Timestamp, Width),

    %% Choose color based on message type
    WSChatState = UIState#ui_state.ws_chat_state,
    CurrentUser = WSChatState#ws_chat_state.username,
    ColorPair =
        case From of
            "SYSTEM" ->
                ?COLOR_SYSTEM_MESSAGE;
            CurrentUser ->
                ?COLOR_OWN_MESSAGE;
            _ ->
                %% Check if this is a sent message (starts with "You -> ")
                case string:prefix(From, "You -> ") of
                    nomatch -> ?COLOR_OTHER_MESSAGE;
                    _ -> ?COLOR_SENT_MESSAGE
                end
        end,

    %% Draw message
    cecho:attron(?ceCOLOR_PAIR(ColorPair)),
    cecho:mvaddstr(Line, 0, FormattedMsg),
    cecho:attroff(?ceCOLOR_PAIR(ColorPair)),

    %% Draw next message
    draw_messages(Rest, Line + 1, Width, UIState).

%% @private
%% @doc Draw the context-sensitive help bar.
%%
%% Displays different help text based on the current mode and connection status:
%% <ul>
%%   <li>Disconnected: Shows connection commands</li>
%%   <li>Connected: Shows messaging commands (send, chat, etc.)</li>
%%   <li>Chat mode: Shows chat-specific commands (:exit, :help, message sending)</li>
%% </ul>
%%
%% The help bar uses white text on black background and is positioned
%% near the bottom of the screen for easy reference.
%%
%% @param UIState Current UI state to determine the appropriate help text.
draw_help_bar(UIState) ->
    #ui_state{screen_height = Height, screen_width = Width} = UIState,

    WSChatState = UIState#ui_state.ws_chat_state,
    HelpLine =
        case
            {
                WSChatState#ws_chat_state.connection_status,
                UIState#ui_state.chat_mode
            }
        of
            {disconnected, _} ->
                "Commands: connect | help | quit";
            {connected, false} ->
                "Commands: help | send | chat | create_room | join_room | list_rooms | list_users | disconnect";
            {connected, true} ->
                "Chat Mode: Type message to send | :exit to leave chat | :help for commands";
            {connecting, _} ->
                "Connecting to WebSocket mTLS server..."
        end,
    HelpLineFmt = format_line(HelpLine, Width),

    cecho:attron(?ceCOLOR_PAIR(?COLOR_HELP_BAR)),
    cecho:mvaddstr(Height - 3, 0, HelpLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_HELP_BAR)).

%% @private
%% @doc Draw the input line with prompt and current user text.
%%
%% Renders the bottom input line where users type their commands or messages.
%% The line includes:
%% <ul>
%%   <li>A ">" prompt to indicate input readiness</li>
%%   <li>The current input text being typed</li>
%%   <li>Automatic truncation if text exceeds screen width</li>
%%   <li>White text on black background for visibility</li>
%% </ul>
%%
%% The input line is cleared before drawing to handle backspace operations
%% and text editing properly.
%%
%% @param UIState Current UI state containing input text and screen dimensions.
draw_input_line(UIState) ->
    #ui_state{
        current_input = Input,
        cursor_position = CursorPos,
        screen_height = Height,
        screen_width = Width
    } = UIState,

    %% Create input line with prompt
    Prompt = "> ",
    PromptLen = length(Prompt),
    InputLine = Prompt ++ Input,

    %% Calculate cursor screen position
    CursorScreenPos = PromptLen + CursorPos,

    %% Handle horizontal scrolling if line is too long
    DisplayLine =
        case length(InputLine) of
            Len when Len > Width ->
                %% Need to scroll - center cursor if possible
                ScrollOffset = max(0, CursorScreenPos - (Width div 2)),
                ScrollOffset2 = min(ScrollOffset, Len - Width),
                string:substr(InputLine, ScrollOffset2 + 1, Width);
            _ ->
                InputLine
        end,

    %% Clear the input line by overwriting with spaces first
    ClearLine = string:chars($\s, Width),
    cecho:attron(?ceCOLOR_PAIR(?COLOR_INPUT)),
    cecho:mvaddstr(Height - 1, 0, ClearLine),

    %% Now draw the actual input content
    cecho:mvaddstr(Height - 1, 0, DisplayLine),

    %% Don't position cursor here - that's done separately in position_cursor/1
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_INPUT)).

%%%===================================================================
%%% Input Handling
%%%===================================================================

%% @private
%% @doc Handle user input events from the input handler process.
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
            %% Add non-empty commands to history
            NewHistory =
                case string:strip(Command) of
                    "" ->
                        UIState#ui_state.command_history;
                    CleanCommand ->
                        %% Add to front, limit to 50 commands
                        lists:sublist(
                            [CleanCommand | UIState#ui_state.command_history],
                            50
                        )
                end,
            ProcessedUIState = process_command(Command, UIState),
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
        _ ->
            %% Ignore other input
            UIState
    end.

%% @private
%% @doc Process a user command and return updated UI state.
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
    %% Establish WebSocket mTLS connection
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            add_system_message(
                "Already connected to WebSocket server", UIState
            );
        connecting ->
            add_system_message("Connection already in progress", UIState);
        disconnected ->
            %% Update status to connecting
            NewWSChatState = WSChatState#ws_chat_state{
                connection_status = connecting
            },
            ConnectingUIState = UIState#ui_state{
                ws_chat_state = NewWSChatState
            },
            ConnectingState = add_system_message(
                "Connecting to WebSocket mTLS server...", ConnectingUIState
            ),

            %% Attempt to connect
            Username = WSChatState#ws_chat_state.username,
            ServerHost = WSChatState#ws_chat_state.server_host,
            CertConfig = WSChatState#ws_chat_state.cert_config,

            case
                cryptic_ws_client:start_link(Username, ServerHost, CertConfig)
            of
                {ok, ClientPid} ->
                    %% Generate keypair for this user
                    {PubKey, PrivKey} = cryptic_lib:gen_keypair(),

                    %% Create a client state record with keypair
                    ClientState = #client_state{
                        ws_client_pid = ClientPid,
                        username = Username,
                        keypair = {PubKey, PrivKey}
                    },
                    %% Connection successful, set UI PID for message forwarding
                    cryptic_ws_client:set_ui_pid(
                        ClientState#client_state.ws_client_pid, self()
                    ),

                    %% Upload the public key to the server
                    case
                        cryptic_ws_client:send_command(ClientPid, #{
                            type => <<"upload_prekey">>,
                            prekey => base64:encode(PubKey)
                        })
                    of
                        ok ->
                            SuccessWSChatState = NewWSChatState#ws_chat_state{
                                connection_status = connected,
                                ws_client_state = {ok, ClientState},
                                keypair = {PubKey, PrivKey}
                            },
                            SuccessUIState = ConnectingState#ui_state{
                                ws_chat_state = SuccessWSChatState
                            },
                            SuccessState = add_system_message(
                                "WebSocket mTLS connection established!",
                                SuccessUIState
                            ),
                            SuccessState2 = add_system_message(
                                "Authenticated as: " ++ Username, SuccessState
                            ),
                            SuccessState3 = add_system_message(
                                "Keypair generated and uploaded to server",
                                SuccessState2
                            ),
                            SuccessState3;
                        queued ->
                            %% Prekey upload queued until WebSocket connection is ready
                            SuccessWSChatState = NewWSChatState#ws_chat_state{
                                connection_status = connected,
                                ws_client_state = {ok, ClientState},
                                keypair = {PubKey, PrivKey}
                            },
                            SuccessUIState = ConnectingState#ui_state{
                                ws_chat_state = SuccessWSChatState
                            },
                            SuccessState = add_system_message(
                                "WebSocket mTLS connection established!",
                                SuccessUIState
                            ),
                            SuccessState2 = add_system_message(
                                "Authenticated as: " ++ Username, SuccessState
                            ),
                            SuccessState3 = add_system_message(
                                "Keypair generated, prekey upload queued...",
                                SuccessState2
                            ),
                            SuccessState3;
                        {error, UploadReason} ->
                            ErrMsg = io_lib:format(
                                "Failed to upload prekey: ~p", [UploadReason]
                            ),
                            FailState = add_system_message(
                                lists:flatten(ErrMsg), ConnectingState
                            ),
                            FailState
                    end;
                {error, Reason} ->
                    %% Connection failed
                    FailWSChatState = NewWSChatState#ws_chat_state{
                        connection_status = disconnected
                    },
                    FailUIState = ConnectingState#ui_state{
                        ws_chat_state = FailWSChatState
                    },
                    ErrMsg = io_lib:format("Connection failed: ~p", [Reason]),
                    add_system_message(lists:flatten(ErrMsg), FailUIState)
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
                    case
                        cryptic_ws_client:send_command(
                            ClientState#client_state.ws_client_pid, #{
                                type => <<"list_users">>
                            }
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
                            case
                                cryptic_ws_client:send_command(
                                    ClientState#client_state.ws_client_pid, #{
                                        type => <<"get_prekey">>,
                                        user => list_to_binary(TrimmedToUser)
                                    }
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
%% @doc Process commands while in chat mode via WebSocket.
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
                                type => <<"get_prekey">>,
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
%% @doc Handle incoming WebSocket messages from the server.
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
                    <<"prekey">> ->
                        %% Prekey response - handle pending encrypted send
                        handle_prekey_response(Data, UIState);
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

%% @doc Handle prekey response and complete the encrypted message send.
%%
%% When we receive a prekey response from the server, we can now encrypt
%% and send the pending message securely.
handle_prekey_response(Data, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{
            type := send_encrypted,
            to_user := ToUser,
            message := Message,
            from_user := FromUser
        } ->
            case maps:get(<<"prekey">>, Data, undefined) of
                undefined ->
                    add_system_message("Error: No prekey in response", UIState);
                PrekeyB64 ->
                    try
                        %% Decode the recipient's public key
                        RecipientPubKey = base64:decode(PrekeyB64),

                        %% Encrypt the message
                        case
                            cryptic_client_lib:encrypt_message(
                                Message, RecipientPubKey
                            )
                        of
                            {ok, {EphPub, Nonce, Cipher}} ->
                                %% Send the encrypted message
                                case
                                    WSChatState#ws_chat_state.ws_client_state
                                of
                                    {ok, ClientState} ->
                                        case
                                            cryptic_ws_client:send_command(
                                                ClientState#client_state.ws_client_pid,
                                                #{
                                                    type => <<"send_message">>,
                                                    from => list_to_binary(
                                                        FromUser
                                                    ),
                                                    to => list_to_binary(
                                                        ToUser
                                                    ),
                                                    ephemeral => base64:encode(
                                                        EphPub
                                                    ),
                                                    nonce => base64:encode(
                                                        Nonce
                                                    ),
                                                    cipher => base64:encode(
                                                        Cipher
                                                    )
                                                }
                                            )
                                        of
                                            ok ->
                                                %% Clear pending operation and show success
                                                ClearWSChatState = WSChatState#ws_chat_state{
                                                    pending_operation =
                                                        undefined
                                                },
                                                ClearUIState = UIState#ui_state{
                                                    ws_chat_state =
                                                        ClearWSChatState
                                                },
                                                SenderText = io_lib:format(
                                                    "You -> ~s", [ToUser]
                                                ),
                                                add_message(
                                                    lists:flatten(SenderText),
                                                    Message,
                                                    ClearUIState
                                                );
                                            {error, Reason} ->
                                                SendErrMsg = io_lib:format(
                                                    "Failed to send encrypted message: ~p",
                                                    [Reason]
                                                ),
                                                add_system_message(
                                                    lists:flatten(SendErrMsg),
                                                    UIState
                                                )
                                        end;
                                    _ ->
                                        add_system_message(
                                            "WebSocket client not available",
                                            UIState
                                        )
                                end;
                            {error, Reason} ->
                                EncryptErrMsg = io_lib:format(
                                    "Failed to encrypt message: ~p", [Reason]
                                ),
                                add_system_message(
                                    lists:flatten(EncryptErrMsg), UIState
                                )
                        end
                    catch
                        _:Error ->
                            ProcessErrMsg = io_lib:format(
                                "Failed to process prekey: ~p", [Error]
                            ),
                            add_system_message(
                                lists:flatten(ProcessErrMsg), UIState
                            )
                    end
            end;
        _ ->
            %% No pending operation or wrong type
            add_system_message("Received unexpected prekey response", UIState)
    end.

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

%% @doc Handle prekey received from WebSocket client for immediate encryption.
%%
%% This function handles prekeys received asynchronously from the server
%% when another user's public key is needed for message encryption.
handle_prekey_received(User, PrekeyB64, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{
            type := send_encrypted,
            to_user := ToUser,
            message := Message,
            from_user := FromUser
        } ->
            %% Check if this prekey matches our pending send operation
            UserStr = binary_to_list(User),
            case ToUser =:= UserStr of
                true ->
                    %% This prekey matches our pending send operation
                    try
                        %% Decode the recipient's public key
                        RecipientPubKey = base64:decode(PrekeyB64),

                        %% Encrypt the message
                        case
                            cryptic_client_lib:encrypt_message(
                                Message, RecipientPubKey
                            )
                        of
                            {ok, {EphPub, Nonce, Cipher}} ->
                                %% Send the encrypted message
                                case
                                    WSChatState#ws_chat_state.ws_client_state
                                of
                                    {ok, ClientState} ->
                                        case
                                            cryptic_ws_client:send_command(
                                                ClientState#client_state.ws_client_pid,
                                                #{
                                                    type => <<"send_message">>,
                                                    from => list_to_binary(
                                                        FromUser
                                                    ),
                                                    to => list_to_binary(
                                                        ToUser
                                                    ),
                                                    ephemeral => base64:encode(
                                                        EphPub
                                                    ),
                                                    nonce => base64:encode(
                                                        Nonce
                                                    ),
                                                    cipher => base64:encode(
                                                        Cipher
                                                    )
                                                }
                                            )
                                        of
                                            ok ->
                                                %% Clear pending operation and show success
                                                ClearWSChatState = WSChatState#ws_chat_state{
                                                    pending_operation =
                                                        undefined
                                                },
                                                ClearUIState = UIState#ui_state{
                                                    ws_chat_state =
                                                        ClearWSChatState
                                                },
                                                SenderText = io_lib:format(
                                                    "You -> ~s", [ToUser]
                                                ),
                                                add_message(
                                                    lists:flatten(SenderText),
                                                    Message,
                                                    ClearUIState
                                                );
                                            queued ->
                                                %% Message queued, clear pending operation
                                                ClearWSChatState = WSChatState#ws_chat_state{
                                                    pending_operation =
                                                        undefined
                                                },
                                                ClearUIState = UIState#ui_state{
                                                    ws_chat_state =
                                                        ClearWSChatState
                                                },
                                                MsgText = io_lib:format(
                                                    "Encrypted message queued for ~s: ~s",
                                                    [ToUser, Message]
                                                ),
                                                add_system_message(
                                                    lists:flatten(MsgText),
                                                    ClearUIState
                                                );
                                            {error, Reason} ->
                                                SendErrMsg = io_lib:format(
                                                    "Failed to send encrypted message: ~p",
                                                    [Reason]
                                                ),
                                                add_system_message(
                                                    lists:flatten(SendErrMsg),
                                                    UIState
                                                )
                                        end;
                                    _ ->
                                        add_system_message(
                                            "WebSocket client not available",
                                            UIState
                                        )
                                end;
                            {error, Reason} ->
                                EncryptErrMsg = io_lib:format(
                                    "Failed to encrypt message: ~p", [Reason]
                                ),
                                add_system_message(
                                    lists:flatten(EncryptErrMsg), UIState
                                )
                        end
                    catch
                        _:Error ->
                            ProcessErrMsg = io_lib:format(
                                "Failed to process prekey: ~p", [Error]
                            ),
                            add_system_message(
                                lists:flatten(ProcessErrMsg), UIState
                            )
                    end;
                false ->
                    %% User mismatch - just acknowledge
                    MsgText = io_lib:format(
                        "Received prekey for user ~s (not waiting for this user)",
                        [UserStr]
                    ),
                    add_system_message(lists:flatten(MsgText), UIState)
            end;
        #{
            type := decrypt_room_message,
            sender_user := SenderUser,
            room_id := RoomId,
            ephemeral := EphemeralB64,
            nonce := NonceB64,
            cipher := CipherB64
        } ->
            %% Check if this prekey matches our pending room message decryption
            UserStr = binary_to_list(User),
            case SenderUser =:= UserStr of
                true ->
                    %% This prekey matches our pending room message decryption
                    try
                        %% Decode the sender's public key
                        SenderPubKey = base64:decode(PrekeyB64),

                        %% Decode message components
                        Ephemeral = base64:decode(EphemeralB64),
                        Nonce = base64:decode(NonceB64),
                        Cipher = base64:decode(CipherB64),

                        %% Decrypt the room message using sender's public key
                        case
                            cryptic_client_lib:decrypt_message(
                                {Ephemeral, Nonce, Cipher}, SenderPubKey
                            )
                        of
                            {ok, PlaintextMessage} ->
                                %% Clear pending operation and display message
                                ClearWSChatState = WSChatState#ws_chat_state{
                                    pending_operation = undefined
                                },
                                ClearUIState = UIState#ui_state{
                                    ws_chat_state = ClearWSChatState
                                },
                                SenderText = io_lib:format(
                                    "[~s] ~s", [RoomId, UserStr]
                                ),
                                add_message(
                                    lists:flatten(SenderText),
                                    PlaintextMessage,
                                    ClearUIState
                                );
                            {error, Reason} ->
                                DecryptErrMsg = io_lib:format(
                                    "Failed to decrypt room message from ~s: ~p",
                                    [UserStr, Reason]
                                ),
                                add_system_message(
                                    lists:flatten(DecryptErrMsg), UIState
                                )
                        end
                    catch
                        _:Error ->
                            ProcessErrMsg = io_lib:format(
                                "Failed to process room message prekey: ~p", [
                                    Error
                                ]
                            ),
                            add_system_message(
                                lists:flatten(ProcessErrMsg), UIState
                            )
                    end;
                false ->
                    %% User mismatch - just acknowledge
                    MsgText = io_lib:format(
                        "Received prekey for user ~s (not waiting for this user)",
                        [UserStr]
                    ),
                    add_system_message(lists:flatten(MsgText), UIState)
            end;
        _ ->
            %% No pending operation - just acknowledge
            MsgText = io_lib:format("Received prekey for user ~s", [
                binary_to_list(User)
            ]),
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
                %% Check if this is an encrypted message with the right fields
                case
                    {
                        maps:get(<<"ephemeral">>, NestedMessage, undefined),
                        maps:get(<<"nonce">>, NestedMessage, undefined),
                        maps:get(<<"cipher">>, NestedMessage, undefined)
                    }
                of
                    {undefined, _, _} ->
                        add_system_message(
                            "Received message missing ephemeral key", UIState
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
                        Timestamp = maps:get(
                            <<"timestamp">>,
                            NestedMessage,
                            erlang:system_time(seconds)
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
                                    SharedSecret = cryptic_lib:scalarmult(
                                        PrivKey, EphemeralPub
                                    ),

                                    %% Derive AEAD key using ephemeral public key as salt
                                    AeadKey = cryptic_lib:derive_aead_key_ephemeral(
                                        SharedSecret, EphemeralPub
                                    ),

                                    %% Decrypt message
                                    case
                                        cryptic_lib:aead_decrypt(
                                            Cipher, AeadKey, Nonce, <<>>
                                        )
                                    of
                                        error ->
                                            CryptoErrMsg = io_lib:format(
                                                "Failed to decrypt message from ~s: decryption_failed",
                                                [From]
                                            ),
                                            add_system_message(
                                                lists:flatten(CryptoErrMsg),
                                                UIState
                                            );
                                        PlainBin ->
                                            %% Convert back to string if possible
                                            PlainText =
                                                case
                                                    unicode:characters_to_list(
                                                        PlainBin
                                                    )
                                                of
                                                    % Keep as binary if not valid UTF-8
                                                    {error, _, _} ->
                                                        PlainBin;
                                                    % Keep as binary if incomplete
                                                    {incomplete, _, _} ->
                                                        PlainBin;
                                                    % Convert to string
                                                    List ->
                                                        List
                                                end,

                                            %% Add to inbox and update message count
                                            NewInbox =
                                                UIState#ui_state.inbox ++
                                                    [
                                                        {From, PlainText,
                                                            Timestamp}
                                                    ],
                                            MessageCount = length(NewInbox),

                                            %% Update pending message count for sender
                                            PendingMessages =
                                                UIState#ui_state.pending_messages,
                                            CurrentCount = maps:get(
                                                From, PendingMessages, 0
                                            ),
                                            NewPendingMessages = maps:put(
                                                From,
                                                CurrentCount + 1,
                                                PendingMessages
                                            ),

                                            TempUIState = UIState#ui_state{
                                                inbox = NewInbox,
                                                message_count = MessageCount,
                                                pending_messages =
                                                    NewPendingMessages
                                            },

                                            %% Check auto_display setting
                                            case
                                                UIState#ui_state.auto_display
                                            of
                                                true ->
                                                    %% Show message immediately and clear pending count
                                                    ClearedPendingMessages = maps:put(
                                                        From,
                                                        0,
                                                        NewPendingMessages
                                                    ),
                                                    NewUIState = TempUIState#ui_state{
                                                        pending_messages =
                                                            ClearedPendingMessages
                                                    },
                                                    add_message(
                                                        From,
                                                        PlainText,
                                                        NewUIState
                                                    );
                                                false ->
                                                    %% Just store in inbox, no notification needed
                                                    TempUIState
                                            end
                                    end
                                catch
                                    error:CryptoReason ->
                                        CatchErrMsg = io_lib:format(
                                            "Failed to decrypt message from ~s: ~p",
                                            [From, CryptoReason]
                                        ),
                                        add_system_message(
                                            lists:flatten(CatchErrMsg), UIState
                                        )
                                end;
                            undefined ->
                                add_system_message(
                                    "No keypair available for decryption",
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
%% @doc Input handler process for keyboard input capture.
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
        % Ctrl+C
        3 ->
            MainPid ! {input, quit};
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
        Char when Char >= 32, Char =< 126 ->
            %% Printable character
            MainPid ! {input, {char, Char}};
        _ ->
            %% Ignore other keys
            ok
    end,
    input_handler(MainPid).

%% @private
%% @doc Status updater process for periodic status bar refresh.
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
%% @doc Initialize color pairs for the terminal display.
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
%% @doc Format a line to fit screen width with padding or truncation.
%%
%% Ensures text fits exactly within the screen width by either:
%% <ul>
%%   <li>Truncating long lines to fit the width</li>
%%   <li>Padding short lines with spaces to fill the width</li>
%% </ul>
%%
%% This creates a consistent visual appearance for status bars and
%% other full-width elements.
%%
%% @param Line The text line to format
%% @param Width Target width for the formatted line
%% @returns String exactly `Width' characters long.
format_line(Line, Width) ->
    case length(Line) of
        Len when Len > Width ->
            string:substr(Line, 1, Width);
        Len ->
            Line ++ string:chars($\s, Width - Len)
    end.

%% @private
%% @doc Format a message for display with sender, content, and timestamp.
%%
%% Creates a formatted message line appropriate for the message type:
%% <ul>
%%   <li>System messages: Just the message text</li>
%%   <li>User messages: "&lt;sender&gt;: message [timestamp]" format</li>
%% </ul>
%%
%% The formatted message is truncated to fit the screen width to ensure
%% proper display layout.
%%
%% @param From Sender identifier ("SYSTEM" for system messages, username for user messages)
%% @param Message The message content text
%% @param Timestamp Time string when the message was received/sent
%% @param Width Screen width for text formatting
%% @returns Formatted message string fitting within the specified width.
format_message(From, Message, Timestamp, Width) ->
    case From of
        "SYSTEM" ->
            format_line(Message, Width);
        _ ->
            FormattedMsg = io_lib:format("<~s>: ~s [~s]", [
                From, Message, Timestamp
            ]),
            format_line(lists:flatten(FormattedMsg), Width)
    end.

%% @private
%% @doc Get visible messages for current scroll position.
%%
%% Calculates which messages should be displayed based on the total
%% message history, scroll position, and available display area height.
%% This supports future scrolling functionality to view message history.
%%
%% The algorithm ensures:
%% <ul>
%%   <li>Most recent messages are shown by default</li>
%%   <li>Scrolling can reveal older messages</li>
%%   <li>Display area constraints are respected</li>
%% </ul>
%%
%% @param Messages Complete list of messages in chronological order
%% @param ScrollPos Current scroll position (0 = most recent)
%% @param AreaHeight Number of lines available for message display
%% @returns List of messages that should be visible on screen.
get_visible_messages(Messages, ScrollPos, AreaHeight) ->
    TotalMessages = length(Messages),
    StartIndex = max(1, TotalMessages - AreaHeight - ScrollPos + 1),
    EndIndex = min(TotalMessages, StartIndex + AreaHeight - 1),

    if
        StartIndex =< EndIndex ->
            lists:sublist(Messages, StartIndex, EndIndex - StartIndex + 1);
        true ->
            []
    end.

%% @private
%% @doc Add a user message to the message history.
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

    UIState#ui_state{message_history = CurrentMessages ++ [NewMessage]}.

%% @private
%% @doc Add a system message to the message history.
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

%%% Room Response Handlers

%% @private
%% @doc Handle room_created response from server.
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
%% @doc Handle rooms_list response from server.
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
%% @doc Handle room_joined response from server.
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
%% @doc Handle room_left response from server.
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
%% @doc Handle room_members response from server.
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
%% @doc Handle room_messages response from server.
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
%% @doc Handle incoming room message.
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
        {EphemeralB64, CipherB64, NonceB64} ->
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
                        {ok, ClientState} ->
                            %% Set pending operation for room message decryption
                            PendingOp = #{
                                type => decrypt_room_message,
                                sender_user => From,
                                room_id => RoomName,
                                ephemeral => EphemeralB64,
                                nonce => NonceB64,
                                cipher => CipherB64
                            },

                            %% Request sender's public key (prekey)
                            Command = #{
                                <<"type">> => <<"get_prekey">>,
                                <<"user">> => list_to_binary(From)
                            },

                            cryptic_ws_client:send_command(
                                ClientState#client_state.ws_client_pid, Command
                            ),

                            %% Update UI state with pending decryption
                            UpdatedWSChatState = WSChatState#ws_chat_state{
                                pending_operation = PendingOp
                            },
                            UIState#ui_state{
                                ws_chat_state = UpdatedWSChatState
                            };
                        error ->
                            add_system_message(
                                "No WebSocket connection for key retrieval",
                                UIState
                            )
                    end
            end
    end.

%% @private
%% @doc Handle room message sent confirmation.
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
%% @doc Handle create_room command.
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
%% @doc Handle join_room command.
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
%% @doc Handle leave_room command.
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
%% @doc Handle list_rooms command.
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
%% @doc Handle room_info command.
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
%% @doc Handle room_chat command.
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
%% @doc Handle send_room command.
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
%% @doc Handle room_history command.
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
%% @doc Parse optional arguments for create_room command.
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

%% @private
%% @doc Handle help command with comprehensive command documentation.
%% Format: help [command_name] or help [category]
handle_help_command(Rest, UIState) ->
    HelpTopic = string:strip(Rest),
    case HelpTopic of
        "" ->
            %% General help overview
            HelpState = add_system_message(
                "=== CRYPTIC CHAT CLIENT HELP ===", UIState
            ),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message(
                "Type 'help <command>' for detailed command help", HelpState2
            ),
            HelpState4 = add_system_message(
                "Type 'help <category>' for category help", HelpState3
            ),
            HelpState5 = add_system_message("", HelpState4),
            HelpState6 = add_system_message("COMMAND CATEGORIES:", HelpState5),
            HelpState7 = add_system_message(
                "  connection  - Server connection commands", HelpState6
            ),
            HelpState8 = add_system_message(
                "  messaging   - Direct messaging commands", HelpState7
            ),
            HelpState9 = add_system_message(
                "  rooms       - Chat room commands", HelpState8
            ),
            HelpState10 = add_system_message(
                "  utilities   - Utility and info commands", HelpState9
            ),
            HelpState11 = add_system_message("", HelpState10),
            HelpState12 = add_system_message("QUICK REFERENCE:", HelpState11),
            HelpState13 = add_system_message(
                "  connect                    - Connect to server", HelpState12
            ),
            HelpState14 = add_system_message(
                "  send <user> <message>      - Send direct message",
                HelpState13
            ),
            HelpState15 = add_system_message(
                "  create_room <name>         - Create new room", HelpState14
            ),
            HelpState16 = add_system_message(
                "  join_room <room>           - Join existing room", HelpState15
            ),
            HelpState17 = add_system_message(
                "  room_chat <room>           - Enter room chat mode",
                HelpState16
            ),
            HelpState18 = add_system_message(
                "  list_rooms                 - List available rooms",
                HelpState17
            ),
            HelpState19 = add_system_message(
                "  list_users                 - List online users", HelpState18
            ),
            add_system_message(
                "  help <topic>               - Get detailed help", HelpState19
            );
        "connection" ->
            %% Connection commands help
            HelpState = add_system_message(
                "=== CONNECTION COMMANDS ===", UIState
            ),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message("connect", HelpState2),
            HelpState4 = add_system_message(
                "  Purpose: Connect to the Cryptic chat server", HelpState3
            ),
            HelpState5 = add_system_message("  Usage:   connect", HelpState4),
            HelpState6 = add_system_message("  Example: connect", HelpState5),
            HelpState7 = add_system_message(
                "  Note:    Uses mTLS authentication with client certificates",
                HelpState6
            ),
            HelpState8 = add_system_message("", HelpState7),
            HelpState9 = add_system_message("disconnect", HelpState8),
            HelpState10 = add_system_message(
                "  Purpose: Disconnect from the chat server", HelpState9
            ),
            HelpState11 = add_system_message(
                "  Usage:   disconnect", HelpState10
            ),
            HelpState12 = add_system_message(
                "  Example: disconnect", HelpState11
            ),
            add_system_message(
                "  Note:    Cleanly closes connection and exits chat modes",
                HelpState12
            );
        "messaging" ->
            %% Direct messaging help
            HelpState = add_system_message(
                "=== DIRECT MESSAGING COMMANDS ===", UIState
            ),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message(
                "send <user> <message>", HelpState2
            ),
            HelpState4 = add_system_message(
                "  Purpose: Send a direct message to another user", HelpState3
            ),
            HelpState5 = add_system_message(
                "  Usage:   send <username> <message_text>", HelpState4
            ),
            HelpState6 = add_system_message(
                "  Example: send alice Hello, how are you?", HelpState5
            ),
            HelpState7 = add_system_message(
                "  Example: send bob \"Message with spaces\"", HelpState6
            ),
            HelpState8 = add_system_message("", HelpState7),
            HelpState9 = add_system_message("chat <user>", HelpState8),
            HelpState10 = add_system_message(
                "  Purpose: Enter direct chat mode with a user", HelpState9
            ),
            HelpState11 = add_system_message(
                "  Usage:   chat <username>", HelpState10
            ),
            HelpState12 = add_system_message(
                "  Example: chat alice", HelpState11
            ),
            HelpState13 = add_system_message(
                "  Note:    In chat mode, type messages directly", HelpState12
            ),
            HelpState14 = add_system_message(
                "           Type :exit to leave chat mode", HelpState13
            ),
            HelpState15 = add_system_message("", HelpState14),
            HelpState16 = add_system_message("inbox [count]", HelpState15),
            HelpState17 = add_system_message(
                "  Purpose: View recent direct messages", HelpState16
            ),
            HelpState18 = add_system_message(
                "  Usage:   inbox [number_of_messages]", HelpState17
            ),
            HelpState19 = add_system_message("  Example: inbox", HelpState18),
            HelpState20 = add_system_message(
                "  Example: inbox 20", HelpState19
            ),
            add_system_message(
                "  Note:    Default count is 10 messages", HelpState20
            );
        "rooms" ->
            %% Room commands help
            HelpState = add_system_message(
                "=== CHAT ROOM COMMANDS ===", UIState
            ),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message(
                "create_room <name> [description] [public|private] [password]",
                HelpState2
            ),
            HelpState4 = add_system_message(
                "  Purpose: Create a new chat room", HelpState3
            ),
            HelpState5 = add_system_message(
                "  Usage:   create_room <room_name> [description] [type] [password]",
                HelpState4
            ),
            HelpState6 = add_system_message(
                "  Example: create_room general", HelpState5
            ),
            HelpState7 = add_system_message(
                "  Example: create_room team \"Team discussions\" private",
                HelpState6
            ),
            HelpState8 = add_system_message(
                "  Example: create_room secure \"Secret room\" private mypass123",
                HelpState7
            ),
            HelpState9 = add_system_message("", HelpState8),
            HelpState10 = add_system_message(
                "join_room <room> [password]", HelpState9
            ),
            HelpState11 = add_system_message(
                "  Purpose: Join an existing room", HelpState10
            ),
            HelpState12 = add_system_message(
                "  Usage:   join_room <room_name_or_id> [password]", HelpState11
            ),
            HelpState13 = add_system_message(
                "  Example: join_room general", HelpState12
            ),
            HelpState14 = add_system_message(
                "  Example: join_room room-abc123 mypassword", HelpState13
            ),
            HelpState15 = add_system_message("", HelpState14),
            HelpState16 = add_system_message("leave_room <room>", HelpState15),
            HelpState17 = add_system_message(
                "  Purpose: Leave a joined room", HelpState16
            ),
            HelpState18 = add_system_message(
                "  Usage:   leave_room <room_name_or_id>", HelpState17
            ),
            HelpState19 = add_system_message(
                "  Example: leave_room general", HelpState18
            ),
            HelpState20 = add_system_message("", HelpState19),
            HelpState21 = add_system_message(
                "list_rooms [filter]", HelpState20
            ),
            HelpState22 = add_system_message(
                "  Purpose: List available rooms", HelpState21
            ),
            HelpState23 = add_system_message(
                "  Usage:   list_rooms [public|private|joined|all]", HelpState22
            ),
            HelpState24 = add_system_message(
                "  Example: list_rooms", HelpState23
            ),
            HelpState25 = add_system_message(
                "  Example: list_rooms joined", HelpState24
            ),
            HelpState26 = add_system_message(
                "  Note:    Default filter is 'public'", HelpState25
            ),
            HelpState27 = add_system_message("", HelpState26),
            HelpState28 = add_system_message("room_info <room>", HelpState27),
            HelpState29 = add_system_message(
                "  Purpose: Get detailed room information", HelpState28
            ),
            HelpState30 = add_system_message(
                "  Usage:   room_info <room_name_or_id>", HelpState29
            ),
            HelpState31 = add_system_message(
                "  Example: room_info general", HelpState30
            ),
            HelpState32 = add_system_message("", HelpState31),
            HelpState33 = add_system_message("room_chat <room>", HelpState32),
            HelpState34 = add_system_message(
                "  Purpose: Enter room chat mode", HelpState33
            ),
            HelpState35 = add_system_message(
                "  Usage:   room_chat <room_name_or_id>", HelpState34
            ),
            HelpState36 = add_system_message(
                "  Example: room_chat general", HelpState35
            ),
            HelpState37 = add_system_message(
                "  Note:    Type messages directly, :exit to leave", HelpState36
            ),
            HelpState38 = add_system_message("", HelpState37),
            HelpState39 = add_system_message(
                "send_room <room> <message>", HelpState38
            ),
            HelpState40 = add_system_message(
                "  Purpose: Send a message to a room", HelpState39
            ),
            HelpState41 = add_system_message(
                "  Usage:   send_room <room_name_or_id> <message>", HelpState40
            ),
            HelpState42 = add_system_message(
                "  Example: send_room general Hello everyone!", HelpState41
            ),
            HelpState43 = add_system_message("", HelpState42),
            HelpState44 = add_system_message(
                "room_history <room> [count]", HelpState43
            ),
            HelpState45 = add_system_message(
                "  Purpose: View room message history", HelpState44
            ),
            HelpState46 = add_system_message(
                "  Usage:   room_history <room_name_or_id> [message_count]",
                HelpState45
            ),
            HelpState47 = add_system_message(
                "  Example: room_history general", HelpState46
            ),
            add_system_message(
                "  Example: room_history team-chat 20", HelpState47
            );
        "utilities" ->
            %% Utility commands help
            HelpState = add_system_message("=== UTILITY COMMANDS ===", UIState),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message("list_users", HelpState2),
            HelpState4 = add_system_message(
                "  Purpose: List all online users", HelpState3
            ),
            HelpState5 = add_system_message(
                "  Usage:   list_users", HelpState4
            ),
            HelpState6 = add_system_message(
                "  Example: list_users", HelpState5
            ),
            HelpState7 = add_system_message("", HelpState6),
            HelpState8 = add_system_message(
                "auto_display [on|off]", HelpState7
            ),
            HelpState9 = add_system_message(
                "  Purpose: Toggle automatic message display", HelpState8
            ),
            HelpState10 = add_system_message(
                "  Usage:   auto_display [on|off]", HelpState9
            ),
            HelpState11 = add_system_message(
                "  Example: auto_display on", HelpState10
            ),
            HelpState12 = add_system_message(
                "  Example: auto_display off", HelpState11
            ),
            HelpState13 = add_system_message(
                "  Note:    Controls real-time message display", HelpState12
            ),
            HelpState14 = add_system_message("", HelpState13),
            HelpState15 = add_system_message("help [topic]", HelpState14),
            HelpState16 = add_system_message(
                "  Purpose: Display help information", HelpState15
            ),
            HelpState17 = add_system_message(
                "  Usage:   help [command_name|category]", HelpState16
            ),
            HelpState18 = add_system_message("  Example: help", HelpState17),
            HelpState19 = add_system_message(
                "  Example: help send", HelpState18
            ),
            add_system_message("  Example: help rooms", HelpState19);
        %% Individual command help
        "connect" ->
            HelpState = add_system_message("COMMAND: connect", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Connect to the Cryptic chat server using mTLS",
                HelpState
            ),
            HelpState3 = add_system_message("  Usage:   connect", HelpState2),
            HelpState4 = add_system_message("  Example: connect", HelpState3),
            HelpState5 = add_system_message(
                "  Details: Uses client certificates for authentication",
                HelpState4
            ),
            add_system_message(
                "  Note:    Must be connected before using other commands",
                HelpState5
            );
        "disconnect" ->
            HelpState = add_system_message("COMMAND: disconnect", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Disconnect from the chat server", HelpState
            ),
            HelpState3 = add_system_message(
                "  Usage:   disconnect", HelpState2
            ),
            HelpState4 = add_system_message(
                "  Example: disconnect", HelpState3
            ),
            add_system_message(
                "  Note:    Automatically exits any active chat modes",
                HelpState4
            );
        "send" ->
            HelpState = add_system_message("COMMAND: send", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Send a direct message to another user", HelpState
            ),
            HelpState3 = add_system_message(
                "  Usage:   send <username> <message>", HelpState2
            ),
            HelpState4 = add_system_message("  Examples:", HelpState3),
            HelpState5 = add_system_message(
                "    send alice Hello there!", HelpState4
            ),
            HelpState6 = add_system_message(
                "    send bob \"Message with spaces\"", HelpState5
            ),
            HelpState7 = add_system_message(
                "    send charlie How's the project going?", HelpState6
            ),
            add_system_message(
                "  Note:    Use quotes for messages with multiple words",
                HelpState7
            );
        "chat" ->
            HelpState = add_system_message("COMMAND: chat", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Enter direct chat mode with a specific user",
                HelpState
            ),
            HelpState3 = add_system_message(
                "  Usage:   chat <username>", HelpState2
            ),
            HelpState4 = add_system_message(
                "  Example: chat alice", HelpState3
            ),
            HelpState5 = add_system_message("  In chat mode:", HelpState4),
            HelpState6 = add_system_message(
                "    - Type messages directly to send", HelpState5
            ),
            HelpState7 = add_system_message(
                "    - Type :exit to leave chat mode", HelpState6
            ),
            add_system_message(
                "    - Type :help for chat mode commands", HelpState7
            );
        "create_room" ->
            HelpState = add_system_message("COMMAND: create_room", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Create a new chat room", HelpState
            ),
            HelpState3 = add_system_message(
                "  Usage:   create_room <name> [description] [public|private] [password]",
                HelpState2
            ),
            HelpState4 = add_system_message("  Examples:", HelpState3),
            HelpState5 = add_system_message(
                "    create_room general", HelpState4
            ),
            HelpState6 = add_system_message(
                "    create_room team \"Team discussions\"", HelpState5
            ),
            HelpState7 = add_system_message(
                "    create_room project \"Project chat\" private", HelpState6
            ),
            HelpState8 = add_system_message(
                "    create_room secure \"Secret room\" private mypass123",
                HelpState7
            ),
            HelpState9 = add_system_message("  Parameters:", HelpState8),
            HelpState10 = add_system_message(
                "    name        - Room name (required)", HelpState9
            ),
            HelpState11 = add_system_message(
                "    description - Room description (optional)", HelpState10
            ),
            HelpState12 = add_system_message(
                "    type        - 'public' or 'private' (default: public)",
                HelpState11
            ),
            add_system_message(
                "    password    - Room password for private rooms (optional)",
                HelpState12
            );
        "join_room" ->
            HelpState = add_system_message("COMMAND: join_room", UIState),
            HelpState2 = add_system_message(
                "  Purpose: Join an existing chat room", HelpState
            ),
            HelpState3 = add_system_message(
                "  Usage:   join_room <room_name_or_id> [password]", HelpState2
            ),
            HelpState4 = add_system_message("  Examples:", HelpState3),
            HelpState5 = add_system_message(
                "    join_room general", HelpState4
            ),
            HelpState6 = add_system_message(
                "    join_room work", HelpState5
            ),
            HelpState7 = add_system_message(
                "    join_room private-room mypassword", HelpState6
            ),
            add_system_message(
                "  Note:    Can use room name or ID; password required for private rooms",
                HelpState7
            );
        _ ->
            %% Unknown help topic
            HelpState = add_system_message(
                "Unknown help topic: '" ++ HelpTopic ++ "'", UIState
            ),
            HelpState2 = add_system_message("", HelpState),
            HelpState3 = add_system_message(
                "Available help topics:", HelpState2
            ),
            HelpState4 = add_system_message(
                "  Categories: connection, messaging, rooms, utilities",
                HelpState3
            ),
            HelpState5 = add_system_message(
                "  Commands: connect, disconnect, send, chat, inbox", HelpState4
            ),
            HelpState6 = add_system_message(
                "            create_room, join_room, leave_room, list_rooms",
                HelpState5
            ),
            HelpState7 = add_system_message(
                "            room_info, room_chat, send_room, room_history",
                HelpState6
            ),
            HelpState8 = add_system_message(
                "            list_users, auto_display, help", HelpState7
            ),
            HelpState9 = add_system_message("", HelpState8),
            add_system_message("Type 'help' for general overview", HelpState9)
    end.

%% @private
%% @doc Send an encrypted room message following proper E2EE architecture.
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
%% @doc Encrypt message with sender's private key for room broadcasting.
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
%% @doc Encrypt message for a single room member.
%% @private
%% @doc Get our private key for encryption.
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
%% @doc Send encrypted messages to room members via server.
add_system_message(Message, UIState) ->
    {{_Year, _Month, _Day}, {Hour, Min, Sec}} = calendar:local_time(),
    Timestamp = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),

    NewMessage = {"SYSTEM", Message, lists:flatten(Timestamp)},
    CurrentMessages = UIState#ui_state.message_history,

    UIState#ui_state{message_history = CurrentMessages ++ [NewMessage]}.

%% @private
%% @doc Cleanup UI resources on exit.
%%
%% Properly shuts down the ncurses interface and restores the terminal
%% to its original state. This should be called before the application
%% exits to ensure the terminal is left in a usable state.
cleanup_ui() ->
    cecho:endwin().
