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

%% Client state record from cryptic_ws_client_lib
-record(client_state, {
    ws_client_pid,
    username,
    keypair
}).

%% @doc WebSocket chat state record containing connection and user information.
%%
%% This record maintains the core state for WebSocket mTLS operations including
%% certificate configuration, server connection details, and message monitoring.
%%
%% @type ws_chat_state() = #ws_chat_state{
%%   server_host :: string(),
%%   server_port :: pos_integer(),
%%   username :: string() | undefined,
%%   cert_config :: #{atom() => string()},
%%   ws_client_state :: term() | undefined,
%%   keypair :: {binary(), binary()} | undefined,
%%   connection_status :: connected | disconnected | connecting
%% }.
-record(ws_chat_state, {
    server_host = "localhost" :: string(),
    server_port = 8443 :: pos_integer(),
    username :: string() | undefined,
    cert_config :: #{atom() => string()},
    ws_client_state :: term() | undefined,
    keypair :: {binary(), binary()} | undefined,
    connection_status = disconnected :: connected | disconnected | connecting,
    pending_operation :: map() | undefined
}).

%% @doc UI state record containing screen layout and interaction state.
%%
%% This record manages all UI-specific state including screen dimensions,
%% message display, input handling, and WebSocket communication.
%%
%% @type ui_state() = #ui_state{
%%   ws_chat_state :: #ws_chat_state{},
%%   screen_height :: integer(),
%%   screen_width :: integer(),
%%   message_history :: [{string(), string(), string()}],
%%   scroll_position :: integer(),
%%   command_history :: [string()],
%%   current_input :: string(),
%%   input_pid :: pid(),
%%   status_pid :: pid(),
%%   chat_mode :: boolean(),
%%   chat_target :: string() | undefined
%% }.
-record(ui_state, {
    ws_chat_state :: #ws_chat_state{},
    screen_height :: integer(),
    screen_width :: integer(),
    message_history = [] :: [{string(), string(), string()}], % {From, Message, Timestamp}
    scroll_position = 0 :: integer(),
    command_history = [] :: [string()],
    current_input = "" :: string(),
    input_pid :: pid(),
    status_pid :: pid(),
    
    %% Chat mode state
    chat_mode = false :: boolean(),               % Whether in chat mode
    chat_target :: string() | undefined,         % Username being chatted with
    
    %% Inbox for encrypted messages
    inbox = [] :: [{string(), string(), integer()}], % {From, Message, Timestamp}
    message_count = 0 :: integer(),               % Number of messages in inbox
    
    %% Auto-display control
    auto_display = true :: boolean(),             % Whether to auto-display incoming messages
    pending_messages = #{} :: #{string() => integer()} % Count of pending messages per user
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
%% @throws Any exception that occurs during initialization or operation.
-spec start(string(), string()) -> ok.
start(Username, ServerHost) ->
    %% Start cecho first (handles ncurses initialization)
    ok = application:start(cecho),

    %% Start other required applications
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(gun),

    %% Start the event manager for logging
    {ok, _} = gen_event:start_link({local, cryptic_event_manager}),

    %% Set up event handlers for UI client with client configuration
    cryptic_event_manager:setup_event_handlers(#{log_type => client, log_dir => "logs"}),

    %% Configure cecho settings
    ok = cecho:start_color(),
    ok = cecho:noecho(),
    ok = cecho:cbreak(),
    ok = cecho:keypad(?ceSTDSCR, true),
    ok = cecho:curs_set(?ceCURS_NORMAL),  % Make cursor visible

    %% Initialize color pairs
    init_colors(),

    %% Get screen dimensions
    {Height, Width} = cecho:getmaxyx(),

    %% Create certificate configuration using environment variables
    CertFile = case os:getenv("CRYPTIC_CLIENT_CERT") of
        false -> "CA/client_keys/" ++ Username ++ ".crt";
        EnvCert -> EnvCert
    end,
    KeyFile = case os:getenv("CRYPTIC_CLIENT_KEY") of
        false -> "CA/client_keys/" ++ Username ++ ".key";
        EnvKey -> EnvKey
    end,
    CAFile = case os:getenv("CRYPTIC_CA_CERT") of
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
        connection_status = disconnected
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
    WelcomeState = add_system_message("=== CRYPTIC WEBSOCKET mTLS CHAT ===", UpdatedUIState),
    WelcomeState2 = add_system_message("Server: " ++ ServerHost ++ ":8443", WelcomeState),
    WelcomeState3 = add_system_message("Certificate: " ++ Username, WelcomeState2),
    WelcomeState4 = add_system_message("Type 'connect' to establish WebSocket mTLS connection", WelcomeState3),
    WelcomeState5 = add_system_message("Type 'help' for commands", WelcomeState4),

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
            cecho:refresh(),

            %% Reposition cursor after status bar update
            position_cursor(UIState),

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
            DecryptUIState = handle_encrypted_message_received(Message, UIState),
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
    #ui_state{current_input = Input, screen_height = Height} = UIState,
    Prompt = "> ",
    CursorX = length(Prompt ++ Input),
    cecho:move(Height - 1, CursorX).

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
    
    %% Draw input line (line Height-1) - but don't position cursor yet
    draw_input_line(UIState),
    
    %% Refresh screen first to update physical display
    cecho:refresh(),
    
    %% NOW position cursor after refresh
    position_cursor(UIState).

%% @private
%% @doc Draw the status bar at the top showing WebSocket connection and user info.
%%
%% The status bar displays:
%% <ul>
%%   <li>Application name and server URL</li>
%%   <li>Current certificate user and connection status</li>
%%   <li>Chat mode status and target user</li>
%%   <li>WebSocket mTLS connection indicator</li>
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
    
    %% Save current cursor position
    {CurY, CurX} = cecho:getyx(),
    
    %% Get current time
    {_, {Hour, Min, Sec}} = calendar:local_time(),
    TimeStr = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),
    
    %% Get user info and connection status
    UserStr = case WSChatState#ws_chat_state.username of
        undefined -> "No cert";
        User -> "Cert: " ++ User
    end,
    
    %% Get connection status
    ConnStatusStr = case WSChatState#ws_chat_state.connection_status of
        connected -> " | Connected";
        connecting -> " | Connecting...";
        disconnected -> " | Disconnected"
    end,
    
    %% Get chat mode status and message count
    ChatModeStr = case UIState#ui_state.chat_mode of
        false -> "";
        true -> 
            case UIState#ui_state.chat_target of
                undefined -> " | Chat mode";
                Target -> " | Chat with: " ++ Target
            end
    end,
    
    %% Get pending message count
    PendingCount = maps:fold(fun(_, Count, Acc) -> Acc + Count end, 0, UIState#ui_state.pending_messages),
    MessageCountStr = case PendingCount of
        0 -> "";
        N -> " | Msgs: " ++ integer_to_list(N)
    end,
    
    %% Create status line
    ServerStr = WSChatState#ws_chat_state.server_host ++ ":8443",
    StatusLine = io_lib:format("CRYPTIC WS mTLS | ~s | ~s~s~s~s | ~s", 
                              [ServerStr, UserStr, ConnStatusStr, ChatModeStr, MessageCountStr, TimeStr]),
    
    %% Truncate or pad to screen width
    StatusLineFmt = format_line(lists:flatten(StatusLine), Width),
    
    %% Draw with status bar colors
    cecho:attron(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)),
    cecho:mvaddstr(0, 0, StatusLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)),
    
    %% Restore cursor position
    cecho:move(CurY, CurX).

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
    ColorPair = case From of
        "SYSTEM" -> ?COLOR_SYSTEM_MESSAGE;
        CurrentUser -> ?COLOR_OWN_MESSAGE;
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
    HelpLine = case {WSChatState#ws_chat_state.connection_status, UIState#ui_state.chat_mode} of
        {disconnected, _} ->
            "Commands: connect | help | quit";
        {connected, false} ->
            "Commands: help | send <user> <msg> | chat <user> | list_users | disconnect | quit";
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
        screen_height = Height,
        screen_width = Width
    } = UIState,
    
    %% Create input line with prompt
    Prompt = "> ",
    InputLine = Prompt ++ Input,
    
    %% Truncate if too long
    DisplayLine = case length(InputLine) of
        Len when Len > Width ->
            string:substr(InputLine, 1, Width);
        _ ->
            InputLine
    end,
    
    %% Clear the input line by overwriting with spaces first
    ClearLine = string:chars($ , Width),
    cecho:attron(?ceCOLOR_PAIR(?COLOR_INPUT)),
    cecho:mvaddstr(Height - 1, 0, ClearLine),
    
    %% Now draw the actual input content
    cecho:mvaddstr(Height - 1, 0, DisplayLine),
    
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_INPUT)).

%%%===================================================================
%%% Input Handling
%%%===================================================================

%% @private
%% @doc Handle user input events from the input handler process.
%%
%% Processes different types of input:
%% <ul>
%%   <li>`quit' - Initiates graceful shutdown</li>
%%   <li>`{char, Char}' - Adds printable characters to input buffer</li>
%%   <li>`{key, 10}' - Enter key processes current command</li>
%%   <li>`{key, backspace}' - Removes last character from input</li>
%% </ul>
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
            %% Add character to input
            CurrentInput = UIState#ui_state.current_input,
            NewInput = CurrentInput ++ [Char],
            UIState#ui_state{current_input = NewInput};
        {key, 10} ->  % Enter key (ASCII 10)
            %% Process command and clear input
            Command = UIState#ui_state.current_input,
            ProcessedUIState = process_command(Command, UIState),
            ProcessedUIState#ui_state{current_input = ""};
        {key, ?ceKEY_BACKSPACE} ->
            %% Remove last character
            CurrentInput = UIState#ui_state.current_input,
            NewInput = case length(CurrentInput) of
                0 -> "";
                Len -> string:substr(CurrentInput, 1, Len - 1)
            end,
            UIState#ui_state{current_input = NewInput};
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
        undefined -> ok;
        {ok, ClientState} ->
            cryptic_ws_client:stop(ClientState#client_state.ws_client_pid);
        _ ->
            ok
    end,
    self() ! quit,
    UIState;
process_command("help", UIState) ->
    %% Show help based on connection status
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        disconnected ->
            HelpState = add_system_message("=== WEBSOCKET mTLS COMMANDS ===", UIState),
            HelpState2 = add_system_message("connect - Establish mTLS WebSocket connection", HelpState),
            HelpState3 = add_system_message("help - Show this help", HelpState2),
            HelpState4 = add_system_message("quit - Exit application", HelpState3),
            HelpState4;
        connected ->
            HelpState = add_system_message("=== CONNECTED COMMANDS ===", UIState),
            HelpState2 = add_system_message("send <user> <message> - Send encrypted message", HelpState),
            HelpState3 = add_system_message("chat <user> - Enter chat mode with user", HelpState2),
            HelpState4 = add_system_message("list_users - List all registered users", HelpState3),
            HelpState5 = add_system_message("inbox - Show message counts by sender", HelpState4),
            HelpState6 = add_system_message("inbox <user> - Show messages from specific user", HelpState5),
            HelpState7 = add_system_message("auto_display on/off - Control message display", HelpState6),
            HelpState8 = add_system_message("disconnect - Close WebSocket connection", HelpState7),
            HelpState9 = add_system_message("quit - Exit application", HelpState8),
            HelpState10 = add_system_message("In chat mode: :exit to leave, :help for commands", HelpState9),
            HelpState10;
        connecting ->
            add_system_message("Please wait for connection to complete...", UIState)
    end;
process_command("connect", UIState) ->
    %% Establish WebSocket mTLS connection
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.connection_status of
        connected ->
            add_system_message("Already connected to WebSocket server", UIState);
        connecting ->
            add_system_message("Connection already in progress", UIState);
        disconnected ->
            %% Update status to connecting
            NewWSChatState = WSChatState#ws_chat_state{connection_status = connecting},
            ConnectingUIState = UIState#ui_state{ws_chat_state = NewWSChatState},
            ConnectingState = add_system_message("Connecting to WebSocket mTLS server...", ConnectingUIState),
            
            %% Attempt to connect
            Username = WSChatState#ws_chat_state.username,
            ServerHost = WSChatState#ws_chat_state.server_host,
            CertConfig = WSChatState#ws_chat_state.cert_config,
            
            case cryptic_ws_client:start_link(Username, ServerHost, CertConfig) of
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
                    cryptic_ws_client:set_ui_pid(ClientState#client_state.ws_client_pid, self()),
                    
                    %% Upload the public key to the server
                    case cryptic_ws_client:send_command(ClientPid, #{
                        type => <<"upload_prekey">>,
                        prekey => base64:encode(PubKey)
                    }) of
                        ok ->
                            SuccessWSChatState = NewWSChatState#ws_chat_state{
                                connection_status = connected,
                                ws_client_state = {ok, ClientState},
                                keypair = {PubKey, PrivKey}
                            },
                            SuccessUIState = ConnectingState#ui_state{ws_chat_state = SuccessWSChatState},
                            SuccessState = add_system_message("WebSocket mTLS connection established!", SuccessUIState),
                            SuccessState2 = add_system_message("Authenticated as: " ++ Username, SuccessState),
                            SuccessState3 = add_system_message("Keypair generated and uploaded to server", SuccessState2),
                            SuccessState3;
                        queued ->
                            %% Prekey upload queued until WebSocket connection is ready
                            SuccessWSChatState = NewWSChatState#ws_chat_state{
                                connection_status = connected,
                                ws_client_state = {ok, ClientState},
                                keypair = {PubKey, PrivKey}
                            },
                            SuccessUIState = ConnectingState#ui_state{ws_chat_state = SuccessWSChatState},
                            SuccessState = add_system_message("WebSocket mTLS connection established!", SuccessUIState),
                            SuccessState2 = add_system_message("Authenticated as: " ++ Username, SuccessState),
                            SuccessState3 = add_system_message("Keypair generated, prekey upload queued...", SuccessState2),
                            SuccessState3;
                        {error, UploadReason} ->
                            ErrMsg = io_lib:format("Failed to upload prekey: ~p", [UploadReason]),
                            FailState = add_system_message(lists:flatten(ErrMsg), ConnectingState),
                            FailState
                    end;
                {error, Reason} ->
                    %% Connection failed
                    FailWSChatState = NewWSChatState#ws_chat_state{connection_status = disconnected},
                    FailUIState = ConnectingState#ui_state{ws_chat_state = FailWSChatState},
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
                    cryptic_ws_client:stop(ClientState#client_state.ws_client_pid),
                    
                    %% Update state
                    NewWSChatState = WSChatState#ws_chat_state{
                        connection_status = disconnected,
                        ws_client_state = undefined
                    },
                    DisconnectedUIState = UIState#ui_state{ws_chat_state = NewWSChatState},
                    add_system_message("Disconnected from WebSocket server", DisconnectedUIState);
                _ ->
                    %% Invalid state, reset
                    NewWSChatState = WSChatState#ws_chat_state{
                        connection_status = disconnected,
                        ws_client_state = undefined
                    },
                    ResetUIState = UIState#ui_state{ws_chat_state = NewWSChatState},
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
                    case cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, #{
                        type => <<"list_users">>
                    }) of
                        ok ->
                            add_system_message("Requesting user list...", UIState);
                        queued ->
                            add_system_message("User list request queued...", UIState);
                        {error, Reason} ->
                            ErrMsg = io_lib:format("Failed to request user list: ~p", [Reason]),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message("WebSocket client not available", UIState)
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
                            case cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, #{
                                type => <<"get_prekey">>,
                                user => list_to_binary(TrimmedToUser)
                            }) of
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
                                    UIState#ui_state{ws_chat_state = NewWSChatState};
                                {error, Reason} ->
                                    ErrMsg = io_lib:format("Failed to get prekey for ~s: ~p", [TrimmedToUser, Reason]),
                                    add_system_message(lists:flatten(ErrMsg), UIState)
                            end;
                        _ ->
                            add_system_message("WebSocket client not available", UIState)
                    end;
                _ ->
                    add_system_message("Usage: send <username> <message>", UIState)
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
                    Msg = io_lib:format("Entering chat mode with ~s. Type ':exit' to leave chat mode.", [TrimmedUser]),
                    add_system_message(lists:flatten(Msg), NewUIState)
            end;
        _ ->
            add_system_message("Not connected. Use 'connect' first.", UIState)
    end;
process_command("auto_display on", UIState) ->
    NewState = UIState#ui_state{auto_display = true},
    StatusState = add_system_message("Auto-display enabled: messages will appear immediately", NewState),
    
    %% Check if there are any pending messages to display
    case UIState#ui_state.pending_messages of
        Empty when Empty =:= #{} ->
            %% No pending messages
            StatusState;
        PendingMessages ->
            %% Show all pending messages and clear the pending counts
            TotalPending = maps:fold(fun(_, Count, Acc) -> Acc + Count end, 0, PendingMessages),
            case TotalPending > 0 of
                true ->
                    %% Show pending messages notification
                    NotifyState = add_system_message("=== DISPLAYING PENDING MESSAGES ===", StatusState),
                    
                    %% Display messages from inbox for each sender with pending count > 0
                    FinalState = maps:fold(fun(From, Count, AccState) ->
                        case Count > 0 of
                            true ->
                                %% Get messages from this sender
                                SenderMessages = [Msg || {MsgFrom, _, _} = Msg <- UIState#ui_state.inbox, MsgFrom =:= From],
                                %% Display the most recent messages up to the pending count
                                RecentMessages = lists:sublist(lists:reverse(SenderMessages), Count),
                                lists:foldl(fun({MsgFrom, Message, _Timestamp}, State) ->
                                    add_message(MsgFrom, Message, State)
                                end, AccState, lists:reverse(RecentMessages));
                            false ->
                                AccState
                        end
                    end, NotifyState, PendingMessages),
                    
                    %% Clear all pending message counts
                    FinalState#ui_state{pending_messages = #{}};
                false ->
                    StatusState
            end
    end;
process_command("auto_display off", UIState) ->
    NewState = UIState#ui_state{auto_display = false},
    add_system_message("Auto-display disabled: messages stored in inbox", NewState);
process_command("auto_display", UIState) ->
    Status = case UIState#ui_state.auto_display of
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
                    PendingWithMessages = maps:filter(fun(_, Count) -> Count > 0 end, PendingMessages),
                    case maps:size(PendingWithMessages) of
                        0 ->
                            add_system_message("Inbox is empty", UIState);
                        _ ->
                            InboxState = add_system_message("=== INBOX SUMMARY ===", UIState),
                            InboxState2 = add_system_message("From                 Messages", InboxState),
                            InboxState3 = add_system_message("----                 --------", InboxState2),
                            FinalState = lists:foldl(fun({From, Count}, AccState) ->
                                Line = io_lib:format("~-20s ~w", [From, Count]),
                                add_system_message(lists:flatten(Line), AccState)
                            end, InboxState3, lists:sort(maps:to_list(PendingWithMessages))),
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
                    SenderMessages = [Msg || {From, _, _} = Msg <- Messages, From =:= Sender],
                    case SenderMessages of
                        [] ->
                            add_system_message("No messages from " ++ Sender, UIState);
                        _ ->
                            InboxState = add_system_message("=== MESSAGES FROM " ++ string:uppercase(Sender) ++ " ===", UIState),
                            FinalState = lists:foldl(fun({_From, Message, Timestamp}, AccState) ->
                                TimeStr = format_timestamp(Timestamp),
                                MsgText = io_lib:format("[~s] ~s", [TimeStr, Message]),
                                add_system_message(lists:flatten(MsgText), AccState)
                            end, InboxState, SenderMessages),
                            %% Clear pending message count for this sender
                            UpdatedPendingMessages = maps:put(Sender, 0, UIState#ui_state.pending_messages),
                            FinalState#ui_state{pending_messages = UpdatedPendingMessages}
                    end
            end
    end;
process_command(Command, UIState) ->
    %% Check if we're in chat mode
    case UIState#ui_state.chat_mode of
        true ->
            process_chat_command(Command, UIState);
        false ->
            %% Unknown command
            add_system_message("Unknown command: " ++ Command, UIState)
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
    HelpState4 = add_system_message("Any other text - Send as message", HelpState3),
    HelpState4;
process_chat_command(":" ++ Command, UIState) ->
    %% Unknown chat command
    add_system_message("Unknown chat command: :" ++ Command, UIState);
process_chat_command(Message, UIState) ->
    %% Send encrypted message to chat target via WebSocket
    WSChatState = UIState#ui_state.ws_chat_state,
    case {WSChatState#ws_chat_state.connection_status, UIState#ui_state.chat_target} of
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
                    case cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, #{
                        type => <<"get_prekey">>,
                        user => list_to_binary(ToUser)
                    }) of
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
                            QueuedState = add_system_message("Message queued for encryption...", UIState),
                            QueuedState#ui_state{ws_chat_state = NewWSChatState};
                        {error, Reason} ->
                            ErrMsg = io_lib:format("Failed to get prekey for ~s: ~p", [ToUser, Reason]),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end;
                _ ->
                    add_system_message("WebSocket client not available", UIState)
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
            try
                Data = jsx:decode(JsonText, [return_maps]),
                case maps:get(<<"type">>, Data, undefined) of
                    <<"message">> ->
                        %% Incoming chat message
                        From = binary_to_list(maps:get(<<"from">>, Data, <<"unknown">>)),
                        Content = binary_to_list(maps:get(<<"message">>, Data, <<"">>)),
                        add_message(From, Content, UIState);
                    <<"users">> ->
                        %% User list response
                        Users = maps:get(<<"users">>, Data, []),
                        UsersState = add_system_message("Available users:", UIState),
                        lists:foldl(fun(User, AccState) ->
                            add_system_message("  - " ++ binary_to_list(User), AccState)
                        end, UsersState, Users);
                    <<"prekey">> ->
                        %% Prekey response - handle pending encrypted send
                        handle_prekey_response(Data, UIState);
                    <<"success">> ->
                        %% Success response
                        Content = binary_to_list(maps:get(<<"message">>, Data, <<"Operation successful">>)),
                        add_system_message("Success: " ++ Content, UIState);
                    <<"error">> ->
                        %% Error response
                        Content = binary_to_list(maps:get(<<"message">>, Data, <<"Unknown error">>)),
                        add_system_message("Error: " ++ Content, UIState);
                    <<"system">> ->
                        %% System message
                        Content = binary_to_list(maps:get(<<"message">>, Data, <<"System message">>)),
                        add_system_message(Content, UIState);
                    _ ->
                        %% Unknown message type
                        add_system_message("Received unknown message type", UIState)
                end
            catch
                _:_ ->
                    add_system_message("Received invalid JSON message", UIState)
            end;
        {binary, _Data} ->
            add_system_message("Received binary WebSocket message", UIState);
        _ ->
            add_system_message("Received unknown WebSocket message format", UIState)
    end.

%% @doc Handle prekey response and complete the encrypted message send.
%%
%% When we receive a prekey response from the server, we can now encrypt
%% and send the pending message securely.
handle_prekey_response(Data, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{type := send_encrypted, to_user := ToUser, message := Message, from_user := FromUser} ->
            case maps:get(<<"prekey">>, Data, undefined) of
                undefined ->
                    add_system_message("Error: No prekey in response", UIState);
                PrekeyB64 ->
                    try
                        %% Decode the recipient's public key
                        RecipientPubKey = base64:decode(PrekeyB64),
                        
                        %% Encrypt the message
                        case cryptic_client_lib:encrypt_message(Message, RecipientPubKey) of
                            {ok, {EphPub, Nonce, Cipher}} ->
                                %% Send the encrypted message
                                case WSChatState#ws_chat_state.ws_client_state of
                                    {ok, ClientState} ->
                                        case cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, #{
                                            type => <<"send_message">>,
                                            from => list_to_binary(FromUser),
                                            to => list_to_binary(ToUser),
                                            ephemeral => base64:encode(EphPub),
                                            nonce => base64:encode(Nonce),
                                            cipher => base64:encode(Cipher)
                                        }) of
                                            ok ->
                                                %% Clear pending operation and show success
                                                ClearWSChatState = WSChatState#ws_chat_state{
                                                    pending_operation = undefined
                                                },
                                                ClearUIState = UIState#ui_state{ws_chat_state = ClearWSChatState},
                                                SenderText = io_lib:format("You -> ~s", [ToUser]),
                                                add_message(lists:flatten(SenderText), Message, ClearUIState);
                                            {error, Reason} ->
                                                SendErrMsg = io_lib:format("Failed to send encrypted message: ~p", [Reason]),
                                                add_system_message(lists:flatten(SendErrMsg), UIState)
                                        end;
                                    _ ->
                                        add_system_message("WebSocket client not available", UIState)
                                end;
                            {error, Reason} ->
                                EncryptErrMsg = io_lib:format("Failed to encrypt message: ~p", [Reason]),
                                add_system_message(lists:flatten(EncryptErrMsg), UIState)
                        end
                    catch
                        _:Error ->
                            ProcessErrMsg = io_lib:format("Failed to process prekey: ~p", [Error]),
                            add_system_message(lists:flatten(ProcessErrMsg), UIState)
                    end
            end;
        _ ->
            %% No pending operation or wrong type
            add_system_message("Received unexpected prekey response", UIState)
    end.

%% @doc Handle prekey received from WebSocket client for immediate encryption.
%%
%% This function handles prekeys received asynchronously from the server
%% when another user's public key is needed for message encryption.
handle_prekey_received(User, PrekeyB64, UIState) ->
    WSChatState = UIState#ui_state.ws_chat_state,
    case WSChatState#ws_chat_state.pending_operation of
        #{type := send_encrypted, to_user := ToUser, message := Message, from_user := FromUser} ->
            %% Check if this prekey matches our pending send operation
            UserStr = binary_to_list(User),
            case ToUser =:= UserStr of
                true ->
                    %% This prekey matches our pending send operation
            try
                %% Decode the recipient's public key
                RecipientPubKey = base64:decode(PrekeyB64),
                
                %% Encrypt the message
                case cryptic_client_lib:encrypt_message(Message, RecipientPubKey) of
                    {ok, {EphPub, Nonce, Cipher}} ->
                        %% Send the encrypted message
                        case WSChatState#ws_chat_state.ws_client_state of
                            {ok, ClientState} ->
                                case cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, #{
                                    type => <<"send_message">>,
                                    from => list_to_binary(FromUser),
                                    to => list_to_binary(ToUser),
                                    ephemeral => base64:encode(EphPub),
                                    nonce => base64:encode(Nonce),
                                    cipher => base64:encode(Cipher)
                                }) of
                                    ok ->
                                        %% Clear pending operation and show success
                                        ClearWSChatState = WSChatState#ws_chat_state{
                                            pending_operation = undefined
                                        },
                                        ClearUIState = UIState#ui_state{ws_chat_state = ClearWSChatState},
                                        SenderText = io_lib:format("You -> ~s", [ToUser]),
                                        add_message(lists:flatten(SenderText), Message, ClearUIState);
                                    queued ->
                                        %% Message queued, clear pending operation
                                        ClearWSChatState = WSChatState#ws_chat_state{
                                            pending_operation = undefined
                                        },
                                        ClearUIState = UIState#ui_state{ws_chat_state = ClearWSChatState},
                                        MsgText = io_lib:format("Encrypted message queued for ~s: ~s", [ToUser, Message]),
                                        add_system_message(lists:flatten(MsgText), ClearUIState);
                                    {error, Reason} ->
                                        SendErrMsg = io_lib:format("Failed to send encrypted message: ~p", [Reason]),
                                        add_system_message(lists:flatten(SendErrMsg), UIState)
                                end;
                            _ ->
                                add_system_message("WebSocket client not available", UIState)
                        end;
                    {error, Reason} ->
                        EncryptErrMsg = io_lib:format("Failed to encrypt message: ~p", [Reason]),
                        add_system_message(lists:flatten(EncryptErrMsg), UIState)
                end
            catch
                _:Error ->
                    ProcessErrMsg = io_lib:format("Failed to process prekey: ~p", [Error]),
                    add_system_message(lists:flatten(ProcessErrMsg), UIState)
            end;
                false ->
                    %% User mismatch - just acknowledge
                    MsgText = io_lib:format("Received prekey for user ~s (not waiting for this user)", [UserStr]),
                    add_system_message(lists:flatten(MsgText), UIState)
            end;
        _ ->
            %% No pending operation - just acknowledge
            MsgText = io_lib:format("Received prekey for user ~s", [binary_to_list(User)]),
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
                add_system_message("Received message without message field", UIState);
            NestedMessage ->
                %% Check if this is an encrypted message with the right fields
                case {maps:get(<<"ephemeral">>, NestedMessage, undefined),
                      maps:get(<<"nonce">>, NestedMessage, undefined),
                      maps:get(<<"cipher">>, NestedMessage, undefined)} of
                    {undefined, _, _} ->
                        add_system_message("Received message missing ephemeral key", UIState);
                    {_, undefined, _} ->
                        add_system_message("Received message missing nonce", UIState);
                    {_, _, undefined} ->
                        add_system_message("Received message missing cipher", UIState);
                    {EphemeralB64, NonceB64, CipherB64} ->
                        Timestamp = maps:get(<<"timestamp">>, NestedMessage, erlang:system_time(seconds)),
                        
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
                                    AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPub),
                                    
                                    %% Decrypt message
                                    case cryptic_lib:aead_decrypt(Cipher, AeadKey, Nonce, <<>>) of
                                        error ->
                                            CryptoErrMsg = io_lib:format("Failed to decrypt message from ~s: decryption_failed", [From]),
                                            add_system_message(lists:flatten(CryptoErrMsg), UIState);
                                        PlainBin ->
                                            %% Convert back to string if possible
                                            PlainText = case unicode:characters_to_list(PlainBin) of
                                                {error, _, _} -> PlainBin;  % Keep as binary if not valid UTF-8
                                                {incomplete, _, _} -> PlainBin;  % Keep as binary if incomplete
                                                List -> List  % Convert to string
                                            end,
                                            
                                            %% Add to inbox and update message count
                                            NewInbox = UIState#ui_state.inbox ++ [{From, PlainText, Timestamp}],
                                            MessageCount = length(NewInbox),
                                            
                                            %% Update pending message count for sender
                                            PendingMessages = UIState#ui_state.pending_messages,
                                            CurrentCount = maps:get(From, PendingMessages, 0),
                                            NewPendingMessages = maps:put(From, CurrentCount + 1, PendingMessages),
                                            
                                            TempUIState = UIState#ui_state{
                                                inbox = NewInbox,
                                                message_count = MessageCount,
                                                pending_messages = NewPendingMessages
                                            },
                                            
                                            %% Check auto_display setting
                                            case UIState#ui_state.auto_display of
                                                true ->
                                                    %% Show message immediately and clear pending count
                                                    ClearedPendingMessages = maps:put(From, 0, NewPendingMessages),
                                                    NewUIState = TempUIState#ui_state{pending_messages = ClearedPendingMessages},
                                                    add_message(From, PlainText, NewUIState);
                                                false ->
                                                    %% Just store in inbox, no notification needed
                                                    TempUIState
                                            end
                                    end
                                catch
                                    error:CryptoReason ->
                                        CatchErrMsg = io_lib:format("Failed to decrypt message from ~s: ~p", [From, CryptoReason]),
                                        add_system_message(lists:flatten(CatchErrMsg), UIState)
                                end;
                            undefined ->
                                add_system_message("No keypair available for decryption", UIState)
                        end
                end
        end
    catch
        _:Error ->
            %% Log the actual message structure for debugging
            ProcessErrMsg = io_lib:format("Failed to process encrypted message: ~p. Message was: ~p", [Error, Message]),
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
            lists:foldl(fun(User, AccState) ->
                UserStr = case is_binary(User) of
                    true -> binary_to_list(User);
                    false -> User
                end,
                add_system_message("  - " ++ UserStr, AccState)
            end, UsersState, Users)
    end.

%% @doc Format timestamp for display.
format_timestamp(Timestamp) ->
    {{Year, Month, Day}, {Hour, Minute, Second}} = 
        calendar:gregorian_seconds_to_datetime(Timestamp + 719528 * 24 * 3600),
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w", 
                  [Year, Month, Day, Hour, Minute, Second]).

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
%%   <li>Printable characters (32-126) - Text input</li>
%%   <li>Other keys - Ignored for now</li>
%% </ul>
%%
%% The process runs in an infinite loop and is linked to the main process
%% for automatic cleanup on exit.
%%
%% @param MainPid PID of the main UI process to send input events to.
input_handler(MainPid) ->
    case cecho:getch() of
        3 ->  % Ctrl+C
            MainPid ! {input, quit};
        10 ->  % Enter
            MainPid ! {input, {key, 10}};
        ?ceKEY_BACKSPACE ->
            MainPid ! {input, {key, ?ceKEY_BACKSPACE}};
        127 ->  % Sometimes backspace is 127
            MainPid ! {input, {key, ?ceKEY_BACKSPACE}};
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
            Line ++ string:chars($ , Width - Len)
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
            FormattedMsg = io_lib:format("<~s>: ~s [~s]", [From, Message, Timestamp]),
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
    
    if StartIndex =< EndIndex ->
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
