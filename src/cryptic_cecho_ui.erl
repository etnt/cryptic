%%% @doc Cryptic Chat Terminal User Interface
%%%
%%% This module provides a full-screen terminal-based user interface for the
%%% Cryptic chat application using the cecho (ncurses) library. It implements
%%% a modern chat interface with real-time messaging, status updates, and
%%% interactive features.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Full-screen terminal UI with status bar, message area, and input line</li>
%%%   <li>Real-time chat mode for one-on-one conversations</li>
%%%   <li>Automatic message count peeking without consuming messages</li>
%%%   <li>Color-coded message display for better readability</li>
%%%   <li>Command-based interface with help system</li>
%%%   <li>Background polling for new messages in chat mode</li>
%%%   <li>Persistent message history during session</li>
%%% </ul>
%%%
%%% == Architecture ==
%%%
%%% The UI uses a main event loop with helper processes:
%%% <ul>
%%%   <li>`ui_main_loop/1' - Main event processing loop</li>
%%%   <li>`input_handler/1' - Dedicated process for keyboard input</li>
%%%   <li>`status_updater/1' - Timer-based status bar updates</li>
%%%   <li>Auto-peek timer - Background message count checking</li>
%%%   <li>Chat poll timer - Real-time message polling in chat mode</li>
%%% </ul>
%%%
%%% == Screen Layout ==
%%%
%%% ```
%%% +--------------------------------------------------+
%%% | Status Bar (server, user, chat mode, messages)  |
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
%%% %% Start with default server
%%% cryptic_cecho_ui:start().
%%%
%%% %% Start with custom server
%%% cryptic_cecho_ui:start("http://example.com:8080").
%%% '''
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-12
-module(cryptic_cecho_ui).

%% Public API
-export([start/0, start/1]).

%% Internal exports for processes
-export([input_handler/1, status_updater/1]).

-include_lib("cecho/include/cecho.hrl").

%% Peek interval in milliseconds
-define(PEEK_INTERVAL, 5000).

%% @doc Chat state record containing server connection and user information.
%%
%% This record maintains the core state for chat operations including
%% server connection details, user authentication, and message monitoring.
%%
%% @type chat_state() = #chat_state{
%%   server_url :: string(),
%%   current_user :: string() | undefined,
%%   keypair :: {binary(), binary()} | undefined,
%%   user_cache :: #{string() => binary()},
%%   peek_enabled :: boolean(),
%%   peek_interval :: pos_integer(),
%%   peek_timer :: timer:tref() | undefined,
%%   storage_initialized :: boolean(),
%%   last_peek_check :: calendar:datetime() | undefined,
%%   undelivered_count :: non_neg_integer()
%% }.
-record(chat_state, {
    server_url = "http://localhost:8080" :: string(),
    current_user :: string() | undefined,
    keypair :: {binary(), binary()} | undefined,
    user_cache = #{} :: #{string() => binary()},  % Username -> PubKey cache

    %% Message peek enhancements
    peek_enabled = true :: boolean(),             % Auto-peeking for message count
    peek_interval = ?PEEK_INTERVAL :: pos_integer(), % Peek interval in milliseconds
    peek_timer :: timer:tref() | undefined,       % Timer reference for peeking
    storage_initialized = false :: boolean(),     % Storage system status
    last_peek_check :: calendar:datetime() | undefined,  % Last peek check time
    undelivered_count = 0 :: non_neg_integer()    % Number of undelivered messages
}).

%% @doc UI state record containing screen layout and interaction state.
%%
%% This record manages all UI-specific state including screen dimensions,
%% message display, input handling, and chat mode operations.
%%
%% @type ui_state() = #ui_state{
%%   chat_state :: #chat_state{},
%%   screen_height :: integer(),
%%   screen_width :: integer(),
%%   message_history :: [{string(), string(), string()}],
%%   scroll_position :: integer(),
%%   command_history :: [string()],
%%   current_input :: string(),
%%   input_pid :: pid(),
%%   status_pid :: pid(),
%%   chat_mode :: boolean(),
%%   chat_target :: string() | undefined,
%%   chat_poll_timer :: timer:tref() | undefined
%% }.
-record(ui_state, {
    chat_state :: #chat_state{},
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
    chat_poll_timer :: timer:tref() | undefined   % Timer for chat mode polling
}).

%% Color pairs
-define(COLOR_STATUS_BAR, 1).
-define(COLOR_HELP_BAR, 2).
-define(COLOR_OWN_MESSAGE, 3).
-define(COLOR_OTHER_MESSAGE, 4).
-define(COLOR_SYSTEM_MESSAGE, 5).
-define(COLOR_TIMESTAMP, 6).
-define(COLOR_INPUT, 7).

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Start the cecho-based UI with default server.
%%
%% Initializes the terminal UI with the default localhost server.
%% This is equivalent to calling `start("http://localhost:8080")'.
%%
%% @returns `ok' when the UI exits normally.
start() ->
    start("http://localhost:8080").

%% @doc Start the cecho-based UI with specified server.
%%
%% Initializes the full-screen terminal interface including:
%% <ul>
%%   <li>ncurses/cecho initialization with color support</li>
%%   <li>Screen layout setup (status, message, help, input areas)</li>
%%   <li>Background processes for input handling and status updates</li>
%%   <li>Auto-peek timer for undelivered message notifications</li>
%%   <li>Main event loop for user interaction</li>
%% </ul>
%%
%% The UI will display welcome messages and enter the main interaction loop.
%% Users can register, send messages, enter chat mode, and perform other
%% operations through the command interface.
%%
%% @param ServerUrl Base URL of the Cryptic server (e.g., "http://localhost:8080")
%% @returns `ok' when the UI exits normally.
%% @throws Any exception that occurs during initialization or operation.
-spec start(string()) -> ok.
start(ServerUrl) ->
    %% Start cecho first (handles ncurses initialization)
    ok = application:start(cecho),

    %% Start other required applications
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),

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

    %% Initialize storage
    InitResult = try
        cryptic_chat_storage:init_storage()
    catch
        _:_ ->
            error
    end,

    %% Create initial state
    ChatState = #chat_state{
        server_url = ServerUrl,
        storage_initialized = (InitResult =:= ok)
    },

    UIState = #ui_state{
        chat_state = ChatState,
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
    WelcomeState = add_system_message("=== CRYPTIC CHAT ===", UpdatedUIState),
    WelcomeState2 = add_system_message("Server: " ++ ServerUrl, WelcomeState),
    WelcomeState3 = add_system_message("Storage: " ++ case InitResult of ok -> "Initialized"; _ -> "Disabled" end, WelcomeState2),
    WelcomeState4 = add_system_message("Type 'help' for commands", WelcomeState3),

    %% Redraw screen with welcome messages
    draw_screen(WelcomeState4),

    %% Start peek timer for undelivered message count
    ChatState = WelcomeState4#ui_state.chat_state,
    case ChatState#chat_state.peek_enabled of
        true ->
            timer:send_interval(ChatState#chat_state.peek_interval, self(), auto_peek);
        false ->
            ok
    end,

    %% Start main UI loop
    try
        ui_main_loop(WelcomeState4)
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
%%   <li>`auto_peek' - Background message count checking</li>
%%   <li>`chat_poll' - Real-time message polling in chat mode</li>
%%   <li>`quit' - Graceful shutdown request</li>
%% </ul>
%%
%% The loop ensures the UI remains responsive while handling background
%% operations like message polling and status updates.
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

        auto_peek ->
            %% Automatic peeking for undelivered message count
            ChatState = UIState#ui_state.chat_state,
            case ChatState#chat_state.peek_enabled of
                true ->
                    %% Peek at message count and update status
                    PeekUIState = process_peek_check(UIState),
                    %% Only update status bar if count changed
                    case PeekUIState#ui_state.chat_state#chat_state.undelivered_count of
                        OldCount when OldCount =:= ChatState#chat_state.undelivered_count ->
                            ui_main_loop(UIState);
                        _NewCount ->
                            %% Count changed, update status bar
                            draw_status_bar(PeekUIState),
                            cecho:refresh(),
                            position_cursor(PeekUIState),
                            ui_main_loop(PeekUIState)
                    end;
                false ->
                    %% Peeking disabled, ignore
                    ui_main_loop(UIState)
            end;

        chat_poll ->
            %% Automatic polling for new messages in chat mode
            case UIState#ui_state.chat_mode of
                true ->
                    %% Check for new messages from chat target
                    ChatPollUIState = process_chat_poll(UIState),
                    case ChatPollUIState of
                        UIState ->
                            %% No new messages, continue
                            ui_main_loop(UIState);
                        _ ->
                            %% New messages found, redraw screen
                            draw_screen(ChatPollUIState),
                            ui_main_loop(ChatPollUIState)
                    end;
                false ->
                    %% Not in chat mode, ignore
                    ui_main_loop(UIState)
            end;

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
%% @doc Draw the status bar at the top showing connection and user info.
%%
%% The status bar displays:
%% <ul>
%%   <li>Application name and server URL</li>
%%   <li>Current user login status</li>
%%   <li>Chat mode status and target user</li>
%%   <li>Undelivered message count (when > 0)</li>
%%   <li>Current time</li>
%% </ul>
%%
%% The status bar uses blue background with white text and automatically
%% truncates content to fit the screen width.
%%
%% @param UIState Current UI state containing chat and display information.
draw_status_bar(UIState) ->
    #ui_state{
        chat_state = ChatState,
        screen_width = Width
    } = UIState,
    
    %% Save current cursor position
    {CurY, CurX} = cecho:getyx(),
    
    %% Get current time
    {_, {Hour, Min, Sec}} = calendar:local_time(),
    TimeStr = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),
    
    %% Get user info and chat mode
    UserStr = case ChatState#chat_state.current_user of
        undefined -> "Not logged in";
        User -> "User: " ++ User
    end,
    
    %% Get chat mode status
    ChatModeStr = case UIState#ui_state.chat_mode of
        false -> "";
        true -> 
            case UIState#ui_state.chat_target of
                undefined -> " | Chat mode";
                Target -> " | Chat with: " ++ Target
            end
    end,
    
    %% Get undelivered message count (only show if > 0)
    MsgCountStr = case ChatState#chat_state.undelivered_count of
        0 -> "";
        Count -> io_lib:format(" | Undelivered: ~w", [Count])
    end,
    
    %% Create status line
    ServerStr = "Server: " ++ ChatState#chat_state.server_url,
    StatusLine = io_lib:format("CRYPTIC CHAT | ~s | ~s~s~s | ~s", 
                              [ServerStr, UserStr, ChatModeStr, MsgCountStr, TimeStr]),
    
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
%%   <li>Green for own messages (future enhancement)</li>
%% </ul>
%%
%% The message area supports scrolling to view message history, though
%% scrolling controls are not yet implemented in the current version.
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
    draw_messages(VisibleMessages, StartLine, Width).

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
draw_messages([], _Line, _Width) ->
    ok;
draw_messages([{From, Message, Timestamp} | Rest], Line, Width) ->
    %% Format message line
    FormattedMsg = format_message(From, Message, Timestamp, Width),
    
    %% Choose color based on message type
    ColorPair = case From of
        "SYSTEM" -> ?COLOR_SYSTEM_MESSAGE;
        _ -> ?COLOR_OTHER_MESSAGE  % Will be enhanced later for own messages
    end,
    
    %% Draw message
    cecho:attron(?ceCOLOR_PAIR(ColorPair)),
    cecho:mvaddstr(Line, 0, FormattedMsg),
    cecho:attroff(?ceCOLOR_PAIR(ColorPair)),
    
    %% Draw next message
    draw_messages(Rest, Line + 1, Width).

%% @private
%% @doc Draw the context-sensitive help bar.
%%
%% Displays different help text based on the current mode:
%% <ul>
%%   <li>Normal mode: Shows available commands (register, send, chat, etc.)</li>
%%   <li>Chat mode: Shows chat-specific commands (:exit, :help, message sending)</li>
%% </ul>
%%
%% The help bar uses white text on black background and is positioned
%% near the bottom of the screen for easy reference.
%%
%% @param UIState Current UI state to determine the appropriate help text.
draw_help_bar(UIState) ->
    #ui_state{screen_height = Height, screen_width = Width} = UIState,
    
    HelpLine = case UIState#ui_state.chat_mode of
        false ->
            "Commands: help | register <user> | send <user> <msg> | chat <user> | inbox | list_users | quit";
        true ->
            "Chat Mode: Type message to send | :exit to leave chat | :help for commands"
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
%% This is the main command dispatcher that handles all user commands:
%%
%% === Core Commands ===
%% <ul>
%%   <li>`help' - Display available commands</li>
%%   <li>`register <username>' - Register with the server</li>
%%   <li>`send <user> <message>' - Send encrypted message</li>
%%   <li>`chat <user>' - Enter real-time chat mode</li>
%%   <li>`inbox' - Check for new messages</li>
%%   <li>`list_users' - Show registered users</li>
%%   <li>`quit' - Exit the application</li>
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
%% The function handles error cases, validates user registration state,
%% and provides appropriate feedback through system messages.
%%
%% @param Command The command string entered by the user
%% @param UIState Current UI state
%% @returns Updated UI state with command results displayed.
process_command("", UIState) ->
    %% Empty command, do nothing
    UIState;
process_command("quit", UIState) ->
    %% Send quit message and stop the node
    self() ! quit,
    UIState;
process_command("help", UIState) ->
    %% Show help
    HelpState = add_system_message("=== COMMANDS ===", UIState),
    HelpState2 = add_system_message("register <username> - Register with server", HelpState),
    HelpState3 = add_system_message("send <user> <message> - Send message", HelpState2),
    HelpState4 = add_system_message("chat <user> - Enter chat mode with user", HelpState3),
    HelpState5 = add_system_message("inbox - Check for new messages", HelpState4),
    HelpState6 = add_system_message("list_users - List all registered users", HelpState5),
    HelpState7 = add_system_message("quit - Exit application", HelpState6),
    HelpState8 = add_system_message("In chat mode: :exit to leave, :help for commands", HelpState7),
    HelpState8;
process_command("register " ++ Username, UIState) ->
    %% Real server registration using cryptic_client_lib
    User = string:trim(Username),
    ChatState = UIState#ui_state.chat_state,
    
    case ChatState#chat_state.current_user of
        undefined ->
            %% Generate keypair and register with server
            {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
            case cryptic_client_lib:upload_prekey(ChatState#chat_state.server_url, User, PubKey) of
                ok ->
                    %% Registration successful
                    NewChatState = ChatState#chat_state{
                        current_user = User,
                        keypair = {PubKey, PrivKey}
                    },
                    NewUIState = UIState#ui_state{chat_state = NewChatState},
                    add_system_message("Successfully registered as: " ++ User, NewUIState);
                {error, Reason} ->
                    %% Registration failed
                    ErrMsg = io_lib:format("Registration failed: ~p", [Reason]),
                    add_system_message(lists:flatten(ErrMsg), UIState)
            end;
        CurrentUser ->
            %% Already registered
            Msg = "Already registered as " ++ CurrentUser ++ ". Use 'quit' to exit.",
            add_system_message(Msg, UIState)
    end;
process_command("test", UIState) ->
    %% Simple test command
    add_system_message("Test command received!", UIState);
process_command("list_users", UIState) ->
    %% List users from server
    ChatState = UIState#ui_state.chat_state,
    case cryptic_client_lib:list_users(ChatState#chat_state.server_url) of
        {ok, Users} ->
            UsersState = add_system_message("Available users:", UIState),
            lists:foldl(fun(User, AccState) ->
                add_system_message("  - " ++ User, AccState)
            end, UsersState, Users);
        {error, Reason} ->
            ErrMsg = io_lib:format("Failed to list users: ~p", [Reason]),
            add_system_message(lists:flatten(ErrMsg), UIState)
    end;
process_command("inbox", UIState) ->
    %% Check inbox
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            add_system_message("Please register first using: register <username>", UIState);
        User ->
            case ChatState#chat_state.keypair of
                undefined ->
                    add_system_message("No keypair found. Please register again.", UIState);
                {_PubKey, PrivKey} ->
                    case cryptic_client_lib:receive_and_decrypt_messages(ChatState#chat_state.server_url, User, PrivKey) of
                        {ok, []} ->
                            add_system_message("No new messages", UIState);
                        {ok, Messages} ->
                            InboxState = add_system_message("=== NEW MESSAGES ===", UIState),
                            lists:foldl(fun({From, Msg}, AccState) ->
                                MsgText = io_lib:format("<~s>: ~s", [From, Msg]),
                                add_system_message(lists:flatten(MsgText), AccState)
                            end, InboxState, Messages);
                        {error, Reason} ->
                            ErrMsg = io_lib:format("Failed to check inbox: ~p", [Reason]),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end
            end
    end;
process_command("send " ++ Rest, UIState) ->
    %% Send message command
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            add_system_message("Please register first using: register <username>", UIState);
        FromUser ->
            case string:split(Rest, " ", leading) of
                [ToUser, Message] ->
                    case ChatState#chat_state.keypair of
                        undefined ->
                            add_system_message("No keypair found. Please register again.", UIState);
                        {_PubKey, PrivKey} ->
                            TrimmedToUser = string:trim(ToUser),
                            TrimmedMessage = string:trim(Message),
                            case cryptic_client_lib:send_encrypted_message(
                                ChatState#chat_state.server_url, 
                                FromUser, 
                                TrimmedToUser, 
                                TrimmedMessage, 
                                PrivKey) of
                                ok ->
                                    MsgText = io_lib:format("Message sent to ~s: ~s", [TrimmedToUser, TrimmedMessage]),
                                    add_system_message(lists:flatten(MsgText), UIState);
                                {error, Reason} ->
                                    ErrMsg = io_lib:format("Failed to send message: ~p", [Reason]),
                                    add_system_message(lists:flatten(ErrMsg), UIState)
                            end
                    end;
                _ ->
                    add_system_message("Usage: send <username> <message>", UIState)
            end
    end;
process_command("chat " ++ Username, UIState) ->
    %% Enter chat mode with specified user
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            add_system_message("Please register first using: register <username>", UIState);
        _CurrentUser ->
            TrimmedUser = string:trim(Username),
            case TrimmedUser of
                "" ->
                    add_system_message("Usage: chat <username>", UIState);
                _ ->
                    %% Start chat polling timer (every 2 seconds for real-time feel)
                    {ok, TimerRef} = timer:send_interval(2000, self(), chat_poll),
                    NewUIState = UIState#ui_state{
                        chat_mode = true,
                        chat_target = TrimmedUser,
                        chat_poll_timer = TimerRef
                    },
                    Msg = io_lib:format("Entering chat mode with ~s. Type ':exit' to leave chat mode.", [TrimmedUser]),
                    add_system_message(lists:flatten(Msg), NewUIState)
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
%% @doc Process commands while in chat mode.
%%
%% Chat mode provides a streamlined interface for real-time conversations.
%% It handles special chat commands that start with ":" and treats all
%% other input as messages to send to the chat target.
%%
%% === Chat Commands ===
%% <ul>
%%   <li>`:exit' - Leave chat mode and stop polling</li>
%%   <li>`:help' - Show chat mode specific help</li>
%%   <li>`:<unknown>' - Display error for unknown chat commands</li>
%% </ul>
%%
%% === Message Sending ===
%% Any text that doesn't start with ":" is treated as a message to send
%% to the current chat target. Messages are sent immediately and displayed
%% in the chat format "You -> target: message".
%%
%% @param Command The command or message entered in chat mode
%% @param UIState Current UI state in chat mode
%% @returns Updated UI state after processing the chat command.
process_chat_command(":exit", UIState) ->
    %% Exit chat mode and stop polling timer
    case UIState#ui_state.chat_poll_timer of
        undefined -> ok;
        TimerRef -> timer:cancel(TimerRef)
    end,
    NewUIState = UIState#ui_state{
        chat_mode = false,
        chat_target = undefined,
        chat_poll_timer = undefined
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
    %% Send message to chat target
    ChatState = UIState#ui_state.chat_state,
    case {ChatState#chat_state.current_user, UIState#ui_state.chat_target} of
        {undefined, _} ->
            add_system_message("Error: Not registered", UIState);
        {_, undefined} ->
            add_system_message("Error: No chat target set", UIState);
        {FromUser, ToUser} ->
            case ChatState#chat_state.keypair of
                undefined ->
                    add_system_message("No keypair found. Please register again.", UIState);
                {_PubKey, PrivKey} ->
                    case cryptic_client_lib:send_encrypted_message(
                        ChatState#chat_state.server_url, 
                        FromUser, 
                        ToUser, 
                        Message, 
                        PrivKey) of
                        ok ->
                            %% Show the sent message in chat format
                            MsgText = io_lib:format("You -> ~s: ~s", [ToUser, Message]),
                            add_system_message(lists:flatten(MsgText), UIState);
                        {error, Reason} ->
                            ErrMsg = io_lib:format("Failed to send message: ~p", [Reason]),
                            add_system_message(lists:flatten(ErrMsg), UIState)
                    end
            end
    end.

%% @private
%% @doc Process peek check for undelivered message count.
%%
%% This function performs a non-destructive check of the user's message
%% inbox to determine how many undelivered messages are waiting. It uses
%% the `/peek_messages/<user>' endpoint which returns just the count
%% without consuming the messages.
%%
%% This is used by the auto-peek timer to update the status bar with
%% undelivered message notifications without interfering with normal
%% message retrieval operations.
%%
%% @param UIState Current UI state
%% @returns Updated UI state with new undelivered count, or unchanged state on error.
process_peek_check(UIState) ->
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            %% Not registered, no peeking
            UIState;
        User ->
            case cryptic_client_lib:peek_message_count(ChatState#chat_state.server_url, User) of
                {ok, Count} ->
                    %% Update undelivered count
                    NewChatState = ChatState#chat_state{
                        undelivered_count = Count,
                        last_peek_check = calendar:universal_time()
                    },
                    UIState#ui_state{chat_state = NewChatState};
                {error, _Reason} ->
                    %% Error peeking, keep current state
                    UIState
            end
    end.

%% @private
%% @doc Process chat poll check for new messages in chat mode.
%%
%% When in chat mode, this function polls for new messages every 2 seconds
%% to provide a real-time chat experience. It:
%% <ol>
%%   <li>Retrieves all new messages for the user</li>
%%   <li>Filters to only show messages from the chat target</li>
%%   <li>Displays new messages in chat format "sender: message"</li>
%%   <li>Ignores errors silently to avoid disrupting the chat flow</li>
%% </ol>
%%
%% This creates a responsive chat experience where messages appear
%% automatically without manual inbox checking.
%%
%% @param UIState Current UI state in chat mode
%% @returns Updated UI state with new messages displayed, or unchanged state.
process_chat_poll(UIState) ->
    ChatState = UIState#ui_state.chat_state,
    case {ChatState#chat_state.current_user, UIState#ui_state.chat_target} of
        {undefined, _} ->
            %% Not registered, no polling
            UIState;
        {_, undefined} ->
            %% No chat target, no polling
            UIState;
        {User, ChatTarget} ->
            case ChatState#chat_state.keypair of
                undefined ->
                    %% No keypair, no polling
                    UIState;
                {_PubKey, PrivKey} ->
                    case cryptic_client_lib:receive_and_decrypt_messages(ChatState#chat_state.server_url, User, PrivKey) of
                        {ok, []} ->
                            %% No new messages, return unchanged state
                            UIState;
                        {ok, Messages} ->
                            %% Filter messages to only show ones from chat target
                            ChatMessages = lists:filter(fun({From, _Msg}) ->
                                From =:= ChatTarget
                            end, Messages),
                            case ChatMessages of
                                [] ->
                                    %% No messages from chat target
                                    UIState;
                                _ ->
                                    %% Display chat messages in chat format
                                    lists:foldl(fun({From, Msg}, AccState) ->
                                        MsgText = io_lib:format("~s: ~s", [From, Msg]),
                                        add_system_message(lists:flatten(MsgText), AccState)
                                    end, UIState, ChatMessages)
                            end;
                        {error, _Reason} ->
                            %% Error checking messages, silently ignore for chat polling
                            UIState
                    end
            end
    end.

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
%% other dynamic information.
%%
%% The status bar shows:
%% <ul>
%%   <li>Current time (HH:MM:SS format)</li>
%%   <li>Server connection status</li>
%%   <li>User login information</li>
%%   <li>Chat mode and target user</li>
%%   <li>Undelivered message count</li>
%% </ul>
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
    cecho:init_pair(?COLOR_INPUT, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK).

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
%% @doc Add a system message to the message history.
%%
%% System messages are used for:
%% <ul>
%%   <li>Command feedback and status updates</li>
%%   <li>Error messages and warnings</li>
%%   <li>Help text and instructions</li>
%%   <li>Application status notifications</li>
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
