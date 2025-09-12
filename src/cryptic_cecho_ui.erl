-module(cryptic_cecho_ui).

%% Public API
-export([start/0, start/1]).

%% Internal exports for processes
-export([input_handler/1, status_updater/1]).

-include_lib("cecho/include/cecho.hrl").

%% Polling interval in milliseconds
-define(POLL_INTERVAL, 2000).

%% Chat state record
-record(chat_state, {
    server_url = "http://localhost:8080" :: string(),
    current_user :: string() | undefined,
    keypair :: {binary(), binary()} | undefined,
    user_cache = #{} :: #{string() => binary()},  % Username -> PubKey cache

    %% Phase 2 enhancements
    polling_enabled = false :: boolean(),         % Auto-polling for messages
    polling_interval = ?POLL_INTERVAL :: pos_integer(), % Polling interval in milliseconds
    polling_timer :: timer:tref() | undefined,    % Timer reference for polling
    storage_initialized = false :: boolean(),     % Storage system status
    last_inbox_check :: calendar:datetime() | undefined,  % Last inbox check time
    unread_count = 0 :: non_neg_integer()         % Number of unread messages
}).

%% UI State record
-record(ui_state, {
    chat_state :: #chat_state{},
    screen_height :: integer(),
    screen_width :: integer(),
    message_history = [] :: [{string(), string(), string()}], % {From, Message, Timestamp}
    scroll_position = 0 :: integer(),
    command_history = [] :: [string()],
    current_input = "" :: string(),
    input_pid :: pid(),
    status_pid :: pid()
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
start() ->
    start("http://localhost:8080").

%% @doc Start the cecho-based UI with specified server.
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
        cryptic_lib:initialize_storage()
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
%% @doc Main UI event loop.
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

        auto_poll ->
            %% Automatic polling for new messages
            ChatState = UIState#ui_state.chat_state,
            case ChatState#chat_state.polling_enabled of
                true ->
                    %% Check for new messages silently (no "No new messages" spam)
                    PollUIState = process_silent_inbox_check(UIState),
                    case PollUIState of
                        UIState ->
                            %% No changes, no need to redraw
                            ui_main_loop(UIState);
                        _ ->
                            %% New messages found, redraw screen
                            draw_screen(PollUIState),
                            ui_main_loop(PollUIState)
                    end;
                false ->
                    %% Polling disabled, ignore
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
%% @doc Position cursor in the input area.
position_cursor(UIState) ->
    #ui_state{current_input = Input, screen_height = Height} = UIState,
    Prompt = "> ",
    CursorX = length(Prompt ++ Input),
    cecho:move(Height - 1, CursorX).

%% @private
%% @doc Draw the complete screen layout.
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
%% @doc Draw the status bar at the top.
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
    
    %% Get user info
    UserStr = case ChatState#chat_state.current_user of
        undefined -> "Not logged in";
        User -> "User: " ++ User
    end,
    
    %% Get message count
    MsgCountStr = io_lib:format("Messages: ~w", [ChatState#chat_state.unread_count]),
    
    %% Create status line
    ServerStr = "Server: " ++ ChatState#chat_state.server_url,
    StatusLine = io_lib:format("CRYPTIC CHAT | ~s | ~s | ~s | ~s", 
                              [ServerStr, UserStr, MsgCountStr, TimeStr]),
    
    %% Truncate or pad to screen width
    StatusLineFmt = format_line(lists:flatten(StatusLine), Width),
    
    %% Draw with status bar colors
    cecho:attron(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)),
    cecho:mvaddstr(0, 0, StatusLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_STATUS_BAR)),
    
    %% Restore cursor position
    cecho:move(CurY, CurX).

%% @private
%% @doc Draw the message display area.
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
%% @doc Draw individual messages.
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
%% @doc Draw the help bar.
draw_help_bar(UIState) ->
    #ui_state{screen_height = Height, screen_width = Width} = UIState,
    
    HelpLine = "Commands: help | register <user> | send <user> <msg> | inbox | list_users | polling on/off | quit",
    HelpLineFmt = format_line(HelpLine, Width),
    
    cecho:attron(?ceCOLOR_PAIR(?COLOR_HELP_BAR)),
    cecho:mvaddstr(Height - 3, 0, HelpLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_HELP_BAR)).

%% @private
%% @doc Draw the input line.
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
%% @doc Handle user input.
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
%% @doc Process a user command.
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
    HelpState4 = add_system_message("inbox - Check for new messages", HelpState3),
    HelpState5 = add_system_message("list_users - List all registered users", HelpState4),
    HelpState6 = add_system_message("polling on/off - Enable/disable auto polling", HelpState5),
    HelpState7 = add_system_message("quit - Exit application", HelpState6),
    HelpState7;
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
process_command("polling on", UIState) ->
    %% Enable automatic polling for new messages
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            add_system_message("Please register first before enabling polling", UIState);
        _User ->
            %% Start polling timer (every 5 seconds)
            timer:send_interval(5000, self(), auto_poll),
            NewChatState = ChatState#chat_state{polling_enabled = true},
            NewUIState = UIState#ui_state{chat_state = NewChatState},
            add_system_message("Automatic polling enabled (5 second interval)", NewUIState)
    end;
process_command("polling off", UIState) ->
    %% Disable automatic polling
    ChatState = UIState#ui_state.chat_state,
    NewChatState = ChatState#chat_state{polling_enabled = false},
    NewUIState = UIState#ui_state{chat_state = NewChatState},
    add_system_message("Automatic polling disabled", NewUIState);
process_command(Command, UIState) ->
    %% Unknown command
    add_system_message("Unknown command: " ++ Command, UIState).

%% @private
%% @doc Process inbox check silently for auto-polling (no spam when no messages).
process_silent_inbox_check(UIState) ->
    ChatState = UIState#ui_state.chat_state,
    case ChatState#chat_state.current_user of
        undefined ->
            %% Not registered, no polling
            UIState;
        User ->
            case ChatState#chat_state.keypair of
                undefined ->
                    %% No keypair, no polling
                    UIState;
                {_PubKey, PrivKey} ->
                    case cryptic_client_lib:receive_and_decrypt_messages(ChatState#chat_state.server_url, User, PrivKey) of
                        {ok, []} ->
                            %% No new messages, return unchanged state (no spam)
                            UIState;
                        {ok, Messages} ->
                            %% New messages found, add them without header
                            lists:foldl(fun({From, Msg}, AccState) ->
                                MsgText = io_lib:format("<~s>: ~s", [From, Msg]),
                                add_system_message(lists:flatten(MsgText), AccState)
                            end, UIState, Messages);
                        {error, _Reason} ->
                            %% Error checking messages, silently ignore for auto-polling
                            UIState
                    end
            end
    end.

%%%===================================================================
%%% Helper Processes
%%%===================================================================

%% @private
%% @doc Input handler process.
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
%% @doc Status updater process.
status_updater(MainPid) ->
    timer:sleep(1000),
    MainPid ! {status_update},
    status_updater(MainPid).

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @private
%% @doc Initialize color pairs.
init_colors() ->
    cecho:init_pair(?COLOR_STATUS_BAR, ?ceCOLOR_WHITE, ?ceCOLOR_BLUE),
    cecho:init_pair(?COLOR_HELP_BAR, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_OWN_MESSAGE, ?ceCOLOR_GREEN, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_OTHER_MESSAGE, ?ceCOLOR_CYAN, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_SYSTEM_MESSAGE, ?ceCOLOR_YELLOW, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_TIMESTAMP, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK),
    cecho:init_pair(?COLOR_INPUT, ?ceCOLOR_WHITE, ?ceCOLOR_BLACK).

%% @private
%% @doc Format a line to fit screen width.
format_line(Line, Width) ->
    case length(Line) of
        Len when Len > Width ->
            string:substr(Line, 1, Width);
        Len ->
            Line ++ string:chars($ , Width - Len)
    end.

%% @private
%% @doc Format a message for display.
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
%% @doc Add a system message.
add_system_message(Message, UIState) ->
    {{_Year, _Month, _Day}, {Hour, Min, Sec}} = calendar:local_time(),
    Timestamp = io_lib:format("~2..0w:~2..0w:~2..0w", [Hour, Min, Sec]),
    
    NewMessage = {"SYSTEM", Message, lists:flatten(Timestamp)},
    CurrentMessages = UIState#ui_state.message_history,
    
    UIState#ui_state{message_history = CurrentMessages ++ [NewMessage]}.

%% @private
%% @doc Cleanup UI on exit.
cleanup_ui() ->
    cecho:endwin().
