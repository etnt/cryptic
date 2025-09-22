%%% @doc Cryptic UI Screen Drawing Module
%%%
%%% This module handles all screen drawing operations for the Cryptic terminal UI.
%%% It provides functions for rendering the complete screen layout including:
%%% status bar, message area, help bar, and input line.
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-21
-module(cryptic_ui_screen).

%% Public API
-export([
    draw_screen/1,
    draw_status_bar/1,
    draw_message_area/1,
    draw_help_bar/1,
    draw_input_line/1,
    position_cursor/1,
    format_message/4,
    format_line/2,
    get_visible_messages/3,
    cleanup_ui/0
]).

-include_lib("cecho/include/cecho.hrl").
-include("cryptic.hrl").
-include("cryptic_ui.hrl").


%%%===================================================================
%%% Public API
%%%===================================================================

%% Draw the complete screen layout with all UI components.
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


%% Draw the status bar at the top showing WebSocket connection and user info.
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

%% Draw the scrollable message display area.
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


%% Draw individual messages with appropriate color coding.
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


%% Draw the context-sensitive help bar.
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
    #ui_state{
        screen_height = Height,
        screen_width = Width,
        passphrase_mode = PassphraseMode
    } = UIState,

    HelpLine =
        case PassphraseMode of
            true ->
                "Passphrase Mode: Type passphrase and press Enter | Ctrl+C to cancel";
            false ->
                WSChatState = UIState#ui_state.ws_chat_state,
                case
                    {
                        WSChatState#ws_chat_state.connection_status,
                        UIState#ui_state.chat_mode
                    }
                of
                    {disconnected, _} ->
                        "Commands: connect | help | quit";
                    {connected, false} ->
                        %% Check if there are enough messages to scroll
                        Messages = UIState#ui_state.message_history,
                        ScreenHeight = UIState#ui_state.screen_height,
                        AreaHeight = ScreenHeight - 4,
                        case length(Messages) > AreaHeight of
                            true ->
                                "Commands: help | send | chat | PgUp/PgDn scroll | disconnect";
                            false ->
                                "Commands: help | send | chat | create_room | join_room | list_rooms | list_users | disconnect"
                        end;
                    {connected, true} ->
                        "Chat Mode: Type message to send | :exit to leave chat | :help for commands";
                    {connecting, _} ->
                        "Connecting to WebSocket mTLS server..."
                end
        end,
    HelpLineFmt = format_line(HelpLine, Width),

    cecho:attron(?ceCOLOR_PAIR(?COLOR_HELP_BAR)),
    cecho:mvaddstr(Height - 3, 0, HelpLineFmt),
    cecho:attroff(?ceCOLOR_PAIR(?COLOR_HELP_BAR)).


%% Draw the input line with prompt and current user text.
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
        screen_width = Width,
        passphrase_mode = PassphraseMode
    } = UIState,

    %% Create input line with prompt
    Prompt =
        case PassphraseMode of
            true -> "Passphrase: ";
            false -> "> "
        end,
    PromptLen = length(Prompt),

    %% Mask input if in passphrase mode
    DisplayInput =
        case PassphraseMode of
            true -> string:chars($*, length(Input));
            false -> Input
        end,

    InputLine = Prompt ++ DisplayInput,

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


%% Position cursor in the input area at the end of current input.
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
        screen_width = Width,
        passphrase_mode = PassphraseMode
    } = UIState,

    %% Use correct prompt based on mode
    Prompt =
        case PassphraseMode of
            true -> "Passphrase: ";
            false -> "> "
        end,
    PromptLen = length(Prompt),

    %% For passphrase mode, use masked input for length calculation
    DisplayInput =
        case PassphraseMode of
            true -> string:chars($*, length(Input));
            false -> Input
        end,

    InputLine = Prompt ++ DisplayInput,

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



%% Format a message for display with sender, content, and timestamp.
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


%% Format a line to fit screen width with padding or truncation.
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


%% Get visible messages for current scroll position.
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


%% Cleanup UI resources on exit.
%%
%% Properly shuts down the ncurses interface and restores the terminal
%% to its original state. This should be called before the application
%% exits to ensure the terminal is left in a usable state.
cleanup_ui() ->
    cecho:endwin().