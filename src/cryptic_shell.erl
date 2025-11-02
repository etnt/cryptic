%%% @doc Cryptic Shell - Enhanced interactive shell with line editing and history
%%%
%%% This module provides a sophisticated interactive shell with advanced line editing
%%% capabilities for the Cryptic messaging application. It implements a custom input
%%% handler with features comparable to modern shells.
%%%
%%% == Features ==
%%% <ul>
%%%   <li><b>Line Editing</b>: Character-by-character editing with cursor movement</li>
%%%   <li><b>Emacs Keybindings</b>: Ctrl+A, Ctrl+E, Ctrl+F, Ctrl+B, Ctrl+K, Ctrl+U, etc.</li>
%%%   <li><b>Arrow Key Support</b>: Left/Right for cursor movement, Up/Down for history</li>
%%%   <li><b>Command History</b>: Navigate through last 100 commands with Up/Down arrows</li>
%%%   <li><b>Input Buffer Preservation</b>: Save/restore partial input across process restarts</li>
%%%   <li><b>Password Input</b>: Secure input with character masking</li>
%%%   <li><b>ANSI Colors</b>: Rich terminal formatting for better UX</li>
%%%   <li><b>Terminal Width Aware</b>: Calculates line wrapping for clean prompt display</li>
%%%   <li><b>Escape Sequence Handling</b>: Robust handling of terminal escape codes</li>
%%% </ul>
%%%
%%% == Keybindings ==
%%% === Navigation ===
%%% <ul>
%%%   <li>`Ctrl+A' or `Home' - Move to beginning of line</li>
%%%   <li>`Ctrl+E' or `End' - Move to end of line</li>
%%%   <li>`Ctrl+F' or `Right Arrow' - Move forward one character</li>
%%%   <li>`Ctrl+B' or `Left Arrow' - Move backward one character</li>
%%% </ul>
%%%
%%% === Editing ===
%%% <ul>
%%%   <li>`Ctrl+D' or `Delete' - Delete character at cursor</li>
%%%   <li>`Ctrl+H' or `Backspace' - Delete character before cursor</li>
%%%   <li>`Ctrl+K' - Kill (delete) to end of line</li>
%%%   <li>`Ctrl+U' - Kill (delete) entire line</li>
%%% </ul>
%%%
%%% === History ===
%%% <ul>
%%%   <li>`Ctrl+P' or `Up Arrow' - Previous command in history</li>
%%%   <li>`Ctrl+N' or `Down Arrow' - Next command in history</li>
%%% </ul>
%%%
%%% == Architecture ==
%%% The shell operates in raw terminal mode to intercept individual keystrokes.
%%% It maintains state in a `line_state' record that tracks:
%%% <ul>
%%%   <li>Current input buffer (list of characters)</li>
%%%   <li>Cursor position within the buffer</li>
%%%   <li>History navigation state</li>
%%%   <li>ETS table reference for persistence</li>
%%% </ul>
%%%
%%% == Buffer Persistence ==
%%% The shell can save partial input to an ETS table (typically `cryptic_console_input_buffer')
%%% allowing the console to preserve user input when the input process is killed by
%%% async messages. The buffer is automatically restored on the next prompt.
%%%
%%% == Command History ==
%%% Commands are stored in the same ETS table with keys `{history, N}' where N is the
%%% command index. The history is circular with a maximum of 100 commands. Empty commands
%%% and duplicate consecutive commands are not saved.
%%%
%%% == Escape Sequence Handling ==
%%% The shell includes special handling for escape sequences that may appear in the input
%%% stream after process restarts or ANSI output. It can:
%%% <ul>
%%%   <li>Detect and consume ANSI color codes (ESC[...m)</li>
%%%   <li>Handle broken arrow key sequences (ESC A instead of ESC [ A)</li>
%%%   <li>Distinguish between escape sequences and user input</li>
%%% </ul>
%%%
%%% == Display Management ==
%%% The shell provides intelligent terminal display management:
%%% <ul>
%%%   <li><b>Line Wrapping</b>: Automatically detects terminal width via `io:columns()'</li>
%%%   <li><b>Multi-line Clearing</b>: Calculates wrapped lines to properly clear commands</li>
%%%   <li><b>ANSI-aware Measurement</b>: Strips escape codes when measuring visible text</li>
%%%   <li><b>Clean Output</b>: Sent messages replace command input without artifacts</li>
%%%   <li><b>Silent Restoration</b>: Partial input restored seamlessly after interruptions</li>
%%% </ul>
%%%
%%% @see cryptic_console
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_shell).

%% Include ANSI escape sequence macros for terminal formatting
-include("cryptic_ansi.hrl").
-include("cryptic.hrl").

%% API
-export([
    start_shell/0, start_shell/1,
    get_line/0,
    get_line/1,
    get_password/1,
    cleanup/0,
    print_user_message/3,
    print_sent_message/3,
    print_history_message/6,
    print_success/1,
    print_error/1,
    print_warning/1,
    print_info/1,
    print_highlight/1,
    print_engine_status/1,
    print_help/0,
    print_help/1,
    print_console_status/1,
    print_ca_response/1,
    make_prompt/0,
    make_prompt/1,
    calculate_wrapped_lines/2,
    clear_lines_up/1
]).

%% Enhanced output functions with ANSI formatting

%% Internal state record for line editing
-record(line_state,
    %% Current line content
    {
        buffer = [] :: [char()],
        %% Cursor position (0-based from start)
        cursor = 0 :: non_neg_integer(),
        %% Current prompt string
        prompt :: string(),
        %% Optional ETS table for buffer persistence
        buffer_table :: ets:tid() | undefined,
        %% History navigation state
        history_pos :: undefined | non_neg_integer(),
        %% Original buffer before history navigation
        original_buffer = [] :: [char()]
    }
).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Make a standard prompt
%% This function can be extended in the future to create dynamic prompts
%% based on context (username, connection status, session info, etc.)
-spec make_prompt() -> string().
make_prompt() ->
    make_prompt(#{}).

%% @doc Make a prompt with optional context information
%% Currently returns the standard "cryptic> " prompt, but can be enhanced
%% to include context like:
%% - Username: "alice@cryptic> "
%% - Server status: "cryptic [connected]> "
%% - Session count: "cryptic (2 active)> "
%% - Custom modes: "cryptic [debug]> "
-spec make_prompt(map()) -> string().
make_prompt(_Context) ->
    %% For now, return the standard prompt
    %% Future enhancement example:
    %% Username = maps:get(username, Context, undefined),
    %% case Username of
    %%     undefined -> "cryptic> ";
    %%     User -> User ++ "@cryptic> "
    %% end
    "cryptic> ".

%% @doc Start the shell in raw mode
-spec start_shell() -> ok | {error, term()}.
start_shell() ->
    start_shell(#{}).

%% @doc Start the shell with options
-spec start_shell(map()) -> ok | {error, term()}.
start_shell(_Options) ->
    try
        %% Try OTP 28 raw mode first
        case shell:start_interactive({noshell, raw}) of
            ok ->
                ok;
            {error, _Reason} ->
                fallback_raw_mode()
        end
    catch
        error:undef ->
            fallback_raw_mode();
        _:Error ->
            {error, Error}
    end.

%% @doc Clean up shell state and restore terminal
-spec cleanup() -> ok.
cleanup() ->
    io:setopts(standard_io, [{raw, false}]).

-spec get_line() -> string() | eof | {error, term()}.
get_line() ->
    get_line(make_prompt()).

%% @doc Get a line of input with line editing
-spec get_line(string()) -> string() | eof | {error, term()}.
get_line(Prompt) ->
    %% Format prompt with bold styling for better visibility
    FormattedPrompt = ?BOLD(Prompt),
    io:format("~s", [FormattedPrompt]),

    %% Check if there's a saved buffer in the named ETS table
    InitialBuffer =
        case ets:whereis(cryptic_console_input_buffer) of
            undefined ->
                [];
            _TableRef ->
                case ets:lookup(cryptic_console_input_buffer, current_input) of
                    [{current_input, Buffer}] ->
                        %% Clear the saved buffer since we're restoring it
                        ets:delete(cryptic_console_input_buffer, current_input),
                        %% Display the restored buffer
                        io:format("~s", [Buffer]),
                        Buffer;
                    [] ->
                        []
                end
        end,

    LineState =
        #line_state{
            buffer = InitialBuffer,
            cursor = length(InitialBuffer),
            prompt = FormattedPrompt,
            buffer_table = cryptic_console_input_buffer
        },
    %% Small delay to let terminal finish processing the prompt ANSI codes
    %% before we start reading input. This prevents characters from being
    %% consumed/lost when the terminal is still processing escape sequences.
    timer:sleep(10),
    line_editor_loop(LineState).

%% @doc Get password input with character masking
-spec get_password(string()) -> string() | eof.
get_password(Prompt) ->
    %% Format password prompt with yellow color and bold for security emphasis
    FormattedPrompt = ?FG_YELLOW_BG_BLACK(?BOLD(Prompt)),
    io:format("~s", [FormattedPrompt]),
    password_loop([]).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Fallback to older raw mode approach
fallback_raw_mode() ->
    case io:setopts(standard_io, [raw]) of
        ok ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Main line editor loop
line_editor_loop(#line_state{buffer = Buffer} = State) ->
    case io:get_chars(standard_io, "", 1) of
        %% Enter keys
        "\n" ->
            finish_line(Buffer);
        "\r" ->
            finish_line(Buffer);
        %% Escape sequence start
        "\e" ->
            handle_escape_sequence(State);
        %% Emacs control keys
        %% Ctrl+A - beginning of line
        [1] ->
            handle_ctrl_a(State);
        %% Ctrl+E - end of line
        [5] ->
            handle_ctrl_e(State);
        %% Ctrl+F - forward char
        [6] ->
            handle_ctrl_f(State);
        %% Ctrl+B - backward char
        [2] ->
            handle_ctrl_b(State);
        %% Ctrl+D - delete char
        [4] ->
            handle_ctrl_d(State);
        %% Ctrl+H - backspace
        [8] ->
            handle_ctrl_h(State);
        %% Ctrl+K - kill to end
        [11] ->
            handle_ctrl_k(State);
        %% Ctrl+U - kill entire line
        [21] ->
            handle_ctrl_u(State);
        %% Ctrl+P - previous history
        [16] ->
            handle_ctrl_p(State);
        %% Ctrl+N - next history
        [14] ->
            handle_ctrl_n(State);
        %% Regular delete key
        %% DEL acts like backspace
        [127] ->
            handle_ctrl_h(State);
        %% EOF
        eof ->
            eof;
        %% Skip other control characters
        [C] when C < 32 ->
            line_editor_loop(State);
        %% Regular printable character
        [Char] ->
            insert_char(State, Char)
    end.

%% @doc Handle escape sequences (arrow keys, etc.)
handle_escape_sequence(State) ->
    %% Read one character at a time to avoid blocking issues
    case io:get_chars(standard_io, "", 1) of
        "[" ->
            %% Now read the command character
            case io:get_chars(standard_io, "", 1) of
                "A" ->
                    %% Up arrow
                    handle_ctrl_p(State);
                "B" ->
                    %% Down arrow
                    handle_ctrl_n(State);
                "C" ->
                    %% Right arrow
                    handle_ctrl_f(State);
                "D" ->
                    %% Left arrow
                    handle_ctrl_b(State);
                %% Might be an ANSI sequence like ESC[0m or ESC[1;36m
                [C] when C >= $0, C =< $9 ->
                    %% Consume the rest of the ANSI sequence (digits, semicolons, until 'm')
                    consume_ansi_sequence(State);
                %% Unknown sequence - consume and ignore
                _Other ->
                    line_editor_loop(State)
            end;
        %% Special case: After process restart, we sometimes get ESC A instead of ESC [ A
        %% This happens because the [ character gets consumed somewhere during restart
        %% Treat bare arrow keys (A/B/C/D) after ESC as arrow key sequences
        "A" ->
            handle_ctrl_p(State);
        "B" ->
            handle_ctrl_n(State);
        "C" ->
            handle_ctrl_f(State);
        "D" ->
            handle_ctrl_b(State);
        %% Other escape sequences - might be from ANSI codes in terminal output
        %% Numeric start - consume ANSI sequence
        [C] when C >= $0, C =< $9 ->
            consume_ansi_sequence(State);
        %% Regular character after ESC - treat as user input
        [Char] ->
            insert_char(State, Char);
        %% Anything else - ignore
        _Other ->
            line_editor_loop(State)
    end.

%% @doc Consume the rest of an ANSI escape sequence
%% ANSI sequences are like ESC[0m or ESC[1;36m - consume until 'm'
consume_ansi_sequence(State) ->
    case io:get_chars(standard_io, "", 1) of
        [C] when C >= $0, C =< $9; C == $; ->
            %% Continue consuming
            consume_ansi_sequence(State);
        "m" ->
            %% End of ANSI sequence
            line_editor_loop(State);
        _ ->
            %% Unexpected - just continue
            line_editor_loop(State)
    end.

%% @doc Finish line editing and return result
finish_line(Buffer) ->
    io:format("\r\n"),
    %% Clear the saved buffer from ETS since input is complete
    case ets:whereis(cryptic_console_input_buffer) of
        undefined ->
            ok;
        TableRef ->
            ets:delete(TableRef, current_input),
            %% Save to history if it's not empty and not a duplicate of the last entry
            FlatBuffer = lists:flatten(Buffer),
            case string:trim(FlatBuffer) of
                %% Don't save empty commands
                "" ->
                    ok;
                TrimmedCmd ->
                    %% Get current history count
                    HistoryCount =
                        case ets:lookup(TableRef, history_count) of
                            [{history_count, Count}] ->
                                Count;
                            [] ->
                                0
                        end,
                    %% Check if it's different from the last command
                    ShouldSave =
                        case HistoryCount of
                            0 ->
                                true;
                            _ ->
                                case
                                    ets:lookup(
                                        TableRef, {history, HistoryCount - 1}
                                    )
                                of
                                    [{_, LastCmd}] ->
                                        TrimmedCmd =/= LastCmd;
                                    [] ->
                                        true
                                end
                        end,
                    case ShouldSave of
                        true ->
                            %% Save command to history
                            ets:insert(TableRef, {
                                {history, HistoryCount}, TrimmedCmd
                            }),
                            %% Update history count
                            ets:insert(
                                TableRef, {history_count, HistoryCount + 1}
                            ),
                            %% Keep only last 100 commands
                            cleanup_old_history(TableRef, HistoryCount + 1);
                        false ->
                            ok
                    end
            end
    end,
    lists:flatten(Buffer).

%% @doc Save current buffer to ETS table for preservation across restarts
save_buffer_to_ets(BufferTable, Buffer) ->
    case BufferTable of
        undefined ->
            ok;
        TableName when is_atom(TableName) ->
            %% Check if the named table exists before writing
            case ets:whereis(TableName) of
                undefined ->
                    ok;
                _Ref ->
                    ets:insert(TableName, {current_input, Buffer})
            end;
        TableRef when is_reference(TableRef) ->
            ets:insert(TableRef, {current_input, Buffer});
        _ ->
            ok
    end.

%% @doc Insert character at cursor position
insert_char(
    #line_state{
        buffer = Buffer,
        cursor = Cursor,
        buffer_table = BufferTable
    } =
        State,
    Char
) ->
    {Left, Right} = lists:split(Cursor, Buffer),
    NewBuffer = Left ++ [Char] ++ Right,
    NewCursor = Cursor + 1,
    NewState = State#line_state{buffer = NewBuffer, cursor = NewCursor},

    %% Save buffer to ETS
    save_buffer_to_ets(BufferTable, NewBuffer),

    case Right of
        [] ->
            %% Inserting at end - just echo
            io:format("~c", [Char]);
        _ ->
            %% Inserting in middle - redraw
            io:format("~c", [Char]),
            redraw_from_cursor(NewState)
    end,

    line_editor_loop(NewState).

%% @doc Move to beginning of line (Ctrl+A)
handle_ctrl_a(#line_state{cursor = 0} = State) ->
    line_editor_loop(State);
handle_ctrl_a(#line_state{cursor = Cursor} = State) ->
    io:format("~s", [lists:duplicate(Cursor, "\b")]),
    line_editor_loop(State#line_state{cursor = 0}).

%% @doc Move to end of line (Ctrl+E)
handle_ctrl_e(#line_state{buffer = Buffer, cursor = Cursor} = State) ->
    LineLen = length(Buffer),
    case LineLen - Cursor of
        0 ->
            line_editor_loop(State);
        Distance ->
            io:format("~s", [lists:duplicate(Distance, "\e[C")]),
            line_editor_loop(State#line_state{cursor = LineLen})
    end.

%% @doc Move forward one character (Ctrl+F, Right Arrow)
handle_ctrl_f(#line_state{buffer = Buffer, cursor = Cursor} = State) ->
    case Cursor < length(Buffer) of
        true ->
            io:format("\e[C"),
            line_editor_loop(State#line_state{cursor = Cursor + 1});
        false ->
            line_editor_loop(State)
    end.

%% @doc Move backward one character (Ctrl+B, Left Arrow)
handle_ctrl_b(#line_state{cursor = 0} = State) ->
    line_editor_loop(State);
handle_ctrl_b(#line_state{cursor = Cursor} = State) ->
    io:format("\b"),
    line_editor_loop(State#line_state{cursor = Cursor - 1}).

%% @doc Delete character at cursor (Ctrl+D)
handle_ctrl_d(
    #line_state{
        buffer = Buffer,
        cursor = Cursor,
        buffer_table = BufferTable
    } =
        State
) ->
    case Cursor < length(Buffer) of
        true ->
            {Left, [_ | Right]} = lists:split(Cursor, Buffer),
            NewBuffer = Left ++ Right,
            NewState = State#line_state{buffer = NewBuffer},

            %% Save buffer to ETS
            save_buffer_to_ets(BufferTable, NewBuffer),

            redraw_from_cursor(NewState),
            line_editor_loop(NewState);
        false ->
            line_editor_loop(State)
    end.

%% @doc Backspace (Ctrl+H)
handle_ctrl_h(#line_state{cursor = 0} = State) ->
    line_editor_loop(State);
handle_ctrl_h(
    #line_state{
        buffer = Buffer,
        cursor = Cursor,
        buffer_table = BufferTable
    } =
        State
) ->
    {Left, Right} = lists:split(Cursor, Buffer),
    NewBuffer = lists:droplast(Left) ++ Right,
    NewCursor = Cursor - 1,

    %% Save buffer to ETS
    save_buffer_to_ets(BufferTable, NewBuffer),

    io:format("\b"),
    NewState = State#line_state{buffer = NewBuffer, cursor = NewCursor},
    redraw_from_cursor(NewState),
    line_editor_loop(NewState).

%% @doc Kill from cursor to end (Ctrl+K)
handle_ctrl_k(
    #line_state{
        buffer = Buffer,
        cursor = Cursor,
        buffer_table = BufferTable
    } =
        State
) ->
    {Left, _Right} = lists:split(Cursor, Buffer),
    NewState = State#line_state{buffer = Left},

    %% Save buffer to ETS
    save_buffer_to_ets(BufferTable, Left),

    io:format("\e[K"),
    line_editor_loop(NewState).

%% @doc Kill entire line (Ctrl+U)
handle_ctrl_u(#line_state{prompt = Prompt, buffer_table = BufferTable} = State) ->
    io:format("\r~s", [Prompt]),
    NewState = State#line_state{buffer = [], cursor = 0},

    %% Save buffer to ETS
    save_buffer_to_ets(BufferTable, []),

    line_editor_loop(NewState).

%% @doc Navigate to previous history entry (Ctrl+P, Up Arrow)
handle_ctrl_p(#line_state{buffer_table = undefined} = State) ->
    %% No history available
    line_editor_loop(State);
handle_ctrl_p(
    #line_state{
        buffer_table = BufferTable,
        history_pos = HistoryPos,
        buffer = CurrentBuffer,
        original_buffer = OriginalBuffer,
        prompt = Prompt
    } =
        State
) ->
    case ets:whereis(BufferTable) of
        undefined ->
            line_editor_loop(State);
        TableRef ->
            %% Get history count
            HistoryCount =
                case ets:lookup(TableRef, history_count) of
                    [{history_count, Count}] ->
                        Count;
                    [] ->
                        0
                end,

            case HistoryCount of
                0 ->
                    %% No history
                    line_editor_loop(State);
                _ ->
                    %% Determine new position
                    NewPos =
                        case HistoryPos of
                            undefined ->
                                %% First time navigating - save current buffer and go to most recent
                                HistoryCount - 1;
                            Pos when Pos > 0 ->
                                %% Go to previous entry
                                Pos - 1;
                            _ ->
                                %% Already at oldest
                                HistoryPos
                        end,

                    %% Only update if position changed
                    case NewPos =:= HistoryPos of
                        true ->
                            line_editor_loop(State);
                        false ->
                            %% Retrieve history entry
                            case ets:lookup(TableRef, {history, NewPos}) of
                                [{_, HistoryCmd}] ->
                                    %% Save original buffer on first navigation
                                    NewOriginal =
                                        case HistoryPos of
                                            undefined ->
                                                CurrentBuffer;
                                            _ ->
                                                OriginalBuffer
                                        end,

                                    %% Replace current line with history entry
                                    replace_line_with_text(
                                        Prompt,
                                        HistoryCmd,
                                        State#line_state{
                                            history_pos = NewPos,
                                            original_buffer =
                                                NewOriginal
                                        }
                                    );
                                [] ->
                                    line_editor_loop(State)
                            end
                    end
            end
    end.

%% @doc Navigate to next history entry (Ctrl+N, Down Arrow)
handle_ctrl_n(#line_state{buffer_table = undefined} = State) ->
    %% No history available
    line_editor_loop(State);
handle_ctrl_n(#line_state{history_pos = undefined} = State) ->
    %% Not navigating history, nothing to do
    line_editor_loop(State);
handle_ctrl_n(
    #line_state{
        buffer_table = BufferTable,
        history_pos = HistoryPos,
        original_buffer = OriginalBuffer,
        prompt = Prompt
    } =
        State
) ->
    case ets:whereis(BufferTable) of
        undefined ->
            line_editor_loop(State);
        TableRef ->
            %% Get history count
            HistoryCount =
                case ets:lookup(TableRef, history_count) of
                    [{history_count, Count}] ->
                        Count;
                    [] ->
                        0
                end,

            NewPos = HistoryPos + 1,

            case NewPos >= HistoryCount of
                true ->
                    %% Return to original buffer
                    replace_line_with_text(
                        Prompt,
                        OriginalBuffer,
                        State#line_state{
                            history_pos = undefined,
                            original_buffer = []
                        }
                    );
                false ->
                    %% Go to next entry
                    case ets:lookup(TableRef, {history, NewPos}) of
                        [{_, HistoryCmd}] ->
                            replace_line_with_text(
                                Prompt,
                                HistoryCmd,
                                State#line_state{history_pos = NewPos}
                            );
                        [] ->
                            line_editor_loop(State)
                    end
            end
    end.

%% @doc Replace current line with new text
replace_line_with_text(Prompt, NewText, State) ->
    %% Clear current line
    io:format("\r~s\e[K", [Prompt]),

    %% Convert text to buffer
    NewBuffer =
        case is_list(NewText) of
            true ->
                NewText;
            false ->
                []
        end,

    %% Display new text
    io:format("~s", [NewBuffer]),

    %% Update state
    NewState = State#line_state{buffer = NewBuffer, cursor = length(NewBuffer)},

    line_editor_loop(NewState).

%% @doc Clean up old history entries, keeping only the last MaxHistory entries
cleanup_old_history(TableRef, CurrentCount) ->
    MaxHistory = 100,
    case CurrentCount > MaxHistory of
        true ->
            %% Delete oldest entries
            NumToDelete = CurrentCount - MaxHistory,
            lists:foreach(
                fun(N) -> ets:delete(TableRef, {history, N}) end,
                lists:seq(0, NumToDelete - 1)
            );
        false ->
            ok
    end.

%% @doc Redraw line content from cursor to end
redraw_from_cursor(#line_state{buffer = Buffer, cursor = Cursor}) ->
    {_Left, Right} = lists:split(Cursor, Buffer),
    RightText = lists:flatten(Right),

    io:format("\e[K~s", [RightText]),
    BackDistance = length(Right),
    if
        BackDistance > 0 ->
            io:format("~s", [lists:duplicate(BackDistance, "\b")]);
        true ->
            ok
    end.

%% @doc Password input loop with masking
password_loop(Acc) ->
    case io:get_chars(standard_io, "", 1) of
        "\n" ->
            io:format("\r\n"),
            lists:reverse(Acc);
        "\r" ->
            io:format("\r\n"),
            lists:reverse(Acc);
        [127] ->
            handle_password_backspace(Acc);
        [8] ->
            handle_password_backspace(Acc);
        eof ->
            io:format("\r\n"),
            lists:reverse(Acc);
        [C] when C < 32 ->
            password_loop(Acc);
        [Char] ->
            io:format("*"),
            password_loop([Char | Acc])
    end.

%% @doc Handle backspace in password mode
handle_password_backspace([]) ->
    password_loop([]);
handle_password_backspace([_Last | Rest]) ->
    io:format("\b \b"),
    password_loop(Rest).

%%%===================================================================
%%% Enhanced Output Functions with ANSI Formatting
%%%===================================================================

print_user_message(FromUser, Message, Timestamp) when
    is_list(FromUser) andalso is_binary(Message)
->
    %% Clear the current line first (in case we're interrupting a prompt)
    io:format("\r~s", [?CLEAR_LINE]),
    %% Should print like:
    %% <bob> Hello there (12:34:56)
    %% where each part is colored differently.
    {{_Year, _Month, _Day}, {Hour, Minute, Second}} =
        calendar:now_to_universal_time(Timestamp),
    TimeStr = io_lib:format("~2..0B:~2..0B:~2..0B", [Hour, Minute, Second]),
    io:format(
        "~s: ~s (~s)\r\n",
        [
            ?FG_CYAN("<" ++ FromUser ++ ">"),
            ?FG_WHITE(binary_to_list(Message)),
            ?FG_YELLOW(TimeStr)
        ]
    ).

%% @doc Print a sent message to show confirmation
%% Formats as: &lt;You => bob&gt; Message text (HH:MM:SS)
-spec print_sent_message(
    ToUser :: string() | binary(),
    Message :: binary(),
    Timestamp :: erlang:timestamp()
) ->
    ok.
print_sent_message(ToUser, Message, Timestamp) when is_binary(ToUser) ->
    print_sent_message(binary_to_list(ToUser), Message, Timestamp);
print_sent_message(ToUser, Message, Timestamp) when
    is_list(ToUser) andalso is_binary(Message)
->
    %% Calculate how many lines the command took up and clear them
    %% The last command was: prompt + the actual command
    %% We need to reconstruct what was typed to know how many lines to clear
    Prompt = make_prompt(),

    %% Get terminal width (default to 80 if we can't determine it)
    TermWidth =
        case io:columns() of
            {ok, Cols} -> Cols;
            _ -> 80
        end,

    %% Reconstruct the command line that was just executed
    %% Format: ":s <username> <message>" or "send <username> <message>"
    CommandLine = Prompt ++ ":s " ++ ToUser ++ " " ++ binary_to_list(Message),

    %% Calculate how many lines this wrapped to
    LinesToClear = calculate_wrapped_lines(CommandLine, TermWidth),

    %% Move up and clear all those lines
    clear_lines_up(LinesToClear),

    %% Now print the sent message confirmation
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

%% @doc Print a message from history
%% Format: [timestamp] from -> to @ server:port: message
%% When ServerHost/ServerPort are undefined, format as: [timestamp] from -> to : message
-spec print_history_message(
    FromUser :: binary() | string(),
    ToUser :: binary() | string(),
    Message :: binary() | string(),
    Timestamp :: calendar:datetime(),
    ServerHost :: binary() | string() | undefined,
    ServerPort :: non_neg_integer() | undefined
) ->
    ok.
print_history_message(
    FromUser, ToUser, Message, Timestamp, ServerHost, ServerPort
) ->
    %% Convert inputs to strings
    FromUserStr =
        case FromUser of
            F when is_binary(F) -> binary_to_list(F);
            F when is_list(F) -> F
        end,
    ToUserStr =
        case ToUser of
            T when is_binary(T) -> binary_to_list(T);
            T when is_list(T) -> T
        end,
    MessageStr =
        case Message of
            M when is_binary(M) -> binary_to_list(M);
            M when is_list(M) -> M
        end,

    %% Format timestamp
    {{Year, Month, Day}, {Hour, Minute, Second}} = Timestamp,
    TimeStr = lists:flatten(
        io_lib:format(
            "~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B",
            [Year, Month, Day, Hour, Minute, Second]
        )
    ),

    %% Print formatted message with or without server info
    case {ServerHost, ServerPort} of
        {undefined, undefined} ->
            %% No server info - simpler format
            io:format("[~s] ~s -> ~s : ~s\r\n", [
                ?FG_CYAN(TimeStr),
                ?FG_YELLOW(FromUserStr),
                ?FG_YELLOW(ToUserStr),
                ?FG_WHITE(MessageStr)
            ]);
        {_, _} ->
            %% Include server info
            ServerHostStr =
                case ServerHost of
                    S when is_binary(S) -> binary_to_list(S);
                    S when is_list(S) -> S
                end,
            io:format("[~s] ~s -> ~s @ ~s:~p: ~s\r\n", [
                ?FG_CYAN(TimeStr),
                ?FG_YELLOW(FromUserStr),
                ?FG_YELLOW(ToUserStr),
                ?FG_MAGENTA(ServerHostStr),
                ServerPort,
                ?FG_WHITE(MessageStr)
            ])
    end.

%% @doc Calculate how many lines a text string will wrap to given terminal width
%% Takes into account ANSI escape sequences which don't consume visible columns
-spec calculate_wrapped_lines(string(), pos_integer()) -> pos_integer().
calculate_wrapped_lines(Text, TermWidth) ->
    %% Strip ANSI escape sequences to get visible length
    VisibleText = strip_ansi_codes(Text),
    VisibleLength = length(VisibleText),

    %% Calculate number of lines (at least 1)
    max(1, (VisibleLength + TermWidth - 1) div TermWidth).

%% @doc Strip ANSI escape sequences from a string
-spec strip_ansi_codes(string()) -> string().
strip_ansi_codes(Text) ->
    %% Remove ANSI escape sequences: ESC[...m and similar
    %% This is a simple implementation - for more complex sequences,
    %% we'd need a proper state machine
    strip_ansi_codes(Text, [], false).

strip_ansi_codes([], Acc, _InEscape) ->
    lists:reverse(Acc);
strip_ansi_codes([27 | Rest], Acc, _InEscape) ->
    %% ESC character - start of escape sequence
    strip_ansi_codes(Rest, Acc, true);
strip_ansi_codes([Char | Rest], Acc, true) ->
    %% Inside escape sequence - skip until we hit a letter
    case
        (Char >= $A andalso Char =< $Z) orelse (Char >= $a andalso Char =< $z)
    of
        true ->
            %% End of escape sequence
            strip_ansi_codes(Rest, Acc, false);
        false ->
            %% Still in escape sequence
            strip_ansi_codes(Rest, Acc, true)
    end;
strip_ansi_codes([Char | Rest], Acc, false) ->
    %% Regular character
    strip_ansi_codes(Rest, [Char | Acc], false).

%% @doc Clear N lines upward from current cursor position
-spec clear_lines_up(pos_integer()) -> ok.
clear_lines_up(N) when N =< 0 ->
    ok;
clear_lines_up(N) ->
    %% Move up N lines
    io:format("~s", [?CURSOR_UP(N)]),
    %% Clear from cursor to end of screen (clears current line and all below)
    io:format("\e[J"),
    ok.

%% @doc Print success message with green formatting
-spec print_success(string()) -> ok.
print_success(Message) ->
    io:format("~s\r\n", [?FG_GREEN(?BOLD("[OK] " ++ Message))]).

%% @doc Print error message with red formatting
-spec print_error(string()) -> ok.
print_error(Message) ->
    io:format("~s\r\n", [?FG_WHITE_BG_RED(?BOLD("[ERROR] " ++ Message))]).

%% @doc Print warning message with yellow formatting
-spec print_warning(string()) -> ok.
print_warning(Message) ->
    io:format("~s\r\n", [?FG_BLACK_BG_YELLOW(?BOLD("[WARN] " ++ Message))]).

%% @doc Print info message with cyan formatting
-spec print_info(string()) -> ok.
print_info(Message) ->
    io:format("~s\r\n", [?FG_CYAN(?BOLD("[INFO] " ++ Message))]).

%% @doc Print highlighted message with blue formatting
-spec print_highlight(string()) -> ok.
print_highlight(Message) ->
    io:format("~s\r\n", [?FG_WHITE_BG_BLUE(?BOLD("[***] " ++ Message))]).

%% @doc Print CA operation response
-spec print_ca_response(map()) -> ok.
print_ca_response(Response) ->
    Type = maps:get(<<"type">>, Response, <<"unknown">>),
    
    case Type of
        <<"invite_create_response">> ->
            print_invite_create_response(Response);
        <<"invite_list_response">> ->
            print_invite_list_response(Response);
        <<"invite_revoke_response">> ->
            print_invite_revoke_response(Response);
        <<"invite_show_response">> ->
            print_invite_show_response(Response);
        _ ->
            %% Generic CA response display
            print_info(io_lib:format("CA Response: ~p", [Response]))
    end.

%% @private Print invite creation response
print_invite_create_response(Response) ->
    case maps:get(<<"status">>, Response, undefined) of
        <<"success">> ->
            InviteId = maps:get(<<"invite_id">>, Response, <<"unknown">>),
            ExpiresAt = maps:get(<<"expires_at">>, Response, 0),
            DateTime = calendar:system_time_to_rfc3339(ExpiresAt, [{unit, second}, {offset, "Z"}]),
            print_success("Invite created successfully"),
            io:format("  Invite ID: ~s\r\n", [InviteId]),
            io:format("  Expires:   ~s\r\n", [DateTime]);
        _ ->
            Error = maps:get(<<"error">>, Response, <<"unknown">>),
            Msg = maps:get(<<"message">>, Response, <<"">>),
            print_error(io_lib:format("Failed to create invite: ~s - ~s", [Error, Msg]))
    end.

%% @private Print invite list response
print_invite_list_response(Response) ->
    case maps:get(<<"status">>, Response, undefined) of
        <<"success">> ->
            Invites = maps:get(<<"invites">>, Response, []),
            print_success(io_lib:format("Found ~p invite(s)", [length(Invites)])),
            lists:foreach(fun(Invite) ->
                InviteId = maps:get(<<"invite_id">>, Invite, <<"unknown">>),
                ExpiresAt = maps:get(<<"expires_at">>, Invite, 0),
                Consumed = maps:get(<<"consumed">>, Invite, false),
                Expired = maps:get(<<"expired">>, Invite, false),
                Meta = maps:get(<<"meta">>, Invite, #{}),
                Note = maps:get(<<"note">>, Meta, <<"">>),
                
                Status = if
                    Consumed -> "CONSUMED";
                    Expired -> "EXPIRED";
                    true -> "ACTIVE"
                end,
                
                DateTime = calendar:system_time_to_rfc3339(ExpiresAt, [{unit, second}, {offset, "Z"}]),
                
                %% Print invite details
                io:format("  ~s\r\n", [InviteId]),
                io:format("    Status:  ~s\r\n", [Status]),
                io:format("    Expires: ~s\r\n", [DateTime]),
                case Note of
                    <<>> -> ok;
                    _ -> io:format("    Note:    ~s\r\n", [Note])
                end,
                io:format("\r\n")
            end, Invites);
        _ ->
            Error = maps:get(<<"error">>, Response, <<"unknown">>),
            Msg = maps:get(<<"message">>, Response, <<"">>),
            print_error(io_lib:format("Failed to list invites: ~s - ~s", [Error, Msg]))
    end.

%% @private Print invite revoke response
print_invite_revoke_response(Response) ->
    case maps:get(<<"status">>, Response, undefined) of
        <<"success">> ->
            InviteId = maps:get(<<"invite_id">>, Response, <<"unknown">>),
            print_success(io_lib:format("Invite revoked: ~s", [InviteId]));
        _ ->
            Error = maps:get(<<"error">>, Response, <<"unknown">>),
            Msg = maps:get(<<"message">>, Response, <<"">>),
            print_error(io_lib:format("Failed to revoke invite: ~s - ~s", [Error, Msg]))
    end.

%% @private Print invite show response
print_invite_show_response(Response) ->
    case maps:get(<<"status">>, Response, undefined) of
        <<"success">> ->
            Invite = maps:get(<<"invite">>, Response, #{}),
            InviteId = maps:get(<<"invite_id">>, Invite, <<"unknown">>),
            ExpiresAt = maps:get(<<"expires_at">>, Invite, 0),
            Consumed = maps:get(<<"consumed">>, Invite, false),
            Expired = maps:get(<<"expired">>, Invite, false),
            Meta = maps:get(<<"meta">>, Invite, #{}),
            Note = maps:get(<<"note">>, Meta, <<"">>),
            
            Status = if
                Consumed -> "CONSUMED";
                Expired -> "EXPIRED";
                true -> "ACTIVE"
            end,
            
            DateTime = calendar:system_time_to_rfc3339(ExpiresAt, [{unit, second}, {offset, "Z"}]),
            
            print_success("Invite details:"),
            io:format("  ID:      ~s\r\n", [InviteId]),
            io:format("  Status:  ~s\r\n", [Status]),
            io:format("  Expires: ~s\r\n", [DateTime]),
            case Note of
                <<>> -> ok;
                _ -> io:format("  Note:    ~s\r\n", [Note])
            end;
        _ ->
            Error = maps:get(<<"error">>, Response, <<"unknown">>),
            Msg = maps:get(<<"message">>, Response, <<"">>),
            print_error(io_lib:format("Failed to show invite: ~s - ~s", [Error, Msg]))
    end.

%% @doc Print engine status on alternate screen
%% Takes a status map and displays it in a formatted view on the alternate screen buffer.
%% This keeps the main message area clean and uncluttered.
-spec print_engine_status(map()) -> ok.
print_engine_status(Status) ->
    %% Switch to alternate screen buffer
    io:format(?ALT_SCREEN_ON),
    io:format(?CLEAR_SCREEN),
    io:format(?MVTO_ROW_COL(1, 1)),

    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              CRYPTIC ENGINE STATUS                            "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    %% Format username
    Username = maps:get(username, Status, <<"unknown">>),
    UsernameStr =
        case Username of
            U when is_binary(U) -> binary_to_list(U);
            U when is_list(U) -> U;
            _ -> "unknown"
        end,
    io:format(?FG_GREEN("  Username:         ") ++ UsernameStr ++ "\r\n"),

    %% Format active sessions
    ActiveSessions = maps:get(active_sessions, Status, 0),
    io:format(
        ?FG_GREEN("  Active Sessions:  ") ++ integer_to_list(ActiveSessions) ++
            "\r\n"
    ),

    %% Format message count
    MessageCount = maps:get(message_count, Status, 0),
    io:format(
        ?FG_GREEN("  Messages Sent:    ") ++ integer_to_list(MessageCount) ++
            "\r\n"
    ),

    %% Format error count with conditional coloring
    ErrorCount = maps:get(error_count, Status, 0),
    ErrorStr = integer_to_list(ErrorCount),
    ErrorColored =
        if
            ErrorCount > 0 -> ?FG_RED(ErrorStr);
            true -> ErrorStr
        end,
    io:format(?FG_GREEN("  Errors:           ") ++ ErrorColored ++ "\r\n"),

    %% Format uptime
    Uptime = maps:get(uptime, Status, 0),
    UptimeFormatted = format_uptime(Uptime),
    io:format(?FG_GREEN("  Uptime:           ") ++ UptimeFormatted ++ "\r\n"),

    %% Display session details if any
    SessionDetails = maps:get(session_details, Status, []),
    case SessionDetails of
        [] ->
            ok;
        _ ->
            io:format("\r\n"),
            io:format(?BOLD(?FG_CYAN("Active Ratchet Sessions:")) ++ "\r\n"),
            io:format(
                ?BOLD(
                    "─────────────────────────────────────────────────────────────────"
                ) ++ "\r\n"
            ),

            lists:foreach(fun format_session_info/1, SessionDetails),

            %% Add metric explanation
            io:format("\r\n"),
            io:format(
                ?FG_CYAN(
                    "  Step X: "
                ) ++
                    ?FG_MAGENTA(
                        "Number of DH ratchet steps (key rotations) that have occurred"
                    ) ++
                    "\r\n"
                    ?FG_CYAN(
                        "  Chain[X init/Y resp]:"
                    ) ++
                    ?FG_MAGENTA(
                        " Current initiator/responder chain message counters"
                    ) ++
                    "\r\n"
                    ?FG_MAGENTA(
                        "                        These reset to 0 when DH ratchet steps occur"
                    ) ++
                    "\r\n"
                    ?FG_CYAN(
                        "  Prev[X msgs]:"
                    ) ++
                    ?FG_MAGENTA(" Messages from the previous receiving chain") ++
                    "\r\n"
                    ?FG_CYAN(
                        "  Skipped[X keys]:"
                    ) ++
                    ?FG_MAGENTA(
                        " Out-of-order messages cached for delayed delivery"
                    ) ++ "\r\n"
            )
    end,

    %% Show instructions and wait for keypress
    io:format("\r\n\r\n"),
    io:format(?FG_YELLOW("Press any key to return...") ++ "\r\n"),

    %% Wait for a keypress
    io:get_chars("", 1),

    %% Return to main screen buffer
    io:format(?ALT_SCREEN_OFF).

%% @doc Format and display a single session info line
%% Helper function for print_engine_status/1
-spec format_session_info(map()) -> ok.
format_session_info(SessionInfo) ->
    PeerUsername = maps:get(peer_username, SessionInfo, <<"unknown">>),
    Peer =
        case PeerUsername of
            P when is_binary(P) -> binary_to_list(P);
            P when is_list(P) -> P;
            _ -> "unknown"
        end,
    DHStep = maps:get(dh_ratchet_step, SessionInfo, 0),
    CurrentSend = maps:get(send_msg_number, SessionInfo, 0),
    CurrentRecv = maps:get(recv_msg_number, SessionInfo, 0),
    PrevChain = maps:get(prev_recv_chain_length, SessionInfo, 0),
    SkippedKeys = maps:get(skipped_keys_count, SessionInfo, 0),

    %% Format with colors
    PeerColored = ?FG_CYAN(Peer),
    io:format("  " ++ PeerColored ++ ": "),
    io:format(?FG_GREEN("Step ") ++ integer_to_list(DHStep) ++ ", "),
    io:format(
        ?FG_GREEN("Chain") ++ "[" ++ integer_to_list(CurrentSend) ++
            ?FG_YELLOW(" init") ++ ", "
    ),
    io:format(integer_to_list(CurrentRecv) ++ ?FG_YELLOW(" resp") ++ "], "),
    io:format(
        ?FG_GREEN("Prev") ++ "[" ++ integer_to_list(PrevChain) ++
            ?FG_YELLOW(" msgs") ++ "]" ++ ", "
    ),
    io:format(
        ?FG_GREEN("Skipped") ++ "[" ++ integer_to_list(SkippedKeys) ++
            ?FG_YELLOW(" keys") ++ "]\r\n"
    ).

%% @doc Format uptime from microseconds to human-readable string
%% Helper function for print_engine_status/1
-spec format_uptime(non_neg_integer()) -> string().
format_uptime(Microseconds) ->
    Seconds = Microseconds div 1000000,
    Minutes = Seconds div 60,
    Hours = Minutes div 60,
    Days = Hours div 24,

    RemainderHours = Hours rem 24,
    RemainderMinutes = Minutes rem 60,
    RemainderSeconds = Seconds rem 60,

    if
        Days > 0 ->
            lists:flatten(
                io_lib:format(
                    "~B days, ~B hours, ~B minutes",
                    [Days, RemainderHours, RemainderMinutes]
                )
            );
        Hours > 0 ->
            lists:flatten(
                io_lib:format(
                    "~B hours, ~B minutes",
                    [Hours, RemainderMinutes]
                )
            );
        Minutes > 0 ->
            lists:flatten(
                io_lib:format(
                    "~B minutes, ~B seconds",
                    [Minutes, RemainderSeconds]
                )
            );
        true ->
            lists:flatten(io_lib:format("~B seconds", [Seconds]))
    end.

%% @doc Display help information on alternate screen
-spec print_help() -> ok.
print_help() ->
    print_help("").

%% @doc Display topic-specific help or general help
-spec print_help(string()) -> ok.
print_help(Topic) ->
    %% Switch to alternate screen buffer
    io:format(?ALT_SCREEN_ON),
    io:format(?CLEAR_SCREEN),
    io:format(?MVTO_ROW_COL(1, 1)),

    case Topic of
        "alias" ->
            print_alias_help();
        "history" ->
            print_history_help();
        "db" ->
            print_db_help();
        "invite" ->
            print_invite_help();
        "cert" ->
            print_cert_help();
        "line_edit" ->
            print_line_edit_help();
        _ ->
            print_general_help()
    end,

    %% Show instructions and wait for keypress
    io:format("\r\n\r\n"),
    io:format(?FG_YELLOW("Press any key to return...") ++ "\r\n"),

    %% Wait for a keypress
    io:get_chars("", 1),

    %% Return to main screen buffer
    io:format(?ALT_SCREEN_OFF).

%% @doc Print general help
print_general_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              CRYPTIC CONSOLE HELP                             "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    %% Commands section
    io:format(?BOLD(?FG_CYAN("Available Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  send") ++ " " ++ ?FG_YELLOW("<username> <message>") ++
            "  - Send message to user " ++ ?FG_MAGENTA("(:s)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias") ++
            "                      - Manage message aliases " ++
            ?FG_MAGENTA("(:a)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  history") ++ " " ++ ?FG_YELLOW("[query]") ++
            "            - View message history " ++
            ?FG_MAGENTA("(:h <query>)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  invite") ++ " " ++ ?FG_YELLOW("[create|list|show|revoke]") ++
            " - Manage invitations " ++
            ?FG_MAGENTA("(:ic,:il,:ir)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  cert") ++ " " ++ ?FG_YELLOW("[status|renew]") ++
            "       - Manage certificates " ++
            ?FG_MAGENTA("(:cs,:cr)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  db") ++ " " ++ ?FG_YELLOW("[enable|disable|status]") ++
            " - Control message storage\r\n"
    ),
    io:format(
        ?FG_GREEN("  status") ++ "                     - Show console status " ++
            ?FG_MAGENTA("(:st)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  engine_status") ++ "              - Show engine status " ++
            ?FG_MAGENTA("(:es)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  help") ++ " " ++ ?FG_YELLOW("[<topic>]") ++
            "             - Show help " ++ ?FG_MAGENTA("(:h)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  quit") ++ "                       - Exit console " ++
            ?FG_MAGENTA("(:q)") ++ "\r\n"
    ),

    %% Topics section
    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Help Topics:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  help alias") ++
            "                  - Alias command details\r\n"
    ),
    io:format(
        ?FG_GREEN("  help history") ++
            "                - Message history queries\r\n"
    ),
    io:format(
        ?FG_GREEN("  help invite") ++
            "                 - Invitation management\r\n"
    ),
    io:format(
        ?FG_GREEN("  help cert") ++
            "                   - Certificate management\r\n"
    ),
    io:format(
        ?FG_GREEN("  help db") ++
            "                     - Database storage control\r\n"
    ),
    io:format(
        ?FG_GREEN("  help line_edit") ++
            "              - Line editing keybindings\r\n"
    ).

%% @doc Print alias-specific help
print_alias_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              ALIAS COMMAND HELP                               "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Description:")) ++ "\r\n"),
    io:format(
        "  Aliases allow you to send messages to multiple users at once.\r\n"
    ),
    io:format(
        "  Think of them as group messaging shortcuts.\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias") ++ " or " ++ ?FG_MAGENTA(":a") ++
            "                 - List all aliases\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias new") ++ " " ++ ?FG_YELLOW("<name> <users...>") ++
            " - Create alias " ++ ?FG_MAGENTA("(:an)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias delete") ++ " " ++ ?FG_YELLOW("<name>") ++
            "         - Delete alias " ++ ?FG_MAGENTA("(:ad)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias add") ++ " " ++ ?FG_YELLOW("<name> <users...>") ++
            " - Add members " ++ ?FG_MAGENTA("(:aa)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  alias rm") ++ " " ++ ?FG_YELLOW("<name> <users...>") ++
            "  - Remove members " ++ ?FG_MAGENTA("(:ar)") ++ "\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Usage Examples:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :an work bob alice dave") ++
            "     # Create alias 'work'\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :s @work Coffee break?") ++
            "      # Send to all in 'work'\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :aa work eve") ++
            "                # Add eve to 'work'\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :ar work dave") ++
            "               # Remove dave from 'work'\r\n"
    ).

%% @doc Print history-specific help
print_history_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "            MESSAGE HISTORY HELP                               "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Description:")) ++ "\r\n"),
    io:format(
        "  View your encrypted message history stored locally.\r\n"
    ),
    io:format(
        "  All messages are encrypted with your passphrase.\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  history") ++ " or " ++ ?FG_MAGENTA(":history") ++
            "           - Show last 10 messages\r\n"
    ),
    io:format(
        ?FG_GREEN("  history last") ++ " " ++ ?FG_YELLOW("<N>") ++
            "              - Show last N messages (max 1000)\r\n"
    ),
    io:format(
        ?FG_GREEN("  history from") ++ " " ++ ?FG_YELLOW("<user>") ++
            " yesterday - Messages from user yesterday\r\n"
    ),
    io:format(
        ?FG_GREEN("  history from") ++ " " ++ ?FG_YELLOW("<user>") ++
            " last " ++ ?FG_YELLOW("<N>") ++ "  - Last N messages from user\r\n"
    ),
    io:format(
        ?FG_GREEN("  history with") ++ " " ++ ?FG_YELLOW("<user>") ++
            " last " ++ ?FG_YELLOW("<N>") ++ "  - Conversation with user\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Shortcuts:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_MAGENTA("  :hi") ++ " " ++ ?FG_YELLOW("<query>") ++
            "                   - Short for 'history <query>'\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Examples:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :history") ++
            "                      # Last 10 messages\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :hi last 20") ++
            "                   # Last 20 messages\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :hi from alice yesterday") ++
            "      # Yesterday's messages from alice\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :hi from bob last 15") ++
            "          # Last 15 messages from bob\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :hi with alice last 30") ++
            "        # Last 30 messages with alice\r\n"
    ).

%% @doc Print database storage help
print_db_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              DATABASE STORAGE CONTROL                        "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Overview:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        "  The database storage feature saves all received messages in an\r\n"
    ),
    io:format(
        "  encrypted SQLite database. You can enable/disable this feature at\r\n"
    ),
    io:format(
        "  runtime for privacy control during sensitive conversations.\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  db enable") ++
            "                  - Enable message storage\r\n"
    ),
    io:format(
        "                             Messages will be encrypted and saved\r\n\r\n"
    ),
    io:format(
        ?FG_GREEN("  db disable") ++
            "                 - Disable message storage\r\n"
    ),
    io:format(
        "                             New messages will NOT be saved to disk\r\n\r\n"
    ),
    io:format(
        ?FG_GREEN("  db status") ++ " or " ++ ?FG_GREEN("db") ++
            "           - Check current storage status\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Configuration:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        "  Set " ++ ?FG_YELLOW("{enable_db, true}") ++
            " in config/sys.config to enable by default\r\n"
    ),
    io:format(
        "  Set " ++ ?FG_YELLOW("{enable_db, false}") ++
            " to disable by default (current)\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Security Note:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        "  All messages are encrypted using ChaCha20-Poly1305 with your\r\n"
    ),
    io:format(
        "  passphrase. However, metadata (usernames, timestamps, server info)\r\n"
    ),
    io:format(
        "  is stored in plaintext. Disable storage for maximum privacy.\r\n"
    ).

%% @doc Print line editing help
print_line_edit_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              LINE EDITING KEYS                                "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Navigation:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+A") ++ " or " ++ ?FG_GREEN("Home") ++
            "           - Beginning of line\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+E") ++ " or " ++ ?FG_GREEN("End") ++
            "            - End of line\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+F") ++ " or " ++ ?FG_GREEN("Right Arrow") ++
            "    - Forward one character\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+B") ++ " or " ++ ?FG_GREEN("Left Arrow") ++
            "     - Back one character\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Editing:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+D") ++ " or " ++ ?FG_GREEN("Delete") ++
            "         - Delete character at cursor\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+H") ++ " or " ++ ?FG_GREEN("Backspace") ++
            "      - Delete previous character\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+K") ++
            "                   - Kill to end of line\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+U") ++ "                   - Kill entire line\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("History:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+P") ++ " or " ++ ?FG_GREEN("Up Arrow") ++
            "       - Previous command\r\n"
    ),
    io:format(
        ?FG_GREEN("  Ctrl+N") ++ " or " ++ ?FG_GREEN("Down Arrow") ++
            "     - Next command\r\n"
    ).

%% @doc Print invite-specific help
print_invite_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              INVITE COMMAND HELP                              "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Description:")) ++ "\r\n"),
    io:format(
        "  Invite commands allow you to create invitation tokens for\r\n"
    ),
    io:format(
        "  onboarding new users to the Cryptic server. Invites are\r\n"
    ),
    io:format(
        "  GPG-signed tokens that can be shared via email, QR code, etc.\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  invite") ++ " or " ++ ?FG_MAGENTA(":il") ++
            "              - List all your invitations\r\n"
    ),
    io:format(
        ?FG_GREEN("  invite create") ++ " " ++ ?FG_YELLOW("[options]") ++
            " - Create new invitation " ++ ?FG_MAGENTA("(:ic)") ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  invite show") ++ " " ++ ?FG_YELLOW("<invite_id>") ++
            " - Show invitation details\r\n"
    ),
    io:format(
        ?FG_GREEN("  invite revoke") ++ " " ++ ?FG_YELLOW("<invite_id>") ++
            " - Revoke invitation " ++ ?FG_MAGENTA("(:ir)") ++ "\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Create Options:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  --expires") ++ " " ++ ?FG_GREEN("<hours>") ++
            "          # Expiry time (default: 24h)\r\n"
    ),
    io:format(
        ?FG_YELLOW("  --note") ++ " " ++ ?FG_GREEN("<message>") ++
            "            # Note about the invite\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Usage Examples:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  invite create --expires 48h --note Welcome Bob") ++
            "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :ic") ++
            "                           # Quick create with defaults\r\n"
    ),
    io:format(
        ?FG_YELLOW("  invite list") ++
            "                    # List all invitations\r\n"
    ),
    io:format(
        ?FG_YELLOW("  invite show inv-8f3b12a4") ++
            "       # Show details\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :ir inv-8f3b12a4") ++
            "               # Revoke invitation\r\n"
    ).

%% @doc Print cert-specific help
print_cert_help() ->
    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              CERT COMMAND HELP                                "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Description:")) ++ "\r\n"),
    io:format(
        "  Certificate commands allow you to check and renew your TLS\r\n"
    ),
    io:format(
        "  client certificate used for mTLS authentication with the server.\r\n"
    ),
    io:format(
        "  Certificates are short-lived (7 days default) and can be renewed.\r\n\r\n"
    ),

    io:format(?BOLD(?FG_CYAN("Commands:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_GREEN("  cert") ++ " or " ++ ?FG_MAGENTA(":cs") ++
            "                - Show certificate status\r\n"
    ),
    io:format(
        ?FG_GREEN("  cert status") ++ " or " ++ ?FG_MAGENTA(":cs") ++
            "        - Show certificate status\r\n"
    ),
    io:format(
        ?FG_GREEN("  cert renew") ++ " " ++ ?FG_YELLOW("[options]") ++
            "   - Renew certificate " ++ ?FG_MAGENTA("(:cr)") ++ "\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Renew Options:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  --force") ++
            "                      # Renew even if not near expiry\r\n"
    ),
    io:format(
        ?FG_YELLOW("  --new-key") ++
            "                    # Generate new TLS key (re-key)\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Usage Examples:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        ?FG_YELLOW("  cert status") ++
            "                    # Check certificate expiry\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :cs") ++
            "                            # Quick status check\r\n"
    ),
    io:format(
        ?FG_YELLOW("  cert renew") ++
            "                     # Renew with existing key\r\n"
    ),
    io:format(
        ?FG_YELLOW("  cert renew --new-key") ++
            "           # Renew and generate new key\r\n"
    ),
    io:format(
        ?FG_YELLOW("  :cr") ++
            "                            # Quick renew\r\n"
    ),

    io:format("\r\n"),
    io:format(?BOLD(?FG_CYAN("Auto-Renewal:")) ++ "\r\n"),
    io:format(
        ?BOLD(
            "─────────────────────────────────────────────────────────────────"
        ) ++ "\r\n"
    ),
    io:format(
        "  Certificates are automatically renewed at 50%% lifetime\r\n"
    ),
    io:format(
        "  (typically 3.5 days for 7-day certificates). You can also\r\n"
    ),
    io:format(
        "  manually renew using the commands above.\r\n"
    ).

%% @doc Display console status information on alternate screen
-spec print_console_status(map()) -> ok.
print_console_status(Status) ->
    %% Switch to alternate screen buffer
    io:format(?ALT_SCREEN_ON),
    io:format(?CLEAR_SCREEN),
    io:format(?MVTO_ROW_COL(1, 1)),

    %% Display header with border
    io:format(
        ?BOLD(
            "╔═══════════════════════════════════════════════════════════════╗"
        ) ++ "\r\n"
    ),
    io:format(
        ?BOLD("║") ++
            ?FG_CYAN(
                "              CRYPTIC CONSOLE STATUS                          "
            ) ++ ?BOLD("║") ++ "\r\n"
    ),
    io:format(
        ?BOLD(
            "╚═══════════════════════════════════════════════════════════════╝"
        ) ++ "\r\n\r\n"
    ),

    %% Format username
    Username = maps:get(username, Status, "unknown"),
    io:format(?FG_GREEN("  Username:         ") ++ Username ++ "\r\n"),

    %% Format server connection
    ServerHost = maps:get(server_host, Status, "unknown"),
    ServerPort = maps:get(server_port, Status, 0),
    io:format(
        ?FG_GREEN("  Server:           ") ++ ServerHost ++ ":" ++
            integer_to_list(ServerPort) ++ "\r\n"
    ),

    %% Format connection status
    WsConnected = maps:get(ws_client_connected, Status, false),
    WsStatus =
        case WsConnected of
            true -> ?FG_GREEN("Connected");
            false -> ?FG_RED("Disconnected")
        end,
    io:format(?FG_GREEN("  WebSocket:        ") ++ WsStatus ++ "\r\n"),

    %% Format engine status
    EngineRunning = maps:get(engine_running, Status, false),
    EngineStatus =
        case EngineRunning of
            true -> ?FG_GREEN("Running");
            false -> ?FG_RED("Stopped")
        end,
    io:format(?FG_GREEN("  Engine:           ") ++ EngineStatus ++ "\r\n"),

    %% Format database status
    DbEnabled = maps:get(db_enabled, Status, false),
    DbStatus =
        case DbEnabled of
            true -> ?FG_GREEN("Enabled (saving messages)");
            false -> ?FG_YELLOW("Disabled (not saving)")
        end,
    io:format(?FG_GREEN("  Database:         ") ++ DbStatus ++ "\r\n"),

    %% Show instructions and wait for keypress
    io:format("\r\n\r\n"),
    io:format(?FG_YELLOW("Press any key to return...") ++ "\r\n"),

    %% Wait for a keypress
    io:get_chars("", 1),

    %% Return to main screen buffer
    io:format(?ALT_SCREEN_OFF).
