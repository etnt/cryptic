%%% @doc Cryptic Shell - Interactive shell with line editing for Cryptic Console
%%%
%%% This module provides an enhanced interactive shell with Emacs-like line editing
%%% capabilities for the Cryptic messaging application. It supports:
%%% - Character echoing and proper terminal handling
%%% - Emacs keybindings (Ctrl+A, Ctrl+E, Ctrl+F, Ctrl+B, etc.)
%%% - Arrow key navigation
%%% - Backspace and delete operations
%%% - Password input with masking
%%% - ANSI color and formatting support for enhanced visual experience
%%%
-module(cryptic_shell).

%% Include ANSI escape sequence macros for terminal formatting
-include("cryptic_ansi.hrl").

%% API
-export([
    start_shell/0,
    start_shell/1,
    get_line/1,
    get_password/1,
    cleanup/0,
    % Enhanced output functions with ANSI formatting
    print_success/1,
    print_error/1,
    print_warning/1,
    print_info/1,
    print_highlight/1
]).

%% Internal state record for line editing
-record(line_state, {
    % Current line content
    buffer = [] :: [char()],
    % Cursor position (0-based from start)
    cursor = 0 :: non_neg_integer(),
    % Current prompt string
    prompt :: string()
}).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Start the shell in raw mode
-spec start_shell() -> ok | {error, term()}.
start_shell() ->
    start_shell(#{}).

%% @doc Start the shell with options
-spec start_shell(map()) -> ok | {error, term()}.
start_shell(Options) ->
    Verbose = maps:get(verbose, Options, false),

    try
        % Try OTP 28 raw mode first
        case shell:start_interactive({noshell, raw}) of
            ok ->
                case Verbose of
                    true ->
                        io:format("~s\r\n", [
                            ?FG_GREEN(?BOLD("Cryptic Shell (OTP 28 raw mode)"))
                        ]);
                    false ->
                        ok
                end,
                ok;
            {error, _Reason} ->
                case Verbose of
                    true ->
                        io:format(
                            "~s\r\n", [
                                ?FG_YELLOW(
                                    ?BOLD(
                                        "OTP 28 mode failed, trying fallback..."
                                    )
                                )
                            ]
                        );
                    false ->
                        ok
                end,
                fallback_raw_mode()
        end
    catch
        error:undef ->
            case Verbose of
                true ->
                    io:format(
                        "~s\r\n", [
                            ?FG_YELLOW(
                                ?BOLD(
                                    "OTP 28 shell function not available, trying fallback..."
                                )
                            )
                        ]
                    );
                false ->
                    ok
            end,
            fallback_raw_mode();
        _:Error ->
            case Verbose of
                true ->
                    io:format("~s\r\n", [
                        ?FG_WHITE_BG_RED(
                            ?BOLD(
                                "Shell setup error: " ++
                                    lists:flatten(io_lib:format("~p", [Error]))
                            )
                        )
                    ]);
                false ->
                    ok
            end,
            {error, Error}
    end.

%% @doc Clean up shell state and restore terminal
-spec cleanup() -> ok.
cleanup() ->
    io:setopts(standard_io, [{raw, false}]).

%% @doc Get a line of input with line editing
-spec get_line(string()) -> string() | eof | {error, term()}.
get_line(Prompt) ->
    % Format prompt with bold styling for better visibility
    FormattedPrompt = ?BOLD(Prompt),
    io:format("~s", [FormattedPrompt]),
    LineState = #line_state{
        buffer = [],
        cursor = 0,
        prompt = FormattedPrompt
    },
    line_editor_loop(LineState).

%% @doc Get password input with character masking
-spec get_password(string()) -> string() | eof.
get_password(Prompt) ->
    % Format password prompt with yellow color and bold for security emphasis
    FormattedPrompt = ?FG_YELLOW_BG_BLACK(?BOLD(Prompt)),
    io:format("~s", [FormattedPrompt]),
    password_loop([]).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Fallback to older raw mode approach
fallback_raw_mode() ->
    case io:setopts(standard_io, [raw]) of
        ok -> ok;
        {error, Reason} -> {error, Reason}
    end.

%% @doc Main line editor loop
line_editor_loop(#line_state{buffer = Buffer} = State) ->
    case io:get_chars(standard_io, "", 1) of
        % Enter keys
        "\n" -> finish_line(Buffer);
        "\r" -> finish_line(Buffer);
        % Escape sequence start
        "\e" -> handle_escape_sequence(State);
        % Emacs control keys

        % Ctrl+A - beginning of line
        [1] -> handle_ctrl_a(State);
        % Ctrl+E - end of line
        [5] -> handle_ctrl_e(State);
        % Ctrl+F - forward char
        [6] -> handle_ctrl_f(State);
        % Ctrl+B - backward char
        [2] -> handle_ctrl_b(State);
        % Ctrl+D - delete char
        [4] -> handle_ctrl_d(State);
        % Ctrl+H - backspace
        [8] -> handle_ctrl_h(State);
        % Ctrl+K - kill to end
        [11] -> handle_ctrl_k(State);
        % Ctrl+U - kill entire line
        [21] -> handle_ctrl_u(State);
        % Regular delete key

        % DEL acts like backspace
        [127] -> handle_ctrl_h(State);
        % EOF
        eof -> eof;
        % Skip other control characters
        [C] when C < 32 -> line_editor_loop(State);
        % Regular printable character
        [Char] -> insert_char(State, Char)
    end.

%% @doc Handle escape sequences (arrow keys, etc.)
handle_escape_sequence(State) ->
    case io:get_chars(standard_io, "", 1) of
        "[" ->
            case io:get_chars(standard_io, "", 1) of
                % Up arrow - ignore for now
                "A" -> line_editor_loop(State);
                % Down arrow - ignore for now
                "B" -> line_editor_loop(State);
                % Right arrow
                "C" -> handle_ctrl_f(State);
                % Left arrow
                "D" -> handle_ctrl_b(State);
                _ -> line_editor_loop(State)
            end;
        _ ->
            line_editor_loop(State)
    end.

%% @doc Finish line editing and return result
finish_line(Buffer) ->
    io:format("\r\n"),
    lists:flatten(Buffer).

%% @doc Insert character at cursor position
insert_char(#line_state{buffer = Buffer, cursor = Cursor} = State, Char) ->
    {Left, Right} = lists:split(Cursor, Buffer),
    NewBuffer = Left ++ [Char] ++ Right,
    NewCursor = Cursor + 1,
    NewState = State#line_state{buffer = NewBuffer, cursor = NewCursor},

    case Right of
        [] ->
            % Inserting at end - just echo
            io:format("~c", [Char]);
        _ ->
            % Inserting in middle - redraw
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
handle_ctrl_d(#line_state{buffer = Buffer, cursor = Cursor} = State) ->
    case Cursor < length(Buffer) of
        true ->
            {Left, [_ | Right]} = lists:split(Cursor, Buffer),
            NewBuffer = Left ++ Right,
            NewState = State#line_state{buffer = NewBuffer},
            redraw_from_cursor(NewState),
            line_editor_loop(NewState);
        false ->
            line_editor_loop(State)
    end.

%% @doc Backspace (Ctrl+H)
handle_ctrl_h(#line_state{cursor = 0} = State) ->
    line_editor_loop(State);
handle_ctrl_h(#line_state{buffer = Buffer, cursor = Cursor} = State) ->
    {Left, Right} = lists:split(Cursor, Buffer),
    NewBuffer = lists:droplast(Left) ++ Right,
    NewCursor = Cursor - 1,

    io:format("\b"),
    NewState = State#line_state{buffer = NewBuffer, cursor = NewCursor},
    redraw_from_cursor(NewState),
    line_editor_loop(NewState).

%% @doc Kill from cursor to end (Ctrl+K)
handle_ctrl_k(#line_state{buffer = Buffer, cursor = Cursor} = State) ->
    {Left, _Right} = lists:split(Cursor, Buffer),
    NewState = State#line_state{buffer = Left},
    io:format("\e[K"),
    line_editor_loop(NewState).

%% @doc Kill entire line (Ctrl+U)
handle_ctrl_u(#line_state{prompt = Prompt} = State) ->
    io:format("\r~s", [Prompt]),
    NewState = State#line_state{buffer = [], cursor = 0},
    line_editor_loop(NewState).

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

%% @doc Print success message with green formatting
-spec print_success(string()) -> ok.
print_success(Message) ->
    io:format("~s~n", [?FG_GREEN(?BOLD("[OK] " ++ Message))]).

%% @doc Print error message with red formatting
-spec print_error(string()) -> ok.
print_error(Message) ->
    io:format("~s~n", [?FG_WHITE_BG_RED(?BOLD("[ERROR] " ++ Message))]).

%% @doc Print warning message with yellow formatting
-spec print_warning(string()) -> ok.
print_warning(Message) ->
    io:format("~s~n", [?FG_BLACK_BG_YELLOW(?BOLD("[WARN] " ++ Message))]).

%% @doc Print info message with cyan formatting
-spec print_info(string()) -> ok.
print_info(Message) ->
    io:format("~s~n", [?FG_CYAN(?BOLD("[INFO] " ++ Message))]).

%% @doc Print highlighted message with blue formatting
-spec print_highlight(string()) -> ok.
print_highlight(Message) ->
    io:format("~s~n", [?FG_WHITE_BG_BLUE(?BOLD("[***] " ++ Message))]).
