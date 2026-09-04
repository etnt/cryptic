%% @doc Cryptic Web Admin - server log reading helpers.
%%
%% Shared, transport-agnostic helpers for reading the server log file, used by
%% both the live log WebSocket ({@link cryptic_webadmin_log_ws}) and the paged
%% history endpoint in {@link cryptic_webadmin_api_handler}.
%%
%% The log file is a UTF-8 text file written by {@link cryptic_file_logger}
%% (one entry per line, format `YYYY-MM-DD HH:MM:SS CRYPTIC <LEVEL>: msg').
%% All functions read on demand; there is no cached file handle so that log
%% rotation/truncation is handled naturally on the next read.
%%
%% Lines are numbered with 1-based absolute indices counted from the start of
%% the file, so the WebSocket backfill and the history endpoint agree on line
%% identity and the UI can prepend older pages without duplication.
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_webadmin_log).

-export([log_file_path/0,
         read_last_lines/1,
         read_delta/2,
         read_page/3]).

-define(DEFAULT_LOG_FILE, "logs/server.log").

%%====================================================================
%% Path resolution
%%====================================================================

%% @doc Resolve the active server log file path.
%%
%% Prefers the path reported by the running file-logger `gen_event' handler;
%% falls back to the conventional `logs/server.log' when the event manager is
%% not running (e.g. during tests).
-spec log_file_path() -> string().
log_file_path() ->
    case whereis(cryptic_event_manager) of
        undefined ->
            ?DEFAULT_LOG_FILE;
        _ ->
            try gen_event:call(cryptic_event_manager, cryptic_file_logger,
                               get_log_file)
            of
                Path when is_list(Path) -> Path;
                Path when is_binary(Path) -> binary_to_list(Path);
                _ -> ?DEFAULT_LOG_FILE
            catch
                _:_ -> ?DEFAULT_LOG_FILE
            end
    end.

%%====================================================================
%% Reads
%%====================================================================

%% @doc Read the last `N' complete lines of the log.
%%
%% Returns the lines (each as `#{n => AbsIndex, text => Line}', oldest first),
%% the total number of complete lines in the file, and the byte offset up to
%% the last newline (the resume point for {@link read_delta/2}). A trailing
%% partial line (a log entry mid-write) is excluded from both the lines and the
%% offset so it is emitted only once it is completed.
-spec read_last_lines(pos_integer()) ->
    {ok, [map()], Total :: non_neg_integer(), Offset :: non_neg_integer()} |
    {error, term()}.
read_last_lines(N) when is_integer(N), N > 0 ->
    case file:read_file(log_file_path()) of
        {ok, Bin} ->
            CLen = complete_len(Bin),
            Complete = binary:part(Bin, 0, CLen),
            Lines = split_lines(Complete),
            Total = length(Lines),
            Start = max(0, Total - N),
            Tail = lists:nthtail(Start, Lines),
            {ok, number_lines(Tail, Start + 1), Total, CLen};
        {error, enoent} ->
            {ok, [], 0, 0};
        {error, _} = Err ->
            Err
    end.

%% @doc Read complete lines appended since byte `Offset'.
%%
%% `NextN' is the absolute line number to assign to the first new line.
%% Returns the new lines (oldest first), the byte offset advanced to the last
%% newline, and the next line number to use on the following poll. Detects
%% truncation/rotation (file shorter than `Offset') and restarts from 0.
-spec read_delta(Offset :: non_neg_integer(), NextN :: pos_integer()) ->
    {ok, [map()], NewOffset :: non_neg_integer(), NewNextN :: pos_integer()} |
    {error, term()}.
read_delta(Offset, NextN) when is_integer(Offset), Offset >= 0 ->
    File = log_file_path(),
    Size = filelib:file_size(File),
    if
        Size < Offset ->
            %% File truncated or rotated: re-read from the beginning.
            read_delta(0, 1);
        Size =:= Offset ->
            {ok, [], Offset, NextN};
        true ->
            read_delta_range(File, Offset, Size - Offset, NextN)
    end.

read_delta_range(File, Offset, Len, NextN) ->
    case file:open(File, [read, binary, raw]) of
        {ok, Fd} ->
            Res = file:pread(Fd, Offset, Len),
            ok = file:close(Fd),
            case Res of
                {ok, Chunk} ->
                    CLen = complete_len(Chunk),
                    Complete = binary:part(Chunk, 0, CLen),
                    Lines = split_lines(Complete),
                    {ok, number_lines(Lines, NextN),
                     Offset + CLen, NextN + length(Lines)};
                eof ->
                    {ok, [], Offset, NextN};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Read a page of history ending just before absolute line `Before'.
%%
%% `Before' of 0 (or >= total) means "from the end". Returns up to `Limit'
%% lines ending at `Before - 1', optionally filtered to entries whose level
%% matches `Level' (`undefined' for no filter). The window is selected first,
%% then filtered, so callers page with the returned `start' index.
-spec read_page(Before :: non_neg_integer(), Limit :: pos_integer(),
                Level :: binary() | undefined) ->
    {ok, map()} | {error, term()}.
read_page(Before, Limit, Level)
        when is_integer(Before), Before >= 0, is_integer(Limit), Limit > 0 ->
    case file:read_file(log_file_path()) of
        {ok, Bin} ->
            CLen = complete_len(Bin),
            Complete = binary:part(Bin, 0, CLen),
            Lines = split_lines(Complete),
            Total = length(Lines),
            EndIdx = case Before of
                         0 -> Total;
                         B when B - 1 < Total -> B - 1;
                         _ -> Total
                     end,
            StartIdx = max(1, EndIdx - Limit + 1),
            Window = case EndIdx >= StartIdx of
                         true -> lists:sublist(Lines, StartIdx, EndIdx - StartIdx + 1);
                         false -> []
                     end,
            Numbered = number_lines(Window, StartIdx),
            Filtered = filter_level(Numbered, Level),
            {ok, #{lines => Filtered,
                   total => Total,
                   start => StartIdx,
                   'end' => EndIdx,
                   has_more => StartIdx > 1}};
        {error, enoent} ->
            {ok, #{lines => [], total => 0, start => 0, 'end' => 0,
                   has_more => false}};
        {error, _} = Err ->
            Err
    end.

%%====================================================================
%% Internal helpers
%%====================================================================

%% Byte length of the prefix of `Bin' up to and including the last newline.
%% Everything after is a partial (in-progress) line.
-spec complete_len(binary()) -> non_neg_integer().
complete_len(Bin) ->
    case binary:matches(Bin, <<"\n">>) of
        [] -> 0;
        Matches ->
            {Pos, _Len} = lists:last(Matches),
            Pos + 1
    end.

%% Split a "complete" binary (ending on a newline, or empty) into line
%% binaries, dropping the trailing empty element left by the final newline.
-spec split_lines(binary()) -> [binary()].
split_lines(<<>>) ->
    [];
split_lines(Bin) ->
    Parts = binary:split(Bin, <<"\n">>, [global]),
    case lists:reverse(Parts) of
        [<<>> | Rest] -> lists:reverse(Rest);
        _ -> Parts
    end.

%% Attach 1-based absolute line numbers starting at `StartN'.
-spec number_lines([binary()], pos_integer()) -> [map()].
number_lines(Lines, StartN) ->
    {Acc, _} = lists:foldl(
        fun(Line, {Out, N}) ->
            {[#{n => N, text => Line} | Out], N + 1}
        end,
        {[], StartN},
        Lines),
    lists:reverse(Acc).

%% Keep only entries whose log level matches `Level' (case-insensitive), e.g.
%% `<<"error">>' matches lines containing `CRYPTIC <ERROR>:'.
-spec filter_level([map()], binary() | undefined) -> [map()].
filter_level(Lines, undefined) ->
    Lines;
filter_level(Lines, <<>>) ->
    Lines;
filter_level(Lines, Level) ->
    Needle = <<"<", (string:uppercase(Level))/binary, ">">>,
    [L || #{text := T} = L <- Lines,
          binary:match(string:uppercase(T), Needle) =/= nomatch].
