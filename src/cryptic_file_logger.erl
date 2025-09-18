%%%-------------------------------------------------------------------
%%% @doc
%%% A file logger for Cryptic.
%%% This module logs Cryptic-specific events to a file for debugging
%%% and monitoring purposes, preventing console output from interfering
%%% with terminal UIs.
%%%
%%% @author GitHub Copilot
%%% @copyright 2025 Torbjörn Törnkvist
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_file_logger).
-behaviour(gen_event).

%% gen_event callbacks
-export([
    init/1,
    handle_event/2,
    handle_call/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    % Debug mode, can be set to true for verbose logging
    debug = false,
    % File handle for logging
    file_handle,
    % Log file path
    log_file_path
}).

%%--------------------------------------------------------------------
%% @doc
%% Initializes the event handler with file logging.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: any()) -> {ok, #state{}} | {error, any()}.
init(Args) ->
    LogDir = case Args of
        #{log_dir := Dir} -> Dir;
        _ -> "logs"
    end,
    
    LogType = case Args of
        #{log_type := Type} when Type =:= server; Type =:= client -> Type;
        _ -> server  % Default to server
    end,

    Username = case Args of
        #{username := U} -> U;
        _ -> ""
    end,
    
    % Ensure log directory exists
    case filelib:ensure_dir(filename:join([LogDir, "dummy"])) of
        ok ->
            LogFileName = case LogType of
                server -> "server.log";
                client -> "client-"++Username++".log"
            end,
            LogFile = filename:join([LogDir, LogFileName]),
            case file:open(LogFile, [write, append, {encoding, utf8}]) of
                {ok, Handle} ->
                    Debug = case maybe_env_debug(application:get_env(cryptic, enable_debug, false)) of
                        {ok, DebugFlag} -> DebugFlag;
                        _ -> false
                    end,
                    
                    % Write startup message
                    Timestamp = format_timestamp(),
                    file:write(Handle, io_lib:format("~s CRYPTIC <INFO>: ~s logger started, log file: ~s~n", 
                                                   [Timestamp, string:to_upper(atom_to_list(LogType)), LogFile])),
                    
                    {ok, #state{
                        debug = Debug,
                        file_handle = Handle,
                        log_file_path = LogFile
                    }};
                {error, Reason} ->
                    error_logger:error_msg("Failed to open log file ~s: ~p~n", [LogFile, Reason]),
                    {error, {log_file_open_failed, Reason}}
            end;
        {error, Reason} ->
            error_logger:error_msg("Failed to create log directory ~s: ~p~n", [LogDir, Reason]),
            {error, {log_dir_create_failed, Reason}}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Determines debug mode based on environment variables and application settings.
%% Environment variables override application settings.
%% @private 
%% @end
%%--------------------------------------------------------------------
-spec maybe_env_debug(Default :: any()) -> {ok, boolean()}.
maybe_env_debug(Default) when Default == true orelse Default == false ->
    case os:getenv("CRYPTIC_DEBUG") of
        "true"  -> {ok, true};
        "false" -> {ok, false};
        _       -> {ok, Default}
    end;
maybe_env_debug(_) ->
    {ok, false}.

%%--------------------------------------------------------------------
%% @doc
%% Formats current timestamp for log entries.
%% @private
%% @end
%%--------------------------------------------------------------------
-spec format_timestamp() -> string().
format_timestamp() ->
    {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:local_time(),
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w", 
                  [Year, Month, Day, Hour, Min, Sec]).

%%--------------------------------------------------------------------
%% @doc
%% Writes a formatted log entry to the file.
%% @private
%% @end
%%--------------------------------------------------------------------
-spec write_log_entry(file:io_device(), string(), string(), list()) -> ok.
write_log_entry(Handle, Level, FmtStr, Args) ->
    Timestamp = format_timestamp(),
    try
        Message = io_lib:format(FmtStr, Args),
        LogEntry = io_lib:format("~s CRYPTIC <~s>: ~s~n", [Timestamp, Level, Message]),
        file:write(Handle, LogEntry)
    catch
        Error:Reason ->
            % Fallback logging in case of format errors
            ErrorMsg = io_lib:format("~s CRYPTIC <ERROR>: Log format error ~p:~p for format ~p with args ~p~n", 
                                   [Timestamp, Error, Reason, FmtStr, Args]),
            file:write(Handle, ErrorMsg)
    end.

%% CRYPTIC specific events
%%--------------------------------------------------------------------
%% @doc
%% Handles Cryptic-specific events and logs them to file.
%% @end
%%--------------------------------------------------------------------
-spec handle_event(Event :: any(), State :: #state{}) -> {ok, #state{}}.
handle_event({info, {FmtStr, Args}}, #state{file_handle = Handle} = State) when
    is_list(FmtStr) andalso is_list(Args)
->
    write_log_entry(Handle, "INFO", FmtStr, Args),
    {ok, State};

handle_event({warning, {FmtStr, Args}}, #state{file_handle = Handle} = State) when
    is_list(FmtStr) andalso is_list(Args)
->
    write_log_entry(Handle, "WARNING", FmtStr, Args),
    {ok, State};

handle_event({error, {FmtStr, Args}}, #state{file_handle = Handle} = State) when
    is_list(FmtStr) andalso is_list(Args)
->
    write_log_entry(Handle, "ERROR", FmtStr, Args),
    {ok, State};

handle_event({debug, {FmtStr, Args}}, #state{debug = true, file_handle = Handle} = State) when
    is_list(FmtStr) andalso is_list(Args)
->
    write_log_entry(Handle, "DEBUG", FmtStr, Args),
    {ok, State};

handle_event({debug, {_FmtStr, _Args}}, #state{debug = false} = State) ->
    {ok, State};

% Handle standard io:format style logs (capture console output)
handle_event({log, {Level, FmtStr, Args}}, #state{file_handle = Handle} = State) when
    is_atom(Level) andalso is_list(FmtStr) andalso is_list(Args)
->
    write_log_entry(Handle, string:to_upper(atom_to_list(Level)), FmtStr, Args),
    {ok, State};

% Handle generic string messages
handle_event({log_message, Message}, #state{file_handle = Handle} = State) when is_list(Message) ->
    Timestamp = format_timestamp(),
    LogEntry = io_lib:format("~s CRYPTIC <LOG>: ~s~n", [Timestamp, Message]),
    file:write(Handle, LogEntry),
    {ok, State};

handle_event(Event, #state{file_handle = Handle} = State) ->
    Timestamp = format_timestamp(),
    LogEntry = io_lib:format("~s CRYPTIC <UNKNOWN>: ~p~n", [Timestamp, Event]),
    file:write(Handle, LogEntry),
    {ok, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles synchronous event handler calls.
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: any(), State :: #state{}) ->
    {ok, Reply :: ok, #state{}}.
handle_call(get_log_file, State) ->
    {ok, State#state.log_file_path, State};
handle_call(flush, #state{file_handle = Handle} = State) ->
    file:sync(Handle),
    {ok, ok, State};
handle_call(_Request, State) ->
    {ok, ok, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles messages sent directly to the event handler.
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: any(), State :: #state{}) -> {noreply, #state{}}.
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @doc
%% Cleans up when the event handler is removed.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: any(), State :: #state{}) -> ok.
terminate(_Reason, #state{file_handle = Handle, log_file_path = LogFile}) ->
    case Handle of
        undefined -> ok;
        _ ->
            Timestamp = format_timestamp(),
            file:write(Handle, io_lib:format("~s CRYPTIC <INFO>: File logger stopping~n", [Timestamp])),
            file:close(Handle)
    end,
    case LogFile of
        undefined -> ok;
        _ -> io:format("Cryptic logs written to: ~s~n", [LogFile])
    end,
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Handles code changes when updating the module.
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: any(), State :: #state{}, Extra :: any()) ->
    {ok, #state{}}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
