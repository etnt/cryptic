%%%-------------------------------------------------------------------
%%% @doc
%%% A console logger for Cryptic.
%%% This module logs Cryptic-specific events to the console for debugging
%%% and monitoring purposes.
%%%
%%% @author Torbjörn Törnkvist <kruskakli@gmail.com>
%%% @copyright 2025 Torbjörn Törnkvist
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_console_logger).
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
    debug = false
}).

%%--------------------------------------------------------------------
%% @doc
%% Initializes the event handler.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: any()) -> {ok, #state{}}.
init(_Args) ->
    case maybe_env_debug(application:get_env(cryptic, enable_debug, false)) of
        {ok, Debug} when is_boolean(Debug) ->
            {ok, #state{debug = Debug}};
        _ ->
            % Default to false if not set
            {ok, #state{debug = false}}
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


%% CRYPTIC specific events
%%--------------------------------------------------------------------
%% @doc
%% Handles Cryptic-specific events and logs them to the console.
%% @end
%%--------------------------------------------------------------------
-spec handle_event(Event :: any(), State :: #state{}) -> {ok, #state{}}.
handle_event({info, {FmtStr, Args}}, State) when
    is_list(FmtStr) andalso is_list(Args)
->
    io:format("CRYPTIC <INFO>: " ++ FmtStr, Args),
    {ok, State};
handle_event({warning, {FmtStr, Args}}, State) when
    is_list(FmtStr) andalso is_list(Args)
->
    io:format("CRYPTIC <WARNING>: " ++ FmtStr, Args),
    {ok, State};
handle_event({error, {FmtStr, Args}}, State) when
    is_list(FmtStr) andalso is_list(Args)
->
    io:format("CRYPTIC <ERROR>: " ++ FmtStr, Args),
    {ok, State};
handle_event({debug, {FmtStr, Args}}, #state{debug = true} = State) when
    is_list(FmtStr) andalso is_list(Args)
->
    io:format("CRYPTIC <DEBUG>: " ++ FmtStr, Args),
    {ok, State};
%%
handle_event({debug, {_FmtStr, _Args}}, #state{debug = false} = State) ->
    {ok, State};
handle_event(Event, State) ->
    io:format("Unknown Cryptic event: ~p~n", [Event]),
    {ok, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles synchronous event handler calls.
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: any(), State :: #state{}) ->
    {ok, Reply :: ok, #state{}}.
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
terminate(_Reason, _State) ->
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
