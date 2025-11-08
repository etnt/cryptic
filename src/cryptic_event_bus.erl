%%--------------------------------------------------------------------
%% @doc Cryptic Event Bus - Publish/Subscribe System
%%
%% A lightweight, OTP-native event bus for multicasting chat events to
%% multiple subscribers. Supports filtering and automatic cleanup of
%% dead subscribers.
%%
%% == Features ==
%% <ul>
%%   <li>Subscribe with optional filter function</li>
%%   <li>Asynchronous event publishing (non-blocking)</li>
%%   <li>Automatic subscriber cleanup on process exit</li>
%%   <li>Topic-based subscriptions for rooms/channels</li>
%%   <li>Safe error handling (filter crashes don't affect other subscribers)</li>
%% </ul>
%%
%% == Usage ==
%% ```
%% %% Start the event bus
%% {ok, _Pid} = cryptic_event_bus:start_link().
%%
%% %% Subscribe to all events
%% cryptic_event_bus:subscribe(self()).
%%
%% %% Subscribe with a filter (only chat messages)
%% Filter = fun(#{type := Type}) -> Type =:= chat_message; (_) -> false end,
%% cryptic_event_bus:subscribe(self(), Filter).
%%
%% %% Subscribe to a specific room
%% cryptic_event_bus:subscribe_topic(self(), <<"room_123">>).
%%
%% %% Publish an event
%% Event = #{type => chat_message, room => <<"room_123">>, text => <<"Hello">>},
%% cryptic_event_bus:publish(Event).
%%
%% %% Unsubscribe
%% cryptic_event_bus:unsubscribe(self()).
%% '''
%%
%% @author Cryptic Development Team
%% @since November 2025
%%--------------------------------------------------------------------
-module(cryptic_event_bus).
-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, stop/0, publish/1,
         subscribe/1, subscribe/2, subscribe_topic/2, unsubscribe/1, list_subscribers/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("cryptic.hrl").

-record(state, {
    subs = #{}   %% Map: Pid => #{filter => FilterFun, mon => MonitorRef}
}).

-type event() :: any().
-type filter_fun() :: fun((event()) -> boolean()).
-type topic() :: binary() | atom().

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Start the event bus with default options.
%%
%% Registers the process locally as `cryptic_event_bus'.
%%
%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
-spec start_link() -> {ok, pid()} | {error, any()}.
start_link() ->
    start_link([]).

%% @doc Start the event bus with custom options.
%%
%% Currently, options are reserved for future use.
%%
%% @param Opts Options list (currently unused)
%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
-spec start_link(list()) -> {ok, pid()} | {error, any()}.
start_link(_Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Stop the event bus.
%%
%% Terminates the event bus process gracefully.
%%
%% @returns `ok'
-spec stop() -> ok.
stop() ->
    gen_server:call(?MODULE, stop).

%% @doc Publish an event to all subscribers.
%%
%% Events are delivered asynchronously via `gen_server:cast', so this
%% function returns immediately without blocking. Each subscriber's 
%% filter function (if any) is evaluated to determine if they should
%% receive the event.
%%
%% If a subscriber's filter function crashes, the error is logged and
%% that subscriber is skipped (other subscribers still receive the event).
%%
%% == Example ==
%% ```
%% Event = #{type => chat_message, from => <<"alice">>, text => <<"Hi!">>},
%% cryptic_event_bus:publish(Event).
%% '''
%%
%% @param Event Any Erlang term representing the event to publish
%% @returns `ok'
-spec publish(event()) -> ok.
publish(Event) ->
    gen_server:cast(?MODULE, {publish, Event}).

%% @doc Subscribe a process to all events.
%%
%% The subscribing process will receive all published events as messages
%% in the form `{event, Event}'. The process is automatically monitored
%% and will be unsubscribed if it exits.
%%
%% This is equivalent to `subscribe(Pid, fun(_) -> true end)'.
%%
%% @param Pid The process to subscribe
%% @returns `ok'
%% @see subscribe/2
-spec subscribe(pid()) -> ok.
subscribe(Pid) when is_pid(Pid) ->
    subscribe(Pid, fun(_) -> true end).

%% @doc Subscribe a process with a filter function.
%%
%% Only events for which `FilterFun(Event)' returns `true' will be
%% delivered to the subscriber. If the filter function crashes, the
%% error is logged and that event is skipped for that subscriber.
%%
%% == Example ==
%% ```
%% %% Only receive chat messages
%% Filter = fun(#{type := chat_message}) -> true; (_) -> false end,
%% cryptic_event_bus:subscribe(self(), Filter).
%%
%% %% Only receive messages from a specific user
%% Filter = fun(#{from := <<"alice">>}) -> true; (_) -> false end,
%% cryptic_event_bus:subscribe(self(), Filter).
%% '''
%%
%% @param Pid The process to subscribe
%% @param FilterFun Predicate function: (Event) -> boolean()
%% @returns `ok'
-spec subscribe(pid(), filter_fun()) -> ok.
subscribe(Pid, FilterFun) when is_pid(Pid), is_function(FilterFun, 1) ->
    gen_server:call(?MODULE, {subscribe, Pid, FilterFun}).

%% @doc Subscribe a process to a specific topic/room.
%%
%% Convenience function for subscribing to room-specific events.
%% Creates a filter that matches events in the format:
%% `{room_msg, Topic, From, Body, Timestamp}'.
%%
%% == Example ==
%% ```
%% %% Subscribe to room "general"
%% cryptic_event_bus:subscribe_topic(self(), <<"general">>).
%%
%% %% Events matching {room_msg, <<"general">>, _, _, _} will be received
%% '''
%%
%% @param Pid The process to subscribe
%% @param Topic The room/topic identifier
%% @returns `ok'
-spec subscribe_topic(pid(), topic()) -> ok.
subscribe_topic(Pid, Topic) when is_pid(Pid) ->
    FilterFun = fun(Event) ->
                    case Event of
                        {room_msg, Topic, _From, _Body, _Ts} -> true;
                        _ -> false
                    end
                end,
    subscribe(Pid, FilterFun).

%% @doc Unsubscribe a process from the event bus.
%%
%% Removes the process from the subscriber list and stops monitoring it.
%% If the process is not subscribed, this is a no-op.
%%
%% @param Pid The process to unsubscribe
%% @returns `ok'
-spec unsubscribe(pid()) -> ok.
unsubscribe(Pid) when is_pid(Pid) ->
    gen_server:call(?MODULE, {unsubscribe, Pid}).

%% @doc List all current subscribers.
%%
%% Returns a list of tuples containing each subscriber's PID and a boolean
%% indicating whether they have a custom filter function (true) or accept
%% all events (false).
%%
%% Useful for debugging and monitoring.
%%
%% @returns List of `{Pid, HasCustomFilter}' tuples
-spec list_subscribers() -> [{pid(), boolean()}].
list_subscribers() ->
    gen_server:call(?MODULE, list_subs).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    process_flag(trap_exit, true),
    {ok, #state{}}.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call({subscribe, Pid, FilterFun}, _From, State=#state{subs = Subs}) ->
    case maps:is_key(Pid, Subs) of
        true ->
            {reply, ok, State};
        false ->
            Mon = erlang:monitor(process, Pid),
            NewEntry = #{filter => FilterFun, mon => Mon},
            NewSubs = maps:put(Pid, NewEntry, Subs),
            {reply, ok, State#state{subs = NewSubs}}
    end;

handle_call({unsubscribe, Pid}, _From, State=#state{subs = Subs}) ->
    case maps:take(Pid, Subs) of
        {Entry, NewSubs} ->
            #{mon := Mon} = Entry,
            erlang:demonitor(Mon, [flush]),
            {reply, ok, State#state{subs = NewSubs}};
        error ->
            {reply, ok, State}
    end;

%% If the subscriber map must be read by caller (debugging)
handle_call(list_subs, _From, State=#state{subs = Subs}) ->
    Pids = maps:keys(Subs),
    %% return list of {Pid, has_filter} for convenience
    Result = [ {Pid, maps:get(filter, maps:get(Pid, Subs)) /= fun(_) -> true end} || Pid <- Pids ],
    {reply, Result, State};

handle_call(_Other, _From, State) ->
    {reply, {error, bad_call}, State}.

handle_cast({publish, Event}, State=#state{subs = Subs}) ->
    %% Deliver asynchronously by sending messages to subscribers.
    %% Use try/catch around FilterFun to avoid crashing the bus.
    maps:fold(
      fun(Pid, Entry, Acc) ->
          FilterFun = maps:get(filter, Entry),
          %% Evaluate filter safely
          Deliver = case safe_eval_filter(FilterFun, Event) of
                        true -> true;
                        false -> false;
                        {error, _} -> false
                    end,
          case Deliver of
              true ->
                  catch Pid ! {event, Event},
                  Acc;
              false ->
                  Acc
          end
      end,
      ok,
      Subs),
    {noreply, State};

handle_cast(_Other, State) ->
    {noreply, State}.

%% handle_info catches DOWN messages for monitored subscribers and other signals
handle_info({'DOWN', MonRef, process, Pid, _Reason}, State=#state{subs = Subs}) ->
    case maps:find(Pid, Subs) of
        {ok, Entry} ->
            case maps:get(mon, Entry) =:= MonRef of
                true ->
                    NewSubs = maps:remove(Pid, Subs),
                    ?info("cryptic_event_bus: removing dead subscriber ~p", [Pid]),
                    {noreply, State#state{subs = NewSubs}};
                false ->
                    {noreply, State}
            end;
        error ->
            {noreply, State}
    end;

handle_info(Info, State) ->
    ?dbg("cryptic_event_bus: unhandled info ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

-spec safe_eval_filter(fun((any()) -> boolean()), any()) -> boolean() | {error, any()}.
safe_eval_filter(FilterFun, Event) ->
    try
        FilterFun(Event)
    catch
        Class:Reason ->
            ?warning("cryptic_event_bus: filter function crashed: ~p:~p", [Class, Reason]),
            {error, {Class, Reason}}
    end.
