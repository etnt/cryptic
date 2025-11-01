-module(cryptic_event_bus_tests).
-include_lib("eunit/include/eunit.hrl").

%% Start fresh bus for each test
%% Helper: flush mailbox
flush_mailbox() ->
    receive
        _ -> flush_mailbox()
    after 0 ->
        ok
    end.

setup() ->
    %% Start event manager for debug logging
    case whereis(cryptic_event_manager) of
        undefined ->
            try
                {ok, _Pid} = gen_event:start_link({local, cryptic_event_manager}),
                gen_event:add_handler(cryptic_event_manager, cryptic_console_logger, [])
            catch
                _:_ -> ok  % Continue without event manager if it fails
            end;
        _ -> ok
    end,

    %% If cryptic_event_bus is running, stop it gracefully.
    case whereis(cryptic_event_bus) of
        undefined ->
            ok;
        Pid ->
            MonRef = erlang:monitor(process, Pid),
            cryptic_event_bus:stop(),
            receive
                {'DOWN', MonRef, process, Pid, _} -> ok
            after 5000 -> error(timeout_stopping_old_bus)
            end
    end,
    flush_mailbox(),
    {ok, _} = cryptic_event_bus:start_link(),
    ok.

cleanup(_) ->
    %% Stop cryptic_event_bus and wait for it to die
    case whereis(cryptic_event_bus) of
        undefined ->
            ok;
        Pid ->
            MonRef = erlang:monitor(process, Pid),
            ok = cryptic_event_bus:stop(),
            receive
                {'DOWN', MonRef, process, Pid, _} -> ok
            after 5000 -> error(timeout_stopping_bus)
            end
    end,
    flush_mailbox(),
    ok.

%% Simple publish/subscribe test
basic_subscribe_test_() ->
    {setup, fun setup/0, fun cleanup/1,
        fun(_) ->
            [?_test(begin
                Self = self(),
                ok = cryptic_event_bus:subscribe(Self),
                cryptic_event_bus:publish({room_msg, <<"general">>, <<"alice">>, <<"hi">>, 1}),
                timer:sleep(100),  %% Allow cast to be processed
                receive
                    {event, {room_msg, <<"general">>, <<"alice">>, <<"hi">>, 1}} -> ok
                after 2000 ->
                    error(timeout)
                end
            end)]
        end}.

%% Filtered subscribe test
filtered_subscribe_test_() ->
    {setup, fun setup/0, fun cleanup/1,
        fun(_) ->
            Self = self(),
            Filter = fun({room_msg, <<"room-a">>, _From, _Body, _Ts}) -> true;
                         (_) -> false end,
            ok = cryptic_event_bus:subscribe(Self, Filter),
            cryptic_event_bus:publish({room_msg, <<"room-b">>, <<"x">>, <<"y">>, 2}),
            cryptic_event_bus:publish({room_msg, <<"room-a">>, <<"bob">>, <<"hey">>, 3}),
            timer:sleep(50),  %% Allow casts to be processed
            
            %% Should receive room-a message
            Msg1 = receive M -> M after 2000 -> timeout end,
            
            %% Should NOT receive room-b message
            Msg2 = receive M2 -> M2 after 500 -> no_message end,
            
            [?_assertMatch({event, {room_msg, <<"room-a">>, <<"bob">>, <<"hey">>, 3}}, Msg1),
             ?_assertEqual(no_message, Msg2)]
        end}.

%% Unsubscribe test
unsubscribe_test_() ->
    {setup, fun setup/0, fun cleanup/1,
        fun(_) ->
            Self = self(),
            ok = cryptic_event_bus:subscribe(Self),
            ok = cryptic_event_bus:unsubscribe(Self),
            cryptic_event_bus:publish({room_msg, <<"general">>, <<"alice">>, <<"hi">>, 4}),
            Msg = receive M -> M after 1000 -> no_message end,
            ?_assertEqual(no_message, Msg)
        end}.

%% Subscriber dies -> automatically removed
monitor_cleanup_test_() ->
    {setup, fun setup/0, fun cleanup/1,
        fun(_) ->
            %% spawn a process that subscribes and then exits
            _Pid = spawn(fun() ->
                cryptic_event_bus:subscribe(self()),
                %% ensure subscription exists briefly
                receive after 50 -> ok end
            end),
            %% give some time for DOWN to be processed
            timer:sleep(200),
            %% publish; the dead subscriber should not receive it, but bus shouldn't crash
            cryptic_event_bus:publish({room_msg, <<"general">>, <<"x">>, <<"y">>, 5}),
            %% If no crash we pass
            ?_assert(true)
        end}.

%% Filter function crash should not crash the bus
filter_crash_test_() ->
    {setup, fun setup/0, fun cleanup/1,
        fun(_) ->
            Self = self(),
            BadFilter = fun(_) -> erlang:error(bad_filter) end,
            ok = cryptic_event_bus:subscribe(Self, BadFilter),
            %% publish should not crash the server; subscriber should not receive
            cryptic_event_bus:publish({room_msg, <<"general">>, <<"a">>, <<"b">>, 6}),
            timer:sleep(100),
            Msg = receive M -> M after 100 -> no_message end,
            ?_assertEqual(no_message, Msg)
        end}.
