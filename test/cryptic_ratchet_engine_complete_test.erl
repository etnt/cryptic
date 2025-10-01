%%% @doc Comprehensive test for the complete ratchet engine implementation
%%%
%%% Tests all state transitions and callback notifications

-module(cryptic_ratchet_engine_complete_test).
-include_lib("eunit/include/eunit.hrl").
-include("cryptic.hrl").

-behaviour(cryptic_ratchet_engine).

%% Test callback implementation
-export([
    handle_state_change/4,
    handle_message_event/4,
    handle_error/4,
    handle_debug_event/4,
    handle_lifecycle_event/3
]).

%% Test state (commented out as we use functional approach)
%% -record(test_callback_state, {
%%     events = [] :: [term()],
%%     pid :: pid()
%% }).

%%% ============================================================================
%%% Test Setup
%%% ============================================================================

complete_alice_to_bob_flow_test() ->
    % Start test callback collector
    CallbackPid = spawn_link(fun() -> callback_collector([]) end),

    % Start Alice and Bob engines
    {ok, AlicePid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),
    {ok, BobPid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),

    try
        % Generate test keys
        {RootKey, AliceKeys, BobKeys} = generate_test_keys(),

        % Initialize Alice as sender
        ok = cryptic_ratchet_engine:init_as_sender(
            AlicePid, RootKey, AliceKeys
        ),

        % Check Alice's state
        AliceState1 = cryptic_ratchet_engine:get_state_info(AlicePid),
        ?assertEqual(sender_init, maps:get(current_state, AliceState1)),

        % Initialize Bob as receiver
        ok = cryptic_ratchet_engine:init_as_receiver(BobPid, RootKey, BobKeys),

        % Check Bob's state
        BobState1 = cryptic_ratchet_engine:get_state_info(BobPid),
        ?assertEqual(receiver_init, maps:get(current_state, BobState1)),

        % Alice encrypts first message
        Message1 = <<"Hello Bob from Alice!">>,
        {ok, EncryptedMsg1} = cryptic_ratchet_engine:encrypt_message(
            AlicePid, Message1
        ),

        % Check Alice transitioned to sending_active
        AliceState2 = cryptic_ratchet_engine:get_state_info(AlicePid),
        ?assertEqual(sending_active, maps:get(current_state, AliceState2)),

        % Bob decrypts the message
        {ok, DecryptedMsg1} = cryptic_ratchet_engine:decrypt_message(
            BobPid, EncryptedMsg1
        ),
        ?assertEqual(Message1, DecryptedMsg1),

        % Check Bob transitioned to receiving_active
        BobState2 = cryptic_ratchet_engine:get_state_info(BobPid),
        ?assertEqual(receiving_active, maps:get(current_state, BobState2)),

        % Bob encrypts reply (should trigger DH ratchet)
        Message2 = <<"Hello Alice from Bob!">>,
        {ok, EncryptedMsg2} = cryptic_ratchet_engine:encrypt_message(
            BobPid, Message2
        ),

        % Check Bob is now bidirectional
        BobState3 = cryptic_ratchet_engine:get_state_info(BobPid),
        ?assertEqual(bidirectional, maps:get(current_state, BobState3)),

        % Alice decrypts Bob's message
        {ok, DecryptedMsg2} = cryptic_ratchet_engine:decrypt_message(
            AlicePid, EncryptedMsg2
        ),
        ?assertEqual(Message2, DecryptedMsg2),

        % Check Alice is now bidirectional too
        AliceState3 = cryptic_ratchet_engine:get_state_info(AlicePid),
        ?assertEqual(bidirectional, maps:get(current_state, AliceState3)),

        % Test bidirectional messaging
        Message3 = <<"Bidirectional test">>,
        {ok, EncryptedMsg3} = cryptic_ratchet_engine:encrypt_message(
            AlicePid, Message3
        ),
        {ok, DecryptedMsg3} = cryptic_ratchet_engine:decrypt_message(
            BobPid, EncryptedMsg3
        ),
        ?assertEqual(Message3, DecryptedMsg3),

        Message4 = <<"Reply in bidirectional mode">>,
        {ok, EncryptedMsg4} = cryptic_ratchet_engine:encrypt_message(
            BobPid, Message4
        ),
        {ok, DecryptedMsg4} = cryptic_ratchet_engine:decrypt_message(
            AlicePid, EncryptedMsg4
        ),
        ?assertEqual(Message4, DecryptedMsg4),

        % Collect callback events
        CallbackPid ! {get_events, self()},
        Events =
            receive
                {events, EventList} -> EventList
            after 1000 ->
                []
            end,

        % Verify we got expected callbacks
        StateChangeEvents = [E || {state_change, _} = E <- Events],
        MessageEvents = [E || {message_event, _} = E <- Events],
        LifecycleEvents = [E || {lifecycle_event, _} = E <- Events],

        % Multiple state transitions
        ?assert(length(StateChangeEvents) >= 6),
        % Encrypt/decrypt operations
        ?assert(length(MessageEvents) >= 8),
        % Started + initialized events
        ?assert(length(LifecycleEvents) >= 4),

        ok
    after
        cryptic_ratchet_engine:stop(AlicePid),
        cryptic_ratchet_engine:stop(BobPid),
        CallbackPid ! stop
    end.

error_handling_test() ->
    CallbackPid = spawn_link(fun() -> callback_collector([]) end),

    {ok, EnginePid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),

    try
        % Try to encrypt without initialization
        Result1 = cryptic_ratchet_engine:encrypt_message(EnginePid, <<"test">>),
        ?assertMatch({error, not_initialized}, Result1),

        % Try to decrypt without initialization
        Result2 = cryptic_ratchet_engine:decrypt_message(
            EnginePid, <<"fake_msg">>
        ),
        ?assertMatch({error, not_initialized}, Result2),

        % Initialize with bad parameters (should trigger error callback)
        BadRootKey = <<"short">>,
        BadKeys = {<<"bad_pub">>, <<"bad_priv">>},
        Result3 = cryptic_ratchet_engine:init_as_sender(
            EnginePid, BadRootKey, BadKeys
        ),
        ?assertMatch({error, _}, Result3),

        % Collect callback events
        CallbackPid ! {get_events, self()},
        Events =
            receive
                {events, EventList} -> EventList
            after 1000 ->
                []
            end,

        % Should have error events
        ErrorEvents = [E || {error, _} = E <- Events],
        ?assert(length(ErrorEvents) >= 2),

        ok
    after
        cryptic_ratchet_engine:stop(EnginePid),
        CallbackPid ! stop
    end.

debug_and_monitoring_test() ->
    CallbackPid = spawn_link(fun() -> callback_collector([]) end),

    {ok, EnginePid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),

    try
        {RootKey, Keys, _} = generate_test_keys(),

        % Initialize
        ok = cryptic_ratchet_engine:init_as_sender(EnginePid, RootKey, Keys),

        % Get debug info
        DebugInfo = cryptic_ratchet_engine:get_debug_info(EnginePid),

        % Verify debug info structure
        ?assert(maps:is_key(current_state, DebugInfo)),
        ?assert(maps:is_key(message_count, DebugInfo)),
        ?assert(maps:is_key(error_count, DebugInfo)),
        ?assert(maps:is_key(callback_module, DebugInfo)),
        ?assert(maps:is_key(subscriber_count, DebugInfo)),

        ?assertEqual(?MODULE, maps:get(callback_module, DebugInfo)),
        ?assertEqual(0, maps:get(message_count, DebugInfo)),
        ?assertEqual(0, maps:get(error_count, DebugInfo)),

        ok
    after
        cryptic_ratchet_engine:stop(EnginePid),
        CallbackPid ! stop
    end.

out_of_order_message_test() ->
    CallbackPid = spawn_link(fun() -> callback_collector([]) end),

    % Start engines for Alice and Bob
    {ok, AlicePid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),
    {ok, BobPid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),

    try
        % Generate test keys
        {RootKey, AliceKeys, BobKeys} = generate_test_keys(),

        % Initialize Alice and Bob
        ok = cryptic_ratchet_engine:init_as_sender(
            AlicePid, RootKey, AliceKeys
        ),
        ok = cryptic_ratchet_engine:init_as_receiver(BobPid, RootKey, BobKeys),

        % Alice sends 4 messages in sequence
        Msg1 = <<"Message 1 - First in sequence">>,
        Msg2 = <<"Message 2 - Second in sequence">>,
        Msg3 = <<"Message 3 - Third in sequence">>,
        Msg4 = <<"Message 4 - Fourth in sequence">>,

        {ok, EncMsg1} = cryptic_ratchet_engine:encrypt_message(AlicePid, Msg1),
        {ok, EncMsg2} = cryptic_ratchet_engine:encrypt_message(AlicePid, Msg2),
        {ok, EncMsg3} = cryptic_ratchet_engine:encrypt_message(AlicePid, Msg3),
        {ok, EncMsg4} = cryptic_ratchet_engine:encrypt_message(AlicePid, Msg4),

        % Bob receives messages out of order: 3, 1, 4, 2
        % This tests the engine's ability to handle skipped message keys

        % Receive message 3 first (skips messages 1 and 2)
        {ok, DecMsg3} = cryptic_ratchet_engine:decrypt_message(BobPid, EncMsg3),
        ?assertEqual(Msg3, DecMsg3),

        % Check Bob's state - should have transitioned to receiving_active
        BobState1 = cryptic_ratchet_engine:get_state_info(BobPid),
        ?assertEqual(receiving_active, maps:get(current_state, BobState1)),

        % Receive message 1 (should use cached/derived key)
        {ok, DecMsg1} = cryptic_ratchet_engine:decrypt_message(BobPid, EncMsg1),
        ?assertEqual(Msg1, DecMsg1),

        % Receive message 4 (another forward jump)
        {ok, DecMsg4} = cryptic_ratchet_engine:decrypt_message(BobPid, EncMsg4),
        ?assertEqual(Msg4, DecMsg4),

        % Receive message 2 (fills in the gap)
        {ok, DecMsg2} = cryptic_ratchet_engine:decrypt_message(BobPid, EncMsg2),
        ?assertEqual(Msg2, DecMsg2),

        % Verify all messages were processed correctly
        BobState2 = cryptic_ratchet_engine:get_state_info(BobPid),
        MessageCount = maps:get(message_count, BobState2),
        ?assertEqual(4, MessageCount),

        % Test bidirectional communication after out-of-order processing
        BobReply = <<"Bob: Received all messages out of order successfully!">>,
        {ok, EncReply} = cryptic_ratchet_engine:encrypt_message(
            BobPid, BobReply
        ),
        {ok, DecReply} = cryptic_ratchet_engine:decrypt_message(
            AlicePid, EncReply
        ),
        ?assertEqual(BobReply, DecReply),

        % Both engines should now be in bidirectional state
        AliceFinalState = cryptic_ratchet_engine:get_state_info(AlicePid),
        BobFinalState = cryptic_ratchet_engine:get_state_info(BobPid),

        ?assertEqual(bidirectional, maps:get(current_state, AliceFinalState)),
        ?assertEqual(bidirectional, maps:get(current_state, BobFinalState)),

        % Collect callback events to verify proper notifications
        CallbackPid ! {get_events, self()},
        Events =
            receive
                {events, EventList} -> EventList
            after 1000 ->
                []
            end,

        % Should have received multiple message events and state changes
        MessageEvents = [E || {message_event, _} = E <- Events],
        StateChangeEvents = [E || {state_change, _} = E <- Events],

        % 4 encrypts + 4 decrypts + 1 reply each way
        ?assert(length(MessageEvents) >= 10),
        % Multiple state transitions
        ?assert(length(StateChangeEvents) >= 4),

        ok
    after
        cryptic_ratchet_engine:stop(AlicePid),
        cryptic_ratchet_engine:stop(BobPid),
        CallbackPid ! stop
    end.

concurrent_message_processing_test() ->
    CallbackPid = spawn_link(fun() -> callback_collector([]) end),

    % Start engines for Alice and Bob
    {ok, AlicePid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),
    {ok, BobPid} = cryptic_ratchet_engine:start_link(?MODULE, #{}, #{
        callback_collector => CallbackPid
    }),

    try
        % Generate test keys
        {RootKey, AliceKeys, BobKeys} = generate_test_keys(),

        % Initialize Alice and Bob
        ok = cryptic_ratchet_engine:init_as_sender(
            AlicePid, RootKey, AliceKeys
        ),
        ok = cryptic_ratchet_engine:init_as_receiver(BobPid, RootKey, BobKeys),

        % Test concurrent encryption operations
        % Alice encrypts multiple messages rapidly
        Messages = [
            <<"Concurrent message 1">>,
            <<"Concurrent message 2">>,
            <<"Concurrent message 3">>,
            <<"Concurrent message 4">>,
            <<"Concurrent message 5">>
        ],

        % Encrypt all messages concurrently using separate processes
        Self = self(),
        EncryptProcesses = [
            spawn_link(fun() ->
                {ok, EncMsg} = cryptic_ratchet_engine:encrypt_message(
                    AlicePid, Msg
                ),
                Self ! {encrypted, N, EncMsg}
            end)
         || {N, Msg} <- lists:enumerate(Messages)
        ],

        % Collect encrypted messages
        EncryptedMessages = lists:sort([
            receive
                {encrypted, N, EncMsg} -> {N, EncMsg}
            end
         || _ <- EncryptProcesses
        ]),

        % Verify all messages were encrypted
        ?assertEqual(5, length(EncryptedMessages)),

        % Bob decrypts all messages in original order
        DecryptedMessages = [
            begin
                {ok, DecMsg} = cryptic_ratchet_engine:decrypt_message(
                    BobPid, EncMsg
                ),
                DecMsg
            end
         || {_N, EncMsg} <- EncryptedMessages
        ],

        % Verify all messages were decrypted correctly
        ?assertEqual(Messages, DecryptedMessages),

        % Verify Bob transitioned to receiving_active
        BobState = cryptic_ratchet_engine:get_state_info(BobPid),
        ?assertEqual(receiving_active, maps:get(current_state, BobState)),

        ok
    after
        cryptic_ratchet_engine:stop(AlicePid),
        cryptic_ratchet_engine:stop(BobPid),
        CallbackPid ! stop
    end.

%%% ============================================================================
%%% Callback Implementation
%%% ============================================================================

handle_state_change(EngineRef, FromState, ToState, Context) ->
    case maps:get(callback_collector, Context, undefined) of
        undefined -> ok;
        Pid -> Pid ! {state_change, {EngineRef, FromState, ToState}}
    end,
    ok.

handle_message_event(EngineRef, Event, Data, Context) ->
    case maps:get(callback_collector, Context, undefined) of
        undefined -> ok;
        Pid -> Pid ! {message_event, {EngineRef, Event, Data}}
    end,
    ok.

handle_error(EngineRef, ErrorType, Error, Context) ->
    case maps:get(callback_collector, Context, undefined) of
        undefined -> ok;
        Pid -> Pid ! {error, {EngineRef, ErrorType, Error}}
    end,
    ok.

handle_debug_event(EngineRef, Event, Data, Context) ->
    case maps:get(callback_collector, Context, undefined) of
        undefined -> ok;
        Pid -> Pid ! {debug_event, {EngineRef, Event, Data}}
    end,
    ok.

handle_lifecycle_event(EngineRef, Event, Context) ->
    case maps:get(callback_collector, Context, undefined) of
        undefined -> ok;
        Pid -> Pid ! {lifecycle_event, {EngineRef, Event}}
    end,
    ok.

%%% ============================================================================
%%% Helper Functions
%%% ============================================================================

generate_test_keys() ->
    RootKey = crypto:strong_rand_bytes(32),
    AliceKeys = cryptic_nif:gen_keypair(),
    BobKeys = cryptic_nif:gen_keypair(),
    {RootKey, AliceKeys, BobKeys}.

callback_collector(Events) ->
    receive
        {get_events, From} ->
            From ! {events, lists:reverse(Events)},
            callback_collector(Events);
        stop ->
            ok;
        Event ->
            callback_collector([Event | Events])
    end.
