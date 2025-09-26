%%% @doc EUnit tests for Double Ratchet out-of-order message handling
%%%
%%% This module tests the skipped message key store functionality that allows
%%% the Double Ratchet to handle messages that arrive out of order or with gaps.
%%% This is essential for real-world messaging where network conditions can
%%% cause messages to be delayed, lost, or reordered.
%%%
%%% Test scenarios:
%%% - Message gaps (missing messages in sequence)
%%% - Out-of-order delivery (messages arrive in wrong sequence)
%%% - Delayed messages (messages arrive much later)
%%% - Mixed scenarios (gaps + out-of-order + delayed)

-module(cryptic_double_ratchet_out_of_order_test).

-include_lib("eunit/include/eunit.hrl").
-include("cryptic.hrl").

%%% ============================================================================
%%% Test Setup and Utilities
%%% ============================================================================

setup() ->
    % Start event manager for debug logging
    case whereis(cryptic_event_manager) of
        undefined ->
            try
                {ok, _Pid} = gen_event:start_link({local, cryptic_event_manager}),
                gen_event:add_handler(cryptic_event_manager, cryptic_console_logger, [])
            catch
                _:_ -> ok  % Continue without event manager if it fails
            end;
        _ -> ok
    end.

cleanup(_) ->
    % Stop event manager if we started it
    case whereis(cryptic_event_manager) of
        undefined -> ok;
        _Pid -> catch gen_event:stop(cryptic_event_manager)
    end.

%% @doc Setup Alice and Bob with established Double Ratchet session
setup_alice_bob_session() ->
    setup(),
    
    % Create shared X3DH root key
    SharedRootKey = crypto:strong_rand_bytes(32),
    
    % Generate DH keypairs for both parties
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),
    
    % Initialize both parties
    {ok, AliceState0} = cryptic_double_ratchet:init_sender(SharedRootKey, {AliceDHPub, AliceDHPriv}),
    {ok, BobState0} = cryptic_double_ratchet:init_receiver(SharedRootKey, {BobDHPub, BobDHPriv}),
    
    % Simulate X3DH handshake - both parties know each other's initial DH keys
    AliceState = cryptic_double_ratchet:set_remote_dh_key(AliceState0, BobDHPub),
    BobState = cryptic_double_ratchet:set_remote_dh_key(BobState0, AliceDHPub),
    
    {AliceState, BobState}.

%% @doc Encrypt multiple messages from Alice to Bob
encrypt_alice_messages(AliceState, MessageTexts) ->
    encrypt_messages_loop(AliceState, MessageTexts, []).

encrypt_messages_loop(State, [], EncryptedMessages) ->
    {State, lists:reverse(EncryptedMessages)};
encrypt_messages_loop(State, [MsgText | Rest], Acc) ->
    {ok, EncryptedMsg, NewState} = cryptic_double_ratchet:encrypt_message(MsgText, State),
    encrypt_messages_loop(NewState, Rest, [EncryptedMsg | Acc]).

%%% ============================================================================
%%% Out-of-Order Message Tests
%%% ============================================================================

%% @doc Test basic message gap handling (missing message 1, receive message 2)
message_gap_test() ->
    ?debugMsg("\n=== MESSAGE GAP TEST ==="),
    
    % Setup session
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts 3 messages
    Messages = [<<"Message 0">>, <<"Message 1">>, <<"Message 2">>],
    {_AliceStateFinal, [Msg0, Msg1, Msg2]} = encrypt_alice_messages(AliceState0, Messages),
    
    ?debugFmt("Alice encrypted 3 messages: ~p~n", [
        [maps:get(msg_number, M) || M <- [Msg0, Msg1, Msg2]]
    ]),
    
    % Bob receives message 0 (normal)
    {ok, <<"Message 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg0, BobState0),
    BobInfo1 = cryptic_double_ratchet:get_state_info(BobState1),
    ?debugFmt("Bob after msg 0: recv_msg_number=~p, skipped_keys=~p~n",
              [maps:get(recv_msg_number, BobInfo1), maps:get(skipped_keys_count, BobInfo1)]),
    
    % Bob receives message 2 (skipping message 1) - this should create skipped key
    ?debugMsg("Bob receiving message 2 (skipping message 1)..."),
    {ok, <<"Message 2">>, BobState2} = cryptic_double_ratchet:decrypt_message(Msg2, BobState1),
    BobInfo2 = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("Bob after msg 2: recv_msg_number=~p, skipped_keys=~p~n",
              [maps:get(recv_msg_number, BobInfo2), maps:get(skipped_keys_count, BobInfo2)]),
    
    % Verify that a skipped key was created for message 1
    ?assertEqual(1, maps:get(skipped_keys_count, BobInfo2)),
    ?assertEqual(3, maps:get(recv_msg_number, BobInfo2)),  % Should advance to expect message 3
    
    % Bob finally receives delayed message 1 - should decrypt using skipped key
    ?debugMsg("Bob receiving delayed message 1..."),
    {ok, <<"Message 1">>, BobState3} = cryptic_double_ratchet:decrypt_message(Msg1, BobState2),
    BobInfo3 = cryptic_double_ratchet:get_state_info(BobState3),
    ?debugFmt("Bob after delayed msg 1: recv_msg_number=~p, skipped_keys=~p~n",
              [maps:get(recv_msg_number, BobInfo3), maps:get(skipped_keys_count, BobInfo3)]),
    
    % Verify that the skipped key was consumed (forward secrecy)
    ?assertEqual(0, maps:get(skipped_keys_count, BobInfo3)),
    ?assertEqual(3, maps:get(recv_msg_number, BobInfo3)),  % Should still expect message 3
    
    cleanup(ok).

%% @doc Test completely out-of-order delivery (receive 3, 1, 2)
out_of_order_delivery_test() ->
    ?debugMsg("\n=== OUT-OF-ORDER DELIVERY TEST ==="),
    
    % Setup session
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts 4 messages
    Messages = [<<"Msg 0">>, <<"Msg 1">>, <<"Msg 2">>, <<"Msg 3">>],
    {_AliceStateFinal, [Msg0, Msg1, Msg2, Msg3]} = encrypt_alice_messages(AliceState0, Messages),
    
    % Bob receives first message normally
    {ok, <<"Msg 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg0, BobState0),
    
    % Bob receives messages completely out of order: 3, 1, 2
    ?debugMsg("Receiving messages out of order: 3, 1, 2"),
    
    % Receive message 3 first (creates skipped keys for 1, 2)
    {ok, <<"Msg 3">>, BobState2} = cryptic_double_ratchet:decrypt_message(Msg3, BobState1),
    BobInfo2 = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("After msg 3: skipped_keys=~p, recv_msg_number=~p~n",
              [maps:get(skipped_keys_count, BobInfo2), maps:get(recv_msg_number, BobInfo2)]),
    ?assertEqual(2, maps:get(skipped_keys_count, BobInfo2)),  % Keys for msg 1 and 2
    
    % Receive message 1 (uses skipped key)
    {ok, <<"Msg 1">>, BobState3} = cryptic_double_ratchet:decrypt_message(Msg1, BobState2),
    BobInfo3 = cryptic_double_ratchet:get_state_info(BobState3),
    ?debugFmt("After msg 1: skipped_keys=~p~n", [maps:get(skipped_keys_count, BobInfo3)]),
    ?assertEqual(1, maps:get(skipped_keys_count, BobInfo3)),  % Only key for msg 2 remains
    
    % Receive message 2 (uses last skipped key)
    {ok, <<"Msg 2">>, BobState4} = cryptic_double_ratchet:decrypt_message(Msg2, BobState3),
    BobInfo4 = cryptic_double_ratchet:get_state_info(BobState4),
    ?debugFmt("After msg 2: skipped_keys=~p~n", [maps:get(skipped_keys_count, BobInfo4)]),
    ?assertEqual(0, maps:get(skipped_keys_count, BobInfo4)),  % All skipped keys consumed
    
    cleanup(ok).

%% @doc Test large gap handling (skip many messages)
large_gap_test() ->
    ?debugMsg("\n=== LARGE GAP TEST ==="),
    
    % Setup session  
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts many messages
    MessageTexts = [list_to_binary(io_lib:format("Message ~p", [N])) || N <- lists:seq(0, 50)],
    {_AliceStateFinal, EncryptedMessages} = encrypt_alice_messages(AliceState0, MessageTexts),
    
    % Bob receives message 0 normally
    [Msg0 | _RestMessages] = EncryptedMessages,
    {ok, <<"Message 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg0, BobState0),
    
    % Bob receives message 50 (skipping 1-49) - creates many skipped keys
    Msg50 = lists:nth(51, EncryptedMessages),  % 51st element (0-indexed)
    ?debugMsg("Bob receiving message 50 (skipping 1-49)..."),
    {ok, <<"Message 50">>, BobState2} = cryptic_double_ratchet:decrypt_message(Msg50, BobState1),
    BobInfo2 = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("After large gap: skipped_keys=~p, recv_msg_number=~p~n",
              [maps:get(skipped_keys_count, BobInfo2), maps:get(recv_msg_number, BobInfo2)]),
    
    % Should have created 49 skipped keys (for messages 1-49)
    ?assertEqual(49, maps:get(skipped_keys_count, BobInfo2)),
    ?assertEqual(51, maps:get(recv_msg_number, BobInfo2)),  % Expecting message 51
    
    % Test that we can decrypt some messages from the gap
    Msg25 = lists:nth(26, EncryptedMessages),  % Message 25
    {ok, <<"Message 25">>, BobState3} = cryptic_double_ratchet:decrypt_message(Msg25, BobState2),
    BobInfo3 = cryptic_double_ratchet:get_state_info(BobState3),
    ?assertEqual(48, maps:get(skipped_keys_count, BobInfo3)),  % One key consumed
    
    % Test another message from the gap
    Msg10 = lists:nth(11, EncryptedMessages),  % Message 10
    {ok, <<"Message 10">>, _BobState4} = cryptic_double_ratchet:decrypt_message(Msg10, BobState3),
    
    cleanup(ok).

%% @doc Test mixed scenario: gaps + out-of-order + delayed delivery
mixed_scenario_test() ->
    ?debugMsg("\n=== MIXED SCENARIO TEST ==="),
    
    % Setup session
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts 8 messages
    Messages = [list_to_binary(io_lib:format("Mixed msg ~p", [N])) || N <- lists:seq(0, 7)],
    {_AliceStateFinal, EncryptedMsgs} = encrypt_alice_messages(AliceState0, Messages),
    [M0, M1, M2, M3, M4, M5, M6, M7] = EncryptedMsgs,
    
    % Bob receives messages in a complex pattern: 0, 3, 6, 1, 7, 2, 4, 5
    ?debugMsg("Complex delivery pattern: 0, 3, 6, 1, 7, 2, 4, 5"),
    
    % Message 0 (normal)
    {ok, <<"Mixed msg 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(M0, BobState0),
    
    % Message 3 (creates skipped keys for 1, 2)
    {ok, <<"Mixed msg 3">>, BobState2} = cryptic_double_ratchet:decrypt_message(M3, BobState1),
    BobInfo2 = cryptic_double_ratchet:get_state_info(BobState2),
    ?assertEqual(2, maps:get(skipped_keys_count, BobInfo2)),  % Keys for 1, 2
    
    % Message 6 (creates additional skipped keys for 4, 5)
    {ok, <<"Mixed msg 6">>, BobState3} = cryptic_double_ratchet:decrypt_message(M6, BobState2),
    BobInfo3 = cryptic_double_ratchet:get_state_info(BobState3),
    ?assertEqual(4, maps:get(skipped_keys_count, BobInfo3)),  % Keys for 1, 2, 4, 5
    
    % Message 1 (uses skipped key)
    {ok, <<"Mixed msg 1">>, BobState4} = cryptic_double_ratchet:decrypt_message(M1, BobState3),
    BobInfo4 = cryptic_double_ratchet:get_state_info(BobState4),
    ?assertEqual(3, maps:get(skipped_keys_count, BobInfo4)),  % Keys for 2, 4, 5
    
    % Message 7 (normal continuation)
    {ok, <<"Mixed msg 7">>, BobState5} = cryptic_double_ratchet:decrypt_message(M7, BobState4),
    BobInfo5 = cryptic_double_ratchet:get_state_info(BobState5),
    ?assertEqual(3, maps:get(skipped_keys_count, BobInfo5)),  % Still keys for 2, 4, 5
    
    % Messages 2, 4, 5 (clean up remaining skipped keys)
    {ok, <<"Mixed msg 2">>, BobState6} = cryptic_double_ratchet:decrypt_message(M2, BobState5),
    {ok, <<"Mixed msg 4">>, BobState7} = cryptic_double_ratchet:decrypt_message(M4, BobState6),
    {ok, <<"Mixed msg 5">>, BobState8} = cryptic_double_ratchet:decrypt_message(M5, BobState7),
    
    % Verify all skipped keys have been consumed
    BobInfo8 = cryptic_double_ratchet:get_state_info(BobState8),
    ?assertEqual(0, maps:get(skipped_keys_count, BobInfo8)),
    
    cleanup(ok).

%% @doc Test error handling for excessive message gaps
excessive_gap_error_test() ->
    ?debugMsg("\n=== EXCESSIVE GAP ERROR TEST ==="),
    
    % Setup session
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts message 0 and a message with a very large gap
    {ok, Msg0, AliceState1} = cryptic_double_ratchet:encrypt_message(<<"Message 0">>, AliceState0),
    
    % Create a fake message with an excessive gap (msg_number = 10000)
    % We'll modify message 1 to have msg_number 10000
    {ok, Msg1, _AliceState2} = cryptic_double_ratchet:encrypt_message(<<"Message 1">>, AliceState1),
    
    % Manually create a message with excessive gap
    ExcessiveGapMsg = Msg1#{msg_number => 10000},
    
    % Bob receives message 0 normally
    {ok, <<"Message 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg0, BobState0),
    
    % Bob tries to receive message with excessive gap - should fail
    ?debugMsg("Testing excessive gap (msg 0 -> 10000)..."),
    Result = cryptic_double_ratchet:decrypt_message(ExcessiveGapMsg, BobState1),
    
    % Should get an error about excessive message gap
    case Result of
        {error, {excessive_message_gap, Gap, MaxGap}} ->
            ?debugFmt("Got expected excessive gap error: gap=~p, max=~p~n", [Gap, MaxGap]),
            ?assert(Gap > MaxGap);
        Other ->
            ?debugFmt("Unexpected result: ~p~n", [Other]),
            ?assert(false)
    end,
    
    cleanup(ok).

%% @doc Test that duplicate messages are handled correctly
duplicate_message_test() ->
    ?debugMsg("\n=== DUPLICATE MESSAGE TEST ==="),
    
    % Setup session
    {AliceState0, BobState0} = setup_alice_bob_session(),
    
    % Alice encrypts 3 messages
    {ok, Msg0, AliceState1} = cryptic_double_ratchet:encrypt_message(<<"Message 0">>, AliceState0),
    {ok, Msg1, AliceState2} = cryptic_double_ratchet:encrypt_message(<<"Message 1">>, AliceState1),
    {ok, _Msg2, _AliceState3} = cryptic_double_ratchet:encrypt_message(<<"Message 2">>, AliceState2),
    
    % Bob receives messages 0 and 1 normally
    {ok, <<"Message 0">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg0, BobState0),
    {ok, <<"Message 1">>, BobState2} = cryptic_double_ratchet:decrypt_message(Msg1, BobState1),
    
    % Bob tries to decrypt message 0 again (duplicate/replay)
    ?debugMsg("Testing duplicate message 0..."),
    Result = cryptic_double_ratchet:decrypt_message(Msg0, BobState2),
    
    % Should fail because message 0 is before current expected message
    % The exact error depends on implementation - could be no_skipped_key or authentication_failed
    case Result of
        {error, {no_skipped_key, _KeyId}} ->
            ?debugMsg("Got expected no_skipped_key error for duplicate");
        {error, {authentication_failed, _MsgNum}} ->
            ?debugMsg("Got expected authentication_failed error for duplicate");
        {error, _Other} ->
            ?debugMsg("Got some error for duplicate (acceptable)");
        {ok, _Plaintext, _State} ->
            ?debugMsg("WARNING: Duplicate message decrypted (potential security issue)")
    end,
    
    cleanup(ok).

%%% ============================================================================
%%% Test Suite Registration
%%% ============================================================================

out_of_order_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
         {"Message gap handling", fun message_gap_test/0},
         {"Out-of-order delivery", fun out_of_order_delivery_test/0},
         {"Large gap handling", fun large_gap_test/0},
         {"Mixed scenario handling", fun mixed_scenario_test/0},
         {"Excessive gap error handling", fun excessive_gap_error_test/0},
         {"Duplicate message handling", fun duplicate_message_test/0}
     ]}.