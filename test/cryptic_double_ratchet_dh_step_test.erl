-module(cryptic_double_ratchet_dh_step_test).
-include_lib("eunit/include/eunit.hrl").
-include("cryptic.hrl").

%% Test specifically when DH ratchet steps should increment

consecutive_messages_test() ->

    % Set up Alice and Bob with shared root key
    SharedRootKey = cryptic_nif:rand_bytes(32),
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),

    % Initialize both parties
    {ok, AliceState0} = cryptic_double_ratchet:init_sender(SharedRootKey, {AliceDHPub, AliceDHPriv}),
    {ok, BobState0} = cryptic_double_ratchet:init_receiver(SharedRootKey, {BobDHPub, BobDHPriv}),

    % Simulate X3DH handshake - both parties should know each other's initial DH keys
    AliceState0Updated = cryptic_double_ratchet:set_remote_dh_key(AliceState0, BobDHPub),
    BobState0Updated = cryptic_double_ratchet:set_remote_dh_key(BobState0, AliceDHPub),

    Alice0Info = cryptic_double_ratchet:get_state_info(AliceState0Updated),
    Bob0Info = cryptic_double_ratchet:get_state_info(BobState0Updated),
    ?debugFmt("=== INITIAL STATE ===", []),
    ?debugFmt("Alice: step=~p, send_chain_active=~p", 
              [maps:get(dh_ratchet_step, Alice0Info), maps:get(sending_chain_active, Alice0Info)]),
    ?debugFmt("Bob: step=~p, send_chain_active=~p", 
              [maps:get(dh_ratchet_step, Bob0Info), maps:get(sending_chain_active, Bob0Info)]),

    % Alice sends first message
    {ok, Msg1, AliceState1} = cryptic_double_ratchet:encrypt_message(<<"Alice message 1">>, AliceState0Updated),
    Alice1Info = cryptic_double_ratchet:get_state_info(AliceState1),
    ?debugFmt("Alice after msg 1: step=~p", [maps:get(dh_ratchet_step, Alice1Info)]),
    ?assertEqual(0, maps:get(dh_ratchet_step, Alice1Info)),

    % Bob receives and decrypts
    {ok, <<"Alice message 1">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg1, BobState0Updated),
    Bob1Info = cryptic_double_ratchet:get_state_info(BobState1),
    ?debugFmt("Bob after decrypt: step=~p, has_remote_dh=~p", 
              [maps:get(dh_ratchet_step, Bob1Info), maps:get(has_remote_dh, Bob1Info)]),
    ?assertEqual(0, maps:get(dh_ratchet_step, Bob1Info)),

    % Bob sends first reply
    {ok, Msg2, BobState2} = cryptic_double_ratchet:encrypt_message(<<"Bob reply 1">>, BobState1),
    Bob2Info = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("Bob after first reply: step=~p", [maps:get(dh_ratchet_step, Bob2Info)]),
    
    % Alice receives Bob's reply
    {ok, <<"Bob reply 1">>, AliceState2} = cryptic_double_ratchet:decrypt_message(Msg2, AliceState1),
    Alice2Info = cryptic_double_ratchet:get_state_info(AliceState2),
    ?debugFmt("Alice after decrypt Bob reply: step=~p", [maps:get(dh_ratchet_step, Alice2Info)]),

    % NOW THE CRITICAL TEST: Bob sends SECOND consecutive message
    % This should trigger a DH ratchet step
    {ok, _Msg3, BobState3} = cryptic_double_ratchet:encrypt_message(<<"Bob message 2">>, BobState2),
    Bob3Info = cryptic_double_ratchet:get_state_info(BobState3),
    ?debugFmt("Bob after SECOND message: step=~p (should be 1?)", [maps:get(dh_ratchet_step, Bob3Info)]),
    
    % Alice sends SECOND message (should also increment)
    {ok, _Msg4, AliceState3} = cryptic_double_ratchet:encrypt_message(<<"Alice message 2">>, AliceState2),
    Alice3Info = cryptic_double_ratchet:get_state_info(AliceState3),
    ?debugFmt("Alice after SECOND message: step=~p (should be 1?)", [maps:get(dh_ratchet_step, Alice3Info)]),

    % The question is: when should the DH step increment?
    % Option 1: Never (just use chain ratcheting)
    % Option 2: On second consecutive message from same sender
    % Option 3: On direction change (Alice->Bob->Alice)

    ?debugFmt("=== SUMMARY ===", []),
    ?debugFmt("Alice final step: ~p", [maps:get(dh_ratchet_step, Alice3Info)]),
    ?debugFmt("Bob final step: ~p", [maps:get(dh_ratchet_step, Bob3Info)]),
    
    ok.

%% @doc Test the exact scenario from manual testing: Alice sends 3 messages, Bob replies, Alice tries to send again
%%
%% This reproduces the issue where Alice's DH ratchet step increments and Bob can't decrypt her next message.
%% The sequence is:
%% 1. Alice -> Bob: msg 1
%% 2. Alice -> Bob: msg 2  
%% 3. Alice -> Bob: msg 3
%% 4. Bob -> Alice: reply 1
%% 5. Alice -> Bob: msg 4 (FAILS in manual testing)
manual_scenario_test() ->
    ?debugFmt("=== TESTING MANUAL SCENARIO ===", []),
    ?debugFmt("Alice sends 3 messages, Bob replies, Alice sends again", []),
    
    % Set up Alice and Bob with shared root key (simulates successful X3DH)
    SharedRootKey = cryptic_nif:rand_bytes(32),
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),

    % Initialize both parties
    {ok, AliceState0} = cryptic_double_ratchet:init_sender(SharedRootKey, {AliceDHPub, AliceDHPriv}),
    {ok, BobState0} = cryptic_double_ratchet:init_receiver(SharedRootKey, {BobDHPub, BobDHPriv}),

    % Simulate X3DH handshake - both parties know each other's initial DH keys
    AliceState = cryptic_double_ratchet:set_remote_dh_key(AliceState0, BobDHPub),
    BobState = cryptic_double_ratchet:set_remote_dh_key(BobState0, AliceDHPub),

    AliceInitInfo = cryptic_double_ratchet:get_state_info(AliceState),
    BobInitInfo = cryptic_double_ratchet:get_state_info(BobState),
    ?debugFmt("INITIAL - Alice: Step ~p, Chain[~p send, ~p recv]", 
              [maps:get(dh_ratchet_step, AliceInitInfo),
               maps:get(send_msg_number, AliceInitInfo),
               maps:get(recv_msg_number, AliceInitInfo)]),
    ?debugFmt("INITIAL - Bob: Step ~p, Chain[~p send, ~p recv]", 
              [maps:get(dh_ratchet_step, BobInitInfo),
               maps:get(send_msg_number, BobInitInfo), 
               maps:get(recv_msg_number, BobInitInfo)]),

    %% PHASE 1: Alice sends 3 consecutive messages to Bob
    
    % Message 1: Alice -> Bob
    {ok, AliceMsg1, AliceState1} = cryptic_double_ratchet:encrypt_message(<<"Alice msg 1">>, AliceState),
    Alice1Info = cryptic_double_ratchet:get_state_info(AliceState1),
    ?debugFmt("After Alice msg 1: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Alice1Info),
               maps:get(send_msg_number, Alice1Info),
               maps:get(recv_msg_number, Alice1Info)]),
    
    {ok, <<"Alice msg 1">>, BobState1} = cryptic_double_ratchet:decrypt_message(AliceMsg1, BobState),
    Bob1Info = cryptic_double_ratchet:get_state_info(BobState1),
    ?debugFmt("After Bob decrypt 1: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Bob1Info),
               maps:get(send_msg_number, Bob1Info),
               maps:get(recv_msg_number, Bob1Info)]),

    % Message 2: Alice -> Bob
    {ok, AliceMsg2, AliceState2} = cryptic_double_ratchet:encrypt_message(<<"Alice msg 2">>, AliceState1),
    Alice2Info = cryptic_double_ratchet:get_state_info(AliceState2),
    ?debugFmt("After Alice msg 2: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Alice2Info),
               maps:get(send_msg_number, Alice2Info),
               maps:get(recv_msg_number, Alice2Info)]),
    
    {ok, <<"Alice msg 2">>, BobState2} = cryptic_double_ratchet:decrypt_message(AliceMsg2, BobState1),
    Bob2Info = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("After Bob decrypt 2: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Bob2Info),
               maps:get(send_msg_number, Bob2Info),
               maps:get(recv_msg_number, Bob2Info)]),

    % Message 3: Alice -> Bob  
    {ok, AliceMsg3, AliceState3} = cryptic_double_ratchet:encrypt_message(<<"Alice msg 3">>, AliceState2),
    Alice3Info = cryptic_double_ratchet:get_state_info(AliceState3),
    ?debugFmt("After Alice msg 3: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Alice3Info),
               maps:get(send_msg_number, Alice3Info),
               maps:get(recv_msg_number, Alice3Info)]),
    
    {ok, <<"Alice msg 3">>, BobState3} = cryptic_double_ratchet:decrypt_message(AliceMsg3, BobState2),
    Bob3Info = cryptic_double_ratchet:get_state_info(BobState3),
    ?debugFmt("After Bob decrypt 3: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Bob3Info),
               maps:get(send_msg_number, Bob3Info),
               maps:get(recv_msg_number, Bob3Info)]),

    %% PHASE 2: Bob sends reply (direction change)
    
    % Message 4: Bob -> Alice (reply)
    {ok, BobReply, BobState4} = cryptic_double_ratchet:encrypt_message(<<"Bob reply 1">>, BobState3),
    Bob4Info = cryptic_double_ratchet:get_state_info(BobState4),
    ?debugFmt("After Bob reply: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Bob4Info),
               maps:get(send_msg_number, Bob4Info),
               maps:get(recv_msg_number, Bob4Info)]),
    
    {ok, <<"Bob reply 1">>, AliceState4} = cryptic_double_ratchet:decrypt_message(BobReply, AliceState3),
    Alice4Info = cryptic_double_ratchet:get_state_info(AliceState4),
    ?debugFmt("After Alice decrypt reply: Step ~p, Chain[~p send, ~p recv]",
              [maps:get(dh_ratchet_step, Alice4Info),
               maps:get(send_msg_number, Alice4Info),
               maps:get(recv_msg_number, Alice4Info)]),

    %% PHASE 3: Alice tries to send again (THIS IS WHERE THE ISSUE OCCURS)
    
    % Message 5: Alice -> Bob (msg 4) - This should work but fails in manual testing
    ?debugFmt("=== CRITICAL TEST: Alice sends msg 4 (after Bob's reply) ===", []),
    
    AliceBeforeMsg4 = cryptic_double_ratchet:get_state_info(AliceState4),
    ?debugFmt("Alice before msg 4: Step ~p, Chain[~p send, ~p recv], Prev[~p msgs]",
              [maps:get(dh_ratchet_step, AliceBeforeMsg4),
               maps:get(send_msg_number, AliceBeforeMsg4),
               maps:get(recv_msg_number, AliceBeforeMsg4),
               maps:get(prev_recv_chain_length, AliceBeforeMsg4)]),
               
    BobBeforeMsg4 = cryptic_double_ratchet:get_state_info(BobState4),
    ?debugFmt("Bob before msg 4: Step ~p, Chain[~p send, ~p recv], Prev[~p msgs]",
              [maps:get(dh_ratchet_step, BobBeforeMsg4),
               maps:get(send_msg_number, BobBeforeMsg4),
               maps:get(recv_msg_number, BobBeforeMsg4),
               maps:get(prev_recv_chain_length, BobBeforeMsg4)]),

    % Try to encrypt Alice's message 4
    case cryptic_double_ratchet:encrypt_message(<<"Alice msg 4">>, AliceState4) of
        {ok, AliceMsg4, AliceState5} ->
            Alice5Info = cryptic_double_ratchet:get_state_info(AliceState5),
            ?debugFmt("Alice msg 4 encrypted successfully: Step ~p, Chain[~p send, ~p recv]",
                      [maps:get(dh_ratchet_step, Alice5Info),
                       maps:get(send_msg_number, Alice5Info),
                       maps:get(recv_msg_number, Alice5Info)]),

            % Now try Bob's decryption - this is where the issue likely is
            case cryptic_double_ratchet:decrypt_message(AliceMsg4, BobState4) of
                {ok, <<"Alice msg 4">>, BobState5} ->
                    Bob5Info = cryptic_double_ratchet:get_state_info(BobState5),
                    ?debugFmt("SUCCESS: Bob decrypted msg 4: Step ~p, Chain[~p send, ~p recv]",
                              [maps:get(dh_ratchet_step, Bob5Info),
                               maps:get(send_msg_number, Bob5Info),
                               maps:get(recv_msg_number, Bob5Info)]),
                    ?debugFmt("=== TEST PASSED: Manual scenario works! ===", []);
                {error, Reason} ->
                    ?debugFmt("FAILED: Bob could not decrypt Alice msg 4: ~p", [Reason]),
                    ?debugFmt("=== TEST REVEALED THE ISSUE ===", []),
                    
                    % Let's examine the message details to debug
                    ?debugFmt("AliceMsg4 details: dh_step=~p, msg_number=~p", 
                              [maps:get(dh_step, AliceMsg4), maps:get(msg_number, AliceMsg4)]),
                    
                    % Check state info via public API
                    Alice5DetailedInfo = cryptic_double_ratchet:get_state_info(AliceState5),
                    Bob4DetailedInfo = cryptic_double_ratchet:get_state_info(BobState4),
                    ?debugFmt("Alice DH public key changed? ~p", [maps:get(dh_public, Alice5DetailedInfo)]),
                    ?debugFmt("Bob remote DH key: ~p", [maps:get(dh_remote, Bob4DetailedInfo)]),
                    
                    ?assert(false) % Fail the test to highlight the issue
            end;
        {error, EncryptError} ->
            ?debugFmt("FAILED: Alice could not encrypt msg 4: ~p", [EncryptError]),
            ?assert(false)
    end.

%% @doc Test simpler back-and-forth to isolate the DH stepping issue
simple_back_and_forth_test() ->
    ?debugFmt("=== SIMPLE BACK-AND-FORTH TEST ===", []),
    
    % Set up Alice and Bob
    SharedRootKey = cryptic_nif:rand_bytes(32),
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),

    {ok, AliceState0} = cryptic_double_ratchet:init_sender(SharedRootKey, {AliceDHPub, AliceDHPriv}),
    {ok, BobState0} = cryptic_double_ratchet:init_receiver(SharedRootKey, {BobDHPub, BobDHPriv}),

    AliceState = cryptic_double_ratchet:set_remote_dh_key(AliceState0, BobDHPub),
    BobState = cryptic_double_ratchet:set_remote_dh_key(BobState0, AliceDHPub),

    % Alice -> Bob (1st message)
    {ok, Msg1, AliceState1} = cryptic_double_ratchet:encrypt_message(<<"Hello Bob">>, AliceState),
    {ok, <<"Hello Bob">>, BobState1} = cryptic_double_ratchet:decrypt_message(Msg1, BobState),
    
    Alice1Info = cryptic_double_ratchet:get_state_info(AliceState1),
    Bob1Info = cryptic_double_ratchet:get_state_info(BobState1),
    ?debugFmt("After A->B: Alice step=~p, Bob step=~p", 
              [maps:get(dh_ratchet_step, Alice1Info), maps:get(dh_ratchet_step, Bob1Info)]),

    % Bob -> Alice (reply)  
    {ok, Msg2, BobState2} = cryptic_double_ratchet:encrypt_message(<<"Hello Alice">>, BobState1),
    {ok, <<"Hello Alice">>, AliceState2} = cryptic_double_ratchet:decrypt_message(Msg2, AliceState1),
    
    Alice2Info = cryptic_double_ratchet:get_state_info(AliceState2),
    Bob2Info = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("After B->A: Alice step=~p, Bob step=~p", 
              [maps:get(dh_ratchet_step, Alice2Info), maps:get(dh_ratchet_step, Bob2Info)]),

    % Alice -> Bob (2nd message) - Should this trigger DH ratchet?
    {ok, Msg3, AliceState3} = cryptic_double_ratchet:encrypt_message(<<"Second message">>, AliceState2),
    
    Alice3Info = cryptic_double_ratchet:get_state_info(AliceState3),
    ?debugFmt("After Alice 2nd msg: Alice step=~p", [maps:get(dh_ratchet_step, Alice3Info)]),
    
    % Critical test: Can Bob decrypt Alice's second message?
    case cryptic_double_ratchet:decrypt_message(Msg3, BobState2) of
        {ok, <<"Second message">>, _BobState3} ->
            ?debugFmt("SUCCESS: Simple back-and-forth works!", []);
        {error, Reason} ->
            ?debugFmt("FAILED: Bob can't decrypt Alice's 2nd message: ~p", [Reason]),
            ?assert(false)
    end.