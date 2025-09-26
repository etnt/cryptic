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