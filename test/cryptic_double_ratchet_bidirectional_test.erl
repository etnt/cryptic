%%% @doc Focused EUnit test for bidirectional Double Ratchet authentication issue
%%%
%%% This test isolates the exact message flow that's failing:
%%% 1. Alice sends first message to Bob (works)
%%% 2. Bob replies to Alice (authentication fails)
%%%
%%% This allows us to debug the X3DH to Double Ratchet transition
%%% without the complexity of WebSocket handlers and integration layers.

-module(cryptic_double_ratchet_bidirectional_test).

-include_lib("eunit/include/eunit.hrl").
-include("cryptic.hrl").

%%% ============================================================================
%%% Test Setup and Utilities
%%% ============================================================================

setup_test_environment() ->
    % Start event manager for debug logging (optional)
    case whereis(cryptic_event_manager) of
        undefined ->
            try
                cryptic_event_manager:start_link(),
                ok
            catch
                _:_ ->
                    % Event manager not available, continue without it
                    ok
            end;
        _Pid ->
            ok
    end.

%% @doc Create shared X3DH root key and DH keypairs for Alice and Bob
setup_alice_and_bob() ->
    setup_test_environment(),
    
    % Simulate X3DH key agreement - both parties get same root key
    SharedRootKey = crypto:strong_rand_bytes(32),
    
    % Generate DH keypairs for Double Ratchet
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),
    
    ?debugMsg("=== Test Setup ==="),
    ?debugFmt("SharedRootKey: ~p bytes~n", [byte_size(SharedRootKey)]),
    ?debugFmt("Alice DH keypair generated~n", []),
    ?debugFmt("Bob DH keypair generated~n", []),
    
    {SharedRootKey, {AliceDHPub, AliceDHPriv}, {BobDHPub, BobDHPriv}}.

%%% ============================================================================
%%% Core Bidirectional Test
%%% ============================================================================

%% @doc Test the exact bidirectional flow that's failing
bidirectional_authentication_test() ->
    ?debugMsg("\n=== BIDIRECTIONAL AUTHENTICATION TEST ==="),
    
    % 1. Setup Alice and Bob with shared X3DH root key
    {SharedRootKey, AliceKeyPair, BobKeyPair} = setup_alice_and_bob(),
    
    % 2. Initialize Alice as sender (sends first message)
    {ok, AliceState0} = cryptic_double_ratchet:init_sender(SharedRootKey, AliceKeyPair),
    AliceInfo0 = cryptic_double_ratchet:get_state_info(AliceState0),
    ?debugFmt("Alice initialized: ~p~n", [AliceInfo0]),
    
    % 3. Initialize Bob as receiver (waits for first message) 
    {ok, BobState0} = cryptic_double_ratchet:init_receiver(SharedRootKey, BobKeyPair),
    BobInfo0 = cryptic_double_ratchet:get_state_info(BobState0),
    ?debugFmt("Bob initialized: ~p~n", [BobInfo0]),
    
    % 3.5. Simulate X3DH handshake - both parties should know each other's initial DH keys
    {AliceDHPub, _AliceDHPriv} = AliceKeyPair,
    {BobDHPub, _BobDHPriv} = BobKeyPair,
    AliceState0Updated = cryptic_double_ratchet:set_remote_dh_key(AliceState0, BobDHPub),
    BobState0Updated = cryptic_double_ratchet:set_remote_dh_key(BobState0, AliceDHPub),
    
    % 4. Alice sends first message to Bob (this should work)
    ?debugMsg("\n--- Alice → Bob (First Message) ---"),
    AliceMessage1 = <<"Hello Bob from Alice">>,
    {ok, EncryptedMsg1, AliceState1} = cryptic_double_ratchet:encrypt_message(AliceMessage1, AliceState0Updated),
    
    AliceInfo1 = cryptic_double_ratchet:get_state_info(AliceState1),
    ?debugFmt("Alice after encrypt: ~p~n", [AliceInfo1]),
    ?debugFmt("Message 1: dh_step=~p, msg_number=~p~n", 
              [maps:get(dh_step, EncryptedMsg1), maps:get(msg_number, EncryptedMsg1)]),
    
    % 5. Bob receives Alice's first message (this should work)
        % 5. Bob decrypts Alice's message (this should work)
    {ok, DecryptedMsg1, BobState1} = cryptic_double_ratchet:decrypt_message(EncryptedMsg1, BobState0Updated),
    ?assertEqual(AliceMessage1, DecryptedMsg1),
    
    BobInfo1 = cryptic_double_ratchet:get_state_info(BobState1),
    ?debugFmt("Bob after decrypt: ~p~n", [BobInfo1]),
    
    % 6. Bob replies to Alice (THIS IS WHERE THE BUG OCCURS)
    ?debugMsg("\n--- Bob → Alice (Reply Message) ---"),
    BobMessage1 = <<"Hello Alice from Bob">>,
    
    ?debugMsg("Bob encrypting reply..."),
    {ok, EncryptedReply1, BobState2} = cryptic_double_ratchet:encrypt_message(BobMessage1, BobState1),
    
    BobInfo2 = cryptic_double_ratchet:get_state_info(BobState2),
    ?debugFmt("Bob after encrypt reply: ~p~n", [BobInfo2]),
    ?debugFmt("Reply message: dh_step=~p, msg_number=~p~n",
              [maps:get(dh_step, EncryptedReply1), maps:get(msg_number, EncryptedReply1)]),
    
    % 7. Alice receives Bob's reply (THIS IS WHERE AUTHENTICATION FAILS)
    ?debugMsg("\n--- Alice decrypting Bob's reply ---"),
    AliceInfo1_pre = cryptic_double_ratchet:get_state_info(AliceState1),
    ?debugFmt("Alice before decrypt reply: ~p~n", [AliceInfo1_pre]),
    
    case cryptic_double_ratchet:decrypt_message(EncryptedReply1, AliceState1) of
        {ok, DecryptedReply1, AliceState2} ->
            ?assertEqual(BobMessage1, DecryptedReply1),
            AliceInfo2 = cryptic_double_ratchet:get_state_info(AliceState2),
            ?debugFmt("Alice after decrypt reply: ~p~n", [AliceInfo2]),
            ?debugMsg("SUCCESS: Bidirectional communication working!");
            
        {error, {authentication_failed, MsgNum}} ->
            ?debugFmt("AUTHENTICATION FAILED for message ~p~n", [MsgNum]),
            ?debugMsg("This is the bug we need to fix!"),
            
            % Add detailed debugging info
            ?debugMsg("\n=== DEBUGGING INFO ==="),
            ?debugFmt("Bob's reply dh_step: ~p~n", [maps:get(dh_step, EncryptedReply1)]),
            ?debugFmt("Bob's reply msg_number: ~p~n", [maps:get(msg_number, EncryptedReply1)]),
            ?debugFmt("Alice's current recv_msg_number: ~p~n", [AliceInfo1_pre]),
            ?debugFmt("Alice's current dh_ratchet_step: ~p~n", [maps:get(dh_ratchet_step, AliceInfo1_pre)]),
            
            % This is expected to fail until we fix the protocol issue
            ?assert(false);  % Fail the test to highlight the issue
            
        {error, Other} ->
            ?debugFmt("Unexpected error: ~p~n", [Other]),
            ?assert(false)
    end.

%% @doc Test chain key derivation isolation
chain_key_derivation_test() ->
    ?debugMsg("\n=== CHAIN KEY DERIVATION TEST ==="),
    
    % Test that Alice's send chain matches Bob's recv chain
    SharedRootKey = crypto:strong_rand_bytes(32),
    
    % Alice derives her sending chain from X3DH root key with "init" context
    AliceSendChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"init">>),
    
    % Bob derives his receiving chain to match Alice's sending
    BobRecvChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"init">>),
    
    ?assertEqual(AliceSendChain, BobRecvChain),
    ?debugMsg("✓ Alice send chain == Bob recv chain"),
    
    % Bob derives his sending chain from X3DH root key with "resp" context (our fix)
    BobSendChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"resp">>),
    
    % Alice should derive her receiving chain to match Bob's sending
    AliceRecvChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"resp">>),
    
    ?assertEqual(BobSendChain, AliceRecvChain),
    ?debugMsg("✓ Bob send chain == Alice recv chain (after fix)"),
    
    % Verify chains are different (not using same key for both directions)
    ?assertNotEqual(AliceSendChain, BobSendChain),
    ?debugMsg("✓ Send chains are different (proper key separation)").

%% @doc Test message key derivation isolation  
message_key_derivation_test() ->
    ?debugMsg("\n=== MESSAGE KEY DERIVATION TEST ==="),
    
    SharedRootKey = crypto:strong_rand_bytes(32),
    
    % Derive chain keys using our protocol
    AliceSendChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"init">>),
    BobSendChain = cryptic_double_ratchet:kdf_derive_chain_key(SharedRootKey, <<"resp">>),
    
    % Test that message key derivation is consistent for same chain + msg_number
    {_NewChain1, AliceMsg0Key} = cryptic_double_ratchet:advance_sending_chain(AliceSendChain, 0),
    {_NewChain2, BobMsg0Key} = cryptic_double_ratchet:advance_receiving_chain(AliceSendChain, 0),
    
    ?assertEqual(AliceMsg0Key, BobMsg0Key),
    ?debugMsg("✓ Alice message key == Bob decryption key for same chain"),
    
    % Test Bob's message keys
    {_NewChain3, BobMsg0SendKey} = cryptic_double_ratchet:advance_sending_chain(BobSendChain, 0),
    {_NewChain4, AliceMsg0RecvKey} = cryptic_double_ratchet:advance_receiving_chain(BobSendChain, 0),
    
    ?assertEqual(BobMsg0SendKey, AliceMsg0RecvKey),
    ?debugMsg("✓ Bob message key == Alice decryption key for Bob's chain").