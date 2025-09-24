%%% @doc Unit tests for Double Ratchet implementation
%%%
%%% This test suite validates the Double Ratchet algorithm implementation
%%% including initialization, message encryption/decryption, key derivation,
%%% and state management.

-module(cryptic_double_ratchet_test).

-include_lib("eunit/include/eunit.hrl").
-include("cryptic.hrl").

% Include the ratchet_state record definition for tests
-record(ratchet_state, {
    root_key,
    send_chain_key,
    send_msg_number,
    recv_chain_key,
    recv_msg_number,
    prev_recv_chain_length,
    dh_self,
    dh_remote,
    dh_ratchet_step,
    skipped_keys,
    max_skip,
    max_cache_size,
    max_cache_age,
    sending_chain_active,
    receiving_chain_active,
    created_at,
    last_updated
}).

%%% ============================================================================
%%% Test Suite Setup
%%% ============================================================================

% Test fixtures and helper functions
setup_alice_bob_ratchets() ->
    % Simulate X3DH key agreement - both parties get the same root key
    RootKey = cryptic_nif:rand_bytes(32),

    % Generate DH keypairs for Alice and Bob (for Double Ratchet, not X3DH)
    {AliceDHPub, AliceDHPriv} = cryptic_nif:gen_keypair(),
    {BobDHPub, BobDHPriv} = cryptic_nif:gen_keypair(),

    % Alice initializes as sender with the shared X3DH root key
    AliceState = cryptic_double_ratchet:init_sender(
        RootKey, {AliceDHPub, AliceDHPriv}
    ),

    % Bob initializes as receiver with the same X3DH root key
    % Note: Bob doesn't know Alice's DH key yet - it comes in the first message
    BobState = cryptic_double_ratchet:init_receiver(
        RootKey, {BobDHPub, BobDHPriv}
    ),

    {AliceState, BobState}.

%%% ============================================================================
%%% Initialization Tests
%%% ============================================================================

init_sender_test() ->
    RootKey = cryptic_nif:rand_bytes(32),
    {DHPub, DHPriv} = cryptic_nif:gen_keypair(),

    State = cryptic_double_ratchet:init_sender(RootKey, {DHPub, DHPriv}),

    % Verify initial state
    ?assertEqual(32, byte_size(State#ratchet_state.root_key)),
    ?assertEqual(32, byte_size(State#ratchet_state.send_chain_key)),
    ?assertEqual(0, State#ratchet_state.send_msg_number),
    ?assertEqual(0, State#ratchet_state.recv_msg_number),
    ?assertEqual({DHPub, DHPriv}, State#ratchet_state.dh_self),
    ?assertEqual(undefined, State#ratchet_state.dh_remote),
    ?assertEqual(true, State#ratchet_state.sending_chain_active),
    ?assertEqual(false, State#ratchet_state.receiving_chain_active),
    ?assertEqual(#{}, State#ratchet_state.skipped_keys).

init_receiver_test() ->
    RootKey = cryptic_nif:rand_bytes(32),
    {DHPub, DHPriv} = cryptic_nif:gen_keypair(),

    State = cryptic_double_ratchet:init_receiver(
        RootKey, {DHPub, DHPriv}
    ),

    % Verify initial state - receiver has compatible chain with Alice
    ?assertEqual(RootKey, State#ratchet_state.root_key),
    % Should have derived receiving chain
    ?assertEqual(32, byte_size(State#ratchet_state.recv_chain_key)),
    ?assertEqual(0, State#ratchet_state.send_msg_number),
    ?assertEqual(0, State#ratchet_state.recv_msg_number),
    ?assertEqual({DHPub, DHPriv}, State#ratchet_state.dh_self),
    % Will be set from first message
    ?assertEqual(undefined, State#ratchet_state.dh_remote),
    ?assertEqual(false, State#ratchet_state.sending_chain_active),
    % Active to receive Alice's messages
    ?assertEqual(true, State#ratchet_state.receiving_chain_active),
    ?assertEqual(#{}, State#ratchet_state.skipped_keys),
    % No DH ratchet step yet - will happen on first received message
    ?assertEqual(0, State#ratchet_state.dh_ratchet_step).

init_invalid_params_test() ->
    % Test with invalid root key size
    ?assertError(
        function_clause,
        cryptic_double_ratchet:init_sender(<<"short">>, {<<"a">>, <<"b">>})
    ),

    % Test with invalid DH key sizes
    RootKey = cryptic_nif:rand_bytes(32),
    ?assertError(
        function_clause,
        cryptic_double_ratchet:init_sender(
            RootKey, {<<"short">>, <<"also_short">>}
        )
    ).

%%% ============================================================================
%%% Key Derivation Tests
%%% ============================================================================

key_derivation_test() ->
    RootKey = cryptic_nif:rand_bytes(32),
    DHOutput = cryptic_nif:rand_bytes(32),

    % Test root key derivation
    {NewRootKey, SendChainKey, RecvChainKey} = cryptic_double_ratchet:kdf_rk(
        RootKey, DHOutput
    ),

    % Verify all keys are 32 bytes and different
    ?assertEqual(32, byte_size(NewRootKey)),
    ?assertEqual(32, byte_size(SendChainKey)),
    ?assertEqual(32, byte_size(RecvChainKey)),

    % Keys should be different from each other
    ?assertNotEqual(NewRootKey, SendChainKey),
    ?assertNotEqual(NewRootKey, RecvChainKey),
    ?assertNotEqual(SendChainKey, RecvChainKey),

    % Keys should be different from input
    ?assertNotEqual(RootKey, NewRootKey),
    ?assertNotEqual(DHOutput, NewRootKey).

chain_key_advancement_test() ->
    ChainKey = cryptic_nif:rand_bytes(32),
    MsgNumber = 5,

    % Test sending chain advancement
    {NewSendChain, SendMsgKey} = cryptic_double_ratchet:advance_sending_chain(
        ChainKey, MsgNumber
    ),
    ?assertEqual(32, byte_size(NewSendChain)),
    ?assertEqual(32, byte_size(SendMsgKey)),
    ?assertNotEqual(ChainKey, NewSendChain),
    ?assertNotEqual(ChainKey, SendMsgKey),
    ?assertNotEqual(NewSendChain, SendMsgKey),

    % Test receiving chain advancement
    {NewRecvChain, RecvMsgKey} = cryptic_double_ratchet:advance_receiving_chain(
        ChainKey, MsgNumber
    ),
    ?assertEqual(32, byte_size(NewRecvChain)),
    ?assertEqual(32, byte_size(RecvMsgKey)),
    ?assertNotEqual(ChainKey, NewRecvChain),
    ?assertNotEqual(ChainKey, RecvMsgKey),
    ?assertNotEqual(NewRecvChain, RecvMsgKey),

    % Both functions should produce identical results for same input (they use same KDF contexts)
    ?assertEqual(NewSendChain, NewRecvChain),
    ?assertEqual(SendMsgKey, RecvMsgKey).

message_key_expansion_test() ->
    MessageKey = cryptic_nif:rand_bytes(32),

    {EncKey, AuthKey} = cryptic_double_ratchet:kdf_mk(MessageKey),

    % Verify correct sizes
    ?assertEqual(32, byte_size(EncKey)),
    ?assertEqual(32, byte_size(AuthKey)),

    % Keys should be different
    ?assertNotEqual(EncKey, AuthKey),
    ?assertNotEqual(MessageKey, EncKey),
    ?assertNotEqual(MessageKey, AuthKey).

%%% ============================================================================
%%% Message Processing Tests
%%% ============================================================================

encrypt_decrypt_basic_test() ->
    {AliceState, BobState} = setup_alice_bob_ratchets(),

    % Alice encrypts a message
    Plaintext = <<"Hello Bob, this is Alice!">>,
    {ok, Message, AliceState2} = cryptic_double_ratchet:encrypt_message(
        Plaintext, AliceState
    ),

    % Verify message structure
    ?assert(is_map(Message)),
    ?assert(maps:is_key(dh_public, Message)),
    ?assert(maps:is_key(dh_step, Message)),
    ?assert(maps:is_key(msg_number, Message)),
    ?assert(maps:is_key(ciphertext, Message)),
    ?assert(maps:is_key(nonce, Message)),

    % Verify Alice's state was updated
    ?assertEqual(1, AliceState2#ratchet_state.send_msg_number),
    ?assertNotEqual(
        AliceState#ratchet_state.send_chain_key,
        AliceState2#ratchet_state.send_chain_key
    ),

    % Debug: Check if Alice and Bob have matching chain keys
    io:format("Alice send chain key: ~p~n", [
        AliceState#ratchet_state.send_chain_key
    ]),
    io:format("Bob recv chain key:   ~p~n", [
        BobState#ratchet_state.recv_chain_key
    ]),
    io:format("Keys match: ~p~n", [
        AliceState#ratchet_state.send_chain_key =:=
            BobState#ratchet_state.recv_chain_key
    ]),
    io:format("Message number: ~p~n", [maps:get(msg_number, Message)]),

    % Bob decrypts the message (Phase 2 implementation)
    DecryptResult = cryptic_double_ratchet:decrypt_message(Message, BobState),
    io:format("Decrypt result: ~p~n", [DecryptResult]),

    {ok, DecryptedText, BobState2} = DecryptResult,

    % Verify decryption worked correctly
    ?assertEqual(Plaintext, DecryptedText),
    ?assert(is_record(BobState2, ratchet_state)).

encrypt_multiple_messages_test() ->
    {AliceState, _BobState} = setup_alice_bob_ratchets(),

    Messages = [
        <<"First message">>,
        <<"Second message">>,
        <<"Third message">>
    ],

    % Encrypt multiple messages and verify state progression
    {FinalState, EncryptedMessages} = lists:foldl(
        fun(Plaintext, {State, AccMessages}) ->
            {ok, Message, NewState} = cryptic_double_ratchet:encrypt_message(
                Plaintext, State
            ),
            {NewState, [Message | AccMessages]}
        end,
        {AliceState, []},
        Messages
    ),

    % Verify message numbers are sequential
    MessageNumbers = [
        maps:get(msg_number, M)
     || M <- lists:reverse(EncryptedMessages)
    ],
    ?assertEqual([0, 1, 2], MessageNumbers),

    % Verify final state
    ?assertEqual(3, FinalState#ratchet_state.send_msg_number),
    ?assertNotEqual(
        AliceState#ratchet_state.send_chain_key,
        FinalState#ratchet_state.send_chain_key
    ).

encrypt_inactive_chain_test() ->
    {_AliceState, BobState} = setup_alice_bob_ratchets(),

    % Bob shouldn't be able to encrypt (receiving-only state initially)
    Plaintext = <<"This should fail">>,
    Result = cryptic_double_ratchet:encrypt_message(Plaintext, BobState),

    ?assertEqual({error, sending_chain_not_active}, Result).

%%% ============================================================================
%%% State Serialization Tests
%%% ============================================================================

serialize_deserialize_test() ->
    {AliceState, _} = setup_alice_bob_ratchets(),

    % Serialize the state
    SerializedData = cryptic_double_ratchet:serialize_state(AliceState),
    ?assert(is_binary(SerializedData)),
    ?assert(byte_size(SerializedData) > 0),

    % Deserialize the state
    {ok, DeserializedState} = cryptic_double_ratchet:deserialize_state(
        SerializedData
    ),

    % Verify deserialized state matches original
    ?assertEqual(
        AliceState#ratchet_state.root_key,
        DeserializedState#ratchet_state.root_key
    ),
    ?assertEqual(
        AliceState#ratchet_state.send_chain_key,
        DeserializedState#ratchet_state.send_chain_key
    ),
    ?assertEqual(
        AliceState#ratchet_state.send_msg_number,
        DeserializedState#ratchet_state.send_msg_number
    ),
    ?assertEqual(
        AliceState#ratchet_state.dh_self,
        DeserializedState#ratchet_state.dh_self
    ),
    ?assertEqual(
        AliceState#ratchet_state.dh_remote,
        DeserializedState#ratchet_state.dh_remote
    ),
    ?assertEqual(
        AliceState#ratchet_state.sending_chain_active,
        DeserializedState#ratchet_state.sending_chain_active
    ),
    ?assertEqual(
        AliceState#ratchet_state.receiving_chain_active,
        DeserializedState#ratchet_state.receiving_chain_active
    ).

serialize_invalid_data_test() ->
    % Test deserializing invalid data
    InvalidData = <<"not_a_valid_serialized_state">>,
    Result = cryptic_double_ratchet:deserialize_state(InvalidData),

    ?assertMatch({error, {deserialization_failed, _}}, Result).

%%% ============================================================================
%%% Utility Function Tests
%%% ============================================================================

get_state_info_test() ->
    {AliceState, _} = setup_alice_bob_ratchets(),

    Info = cryptic_double_ratchet:get_state_info(AliceState),

    % Verify info map contains expected keys
    ExpectedKeys = [
        dh_ratchet_step,
        send_msg_number,
        recv_msg_number,
        prev_recv_chain_length,
        skipped_keys_count,
        sending_chain_active,
        receiving_chain_active,
        created_at,
        last_updated,
        has_remote_dh
    ],

    lists:foreach(
        fun(Key) ->
            ?assert(maps:is_key(Key, Info))
        end,
        ExpectedKeys
    ),

    % Verify some specific values
    ?assertEqual(0, maps:get(dh_ratchet_step, Info)),
    ?assertEqual(0, maps:get(send_msg_number, Info)),
    ?assertEqual(true, maps:get(sending_chain_active, Info)),
    ?assertEqual(false, maps:get(receiving_chain_active, Info)),
    ?assertEqual(false, maps:get(has_remote_dh, Info)).

cleanup_expired_keys_test() ->
    {AliceState, _} = setup_alice_bob_ratchets(),

    % Add some mock skipped keys with old timestamps

    % Very old
    OldTime = erlang:system_time(millisecond) - 90000000,
    % Recent
    NewTime = erlang:system_time(millisecond) - 1000,

    MockSkippedKeys = #{
        {0, 1} => #{
            message_key => <<"old_key">>,
            timestamp => OldTime,
            chain_key => <<"old_chain">>,
            dh_public => <<"old_dh">>
        },
        {0, 2} => #{
            message_key => <<"new_key">>,
            timestamp => NewTime,
            chain_key => <<"new_chain">>,
            dh_public => <<"new_dh">>
        }
    },

    StateWithSkippedKeys = AliceState#ratchet_state{
        skipped_keys = MockSkippedKeys
    },

    % Cleanup expired keys
    CleanedState = cryptic_double_ratchet:cleanup_expired_keys(
        StateWithSkippedKeys
    ),

    % Should have removed the old key but kept the new one
    ?assertEqual(1, maps:size(CleanedState#ratchet_state.skipped_keys)),
    ?assert(maps:is_key({0, 2}, CleanedState#ratchet_state.skipped_keys)),
    ?assertNot(maps:is_key({0, 1}, CleanedState#ratchet_state.skipped_keys)).

%%% ============================================================================
%%% Performance and Security Tests
%%% ============================================================================

key_derivation_performance_test() ->
    % Test that key derivation is reasonably fast
    RootKey = cryptic_nif:rand_bytes(32),
    DHOutput = cryptic_nif:rand_bytes(32),

    StartTime = erlang:system_time(microsecond),

    % Perform many key derivations
    lists:foreach(
        fun(_) ->
            cryptic_double_ratchet:kdf_rk(RootKey, DHOutput)
        end,
        lists:seq(1, 1000)
    ),

    EndTime = erlang:system_time(microsecond),
    Duration = EndTime - StartTime,

    % Should complete 1000 operations in under 100ms (100,000 microseconds)
    ?assert(Duration < 100000),

    % Log performance for monitoring
    io:format("~n1000 key derivations completed in ~p microseconds~n", [
        Duration
    ]).

key_uniqueness_test() ->
    % Verify that different inputs produce different keys
    RootKey1 = cryptic_nif:rand_bytes(32),
    RootKey2 = cryptic_nif:rand_bytes(32),
    DHOutput = cryptic_nif:rand_bytes(32),

    {Key1_1, Key1_2, Key1_3} = cryptic_double_ratchet:kdf_rk(
        RootKey1, DHOutput
    ),
    {Key2_1, Key2_2, Key2_3} = cryptic_double_ratchet:kdf_rk(
        RootKey2, DHOutput
    ),

    % Different root keys should produce different derived keys
    ?assertNotEqual(Key1_1, Key2_1),
    ?assertNotEqual(Key1_2, Key2_2),
    ?assertNotEqual(Key1_3, Key2_3).

deterministic_key_derivation_test() ->
    % Verify that same inputs always produce same outputs (deterministic)
    RootKey = cryptic_nif:rand_bytes(32),
    DHOutput = cryptic_nif:rand_bytes(32),

    {Key1_1, Key1_2, Key1_3} = cryptic_double_ratchet:kdf_rk(RootKey, DHOutput),
    {Key2_1, Key2_2, Key2_3} = cryptic_double_ratchet:kdf_rk(RootKey, DHOutput),

    % Same inputs should produce identical outputs
    ?assertEqual(Key1_1, Key2_1),
    ?assertEqual(Key1_2, Key2_2),
    ?assertEqual(Key1_3, Key2_3).

%%% ============================================================================
%%% Integration Tests with Mock X3DH
%%% ============================================================================

full_initialization_flow_test() ->
    % Simulate complete X3DH + Double Ratchet initialization

    % 1. X3DH key agreement (simplified)
    {AliceX3DHPub, AliceX3DHPriv} = cryptic_nif:gen_keypair(),
    {BobX3DHPub, BobX3DHPriv} = cryptic_nif:gen_keypair(),

    % Compute shared secret (simplified - real X3DH is more complex)
    SharedSecret1 = cryptic_nif:scalarmult(AliceX3DHPriv, BobX3DHPub),
    SharedSecret2 = cryptic_nif:scalarmult(BobX3DHPriv, AliceX3DHPub),
    % Verify X3DH worked
    ?assertEqual(SharedSecret1, SharedSecret2),

    % 2. Initialize Double Ratchet states
    {AliceRatchetPub, AliceRatchetPriv} = cryptic_nif:gen_keypair(),
    {BobRatchetPub, BobRatchetPriv} = cryptic_nif:gen_keypair(),

    AliceState = cryptic_double_ratchet:init_sender(
        SharedSecret1, {AliceRatchetPub, AliceRatchetPriv}
    ),
    BobState = cryptic_double_ratchet:init_receiver(
        SharedSecret2, {BobRatchetPub, BobRatchetPriv}
    ),

    % 3. Verify states are properly initialized and complementary
    ?assertEqual(true, AliceState#ratchet_state.sending_chain_active),
    ?assertEqual(false, AliceState#ratchet_state.receiving_chain_active),
    ?assertEqual(false, BobState#ratchet_state.sending_chain_active),
    % Active to receive Alice's messages
    ?assertEqual(true, BobState#ratchet_state.receiving_chain_active),

    ?assertEqual(undefined, AliceState#ratchet_state.dh_remote),
    % Will be set from first message
    ?assertEqual(undefined, BobState#ratchet_state.dh_remote),

    % 4. Test that Alice can encrypt
    {ok, _Message, _NewAliceState} = cryptic_double_ratchet:encrypt_message(
        <<"Test">>, AliceState
    ),

    % 5. Test that Bob initially cannot encrypt (receiving only)
    ?assertEqual(
        {error, sending_chain_not_active},
        cryptic_double_ratchet:encrypt_message(<<"Test">>, BobState)
    ).

%%% ============================================================================
%%% Error Handling Tests
%%% ============================================================================

encrypt_message_error_handling_test() ->
    % Test error handling in encrypt_message
    {AliceState, _} = setup_alice_bob_ratchets(),

    % Test with inactive sending chain
    InactiveState = AliceState#ratchet_state{sending_chain_active = false},
    Result = cryptic_double_ratchet:encrypt_message(<<"test">>, InactiveState),

    % Should return error for inactive chain
    ?assertEqual({error, sending_chain_not_active}, Result).

decrypt_message_error_handling_test() ->
    % Test error handling in decrypt_message
    {_, BobState} = setup_alice_bob_ratchets(),

    % Create invalid message
    InvalidMessage = #{
        dh_public => <<"invalid">>,
        dh_step => 0,
        msg_number => 0,
        ciphertext => <<"invalid">>,
        nonce => <<"invalid">>
    },

    Result = cryptic_double_ratchet:decrypt_message(InvalidMessage, BobState),

    % Should handle errors gracefully
    ?assert(is_tuple(Result)).

%%% ============================================================================
%%% Test Runner
%%% ============================================================================

% Run all tests
all_test() ->
    io:format("~n=== Running Double Ratchet Phase 1 Tests ===~n"),

    % Basic functionality tests
    init_sender_test(),
    init_receiver_test(),
    init_invalid_params_test(),

    % Key derivation tests
    key_derivation_test(),
    chain_key_advancement_test(),
    message_key_expansion_test(),

    % Message processing tests (Phase 1 implementations)
    encrypt_decrypt_basic_test(),
    encrypt_multiple_messages_test(),
    encrypt_inactive_chain_test(),

    % State management tests
    serialize_deserialize_test(),
    serialize_invalid_data_test(),

    % Utility tests
    get_state_info_test(),
    cleanup_expired_keys_test(),

    % Performance and security tests
    key_derivation_performance_test(),
    key_uniqueness_test(),
    deterministic_key_derivation_test(),

    % Integration tests
    full_initialization_flow_test(),

    % Error handling tests
    encrypt_message_error_handling_test(),
    decrypt_message_error_handling_test(),

    io:format("~n=== All Double Ratchet Phase 1 Tests Completed ===~n"),
    ok.
