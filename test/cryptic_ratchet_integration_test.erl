%%% @doc Integration tests for Double Ratchet WebSocket integration
%%%
%%% Tests the complete flow of Double Ratchet integration with the WebSocket
%%% handler and chat storage system.

-module(cryptic_ratchet_integration_test).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Integration Tests
%%%===================================================================

%% Test suite setup and teardown
setup() ->
    %% Initialize storage system
    cryptic_chat_storage:init_storage(),
    ok.

cleanup(_) ->
    ok.

%% Test fixture for each test
ratchet_integration_test_() ->
    {setup, fun setup/0, fun cleanup/1, [
        {"Conversation ID generation", fun test_conversation_id/0},
        {"Ratchet state storage and retrieval",
            fun test_ratchet_state_persistence/0},
        {"Complete ratchet message flow", fun test_complete_message_flow/0}
    ]}.

%%%===================================================================
%%% Individual Tests
%%%===================================================================

%% Test conversation ID generation consistency
test_conversation_id() ->
    %% Test that conversation IDs are symmetric
    Id1 = cryptic_ws_handler:create_conversation_id("alice", "bob"),
    Id2 = cryptic_ws_handler:create_conversation_id("bob", "alice"),
    ?assertEqual(Id1, Id2),

    %% Test different users produce different IDs
    Id3 = cryptic_ws_handler:create_conversation_id("alice", "charlie"),
    ?assertNotEqual(Id1, Id3).

%% Test ratchet state storage and retrieval
test_ratchet_state_persistence() ->
    ConversationId = "alice-bob",

    %% Create a test ratchet state
    SharedSecret = crypto:strong_rand_bytes(32),
    {PeerPubKey, _PeerPrivKey} = cryptic_nif:gen_keypair(),
    InitialState = cryptic_double_ratchet:init_sender(SharedSecret, PeerPubKey),

    %% Store the state
    ?assertEqual(
        ok, cryptic_ws_handler:store_ratchet_state(ConversationId, InitialState)
    ),

    %% Retrieve and verify the state
    {ok, RetrievedState} = cryptic_ws_handler:get_ratchet_state(ConversationId),
    ?assertEqual(InitialState, RetrievedState),

    %% Update the state
    UpdatedState = InitialState#{send_msg_number => 1},
    ?assertEqual(
        ok,
        cryptic_ws_handler:update_ratchet_state(ConversationId, UpdatedState)
    ),

    %% Verify the update
    {ok, FinalState} = cryptic_ws_handler:get_ratchet_state(ConversationId),
    ?assertEqual(UpdatedState, FinalState).

%% Test complete Double Ratchet message flow
test_complete_message_flow() ->
    %% Setup: Create ratchet states for Alice and Bob
    SharedSecret = crypto:strong_rand_bytes(32),
    {AliceDhPub, _AliceDhPriv} = cryptic_nif:gen_keypair(),
    {BobDhPub, _BobDhPriv} = cryptic_nif:gen_keypair(),

    %% Initialize ratchet states
    AliceState = cryptic_double_ratchet:init_sender(SharedSecret, BobDhPub),
    BobState = cryptic_double_ratchet:init_receiver(
        SharedSecret, AliceDhPub, 32
    ),

    %% Store ratchet states
    AliceConvId = cryptic_ws_handler:create_conversation_id("alice", "bob"),
    BobConvId = cryptic_ws_handler:create_conversation_id("bob", "alice"),
    % Should be the same
    ?assertEqual(AliceConvId, BobConvId),

    ?assertEqual(
        ok, cryptic_ws_handler:store_ratchet_state(AliceConvId, AliceState)
    ),
    ?assertEqual(
        ok, cryptic_ws_handler:store_ratchet_state(BobConvId, BobState)
    ),

    %% Test message encryption from Alice's side
    Plaintext = <<"Hello Bob! This is a Double Ratchet message.">>,

    %% Alice encrypts message
    {ok, AliceUpdatedState} = cryptic_ws_handler:get_ratchet_state(AliceConvId),
    {ok, RatchetMessage, AliceNewState} = cryptic_double_ratchet:encrypt_message(
        Plaintext, AliceUpdatedState
    ),
    ?assertEqual(
        ok, cryptic_ws_handler:update_ratchet_state(AliceConvId, AliceNewState)
    ),

    %% Bob decrypts message
    {ok, BobUpdatedState} = cryptic_ws_handler:get_ratchet_state(BobConvId),
    {ok, DecryptedPlaintext, BobNewState} = cryptic_double_ratchet:decrypt_message(
        RatchetMessage, BobUpdatedState
    ),
    ?assertEqual(
        ok, cryptic_ws_handler:update_ratchet_state(BobConvId, BobNewState)
    ),

    %% Verify decryption worked correctly
    ?assertEqual(Plaintext, DecryptedPlaintext).

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% Helper to access private functions in cryptic_ws_handler
%% (In real implementation, these would be exported or in a separate module)
%% For now, we assume they're available for testing
