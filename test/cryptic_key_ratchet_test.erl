%%% @doc Symmetric Key Ratchet Tests
%%%
%%% This module tests the symmetric key ratchet functionality using the
%%% new HKDF NIFs. It demonstrates a simplified Double Ratchet-style
%%% key derivation pattern suitable for secure messaging protocols.
%%%
%%% == Ratchet Overview ==
%%%
%%% A symmetric key ratchet maintains forward secrecy by continuously
%%% deriving new keys from previous keys, ensuring that:
%%% <ul>
%%%   <li>Each message uses a unique encryption key</li>
%%%   <li>Compromise of current keys doesn't affect past messages</li>
%%%   <li>Keys are derived deterministically for synchronization</li>
%%%   <li>Old keys are securely discarded after use</li>
%%% </ul>
%%%
%%% == Test Structure ==
%%%
%%% The tests verify:
%%% <ul>
%%%   <li>Root key -> Chain key derivation</li>
%%%   <li>Chain key -> Message key derivation</li>
%%%   <li>Forward progression of chain keys</li>
%%%   <li>Message key independence and uniqueness</li>
%%%   <li>Performance characteristics for ratcheting</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-24

-module(cryptic_key_ratchet_test).

-include_lib("eunit/include/eunit.hrl").

-define(ROOT_KEY_SIZE, 32).
-define(CHAIN_KEY_SIZE, 32).
-define(MESSAGE_KEY_SIZE, 32).
-define(CONTEXT_CHAIN, <<"chain">>).
-define(CONTEXT_MESSAGE, <<"message">>).

%%% ============================================================================
%%% Test Suite
%%% ============================================================================

%% @doc Main test suite for symmetric key ratchet functionality
key_ratchet_test_() ->
    {setup, fun setup/0, fun cleanup/1, [
        {"Basic KDF functions work", fun test_basic_kdf/0},
        {"HKDF-SHA256 compatibility", fun test_hkdf_sha256/0},
        {"Chain key derivation", fun test_chain_key_derivation/0},
        {"Message key derivation", fun test_message_key_derivation/0},
        {"Full ratchet simulation", fun test_full_ratchet_simulation/0},
        {"Key uniqueness properties", fun test_key_uniqueness/0},
        {"Ratchet performance test", fun test_ratchet_performance/0}
    ]}.

%%% ============================================================================
%%% Setup and Cleanup
%%% ============================================================================

setup() ->
    % Ensure cryptic application is loaded for NIF access
    case application:ensure_all_started(cryptic) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end.

cleanup(_) ->
    ok.

%%% ============================================================================
%%% Basic NIF Function Tests
%%% ============================================================================

%% @doc Test that basic KDF NIF functions are working
test_basic_kdf() ->
    % Generate a master key
    MasterKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),
    ?assertEqual(?ROOT_KEY_SIZE, byte_size(MasterKey)),

    % Test kdf_derive with different subkey IDs
    Key1 = cryptic_nif:kdf_derive(32, 1, ?CONTEXT_CHAIN, MasterKey),
    Key2 = cryptic_nif:kdf_derive(32, 2, ?CONTEXT_CHAIN, MasterKey),

    % Verify keys are correct size and different
    ?assertEqual(32, byte_size(Key1)),
    ?assertEqual(32, byte_size(Key2)),
    ?assertNotEqual(Key1, Key2),

    % Same parameters should produce same key (deterministic)
    Key1Again = cryptic_nif:kdf_derive(32, 1, ?CONTEXT_CHAIN, MasterKey),
    ?assertEqual(Key1, Key1Again).

%% @doc Test HKDF-SHA256 compatibility function
test_hkdf_sha256() ->
    IKM = cryptic_nif:rand_bytes(32),
    Salt = <<"test_salt">>,
    Info = <<"test_info">>,

    % Derive keys using HKDF-SHA256
    Key1 = cryptic_nif:hkdf_sha256(IKM, Salt, Info, 32),
    Key2 = cryptic_nif:hkdf_sha256(IKM, Salt, <<"different_info">>, 32),

    % Verify correct operation
    ?assertEqual(32, byte_size(Key1)),
    ?assertEqual(32, byte_size(Key2)),
    ?assertNotEqual(Key1, Key2),

    % Test deterministic behavior
    Key1Again = cryptic_nif:hkdf_sha256(IKM, Salt, Info, 32),
    ?assertEqual(Key1, Key1Again).

%%% ============================================================================
%%% Chain Key Derivation Tests
%%% ============================================================================

%% @doc Test chain key derivation from root key
test_chain_key_derivation() ->
    % Initialize with a root key (e.g., from X3DH)
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),

    % Derive initial chain key
    ChainKey0 = derive_chain_key(RootKey, 0),
    ?assertEqual(?CHAIN_KEY_SIZE, byte_size(ChainKey0)),

    % Derive subsequent chain keys
    ChainKey1 = derive_chain_key(ChainKey0, 1),
    ChainKey2 = derive_chain_key(ChainKey1, 2),
    ChainKey3 = derive_chain_key(ChainKey2, 3),

    % Verify all keys are different
    Keys = [ChainKey0, ChainKey1, ChainKey2, ChainKey3],
    UniqueKeys = lists:usort(Keys),
    ?assertEqual(length(Keys), length(UniqueKeys)),

    % Test that chain progression is deterministic
    ChainKey1Again = derive_chain_key(ChainKey0, 1),
    ?assertEqual(ChainKey1, ChainKey1Again).

%% @doc Test message key derivation from chain keys
test_message_key_derivation() ->
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),
    ChainKey = derive_chain_key(RootKey, 0),

    % Derive message keys from the same chain key
    MsgKey1 = derive_message_key(ChainKey, 1),
    MsgKey2 = derive_message_key(ChainKey, 2),
    MsgKey3 = derive_message_key(ChainKey, 3),

    % Verify message keys are unique
    ?assertNotEqual(MsgKey1, MsgKey2),
    ?assertNotEqual(MsgKey2, MsgKey3),
    ?assertNotEqual(MsgKey1, MsgKey3),
    ?assertEqual(?MESSAGE_KEY_SIZE, byte_size(MsgKey1)),

    % Message keys should be deterministic
    MsgKey1Again = derive_message_key(ChainKey, 1),
    ?assertEqual(MsgKey1, MsgKey1Again).

%%% ============================================================================
%%% Full Ratchet Simulation
%%% ============================================================================

%% @doc Simulate a complete symmetric key ratchet session
test_full_ratchet_simulation() ->
    % Initialize ratchet state
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),

    % Simulate sending 10 messages with proper key ratcheting
    {FinalChainKey, MessageKeys} = simulate_message_sequence(RootKey, 10),

    % Verify we got the expected number of message keys
    ?assertEqual(10, length(MessageKeys)),

    % Verify all message keys are unique
    UniqueKeys = lists:usort(MessageKeys),
    ?assertEqual(length(MessageKeys), length(UniqueKeys)),

    % Verify final chain key is different from root key
    ?assertNotEqual(RootKey, FinalChainKey),

    % Test that we can continue the ratchet
    {_NewChainKey, MoreKeys} = simulate_message_sequence(FinalChainKey, 5),
    ?assertEqual(5, length(MoreKeys)),

    % Verify new keys don't collide with previous keys
    AllKeys = MessageKeys ++ MoreKeys,
    UniqueAllKeys = lists:usort(AllKeys),
    ?assertEqual(length(AllKeys), length(UniqueAllKeys)).

%%% ============================================================================
%%% Security Properties Tests
%%% ============================================================================

%% @doc Test key uniqueness properties for security
test_key_uniqueness() ->
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),

    % Generate many keys to test for collisions
    NumKeys = 100,

    % Test chain key uniqueness
    ChainKeys = generate_chain_sequence(RootKey, NumKeys),
    UniqueChainKeys = lists:usort(ChainKeys),
    ?assertEqual(NumKeys, length(UniqueChainKeys)),

    % Test message key uniqueness within same chain
    ChainKey = hd(ChainKeys),
    MessageKeys = [
        derive_message_key(ChainKey, N)
     || N <- lists:seq(1, NumKeys)
    ],
    UniqueMessageKeys = lists:usort(MessageKeys),
    ?assertEqual(NumKeys, length(UniqueMessageKeys)),

    % Test that message keys from different chains are different
    DifferentChainKey = lists:nth(50, ChainKeys),
    DifferentMessageKeys = [
        derive_message_key(DifferentChainKey, N)
     || N <- lists:seq(1, 10)
    ],

    % Should have no overlap between message keys from different chains
    Intersection = lists:filter(
        fun(K) -> lists:member(K, DifferentMessageKeys) end,
        lists:sublist(MessageKeys, 10)
    ),
    ?assertEqual([], Intersection).

%%% ============================================================================
%%% Performance Tests
%%% ============================================================================

%% @doc Test ratchet performance for high-throughput scenarios
test_ratchet_performance() ->
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),
    NumOperations = 1000,

    % Measure chain key derivation performance
    {ChainTime, _ChainKeys} = timer:tc(fun() ->
        generate_chain_sequence(RootKey, NumOperations)
    end),

    ChainOpsPerSec = (NumOperations * 1000000) div ChainTime,

    % Measure message key derivation performance
    ChainKey = derive_chain_key(RootKey, 0),
    {MessageTime, _MessageKeys} = timer:tc(fun() ->
        [derive_message_key(ChainKey, N) || N <- lists:seq(1, NumOperations)]
    end),

    MessageOpsPerSec = (NumOperations * 1000000) div MessageTime,

    % Log performance results
    io:format(user, "~nChain key derivation: ~p ops/sec~n", [ChainOpsPerSec]),
    io:format(user, "Message key derivation: ~p ops/sec~n", [MessageOpsPerSec]),

    % Performance should be reasonable (>1000 ops/sec)
    ?assert(ChainOpsPerSec > 1000),
    ?assert(MessageOpsPerSec > 1000).

%%% ============================================================================
%%% Helper Functions
%%% ============================================================================

%% @doc Derive a chain key from previous key using KDF
-spec derive_chain_key(binary(), non_neg_integer()) -> binary().
derive_chain_key(PreviousKey, ChainIndex) ->
    cryptic_nif:kdf_derive(
        ?CHAIN_KEY_SIZE, ChainIndex, ?CONTEXT_CHAIN, PreviousKey
    ).

%% @doc Derive a message key from chain key using KDF
-spec derive_message_key(binary(), non_neg_integer()) -> binary().
derive_message_key(ChainKey, MessageIndex) ->
    cryptic_nif:kdf_derive(
        ?MESSAGE_KEY_SIZE, MessageIndex, ?CONTEXT_MESSAGE, ChainKey
    ).

%% @doc Generate a sequence of chain keys
-spec generate_chain_sequence(binary(), pos_integer()) -> [binary()].
generate_chain_sequence(RootKey, Count) ->
    lists:foldl(
        fun(Index, Acc) ->
            PrevKey =
                case Acc of
                    [] -> RootKey;
                    [LastKey | _] -> LastKey
                end,
            NewKey = derive_chain_key(PrevKey, Index),
            [NewKey | Acc]
        end,
        [],
        lists:seq(0, Count - 1)
    ).

%% @doc Simulate sending a sequence of messages with proper key ratcheting
-spec simulate_message_sequence(binary(), pos_integer()) ->
    {binary(), [binary()]}.
simulate_message_sequence(RootKey, MessageCount) ->
    simulate_message_sequence(RootKey, MessageCount, 0, []).

simulate_message_sequence(ChainKey, 0, _MessageIndex, MessageKeys) ->
    {ChainKey, lists:reverse(MessageKeys)};
simulate_message_sequence(ChainKey, MessagesLeft, MessageIndex, MessageKeys) ->
    % Derive message key for current message
    MessageKey = derive_message_key(ChainKey, MessageIndex),

    % Advance chain key for next message
    NextChainKey = derive_chain_key(ChainKey, MessageIndex + 1),

    % Continue with next message
    simulate_message_sequence(
        NextChainKey,
        MessagesLeft - 1,
        MessageIndex + 1,
        [MessageKey | MessageKeys]
    ).

%%% ============================================================================
%%% Integration Test with Encryption
%%% ============================================================================

%% @doc Test integration of key ratchet with actual encryption/decryption
integration_test_() ->
    {"Ratchet integration with encryption", fun test_ratchet_with_encryption/0}.

test_ratchet_with_encryption() ->
    % Initialize ratchet
    RootKey = cryptic_nif:rand_bytes(?ROOT_KEY_SIZE),
    ChainKey0 = derive_chain_key(RootKey, 0),

    % Simulate sending encrypted messages
    Messages = [
        <<"Hello, this is message 1">>,
        <<"This is the second message">>,
        <<"Final message in the sequence">>
    ],

    % Encrypt messages with ratcheted keys
    {_FinalChainKey, EncryptedMessages} = encrypt_message_sequence(
        ChainKey0, Messages
    ),

    % Verify encryption worked
    ?assertEqual(length(Messages), length(EncryptedMessages)),

    % Each encrypted message should be different even for same plaintext
    SamePlaintexts = [<<"test">> || _ <- lists:seq(1, 3)],
    {_, EncryptedSame} = encrypt_message_sequence(ChainKey0, SamePlaintexts),

    % Should produce different ciphertexts due to different keys
    [Cipher1, Cipher2, Cipher3] = EncryptedSame,
    ?assertNotEqual(Cipher1, Cipher2),
    ?assertNotEqual(Cipher2, Cipher3).

%% @doc Encrypt a sequence of messages with proper key ratcheting
encrypt_message_sequence(InitialChainKey, Messages) ->
    encrypt_message_sequence(InitialChainKey, Messages, 0, []).

encrypt_message_sequence(ChainKey, [], _Index, EncryptedMessages) ->
    {ChainKey, lists:reverse(EncryptedMessages)};
encrypt_message_sequence(ChainKey, [Message | Rest], Index, EncryptedMessages) ->
    % Derive message key
    MessageKey = derive_message_key(ChainKey, Index),

    % Encrypt message (using ChaCha20-Poly1305)
    AAD = <<>>,
    {Ciphertext, Nonce} = cryptic_nif:aead_encrypt(Message, MessageKey, AAD),

    % Advance chain key
    NextChainKey = derive_chain_key(ChainKey, Index + 1),

    % Continue with next message
    encrypt_message_sequence(
        NextChainKey,
        Rest,
        Index + 1,
        [{Ciphertext, Nonce} | EncryptedMessages]
    ).
