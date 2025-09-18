%%% @doc EUnit tests for Step 1 Architecture Sketch implementation
%%%
%%% This module tests the complete Step 1 secure messaging implementation
%%% including message integrity, replay protection, and key management.
%%%
%%% == Test Coverage ==
%%% <ul>
%%%   <li>Ed25519 digital signatures (sign/verify)</li>
%%%   <li>X25519 ECDH key agreement</li>
%%%   <li>Secure message encryption/decryption with metadata</li>
%%%   <li>Sequence number management for replay protection</li>
%%%   <li>Key bundle storage and retrieval</li>
%%%   <li>OTPK consumption tracking</li>
%%%   <li>Error handling and edge cases</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-18
-module(cryptic_step1_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

setup() ->
    %% Initialize cryptic_lib for testing
    ok = cryptic_lib:initialize(),
    %% Generate test keys for consistent testing
    {SenderPub, SenderPriv} = cryptic_lib:gen_keypair(),
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),

    %% Generate Ed25519 keys for signing
    SenderSeed = crypto:strong_rand_bytes(32),
    {SenderSignPub, SenderSignPriv} = crypto:generate_key(
        eddsa, ed25519, SenderSeed
    ),

    #{
        sender_pub => SenderPub,
        sender_priv => SenderPriv,
        recipient_pub => RecipientPub,
        recipient_priv => RecipientPriv,
        sender_sign_pub => SenderSignPub,
        sender_sign_priv => SenderSignPriv
    }.

cleanup(_State) ->
    %% No cleanup needed for in-memory tests
    ok.

%%%===================================================================
%%% Test Generators
%%%===================================================================

%% Main test generator
cryptic_step1_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(State) ->
        [
            %% Basic cryptographic primitives
            test_ed25519_signing(State),
            test_x25519_ecdh(State),
            test_aead_encryption(State),

            %% Secure messaging with metadata
            test_secure_message_flow(State),
            test_metadata_validation(State),
            test_signature_verification(State),

            %% Sequence number management
            test_sequence_number_management(State),
            test_replay_protection(State),

            %% Key bundle management
            test_key_bundle_storage(State),
            test_otpk_consumption(State),

            %% Error conditions
            test_invalid_signatures(State),
            test_corrupted_messages(State),
            test_key_mismatch_errors(State)
        ]
    end}.

%%%===================================================================
%%% Basic Cryptographic Primitive Tests
%%%===================================================================

test_ed25519_signing(#{sender_sign_pub := PubKey, sender_sign_priv := PrivKey}) ->
    {"Ed25519 signing and verification", fun() ->
        Message = <<"Hello, cryptographic world!">>,

        %% Test signing
        Signature = cryptic_lib:sign_message(Message, PrivKey),
        ?assertEqual(64, byte_size(Signature)),

        %% Test valid signature verification
        ?assert(cryptic_lib:verify_signature(Message, Signature, PubKey)),

        %% Test invalid signature (wrong message)
        WrongMessage = <<"Different message">>,
        ?assertNot(
            cryptic_lib:verify_signature(WrongMessage, Signature, PubKey)
        ),

        %% Test invalid signature (corrupted signature)
        <<FirstByte, Rest/binary>> = Signature,
        CorruptedSignature = <<(FirstByte bxor 1), Rest/binary>>,
        ?assertNot(
            cryptic_lib:verify_signature(Message, CorruptedSignature, PubKey)
        ),

        %% Test invalid signature (wrong public key)
        WrongSeed = crypto:strong_rand_bytes(32),
        {WrongPubKey, _} = crypto:generate_key(eddsa, ed25519, WrongSeed),
        ?assertNot(
            cryptic_lib:verify_signature(Message, Signature, WrongPubKey)
        )
    end}.

test_x25519_ecdh(#{
    sender_pub := SenderPub,
    sender_priv := SenderPriv,
    recipient_pub := RecipientPub,
    recipient_priv := RecipientPriv
}) ->
    {"X25519 ECDH key agreement", fun() ->
        %% Test ECDH property: Alice × Bob_pub = Bob × Alice_pub
        SharedAlice = cryptic_lib:scalarmult(SenderPriv, RecipientPub),
        SharedBob = cryptic_lib:scalarmult(RecipientPriv, SenderPub),

        ?assertEqual(SharedAlice, SharedBob),
        ?assertEqual(32, byte_size(SharedAlice)),

        %% Test determinism - same inputs produce same output
        SharedAlice2 = cryptic_lib:scalarmult(SenderPriv, RecipientPub),
        ?assertEqual(SharedAlice, SharedAlice2)
    end}.

test_aead_encryption(_State) ->
    {"ChaCha20-Poly1305 AEAD encryption/decryption", fun() ->
        Message = <<"Secret message">>,
        Key = cryptic_lib:rand_bytes(32),
        AAD = <<"additional authenticated data">>,

        %% Test encryption
        {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(Message, Key, AAD),
        % Includes auth tag
        ?assert(byte_size(Ciphertext) > byte_size(Message)),
        % ChaCha20-Poly1305-IETF nonce
        ?assertEqual(12, byte_size(Nonce)),

        %% Test successful decryption
        Decrypted = cryptic_lib:aead_decrypt(Ciphertext, Key, Nonce, AAD),
        ?assertEqual(Message, Decrypted),

        %% Test decryption with wrong key
        WrongKey = cryptic_lib:rand_bytes(32),
        ?assertEqual(
            error, cryptic_lib:aead_decrypt(Ciphertext, WrongKey, Nonce, AAD)
        ),

        %% Test decryption with wrong AAD
        WrongAAD = <<"wrong aad">>,
        ?assertEqual(
            error, cryptic_lib:aead_decrypt(Ciphertext, Key, Nonce, WrongAAD)
        )
    end}.

%%%===================================================================
%%% Secure Messaging Tests
%%%===================================================================

test_secure_message_flow(#{
    recipient_pub := RecipientPub,
    recipient_priv := RecipientPriv,
    sender_sign_pub := SenderSignPub,
    sender_sign_priv := SenderSignPriv
}) ->
    {"Complete secure message encryption/decryption flow", fun() ->
        Message = <<"This is a secure test message">>,
        Metadata = #{
            sender_id => <<"alice">>,
            recipient_id => <<"bob">>,
            sender_key_id => crypto:strong_rand_bytes(16),
            timestamp => erlang:system_time(second),
            sequence => 1,
            sender_sign_key => SenderSignPriv
        },

        %% Test encryption
        {ok, {EphPub, Nonce, Ciphertext}} =
            cryptic_lib:encrypt_message_secure(Message, Metadata, RecipientPub),

        ?assertEqual(32, byte_size(EphPub)),
        ?assertEqual(12, byte_size(Nonce)),
        ?assert(byte_size(Ciphertext) > 0),

        %% Test decryption
        {ok, {DecryptedMessage, ReceivedMetadata}} =
            cryptic_lib:decrypt_message_secure(
                {EphPub, Nonce, Ciphertext}, RecipientPriv, SenderSignPub
            ),

        %% Verify message content
        ?assertEqual(Message, DecryptedMessage),

        %% Verify metadata
        ?assertEqual(<<"alice">>, maps:get(sender_id, ReceivedMetadata)),
        ?assertEqual(<<"bob">>, maps:get(recipient_id, ReceivedMetadata)),
        ?assertEqual(1, maps:get(sequence, ReceivedMetadata)),
        ?assert(maps:is_key(timestamp, ReceivedMetadata)),
        ?assert(maps:is_key(sender_key_id, ReceivedMetadata))
    end}.

test_metadata_validation(#{
    recipient_pub := RecipientPub,
    recipient_priv := RecipientPriv,
    sender_sign_pub := SenderSignPub,
    sender_sign_priv := SenderSignPriv
}) ->
    {"Metadata inclusion and validation", fun() ->
        Message = <<"Test message with metadata">>,
        KeyId = crypto:strong_rand_bytes(16),
        Timestamp = erlang:system_time(second),

        Metadata = #{
            sender_id => <<"test_sender">>,
            recipient_id => <<"test_recipient">>,
            sender_key_id => KeyId,
            timestamp => Timestamp,
            sequence => 42,
            sender_sign_key => SenderSignPriv
        },

        %% Encrypt and decrypt
        {ok, EncryptedBlob} =
            cryptic_lib:encrypt_message_secure(Message, Metadata, RecipientPub),
        {ok, {_DecryptedMessage, ReceivedMetadata}} =
            cryptic_lib:decrypt_message_secure(
                EncryptedBlob, RecipientPriv, SenderSignPub
            ),

        %% Verify all metadata fields are preserved
        ?assertEqual(<<"test_sender">>, maps:get(sender_id, ReceivedMetadata)),
        ?assertEqual(
            <<"test_recipient">>, maps:get(recipient_id, ReceivedMetadata)
        ),
        ?assertEqual(KeyId, maps:get(sender_key_id, ReceivedMetadata)),
        ?assertEqual(Timestamp, maps:get(timestamp, ReceivedMetadata)),
        ?assertEqual(42, maps:get(sequence, ReceivedMetadata))
    end}.

test_signature_verification(#{
    recipient_pub := RecipientPub,
    recipient_priv := RecipientPriv,
    sender_sign_pub := SenderSignPub,
    sender_sign_priv := SenderSignPriv
}) ->
    {"Message signature verification in secure messaging", fun() ->
        Message = <<"Signed message test">>,
        Metadata = #{
            sender_id => <<"alice">>,
            recipient_id => <<"bob">>,
            sender_key_id => crypto:strong_rand_bytes(16),
            timestamp => erlang:system_time(second),
            sequence => 1,
            sender_sign_key => SenderSignPriv
        },

        %% Encrypt with correct signing key
        {ok, EncryptedBlob} =
            cryptic_lib:encrypt_message_secure(Message, Metadata, RecipientPub),

        %% Decrypt with correct verification key should succeed
        {ok, {DecryptedMessage, _}} =
            cryptic_lib:decrypt_message_secure(
                EncryptedBlob, RecipientPriv, SenderSignPub
            ),
        ?assertEqual(Message, DecryptedMessage),

        %% Decrypt with wrong verification key should fail
        WrongSeed = crypto:strong_rand_bytes(32),
        {WrongSignPub, _} = crypto:generate_key(eddsa, ed25519, WrongSeed),
        ?assertEqual(
            {error, signature_verification_failed},
            cryptic_lib:decrypt_message_secure(
                EncryptedBlob, RecipientPriv, WrongSignPub
            )
        )
    end}.

%%%===================================================================
%%% Sequence Number Management Tests
%%%===================================================================

test_sequence_number_management(_State) ->
    {"Sequence number generation and management", fun() ->
        SenderID = <<"alice">>,
        RecipientID = <<"bob">>,

        %% Test first sequence number
        Seq1 = cryptic_lib:get_next_sequence(SenderID, RecipientID),
        ?assertEqual(1, Seq1),

        %% Test incrementing sequence numbers
        Seq2 = cryptic_lib:get_next_sequence(SenderID, RecipientID),
        ?assertEqual(2, Seq2),

        Seq3 = cryptic_lib:get_next_sequence(SenderID, RecipientID),
        ?assertEqual(3, Seq3),

        %% Test different communication pair has independent sequence
        DifferentRecipient = <<"charlie">>,
        DiffSeq1 = cryptic_lib:get_next_sequence(SenderID, DifferentRecipient),
        ?assertEqual(1, DiffSeq1),

        %% Original pair should still continue from where it left off
        Seq4 = cryptic_lib:get_next_sequence(SenderID, RecipientID),
        ?assertEqual(4, Seq4)
    end}.

test_replay_protection(_State) ->
    {"Sequence number validation for replay protection", fun() ->
        SenderID = <<"eve">>,
        RecipientID = <<"mallory">>,

        %% First message should be valid
        ?assert(cryptic_lib:validate_sequence(SenderID, RecipientID, 1)),
        cryptic_lib:update_sequence(SenderID, RecipientID, 1),

        %% Higher sequence numbers should be valid
        ?assert(cryptic_lib:validate_sequence(SenderID, RecipientID, 2)),
        ?assert(cryptic_lib:validate_sequence(SenderID, RecipientID, 3)),

        %% Update to sequence 5
        cryptic_lib:update_sequence(SenderID, RecipientID, 5),

        %% Replay of old sequence should be rejected (too far back)
        ?assertNot(cryptic_lib:validate_sequence(SenderID, RecipientID, 1)),

        %% Recent out-of-order should be allowed
        ?assert(cryptic_lib:validate_sequence(SenderID, RecipientID, 4)),

        %% Very old messages should be rejected (outside window)
        cryptic_lib:update_sequence(SenderID, RecipientID, 200),
        ?assertNot(cryptic_lib:validate_sequence(SenderID, RecipientID, 50))
    end}.

%%%===================================================================
%%% Key Bundle Management Tests
%%%===================================================================

test_key_bundle_storage(_State) ->
    {"Key bundle storage and retrieval", fun() ->
        Username = "test_user",
        KeyBundle = cryptic_lib:generate_client_keys(),

        %% Store key bundle
        ok = cryptic_lib:store_key_bundle(Username, KeyBundle),

        %% Retrieve key bundle
        {ok, StoredBundle} = cryptic_lib:get_key_bundle(Username),

        %% Verify bundle structure
        ?assert(maps:is_key(username, StoredBundle)),
        ?assert(maps:is_key(key_id, StoredBundle)),
        ?assert(maps:is_key(identity_sign_public, StoredBundle)),
        ?assert(maps:is_key(signed_prekey, StoredBundle)),
        ?assert(maps:is_key(one_time_prekeys, StoredBundle)),
        ?assert(maps:is_key(created_at, StoredBundle)),

        %% Verify username is stored correctly
        ?assertEqual(Username, maps:get(username, StoredBundle)),

        %% Verify signed prekey structure
        SignedPrekey = maps:get(signed_prekey, StoredBundle),
        ?assert(maps:is_key(public, SignedPrekey)),
        ?assert(maps:is_key(signature, SignedPrekey)),
        ?assert(maps:is_key(timestamp, SignedPrekey)),

        %% Test signed prekey retrieval
        {ok, {PrekeyPub, Signature, IdentityPub}} =
            cryptic_lib:get_signed_prekey_with_signature(Username),
        ?assertEqual(maps:get(public, SignedPrekey), PrekeyPub),
        ?assertEqual(maps:get(signature, SignedPrekey), Signature),
        ?assertEqual(maps:get(identity_sign_public, StoredBundle), IdentityPub)
    end}.

test_otpk_consumption(_State) ->
    {"One-Time Prekey consumption tracking", fun() ->
        Username = "otpk_test_user",
        KeyBundle = cryptic_lib:generate_client_keys(),
        OneTimePrekeys = maps:get(one_time_prekeys, KeyBundle),

        %% Store key bundle
        ok = cryptic_lib:store_key_bundle(Username, KeyBundle),

        %% Get initial OTPK count
        {ok, InitialBundle} = cryptic_lib:get_key_bundle(Username),
        InitialOtpks = maps:get(one_time_prekeys, InitialBundle),
        InitialCount = length(InitialOtpks),
        % Default generation count
        ?assertEqual(10, InitialCount),

        %% Consume one OTPK
        [FirstOtpk | _] = OneTimePrekeys,
        FirstOtpkId = maps:get(id, FirstOtpk),
        ok = cryptic_lib:mark_otpk_consumed(Username, FirstOtpkId),

        %% Verify OTPK was removed
        {ok, UpdatedBundle} = cryptic_lib:get_key_bundle(Username),
        UpdatedOtpks = maps:get(one_time_prekeys, UpdatedBundle),
        UpdatedCount = length(UpdatedOtpks),
        ?assertEqual(InitialCount - 1, UpdatedCount),

        %% Verify the specific OTPK was removed
        RemainingIds = [maps:get(id, Otpk) || Otpk <- UpdatedOtpks],
        ?assertNot(lists:member(FirstOtpkId, RemainingIds)),

        %% Test consuming non-existent OTPK
        FakeId = crypto:strong_rand_bytes(8),
        % Should not crash
        ok = cryptic_lib:mark_otpk_consumed(Username, FakeId),

        %% Verify count didn't change
        {ok, FinalBundle} = cryptic_lib:get_key_bundle(Username),
        FinalOtpks = maps:get(one_time_prekeys, FinalBundle),
        ?assertEqual(UpdatedCount, length(FinalOtpks))
    end}.

%%%===================================================================
%%% Error Condition Tests
%%%===================================================================

test_invalid_signatures(#{
    recipient_pub := RecipientPub, recipient_priv := RecipientPriv
}) ->
    {"Handling of invalid signatures", fun() ->
        %% Generate wrong signing keys
        WrongSeed = crypto:strong_rand_bytes(32),
        {_WrongSignPub, WrongSignPriv} = crypto:generate_key(
            eddsa, ed25519, WrongSeed
        ),

        Message = <<"Message with wrong signature">>,
        Metadata = #{
            sender_id => <<"alice">>,
            recipient_id => <<"bob">>,
            sender_key_id => crypto:strong_rand_bytes(16),
            timestamp => erlang:system_time(second),
            sequence => 1,
            % Wrong signing key!
            sender_sign_key => WrongSignPriv
        },

        %% Encrypt message (should succeed)
        {ok, EncryptedBlob} =
            cryptic_lib:encrypt_message_secure(Message, Metadata, RecipientPub),

        %% Decrypt with different verification key (should fail)
        CorrectSeed = crypto:strong_rand_bytes(32),
        {CorrectSignPub, _} = crypto:generate_key(eddsa, ed25519, CorrectSeed),

        ?assertEqual(
            {error, signature_verification_failed},
            cryptic_lib:decrypt_message_secure(
                EncryptedBlob, RecipientPriv, CorrectSignPub
            )
        )
    end}.

test_corrupted_messages(#{
    recipient_pub := RecipientPub,
    recipient_priv := RecipientPriv,
    sender_sign_pub := SenderSignPub,
    sender_sign_priv := SenderSignPriv
}) ->
    {"Handling of corrupted messages", fun() ->
        Message = <<"Message to be corrupted">>,
        Metadata = #{
            sender_id => <<"alice">>,
            recipient_id => <<"bob">>,
            sender_key_id => crypto:strong_rand_bytes(16),
            timestamp => erlang:system_time(second),
            sequence => 1,
            sender_sign_key => SenderSignPriv
        },

        %% Encrypt message
        {ok, {EphPub, Nonce, Ciphertext}} =
            cryptic_lib:encrypt_message_secure(Message, Metadata, RecipientPub),

        %% Corrupt the ciphertext
        <<FirstByte, Rest/binary>> = Ciphertext,
        CorruptedCiphertext = <<(FirstByte bxor 1), Rest/binary>>,

        %% Decrypt corrupted message should fail
        ?assertEqual(
            {error, decryption_failed},
            cryptic_lib:decrypt_message_secure(
                {EphPub, Nonce, CorruptedCiphertext},
                RecipientPriv,
                SenderSignPub
            )
        ),

        %% Corrupt the ephemeral public key
        <<EphFirstByte, EphRest/binary>> = EphPub,
        CorruptedEphPub = <<(EphFirstByte bxor 1), EphRest/binary>>,

        %% Decrypt with corrupted ephemeral key should fail
        ?assertEqual(
            {error, decryption_failed},
            cryptic_lib:decrypt_message_secure(
                {CorruptedEphPub, Nonce, Ciphertext},
                RecipientPriv,
                SenderSignPub
            )
        )
    end}.

test_key_mismatch_errors(#{sender_sign_priv := SenderSignPriv}) ->
    {"Handling of key mismatches and invalid parameters", fun() ->
        %% Test encryption with mismatched keys
        Message = <<"Test message">>,
        Metadata = #{
            sender_id => <<"alice">>,
            recipient_id => <<"bob">>,
            sender_key_id => crypto:strong_rand_bytes(16),
            timestamp => erlang:system_time(second),
            sequence => 1,
            sender_sign_key => SenderSignPriv
        },

        %% Invalid recipient public key (wrong size)

        % Should be 32 bytes
        InvalidPubKey = crypto:strong_rand_bytes(16),

        %% Should handle invalid key gracefully
        Result = cryptic_lib:encrypt_message_secure(
            Message, Metadata, InvalidPubKey
        ),
        ?assertMatch({error, _}, Result),

        %% Test with missing metadata fields
        IncompleteMetadata = #{
            sender_id => <<"alice">>,
            % Missing other required fields
            sender_sign_key => SenderSignPriv
        },

        {ValidPub, _} = cryptic_lib:gen_keypair(),
        Result2 = cryptic_lib:encrypt_message_secure(
            Message, IncompleteMetadata, ValidPub
        ),
        ?assertMatch({error, _}, Result2)
    end}.

%%%===================================================================
%%% Helper Functions (for future extension)
%%%===================================================================

%% These helper functions are kept for potential future test extensions
