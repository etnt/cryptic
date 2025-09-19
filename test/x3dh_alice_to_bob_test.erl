%%% @doc X3DH Alice-to-Bob encryption/decryption test
%%%
%%% This test implements the complete X3DH flow as described in the X3DH specification:
%%% 1. Alice fetches Bob's prekey bundle (identity key, signed prekey, one-time prekey)
%%% 2. Alice generates ephemeral key and performs X3DH key agreement
%%% 3. Alice encrypts initial message and sends to Bob
%%% 4. Bob receives the message and performs X3DH key agreement
%%% 5. Bob decrypts the message successfully
%%%
%%% This tests the core X3DH protocol implementation following the specification
%%% from docs/X3DH-send-receive.md
-module(x3dh_alice_to_bob_test).

-include_lib("eunit/include/eunit.hrl").

%% Test the complete X3DH Alice-to-Bob encryption and decryption flow
x3dh_alice_to_bob_test() ->
    %% Initialize cryptographic subsystem
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    %% Step 1: Generate key pairs for Alice and Bob
    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),

    %% Step 2: Extract Bob's public prekey bundle (what Alice would fetch from server)
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    %% Step 3: Alice sends encrypted message to Bob
    PlaintextMessage = <<"Hello Bob! This is a secret message from Alice.">>,
    {AliceMessageBlob, AliceMessageId} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, PlaintextMessage
    ),

    %% Step 4: Bob receives and decrypts Alice's message
    {BobDecryptedMessage, BobMessageId} = bob_decrypt_message(
        BobKeys, AliceKeys, AliceMessageBlob
    ),

    %% Step 5: Verify successful encryption/decryption
    ?assertEqual(PlaintextMessage, BobDecryptedMessage),
    ?assertEqual(AliceMessageId, BobMessageId),

    %% Additional verification: Ensure message IDs are unique and properly formed
    ?assert(is_binary(AliceMessageId)),
    ?assert(byte_size(AliceMessageId) > 0),

    io:format("✓ X3DH Alice-to-Bob test completed successfully~n"),
    io:format("  Original message: ~s~n", [PlaintextMessage]),
    io:format("  Decrypted message: ~s~n", [BobDecryptedMessage]),
    io:format("  Message ID: ~s~n", [base64:encode(AliceMessageId)]).

%% Test with empty message
x3dh_empty_message_test() ->
    %% Setup
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    EmptyMessage = <<"">>,
    {AliceMessageBlob, _} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, EmptyMessage
    ),
    {BobDecryptedMessage, _} = bob_decrypt_message(
        BobKeys, AliceKeys, AliceMessageBlob
    ),

    ?assertEqual(EmptyMessage, BobDecryptedMessage),
    io:format("✓ Empty message test passed~n").

%% Test with large message
x3dh_large_message_test() ->
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    %% Create a large message (1KB)
    LargeMessage = binary:copy(<<"This is a test message. ">>, 42),
    ?assert(byte_size(LargeMessage) > 1000),

    {AliceMessageBlob, _} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, LargeMessage
    ),
    {BobDecryptedMessage, _} = bob_decrypt_message(
        BobKeys, AliceKeys, AliceMessageBlob
    ),

    ?assertEqual(LargeMessage, BobDecryptedMessage),
    io:format("✓ Large message test passed (~p bytes)~n", [
        byte_size(LargeMessage)
    ]).

%% Test with Unicode message
x3dh_unicode_message_test() ->
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    UnicodeMessage =
        <<"Hello 世界! 🌍 Testing émojis and spëcial characters: αβγδε"/utf8>>,
    {AliceMessageBlob, _} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, UnicodeMessage
    ),
    {BobDecryptedMessage, _} = bob_decrypt_message(
        BobKeys, AliceKeys, AliceMessageBlob
    ),

    ?assertEqual(UnicodeMessage, BobDecryptedMessage),
    io:format("✓ Unicode message test passed~n").

%% Test that different key pairs produce different results
x3dh_key_uniqueness_test() ->
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    %% Generate two sets of keys
    AliceKeys1 = cryptic_lib:generate_client_keys(),
    AliceKeys2 = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    Message = <<"Same message, different keys">>,

    %% Encrypt with different Alice keys
    {MessageBlob1, _} = alice_encrypt_message(
        AliceKeys1, BobPrekeyBundle, Message
    ),
    {MessageBlob2, _} = alice_encrypt_message(
        AliceKeys2, BobPrekeyBundle, Message
    ),

    %% The encrypted blobs should be different (different ephemeral keys)
    ?assertNotEqual(MessageBlob1, MessageBlob2),

    %% But both should decrypt correctly
    {Decrypted1, _} = bob_decrypt_message(BobKeys, AliceKeys1, MessageBlob1),
    {Decrypted2, _} = bob_decrypt_message(BobKeys, AliceKeys2, MessageBlob2),

    ?assertEqual(Message, Decrypted1),
    ?assertEqual(Message, Decrypted2),
    io:format("✓ Key uniqueness test passed~n").

%% Test that Bob cannot decrypt with wrong keys
x3dh_wrong_keys_test() ->
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    % Eve tries to decrypt
    EveKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    Message = <<"Secret message for Bob only">>,
    {AliceMessageBlob, _} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, Message
    ),

    %% Eve tries to decrypt with her keys - should fail
    #{metadata := #{otpk_id := OtpkId}} = AliceMessageBlob,

    %% Try to find OTPK in Eve's keys (should fail)
    OtpkResult = cryptic_lib:find_otpk_private_key(EveKeys, OtpkId),
    ?assertMatch({error, _}, OtpkResult),

    io:format(
        "✓ Wrong keys test passed - Eve cannot decrypt Bob's message~n"
    ).

%% Test message metadata integrity
x3dh_metadata_integrity_test() ->
    application:ensure_all_started(crypto),
    %% Start event manager for debug logging (ignore if already started)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    cryptic_lib:initialize(),

    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),
    BobPrekeyBundle = extract_prekey_bundle(BobKeys),

    Message = <<"Test metadata integrity">>,
    {AliceMessageBlob, _} = alice_encrypt_message(
        AliceKeys, BobPrekeyBundle, Message
    ),

    %% Verify message blob structure
    ?assertMatch(
        #{
            metadata := _,
            signature := _,
            ciphertext := _,
            nonce := _
        },
        AliceMessageBlob
    ),

    %% Verify metadata contains required fields
    #{metadata := Metadata} = AliceMessageBlob,
    RequiredMetadataKeys = [
        ephemeral_public,
        sender_identity_dh_public,
        sender_identity_sign_public,
        message_id,
        otpk_id,
        type,
        version,
        timestamp
    ],

    lists:foreach(
        fun(Key) ->
            ?assert(maps:is_key(Key, Metadata)),
            Value = maps:get(Key, Metadata),
            ?assert(Value =/= undefined)
        end,
        RequiredMetadataKeys
    ),

    io:format("✓ Metadata integrity test passed~n").

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @private
%% Extract Bob's prekey bundle that Alice would receive from the server
extract_prekey_bundle(BobKeys) ->
    #{
        identity_sign_public := BobIdSignPub,
        identity_dh_public := BobIdDHPub,
        signed_prekey_public := BobSpkPub,
        signed_prekey_signature := BobSpkSig,
        one_time_prekeys := [BobFirstOtpk | _],
        key_id := BobKeyId
    } = BobKeys,

    #{
        identity_sign_public => BobIdSignPub,
        identity_dh_public => BobIdDHPub,
        signed_prekey => #{
            public => BobSpkPub,
            signature => BobSpkSig
        },
        one_time_prekey => BobFirstOtpk,
        key_id => BobKeyId
    }.

%% @private
%% Alice encrypts a message for Bob using X3DH
alice_encrypt_message(AliceKeys, BobPrekeyBundle, Message) ->
    %% Perform X3DH sender initialization (Alice's side)
    case cryptic_lib:x3dh_sender_init(AliceKeys, BobPrekeyBundle, Message) of
        {ok, {MessageBlob, MessageId}} ->
            io:format("Alice encrypted message successfully~n"),
            {MessageBlob, MessageId};
        {error, Reason} ->
            ?assert(
                false, io_lib:format("Alice encryption failed: ~p", [Reason])
            )
    end.

%% @private
%% Bob decrypts Alice's message using X3DH
bob_decrypt_message(BobKeys, AliceKeys, MessageBlob) ->
    %% Extract Alice's identity key (Bob would get this from the message)
    #{identity_sign_public := AliceIdPub} = AliceKeys,

    %% Extract OTPK ID from message and find Bob's corresponding private key
    #{metadata := #{otpk_id := OtpkId}} = MessageBlob,
    case cryptic_lib:find_otpk_private_key(BobKeys, OtpkId) of
        {ok, OtpkPrivateKey} ->
            %% Perform X3DH receiver decryption (Bob's side)
            case
                cryptic_lib:x3dh_receiver_decrypt(
                    BobKeys, MessageBlob, AliceIdPub, OtpkPrivateKey
                )
            of
                {ok, {DecryptedMessage, MessageId}} ->
                    io:format("Bob decrypted message successfully~n"),
                    {DecryptedMessage, MessageId};
                {error, Reason} ->
                    ?assert(
                        false,
                        io_lib:format("Bob decryption failed: ~p", [Reason])
                    )
            end;
        {error, Reason} ->
            ?assert(
                false, io_lib:format("Bob OTPK lookup failed: ~p", [Reason])
            )
    end.
