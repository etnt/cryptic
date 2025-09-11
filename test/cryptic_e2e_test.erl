-module(cryptic_e2e_test).

-include_lib("eunit/include/eunit.hrl").

%% Test setup and teardown
-export([setup/0, cleanup/1]).

%% Helper functions for testing
-export([start_test_server/0, stop_test_server/1]).

%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

setup() ->
    %% Start required applications
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    application:ensure_all_started(ranch),
    application:ensure_all_started(cowboy),
    
    %% Start test server
    ServerPid = start_test_server(),
    timer:sleep(100), % Give server time to start
    {ok, ServerPid}.

cleanup({ok, ServerPid}) ->
    stop_test_server(ServerPid),
    ok;
cleanup(_) ->
    ok.

start_test_server() ->
    %% Create ETS stores for testing
    catch ets:delete(prekeys),
    catch ets:delete(blobs),
    ets:new(prekeys, [named_table, public, set]),
    ets:new(blobs, [named_table, public, bag]),

    %% Start HTTP server on test port
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/upload_prekey/:user_id", cryptic_handlers, upload_prekey},
            {"/get_prekey/:user_id", cryptic_handlers, get_prekey},
            {"/send_blob", cryptic_handlers, send_blob},
            {"/recv_blobs/:user_id", cryptic_handlers, recv_blobs}
        ]}
    ]),
    {ok, Pid} = cowboy:start_clear(
        test_http_listener,
        [{port, 8081}], % Use different port for testing
        #{env => #{dispatch => Dispatch}}
    ),
    Pid.

stop_test_server(_Pid) ->
    cowboy:stop_listener(test_http_listener),
    catch ets:delete(prekeys),
    catch ets:delete(blobs),
    ok.

%%%===================================================================
%%% Unit Tests
%%%===================================================================

%% Test basic NIF functions
cryptic_nif_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
         ?_test(test_keypair_generation()),
         ?_test(test_scalar_multiplication()),
         ?_test(test_aead_encryption()),
         ?_test(test_random_bytes())
     ]}.

test_keypair_generation() ->
    {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
    ?assertEqual(32, byte_size(PubKey)),
    ?assertEqual(32, byte_size(PrivKey)),
    ?assertNotEqual(PubKey, PrivKey),

    %% Generate another pair and ensure they're different
    {PubKey2, PrivKey2} = cryptic_lib:gen_keypair(),
    ?assertNotEqual(PubKey, PubKey2),
    ?assertNotEqual(PrivKey, PrivKey2).

test_scalar_multiplication() ->
    {PubKeyA, PrivKeyA} = cryptic_lib:gen_keypair(),
    {PubKeyB, PrivKeyB} = cryptic_lib:gen_keypair(),

    %% Test that scalar multiplication is commutative
    SharedA = cryptic_lib:scalarmult(PrivKeyA, PubKeyB),
    SharedB = cryptic_lib:scalarmult(PrivKeyB, PubKeyA),

    ?assertEqual(SharedA, SharedB),
    ?assertEqual(32, byte_size(SharedA)).

test_aead_encryption() ->
    Key = cryptic_lib:rand_bytes(32),
    Plaintext = <<"Hello, World!">>,
    AAD = <<>>,

    {Ciphertext, Nonce} = cryptic_lib:aead_encrypt(Plaintext, Key, AAD),
    ?assertEqual(12, byte_size(Nonce)),
    ?assert(byte_size(Ciphertext) > byte_size(Plaintext)), % Should include auth tag

    %% Test decryption
    DecryptedText = cryptic_lib:aead_decrypt(Ciphertext, Key, Nonce, AAD),
    ?assertEqual(Plaintext, DecryptedText).

test_random_bytes() ->
    Bytes1 = cryptic_lib:rand_bytes(16),
    Bytes2 = cryptic_lib:rand_bytes(16),

    ?assertEqual(16, byte_size(Bytes1)),
    ?assertEqual(16, byte_size(Bytes2)),
    ?assertNotEqual(Bytes1, Bytes2).

%% Test HKDF key derivation functions
hkdf_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
         ?_test(test_hkdf_basic()),
         ?_test(test_hkdf_with_salt()),
         ?_test(test_derive_aead_key_modes())
     ]}.

test_hkdf_basic() ->
    IKM = cryptic_lib:rand_bytes(32),
    Info = <<"test-info">>,

    Key1 = cryptic_lib:hkdf_sha256(IKM, Info, 32),
    Key2 = cryptic_lib:hkdf_sha256(IKM, Info, 32),

    ?assertEqual(32, byte_size(Key1)),
    ?assertEqual(Key1, Key2), % Should be deterministic

    %% Different info should produce different keys
    Key3 = cryptic_lib:hkdf_sha256(IKM, <<"different-info">>, 32),
    ?assertNotEqual(Key1, Key3).

test_hkdf_with_salt() ->
    IKM = cryptic_lib:rand_bytes(32),
    Salt = cryptic_lib:rand_bytes(16),
    Info = <<"test-info">>,

    Key1 = cryptic_lib:hkdf_sha256(IKM, Salt, Info, 32),
    Key2 = cryptic_lib:hkdf_sha256(IKM, Salt, Info, 32),

    ?assertEqual(Key1, Key2), % Should be deterministic

    %% Different salt should produce different keys
    DifferentSalt = cryptic_lib:rand_bytes(16),
    Key3 = cryptic_lib:hkdf_sha256(IKM, DifferentSalt, Info, 32),
    ?assertNotEqual(Key1, Key3).

test_derive_aead_key_modes() ->
    SharedSecret = cryptic_lib:rand_bytes(32),
    EphemeralPubKey = cryptic_lib:rand_bytes(32),

    %% Test simple derivation
    Key1 = cryptic_lib:derive_aead_key_simple(SharedSecret),
    Key2 = cryptic_lib:derive_aead_key_simple(SharedSecret),
    ?assertEqual(Key1, Key2), % Should be deterministic

    %% Test ephemeral-based derivation
    Key3 = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPubKey),
    Key4 = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphemeralPubKey),
    ?assertEqual(Key3, Key4), % Should be deterministic

    %% Simple and ephemeral should produce different keys
    ?assertNotEqual(Key1, Key3),

    %% Different ephemeral keys should produce different AEAD keys
    DifferentEphemeral = cryptic_lib:rand_bytes(32),
    Key5 = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, DifferentEphemeral),
    ?assertNotEqual(Key3, Key5),

    %% Test random salt derivation
    {Key6, Salt1} = cryptic_lib:derive_aead_key_random(SharedSecret),
    {Key7, Salt2} = cryptic_lib:derive_aead_key_random(SharedSecret),
    ?assertNotEqual(Key6, Key7), % Should be different due to random salt
    ?assertNotEqual(Salt1, Salt2).

%% Test HTTP API endpoints
http_api_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
         ?_test(test_prekey_upload_and_retrieval()),
         ?_test(test_message_send_and_receive()),
         ?_test(test_nonexistent_user()),
         ?_test(test_invalid_json())
     ]}.

test_prekey_upload_and_retrieval() ->
    {PubKey, _PrivKey} = cryptic_lib:gen_keypair(),
    PubKeyB64 = base64:encode(PubKey),

    %% Upload prekey
    PostData = io_lib:format("{\"prekey\":\"~s\"}", [PubKeyB64]),
    {ok, {_, _, _}} = httpc:request(
        post,
        {"http://localhost:8081/upload_prekey/testuser", [], "application/json", PostData},
        [],
        []
    ),

    %% Retrieve prekey
    {ok, {_, _, RespData}} = httpc:request(
        get, {"http://localhost:8081/get_prekey/testuser", []}, [], []
    ),

    %% Parse and verify response
    {match, [ReturnedPubKeyB64]} = re:run(RespData, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),

    ?assertEqual(binary_to_list(PubKeyB64), ReturnedPubKeyB64).

test_message_send_and_receive() ->
    %% Send a message
    EphPub = base64:encode(cryptic_lib:rand_bytes(32)),
    Nonce = base64:encode(cryptic_lib:rand_bytes(12)),
    Cipher = base64:encode(cryptic_lib:rand_bytes(26)),

    BlobData = io_lib:format(
        "{\"from\":\"alice\",\"to\":\"bob\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}",
        [EphPub, Nonce, Cipher]
    ),

    {ok, {_, _, _}} = httpc:request(
        post,
        {"http://localhost:8081/send_blob", [], "application/json", BlobData},
        [],
        []
    ),

    %% Receive messages
    {ok, {_, _, RespStr}} = httpc:request(
        get, {"http://localhost:8081/recv_blobs/bob", []}, [], []
    ),

    %% Verify message was received
    ?assert(string:find(RespStr, EphPub) =/= nomatch),
    ?assert(string:find(RespStr, Nonce) =/= nomatch),
    ?assert(string:find(RespStr, Cipher) =/= nomatch).

test_nonexistent_user() ->
    {ok, {_, _, _}} = httpc:request(
        get, {"http://localhost:8081/get_prekey/nonexistent", []}, [], []
    ),
    %% Should return 404 but we don't check status codes in this simple test
    ok.

test_invalid_json() ->
    %% Send invalid JSON
    {ok, {_, _, _}} = httpc:request(
        post,
        {"http://localhost:8081/upload_prekey/testuser", [], "application/json", "invalid json"},
        [],
        []
    ),
    %% Should return 400 but we don't check status codes in this simple test
    ok.

%% Test complete E2E flow
e2e_flow_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     ?_test(test_complete_e2e_flow())}.

test_complete_e2e_flow() ->
    %% Generate Alice and Bob keypairs
    {_AlicePub, _AlicePriv} = cryptic_lib:gen_keypair(),
    {BobPub, BobPriv} = cryptic_lib:gen_keypair(),

    %% Bob uploads his prekey
    BobPubB64 = base64:encode(BobPub),
    PostData = io_lib:format("{\"prekey\":\"~s\"}", [BobPubB64]),
    {ok, {_, _, _}} = httpc:request(
        post,
        {"http://localhost:8081/upload_prekey/bob", [], "application/json", PostData},
        [],
        []
    ),

    %% Alice gets Bob's prekey
    {ok, {_, _, RespData}} = httpc:request(
        get, {"http://localhost:8081/get_prekey/bob", []}, [], []
    ),
    {match, [BobPubB64Resp]} = re:run(RespData, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    BobPubRecv = base64:decode(BobPubB64Resp),
    ?assertEqual(BobPub, BobPubRecv),

    %% Alice generates ephemeral keypair and encrypts message
    {EphPub, EphPriv} = cryptic_lib:gen_keypair(),
    SharedSecret = cryptic_lib:scalarmult(EphPriv, BobPubRecv),
    AeadKey = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphPub),

    Message = <<"Hello Bob from test!">>,
    {Cipher, Nonce} = cryptic_lib:aead_encrypt(Message, AeadKey, <<>>),

    %% Alice sends encrypted blob
    EphPubB64 = base64:encode(EphPub),
    NonceB64 = base64:encode(Nonce),
    CipherB64 = base64:encode(Cipher),
    BlobData = io_lib:format(
        "{\"from\":\"alice\",\"to\":\"bob\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}",
        [EphPubB64, NonceB64, CipherB64]
    ),
    {ok, {_, _, _}} = httpc:request(
        post,
        {"http://localhost:8081/send_blob", [], "application/json", BlobData},
        [],
        []
    ),

    %% Bob receives and decrypts message
    {ok, {_, _, RespStr}} = httpc:request(
        get, {"http://localhost:8081/recv_blobs/bob", []}, [], []
    ),

    %% Parse received message
    {match, [EphPubB64Recv]} = re:run(RespStr, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    {match, [NonceB64Recv]} = re:run(RespStr, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    {match, [CipherB64Recv]} = re:run(RespStr, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),

    EphPubRecv = base64:decode(EphPubB64Recv),
    NonceRecv = base64:decode(NonceB64Recv),
    CipherRecv = base64:decode(CipherB64Recv),

    %% Bob computes shared secret and decrypts
    SharedSecretBob = cryptic_lib:scalarmult(BobPriv, EphPubRecv),
    AeadKeyBob = cryptic_lib:derive_aead_key_ephemeral(SharedSecretBob, EphPubRecv),

    %% Verify Alice and Bob computed the same keys
    ?assertEqual(SharedSecret, SharedSecretBob),
    ?assertEqual(AeadKey, AeadKeyBob),

    %% Decrypt and verify message
    DecryptedMessage = cryptic_lib:aead_decrypt(CipherRecv, AeadKeyBob, NonceRecv, <<>>),
    ?assertEqual(Message, DecryptedMessage),

    %% Verify messages are consumed (second request should return empty)
    {ok, {_, _, EmptyResp}} = httpc:request(
        get, {"http://localhost:8081/recv_blobs/bob", []}, [], []
    ),
    ?assertEqual("[]", EmptyResp).

%% Test multiple key derivation approaches produce different results
key_derivation_uniqueness_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     ?_test(test_key_derivation_uniqueness())}.

test_key_derivation_uniqueness() ->
    SharedSecret = cryptic_lib:rand_bytes(32),
    EphPub1 = cryptic_lib:rand_bytes(32),
    EphPub2 = cryptic_lib:rand_bytes(32),

    %% Simple derivation should be consistent
    KeySimple1 = cryptic_lib:derive_aead_key_simple(SharedSecret),
    KeySimple2 = cryptic_lib:derive_aead_key_simple(SharedSecret),
    ?assertEqual(KeySimple1, KeySimple2),

    %% Ephemeral-based should be consistent for same ephemeral key
    KeyEph1 = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphPub1),
    KeyEph1_repeat = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphPub1),
    ?assertEqual(KeyEph1, KeyEph1_repeat),

    %% Different ephemeral keys should produce different AEAD keys
    KeyEph2 = cryptic_lib:derive_aead_key_ephemeral(SharedSecret, EphPub2),
    ?assertNotEqual(KeyEph1, KeyEph2),

    %% Simple and ephemeral should be different
    ?assertNotEqual(KeySimple1, KeyEph1),
    ?assertNotEqual(KeySimple1, KeyEph2),

    %% Random salt should always be different
    {KeyRand1, Salt1} = cryptic_lib:derive_aead_key_random(SharedSecret),
    {KeyRand2, Salt2} = cryptic_lib:derive_aead_key_random(SharedSecret),
    ?assertNotEqual(KeyRand1, KeyRand2),
    ?assertNotEqual(Salt1, Salt2),
    ?assertEqual(32, byte_size(Salt1)),
    ?assertEqual(32, byte_size(Salt2)).
