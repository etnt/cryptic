-module(cryptic_client_lib_test).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

setup() ->
    %% Start required applications for client library
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    application:ensure_all_started(ranch),
    application:ensure_all_started(cowboy),
    
    %% Initialize client library
    cryptic_client_lib:init_client(),
    
    %% Start test server on different port
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
    catch ets:delete(prekeys_test),
    catch ets:delete(blobs_test),
    ets:new(prekeys_test, [named_table, public, set]),
    ets:new(blobs_test, [named_table, public, bag]),
    
    %% Start HTTP server on test port
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/upload_prekey/:user_id", cryptic_client_lib_test_handler, upload_prekey},
            {"/get_prekey/:user_id", cryptic_client_lib_test_handler, get_prekey},
            {"/send_blob", cryptic_client_lib_test_handler, send_blob},
            {"/recv_blobs/:user_id", cryptic_client_lib_test_handler, recv_blobs}
        ]}
    ]),
    {ok, Pid} = cowboy:start_clear(
        test_client_lib_listener,
        [{port, 8082}], % Different port from main tests
        #{env => #{dispatch => Dispatch}}
    ),
    Pid.

stop_test_server(_Pid) ->
    cowboy:stop_listener(test_client_lib_listener),
    catch ets:delete(prekeys_test),
    catch ets:delete(blobs_test),
    ok.

%%%===================================================================
%%% Client Library API Tests
%%%===================================================================

%% Test client initialization
client_init_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     ?_test(test_init_client())}.

test_init_client() ->
    %% Should not crash and should be idempotent
    ?assertEqual(ok, cryptic_client_lib:init_client()),
    ?assertEqual(ok, cryptic_client_lib:init_client()).

%% Test prekey management
prekey_management_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_upload_and_get_prekey()),
      ?_test(test_get_nonexistent_prekey()),
      ?_test(test_upload_prekey_network_error())]}.

test_upload_and_get_prekey() ->
    ServerUrl = "http://localhost:8082",
    UserId = "test_user_1",
    {Pub, _Priv} = cryptic_lib:gen_keypair(),
    
    %% Upload prekey
    ?assertEqual(ok, cryptic_client_lib:upload_prekey(ServerUrl, UserId, Pub)),
    
    %% Retrieve prekey
    ?assertMatch({ok, Pub}, cryptic_client_lib:get_prekey(ServerUrl, UserId)).

test_get_nonexistent_prekey() ->
    ServerUrl = "http://localhost:8082",
    Result = cryptic_client_lib:get_prekey(ServerUrl, "nonexistent_user"),
    ?assertMatch({error, _}, Result).

test_upload_prekey_network_error() ->
    {Pub, _Priv} = cryptic_lib:gen_keypair(),
    Result = cryptic_client_lib:upload_prekey("http://invalid:9999", "user", Pub),
    ?assertMatch({error, _}, Result).

%% Test message encryption/decryption
message_crypto_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_encrypt_decrypt_roundtrip()),
      ?_test(test_decrypt_invalid_message()),
      ?_test(test_encrypt_invalid_key())]}.

test_encrypt_decrypt_roundtrip() ->
    %% Generate keys
    {_SenderPub, _SenderPriv} = cryptic_lib:gen_keypair(),
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),
    
    Message = "Hello, this is a test message!",
    
    %% Encrypt message
    {ok, {EphemeralPub, Nonce, Cipher}} = cryptic_client_lib:encrypt_message(Message, RecipientPub),
    
    %% Decrypt message
    {ok, Decrypted} = cryptic_client_lib:decrypt_message({EphemeralPub, Nonce, Cipher}, RecipientPriv),
    
    ?assertEqual(Message, Decrypted).

test_decrypt_invalid_message() ->
    {_Pub, Priv} = cryptic_lib:gen_keypair(),
    
    %% Try to decrypt invalid cipher
    InvalidCipher = {crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(24), <<"invalid">>},
    Result = cryptic_client_lib:decrypt_message(InvalidCipher, Priv),
    ?assertMatch({error, _}, Result).

test_encrypt_invalid_key() ->
    InvalidKey = <<"invalid_key_length">>,
    Message = "Test message",
    Result = cryptic_client_lib:encrypt_message(Message, InvalidKey),
    ?assertMatch({error, _}, Result).

%% Test high-level E2E functions
high_level_e2e_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_send_and_receive_message()),
      ?_test(test_receive_empty_messages()),
      ?_test(test_send_message_network_error())]}.

test_send_and_receive_message() ->
    ServerUrl = "http://localhost:8082",
    
    %% Setup sender and recipient
    {SenderPub, SenderPriv} = cryptic_lib:gen_keypair(),
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),
    
    SenderId = "sender_user",
    RecipientId = "recipient_user",
    
    %% Upload prekeys
    ?assertEqual(ok, cryptic_client_lib:upload_prekey(ServerUrl, SenderId, SenderPub)),
    ?assertEqual(ok, cryptic_client_lib:upload_prekey(ServerUrl, RecipientId, RecipientPub)),
    
    Message = "Hello from sender!",
    
    %% Send encrypted message
    ?assertEqual(ok, cryptic_client_lib:send_encrypted_message(
        ServerUrl, SenderId, RecipientId, Message, SenderPriv)),
    
    %% Receive and decrypt messages
    {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
        ServerUrl, RecipientId, RecipientPriv),
    
    %% Verify received message
    ?assertEqual(1, length(Messages)),
    {From, DecryptedMessage} = hd(Messages),
    ?assertEqual(SenderId, From),
    ?assertEqual(Message, DecryptedMessage).

test_receive_empty_messages() ->
    ServerUrl = "http://localhost:8082",
    {_Pub, Priv} = cryptic_lib:gen_keypair(),
    
    %% Try to receive messages when none exist
    {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
        ServerUrl, "empty_user", Priv),
    ?assertEqual([], Messages).

test_send_message_network_error() ->
    {_Pub, Priv} = cryptic_lib:gen_keypair(),
    
    Result = cryptic_client_lib:send_encrypted_message(
        "http://invalid:9999", "sender", "recipient", "message", Priv),
    ?assertMatch({error, _}, Result).

%% Test utility functions
utility_functions_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_format_send_blob_request()),
      ?_test(test_parse_recv_blobs_response()),
      ?_test(test_parse_get_prekey_response())]}.

test_format_send_blob_request() ->
    From = "sender",
    To = "recipient",
    Ephemeral = crypto:strong_rand_bytes(32),
    Nonce = crypto:strong_rand_bytes(24),
    Cipher = <<"encrypted_data">>,
    
    Result = cryptic_client_lib:format_send_blob_request(From, To, Ephemeral, Nonce, Cipher),
    
    %% Should be valid JSON string
    ?assert(is_list(Result)),
    ?assert(length(Result) > 0).

test_parse_recv_blobs_response() ->
    %% Test empty response
    EmptyResp = "[]",
    ?assertEqual([], cryptic_client_lib:parse_recv_blobs_response(EmptyResp)),
    
    %% Test single message response
    Ephemeral = base64:encode(crypto:strong_rand_bytes(32)),
    Nonce = base64:encode(crypto:strong_rand_bytes(24)),
    Cipher = base64:encode(<<"test_cipher">>),
    
    SingleResp = io_lib:format(
        "[{\"from\":\"sender\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}]",
        [Ephemeral, Nonce, Cipher]),
    
    Result = cryptic_client_lib:parse_recv_blobs_response(lists:flatten(SingleResp)),
    ?assertEqual(1, length(Result)),
    
    {From, EphDec, NonceDec, CiphDec} = hd(Result),
    ?assertEqual("sender", From),
    ?assertEqual(base64:decode(Ephemeral), EphDec),
    ?assertEqual(base64:decode(Nonce), NonceDec),
    ?assertEqual(base64:decode(Cipher), CiphDec).

test_parse_get_prekey_response() ->
    UserId = "test_user",
    PubKey = crypto:strong_rand_bytes(32),
    PubKeyB64 = base64:encode(PubKey),
    
    Response = io_lib:format(
        "{\"user_id\":\"~s\",\"pub\":\"~s\"}", 
        [UserId, PubKeyB64]),
    
    Result = cryptic_client_lib:parse_get_prekey_response(lists:flatten(Response)),
    ?assertMatch({ok, PubKey}, Result).

%% Test error handling
error_handling_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_invalid_server_response()),
      ?_test(test_malformed_json_response())]}.

test_invalid_server_response() ->
    %% Test with invalid JSON
    Result = cryptic_client_lib:parse_get_prekey_response("invalid json"),
    ?assertMatch({error, _}, Result).

test_malformed_json_response() ->
    %% Test with malformed blob response
    Result = cryptic_client_lib:parse_recv_blobs_response("malformed"),
    ?assertEqual([], Result). % Should handle gracefully

%% Test edge cases
edge_cases_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [?_test(test_empty_message_encryption()),
      ?_test(test_large_message_encryption()),
      ?_test(test_unicode_message_encryption())]}.

test_empty_message_encryption() ->
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),
    
    %% Encrypt and decrypt empty message
    {ok, Encrypted} = cryptic_client_lib:encrypt_message("", RecipientPub),
    {ok, Decrypted} = cryptic_client_lib:decrypt_message(Encrypted, RecipientPriv),
    
    ?assertEqual("", Decrypted).

test_large_message_encryption() ->
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),
    
    %% Large message (1KB)
    LargeMessage = lists:duplicate(1024, $A),
    
    {ok, Encrypted} = cryptic_client_lib:encrypt_message(LargeMessage, RecipientPub),
    {ok, Decrypted} = cryptic_client_lib:decrypt_message(Encrypted, RecipientPriv),
    
    ?assertEqual(LargeMessage, Decrypted).

test_unicode_message_encryption() ->
    {RecipientPub, RecipientPriv} = cryptic_lib:gen_keypair(),
    
    %% Unicode message
    UnicodeMessage = "Hello 世界! 🚀 Testing unicode chars: åäö",
    
    {ok, Encrypted} = cryptic_client_lib:encrypt_message(UnicodeMessage, RecipientPub),
    {ok, Decrypted} = cryptic_client_lib:decrypt_message(Encrypted, RecipientPriv),
    
    ?assertEqual(UnicodeMessage, Decrypted).
