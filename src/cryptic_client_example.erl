%% Run with: erl -noshell -sname client -pa _build/default/lib/*/ebin -eval 'cryptic_client_example:start().' -s init stop
-module(cryptic_client_example).

-export([start/0, test/0]).

test() ->
    start().

start() ->
    % Start required applications
    application:start(inets),
    application:start(crypto),
    io:format("Generating keypairs for alice and bob...~n"),

    {BPub, BSec} = cryptic_lib:gen_keypair(),
    {_APub, _ASec} = cryptic_lib:gen_keypair(),

    % Bob uploads his prekey
    upload_bob_prekey(BPub),

    % Alice gets Bob's prekey
    BPubRecv = get_bob_prekey(),

    % Alice encrypts and sends message
    send_encrypted_message(BPubRecv),

    % Bob receives and decrypts message
    receive_and_decrypt_message(BSec),

    ok.

upload_bob_prekey(BPub) ->
    BPubB64 = base64:encode(BPub),
    PostData = io_lib:format("{\"prekey\":\"~s\"}", [BPubB64]),
    {ok, {_, _, _}} =
        httpc:request(
            post,
            {"http://localhost:8080/upload_prekey/bob", [], "application/json", PostData},
            [],
            []
        ),
    io:format("Bob prekey uploaded.~n").

get_bob_prekey() ->
    {ok, {_, _, RespData}} =
        httpc:request(
            get, {"http://localhost:8080/get_prekey/bob", []}, [], []
        ),
    io:format("RespData from get_prekey: ~p~n", [RespData]),
    {match, [BPubB64Resp]} = re:run(RespData, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    base64:decode(BPubB64Resp).

send_encrypted_message(BPubRecv) ->
    % Alice generates ephemeral keypair and shared secret
    {EphPub, EphSec} = cryptic_lib:gen_keypair(),
    Shared = cryptic_lib:scalarmult(EphSec, BPubRecv),
    AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, EphPub),

    io:format("Alice - EphPub: ~p~n", [base64:encode(EphPub)]),
    io:format("Alice - Shared: ~p~n", [base64:encode(Shared)]),
    io:format("Alice - AeadKey: ~p~n", [base64:encode(AeadKey)]),

    % Alice encrypts a message
    Message = <<"Hello Bob!">>,
    {Cipher, Nonce} = cryptic_lib:aead_encrypt(Message, AeadKey, <<>>),

    % Alice sends the encrypted blob
    EphPubB64 = base64:encode(EphPub),
    NonceB64 = base64:encode(Nonce),
    CipherB64 = base64:encode(Cipher),
    BlobData = io_lib:format(
        "{\"from\":\"alice\",\"to\":\"bob\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}",
        [EphPubB64, NonceB64, CipherB64]
    ),
    {ok, {_, _, _}} =
        httpc:request(
            post,
            {"http://localhost:8080/send_blob", [], "application/json", BlobData},
            [],
            []
        ),
    io:format("Alice sent encrypted blob to server.~n").

receive_and_decrypt_message(BSec) ->
    % Bob fetches blobs
    {ok, {_, _, RespStr}} =
        httpc:request(
            get, {"http://localhost:8080/recv_blobs/bob", []}, [], []
        ),
    io:format("Bob received: ~s~n", [RespStr]),

    % Check if there are any messages
    case RespStr of
        "[]" ->
            io:format("No messages for Bob~n");
        _ ->
            decrypt_message(RespStr, BSec)
    end.

decrypt_message(RespStr, BSec) ->
    % Parse the JSON response to extract ephemeral, nonce, cipher
    {EphemeralB64, NonceB64, CipherB64} = parse_message_json(RespStr),
    
    % Decode base64 fields
    Ephemeral = base64:decode(EphemeralB64),
    Nonce = base64:decode(NonceB64),
    Cipher = base64:decode(CipherB64),

    io:format("Debug - Decoded sizes: Ephemeral=~p bytes, Nonce=~p bytes, Cipher=~p bytes~n", 
              [byte_size(Ephemeral), byte_size(Nonce), byte_size(Cipher)]),

    io:format("Bob - EphPub received: ~p~n", [EphemeralB64]),
    
    % Bob computes shared secret X25519(BSec, ephemeral_pub)
    Shared = cryptic_lib:scalarmult(BSec, Ephemeral),
    AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, Ephemeral),
    
    io:format("Bob - Shared: ~p~n", [base64:encode(Shared)]),
    io:format("Bob - AeadKey: ~p~n", [base64:encode(AeadKey)]),
    io:format("Debug - Shared secret size: ~p bytes, AeadKey size: ~p bytes~n", 
              [byte_size(Shared), byte_size(AeadKey)]),
    
    Plain = cryptic_lib:aead_decrypt(Cipher, AeadKey, Nonce, <<>>),
    io:format("Bob decrypted message: ~p~n", [Plain]).

parse_message_json(RespStr) ->
    EpResult = re:run(RespStr, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    NoResult = re:run(RespStr, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    CResult = re:run(RespStr, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    io:format("Debug regex results - Eph: ~p, Nonce: ~p, Cipher: ~p~n", [EpResult, NoResult, CResult]),
    
    {match, EpMatch} = EpResult,
    {match, NoMatch} = NoResult,
    {match, CMatch} = CResult,
    
    EphemeralB64 = lists:nth(1, EpMatch),
    NonceB64 = lists:nth(1, NoMatch),
    CipherB64 = lists:nth(1, CMatch),
    
    io:format("Debug - Raw base64: Eph=~p, Nonce=~p, Cipher=~p~n", [EphemeralB64, NonceB64, CipherB64]),
    {EphemeralB64, NonceB64, CipherB64}.
