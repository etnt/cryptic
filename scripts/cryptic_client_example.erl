%% Run with: erl -noshell -sname client -pa _build/default/lib/*/ebin -eval 'client_example:start().' -s init stop
-module(cryptic_client_example).

-export([start/0]).

start() ->
    % Start the server app (if running inside same VM); otherwise run server separately.
    application:start(salty),
    io:format("Generating keypairs for alice and bob...~n"),
    {b_pub, b_sec} = crypto_lib:gen_keypair(),
    {a_pub, a_sec} = crypto_lib:gen_keypair(),

    BPub64 = base64:encode(b_pub),
    APub64 = base64:encode(a_pub),
    %% Upload Bob prekey to server
    PrekeyJson = io_lib:format("{\"user_id\":\"bob\",\"pub\":\"~s\"}", [BPub64]),
    http_post("http://localhost:8080/upload_prekey", list_to_binary(PrekeyJson)),
    io:format("Bob prekey uploaded.~n"),

    %% Alice fetches Bob prekey
    {ok, {_, _, Body}} =
        httpc:request(get, {"http://localhost:8080/get_prekey/bob", []}, [], []),
    {_, PubB64} = re:run(Body, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    PubB64Str =
        lists:flatten(
            lists:nth(1, PubB64)),
    PubBin = base64:decode(PubB64Str),

    %% Alice computes shared secret = X25519(a_priv, b_pub)
    Shared = crypto_lib:scalarmult(a_sec, PubBin),
    %% Derive a 32-byte AEAD key from shared secret (HKDF/sha256 simple derive)
    AeadKey = hkdf_sha256(Shared, <<"chat-poc">>, 32),

    %% Alice encrypts message
    Plain = <<"Hello Bob from Alice">>,
    {Cipher, Nonce} = crypto_lib:aead_encrypt(Plain, AeadKey, <<>>),

    %% Alice sends ciphertext blob to server
    BodySend =
        io_lib:format("{\"from\":\"alice\",\"to\":\"bob\",\"ephemeral\":\"~s\",\"nonce\":\""
                      "~s\",\"cipher\":\"~s\"}",
                      [base64:encode(a_pub), base64:encode(Nonce), base64:encode(Cipher)]),
    http_post("http://localhost:8080/send_blob", list_to_binary(BodySend)),
    io:format("Alice sent encrypted blob to server.~n"),

    %% Bob fetches blobs
    {ok, {_, _, Resp}} =
        httpc:request(get, {"http://localhost:8080/recv_blobs/bob", []}, [], []),
    RespStr = binary_to_list(Resp),
    io:format("Bob received: ~s~n", [RespStr]),

    %% Parse the first blob and decrypt
    {_, EpMatch} =
        re:run(RespStr, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, NonMatch} = re:run(RespStr, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, CMatch} = re:run(RespStr, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    EphemeralB64 =
        lists:flatten(
            lists:nth(1, EpMatch)),
    NonceB64 =
        lists:flatten(
            lists:nth(1, NonMatch)),
    CipherB64 =
        lists:flatten(
            lists:nth(1, CMatch)),
    Ephemeral = base64:decode(EphemeralB64),
    Nonce2 = base64:decode(NonceB64),
    Cipher2 = base64:decode(CipherB64),

    %% Bob computes shared secret X25519(b_sec, ephemeral_pub)
    Shared2 = crypto_lib:scalarmult(b_sec, Ephemeral),
    AeadKey2 = hkdf_sha256(Shared2, <<"chat-poc">>, 32),
    Plain2 = crypto_lib:aead_decrypt(Cipher2, AeadKey2, Nonce2, <<>>),
    io:format("Bob decrypted message: ~p~n", [Plain2]),

    ok.

http_post(Url, BodyBin) ->
    Headers = [{"Content-Type", "application/json"}],
    httpc:request(post, {Url, Headers, "application/json", BodyBin}, [], []).

hkdf_sha256(IKM, Info, L) ->
    %% Simple HKDF using crypto:mac/4
    Salt = <<0:256>>, %% zero salt for simplicity in PoC (use random salt in production)
    PRK = crypto:hmac(sha256, Salt, IKM),
    T1 = crypto:hmac(sha256, PRK, <<Info/binary, 1:8>>),
    %% For 32-byte output, single iteration ok
    binary:part(T1, 0, L).
