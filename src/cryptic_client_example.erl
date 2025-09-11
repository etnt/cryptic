%% Run with: erl -noshell -sname client -pa _build/default/lib/*/ebin -eval 'cryptic_client_example:start().' -s init stop
-module(cryptic_client_example).

-export([start/0, test/0]).

-define(SERVER_URL, "http://localhost:8080").

test() ->
    start().

start() ->
    %% Initialize client
    cryptic_client_lib:init_client(),
    io:format("Generating keypairs for alice and bob...~n"),

    {BobPub, BobSec} = cryptic_lib:gen_keypair(),
    {_AlicePub, _AliceSec} = cryptic_lib:gen_keypair(),

    %% Bob uploads his prekey
    upload_bob_prekey(BobPub),

    %% Alice gets Bob's prekey
    BobPubRecv = get_bob_prekey(),

    %% Alice encrypts and sends message
    send_encrypted_message(BobPubRecv),

    %% Bob receives and decrypts message
    receive_and_decrypt_message(BobSec),

    ok.

upload_bob_prekey(BobPub) ->
    case cryptic_client_lib:upload_prekey(?SERVER_URL, "bob", BobPub) of
        ok ->
            io:format("Bob prekey uploaded.~n");
        {error, Reason} ->
            io:format("Failed to upload Bob's prekey: ~p~n", [Reason])
    end.

get_bob_prekey() ->
    case cryptic_client_lib:get_prekey(?SERVER_URL, "bob") of
        {ok, PubKey} ->
            io:format("Retrieved Bob's prekey~n"),
            PubKey;
        {error, Reason} ->
            io:format("Failed to get Bob's prekey: ~p~n", [Reason]),
            error({prekey_fetch_failed, Reason})
    end.

send_encrypted_message(BobPubRecv) ->
    Message = <<"Hello Bob!">>,
    
    case cryptic_client_lib:send_encrypted_message(
        ?SERVER_URL, "alice", "bob", BobPubRecv, Message
    ) of
        ok ->
            io:format("Alice sent encrypted message to Bob.~n");
        {error, Reason} ->
            io:format("Failed to send encrypted message: ~p~n", [Reason])
    end.

receive_and_decrypt_message(BobSec) ->
    case cryptic_client_lib:receive_and_decrypt_messages(?SERVER_URL, "bob", BobSec) of
        {ok, []} ->
            io:format("No messages for Bob~n");
        {ok, Messages} ->
            io:format("Bob received and decrypted ~p messages:~n", [length(Messages)]),
            lists:foreach(fun(Msg) ->
                io:format("  Decrypted message: ~p~n", [Msg])
            end, Messages);
        {error, Reason} ->
            io:format("Failed to receive/decrypt messages: ~p~n", [Reason])
    end.
