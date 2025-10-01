#!/usr/bin/env escript
%%! -pa _build/default/lib/cryptic/ebin

%%% @doc Validation script for the complete Double Ratchet engine implementation
%%%
%%% This script demonstrates all the functionality we've implemented

main(_Args) ->
    io:format("=== Cryptic Double Ratchet Engine Validation ===~n"),

    %% 1. Test compilation status
    io:format("1. Testing compilation...~n"),
    case code:which(cryptic_ratchet_engine) of
        non_existing ->
            io:format("   ERROR: cryptic_ratchet_engine module not found~n"),
            halt(1);
        Path ->
            io:format("   SUCCESS: Module compiled at ~s~n", [Path])
    end,

    case code:which(cryptic_console_simple) of
        non_existing ->
            io:format("   ERROR: cryptic_console_simple module not found~n"),
            halt(1);
        Path2 ->
            io:format("   SUCCESS: Console module compiled at ~s~n", [Path2])
    end,

    %% 2. Test key generation and complete flow
    io:format("~n2. Testing complete flow...~n"),
    try
        %% Generate keys
        RootKey = crypto:strong_rand_bytes(32),
        AliceKeys = cryptic_nif:gen_keypair(),
        BobKeys = cryptic_nif:gen_keypair(),
        io:format("   SUCCESS: Generated root key and keypairs~n"),
        io:format("   Root key length: ~p bytes~n", [byte_size(RootKey)]),
        io:format("   Alice public key length: ~p bytes~n", [
            byte_size(element(1, AliceKeys))
        ]),
        io:format("   Bob public key length: ~p bytes~n", [
            byte_size(element(1, BobKeys))
        ]),

        %% 3. Test engine startup
        io:format("~n3. Testing engine startup...~n"),
        %% Start Alice engine
        CallbackMod = cryptic_console_simple,
        CallbackContext = #{},
        %%CallbackContext = #{verbose => true},
        {ok, AlicePid} = cryptic_ratchet_engine:start_link(
            CallbackMod, #{}, CallbackContext
        ),
        io:format("   SUCCESS: Alice engine started (PID: ~p)~n", [AlicePid]),

        %% Start Bob engine
        {ok, BobPid} = cryptic_ratchet_engine:start_link(
            cryptic_console_simple, #{}, #{}
        ),
        io:format("   SUCCESS: Bob engine started (PID: ~p)~n", [BobPid]),

        %% 4. Test initialization
        io:format("~n4. Testing engine initialization...~n"),
        ok = cryptic_ratchet_engine:init_as_sender(
            AlicePid, RootKey, AliceKeys
        ),
        io:format("   SUCCESS: Alice initialized as sender~n"),

        ok = cryptic_ratchet_engine:init_as_receiver(BobPid, RootKey, BobKeys),
        io:format("   SUCCESS: Bob initialized as receiver~n"),

        %% 5. Test state checking
        io:format("~n5. Testing state information...~n"),
        AliceState = cryptic_ratchet_engine:get_state_info(AlicePid),
        BobState = cryptic_ratchet_engine:get_state_info(BobPid),

        io:format("   Alice state: ~p~n", [maps:get(current_state, AliceState)]),
        io:format("   Bob state: ~p~n", [maps:get(current_state, BobState)]),

        %% 6. Test message encryption/decryption
        io:format("~n6. Testing message encryption/decryption...~n"),
        Message = <<"Hello from Alice to Bob!">>,

        {ok, EncryptedMsg} = cryptic_ratchet_engine:encrypt_message(
            AlicePid, Message
        ),
        io:format("   SUCCESS: Message encrypted (length: ~p bytes)~n", [
            byte_size(maps:get(ciphertext, EncryptedMsg))
        ]),

        {ok, DecryptedMsg} = cryptic_ratchet_engine:decrypt_message(
            BobPid, EncryptedMsg
        ),
        io:format("   SUCCESS: Message decrypted~n"),

        case DecryptedMsg =:= Message of
            true ->
                io:format("   SUCCESS: Message integrity verified~n");
            false ->
                io:format("   ERROR: Message integrity check failed~n"),
                halt(1)
        end,

        %% 7. Test bidirectional communication
        io:format("~n7. Testing bidirectional communication...~n"),
        Reply = <<"Hello back from Bob to Alice!">>,

        {ok, EncryptedReply} = cryptic_ratchet_engine:encrypt_message(
            BobPid, Reply
        ),
        io:format("   SUCCESS: Bob encrypted reply~n"),

        {ok, DecryptedReply} = cryptic_ratchet_engine:decrypt_message(
            AlicePid, EncryptedReply
        ),
        io:format("   SUCCESS: Alice decrypted reply~n"),

        case DecryptedReply =:= Reply of
            true ->
                io:format("   SUCCESS: Bidirectional communication verified~n");
            false ->
                io:format("   ERROR: Reply integrity check failed~n"),
                halt(1)
        end,

        %% Check final states
        AliceFinalState = cryptic_ratchet_engine:get_state_info(AlicePid),
        BobFinalState = cryptic_ratchet_engine:get_state_info(BobPid),

        io:format("   Alice final state: ~p~n", [
            maps:get(current_state, AliceFinalState)
        ]),
        io:format("   Bob final state: ~p~n", [
            maps:get(current_state, BobFinalState)
        ]),

        %% 8. Test debug information
        io:format("~n8. Testing debug information...~n"),
        AliceDebug = cryptic_ratchet_engine:get_debug_info(AlicePid),
        BobDebug = cryptic_ratchet_engine:get_debug_info(BobPid),

        io:format("   Alice messages processed: ~p~n", [
            maps:get(message_count, AliceDebug)
        ]),
        io:format("   Bob messages processed: ~p~n", [
            maps:get(message_count, BobDebug)
        ]),
        io:format("   Alice errors: ~p~n", [maps:get(error_count, AliceDebug)]),
        io:format("   Bob errors: ~p~n", [maps:get(error_count, BobDebug)]),

        %% Cleanup
        ok = cryptic_ratchet_engine:stop(AlicePid),
        ok = cryptic_ratchet_engine:stop(BobPid),
        io:format("   SUCCESS: Engines stopped cleanly~n"),

        io:format("~n=== ALL TESTS PASSED ===~n"),
        io:format("The Double Ratchet engine is fully functional!~n"),
        halt(0)
    catch
        Error2:Reason2:Stack ->
            io:format("   ERROR: ~p:~p~n", [Error2, Reason2]),
            io:format("   Stack: ~p~n", [Stack]),
            halt(1)
    end.

