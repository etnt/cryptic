%%% @doc Simple Console Interface for Double Ratchet Engine
%%%
%%% This module provides a simple command-line interface for testing
%%% the Double Ratchet state engine. Perfect for Lux test automation.
%%%
%%% Commands:
%%%   start_alice &lt;root_key&gt; &lt;dh_keypair&gt;
%%%   start_bob &lt;root_key&gt; &lt;dh_keypair&gt;
%%%   encrypt &lt;message&gt;
%%%   decrypt &lt;encrypted_message&gt;
%%%   status
%%%   debug
%%%   help
%%%   quit
%%%
%%% @author Cryptic Team
%%% @end

-module(cryptic_console_simple).
-behaviour(cryptic_ratchet_engine).

%% Public API
-export([
    start/0,
    start/1,
    main/1
]).

%% Callback exports
-export([
    handle_state_change/4,
    handle_message_event/4,
    handle_error/4,
    handle_debug_event/4,
    handle_lifecycle_event/3
]).

%% Internal state
-record(console_state, {
    engine_ref :: pid() | undefined,
    role :: alice | bob | undefined,
    message_count :: non_neg_integer(),
    verbose :: boolean()
}).

%%% ============================================================================
%%% Public API
%%% ============================================================================

%% @doc Start interactive console
start() ->
    start([]).

start(Args) ->
    main(Args).

%% @doc Main entry point for escript
main(Args) ->
    io:format("Cryptic Double Ratchet Console~n"),
    io:format("Type 'help' for commands~nArgs: ~p~n", [Args]),

    State = #console_state{
        message_count = 0,
        verbose = lists:member(verbose, Args)
    },

    command_loop(State).

%%% ============================================================================
%%% Command Loop
%%% ============================================================================

command_loop(State) ->
    case io:get_line("cryptic> ") of
        eof ->
            cleanup(State),
            ok;
        {error, _} ->
            cleanup(State),
            error;
        Line ->
            Command = string:trim(Line),
            case parse_command(Command) of
                {quit} ->
                    cleanup(State),
                    io:format("Goodbye!~n");
                {help} ->
                    show_help(),
                    command_loop(State);
                ParsedCmd ->
                    NewState = execute_command(ParsedCmd, State),
                    command_loop(NewState)
            end
    end.

%%% ============================================================================
%%% Command Parsing
%%% ============================================================================

parse_command("") ->
    {noop};
parse_command("help") ->
    {help};
parse_command("quit") ->
    {quit};
parse_command("exit") ->
    {quit};
parse_command("status") ->
    {status};
parse_command("debug") ->
    {debug};
parse_command("verbose") ->
    {verbose, toggle};
parse_command(Line) ->
    Parts = string:tokens(Line, " "),
    parse_command_parts(Parts).

parse_command_parts(["start_alice", RootKeyHex, PubKeyHex, PrivKeyHex]) ->
    try
        RootKey = hex_to_binary(RootKeyHex),
        PubKey = hex_to_binary(PubKeyHex),
        PrivKey = hex_to_binary(PrivKeyHex),
        {start_alice, RootKey, {PubKey, PrivKey}}
    catch
        _:_ -> {error, "Invalid hex format"}
    end;
parse_command_parts(["start_bob", RootKeyHex, PubKeyHex, PrivKeyHex]) ->
    try
        RootKey = hex_to_binary(RootKeyHex),
        PubKey = hex_to_binary(PubKeyHex),
        PrivKey = hex_to_binary(PrivKeyHex),
        {start_bob, RootKey, {PubKey, PrivKey}}
    catch
        _:_ -> {error, "Invalid hex format"}
    end;
parse_command_parts(["encrypt" | MessageParts]) ->
    Message = string:join(MessageParts, " "),
    {encrypt, list_to_binary(Message)};
parse_command_parts(["decrypt", EncryptedHex]) ->
    try
        % For simplicity, assume encrypted message is hex-encoded
        {decrypt, hex_to_binary(EncryptedHex)}
    catch
        _:_ -> {error, "Invalid encrypted message format"}
    end;
parse_command_parts(["generate_keys"]) ->
    {generate_keys};
parse_command_parts(["generate_root_key"]) ->
    {generate_root_key};
parse_command_parts(_) ->
    {error, "Unknown command"}.

%%% ============================================================================
%%% Command Execution
%%% ============================================================================

execute_command({noop}, State) ->
    State;
execute_command({error, Msg}, State) ->
    io:format("ERROR: ~s~n", [Msg]),
    State;
execute_command({start_alice, RootKey, DHKeyPair}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            case start_engine(State) of
                {ok, EngineRef, NewState} ->
                    case
                        cryptic_ratchet_engine:init_as_sender(
                            EngineRef, RootKey, DHKeyPair
                        )
                    of
                        ok ->
                            io:format("SUCCESS: Alice initialized~n"),
                            NewState#console_state{
                                engine_ref = EngineRef,
                                role = alice
                            };
                        {error, Reason} ->
                            io:format(
                                "ERROR: Failed to initialize Alice: ~p~n", [
                                    Reason
                                ]
                            ),
                            cryptic_ratchet_engine:stop(EngineRef),
                            State
                    end;
                {error, Reason} ->
                    io:format("ERROR: Failed to start engine: ~p~n", [Reason]),
                    State
            end;
        _ ->
            io:format("ERROR: Engine already started~n"),
            State
    end;
execute_command({start_bob, RootKey, DHKeyPair}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            case start_engine(State) of
                {ok, EngineRef, NewState} ->
                    case
                        cryptic_ratchet_engine:init_as_receiver(
                            EngineRef, RootKey, DHKeyPair
                        )
                    of
                        ok ->
                            io:format("SUCCESS: Bob initialized~n"),
                            NewState#console_state{
                                engine_ref = EngineRef,
                                role = bob
                            };
                        {error, Reason} ->
                            io:format(
                                "ERROR: Failed to initialize Bob: ~p~n", [
                                    Reason
                                ]
                            ),
                            cryptic_ratchet_engine:stop(EngineRef),
                            State
                    end;
                {error, Reason} ->
                    io:format("ERROR: Failed to start engine: ~p~n", [Reason]),
                    State
            end;
        _ ->
            io:format("ERROR: Engine already started~n"),
            State
    end;
execute_command({encrypt, Message}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            io:format("ERROR: No engine started. Use start_alice first.~n"),
            State;
        EngineRef ->
            case cryptic_ratchet_engine:encrypt_message(EngineRef, Message) of
                {ok, EncryptedMessage} ->
                    % For simplicity, output as hex
                    HexOutput = binary_to_hex(term_to_binary(EncryptedMessage)),
                    io:format("SUCCESS: ~s~n", [HexOutput]),
                    State#console_state{
                        message_count = State#console_state.message_count + 1
                    };
                {error, Reason} ->
                    io:format("ERROR: Encryption failed: ~p~n", [Reason]),
                    State
            end
    end;
execute_command({decrypt, EncryptedData}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            io:format("ERROR: No engine started. Use start_bob first.~n"),
            State;
        EngineRef ->
            try
                EncryptedMessage = binary_to_term(EncryptedData),
                case
                    cryptic_ratchet_engine:decrypt_message(
                        EngineRef, EncryptedMessage
                    )
                of
                    {ok, Plaintext} ->
                        io:format("SUCCESS: ~s~n", [Plaintext]),
                        State#console_state{
                            message_count =
                                State#console_state.message_count + 1
                        };
                    {error, Reason} ->
                        io:format("ERROR: Decryption failed: ~p~n", [Reason]),
                        State
                end
            catch
                _:_ ->
                    io:format("ERROR: Invalid encrypted message format~n"),
                    State
            end
    end;
execute_command({status}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            io:format("ENGINE: Not started~n"),
            io:format("ROLE: None~n"),
            io:format("MESSAGES: 0~n");
        EngineRef ->
            StateInfo = cryptic_ratchet_engine:get_state_info(EngineRef),
            io:format("ENGINE: Running (~p)~n", [EngineRef]),
            io:format("ROLE: ~p~n", [State#console_state.role]),
            io:format("STATE: ~p~n", [
                maps:get(current_state, StateInfo, unknown)
            ]),
            io:format("MESSAGES: ~p~n", [State#console_state.message_count]),
            io:format("ERRORS: ~p~n", [maps:get(error_count, StateInfo, 0)])
    end,
    State;
execute_command({debug}, State) ->
    case State#console_state.engine_ref of
        undefined ->
            io:format("ERROR: No engine started~n");
        EngineRef ->
            DebugInfo = cryptic_ratchet_engine:get_debug_info(EngineRef),
            io:format("DEBUG INFO:~n"),
            maps:fold(
                fun(K, V, _) ->
                    io:format("  ~p: ~p~n", [K, V])
                end,
                ok,
                DebugInfo
            )
    end,
    State;
execute_command({verbose, toggle}, State) ->
    NewVerbose = not State#console_state.verbose,
    io:format("Verbose mode: ~p~n", [NewVerbose]),
    State#console_state{verbose = NewVerbose};
execute_command({generate_keys}, State) ->
    {PubKey, PrivKey} = cryptic_nif:gen_keypair(),
    io:format("PUBLIC_KEY: ~s~n", [binary_to_hex(PubKey)]),
    io:format("PRIVATE_KEY: ~s~n", [binary_to_hex(PrivKey)]),
    State;
execute_command({generate_root_key}, State) ->
    RootKey = crypto:strong_rand_bytes(32),
    io:format("ROOT_KEY: ~s~n", [binary_to_hex(RootKey)]),
    State.

%%% ============================================================================
%%% Engine Management
%%% ============================================================================

start_engine(State) ->
    Config = #{
        verbose => State#console_state.verbose
    },
    case cryptic_ratchet_engine:start_link(?MODULE, #{}, Config) of
        {ok, EngineRef} ->
            % Subscribe to all events for simple logging
            cryptic_ratchet_engine:subscribe_events(
                EngineRef,
                [state_change, message_event, error, lifecycle]
            ),
            {ok, EngineRef, State};
        Error ->
            Error
    end.

cleanup(State) ->
    case State#console_state.engine_ref of
        undefined -> ok;
        EngineRef -> cryptic_ratchet_engine:stop(EngineRef)
    end.

%%% ============================================================================
%%% Callback Implementation (Simple Logging)
%%% ============================================================================

handle_state_change(_EngineRef, FromState, ToState, Context) ->
    case maps:get(verbose, Context, false) of
        true ->
            io:format("LOG: State change ~p -> ~p~n", [FromState, ToState]);
        false ->
            ok
    end,
    ok.

handle_message_event(_EngineRef, Event, _Data, Context) ->
    case maps:get(verbose, Context, false) of
        true ->
            io:format("LOG: Message event ~p~n", [Event]);
        false ->
            ok
    end,
    ok.

handle_error(_EngineRef, ErrorType, Error, _Context) ->
    io:format("LOG: Error (~p): ~p~n", [ErrorType, Error]),
    ok.

handle_debug_event(_EngineRef, Event, _Data, Context) ->
    case maps:get(verbose, Context, false) of
        true ->
            io:format("LOG: Debug event ~p~n", [Event]);
        false ->
            ok
    end,
    ok.

handle_lifecycle_event(_EngineRef, Event, Context) ->
    case maps:get(verbose, Context, false) of
        true ->
            io:format("LOG: Lifecycle event ~p~n", [Event]);
        false ->
            ok
    end,
    ok.

%%% ============================================================================
%%% Helper Functions
%%% ============================================================================

show_help() ->
    io:format("Available commands:~n"),
    io:format(
        "  generate_root_key                    - Generate a random root key~n"
    ),
    io:format("  generate_keys                        - Generate DH keypair~n"),
    io:format(
        "  start_alice <root_key> <pub> <priv>  - Initialize as Alice (sender)~n"
    ),
    io:format(
        "  start_bob <root_key> <pub> <priv>    - Initialize as Bob (receiver)~n"
    ),
    io:format("  encrypt <message>                    - Encrypt a message~n"),
    io:format("  decrypt <encrypted_hex>              - Decrypt a message~n"),
    io:format("  status                               - Show engine status~n"),
    io:format(
        "  debug                                - Show debug information~n"
    ),
    io:format(
        "  verbose                              - Toggle verbose logging~n"
    ),
    io:format("  help                                 - Show this help~n"),
    io:format("  quit                                 - Exit~n~n"),
    io:format("Note: Keys and encrypted data are in hexadecimal format~n").

%% @doc Convert binary to hex string
binary_to_hex(Binary) ->
    <<<<(hex_char(H)), (hex_char(L))>> || <<H:4, L:4>> <= Binary>>.

hex_char(N) when N < 10 -> $0 + N;
hex_char(N) -> $a + N - 10.

%% @doc Convert hex string to binary
hex_to_binary(HexString) ->
    HexList = binary_to_list(list_to_binary(HexString)),
    hex_string_to_binary(HexList).

hex_string_to_binary([]) ->
    <<>>;
hex_string_to_binary([H1, H2 | Rest]) ->
    Byte = hex_digit_to_int(H1) * 16 + hex_digit_to_int(H2),
    <<Byte, (hex_string_to_binary(Rest))/binary>>.

hex_digit_to_int(C) when C >= $0, C =< $9 -> C - $0;
hex_digit_to_int(C) when C >= $a, C =< $f -> C - $a + 10;
hex_digit_to_int(C) when C >= $A, C =< $F -> C - $A + 10.
