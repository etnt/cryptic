%%% @doc Console UI Callback Implementation for Ratchet Engine
%%%
%%% This module demonstrates how to implement a simple console-based UI
%%% for the Double Ratchet state engine using the callback API.
%%%
%%% @author Cryptic Team

-module(cryptic_console_ui_callback).
-behaviour(cryptic_ratchet_engine).

%% Callback exports
-export([
    handle_state_change/4,
    handle_message_event/4,
    handle_error/4,
    handle_debug_event/4,
    handle_lifecycle_event/3
]).

%% Public API for console UI
-export([
    start_session/1,
    stop_session/1,
    set_verbose/2
]).

-define(COLOR_GREEN, "\033[32m").
-define(COLOR_RED, "\033[31m").
-define(COLOR_YELLOW, "\033[33m").
-define(COLOR_BLUE, "\033[34m").
-define(COLOR_CYAN, "\033[36m").
-define(COLOR_RESET, "\033[0m").

%%% ============================================================================
%%% Public API
%%% ============================================================================

%% @doc Start a console UI session
start_session(Config) ->
    UIConfig = maps:merge(
        #{
            verbose => false,
            show_timestamps => true,
            color_output => true
        },
        Config
    ),

    case cryptic_ratchet_engine:start_link(?MODULE, #{}, UIConfig) of
        {ok, EngineRef} ->
            % Subscribe to all event types
            cryptic_ratchet_engine:subscribe_events(
                EngineRef,
                [state_change, message_event, error, debug, lifecycle]
            ),

            print_banner(UIConfig),
            io:format("Console session started. Engine: ~p~n", [EngineRef]),
            {ok, EngineRef};
        Error ->
            Error
    end.

%% @doc Stop console UI session
stop_session(EngineRef) ->
    io:format("Stopping console session...~n"),
    cryptic_ratchet_engine:stop(EngineRef).

%% @doc Set verbose mode
set_verbose(_EngineRef, Verbose) when is_boolean(Verbose) ->
    % This would update the callback context
    io:format("Verbose mode: ~p~n", [Verbose]),
    ok.

%%% ============================================================================
%%% Callback Implementation
%%% ============================================================================

%% @doc Handle state transitions
handle_state_change(_EngineRef, FromState, ToState, Context) ->
    Timestamp = format_timestamp(Context),
    Color = get_color(state_change, Context),

    io:format("~s[~s] State: ~s → ~s~s~n", [
        Color, Timestamp, FromState, ToState, get_reset(Context)
    ]),

    % Show additional context for certain transitions
    case {FromState, ToState} of
        {uninitialized, sender_init} ->
            io:format("  └─ Initialized as message sender (Alice)~n");
        {uninitialized, receiver_init} ->
            io:format("  └─ Initialized as message receiver (Bob)~n");
        {sender_init, sending_active} ->
            io:format(
                "  └─ First message sent, entering active sending mode~n"
            );
        {receiver_init, receiving_active} ->
            io:format(
                "  └─ First message received, entering active receiving mode~n"
            );
        {receiving_active, activating_send_chain} ->
            io:format(
                "  └─ Activating send chain for bidirectional communication~n"
            );
        {_, bidirectional} ->
            io:format("  └─ Full bidirectional communication enabled~n");
        {_, error_state} ->
            io:format("  └─ ERROR: Engine entered error state~n");
        _ ->
            ok
    end,

    ok.

%% @doc Handle message encryption/decryption events
handle_message_event(_EngineRef, Event, Data, Context) ->
    Timestamp = format_timestamp(Context),
    Color = get_color(message_event, Context),

    case Event of
        encrypt_success ->
            Size = maps:get(plaintext_size, Data, unknown),
            io:format("~s[~s] 🔐 Message encrypted (~p bytes)~s~n", [
                Color, Timestamp, Size, get_reset(Context)
            ]);
        encrypt_error ->
            Reason = maps:get(reason, Data, unknown),
            io:format("~s[~s] ❌ Encryption failed: ~p~s~n", [
                Color, Timestamp, Reason, get_reset(Context)
            ]);
        decrypt_success ->
            Size = maps:get(plaintext_size, Data, unknown),
            io:format("~s[~s] 🔓 Message decrypted (~p bytes)~s~n", [
                Color, Timestamp, Size, get_reset(Context)
            ]);
        decrypt_error ->
            Reason = maps:get(reason, Data, unknown),
            io:format("~s[~s] ❌ Decryption failed: ~p~s~n", [
                Color, Timestamp, Reason, get_reset(Context)
            ])
    end,

    % Show detailed info in verbose mode
    case maps:get(verbose, Context, false) of
        true ->
            show_verbose_message_info(Event, Data);
        false ->
            ok
    end,

    ok.

%% @doc Handle error conditions
handle_error(_EngineRef, ErrorType, Error, Context) ->
    Timestamp = format_timestamp(Context),
    Color = ?COLOR_RED,

    io:format("~s[~s] 🚨 ERROR (~p): ~p~s~n", [
        Color, Timestamp, ErrorType, Error, get_reset(Context)
    ]),

    % Provide helpful error explanations
    case ErrorType of
        protocol_error ->
            io:format(
                "  └─ Double Ratchet protocol error - check key material~n"
            );
        state_error ->
            io:format("  └─ Invalid operation for current state~n");
        crypto_error ->
            io:format("  └─ Cryptographic operation failed~n")
    end,

    ok.

%% @doc Handle debug/monitoring events
handle_debug_event(_EngineRef, Event, Data, Context) ->
    case maps:get(verbose, Context, false) of
        % Only show debug info in verbose mode
        false ->
            ok;
        true ->
            Timestamp = format_timestamp(Context),
            Color = get_color(debug, Context),

            case Event of
                performance_metric ->
                    io:format("~s[~s] 📊 Performance: ~p~s~n", [
                        Color, Timestamp, Data, get_reset(Context)
                    ]);
                state_info ->
                    show_state_info(Data, Context);
                transition_history ->
                    show_transition_history(Data, Context);
                custom ->
                    io:format("~s[~s] 🔍 Debug: ~p~s~n", [
                        Color, Timestamp, Data, get_reset(Context)
                    ])
            end
    end,
    ok.

%% @doc Handle engine lifecycle events
handle_lifecycle_event(_EngineRef, Event, Context) ->
    Timestamp = format_timestamp(Context),
    Color = get_color(lifecycle, Context),

    case Event of
        started ->
            io:format("~s[~s] 🚀 Ratchet engine started~s~n", [
                Color, Timestamp, get_reset(Context)
            ]);
        stopping ->
            FinalState = maps:get(final_state, Context, unknown),
            Reason = maps:get(reason, Context, normal),
            io:format(
                "~s[~s] 🛑 Engine stopping (state: ~p, reason: ~p)~s~n", [
                    Color, Timestamp, FinalState, Reason, get_reset(Context)
                ]
            );
        initialized ->
            io:format("~s[~s] ✅ Engine initialized and ready~s~n", [
                Color, Timestamp, get_reset(Context)
            ]);
        reset ->
            io:format("~s[~s] 🔄 Engine reset~s~n", [
                Color, Timestamp, get_reset(Context)
            ])
    end,
    ok.

%%% ============================================================================
%%% Helper Functions
%%% ============================================================================

%% @doc Print welcome banner
print_banner(Config) ->
    case maps:get(color_output, Config, true) of
        true ->
            io:format(
                "~n~s╔══════════════════════════════════════╗~s~n",
                [?COLOR_CYAN, ?COLOR_RESET]
            ),
            io:format(
                "~s║    Cryptic Double Ratchet Console    ║~s~n",
                [?COLOR_CYAN, ?COLOR_RESET]
            ),
            io:format(
                "~s╚══════════════════════════════════════╝~s~n~n",
                [?COLOR_CYAN, ?COLOR_RESET]
            );
        false ->
            io:format("~n=== Cryptic Double Ratchet Console ===~n~n")
    end.

%% @doc Format timestamp for display
format_timestamp(Context) ->
    case maps:get(show_timestamps, Context, true) of
        true ->
            {{_Y, _M, _D}, {H, Min, S}} = calendar:local_time(),
            io_lib:format("~2..0w:~2..0w:~2..0w", [H, Min, S]);
        false ->
            ""
    end.

%% @doc Get color for event type
get_color(EventType, Context) ->
    case maps:get(color_output, Context, true) of
        false ->
            "";
        true ->
            case EventType of
                state_change -> ?COLOR_BLUE;
                message_event -> ?COLOR_GREEN;
                error -> ?COLOR_RED;
                debug -> ?COLOR_YELLOW;
                lifecycle -> ?COLOR_CYAN;
                _ -> ""
            end
    end.

%% @doc Get color reset sequence
get_reset(Context) ->
    case maps:get(color_output, Context, true) of
        true -> ?COLOR_RESET;
        false -> ""
    end.

%% @doc Show verbose message information
show_verbose_message_info(Event, Data) ->
    case Event of
        encrypt_success ->
            _Message = maps:get(message, Data, #{}),
            io:format("    Message details: ~p~n", [
                maps:without([message], Data)
            ]);
        decrypt_success ->
            Plaintext = maps:get(plaintext, Data, <<"[hidden]">>),
            PlaintextPreview =
                case byte_size(Plaintext) > 20 of
                    true -> <<(binary_part(Plaintext, 0, 17))/binary, "...">>;
                    false -> Plaintext
                end,
            io:format("    Plaintext preview: ~p~n", [PlaintextPreview]);
        _ ->
            io:format("    Data: ~p~n", [Data])
    end.

%% @doc Show detailed state information
show_state_info(StateInfo, _Context) ->
    io:format("  📋 State Information:~n"),
    maps:fold(
        fun(K, V, _) ->
            io:format("    ~p: ~p~n", [K, V])
        end,
        ok,
        StateInfo
    ).

%% @doc Show transition history
show_transition_history(Transitions, _Context) ->
    io:format("  🔄 Recent Transitions:~n"),
    lists:foreach(
        fun(Transition) ->
            FromState = maps:get(from_state, Transition, unknown),
            ToState = maps:get(to_state, Transition, unknown),
            Event = maps:get(event, Transition, unknown),
            Duration = maps:get(duration_us, Transition, 0),
            io:format(
                "    ~p → ~p (~p) [~pμs]~n",
                [FromState, ToState, Event, Duration]
            )
        end,
        Transitions
    ).
