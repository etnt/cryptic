%%% @doc Reusable Double Ratchet State Engine with Callback API
%%%
%%% This module provides a production-ready, callback-based state engine for the
%%% Double Ratchet protocol. It implements a complete state machine using gen_statem
%%% behavior and enables integration into different UI contexts (console, ncurses,
%%% web, mobile, embedded) through a flexible callback mechanism.
%%%
%%% == Features ==
%%% <ul>
%%% <li>**Complete State Machine**: 8 states covering full Double Ratchet lifecycle</li>
%%% <li>**Callback Architecture**: Pluggable UI layer through behavior callbacks</li>
%%% <li>**Forward Secrecy**: Uses cryptographically secure Double Ratchet protocol</li>
%%% <li>**Error Recovery**: Comprehensive error handling with graceful fallback</li>
%%% <li>**Event Tracking**: Complete history of state transitions and events</li>
%%% <li>**Debug Support**: Rich debugging and monitoring capabilities</li>
%%% <li>**Concurrent Safe**: Handles multiple concurrent message operations</li>
%%% </ul>
%%% == State Machine Overview ==
%%%
%%% The engine implements the following state transitions:
%%%
%%% <pre>
%%%                    ┌─────────────────┐
%%%                    │  uninitialized  │
%%%                    └─────────┬───────┘
%%%                              │
%%%                    ┌─────────▼───────┐
%%%           ┌────────┤   init_call     ├────────┐
%%%           │        └─────────────────┘        │
%%%           │                                   │
%%%     ┌─────▼──────┐                     ┌──────▼──────┐
%%%     │sender_init │                     │receiver_init│
%%%     └─────┬──────┘                     └─────┬───────┘
%%%           │                                  │
%%%           │ encrypt_message                  │ decrypt_message
%%%           │                                  │
%%%     ┌─────▼──────┐                     ┌─────▼──────┐
%%%     │sending_    │◄────────────────────┤receiving_  │
%%%     │active      │    decrypt_message  │active      │
%%%     └─────┬──────┘                     └─────┬──────┘
%%%           │                                  │
%%%           │                                  │ encrypt_message
%%%           │                                  │ (DH ratchet)
%%%           │        ┌─────────────────┐       │
%%%           └────────►   bidirectional ◄───────┘
%%%                    └─────────────────┘
%%% </pre>
%%%
%%% == Usage Examples ==
%%%
%%% === Basic Alice-to-Bob Flow ===
%%%
%%% <pre>
%%% % Start engines for Alice and Bob
%%% {ok, AlicePid} = cryptic_ratchet_engine:start_link(my_callback, #{}, #{}),
%%% {ok, BobPid} = cryptic_ratchet_engine:start_link(my_callback, #{}, #{}),
%%%
%%% % Generate shared root key and keypairs
%%% RootKey = crypto:strong_rand_bytes(32),
%%% AliceKeys = cryptic_nif:gen_keypair(),
%%% BobKeys = cryptic_nif:gen_keypair(),
%%%
%%% % Initialize participants
%%% ok = cryptic_ratchet_engine:init_as_sender(AlicePid, RootKey, AliceKeys),
%%% ok = cryptic_ratchet_engine:init_as_receiver(BobPid, RootKey, BobKeys),
%%%
%%% % Alice sends first message
%%% {ok, Encrypted} = cryptic_ratchet_engine:encrypt_message(AlicePid, &lt;&lt;"Hello Bob">>),
%%%
%%% % Bob receives and decrypts
%%% {ok, &lt;&lt;"Hello Bob">>} = cryptic_ratchet_engine:decrypt_message(BobPid, Encrypted),
%%%
%%% % Now Bob can reply (triggers DH ratchet)
%%% {ok, Reply} = cryptic_ratchet_engine:encrypt_message(BobPid, &lt;&lt;"Hello Alice">>),
%%% {ok, &lt;&lt;"Hello Alice">>} = cryptic_ratchet_engine:decrypt_message(AlicePid, Reply),
%%%
%%% % Both are now in bidirectional state
%%% #{current_state := bidirectional} = cryptic_ratchet_engine:get_state_info(AlicePid),
%%% #{current_state := bidirectional} = cryptic_ratchet_engine:get_state_info(BobPid).
%%% </pre>
%%%
%%% === Implementing a Callback Module ===
%%%
%%% <pre>
%%% -module(my_ui_callback).
%%% -behaviour(cryptic_ratchet_engine).
%%%
%%% -export([handle_state_change/4, handle_message_event/4, handle_error/4]).
%%%
%%% handle_state_change(Engine, FromState, ToState, Context) ->
%%%     io:format("State: ~p -> ~p~n", [FromState, ToState]),
%%%     ok.
%%%
%%% handle_message_event(Engine, Event, Data, Context) ->
%%%     case Event of
%%%         encrypt_success ->
%%%             Size = maps:get(plaintext_size, Data),
%%%             io:format("Encrypted ~p bytes~n", [Size]);
%%%         decrypt_success ->
%%%             Msg = maps:get(plaintext, Data),
%%%             io:format("Decrypted: ~s~n", [Msg])
%%%     end,
%%%     ok.
%%%
%%% handle_error(Engine, ErrorType, Error, Context) ->
%%%     io:format("Error ~p: ~p~n", [ErrorType, Error]),
%%%     ok.
%%% </pre>
%%%
%%% == State Descriptions ==
%%%
%%% * `uninitialized` - Engine created but not yet configured for any role
%%% * `sender_init` - Alice initialized and ready to send first message
%%% * `receiver_init` - Bob initialized and waiting for first message
%%% * `sending_active` - Alice sending messages, can also decrypt Bob's replies
%%% * `receiving_active` - Bob receiving messages, can activate sending when ready
%%% * `activating_send_chain` - Temporary state during DH ratchet activation
%%% * `bidirectional` - Both parties can send and receive freely
%%% * `error_state` - Terminal error state for unrecoverable conditions
%%%
%%% == Callback Events ==
%%%
%%% Callback behavior for ratchet engine event handlers
%%% This behavior defines the interface that callback modules must implement
%%% to receive notifications from the Double Ratchet engine. All callbacks
%%% are called asynchronously and should not block. Callback errors are
%%% caught and ignored to prevent engine crashes.
%%%
%%% The callback module receives notifications for:
%%%
%%% * **State Changes**: `handle_state_change/4' - All state transitions
%%% * **Message Events**: `handle_message_event/4' - Encrypt/decrypt operations
%%% * **Errors**: `handle_error/4' - Protocol, state, and crypto errors
%%% * **Debug Events**: `handle_debug_event/4' - Performance and monitoring data
%%% * **Lifecycle**: `handle_lifecycle_event/3' - Engine start/stop events
%%%
%%% @author Cryptic Team
%%% @version 0.2.0
%%% @since 0.1.0
%%% @end

-module(cryptic_ratchet_engine).
-behaviour(gen_statem).

%% Public API
-export([
    start_link/2,
    start_link/3,
    init_as_sender/3,
    init_as_receiver/3,
    encrypt_message/2,
    decrypt_message/2,
    set_remote_dh_key/2,
    get_state_info/1,
    get_debug_info/1,
    set_callback_handler/2,
    subscribe_events/2,
    unsubscribe_events/2,
    stop/1
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3
]).

%% State function exports
-export([
    uninitialized/3,
    sender_init/3,
    receiver_init/3,
    sending_active/3,
    receiving_active/3,
    activating_send_chain/3,
    bidirectional/3,
    error_state/3
]).

-include("cryptic.hrl").

%%% ============================================================================
%%% Callback Behavior Definition
%%% ============================================================================

%%% Handle state transitions in the Double Ratchet protocol
%%%
%%% Called whenever the engine transitions between states. This is essential
%%% for UI updates to reflect the current protocol state.
%%%
%%% == Parameters ==
%%%
%%% * `EngineRef' - PID of the engine instance
%%% * `FromState' - Previous state (atom)
%%% * `ToState' - New current state (atom)
%%% * `Context' - Map with current engine context and metadata
%%%
%%% == Context Map ==
%%%
%%% The context map includes:
%%% * `current_state' - Current state name
%%% * `message_count' - Total messages processed
%%% * `error_count' - Total errors encountered
%%% * `uptime_ms' - Engine uptime in milliseconds
%%% * Plus any custom context from start_link/3
%%%
%%% == Example ==
%%%
%%% <pre>
%%% handle_state_change(Engine, sender_init, sending_active, Context) ->
%%%     MsgCount = maps:get(message_count, Context),
%%%     io:format("Alice sent first message (~p total)~n", [MsgCount]),
%%%     ok.
%%% </pre>
-callback handle_state_change(
    EngineRef :: pid(),
    FromState :: atom(),
    ToState :: atom(),
    Context :: map()
) ->
    ok | {error, term()}.

%%% Handle message encryption/decryption events
%%%
%%% Called for all message processing operations, both successful and failed.
%%% Essential for implementing message logging, UI feedback, and statistics.
%%%
%%% == Events ==
%%%
%%% * `encrypt_success' - Message successfully encrypted
%%% * `encrypt_error' - Encryption failed
%%% * `decrypt_success' - Message successfully decrypted
%%% * `decrypt_error' - Decryption failed
%%%
%%% == Data Map Contents ==
%%%
%%% For `encrypt_success':
%%% * `plaintext_size' - Size of original message in bytes
%%% * `message' - Encrypted message data
%%% * `dh_ratchet_performed' - Boolean, true if DH ratchet occurred
%%%
%%% For `decrypt_success':
%%% * `plaintext_size' - Size of decrypted message in bytes
%%% * `plaintext' - Decrypted message content
%%%
%%% For errors:
%%% * `reason' - Error reason atom or tuple
%%% * `stage' - Which stage failed (if applicable)
%%%
%%% == Example ==
%%%
%%% <pre>
%%% handle_message_event(Engine, encrypt_success, Data, Context) ->
%%%     Size = maps:get(plaintext_size, Data),
%%%     DH = maps:get(dh_ratchet_performed, Data, false),
%%%     Status = if DH -> " (DH ratchet)"; true -> "" end,
%%%     io:format("Encrypted ~p bytes~s~n", [Size, Status]),
%%%     ok.
%%% </pre>
-callback handle_message_event(
    EngineRef :: pid(),
    Event ::
        encrypt_success
        | encrypt_error
        | decrypt_success
        | decrypt_error,
    Data :: map(),
    Context :: map()
) ->
    ok | {error, term()}.

%%% Handle error conditions and exceptions
%%%
%%% Called when errors occur during protocol operations. Critical for
%%% debugging, logging, and providing user feedback for error conditions.
%%%
%%% == Error Types ==
%%%
%%% * `protocol_error' - Double Ratchet protocol violation or crypto failure
%%% * `state_error' - Invalid state transition or operation for current state
%%% * `crypto_error' - Low-level cryptographic operation failure or exception
%%%
%%% == Error Values ==
%%%
%%% * Atoms for simple errors: `not_initialized', `invalid_message', etc.
%%% * Tuples for complex errors: `{bad_key, Reason}', `{decrypt_failed, Details}'
%%% * Exception tuples: `{Class, Error, Stacktrace}' for caught exceptions
%%%
%%% == Example ==
%%%
%%% <pre>
%%% handle_error(Engine, state_error, not_initialized, Context) ->
%%%     io:format("Error: Engine not initialized for this operation~n"),
%%%     ok;
%%% handle_error(Engine, crypto_error, {Class, Error, _Stack}, Context) ->
%%%     io:format("Crypto error: ~p:~p~n", [Class, Error]),
%%%     ok.
%%% </pre>
-callback handle_error(
    EngineRef :: pid(),
    ErrorType :: protocol_error | state_error | crypto_error,
    Error :: term(),
    Context :: map()
) ->
    ok | {error, term()}.

%%% Handle debug and monitoring events
%%%
%%% Called for performance metrics, debugging information, and monitoring
%%% data. Useful for performance analysis, troubleshooting, and statistics.
%%%
%%% == Event Types ==
%%%
%%% * `performance_metric' - Timing and performance data
%%% * `state_info' - Current state information snapshot
%%% * `transition_history' - Recent state transition history
%%% * `custom' - Custom debug events from specific operations
%%%
%%% == Data Contents ==
%%%
%%% Varies by event type. May include timing data, state snapshots,
%%% transition records, or custom debugging information.
%%%
%%% == Example ==
%%%
%%% <pre>
%%% handle_debug_event(Engine, performance_metric, Data, Context) ->
%%%     case maps:get(operation, Data) of
%%%         encrypt ->
%%%             Duration = maps:get(duration_us, Data),
%%%             io:format("Encrypt took ~p μs~n", [Duration]);
%%%         _ ->
%%%             ok
%%%     end,
%%%     ok.
%%% </pre>
-callback handle_debug_event(
    EngineRef :: pid(),
    Event ::
        performance_metric
        | state_info
        | transition_history
        | custom,
    Data :: term(),
    Context :: map()
) ->
    ok | {error, term()}.

%%% Handle engine lifecycle events (optional)
%%%
%%% Called for major engine lifecycle events. Useful for resource management,
%%% logging, and coordination with external systems.
%%%
%%% == Lifecycle Events ==
%%%
%%% * `started' - Engine process started successfully
%%% * `stopping' - Engine is about to terminate
%%% * `stopped' - Engine has terminated (may not be received)
%%% * `initialized' - Engine initialized as sender or receiver
%%% * `reset' - Engine state has been reset (if implemented)
%%%
%%% == Context ==
%%%
%%% May include additional information like termination reason for `stopping'
%%% event, or initialization role for `initialized' event.
%%%
%%% == Example ==
%%%
%%% <pre>
%%% handle_lifecycle_event(Engine, initialized, Context) ->
%%%     Role = maps:get(role, Context, unknown),
%%%     io:format("Engine initialized as ~p~n", [Role]),
%%%     ok;
%%% handle_lifecycle_event(Engine, stopping, Context) ->
%%%     Reason = maps:get(reason, Context, normal),
%%%     io:format("Engine stopping: ~p~n", [Reason]),
%%%     ok.
%%% </pre>
-callback handle_lifecycle_event(
    EngineRef :: pid(),
    Event ::
        started
        | stopping
        | stopped
        | initialized
        | reset,
    Context :: map()
) ->
    ok | {error, term()}.

%% Make lifecycle callback optional
-optional_callbacks([handle_lifecycle_event/3]).

%%% ============================================================================
%%% ============================================================================
%%% Type Definitions
%%% ============================================================================

%% Reference to a Double Ratchet engine process. Use this to call engine functions.
-type engine_ref() :: pid().

%% Module name implementing the cryptic_ratchet_engine behavior for event callbacks.
-type callback_module() :: atom().

%% Types of events that can be subscribed to for direct message delivery.
-type event_type() :: state_change | message_event | error | debug | lifecycle.

%% Internal type representing an event subscription by a process.
-type subscription() :: {Pid :: pid(), Events :: [event_type()]}.

%%% ============================================================================
%%% Internal Record Definitions
%%% ============================================================================

%% Record for tracking individual events in the engine history
%%
%% Used internally to maintain a history of operations for debugging
%% and monitoring purposes. Events are stored in chronological order.
-record(event_record, {
    % Event data or description
    event :: term(),
    % State when event occurred
    state :: atom(),
    % When the event happened
    timestamp :: erlang:timestamp(),
    % Whether event succeeded
    result :: ok | error
}).

%% Record for tracking state transitions with timing information
%%
%% Maintains detailed history of state machine transitions including
%% timing data for performance analysis and debugging.
-record(transition_record, {
    % Previous state
    from_state :: atom(),
    % New state
    to_state :: atom(),
    % Event that triggered transition
    event :: term(),
    % When transition occurred
    timestamp :: erlang:timestamp(),
    % Time spent in previous state (μs)
    duration_us :: non_neg_integer()
}).

%% Main state record for the Double Ratchet engine
%%
%% This record contains all the internal state needed by the engine,
%% including cryptographic state, event history, callback configuration,
%% and performance metrics.
-record(engine_state, {
    % Core cryptographic state from Double Ratchet protocol
    ratchet_state :: cryptic_double_ratchet:ratchet_state() | undefined,

    % State machine metadata

    % Current state name
    current_state_name :: atom(),
    % When we entered current state
    state_enter_time :: erlang:timestamp(),

    % Event processing history (limited to last 100 entries)

    % Recent events
    event_history :: [#event_record{}],
    % Recent transitions
    transition_history :: [#transition_record{}],

    % Configuration and customization

    % Engine configuration options
    config :: map(),

    % Error tracking and statistics

    % Total errors encountered
    error_count :: non_neg_integer(),
    % Most recent error
    last_error :: term() | undefined,

    % Callback system for event notifications

    % Current callback module
    callback_module :: callback_module() | undefined,
    % Custom context for callbacks
    callback_context :: map(),
    % Direct message subscribers
    event_subscribers :: [subscription()],

    % Performance metrics and monitoring

    % Total messages processed
    message_count :: non_neg_integer(),
    % Engine start time
    start_time :: erlang:timestamp()
}).

%%% ============================================================================
%%% Public API
%%% ============================================================================

%%% @doc Start a Double Ratchet engine with callback module
%%%
%%% Creates and starts a new Double Ratchet engine instance with the specified
%%% callback module for event notifications. The engine starts in the
%%% `uninitialized' state and must be initialized as either sender or receiver.
%%%
%%% @param CallbackModule Module implementing the cryptic_ratchet_engine behavior
%%% @param Config Configuration map for engine behavior (currently unused)
%%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
%%%
%%% @see start_link/3
%%% @end
-spec start_link(callback_module(), map()) -> {ok, pid()} | {error, term()}.
start_link(CallbackModule, Config) ->
    start_link(CallbackModule, Config, #{}).

%% @doc Start a Double Ratchet engine with callback module and context
%%%
%%% Creates and starts a new Double Ratchet engine instance with custom
%%% callback context that will be passed to all callback functions.
%%%
%%% @param CallbackModule Module implementing the cryptic_ratchet_engine behavior
%%% @param Config Configuration map for engine behavior
%%% @param CallbackContext Custom context map passed to all callbacks
%%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
%%%
%%% == Example ==
%%%
%%% <pre>
%%% Context = #{ui_pid => self(), log_level => debug},
%%% {ok, Engine} = cryptic_ratchet_engine:start_link(my_callback, #{}, Context).
%%% </pre>
-spec start_link(callback_module(), map(), map()) ->
    {ok, pid()} | {error, term()}.
start_link(CallbackModule, Config, CallbackContext) ->
    InitArgs = #{
        callback_module => CallbackModule,
        callback_context => CallbackContext,
        config => Config
    },
    gen_statem:start_link(?MODULE, InitArgs, []).

%% @doc Initialize engine as message sender (Alice role)
%%%
%%% Initializes the engine to act as the message sender in a Double Ratchet
%%% session. This is typically the party that sends the first message.
%%% Transitions the engine from `uninitialized' to `sender_init' state.
%%%
%%% @param EngineRef PID of the engine process
%%% @param RootKey Shared 32-byte root key for the session
%%% @param DHKeyPair Diffie-Hellman keypair {PublicKey, PrivateKey}
%%% @returns `ok' on success, `{error, Reason}' on failure
%%%
%%% == Key Requirements ==
%%%
%%% * `RootKey' must be exactly 32 bytes of cryptographically secure random data
%%% * `DHKeyPair' must be a valid Curve25519 keypair from `cryptic_nif:gen_keypair()'
%%% * Both parties must use the same `RootKey'
%%%
%%% == Example ==
%%%
%%% <pre>
%%% RootKey = crypto:strong_rand_bytes(32),
%%% Keys = cryptic_nif:gen_keypair(),
%%% ok = cryptic_ratchet_engine:init_as_sender(Engine, RootKey, Keys).
%%% </pre>
-spec init_as_sender(engine_ref(), binary(), {binary(), binary()}) ->
    ok | {error, term()}.
init_as_sender(EngineRef, RootKey, DHKeyPair) ->
    gen_statem:call(EngineRef, {init_sender, RootKey, DHKeyPair}).

%% @doc Initialize engine as message receiver (Bob role)
%%%
%%% Initializes the engine to act as the message receiver in a Double Ratchet
%%% session. This is typically the party that receives the first message.
%%% Transitions the engine from `uninitialized' to `receiver_init' state.
%%%
%%% @param EngineRef PID of the engine process
%%% @param RootKey Shared 32-byte root key for the session (must match sender)
%%% @param DHKeyPair Diffie-Hellman keypair {PublicKey, PrivateKey}
%%% @returns `ok' on success, `{error, Reason}' on failure
%%%
%%% == Example ==
%%%
%%% <pre>
%%% % Same RootKey as sender, different DHKeyPair
%%% ok = cryptic_ratchet_engine:init_as_receiver(Engine, RootKey, BobKeys).
%%% </pre>
-spec init_as_receiver(engine_ref(), binary(), {binary(), binary()}) ->
    ok | {error, term()}.
init_as_receiver(EngineRef, RootKey, DHKeyPair) ->
    gen_statem:call(EngineRef, {init_receiver, RootKey, DHKeyPair}).

%% @doc Encrypt a plaintext message
%%%
%%% Encrypts a message using the Double Ratchet protocol, providing forward
%%% secrecy and post-compromise security. The operation behavior depends on
%%% the current engine state.
%%%
%%% @param EngineRef PID of the engine process
%%% @param Plaintext Binary message to encrypt (any length)
%%% @returns `{ok, EncryptedMessage}' or `{error, Reason}'
%%%
%%% == State Behavior ==
%%%
%%% * `sender_init' → `sending_active': First message from Alice
%%% * `sending_active': Continue sending (Alice)
%%% * `receiving_active' → `bidirectional': First message from Bob (DH ratchet)
%%% * `bidirectional': Normal bidirectional messaging
%%% * Other states: Returns `{error, invalid_state}'
%%%
%%% == Example ==
%%%
%%% <pre>
%%% {ok, Encrypted} = cryptic_ratchet_engine:encrypt_message(Engine, &lt;&lt;"Hello!">>),
%%% % Encrypted can be sent over any transport
%%% send_to_peer(Encrypted).
%%% </pre>
-spec encrypt_message(engine_ref(), binary()) ->
    {ok, term()} | {error, term()}.
encrypt_message(EngineRef, Plaintext) ->
    gen_statem:call(EngineRef, {encrypt_request, Plaintext}).

%% @doc Decrypt an encrypted message
%%%
%%% Decrypts a message received from the peer using the Double Ratchet protocol.
%%% Automatically handles key rotation and maintains forward secrecy.
%%%
%%% @param EngineRef PID of the engine process
%%% @param EncryptedMessage Message received from peer (from encrypt_message/2)
%%% @returns `{ok, Plaintext}' or `{error, Reason}'
%%%
%%% == State Behavior ==
%%%
%%% * `receiver_init' → `receiving_active': First message to Bob
%%% * `receiving_active': Continue receiving (Bob)
%%% * `sending_active' → `bidirectional': First message from Bob to Alice
%%% * `bidirectional': Normal bidirectional messaging
%%% * Other states: Returns `{error, invalid_state}'
%%%
%%% == Error Cases ==
%%%
%%% * `{error, invalid_message}' - Corrupted or invalid encrypted message
%%% * `{error, key_mismatch}' - Message not for this session
%%% * `{error, replay_attack}' - Old message replayed
%%%
%%% == Example ==
%%%
%%% <pre>
%%% % Receive encrypted message from peer
%%% Encrypted = receive_from_peer(),
%%% {ok, &lt;&lt;"Hello!">>} = cryptic_ratchet_engine:decrypt_message(Engine, Encrypted).
%%% </pre>
-spec decrypt_message(engine_ref(), term()) ->
    {ok, binary()} | {error, term()}.
decrypt_message(EngineRef, EncryptedMessage) ->
    gen_statem:call(EngineRef, {decrypt_request, EncryptedMessage}).

%% @doc Set the remote peer's DH ratchet public key
%%%
%%% This is used when the sender includes their DH ratchet public key in the X3DH metadata.
%%% It allows the receiver to activate the sending chain immediately without waiting for
%%% a ratchet-encrypted message from the sender.
%%%
%%% @param EngineRef PID of the engine process
%%% @param RemoteDHPub Sender's DH ratchet public key (32 bytes)
%%% @returns `ok' or `{error, Reason}'
-spec set_remote_dh_key(engine_ref(), binary()) -> ok | {error, term()}.
set_remote_dh_key(EngineRef, RemoteDHPub) when byte_size(RemoteDHPub) =:= 32 ->
    gen_statem:call(EngineRef, {set_remote_dh_key, RemoteDHPub}).

%% @doc Get current engine state information
%%%
%%% Returns a map containing the current state of the engine, including
%%% protocol state, message counts, error statistics, and timing information.
%%%
%%% @param EngineRef PID of the engine process
%%% @returns Map with current state information
%%%
%%% == Return Map Keys ==
%%%
%%% * `current_state' - Current state atom
%%% * `error_count' - Total number of errors encountered
%%% * `transition_count' - Number of state transitions performed
%%% * `message_count' - Total messages processed (sent + received)
%%% * Additional keys may be present from underlying ratchet state
%%%
%%% == Example ==
%%%
%%% <pre>
%%% Info = cryptic_ratchet_engine:get_state_info(Engine),
%%% CurrentState = maps:get(current_state, Info),
%%% MsgCount = maps:get(message_count, Info),
%%% io:format("State: ~p, Messages: ~p~n", [CurrentState, MsgCount]).
%%% </pre>
-spec get_state_info(engine_ref()) -> map().
get_state_info(EngineRef) ->
    gen_statem:call(EngineRef, get_state_info).

%% @doc Get detailed debug information
%%%
%%% Returns comprehensive debugging and monitoring information about the
%%% engine state, including performance metrics, event history, and
%%% internal state details.
%%%
%%% @param EngineRef PID of the engine process
%%% @returns Map with debug information
%%%
%%% == Debug Information ==
%%%
%%% * `current_state' - Current state atom
%%% * `state_enter_time' - When current state was entered
%%% * `error_count' - Total errors and last error details
%%% * `transition_count' - Number of transitions and recent history
%%% * `event_count' - Number of events and recent event history
%%% * `config' - Engine configuration
%%% * `callback_module' - Currently active callback module
%%% * `subscriber_count' - Number of event subscribers
%%%
%%% == Example ==
%%%
%%% <pre>
%%% Debug = cryptic_ratchet_engine:get_debug_info(Engine),
%%% Transitions = maps:get(recent_transitions, Debug),
%%% Events = maps:get(recent_events, Debug),
%%% % Analyze performance or troubleshoot issues
%%% </pre>
-spec get_debug_info(engine_ref()) -> map().
get_debug_info(EngineRef) ->
    gen_statem:call(EngineRef, get_debug_info).

%% @doc Set or change the callback handler module
%%%
%%% Changes the callback module used for event notifications. All future
%%% events will be sent to the new callback module.
%%%
%%% @param EngineRef PID of the engine process
%%% @param CallbackModule New module implementing cryptic_ratchet_engine behavior
%%% @returns `ok' or `{error, Reason}'
%%%
%%% == Use Cases ==
%%%
%%% * Switch between different UI implementations
%%% * Enable/disable different levels of event handling
%%% * Dynamically change callback behavior based on application state
%%%
%%% == Example ==
%%%
%%% <pre>
%%% % Switch from console to GUI callback
%%% ok = cryptic_ratchet_engine:set_callback_handler(Engine, gui_callback).
%%% </pre>
-spec set_callback_handler(engine_ref(), callback_module()) ->
    ok | {error, term()}.
set_callback_handler(EngineRef, CallbackModule) ->
    gen_statem:call(EngineRef, {set_callback_handler, CallbackModule}).

%% @doc Subscribe to specific event types via direct messages
%%%
%%% Subscribe the calling process to receive direct Erlang messages for
%%% specific event types. This is an alternative to callback functions
%%% for processes that want direct event delivery.
%%%
%%% @param EngineRef PID of the engine process
%%% @param EventTypes List of event types to subscribe to
%%% @returns `ok'
%%%
%%% == Event Types ==
%%%
%%% * `state_change' - State transition events
%%% * `message_event' - Encrypt/decrypt operation events
%%% * `error' - Error condition events
%%% * `debug' - Debug and monitoring events
%%% * `lifecycle' - Engine lifecycle events
%%%
%%% == Message Format ==
%%%
%%% Messages are sent as: `{ratchet_engine_event, EnginePid, EventType, EventData}'
%%%
%%% == Example ==
%%%
%%% <pre>
%%% ok = cryptic_ratchet_engine:subscribe_events(Engine, [state_change, error]),
%%% receive
%%%     {ratchet_engine_event, Engine, state_change, Data} ->
%%%         handle_state_change(Data);
%%%     {ratchet_engine_event, Engine, error, Data} ->
%%%         handle_error(Data)
%%% end.
%%% </pre>
-spec subscribe_events(engine_ref(), [event_type()]) -> ok.
subscribe_events(EngineRef, EventTypes) ->
    gen_statem:call(EngineRef, {subscribe_events, self(), EventTypes}).

%% @doc Unsubscribe from event type messages
%%%
%%% Remove subscription for the calling process, stopping direct message
%%% delivery for the specified event types.
%%%
%%% @param EngineRef PID of the engine process
%%% @param EventTypes List of event types to unsubscribe from (ignored, removes all)
%%% @returns `ok'
%%%
%%% Note: Currently removes ALL subscriptions for the calling process.
-spec unsubscribe_events(engine_ref(), [event_type()]) -> ok.
unsubscribe_events(EngineRef, EventTypes) ->
    gen_statem:call(EngineRef, {unsubscribe_events, self(), EventTypes}).

%% @doc Stop the engine gracefully
%%%
%%% Stops the engine process gracefully, allowing it to clean up resources
%%% and notify callbacks of the shutdown.
%%%
%%% @param EngineRef PID of the engine process
%%% @returns `ok'
%%%
%%% == Cleanup ==
%%%
%%% * Sends `stopping' lifecycle event to callbacks
%%% * Cleans up internal state and timers
%%% * Terminates the gen_statem process
%%%
%%% == Example ==
%%%
%%% <pre>
%%% ok = cryptic_ratchet_engine:stop(Engine).
%%% % Engine process is now terminated
%%% </pre>
-spec stop(engine_ref()) -> ok.
stop(EngineRef) ->
    gen_statem:stop(EngineRef).

%%% ============================================================================
%%% gen_statem Behavior Callbacks
%%% ============================================================================

%% @doc Initialize the Double Ratchet engine state machine
%%
%% Called by gen_statem when the engine process starts. Initializes all
%% internal state and notifies the callback module that the engine has started.
%%
%% @private
init(#{
    callback_module := CallbackModule,
    callback_context := CallbackContext,
    config := Config
}) ->
    StateData = #engine_state{
        current_state_name = uninitialized,
        state_enter_time = erlang:timestamp(),
        event_history = [],
        transition_history = [],
        config = Config,
        error_count = 0,
        callback_module = CallbackModule,
        callback_context = CallbackContext,
        event_subscribers = [],
        message_count = 0,
        start_time = erlang:timestamp()
    },

    % Notify callback of engine start
    notify_lifecycle_event(started, StateData),

    {ok, uninitialized, StateData}.

%% @doc Specify gen_statem callback mode
%%
%% Uses state_functions mode where each state has its own function.
%% This provides clear separation of state-specific logic and makes
%% the state machine easier to understand and maintain.
%%
%% @private
callback_mode() ->
    state_functions.

%% @doc Handle engine process termination
%%
%% Called when the engine process is stopping. Notifies callbacks
%% of the termination with contextual information about the reason
%% and final state.
%%
%% @private
terminate(Reason, StateName, StateData) ->
    % Notify callback of engine stopping
    Context = maps:put(reason, Reason, StateData#engine_state.callback_context),
    Context2 = maps:put(final_state, StateName, Context),
    notify_lifecycle_event(stopping, StateData#engine_state{
        callback_context = Context2
    }),
    ok.

%%% ============================================================================
%%% State Machine Functions
%%% ============================================================================

%% @doc Uninitialized state - waiting for role initialization
%%
%% Initial state of the engine. Only accepts initialization calls to
%% set the engine role as either sender (Alice) or receiver (Bob).
%% All other operations return appropriate error responses.
%%
%% == Valid Transitions ==
%%
%% * `init_sender' → `sender_init'
%% * `init_receiver' → `receiver_init'
%% * All other operations → error response
%%
%% @private
uninitialized(enter, _OldState, StateData) ->
    NewStateData = record_state_enter(uninitialized, StateData),
    {keep_state, NewStateData};
uninitialized({call, From}, {init_sender, RootKey, DHKeyPair}, StateData) ->
    try
        case cryptic_double_ratchet:init_sender(RootKey, DHKeyPair) of
            {ok, RatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = RatchetState
                },

                % Record transition and notify callbacks
                TransitionData = record_transition(
                    uninitialized, sender_init, {init_sender}, NewStateData
                ),

                notify_state_change(uninitialized, sender_init, TransitionData),
                notify_lifecycle_event(initialized, TransitionData),

                Actions = [{reply, From, ok}],
                {next_state, sender_init, TransitionData, Actions};
            {error, Reason} ->
                notify_error(protocol_error, Reason, StateData),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
uninitialized({call, From}, {init_receiver, RootKey, DHKeyPair}, StateData) ->
    try
        case cryptic_double_ratchet:init_receiver(RootKey, DHKeyPair) of
            {ok, RatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = RatchetState
                },

                TransitionData = record_transition(
                    uninitialized, receiver_init, {init_receiver}, NewStateData
                ),

                notify_state_change(
                    uninitialized, receiver_init, TransitionData
                ),
                notify_lifecycle_event(initialized, TransitionData),

                Actions = [{reply, From, ok}],
                {next_state, receiver_init, TransitionData, Actions};
            {error, Reason} ->
                notify_error(protocol_error, Reason, StateData),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
uninitialized({call, From}, {encrypt_request, _}, StateData) ->
    notify_error(state_error, not_initialized, StateData),
    {keep_state, StateData, [{reply, From, {error, not_initialized}}]};
uninitialized({call, From}, {decrypt_request, _}, StateData) ->
    notify_error(state_error, not_initialized, StateData),
    {keep_state, StateData, [{reply, From, {error, not_initialized}}]};
uninitialized(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, uninitialized, StateData).

%% @doc Sender initial state - Alice ready to send first message
%%
%% State for Alice after initialization. Can immediately encrypt and send
%% the first message to Bob, which will trigger the initial DH ratchet step.
%%
%% == Valid Operations ==
%%
%% * `encrypt_message' → `sending_active' (first message)
%% * `decrypt_message' → error (Bob hasn't sent anything yet)
%% * State queries and debug operations work normally
%%
%% == Protocol Notes ==
%%
%% The first encrypt operation establishes the initial sending chain
%% and transitions to `sending_active' state. Bob must decrypt this
%% message before he can send messages back.
%%
%% @private
sender_init(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(sender_init, StateData)};
sender_init({call, From}, {encrypt_request, Plaintext}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:encrypt_message(Plaintext, RatchetState) of
            {ok, Message, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                TransitionData = record_transition(
                    sender_init, sending_active, {encrypt_request}, NewStateData
                ),

                % Notify callbacks
                notify_state_change(
                    sender_init, sending_active, TransitionData
                ),
                notify_message_event(
                    encrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        message => Message
                    },
                    TransitionData
                ),

                Actions = [{reply, From, {ok, Message}}],
                {next_state, sending_active, TransitionData, Actions};
            {error, Reason} ->
                notify_message_event(
                    encrypt_error,
                    #{
                        reason => Reason,
                        plaintext_size => byte_size(Plaintext)
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
sender_init({call, From}, {decrypt_request, Message}, StateData) ->
    % With X3DH ephemeral key as initial DH key, Bob can reply immediately
    % Alice transitions sender_init → bidirectional when receiving Bob's first message
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:decrypt_message(Message, RatchetState) of
            {ok, Plaintext, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                TransitionData = record_transition(
                    sender_init, bidirectional, {decrypt_request}, NewStateData
                ),

                % Notify callbacks - Alice can now both send and receive
                notify_state_change(
                    sender_init, bidirectional, TransitionData
                ),
                notify_message_event(
                    decrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        plaintext => Plaintext
                    },
                    TransitionData
                ),

                Actions = [{reply, From, {ok, Plaintext}}],
                {next_state, bidirectional, TransitionData, Actions};
            {error, Reason} ->
                notify_message_event(
                    decrypt_error,
                    #{reason => Reason},
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
sender_init(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, sender_init, StateData).

%% Continue with other states... (abbreviated for space)
%% The pattern would be similar - add callback notifications to each state function

%%% ============================================================================
%%% Callback Management Functions
%%% ============================================================================

%% @doc Notify callback module of state change
notify_state_change(FromState, ToState, StateData) ->
    case StateData#engine_state.callback_module of
        undefined ->
            ok;
        CallbackModule ->
            Context = create_callback_context(StateData),
            try
                CallbackModule:handle_state_change(
                    self(), FromState, ToState, Context
                )
            catch
                % Ignore callback errors to prevent engine crashes
                _:_ -> ok
            end
    end,
    notify_subscribers(
        state_change,
        #{
            from_state => FromState,
            to_state => ToState,
            timestamp => erlang:timestamp()
        },
        StateData
    ).

%% @doc Notify callback module of message events
notify_message_event(Event, Data, StateData) ->
    case StateData#engine_state.callback_module of
        undefined ->
            ok;
        CallbackModule ->
            Context = create_callback_context(StateData),
            try
                CallbackModule:handle_message_event(
                    self(), Event, Data, Context
                )
            catch
                _:_ -> ok
            end
    end,
    notify_subscribers(
        message_event,
        #{
            event => Event,
            data => Data,
            timestamp => erlang:timestamp()
        },
        StateData
    ).

%% @doc Notify callback module of errors
notify_error(ErrorType, Error, StateData) ->
    case StateData#engine_state.callback_module of
        undefined ->
            ok;
        CallbackModule ->
            Context = create_callback_context(StateData),
            try
                CallbackModule:handle_error(self(), ErrorType, Error, Context)
            catch
                _:_ -> ok
            end
    end,
    notify_subscribers(
        error,
        #{
            error_type => ErrorType,
            error => Error,
            timestamp => erlang:timestamp()
        },
        StateData
    ).

%% @doc Notify callback module of lifecycle events
notify_lifecycle_event(Event, StateData) ->
    case StateData#engine_state.callback_module of
        undefined ->
            ok;
        CallbackModule ->
            Context = create_callback_context(StateData),
            try
                case
                    erlang:function_exported(
                        CallbackModule, handle_lifecycle_event, 3
                    )
                of
                    true ->
                        CallbackModule:handle_lifecycle_event(
                            self(), Event, Context
                        );
                    false ->
                        ok
                end
            catch
                _:_ -> ok
            end
    end,
    notify_subscribers(
        lifecycle,
        #{
            event => Event,
            timestamp => erlang:timestamp()
        },
        StateData
    ).

%% @doc Notify event subscribers
notify_subscribers(EventType, EventData, StateData) ->
    Subscribers = StateData#engine_state.event_subscribers,
    lists:foreach(
        fun({Pid, EventTypes}) ->
            case lists:member(EventType, EventTypes) of
                true ->
                    try
                        Pid !
                            {ratchet_engine_event, self(), EventType, EventData}
                    catch
                        % Ignore send failures
                        _:_ -> ok
                    end;
                false ->
                    ok
            end
        end,
        Subscribers
    ).

%% @doc Create callback context map
create_callback_context(StateData) ->
    maps:merge(StateData#engine_state.callback_context, #{
        current_state => StateData#engine_state.current_state_name,
        message_count => StateData#engine_state.message_count,
        error_count => StateData#engine_state.error_count,
        uptime_ms => timer:now_diff(
            erlang:timestamp(), StateData#engine_state.start_time
        ) div 1000
    }).

%%% ============================================================================
%%% Common Event Handling & Helper Functions
%%% ============================================================================

handle_common_event({call, From}, get_state_info, StateName, StateData) ->
    StateInfo = create_state_info(StateName, StateData),
    {keep_state, StateData, [{reply, From, StateInfo}]};
handle_common_event({call, From}, get_debug_info, _StateName, StateData) ->
    DebugInfo = create_debug_info(StateData),
    notify_debug_event(state_info, DebugInfo, StateData),
    {keep_state, StateData, [{reply, From, DebugInfo}]};
handle_common_event(
    {call, From}, {set_callback_handler, CallbackModule}, _StateName, StateData
) ->
    NewStateData = StateData#engine_state{callback_module = CallbackModule},
    {keep_state, NewStateData, [{reply, From, ok}]};
handle_common_event(
    {call, From}, {subscribe_events, Pid, EventTypes}, _StateName, StateData
) ->
    Subscribers = StateData#engine_state.event_subscribers,
    % Remove existing subscription for this Pid, then add new one
    CleanedSubscribers = lists:keydelete(Pid, 1, Subscribers),
    NewSubscribers = [{Pid, EventTypes} | CleanedSubscribers],
    NewStateData = StateData#engine_state{event_subscribers = NewSubscribers},
    {keep_state, NewStateData, [{reply, From, ok}]};
handle_common_event(
    {call, From}, {unsubscribe_events, Pid, _EventTypes}, _StateName, StateData
) ->
    Subscribers = StateData#engine_state.event_subscribers,
    NewSubscribers = lists:keydelete(Pid, 1, Subscribers),
    NewStateData = StateData#engine_state{event_subscribers = NewSubscribers},
    {keep_state, NewStateData, [{reply, From, ok}]};
handle_common_event(_EventType, _Event, _StateName, StateData) ->
    {keep_state, StateData}.

%% @doc Notify debug events
notify_debug_event(Event, Data, StateData) ->
    case StateData#engine_state.callback_module of
        undefined ->
            ok;
        CallbackModule ->
            Context = create_callback_context(StateData),
            try
                CallbackModule:handle_debug_event(self(), Event, Data, Context)
            catch
                _:_ -> ok
            end
    end.

%% Helper functions (record_state_enter, record_transition, etc.)
%% These would be similar to the prototype but with added callback notifications

record_state_enter(StateName, StateData) ->
    StateData#engine_state{
        current_state_name = StateName,
        state_enter_time = erlang:timestamp()
    }.

record_transition(FromState, ToState, Event, StateData) ->
    Timestamp = erlang:timestamp(),
    Duration =
        case StateData#engine_state.state_enter_time of
            undefined -> 0;
            StartTime -> timer:now_diff(Timestamp, StartTime)
        end,

    Transition = #transition_record{
        from_state = FromState,
        to_state = ToState,
        event = Event,
        timestamp = Timestamp,
        duration_us = Duration
    },

    Transitions = [Transition | StateData#engine_state.transition_history],
    StateData#engine_state{
        % Keep last 100
        transition_history = lists:sublist(Transitions, 100),
        current_state_name = ToState,
        state_enter_time = Timestamp
    }.

record_error(Error, StateData) ->
    StateData#engine_state{
        error_count = StateData#engine_state.error_count + 1,
        last_error = Error
    }.

record_event(Event, Result, StateData) ->
    Timestamp = erlang:timestamp(),
    EventRecord = #event_record{
        event = Event,
        state = StateData#engine_state.current_state_name,
        timestamp = Timestamp,
        result = Result
    },

    Events = [EventRecord | StateData#engine_state.event_history],
    StateData#engine_state{
        % Keep last 100 events
        event_history = lists:sublist(Events, 100)
    }.

create_state_info(StateName, StateData) ->
    BaseInfo = #{
        current_state => StateName,
        error_count => StateData#engine_state.error_count,
        transition_count => length(StateData#engine_state.transition_history),
        message_count => StateData#engine_state.message_count
    },

    case StateData#engine_state.ratchet_state of
        undefined ->
            BaseInfo;
        RatchetState ->
            case cryptic_double_ratchet:get_state_info(RatchetState) of
                {error, _} ->
                    BaseInfo;
                RatchetInfo when is_map(RatchetInfo) ->
                    ?dbg("Ratchet Info: ~p~n", [RatchetInfo]),
                    maps:merge(BaseInfo, RatchetInfo);
                _ ->
                    BaseInfo
            end
    end.

create_debug_info(StateData) ->
    #{
        current_state => StateData#engine_state.current_state_name,
        state_enter_time => StateData#engine_state.state_enter_time,
        error_count => StateData#engine_state.error_count,
        last_error => StateData#engine_state.last_error,
        transition_count => length(StateData#engine_state.transition_history),
        recent_transitions => lists:sublist(
            StateData#engine_state.transition_history, 5
        ),
        event_count => length(StateData#engine_state.event_history),
        recent_events => lists:sublist(
            StateData#engine_state.event_history, 10
        ),
        config => StateData#engine_state.config,
        message_count => StateData#engine_state.message_count,
        callback_module => StateData#engine_state.callback_module,
        subscriber_count => length(StateData#engine_state.event_subscribers)
    }.

%% @doc Receiver initial state - can only decrypt initially
receiver_init(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(receiver_init, StateData)};
receiver_init({call, From}, {decrypt_request, Message}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:decrypt_message(Message, RatchetState) of
            {ok, Plaintext, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                TransitionData = record_transition(
                    receiver_init,
                    receiving_active,
                    {decrypt_request},
                    NewStateData
                ),

                % Notify callbacks
                notify_state_change(
                    receiver_init, receiving_active, TransitionData
                ),
                notify_message_event(
                    decrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        plaintext => Plaintext
                    },
                    TransitionData
                ),

                Actions = [{reply, From, {ok, Plaintext}}],
                {next_state, receiving_active, TransitionData, Actions};
            {error, Reason} ->
                notify_message_event(
                    decrypt_error,
                    #{
                        reason => Reason
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
receiver_init({call, From}, {encrypt_request, _Plaintext}, StateData) ->
    % Receiver needs to activate sending chain first
    notify_error(state_error, must_receive_first, StateData),
    {keep_state, StateData, [{reply, From, {error, must_receive_first}}]};
receiver_init({call, From}, {set_remote_dh_key, RemoteDHPub}, StateData) ->
    % Set the remote DH key in the ratchet state to enable sending
    RatchetState = StateData#engine_state.ratchet_state,
    try
        NewRatchetState = cryptic_double_ratchet:set_remote_dh_key(RatchetState, RemoteDHPub),
        NewStateData = StateData#engine_state{
            ratchet_state = NewRatchetState
        },
        
        % Transition to bidirectional since we can now both send and receive
        TransitionData = record_transition(
            receiver_init,
            bidirectional,
            {set_remote_dh_key},
            NewStateData
        ),
        
        notify_state_change(receiver_init, bidirectional, TransitionData),
        
        Actions = [{reply, From, ok}],
        {next_state, bidirectional, TransitionData, Actions}
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
receiver_init(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, receiver_init, StateData).

%% @doc Sending active state - primarily sending messages
sending_active(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(sending_active, StateData)};
sending_active({call, From}, {encrypt_request, Plaintext}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:encrypt_message(Plaintext, RatchetState) of
            {ok, Message, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                % Notify callbacks but stay in sending_active state
                notify_message_event(
                    encrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        message => Message
                    },
                    NewStateData
                ),

                Actions = [{reply, From, {ok, Message}}],
                {keep_state, record_event({encrypt_request}, ok, NewStateData),
                    Actions};
            {error, Reason} ->
                notify_message_event(
                    encrypt_error,
                    #{
                        reason => Reason,
                        plaintext_size => byte_size(Plaintext)
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
sending_active({call, From}, {decrypt_request, Message}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:decrypt_message(Message, RatchetState) of
            {ok, Plaintext, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                TransitionData = record_transition(
                    sending_active,
                    bidirectional,
                    {decrypt_request},
                    NewStateData
                ),

                % Notify callbacks - now bidirectional!
                notify_state_change(
                    sending_active, bidirectional, TransitionData
                ),
                notify_message_event(
                    decrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        plaintext => Plaintext
                    },
                    TransitionData
                ),

                Actions = [{reply, From, {ok, Plaintext}}],
                {next_state, bidirectional, TransitionData, Actions};
            {error, Reason} ->
                notify_message_event(
                    decrypt_error,
                    #{
                        reason => Reason
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
sending_active(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, sending_active, StateData).

%% @doc Receiving active state - primarily receiving messages
receiving_active(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(receiving_active, StateData)};
receiving_active({call, From}, {decrypt_request, Message}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:decrypt_message(Message, RatchetState) of
            {ok, Plaintext, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                % Notify callbacks but stay in receiving_active state
                notify_message_event(
                    decrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        plaintext => Plaintext
                    },
                    NewStateData
                ),

                Actions = [{reply, From, {ok, Plaintext}}],
                {keep_state, record_event({decrypt_request}, ok, NewStateData),
                    Actions};
            {error, Reason} ->
                notify_message_event(
                    decrypt_error,
                    #{
                        reason => Reason
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
receiving_active({call, From}, {encrypt_request, Plaintext}, StateData) ->
    % Need to activate sending chain (triggers DH ratchet)
    RatchetState = StateData#engine_state.ratchet_state,

    % Transition to activating_send_chain state first
    TransitionData = record_transition(
        receiving_active, activating_send_chain, {encrypt_request}, StateData
    ),

    notify_state_change(
        receiving_active, activating_send_chain, TransitionData
    ),

    % Perform the activation and encryption
    try
        case cryptic_double_ratchet:activate_sending_chain(RatchetState) of
            {ok, ActivatedRatchetState} ->
                % Now try encryption
                case
                    cryptic_double_ratchet:encrypt_message(
                        Plaintext, ActivatedRatchetState
                    )
                of
                    {ok, Message, NewRatchetState} ->
                        NewStateData = TransitionData#engine_state{
                            ratchet_state = NewRatchetState,
                            message_count =
                                TransitionData#engine_state.message_count + 1
                        },

                        FinalTransitionData = record_transition(
                            activating_send_chain,
                            bidirectional,
                            {encrypt_success},
                            NewStateData
                        ),

                        % Notify callbacks - now bidirectional!
                        notify_state_change(
                            activating_send_chain,
                            bidirectional,
                            FinalTransitionData
                        ),
                        notify_message_event(
                            encrypt_success,
                            #{
                                plaintext_size => byte_size(Plaintext),
                                message => Message,
                                dh_ratchet_performed => true
                            },
                            FinalTransitionData
                        ),

                        Actions = [{reply, From, {ok, Message}}],
                        {next_state, bidirectional, FinalTransitionData,
                            Actions};
                    {error, Reason} ->
                        notify_message_event(
                            encrypt_error,
                            #{
                                reason => Reason,
                                plaintext_size => byte_size(Plaintext),
                                stage => encryption_after_activation
                            },
                            TransitionData
                        ),
                        {keep_state, record_error(Reason, TransitionData), [
                            {reply, From, {error, Reason}}
                        ]}
                end;
            {error, Reason} ->
                notify_message_event(
                    encrypt_error,
                    #{
                        reason => Reason,
                        plaintext_size => byte_size(Plaintext),
                        stage => send_chain_activation
                    },
                    TransitionData
                ),
                {keep_state, record_error(Reason, TransitionData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, TransitionData),
            {keep_state, record_error(ErrorReason, TransitionData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
receiving_active(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, receiving_active, StateData).

%% @doc Activating send chain state - temporary state during DH ratchet
activating_send_chain(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(activating_send_chain, StateData)};
activating_send_chain({call, _From}, _Event, StateData) ->
    % Postpone all events while activating
    notify_error(state_error, activation_in_progress, StateData),
    {keep_state, StateData, [postpone]};
activating_send_chain(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, activating_send_chain, StateData).

%% @doc Bidirectional state - can freely send and receive
bidirectional(enter, _OldState, StateData) ->
    {keep_state, record_state_enter(bidirectional, StateData)};
bidirectional({call, From}, {encrypt_request, Plaintext}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:encrypt_message(Plaintext, RatchetState) of
            {ok, Message, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                notify_message_event(
                    encrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        message => Message
                    },
                    NewStateData
                ),

                Actions = [{reply, From, {ok, Message}}],
                {keep_state, record_event({encrypt_request}, ok, NewStateData),
                    Actions};
            {error, Reason} ->
                notify_message_event(
                    encrypt_error,
                    #{
                        reason => Reason,
                        plaintext_size => byte_size(Plaintext)
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
bidirectional({call, From}, {decrypt_request, Message}, StateData) ->
    RatchetState = StateData#engine_state.ratchet_state,
    try
        case cryptic_double_ratchet:decrypt_message(Message, RatchetState) of
            {ok, Plaintext, NewRatchetState} ->
                NewStateData = StateData#engine_state{
                    ratchet_state = NewRatchetState,
                    message_count = StateData#engine_state.message_count + 1
                },

                notify_message_event(
                    decrypt_success,
                    #{
                        plaintext_size => byte_size(Plaintext),
                        plaintext => Plaintext
                    },
                    NewStateData
                ),

                Actions = [{reply, From, {ok, Plaintext}}],
                {keep_state, record_event({decrypt_request}, ok, NewStateData),
                    Actions};
            {error, Reason} ->
                notify_message_event(
                    decrypt_error,
                    #{
                        reason => Reason
                    },
                    StateData
                ),
                {keep_state, record_error(Reason, StateData), [
                    {reply, From, {error, Reason}}
                ]}
        end
    catch
        Class:Error:Stacktrace ->
            ErrorReason = {Class, Error, Stacktrace},
            notify_error(crypto_error, ErrorReason, StateData),
            {keep_state, record_error(ErrorReason, StateData), [
                {reply, From, {error, {exception, Class, Error}}}
            ]}
    end;
bidirectional(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, bidirectional, StateData).

%% @doc Error state - terminal state for unrecoverable errors
error_state(enter, _OldState, StateData) ->
    notify_error(state_error, entered_error_state, StateData),
    {keep_state, record_state_enter(error_state, StateData)};
error_state({call, From}, _Event, StateData) ->
    notify_error(state_error, engine_in_error_state, StateData),
    {keep_state, StateData, [{reply, From, {error, engine_in_error_state}}]};
error_state(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, error_state, StateData).
