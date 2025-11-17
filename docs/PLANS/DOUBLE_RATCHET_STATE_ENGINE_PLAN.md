# Double Ratchet State Engine Implementation Plan

## Executive Summary

This document outlines a comprehensive plan to refactor the current
function-based Double Ratchet implementation into a proper state machine
engine using Erlang/OTP `gen_statem` behavior. This will provide better
error handling, clearer state transitions, improved testability, and more
robust synchronization between communicating parties.

## Current Architecture Analysis

### Current Implementation Issues

1. **Implicit State Management**: State transitions are embedded within function logic
2. **Complex Error Handling**: Error paths scattered across multiple functions
3. **Testing Complexity**: Hard to test specific state transitions in isolation
4. **Race Conditions**: Potential for state desynchronization during concurrent operations
5. **Debugging Difficulty**: No clear visibility into state transition history

### Current State Transitions (Function-Based)

```erlang
% Current approach - implicit state changes
encrypt_message(Plaintext, State) ->
    case State#ratchet_state.sending_chain_active of
        false -> activate_sending_chain(State);  % Implicit state transition
        true -> encrypt_message_impl(Plaintext, State)
    end.
```

## Proposed State Engine Architecture

### 1. Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Double Ratchet State Engine                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   State Engine  │  │  Event Handlers │  │ Action Modules  │  │
│  │   (gen_statem)  │  │                 │  │                 │  │
│  │                 │  │ - encrypt_event │  │ - chain_ops     │  │
│  │ - State storage │  │ - decrypt_event │  │ - dh_ratchet    │  │
│  │ - Transitions   │  │ - ratchet_event │  │ - key_derivation│  │
│  │ - Event routing │  │ - gap_event     │  │ - serialization │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  State Guards   │  │   Side Effects  │  │    Observers    │  │
│  │                 │  │                 │  │                 │  │
│  │ - Preconditions │  │ - Logging       │  │ - Metrics       │  │
│  │ - Validations   │  │ - Notifications │  │ - Debug traces  │  │
│  │ - Constraints   │  │ - Persistence   │  │ - State history │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2. State Definitions

#### Primary States

```erlang
-type ratchet_state_name() :: 
    sender_init |           % Alice's initial state (can send immediately)
    receiver_init |         % Bob's initial state (receiving only)  
    sending_active |        % Actively sending messages
    receiving_active |      % Actively receiving messages
    activating_send_chain | % Transitioning to bidirectional (DH ratchet)
    bidirectional |         % Can send and receive freely
    error_state.           % Error recovery state

-type ratchet_event() ::
    {encrypt_request, binary()} |           % Request to encrypt message
    {decrypt_request, message()} |          % Request to decrypt message  
    {activate_send_chain} |                 % Activate sending capability
    {dh_ratchet_step, dh_info()} |         % Perform DH ratchet
    {handle_message_gap, gap_info()} |     % Handle out-of-order messages
    {cleanup_expired_keys} |               % Maintenance operations
    {error, term()}.                       % Error conditions
```

#### State Data Structure

```erlang
-record(ratchet_engine_state, {
    % Core cryptographic state (same as current implementation)
    ratchet_state :: ratchet_state(),
    
    % State machine metadata
    current_state :: ratchet_state_name(),
    state_history :: [state_transition()],
    
    % Event processing
    event_queue :: queue:queue(ratchet_event()),
    processing_event :: ratchet_event() | undefined,
    
    % Configuration and policies
    config :: engine_config(),
    
    % Observability
    metrics :: #{atom() => integer()},
    debug_enabled :: boolean(),
    
    % Error handling
    error_count :: non_neg_integer(),
    last_error :: term() | undefined,
    
    % Persistence
    dirty :: boolean(),
    last_checkpoint :: erlang:timestamp()
}).

-record(state_transition, {
    from_state :: ratchet_state_name(),
    to_state :: ratchet_state_name(),
    event :: ratchet_event(),
    timestamp :: erlang:timestamp(),
    duration_us :: non_neg_integer()
}).
```

### 3. State Machine Implementation

#### Module Structure

```
src/
├── ratchet_engine/
│   ├── cryptic_ratchet_engine.erl          % Main gen_statem implementation
│   ├── ratchet_state_handlers.erl          % State-specific event handlers
│   ├── ratchet_actions.erl                 % Cryptographic operations
│   ├── ratchet_guards.erl                  % Validation and preconditions
│   ├── ratchet_observers.erl               % Metrics and logging
│   └── ratchet_config.erl                  % Configuration management
└── ratchet_engine_sup.erl                  % Supervision tree
```

#### Main State Machine Module

```erlang
-module(cryptic_ratchet_engine).
-behaviour(gen_statem).

%% Public API
-export([
    start_link/1,
    init_as_sender/3,
    init_as_receiver/3,
    encrypt_message/2,
    decrypt_message/2,
    get_state_info/1,
    stop/1
]).

%% gen_statem callbacks  
-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State function exports
-export([
    sender_init/3,
    receiver_init/3,
    sending_active/3,
    receiving_active/3,
    activating_send_chain/3,
    bidirectional/3,
    error_state/3
]).

%% API Functions
start_link(InitialConfig) ->
    gen_statem:start_link(?MODULE, InitialConfig, []).

init_as_sender(Pid, RootKey, DHKeyPair) ->
    gen_statem:call(Pid, {init_sender, RootKey, DHKeyPair}).

encrypt_message(Pid, Plaintext) ->
    gen_statem:call(Pid, {encrypt_request, Plaintext}).

%% gen_statem Implementation
callback_mode() -> [state_functions, state_enter].

init(Config) ->
    State = #ratchet_engine_state{
        config = Config,
        state_history = [],
        event_queue = queue:new(),
        metrics = #{},
        debug_enabled = maps:get(debug, Config, false)
    },
    {ok, uninitialized, State}.

%% State Functions
sender_init(enter, _OldState, StateData) ->
    % Entry actions for sender_init state
    {keep_state, StateData};
    
sender_init({call, From}, {encrypt_request, Plaintext}, StateData) ->
    % Handle encryption request in sender_init state
    case ratchet_actions:encrypt_message(Plaintext, StateData#ratchet_engine_state.ratchet_state) of
        {ok, Message, NewRatchetState} ->
            NewStateData = StateData#ratchet_engine_state{
                ratchet_state = NewRatchetState
            },
            {next_state, sending_active, NewStateData, [{reply, From, {ok, Message}}]};
        {error, Reason} ->
            {keep_state, StateData, [{reply, From, {error, Reason}}]}
    end;
    
sender_init(EventType, Event, StateData) ->
    handle_common_event(EventType, Event, sender_init, StateData).
```

### 4. Detailed State Transition Logic

#### State Transition Matrix

| Current State         | Event               | Guards                  | Actions                                 | Next State            | Side Effects                    |
|-----------------------|---------------------|-------------------------|-----------------------------------------|-----------------------|---------------------------------|
| sender_init           | encrypt_request     | validate_plaintext      | derive_message_key, advance_send_chain  | sending_active        | log_encryption, update_metrics  |
| receiver_init         | decrypt_request     | validate_message        | derive_message_key, advance_recv_chain  | receiving_active      | log_decryption, cache_remote_dh |
| receiving_active      | encrypt_request     | has_remote_dh           | perform_dh_ratchet, activate_send_chain | activating_send_chain | log_direction_change            |
| activating_send_chain | internal_send_ready | -                       | derive_send_chain_key                   | bidirectional         | log_bidirectional_active        |
| sending_active        | decrypt_request     | validate_new_dh         | perform_dh_ratchet, update_recv_chain   | bidirectional         | log_recv_ratchet                |
| bidirectional         | encrypt_request     | check_dh_ratchet_needed | optional_dh_ratchet, advance_send_chain | bidirectional         | log_message_sent                |
| bidirectional         | decrypt_request     | validate_message        | handle_gaps, advance_recv_chain         | bidirectional         | log_message_received            |
| any_state             | error               | -                       | log_error, increment_error_count        | error_state           | alert_observers                 |
| error_state           | recovery_attempt    | validate_recovery       | restore_state                           | previous_state        | log_recovery                    |
  
#### State Guard Functions

```erlang
-module(ratchet_guards).

validate_plaintext(Plaintext) when is_binary(Plaintext), byte_size(Plaintext) > 0 -> true;
validate_plaintext(_) -> false.

validate_message(#{dh_public := DH, ciphertext := CT, nonce := N}) 
    when byte_size(DH) =:= 32, is_binary(CT), byte_size(N) > 0 -> true;
validate_message(_) -> false.

has_remote_dh(#ratchet_engine_state{ratchet_state = RS}) ->
    RS#ratchet_state.dh_remote =/= undefined.

check_dh_ratchet_needed(StateData) ->
    RS = StateData#ratchet_engine_state.ratchet_state,
    RS#ratchet_state.recv_msg_number > 0 andalso 
    RS#ratchet_state.send_msg_number == 0.
```

#### Action Modules

```erlang
-module(ratchet_actions).

encrypt_message(Plaintext, RatchetState) ->
    % Same cryptographic logic as current implementation
    % But returns structured result for state machine processing
    try
        {NewSendChainKey, MessageKey} = advance_sending_chain(
            RatchetState#ratchet_state.send_chain_key,
            RatchetState#ratchet_state.send_msg_number
        ),
        {EncKey, _AuthKey} = kdf_mk(MessageKey),
        {CipherText, Nonce} = cryptic_nif:aead_encrypt(Plaintext, EncKey, <<>>),
        
        Message = #{
            dh_public => element(1, RatchetState#ratchet_state.dh_self),
            dh_step => RatchetState#ratchet_state.dh_ratchet_step,
            msg_number => RatchetState#ratchet_state.send_msg_number,
            ciphertext => CipherText,
            nonce => Nonce
        },
        
        NewRatchetState = RatchetState#ratchet_state{
            send_chain_key = NewSendChainKey,
            send_msg_number = RatchetState#ratchet_state.send_msg_number + 1
        },
        
        {ok, Message, NewRatchetState}
    catch
        Class:Reason:Stack ->
            {error, {encryption_failed, Class, Reason, Stack}}
    end.

perform_dh_ratchet(StateData, RemoteDHPub) ->
    % DH ratchet logic with detailed error handling
    try
        RS = StateData#ratchet_engine_state.ratchet_state,
        {_OwnDHPub, OwnDHPriv} = RS#ratchet_state.dh_self,
        
        DHOutput = cryptic_nif:scalarmult(OwnDHPriv, RemoteDHPub),
        {NewRootKey, InitChainKey, RespChainKey} = kdf_rk(RS#ratchet_state.root_key, DHOutput),
        
        {NewOwnDHPub, NewOwnDHPriv} = cryptic_nif:gen_keypair(),
        
        NewRS = RS#ratchet_state{
            root_key = NewRootKey,
            dh_self = {NewOwnDHPub, NewOwnDHPriv},
            dh_remote = RemoteDHPub,
            dh_ratchet_step = RS#ratchet_state.dh_ratchet_step + 1,
            send_chain_key = determine_send_chain(RS, InitChainKey, RespChainKey),
            recv_chain_key = determine_recv_chain(RS, InitChainKey, RespChainKey),
            send_msg_number = 0,
            recv_msg_number = 0
        },
        
        NewStateData = StateData#ratchet_engine_state{ratchet_state = NewRS},
        {ok, NewStateData}
    catch
        Class:Reason:Stack ->
            {error, {dh_ratchet_failed, Class, Reason, Stack}}
    end.
```

### 5. Advanced Features

#### Event Queue Management

```erlang
-module(ratchet_event_queue).

enqueue_event(Event, StateData) ->
    NewQueue = queue:in(Event, StateData#ratchet_engine_state.event_queue),
    StateData#ratchet_engine_state{event_queue = NewQueue}.

dequeue_event(StateData) ->
    case queue:out(StateData#ratchet_engine_state.event_queue) of
        {{value, Event}, NewQueue} ->
            {Event, StateData#ratchet_engine_state{event_queue = NewQueue}};
        {empty, Queue} ->
            {no_event, StateData#ratchet_engine_state{event_queue = Queue}}
    end.

process_queued_events(StateData) ->
    case dequeue_event(StateData) of
        {no_event, StateData1} ->
            StateData1;
        {Event, StateData1} ->
            NewStateData = handle_event(Event, StateData1),
            process_queued_events(NewStateData)
    end.
```

#### State History and Debugging

```erlang
-module(ratchet_observers).

record_state_transition(FromState, ToState, Event, StateData) ->
    Transition = #state_transition{
        from_state = FromState,
        to_state = ToState,
        event = Event,
        timestamp = erlang:timestamp(),
        duration_us = calculate_duration(StateData)
    },
    
    History = [Transition | StateData#ratchet_engine_state.state_history],
    TruncatedHistory = lists:sublist(History, 100), % Keep last 100 transitions
    
    StateData#ratchet_engine_state{state_history = TruncatedHistory}.

get_transition_history(StateData) ->
    StateData#ratchet_engine_state.state_history.

generate_debug_report(StateData) ->
    #{
        current_state => StateData#ratchet_engine_state.current_state,
        history_length => length(StateData#ratchet_engine_state.state_history),
        recent_transitions => lists:sublist(StateData#ratchet_engine_state.state_history, 10),
        metrics => StateData#ratchet_engine_state.metrics,
        error_count => StateData#ratchet_engine_state.error_count,
        queue_length => queue:len(StateData#ratchet_engine_state.event_queue)
    }.
```

#### Configuration Management

```erlang
-module(ratchet_config).

-record(engine_config, {
    max_skip_count = 1000 :: pos_integer(),
    max_cache_size = 10000 :: pos_integer(),
    max_cache_age_ms = 86400000 :: pos_integer(),
    enable_history = true :: boolean(),
    enable_metrics = true :: boolean(),
    enable_debug = false :: boolean(),
    auto_checkpoint_interval_ms = 60000 :: pos_integer(),
    max_error_count = 10 :: pos_integer(),
    error_recovery_strategy = restart :: restart | ignore | custom
}).

default_config() ->
    #engine_config{}.

validate_config(Config) ->
    case Config of
        #engine_config{max_skip_count = MSC} when MSC > 0 andalso MSC =< 10000 ->
            ok;
        _ ->
            {error, invalid_max_skip_count}
    end.
```

### 6. Integration with Existing System

#### Backward Compatibility Layer

```erlang
-module(cryptic_double_ratchet_compat).
% Provides same API as current implementation but uses state engine internally

encrypt_message(Plaintext, RatchetState) ->
    % Convert old ratchet_state to engine state
    {ok, EnginePid} = start_temporary_engine(RatchetState),
    try
        case cryptic_ratchet_engine:encrypt_message(EnginePid, Plaintext) of
            {ok, Message} ->
                NewRatchetState = extract_ratchet_state(EnginePid),
                {ok, Message, NewRatchetState};
            {error, Reason} ->
                {error, Reason}
        end
    after
        cryptic_ratchet_engine:stop(EnginePid)
    end.

start_temporary_engine(RatchetState) ->
    % Create engine with existing state for backward compatibility
    Config = ratchet_config:default_config(),
    {ok, Pid} = cryptic_ratchet_engine:start_link(Config),
    ok = cryptic_ratchet_engine:load_state(Pid, RatchetState),
    {ok, Pid}.
```

#### Migration Strategy

1. **Phase 1**: Implement state engine alongside existing implementation
2. **Phase 2**: Create compatibility layer for seamless transition
3. **Phase 3**: Migrate tests to use state engine
4. **Phase 4**: Replace existing implementation with engine calls
5. **Phase 5**: Remove compatibility layer and old implementation

### 7. Testing Strategy

#### State Machine Property Testing

```erlang
-module(ratchet_engine_prop_tests).
-include_lib("proper/include/proper.hrl").

% Property: State transitions are deterministic
prop_deterministic_transitions() ->
    ?FORALL({State, Event}, {valid_state(), valid_event()},
        begin
            Result1 = apply_event(State, Event),
            Result2 = apply_event(State, Event),
            Result1 =:= Result2
        end).

% Property: No invalid state transitions  
prop_valid_transitions() ->
    ?FORALL({State, Event}, {valid_state(), valid_event()},
        case apply_event(State, Event) of
            {ok, NewState, _Actions} -> is_valid_transition(State, NewState, Event);
            {error, _Reason} -> true % Errors are acceptable
        end).

% Property: Message encryption/decryption roundtrip
prop_encrypt_decrypt_roundtrip() ->
    ?FORALL({AliceState, BobState, Message}, alice_bob_states_with_message(),
        begin
            {ok, EncMessage, AliceState1} = encrypt_in_state(AliceState, Message),
            {ok, DecMessage, BobState1} = decrypt_in_state(BobState, EncMessage),
            Message =:= DecMessage
        end).
```

#### Unit Tests for State Functions

```erlang
-module(ratchet_engine_tests).
-include_lib("eunit/include/eunit.hrl").

sender_init_encrypt_test() ->
    StateData = create_test_sender_state(),
    Event = {encrypt_request, <<"test message">>},
    
    {NextState, NewStateData, Actions} = 
        cryptic_ratchet_engine:sender_init({call, self()}, Event, StateData),
    
    ?assertEqual(sending_active, NextState),
    ?assertMatch([{reply, _, {ok, _}}], Actions),
    ?assert(NewStateData#ratchet_engine_state.ratchet_state#ratchet_state.send_msg_number > 0).

bidirectional_dh_ratchet_test() ->
    StateData = create_test_bidirectional_state(),
    Event = {decrypt_request, create_test_message_with_new_dh()},
    
    {NextState, NewStateData, Actions} = 
        cryptic_ratchet_engine:bidirectional({call, self()}, Event, StateData),
    
    ?assertEqual(bidirectional, NextState),
    ?assertMatch([{reply, _, {ok, _}}], Actions),
    % Verify DH ratchet step incremented
    OldStep = StateData#ratchet_engine_state.ratchet_state#ratchet_state.dh_ratchet_step,
    NewStep = NewStateData#ratchet_engine_state.ratchet_state#ratchet_state.dh_ratchet_step,
    ?assertEqual(OldStep + 1, NewStep).
```

### 8. Performance Considerations

#### Optimization Strategies

1. **State Data Copying**: Minimize copying of large state structures
2. **Event Batching**: Process multiple events in single state transition
3. **Lazy Evaluation**: Defer expensive operations until necessary
4. **Memory Management**: Efficient cleanup of expired keys and history
5. **Process Pooling**: Reuse engine processes for multiple sessions

#### Memory Usage

```erlang
% Estimated memory usage per engine process
-define(BASE_STATE_SIZE, 1024).        % Basic gen_statem overhead
-define(RATCHET_STATE_SIZE, 512).      % Core cryptographic state  
-define(HISTORY_ENTRY_SIZE, 128).      % Per state transition record
-define(CACHED_KEY_SIZE, 96).          % Per skipped message key

estimate_memory_usage(StateData) ->
    BaseSize = ?BASE_STATE_SIZE + ?RATCHET_STATE_SIZE,
    HistorySize = length(StateData#ratchet_engine_state.state_history) * ?HISTORY_ENTRY_SIZE,
    CachedKeysSize = maps:size(StateData#ratchet_engine_state.ratchet_state#ratchet_state.skipped_keys) * ?CACHED_KEY_SIZE,
    BaseSize + HistorySize + CachedKeysSize.
```

### 9. Deployment and Operations

#### Supervision Tree

```erlang
-module(ratchet_engine_sup).
-behaviour(supervisor).

init([]) ->
    Children = [
        #{
            id => ratchet_engine_registry,
            start => {ratchet_engine_registry, start_link, []},
            type => worker
        },
        #{
            id => ratchet_engine_pool_sup,
            start => {ratchet_engine_pool_sup, start_link, []},
            type => supervisor
        }
    ],
    {ok, {{one_for_one, 5, 10}, Children}}.
```

#### Monitoring and Alerting

```erlang
-module(ratchet_engine_monitor).

% Telemetry events
-define(TELEMETRY_EVENTS, [
    [ratchet_engine, state_transition],
    [ratchet_engine, encryption, success],
    [ratchet_engine, decryption, success],  
    [ratchet_engine, dh_ratchet, performed],
    [ratchet_engine, error, occurred]
]).

setup_telemetry() ->
    lists:foreach(fun(Event) ->
        telemetry:attach(
            Event,
            Event, 
            fun handle_telemetry_event/4,
            []
        )
    end, ?TELEMETRY_EVENTS).

handle_telemetry_event([ratchet_engine, error, occurred], Measurements, Metadata, _Config) ->
    error_logger:error_msg("Ratchet engine error: ~p", [Metadata]),
    prometheus_counter:inc(ratchet_engine_errors_total, [Metadata.error_type]).
```

## Implementation Timeline

### Phase 1: Core State Machine (Weeks 1-2)
- [ ] Implement basic `gen_statem` structure
- [ ] Define all states and events
- [ ] Implement core state transition functions
- [ ] Basic unit tests for state transitions

### Phase 2: Cryptographic Actions (Weeks 3-4)  
- [ ] Port existing crypto operations to action modules
- [ ] Implement DH ratchet logic in state machine context
- [ ] Add error handling and recovery mechanisms
- [ ] Integration tests with crypto operations

### Phase 3: Advanced Features (Weeks 5-6)
- [ ] Event queue management
- [ ] State history and debugging support
- [ ] Performance optimizations
- [ ] Comprehensive test suite

### Phase 4: Integration (Weeks 7-8)
- [ ] Backward compatibility layer
- [ ] Migration from existing implementation  
- [ ] Performance benchmarking
- [ ] Documentation updates

### Phase 5: Production Readiness (Weeks 9-10)
- [ ] Supervision tree implementation
- [ ] Monitoring and alerting
- [ ] Load testing and optimization
- [ ] Production deployment

## Benefits of State Engine Approach

### 1. **Correctness**
- Explicit state transitions prevent invalid operations
- Guards ensure preconditions are met before state changes
- Comprehensive error handling with recovery mechanisms

### 2. **Testability**
- Isolated testing of individual state transitions
- Property-based testing of state machine invariants
- Deterministic behavior for reliable testing

### 3. **Maintainability**  
- Clear separation between state logic and cryptographic operations
- Modular design allows independent development of components
- Comprehensive debugging and observability features

### 4. **Robustness**
- Built-in supervision and fault tolerance via OTP
- Graceful error recovery and state restoration
- Protection against race conditions and state corruption

### 5. **Performance**
- Efficient event processing and state management
- Optimized memory usage and garbage collection
- Scalable architecture for concurrent sessions

This state engine approach will transform the Double Ratchet implementation from a collection of functions into a robust, maintainable, and testable system that properly models the complex state synchronization requirements of the protocol.
