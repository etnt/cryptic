# Chess Feature Architecture for Cryptic

> **Version**: 1.0  
> **Date**: December 2025  
> **Status**: Design Proposal

## Table of Contents
1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [Architecture Components](#architecture-components)
4. [Event Bus Integration](#event-bus-integration)
5. [Protocol Messages](#protocol-messages)
6. [State Management](#state-management)
7. [Server-Side Components](#server-side-components)
8. [Client-Side Components](#client-side-components)
9. [Implementation Plan](#implementation-plan)
10. [Testing Strategy](#testing-strategy)

---

## Overview

The chess feature enables two Cryptic users to play chess games through the existing secure messaging infrastructure. Chess moves are transmitted as encrypted messages using the existing X3DH/Double Ratchet protocol, ensuring the same end-to-end encryption guarantees as regular messages.

### Goals
- **Minimal Core Changes**: Leverage existing event bus architecture without modifying core messaging components
- **Event-Driven**: All chess state changes published via `cryptic_event_bus` for UI flexibility
- **Transport Agnostic**: Chess logic separate from WebSocket/encryption layers
- **Pluggable UIs**: Any client (console, TUI, GUI) can subscribe to chess events
- **Library Integration**: Use `erl_chess` library for board state and move validation

### Non-Goals
- AI opponents (human vs. human only)
- Tournament management
- ELO ratings / matchmaking
- Chess variant support (standard chess only)

---

## Design Principles

1. **Event Bus First**: All chess activity flows through `cryptic_event_bus`
2. **Stateless Server**: Server only routes chess messages, clients maintain game state
3. **Message as State Transfer**: Chess moves are regular encrypted Cryptic messages with chess metadata
4. **Optional Feature**: Existing clients ignore chess messages; chess-aware clients render them
5. **Peer-to-Peer Logic**: Game state synchronized between two peers via encrypted messages

---

## Architecture Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UI Layer (Client)                            │
│  - cryptic_console (text-based)                                      │
│  - cryptic_tui (Rust Ratatui)                                        │
│  - Any custom UI                                                     │
│                                                                       │
│  Subscribes to:                                                      │
│    - chess_game_invite      (show invitation popup)                 │
│    - chess_game_started     (open chess board view)                 │
│    - chess_move_made        (update board display)                  │
│    - chess_game_ended       (show result, close board)              │
│  Publishes:                                                          │
│    - chess_send_invite      (challenge opponent)                    │
│    - chess_make_move        (user makes move)                       │
│    - chess_accept_invite    (accept game)                           │
│    - chess_decline_invite   (decline game)                          │
│    - chess_resign           (forfeit game)                          │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            │ Events via cryptic_event_bus
                            │
┌───────────────────────────┴─────────────────────────────────────────┐
│                      Event Bus (gen_server)                          │
│                   cryptic_event_bus module                           │
│                   (NO CHANGES REQUIRED)                              │
└───────────────┬─────────────────────────────┬───────────────────────┘
                │                             │
    ┌───────────┘                             └───────────┐
    │                                                     │
    ▼                                                     ▼
┌─────────────────────────┐                  ┌─────────────────────────┐
│   Chess Manager         │                  │   Cryptic Engine        │
│  (NEW MODULE)           │                  │  (NO CHANGES)           │
│  cryptic_chess_manager  │                  │                         │
│                         │                  │  - Encrypts chess msgs  │
│  - Game state tracking  │                  │  - Decrypts chess msgs  │
│  - Move validation      │                  │  - Publishes            │
│  - erl_chess integration│                  │    deliver_message      │
│  - Timeout handling     │                  │                         │
│                         │                  └─────────────────────────┘
│  Subscribes to:         │                              │
│  - deliver_message      │◄─────────────────────────────┘
│    (filters chess msgs) │                  
│  - chess_* commands     │
│  Publishes:             │
│  - chess_game_invite    │
│  - chess_move_made      │
│  - chess_game_ended     │
│  - websocket_outbound   │
│    (to send moves)      │
└─────────────────────────┘
```

---

## Event Bus Integration

### New Event Types (Published by Chess Manager)

#### `chess_game_invite`
Published when a remote user sends a game invitation.

```erlang
#{
    type => chess_game_invite,
    game_id => <<"uuid-1234">>,
    from_user => <<"alice">>,
    to_user => <<"bob">>,
    color => white,  % or black
    time_control => #{
        type => classical,  % or blitz, rapid, bullet
        minutes => 15,
        increment => 10  % seconds per move
    },
    timestamp => erlang:timestamp()
}
```

#### `chess_game_started`
Published when both players have accepted and game begins.

```erlang
#{
    type => chess_game_started,
    game_id => <<"uuid-1234">>,
    opponent => <<"alice">>,
    my_color => white,  % or black
    initial_fen => <<"rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1">>,
    timestamp => erlang:timestamp()
}
```

#### `chess_move_made`
Published when a move is made (by local user or opponent).

```erlang
#{
    type => chess_move_made,
    game_id => <<"uuid-1234">>,
    move => #{
        from => <<"e2">>,
        to => <<"e4">>,
        san => <<"e4">>,           % Standard Algebraic Notation
        uci => <<"e2e4">>,         % UCI format
        piece => pawn,
        captured => undefined,     % or piece type
        promotion => undefined     % or piece type
    },
    made_by => <<"alice">>,
    new_fen => <<"rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1">>,
    is_check => false,
    is_checkmate => false,
    move_number => 1,
    timestamp => erlang:timestamp()
}
```

#### `chess_game_ended`
Published when game concludes.

```erlang
#{
    type => chess_game_ended,
    game_id => <<"uuid-1234">>,
    result => white_wins,  % or black_wins, draw, aborted
    reason => checkmate,   % or resignation, timeout, stalemate, agreement
    winner => <<"alice">>,
    loser => <<"bob">>,
    final_fen => <<"r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR b KQkq - 0 1">>,
    timestamp => erlang:timestamp()
}
```

#### `chess_game_error`
Published on invalid moves or game state errors.

```erlang
#{
    type => chess_game_error,
    game_id => <<"uuid-1234">>,
    error => illegal_move,  % or not_your_turn, game_not_found, timeout
    details => <<"Knight cannot move from e2 to e5">>,
    timestamp => erlang:timestamp()
}
```

### New Event Types (Consumed by Chess Manager)

#### `chess_send_invite`
UI publishes this to challenge another user.

```erlang
#{
    type => chess_send_invite,
    to_user => <<"bob">>,
    color => white,  % preferred color (opponent can reject)
    time_control => #{type => blitz, minutes => 5, increment => 3}
}
```

#### `chess_accept_invite`
UI publishes this to accept an invitation.

```erlang
#{
    type => chess_accept_invite,
    game_id => <<"uuid-1234">>
}
```

#### `chess_decline_invite`
UI publishes this to decline an invitation.

```erlang
#{
    type => chess_decline_invite,
    game_id => <<"uuid-1234">>,
    reason => <<"Busy right now">>  % optional
}
```

#### `chess_make_move`
UI publishes this when user makes a move.

```erlang
#{
    type => chess_make_move,
    game_id => <<"uuid-1234">>,
    move => #{
        from => <<"e2">>,
        to => <<"e4">>
        % optionally: promotion => queen (for pawn promotions)
    }
}
```

#### `chess_resign`
UI publishes this to forfeit the game.

```erlang
#{
    type => chess_resign,
    game_id => <<"uuid-1234">>
}
```

#### `chess_offer_draw`
UI publishes this to propose a draw.

```erlang
#{
    type => chess_offer_draw,
    game_id => <<"uuid-1234">>
}
```

---

## Protocol Messages

Chess data is transmitted as **regular encrypted Cryptic messages** with a special structure. The `cryptic_engine` treats these as normal messages; the `cryptic_chess_manager` recognizes and processes them.

### Message Format

All chess-related messages use a JSON payload with a `chess` top-level field:

```json
{
  "chess": {
    "version": "1.0",
    "type": "invite|accept|decline|move|resign|draw_offer|draw_accept|game_end",
    "game_id": "uuid-1234",
    "payload": { ... type-specific fields ... }
  }
}
```

### Invite Message

```json
{
  "chess": {
    "version": "1.0",
    "type": "invite",
    "game_id": "550e8400-e29b-41d4-a716-446655440000",
    "payload": {
      "from": "alice",
      "to": "bob",
      "color": "white",
      "time_control": {
        "type": "blitz",
        "minutes": 5,
        "increment": 3
      }
    }
  }
}
```

### Accept Message

```json
{
  "chess": {
    "version": "1.0",
    "type": "accept",
    "game_id": "550e8400-e29b-41d4-a716-446655440000",
    "payload": {
      "accepted_by": "bob"
    }
  }
}
```

### Move Message

```json
{
  "chess": {
    "version": "1.0",
    "type": "move",
    "game_id": "550e8400-e29b-41d4-a716-446655440000",
    "payload": {
      "from": "e2",
      "to": "e4",
      "uci": "e2e4",
      "san": "e4",
      "fen": "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1",
      "move_number": 1,
      "is_check": false,
      "is_checkmate": false,
      "timestamp": 1699999999
    }
  }
}
```

### Resign Message

```json
{
  "chess": {
    "version": "1.0",
    "type": "resign",
    "game_id": "550e8400-e29b-41d4-a716-446655440000",
    "payload": {
      "resigned_by": "alice"
    }
  }
}
```

---

## State Management

### Client-Side State (cryptic_chess_manager)

The chess manager maintains an ETS table `cryptic_chess_games` with:

```erlang
-record(chess_game, {
    game_id :: binary(),          % UUID
    opponent :: binary(),          % Username
    my_color :: white | black,
    board_state :: erl_chess:board(),  % From erl_chess library
    current_fen :: binary(),
    status :: pending | active | ended,
    result :: undefined | {winner, User} | draw,
    move_history :: [move()],
    time_control :: map(),
    my_time_remaining :: integer(),  % milliseconds
    opponent_time_remaining :: integer(),
    last_move_timestamp :: erlang:timestamp(),
    created_at :: erlang:timestamp()
}).
```

### Server-Side State (NONE)

The server does **NOT** maintain chess game state. It only:
1. Routes encrypted chess messages between users (same as regular messages)
2. Stores chess messages for offline users (existing pending message feature)

This keeps the server stateless and chess logic entirely client-side.

---

## Server-Side Components

### No New WebSocket Commands

Chess uses existing WebSocket protocol:
- Invitations/moves sent via regular `ratchet` or `x3dh` encrypted messages
- Server routes them like any other message
- No new `<<"type">>` values in `cryptic_ws_handler`

### Optional: Chess Message Storage

If desired, chess messages can be flagged for separate storage:

```erlang
%% In cryptic_ws_handler.erl (optional enhancement)
handle_incoming_message(Message, State) ->
    case is_chess_message(Message) of
        true -> store_as_chess_message(Message);
        false -> store_as_regular_message(Message)
    end.

is_chess_message(#{<<"ciphertext">> := Ciphertext}) ->
    %% Heuristic: check if decrypted message contains "chess" field
    %% (requires partial decrypt or metadata)
    false.  % Default: treat all as regular messages
```

**Recommendation**: Don't implement this initially. Store all messages uniformly.

---

## Client-Side Components

### 1. cryptic_chess_manager.erl (NEW)

A `gen_server` that manages all chess game logic.

**Responsibilities**:
- Subscribe to `cryptic_event_bus` for chess commands and decrypted messages
- Maintain ETS table of active games
- Validate moves using `erl_chess` library
- Generate and publish chess events
- Send encrypted chess messages via event bus
- Handle timeouts and game endings

**API**:
```erlang
-module(cryptic_chess_manager).
-behaviour(gen_server).

%% API
-export([
    start_link/1,
    send_invite/3,
    accept_invite/1,
    decline_invite/2,
    make_move/2,
    resign/1,
    offer_draw/1,
    accept_draw/1,
    get_game_state/1,
    list_active_games/0
]).

%% Configuration
-type config() :: #{
    username := binary(),
    event_bus := pid(),
    auto_accept_invites => boolean()
}.
```

**Event Subscriptions**:
```erlang
init(Config) ->
    %% Subscribe to chess commands from UI
    ChessCommandFilter = fun(Event) ->
        case Event of
            #{type := chess_send_invite} -> true;
            #{type := chess_accept_invite} -> true;
            #{type := chess_decline_invite} -> true;
            #{type := chess_make_move} -> true;
            #{type := chess_resign} -> true;
            #{type := chess_offer_draw} -> true;
            #{type := chess_accept_draw} -> true;
            _ -> false
        end
    end,
    cryptic_event_bus:subscribe(self(), ChessCommandFilter),
    
    %% Subscribe to decrypted messages (to receive chess messages)
    MessageFilter = fun(Event) ->
        case Event of
            #{type := deliver_message, message := Msg} ->
                is_chess_message(Msg);
            _ -> false
        end
    end,
    cryptic_event_bus:subscribe(self(), MessageFilter),
    
    {ok, init_state(Config)}.

is_chess_message(Message) when is_binary(Message) ->
    case jsx:decode(Message, [return_maps]) of
        #{<<"chess">> := _} -> true;
        _ -> false
    catch
        _:_ -> false
    end.
```

**Core Logic**:
```erlang
handle_info({event, #{type := chess_make_move, game_id := GameId, move := Move}}, State) ->
    case validate_and_apply_move(GameId, Move, State) of
        {ok, NewGameState, UpdatedState} ->
            %% Publish move event for UI
            cryptic_event_bus:publish(#{
                type => chess_move_made,
                game_id => GameId,
                move => Move,
                new_fen => erl_chess:to_fen(NewGameState#chess_game.board_state),
                made_by => State#state.username
            }),
            
            %% Send encrypted move to opponent
            ChessMessage = encode_chess_move(GameId, Move, NewGameState),
            cryptic_event_bus:publish(#{
                type => websocket_outbound,
                message => #{
                    <<"type">> => <<"send_message">>,
                    <<"to_user">> => NewGameState#chess_game.opponent,
                    <<"plaintext">> => ChessMessage
                }
            }),
            
            %% Check for game end
            case check_game_end(NewGameState) of
                {ended, Result} ->
                    publish_game_ended(GameId, Result),
                    {noreply, UpdatedState};
                ongoing ->
                    {noreply, UpdatedState}
            end;
            
        {error, Reason} ->
            cryptic_event_bus:publish(#{
                type => chess_game_error,
                game_id => GameId,
                error => Reason
            }),
            {noreply, State}
    end.
```

### 2. erl_chess Integration

The `erl_chess` library provides:
- Board representation
- Move validation
- Check/checkmate detection
- FEN parsing/generation

**Example Usage**:
```erlang
%% Initialize board
{ok, Board} = erl_chess:new_game().

%% Make a move
case erl_chess:move(Board, "e2", "e4") of
    {ok, NewBoard} ->
        FEN = erl_chess:to_fen(NewBoard),
        IsCheck = erl_chess:is_check(NewBoard),
        IsCheckmate = erl_chess:is_checkmate(NewBoard);
    {error, illegal_move} ->
        handle_error()
end.

%% Get legal moves
LegalMoves = erl_chess:legal_moves(Board, "e2").
```

### 3. UI Changes (Minimal)

#### Console UI (cryptic_console.erl)

Add chess command handlers and event display:

```erlang
%% Add to command processing
handle_user_input("/chess invite " ++ Username, State) ->
    cryptic_event_bus:publish(#{
        type => chess_send_invite,
        to_user => list_to_binary(Username),
        color => white,
        time_control => #{type => blitz, minutes => 5, increment => 3}
    }),
    console_loop(State);

handle_user_input("/chess move " ++ MoveStr, State) ->
    [FromStr, ToStr] = string:split(MoveStr, " "),
    cryptic_event_bus:publish(#{
        type => chess_make_move,
        game_id => State#state.active_chess_game,
        move => #{
            from => list_to_binary(FromStr),
            to => list_to_binary(ToStr)
        }
    }),
    console_loop(State).

%% Add event subscriptions
ChessFilter = fun(Event) ->
    case Event of
        #{type := chess_game_invite} -> true;
        #{type := chess_game_started} -> true;
        #{type := chess_move_made} -> true;
        #{type := chess_game_ended} -> true;
        #{type := chess_game_error} -> true;
        _ -> false
    end
end,
cryptic_event_bus:subscribe(self(), ChessFilter).

%% Display handlers
receive
    {event, #{type := chess_game_invite, from_user := From, game_id := GameId}} ->
        io:format("~n🎮 Chess game invitation from ~s~n", [From]),
        io:format("   /chess accept ~s  or  /chess decline ~s~n", [GameId, GameId]);
    
    {event, #{type := chess_move_made, move := Move, made_by := Player}} ->
        io:format("~n♟️  ~s: ~s -> ~s~n", [Player, 
            maps:get(from, Move), 
            maps:get(to, Move)]);
    
    {event, #{type := chess_game_ended, winner := Winner, reason := Reason}} ->
        io:format("~n🏆 Game Over! ~s wins by ~s~n", [Winner, Reason])
end.
```

#### Rust TUI (External Integration)

The Rust TUI subscribes to chess events via Erlport:

```rust
// In Rust TUI event loop
match event {
    Event::ChessGameInvite { from, game_id, color, time_control } => {
        show_chess_invite_popup(from, game_id, color, time_control);
    }
    Event::ChessGameStarted { game_id, opponent, my_color, fen } => {
        open_chess_board_view(game_id, opponent, my_color, fen);
    }
    Event::ChessMoveMade { game_id, move, new_fen, made_by } => {
        update_chess_board(game_id, move, new_fen);
        animate_piece_movement(move);
    }
    Event::ChessGameEnded { winner, reason, final_fen } => {
        show_game_over_dialog(winner, reason);
        close_chess_board_view();
    }
}
```

---

## Implementation Plan

### Phase 1: Core Chess Manager (Week 1-2)

1. **Create `cryptic_chess_manager.erl`**
   - Basic gen_server skeleton
   - ETS table setup for game state
   - Event bus subscription
   - Simple invite/accept flow

2. **Integrate `erl_chess` library**
   - Add as dependency in `rebar.config`
   - Wrapper functions for board operations
   - Move validation logic

3. **Message encoding/decoding**
   - JSON chess message format
   - Encryption via existing `websocket_outbound` events
   - Parsing of incoming chess messages

### Phase 2: Console UI Integration (Week 2)

1. **Add chess commands to `cryptic_console.erl`**
   - `/chess invite <user>`
   - `/chess move <from> <to>`
   - `/chess resign`
   - `/chess accept <game_id>`

2. **Display chess events**
   - Invitation notifications
   - Move updates (simple text format)
   - Game end messages

3. **Basic board rendering**
   - ASCII art chess board
   - Current position display

### Phase 3: Advanced Features (Week 3-4)

1. **Time controls**
   - Clock tracking per player
   - Timeout detection
   - Timer events

2. **Move history**
   - PGN export
   - Move list display
   - Undo requests (mutual agreement)

3. **Draw handling**
   - Draw offers
   - Stalemate detection
   - Threefold repetition

### Phase 4: Testing & Documentation (Week 4)

1. **Unit tests**
   - Move validation
   - Game state transitions
   - Message parsing

2. **Integration tests**
   - Two-client game simulation
   - Network interruption handling
   - Concurrent games

3. **Documentation**
   - API documentation
   - User guide
   - UI integration examples

---

## Testing Strategy

### Unit Tests

**`cryptic_chess_manager_tests.erl`**:
```erlang
-module(cryptic_chess_manager_tests).
-include_lib("eunit/include/eunit.hrl").

invite_accept_flow_test() ->
    %% Test full invitation flow
    {ok, _} = cryptic_event_bus:start_link(),
    {ok, Manager1} = cryptic_chess_manager:start_link(#{username => <<"alice">>}),
    {ok, Manager2} = cryptic_chess_manager:start_link(#{username => <<"bob">>}),
    
    %% Alice invites Bob
    ok = cryptic_chess_manager:send_invite(Manager1, <<"bob">>, #{color => white}),
    
    %% Bob should receive invite event
    receive
        {event, #{type := chess_game_invite, game_id := GameId}} ->
            %% Bob accepts
            ok = cryptic_chess_manager:accept_invite(Manager2, GameId),
            
            %% Both should receive game_started event
            receive
                {event, #{type := chess_game_started}} -> ok
            after 1000 -> ?assert(false)
            end
    after 1000 -> ?assert(false)
    end.

valid_move_test() ->
    {ok, Manager} = cryptic_chess_manager:start_link(#{username => <<"alice">>}),
    GameId = setup_test_game(Manager, white),
    
    %% Make valid move e2-e4
    ok = cryptic_chess_manager:make_move(Manager, GameId, #{
        from => <<"e2">>, to => <<"e4">>
    }),
    
    %% Should publish move_made event
    receive
        {event, #{type := chess_move_made, move := #{from := <<"e2">>}}} ->
            ok
    after 1000 -> ?assert(false)
    end.

invalid_move_test() ->
    {ok, Manager} = cryptic_chess_manager:start_link(#{username => <<"alice">>}),
    GameId = setup_test_game(Manager, white),
    
    %% Make invalid move e2-e5 (can't skip square)
    ok = cryptic_chess_manager:make_move(Manager, GameId, #{
        from => <<"e2">>, to => <<"e5">>
    }),
    
    %% Should publish error event
    receive
        {event, #{type := chess_game_error, error := illegal_move}} ->
            ok
    after 1000 -> ?assert(false)
    end.
```

### Integration Tests

**`cryptic_chess_integration_tests.erl`**:
```erlang
two_player_game_test() ->
    %% Simulate full game between Alice and Bob
    {ok, _} = cryptic_event_bus:start_link(),
    {ok, Alice} = cryptic_chess_manager:start_link(#{username => <<"alice">>}),
    {ok, Bob} = cryptic_chess_manager:start_link(#{username => <<"bob">>}),
    
    %% Play scholar's mate
    Moves = [
        {alice, <<"e2">>, <<"e4">>},
        {bob, <<"e7">>, <<"e5">>},
        {alice, <<"f1">>, <<"c4">>},
        {bob, <<"b8">>, <<"c6">>},
        {alice, <<"d1">>, <<"h5">>},
        {bob, <<"g8">>, <<"f6">>},
        {alice, <<"h5">>, <<"f7">>}  % Checkmate
    ],
    
    play_moves(Moves, Alice, Bob),
    
    %% Verify checkmate event
    receive
        {event, #{type := chess_game_ended, 
                  result := white_wins,
                  reason := checkmate}} ->
            ok
    after 5000 -> ?assert(false)
    end.
```

### End-to-End Tests

1. **Manual Testing Checklist**:
   - [ ] Start two console clients
   - [ ] Send invitation
   - [ ] Accept invitation
   - [ ] Play 10 moves
   - [ ] Resign
   - [ ] Verify game end
   - [ ] Start new game
   - [ ] Test timeout
   - [ ] Test illegal move rejection

2. **Load Testing**:
   - [ ] 10 concurrent games
   - [ ] 100 concurrent games
   - [ ] Network latency simulation
   - [ ] Message reordering

---

## Security Considerations

1. **Move Validation**:
   - Always validate moves locally before sending
   - Re-validate opponent moves on receipt
   - Reject malformed chess messages

2. **Cheating Prevention**:
   - No server-side validation (trust model)
   - Clients can detect invalid opponent moves
   - Option to abort game if opponent cheats

3. **Denial of Service**:
   - Rate limit invitations (max 5 pending per user)
   - Timeout inactive games (30 minutes)
   - Limit concurrent games (max 10 per user)

4. **Privacy**:
   - Chess moves are end-to-end encrypted (same as messages)
   - Game state never stored on server
   - Opponents cannot see each other's client details

---

## Future Enhancements

1. **Spectator Mode**:
   - Invite observers to watch games
   - Broadcast moves to multiple subscribers
   - Chat during spectating

2. **Game Analysis**:
   - Save PGN files locally
   - Export to chess engines (Stockfish)
   - Move annotations

3. **Multiple Variants**:
   - Chess960 (Fischer Random)
   - Crazyhouse
   - Three-check

4. **Tournament Support**:
   - Bracket management
   - Swiss system pairings
   - Rating calculations

5. **Mobile Clients**:
   - React Native app
   - Flutter app
   - Subscribe to same event bus via bridge

---

## File Structure

```
cryptic/
├── src/
│   ├── cryptic_chess_manager.erl       (NEW - core chess logic)
│   ├── cryptic_chess_messages.erl      (NEW - message encoding/decoding)
│   ├── cryptic_console.erl             (MODIFIED - add chess commands)
│   └── ...existing files unchanged...
├── test/
│   ├── cryptic_chess_manager_tests.erl (NEW - unit tests)
│   └── cryptic_chess_integration_tests.erl (NEW - integration tests)
├── docs/
│   ├── CHESS_ARCHITECTURE.md           (THIS FILE)
│   └── CHESS_USER_GUIDE.md             (NEW - user documentation)
└── rebar.config                        (MODIFIED - add erl_chess dep)
```

---

## Summary

This architecture enables chess functionality in Cryptic with **minimal changes** to existing code:

### Changes Required
1. ✅ **New module**: `cryptic_chess_manager.erl` (chess game logic)
2. ✅ **New module**: `cryptic_chess_messages.erl` (message formatting)
3. ✅ **Modified**: `cryptic_console.erl` (add chess commands/events)
4. ✅ **Modified**: `rebar.config` (add `erl_chess` dependency)
5. ✅ **New**: Test files

### No Changes Required
- ❌ `cryptic_event_bus.erl` - works as-is
- ❌ `cryptic_engine.erl` - works as-is
- ❌ `cryptic_ws_handler.erl` - works as-is
- ❌ `cryptic_ws_client.erl` - works as-is
- ❌ Server WebSocket protocol - works as-is

### Key Benefits
1. **Event-driven**: All UIs can subscribe to chess events
2. **Encrypted**: Chess moves use existing E2EE infrastructure
3. **Decoupled**: Chess manager is independent gen_server
4. **Extensible**: Easy to add new chess features
5. **Optional**: Non-chess clients unaffected

---

**Next Steps**: Review this architecture, then proceed with Phase 1 implementation.
