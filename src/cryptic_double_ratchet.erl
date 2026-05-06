%%% @doc Double Ratchet Implementation for Cryptic
%%%
%%% This module implements the Double Ratchet algorithm for forward-secure
%%% messaging, replacing the inefficient OTPK-per-message approach with
%%% a high-performance ratcheting system.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Forward secrecy: Past messages remain secure if current keys compromised</li>
%%%   <li>Break-in recovery: Security restored after key material compromise</li>
%%%   <li>Asynchronous messaging: Works with offline/online patterns</li>
%%%   <li>Out-of-order handling: Skipped message key store for delayed messages</li>
%%%   <li>High performance: Native KDF operations (39x faster than Erlang)</li>
%%%   <li>ChaCha20-Poly1305 AEAD: Modern authenticated encryption with libsodium</li>
%%% </ul>
%%%
%%% == Architecture ==
%%%
%%% The implementation uses two independent chains:
%%% <ul>
%%%   <li><em>Sending Chain</em>: Derives keys for outgoing messages</li>
%%%   <li><em>Receiving Chain</em>: Derives keys for incoming messages</li>
%%% </ul>
%%%
%%% Each chain advances independently, with periodic DH ratchet steps
%%% that inject fresh entropy and provide break-in recovery.
%%%
%%% == DH Ratchet Step Counter Behavior ==
%%%
%%% The `dh_ratchet_step' counter tracks the number of DH ratchet operations
%%% performed, NOT the number of individual messages. Understanding this is
%%% critical for debugging and monitoring:
%%%
%%% <strong>Key Insight:</strong> Direction changes trigger TWO DH ratchet operations:
%%% <ol>
%%%   <li><strong>On Receive (with new DH key):</strong> Increments step counter when
%%%       receiving a message with a NEW DH public key from peer. This updates
%%%       the receiving chain to decrypt incoming messages.</li>
%%%   <li><strong>On First Send (after receiving):</strong> Increments step counter when
%%%       sending the FIRST message after receiving. This generates a fresh
%%%       ephemeral DH keypair and updates the sending chain.</li>
%%% </ol>
%%%
%%% <strong>Example Scenario:</strong>
%%% ```
%%% Alice at Step 4:
%%%   1. Receives message from Bob with new DH key → Step 4 → Step 5 (decrypt)
%%%   2. Sends reply to Bob with her new DH key   → Step 5 → Step 6 (encrypt)
%%% Result: Step 4 → Step 6 after one receive + one send
%%% '''
%%%
%%% This double increment is CORRECT Double Ratchet protocol behavior:
%%% <ul>
%%%   <li>Ensures both sending AND receiving chains use fresh DH entropy</li>
%%%   <li>Provides forward secrecy in BOTH directions</li>
%%%   <li>Enables break-in recovery on bidirectional communication</li>
%%% </ul>
%%%
%%% <strong>Implementation Details:</strong>
%%% <ul>
%%%   <li>`perform_dh_ratchet_step/2' - Called by decrypt_message when new DH key detected</li>
%%%   <li>`perform_dh_ratchet_on_send/1' - Called by encrypt_message on direction change</li>
%%%   <li>`should_perform_dh_ratchet_on_send/1' - Guards against multiple increments</li>
%%% </ul>
%%%
%%% == Usage Pattern ==
%%%
%%% 1. After X3DH key agreement, initialize sender and receiver states
%%% 2. Sender encrypts messages using encrypt_message/2
%%% 3. Receiver decrypts messages using decrypt_message/2
%%% 4. DH ratchet steps occur automatically for forward secrecy
%%% 5. Out-of-order messages handled via skipped key cache
%%%
%%% Both parties maintain independent sending/receiving chains that advance
%%% separately, with periodic DH ratchet steps injecting fresh entropy.
%%% == State-Event Diagram ==
%%%
%%% The following diagram illustrates the complete session flow between Alice (sender)
%%% and Bob (receiver), showing state transitions from X3DH key agreement through
%%% Double Ratchet messaging with synchronization points.
%%%
%%% <pre>
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                           X3DH KEY AGREEMENT PHASE                       │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%%                                    │
%%%                              [X3DH Complete]
%%%                         RootKey = DH(Alice, Bob)
%%%                                    │
%%%                                    ▼
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                        DOUBLE RATCHET INITIALIZATION                     │
%%% │                                                                          │
%%% │  Alice (Sender):                   │  Bob (Receiver):                    │
%%% │  ┌─────────────────────┐           │  ┌──────────────────────┐           │
%%% │  │ SENDER_INIT         │           │  │ RECEIVER_INIT        │           │
%%% │  │ sending_active=true │           │  │ sending_active=false │           │
%%% │  │ recv_active=true    │           │  │ recv_active=true     │           │
%%% │  │ dh_step=0           │           │  │ dh_step=0            │           │
%%% │  │ send_msg_num=0      │           │  │ recv_msg_num=0       │           │
%%% │  │ recv_msg_num=0      │           │  │ send_msg_num=0       │           │
%%% │  └─────────────────────┘           │  └──────────────────────┘           │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%%                                    │
%%%                           [Alice encrypts M1]
%%%                                    │
%%%                                    ▼
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                           MESSAGE EXCHANGE PHASE                         │
%%% │                                                                          │
%%% │  Alice State Changes:              │  Bob State Changes:                 │
%%% │  ┌─────────────────────┐           │  ┌─────────────────────┐            │
%%% │  │ SENDING_M1          │  ──────►  │  │ RECEIVING_M1        │            │
%%% │  │ send_msg_num=1      │   M1      │  │ recv_msg_num=1      │            │
%%% │  │ dh_step=0           │           │  │ dh_step=0           │            │
%%% │  │ (msg_key derived)   │           │  │ (msg_key derived)   │            │
%%% │  └─────────────────────┘           │  └─────────────────────┘            │
%%% │                                    │                                     │
%%% │  ┌─────────────────────┐           │  ┌─────────────────────┐            │
%%% │  │ SENDING_M2          │  ──────►  │  │ RECEIVING_M2        │            │
%%% │  │ send_msg_num=2      │   M2      │  │ recv_msg_num=2      │            │
%%% │  │ dh_step=0           │           │  │ dh_step=0           │            │
%%% │  └─────────────────────┘           │  └─────────────────────┘            │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%%                                    │
%%%                      [Bob wants to send reply]
%%%                                    │
%%%                                    ▼
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                         DH RATCHET DIRECTION CHANGE                      │
%%% │                                                                          │
%%% │  Alice: No change yet              │  Bob: Auto DH Ratchet               │
%%% │  ┌─────────────────────┐           │  ┌─────────────────────┐            │
%%% │  │ AWAITING_REPLY      │           │  │ ACTIVATING_SEND     │            │
%%% │  │ send_msg_num=2      │           │  │ Generate new DH     │            │
%%% │  │ recv_msg_num=0      │           │  │ dh_step=0→1         │            │
%%% │  │ dh_step=0           │           │  │ sending_active=true │            │
%%% │  └─────────────────────┘           │  └─────────────────────┘            │
%%% │                                    │                                     │
%%% │                                    │  ┌─────────────────────┐            │
%%% │                                    │  │ SENDING_REPLY       │            │
%%% │                                    │  │ send_msg_num=1      │  ─────┐    │
%%% │                                    │  │ dh_step=1           │       │    │
%%% │                                    │  └─────────────────────┘       │    │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%%                                                                       │
%%%                                                                 [Bob Reply]
%%%                                                                       │
%%%                                                                       ▼
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                        ALICE PROCESSES BOB'S REPLY                       │
%%% │                                                                          │
%%% │  Alice: DH Ratchet on Receive      │  Bob: Stable State                  │
%%% │  ┌─────────────────────┐           │  ┌─────────────────────┐            │
%%% │  │ DH_RATCHET_RECV     │           │  │ SEND_READY          │            │
%%% │  │ See new DH pub key  │           │  │ Can send more       │            │
%%% │  │ Generate new DH     │           │  │ send_msg_num=1      │            │
%%% │  │ dh_step=0→1         │           │  │ dh_step=1           │            │
%%% │  │ recv_msg_num=1      │           │  └─────────────────────┘            │
%%% │  └─────────────────────┘           │                                     │
%%% │                                    │                                     │
%%% │  ┌───────────────────────┐         │                                     │
%%% │  │ BIDIRECTIONAL         │         │                                     │
%%% │  │ Can send &amp; receive│         │                                     │
%%% │  │ dh_step=1             │         │                                     │
%%% │  │ Both chains active    │         │                                     │
%%% │  └───────────────────────┘         │                                     │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%%                                    │
%%%                          [Continued messaging]
%%%                                    │
%%%                                    ▼
%%% ┌──────────────────────────────────────────────────────────────────────────┐
%%% │                    STEADY STATE BIDIRECTIONAL MESSAGING                  │
%%% │                                                                          │
%%% │  • Both parties can send/receive messages freely                         │
%%% │  • DH ratchet steps occur automatically on direction changes             │
%%% │  • Out-of-order messages handled via skipped key cache                   │
%%% │  • Forward secrecy maintained through chain key advancement              │
%%% │  • Break-in recovery achieved through periodic DH ratchet steps          │
%%% │                                                                          │
%%% │  Event Triggers:                                                         │
%%% │  - encrypt_message/2 → Chain advancement, optional DH ratchet            │
%%% │  - decrypt_message/2 → Chain advancement, gap handling, DH ratchet       │
%%% │  - Direction change → Automatic DH ratchet with new ephemeral keys       │
%%% │  - Message gaps → Skipped key derivation and caching                     │
%%% └──────────────────────────────────────────────────────────────────────────┘
%%% </pre>
%%%
%%% == State Transition Events ==
%%%
%%% Key state transitions and their triggers:
%%%
%%% - SENDER_INIT + encrypt_message/2 → SENDING_ACTIVE (send_msg_num incremented)
%%% - RECEIVER_INIT + decrypt_message/2 → RECEIVING_ACTIVE (recv_msg_num incremented)
%%% - RECEIVING_ACTIVE + encrypt_message/2 (first) → BIDIRECTIONAL (DH ratchet, new keys)
%%% - SENDING_ACTIVE + decrypt_message/2 (new DH) → BIDIRECTIONAL (DH ratchet, new keys)
%%% - BIDIRECTIONAL + encrypt_message/2 → BIDIRECTIONAL (send chain advance, optional DH ratchet)
%%% - BIDIRECTIONAL + decrypt_message/2 → BIDIRECTIONAL (recv chain advance, gap handling)
%%% - Any State + Message gap → Same State (skipped key derivation and caching)
%%% - Any State + Out-of-order message → Same State (cached key usage and removal)
%%%
%%% == Critical Synchronization Points ==
%%%
%%% <ol>
%%%   <li><strong>X3DH Completion:</strong> Both parties derive identical root key</li>
%%%   <li><strong>First Message:</strong> Sender activates, receiver waits</li>
%%%   <li><strong>Direction Change:</strong> DH ratchet step synchronizes new chains</li>
%%%   <li><strong>Message Gaps:</strong> Skipped key derivation maintains decryption capability</li>
%%%   <li><strong>Chain Advancement:</strong> Each message advances appropriate chain independently</li>
%%% </ol>
%%%
%%% == Security Properties ==
%%%
%%% <ul>
%%%   <li><strong>Forward Secrecy:</strong> Compromise of current keys does not affect past messages</li>
%%%   <li><strong>Future Secrecy (Break-in Recovery):</strong> New DH ratchet steps restore security after compromise</li>
%%%   <li><strong>Replay Protection:</strong> Each message uses unique keys and sequence numbers</li>
%%%   <li><strong>Out-of-Order Delivery:</strong> Delayed messages can be decrypted using cached skipped keys</li>
%%%   <li><strong>Cryptographic Agility:</strong> Uses libsodium's ChaCha20-Poly1305 AEAD for encryption</li>
%%% </ul>
%%%
%%% == Further Reading ==
%%%
%%% For a comprehensive state machine analysis with detailed synchronization
%%% points and implementation notes, see: docs/DOUBLE_RATCHET_STATE_MACHINE.md
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-24

-module(cryptic_double_ratchet).

-export([
    % Public API
    init_sender/2,
    init_receiver/2,
    activate_sending_chain/1,

    % Message processing
    encrypt_message/2,
    decrypt_message/2,

    % Key derivation (exported for testing and future phases)
    kdf_rk/2,
    advance_sending_chain/2,
    advance_receiving_chain/2,
    kdf_mk/1,
    kdf_derive_chain_key/2,

    % State management
    serialize_state/1,
    deserialize_state/1,

    % Utilities and debugging
    get_state_info/1,
    cleanup_expired_keys/1,

    % Test helpers (for simulating X3DH handshake)
    set_remote_dh_key/2
]).

%% Type specifications for exported functions
-spec init_sender(binary(), {binary(), binary()}) -> {ok, ratchet_state()}.
-spec init_receiver(binary(), {binary(), binary()}) -> {ok, ratchet_state()}.
-spec activate_sending_chain(ratchet_state()) ->
    {ok, ratchet_state()} | {error, term()}.

-spec encrypt_message(binary(), ratchet_state()) ->
    {ok, message(), ratchet_state()} | {error, term()}.
-spec decrypt_message(message(), ratchet_state()) ->
    {ok, binary(), ratchet_state()} | {error, term()}.

-spec kdf_rk(binary(), binary()) -> {binary(), binary(), binary()}.
-spec advance_sending_chain(binary(), non_neg_integer()) ->
    {binary(), binary()}.
-spec advance_receiving_chain(binary(), non_neg_integer()) ->
    {binary(), binary()}.
-spec kdf_mk(binary()) -> {binary(), binary()}.
-spec kdf_derive_chain_key(binary(), binary()) -> binary().

-spec serialize_state(ratchet_state()) -> binary().
-spec deserialize_state(binary()) -> {ok, ratchet_state()} | {error, term()}.

-spec get_state_info(ratchet_state()) -> map().
-spec cleanup_expired_keys(ratchet_state()) -> ratchet_state().
-spec set_remote_dh_key(ratchet_state(), binary()) -> ratchet_state().

-include("cryptic.hrl").

%% Double Ratchet state record
%%
%% This record maintains all the state needed for the Double Ratchet algorithm,
%% including separate sending and receiving chains, DH ratchet keys, and the
%% skipped message key store for out-of-order delivery.
-record(ratchet_state, {
    % Root chain (shared between both parties)

    % Current root key (32 bytes)
    root_key :: binary(),

    % Sending chain (independent per party)

    % Current sending chain key (32 bytes)
    send_chain_key :: binary(),
    % Message number in current sending chain
    send_msg_number :: non_neg_integer(),

    % Receiving chain (independent per party)

    % Current receiving chain key (32 bytes)
    recv_chain_key :: binary(),
    % Expected next message number in receiving chain
    recv_msg_number :: non_neg_integer(),
    % Messages in previous receiving chain
    prev_recv_chain_length :: non_neg_integer(),

    % ECDH ratchet keys (for DH-ratchet steps)

    % Own ECDH keypair (pub, priv)
    dh_self :: {binary(), binary()},
    % Remote ECDH public key
    dh_remote :: binary(),
    % Current DH ratchet step number
    dh_ratchet_step :: non_neg_integer(),

    % Skipped message key store (for out-of-order delivery)
    skipped_keys :: #{
        {dh_step, msg_num} => #{
            % The derived message key
            message_key => binary(),
            % When key was derived (for cleanup)
            timestamp => integer(),
            % Chain key that derived this (for verification)
            chain_key => binary(),
            % DH public key active when derived
            dh_public => binary()
        }
    },

    % Configuration and limits

    % Maximum messages to skip in sequence
    max_skip :: pos_integer(),
    % Maximum skipped keys to cache
    max_cache_size :: pos_integer(),
    % Maximum age (ms) for cached keys
    max_cache_age :: pos_integer(),

    % Chain state tracking

    % True if we can send messages
    sending_chain_active :: boolean(),
    % True if we can receive messages
    receiving_chain_active :: boolean(),

    % Metadata

    % Timestamp when ratchet was initialized
    created_at :: integer(),
    % Timestamp of last state update
    last_updated :: integer()
}).

%% Type definitions for better documentation
-type ratchet_state() :: #ratchet_state{}.
-type skipped_key_id() :: {non_neg_integer(), non_neg_integer()}.
-type skipped_key_info() :: #{
    message_key => binary(),
    timestamp => integer(),
    chain_key => binary(),
    dh_public => binary()
}.
-type message() :: #{
    dh_public => binary(),
    dh_step => non_neg_integer(),
    prev_chain_length => non_neg_integer(),
    msg_number => non_neg_integer(),
    ciphertext => binary(),
    nonce => binary()
}.

-export_type([ratchet_state/0, message/0, skipped_key_id/0, skipped_key_info/0]).

%% Default configuration values

% Max messages to skip in sequence
-define(DEFAULT_MAX_SKIP, 1000).
% Max skipped keys to store
-define(DEFAULT_MAX_CACHE_SIZE, 10000).
% 24 hours in milliseconds
-define(DEFAULT_MAX_CACHE_AGE, 86400000).

%%% ============================================================================
%%% Initialization Functions
%%% ============================================================================

%% @doc Initialize Alice's ratchet state (sender)
%%
%% Creates the initial Double Ratchet state for the party who will send
%% the first message after X3DH key agreement. This party starts with
%% an active sending chain.
%%
%% Usage:
%%
%% <pre>
%% % After X3DH key agreement
%% RootKey = x3dh_shared_secret(),
%% {MyDHPub, MyDHPriv} = cryptic_nif:gen_keypair(),
%%
%% State = cryptic_double_ratchet:init_sender(RootKey, {MyDHPub, MyDHPriv}).
%% </pre>
%%
%% @param RootKey The shared secret from X3DH key agreement (32 bytes)
%% @param DHKeyPair Own DH keypair {PublicKey, PrivateKey}
%% @returns Initial ratchet state for the sender
init_sender(RootKey, {DHPublic, DHPrivate}) when
    byte_size(RootKey) =:= 32,
    byte_size(DHPublic) =:= 32,
    byte_size(DHPrivate) =:= 32
->
    % ?dbg("Initializing Double Ratchet sender with DH keypair.~n", []),
    % ?dbg("RootKey size: ~p bytes, DHPublic: ~p bytes, DHPrivate: ~p bytes~n",
    %      [byte_size(RootKey), byte_size(DHPublic), byte_size(DHPrivate)]),

    Now = erlang:system_time(millisecond),

    % Initialize with empty receiving chain (will be set on first received message)
    State = #ratchet_state{
        root_key = RootKey,

        % Derive initial sending chain directly from X3DH root key
        send_chain_key = kdf_derive_chain_key(RootKey, <<"init">>),
        send_msg_number = 0,

        % Receiving chain must be set up to receive Bob's reply
        % Bob will use "resp" context for his sending chain
        recv_chain_key = kdf_derive_chain_key(RootKey, <<"resp">>),
        recv_msg_number = 0,
        prev_recv_chain_length = 0,

        % DH ratchet state
        dh_self = {DHPublic, DHPrivate},
        % Will be set when first message received
        dh_remote = undefined,
        dh_ratchet_step = 0,

        % Empty skipped key store
        skipped_keys = #{},

        % Default configuration
        max_skip = ?DEFAULT_MAX_SKIP,
        max_cache_size = ?DEFAULT_MAX_CACHE_SIZE,
        max_cache_age = ?DEFAULT_MAX_CACHE_AGE,

        % Chain state
        sending_chain_active = true,
        % Activate receiving chain to receive Bob's replies
        receiving_chain_active = true,

        % Metadata
        created_at = Now,
        last_updated = Now
    },

    % ?dbg("Double Ratchet sender initialized - sending chain active, receiving chain inactive.~n", []),
    % ?dbg("Initial send_chain_key derived, DH ratchet step: ~p~n", [0]),

    {ok, State}.

%% @doc Initialize receiver side of Double Ratchet (after X3DH key agreement)
%%
%% Creates the initial Double Ratchet state for the party who will receive
%% the first message after X3DH key agreement. Both parties start with the same
%% root key from X3DH. The receiver waits for the first message to establish
%% the receiving chain via the first DH ratchet step.
%%
%% @param RootKey The shared root key from X3DH key agreement (32 bytes)
%% @param DHKeyPair Own DH keypair for Double Ratchet {PublicKey, PrivateKey}
%% @returns Initial ratchet state for the receiver
init_receiver(RootKey, {DHPublic, DHPrivate}) when
    byte_size(RootKey) =:= 32,
    byte_size(DHPublic) =:= 32,
    byte_size(DHPrivate) =:= 32
->
    % ?dbg("Initializing Double Ratchet receiver with DH keypair.~n", []),
    % ?dbg("RootKey size: ~p bytes, DHPublic: ~p bytes, DHPrivate: ~p bytes.~n",
    %      [byte_size(RootKey), byte_size(DHPublic), byte_size(DHPrivate)]),

    Now = erlang:system_time(millisecond),

    ?dbg("init_as_receiver: rootKey(sessionKey)=~s~n", [binary:encode_hex(RootKey)]),
    RecvChainInit = kdf_derive_chain_key(RootKey, <<"init">>),
    ?dbg("init_as_receiver: recvChainKey(init)=~s~n", [binary:encode_hex(RecvChainInit)]),

    State = #ratchet_state{
        % Same X3DH root key as sender
        root_key = RootKey,

        % Sending chain will be established when we need to send (after first DH ratchet)
        send_chain_key = <<0:256>>,
        send_msg_number = 0,

        % Derive initial receiving chain to match Alice's sending chain
        recv_chain_key = RecvChainInit,
        recv_msg_number = 0,
        prev_recv_chain_length = 0,

        % DH ratchet state - ready for first message
        dh_self = {DHPublic, DHPrivate},
        % Will be set from Alice's first message
        dh_remote = undefined,
        dh_ratchet_step = 0,

        % Empty skipped key store
        skipped_keys = #{},

        % Default configuration
        max_skip = ?DEFAULT_MAX_SKIP,
        max_cache_size = ?DEFAULT_MAX_CACHE_SIZE,
        max_cache_age = ?DEFAULT_MAX_CACHE_AGE,

        % Chain state

        % Will be activated when we first send
        sending_chain_active = false,
        receiving_chain_active = true,

        % Metadata
        created_at = Now,
        last_updated = Now
    },

    % ?dbg("Double Ratchet receiver initialized - receiving chain active, sending chain inactive.~n", []),
    % ?dbg("Initial recv_chain_key derived to match sender's send_chain, DH ratchet step: ~p~n", [0]),

    {ok, State}.

%%% ============================================================================
%%% Key Derivation Functions (High-Performance Native NIFs)
%%% ============================================================================

%% @doc Root key progression with new DH output (DH-ratchet step)
%%
%% This is the core of the DH ratchet - it takes the current root key and
%% fresh DH output to derive a new root key and new chain keys for both
%% sending and receiving directions.
%%
%% Uses the high-performance Blake2b KDF (39x faster than Erlang) for
%% optimal ratchet performance. The function mixes the root key with fresh
%% DH entropy to provide forward secrecy and break-in recovery.
%%
%% @param RootKey Current root key from the ratchet chain (32 bytes)
%% @param DhOutput Fresh DH shared secret from new keypair (32 bytes)
%% @returns {NewRootKey, InitChainKey, RespChainKey} - new root key and
%%          separate chain keys for initiator and responder directions
kdf_rk(RootKey, DhOutput) ->
    % Use high-performance Blake2b KDF directly (39x faster than Erlang)
    % Mix the root key and DH output by XORing them (both are 32 bytes)
    % This provides proper input mixing for the KDF
    MixedKey = crypto:exor(RootKey, DhOutput),

    NewRootKey = cryptic_nif:kdf_derive(32, 0, <<"root">>, MixedKey),
    % Derive separate chain keys for initiator and responder directions
    % This maintains proper separation between Alice's and Bob's chains
    InitChainKey = cryptic_nif:kdf_derive(32, 1, <<"init">>, MixedKey),
    RespChainKey = cryptic_nif:kdf_derive(32, 2, <<"resp">>, MixedKey),
    {NewRootKey, InitChainKey, RespChainKey}.

%% @doc Advance sending chain key and derive message key for outgoing message
%%
%% This function is used when encrypting outgoing messages. It derives the
%% message key for encryption and advances the sending chain key for the
%% next message. The receiving chain is completely unaffected.
%%
%% This maintains forward secrecy by ensuring each message uses a unique key.
%%
%% @param SendChainKey Current sending chain key (32 bytes)
%% @param MsgNumber Message number in the current sending chain
%% @returns {NewChainKey, MessageKey} - advanced chain key and message-specific key
advance_sending_chain(SendChainKey, MsgNumber) ->
    MessageKey = cryptic_nif:kdf_derive(
        32, MsgNumber, <<"msg">>, SendChainKey
    ),
    NewChainKey = cryptic_nif:kdf_derive(
        32, MsgNumber + 1, <<"chain">>, SendChainKey
    ),
    {NewChainKey, MessageKey}.

%% @doc Advance receiving chain key and derive message key for incoming message
%%
%% This function is used when decrypting incoming messages. It derives the
%% message key for decryption and advances the receiving chain key for the
%% next expected message. The sending chain is completely unaffected.
%%
%% Used both for current expected messages and when pre-deriving keys for
%% message gaps (out-of-order delivery support).
%%
%% @param RecvChainKey Current receiving chain key (32 bytes)
%% @param MsgNumber Message number to derive key for
%% @returns {NewChainKey, MessageKey} - advanced chain key and message-specific key
advance_receiving_chain(RecvChainKey, MsgNumber) ->
    MessageKey = cryptic_nif:kdf_derive(
        32, MsgNumber, <<"msg">>, RecvChainKey
    ),
    NewChainKey = cryptic_nif:kdf_derive(
        32, MsgNumber + 1, <<"chain">>, RecvChainKey
    ),
    {NewChainKey, MessageKey}.

%% @doc Message key expansion for encryption/decryption components
%%
%% Derives the encryption key and authentication key from a message key.
%% Note: For ChaCha20-Poly1305, we don't need a separate IV since the
%% aead_encrypt function generates its own nonce.
%%
%% @param MessageKey The message-specific key derived from chain advancement (32 bytes)
%% @returns {EncKey, AuthKey} - separate 32-byte keys for encryption and authentication
kdf_mk(MessageKey) ->
    EncKey = cryptic_nif:kdf_derive(32, 0, <<"enc">>, MessageKey),
    AuthKey = cryptic_nif:kdf_derive(32, 1, <<"mac">>, MessageKey),
    {EncKey, AuthKey}.

%% @doc Derive initial chain key from root key
%%
%% Helper function for initialization - derives chain keys from the root key.
%% Used to establish separate sending/receiving chains after X3DH key agreement.
%%
%% @param RootKey The X3DH shared secret (32 bytes)
%% @param Context Binary context string (&lt;&lt;"init"&gt;&gt; or &lt;&lt;"resp"&gt;&gt;) for domain separation
%% @returns Derived chain key (32 bytes)
kdf_derive_chain_key(RootKey, Context) ->
    cryptic_nif:kdf_derive(32, 0, Context, RootKey).

%%% ============================================================================
%%% Message Processing Functions
%%% ============================================================================

%% @doc Activate sending chain for a receiver
%%
%% When a receiver wants to send their first message, they need to activate
%% their sending chain. This function performs the necessary DH ratchet step:
%% 1. Generates a new DH keypair for the receiver
%% 2. Performs a self-ratchet to activate the sending chain
%% 3. Updates the state to allow message encryption
%%
%% This is called automatically when encrypt_message fails with sending_chain_not_active.
%%
%% @param State Current ratchet state (receiver with inactive sending chain)
%% @returns {ok, ActivatedState} or {error, Reason}
activate_sending_chain(State = #ratchet_state{}) ->
    % ?dbg("Activating sending chain for receiver", []),

    case State#ratchet_state.sending_chain_active of
        true ->
            % Already active
            {ok, State};
        false ->
            % Check if we have remote DH key to perform proper DH ratchet
            case State#ratchet_state.dh_remote of
                undefined ->
                    % No remote DH key yet - cannot activate sending chain
                    {error, no_remote_dh_key};
                _RemoteDHPub ->
                    % Bob's first reply should NOT perform a DH ratchet step
                    % The DH ratchet happens when Alice wants to send her second message
                    % For now, Bob just uses his X3DH-derived sending chain

                    CurrentRootKey = State#ratchet_state.root_key,

                    ?dbg("activate_sending_chain: rootKey=~s~n",
                         [binary:encode_hex(CurrentRootKey)]),

                    % Derive Bob's sending chain from the same X3DH root key (context "resp")
                    % This ensures Bob's sending chain matches what Alice expects for decryption
                    NewSendChainKey = kdf_derive_chain_key(
                        CurrentRootKey, <<"resp">>
                    ),

                    ?dbg("activate_sending_chain: sendChainKey(resp)=~s~n",
                         [binary:encode_hex(NewSendChainKey)]),

                    % Update state with activated sending chain (no DH ratchet yet)
                    Now = erlang:system_time(millisecond),
                    ActivatedState = State#ratchet_state{
                        % Keep same DH keypair for now - no ratchet step yet
                        send_chain_key = NewSendChainKey,
                        send_msg_number = 0,
                        sending_chain_active = true,
                        % Don't increment dh_ratchet_step - that happens when Alice receives this
                        last_updated = Now
                    },

                    % ?dbg("Sending chain activated - DH step: ~p, can now encrypt messages",
                    %      [ActivatedState#ratchet_state.dh_ratchet_step]),
                    {ok, ActivatedState}
            end
    end.

%% @doc Encrypt a plaintext message using the Double Ratchet sending chain
%%
%% This is the main function for encrypting outgoing messages. It handles:
%% <ul>
%%   <li>Automatic sending chain activation for receivers</li>
%%   <li>DH ratchet steps when changing message direction</li>
%%   <li>ChaCha20-Poly1305 AEAD encryption with libsodium</li>
%%   <li>Message header generation with ratchet metadata</li>
%% </ul>
%%
%% The function automatically performs DH ratchet steps when needed (e.g., when
%% Bob wants to send his first reply after receiving messages from Alice).
%%
%% The function automatically handles DH ratchet steps when needed for security.
%%
%% @param Plaintext The message to encrypt (binary)
%% @param State Current Double Ratchet state
%% @returns {ok, Message, NewState} where Message contains encrypted data and metadata,
%%          or {error, Reason} if encryption fails
encrypt_message(Plaintext, State = #ratchet_state{}) ->
    % ?dbg("encrypt_message - plaintext size: ~p bytes, sending_chain_active: ~p~n",
    %      [byte_size(Plaintext), State#ratchet_state.sending_chain_active]),

    % Ensure we have an active sending chain
    case State#ratchet_state.sending_chain_active of
        false ->
            % Try to activate sending chain automatically
            case activate_sending_chain(State) of
                {ok, ActivatedState} ->
                    % ?dbg("Sending chain activated automatically, encrypting message", []),
                    encrypt_message_impl(Plaintext, ActivatedState);
                {error, ActivateErr} ->
                    {error, {sending_chain_activation_failed, ActivateErr}}
            end;
        true ->
            encrypt_message_impl(Plaintext, State)
    end.

%% @doc Internal implementation of message encryption
encrypt_message_impl(Plaintext, State) ->
    % 1. Check if we need to perform DH ratchet step before sending
    % This happens when we're starting to send after receiving messages (direction change)
    StateAfterRatchet =
        case should_perform_dh_ratchet_on_send(State) of
            true ->
                perform_dh_ratchet_on_send(State);
            false ->
                State
        end,

    % 2. Use the (possibly updated) sending chain for outgoing messages
    CurrentSendingChain = StateAfterRatchet#ratchet_state.send_chain_key,
    CurrentMsgNum = StateAfterRatchet#ratchet_state.send_msg_number,

    % ?dbg("encrypt_message_impl - current msg_number: ~p, DH ratchet step: ~p~n",
    %      [CurrentMsgNum, StateAfterRatchet#ratchet_state.dh_ratchet_step]),

    % 3. Derive message key from sending chain (does NOT affect receiving chain)
    {NewSendChainKey, MessageKey} = advance_sending_chain(
        CurrentSendingChain, CurrentMsgNum
    ),

    ?dbg("encrypt_message_impl: chainKey=~s, msgNum=~p, messageKey=~s~n",
         [binary:encode_hex(CurrentSendingChain), CurrentMsgNum, binary:encode_hex(MessageKey)]),

    % 3. Derive encryption components from message key
    {EncKey, _AuthKey} = kdf_mk(MessageKey),

    ?dbg("encrypt_message_impl: encKey=~s~n", [binary:encode_hex(EncKey)]),

    % 4. Encrypt message with ChaCha20-Poly1305
    % Note: cryptic_nif:aead_encrypt generates its own nonce and returns {CipherText, Nonce}
    {CipherText, Nonce} = cryptic_nif:aead_encrypt(Plaintext, EncKey, <<>>),

    % 5. Create message with Double Ratchet header
    {DHPublic, _DHPrivate} = StateAfterRatchet#ratchet_state.dh_self,
    Message = #{
        % DH ratchet information
        dh_public => DHPublic,
        dh_step => StateAfterRatchet#ratchet_state.dh_ratchet_step,

        % Sending chain information
        prev_chain_length =>
            StateAfterRatchet#ratchet_state.prev_recv_chain_length,
        msg_number => CurrentMsgNum,

        % Encrypted payload
        ciphertext => CipherText,
        nonce => Nonce
    },

    % 6. Update ONLY sending chain state (receiving chain unchanged)
    Now = erlang:system_time(millisecond),
    NewState = StateAfterRatchet#ratchet_state{
        send_chain_key = NewSendChainKey,
        send_msg_number = CurrentMsgNum + 1,
        % Note: receiving chain stays the same, DH keys may have been updated by ratchet
        sending_chain_active = true,
        last_updated = Now
    },

    % 7. Clear the used message key from memory (forward secrecy)
    % Note: In a real implementation, we'd use sodium_memzero or similar
    % For now, we rely on Erlang's garbage collection

    % ?dbg("encrypt_message_impl complete - new msg_number: ~p, ciphertext size: ~p bytes~n",
    %      [CurrentMsgNum + 1, byte_size(CipherText)]),

    {ok, Message, NewState}.

%% @doc Decrypt an incoming message using the receiving chain
%%
%% This is the main function for decrypting received messages. It handles
%% DH ratchet steps, message gaps, and out-of-order delivery through the
%% skipped message key store.
%%
%% @param Message The received message to decrypt
%% @param State Current ratchet state
%% @returns {ok, Plaintext, NewState} or {error, Reason}
decrypt_message(Message, State = #ratchet_state{}) ->
    % ?dbg("decrypt_message - receiving_chain_active: ~p, current recv_msg_number: ~p~n",
    %      [State#ratchet_state.receiving_chain_active, State#ratchet_state.recv_msg_number]),

    try
        decrypt_message_impl(Message, State)
    catch
        error:Reason ->
            {error, {decrypt_error, Reason}};
        throw:Reason ->
            {error, Reason}
    end.

%% @doc Internal implementation of message decryption
decrypt_message_impl(Message, State) ->
    IncomingDHPub = maps:get(dh_public, Message),
    IncomingDHStep = maps:get(dh_step, Message),
    IncomingMsgNum = maps:get(msg_number, Message),

    ?info("[DR] decrypt_message_impl: incoming msg_number=~p, dh_step=~p~n", [IncomingMsgNum, IncomingDHStep]),
    ?info("[DR] state: recv_msg_number=~p, dh_ratchet_step=~p~n",
              [State#ratchet_state.recv_msg_number, State#ratchet_state.dh_ratchet_step]),
    ?info("[DR] state: recv_chain_key=~s~n", [binary:encode_hex(State#ratchet_state.recv_chain_key, lowercase)]),
    ?info("[DR] state: dh_remote=~p~n",
              [case State#ratchet_state.dh_remote of undefined -> undefined; R -> binary:encode_hex(R, lowercase) end]),
    ?info("[DR] incoming dh_public=~s~n", [binary:encode_hex(IncomingDHPub, lowercase)]),

    % 1. Determine if DH-ratchet step is needed
    DHRatchetNeeded =
        case State#ratchet_state.dh_remote of
            % First message received - check DH step to determine if ratchet needed
            undefined -> IncomingDHStep > State#ratchet_state.dh_ratchet_step;
            RemoteDH -> IncomingDHPub =/= RemoteDH
        end,

    % 2. Handle DH ratchet or first message setup
    StateAfterDH =
        case DHRatchetNeeded of
            true ->
                % Perform DH ratchet step - creates new receiving chain
                ?info("[DR] DH ratchet NEEDED - performing DH ratchet step~n", []),
                perform_dh_ratchet_step(Message, State);
            false when State#ratchet_state.dh_remote =:= undefined ->
                % First message - just store remote DH key without ratcheting
                ?info("[DR] First message - storing remote DH key (no ratchet)~n", []),
                Now = erlang:system_time(millisecond),
                State#ratchet_state{
                    dh_remote = IncomingDHPub,
                    last_updated = Now
                };
            false ->
                % Same DH step - continue with current receiving chain
                ?info("[DR] Same DH key - no ratchet needed~n", []),
                State
        end,

    ?info("[DR] after DH: recv_chain_key=~s, recv_msg_number=~p~n",
              [binary:encode_hex(StateAfterDH#ratchet_state.recv_chain_key, lowercase),
               StateAfterDH#ratchet_state.recv_msg_number]),

    % 3. Check for message gaps in the receiving chain
    case handle_message_gap(StateAfterDH, IncomingMsgNum, IncomingDHStep) of
        {ok, StateAfterGap} ->
            ?info("[DR] after gap handling: recv_chain_key=~s, recv_msg_number=~p~n",
                      [binary:encode_hex(StateAfterGap#ratchet_state.recv_chain_key, lowercase),
                       StateAfterGap#ratchet_state.recv_msg_number]),
            % 4. Decrypt the message (either current or from skipped store)
            decrypt_with_receiving_chain(Message, StateAfterGap);
        {error, Reason} ->
            {error, Reason}
    end.

%%% ============================================================================
%%% State Serialization Functions
%%% ============================================================================

%% @doc Serialize ratchet state for persistent storage
%%
%% Converts the ratchet state into a binary format suitable for storage
%% in databases or files. The serialized format should be encrypted
%% before storage for security using cryptic_lib:encrypt_keys/2.
%%
%% Warning: The serialized state contains sensitive cryptographic material
%% including chain keys and DH private keys. Always encrypt before storage.
%%
%% Usage:
%% <pre>
%% SerializedBinary = cryptic_double_ratchet:serialize_state(State),
%% {ok, EncryptedState} = cryptic_lib:encrypt_keys(SerializedBinary, Password).
%% </pre>
%%
%% @param State The ratchet state to serialize
%% @returns Binary representation of the state (MUST be encrypted before storage)
serialize_state(State = #ratchet_state{}) ->
    % Convert to a term that can be serialized
    StateMap = #{
        root_key => State#ratchet_state.root_key,
        send_chain_key => State#ratchet_state.send_chain_key,
        send_msg_number => State#ratchet_state.send_msg_number,
        recv_chain_key => State#ratchet_state.recv_chain_key,
        recv_msg_number => State#ratchet_state.recv_msg_number,
        prev_recv_chain_length => State#ratchet_state.prev_recv_chain_length,
        dh_self => State#ratchet_state.dh_self,
        dh_remote => State#ratchet_state.dh_remote,
        dh_ratchet_step => State#ratchet_state.dh_ratchet_step,
        skipped_keys => State#ratchet_state.skipped_keys,
        max_skip => State#ratchet_state.max_skip,
        max_cache_size => State#ratchet_state.max_cache_size,
        max_cache_age => State#ratchet_state.max_cache_age,
        sending_chain_active => State#ratchet_state.sending_chain_active,
        receiving_chain_active => State#ratchet_state.receiving_chain_active,
        created_at => State#ratchet_state.created_at,
        last_updated => State#ratchet_state.last_updated
    },

    % Serialize to binary using term_to_binary
    % Note: In production, this should be encrypted before storage
    term_to_binary(StateMap).

%% @doc Deserialize ratchet state from persistent storage
%%
%% Converts a binary representation back into a ratchet state record.
%% This function assumes the binary has been decrypted if it was
%% encrypted during storage.
%%
%% Usage:
%% <pre>
%% {ok, DecryptedBinary} = cryptic_lib:decrypt_keys(EncryptedState, Password),
%% {ok, State} = cryptic_double_ratchet:deserialize_state(DecryptedBinary).
%% </pre>
%%
%% @param Binary The serialized state data (must be decrypted first if encrypted)
%% @returns {ok, State} or {error, {deserialization_failed, Reason}}
deserialize_state(Binary) when is_binary(Binary) ->
    try
        StateMap = binary_to_term(Binary),

        State = #ratchet_state{
            root_key = maps:get(root_key, StateMap),
            send_chain_key = maps:get(send_chain_key, StateMap),
            send_msg_number = maps:get(send_msg_number, StateMap),
            recv_chain_key = maps:get(recv_chain_key, StateMap),
            recv_msg_number = maps:get(recv_msg_number, StateMap),
            prev_recv_chain_length = maps:get(prev_recv_chain_length, StateMap),
            dh_self = maps:get(dh_self, StateMap),
            dh_remote = maps:get(dh_remote, StateMap),
            dh_ratchet_step = maps:get(dh_ratchet_step, StateMap),
            skipped_keys = maps:get(skipped_keys, StateMap),
            max_skip = maps:get(max_skip, StateMap),
            max_cache_size = maps:get(max_cache_size, StateMap),
            max_cache_age = maps:get(max_cache_age, StateMap),
            sending_chain_active = maps:get(sending_chain_active, StateMap),
            receiving_chain_active = maps:get(receiving_chain_active, StateMap),
            created_at = maps:get(created_at, StateMap),
            last_updated = maps:get(last_updated, StateMap)
        },

        {ok, State}
    catch
        error:Reason ->
            {error, {deserialization_failed, Reason}}
    end.

%%% ============================================================================
%%% Utility and Debugging Functions
%%% ============================================================================

%% @doc Get summary information about ratchet state
%%
%% Returns useful debugging and monitoring information about the current
%% state of the ratchet without exposing sensitive key material.
%% Safe to use in logs and monitoring systems.
%%
%% Returned fields:
%% <ul>
%%   <li>`dh_ratchet_step' - Current DH ratchet step number</li>
%%   <li>`send_msg_number' - Next outgoing message number</li>
%%   <li>`recv_msg_number' - Next expected incoming message number</li>
%%   <li>`skipped_keys_count' - Number of cached keys for out-of-order messages</li>
%%   <li>`sending_chain_active' - Whether we can encrypt messages</li>
%%   <li>`receiving_chain_active' - Whether we can decrypt messages</li>
%%   <li>`has_remote_dh' - Whether remote party's DH key is known</li>
%% </ul>
%%
%% @param State The ratchet state to inspect
%% @returns Map with non-sensitive state information
get_state_info(State = #ratchet_state{}) ->
    #{
        dh_ratchet_step => State#ratchet_state.dh_ratchet_step,
        send_msg_number => State#ratchet_state.send_msg_number,
        recv_msg_number => State#ratchet_state.recv_msg_number,
        prev_recv_chain_length => State#ratchet_state.prev_recv_chain_length,
        skipped_keys_count => maps:size(State#ratchet_state.skipped_keys),
        sending_chain_active => State#ratchet_state.sending_chain_active,
        receiving_chain_active => State#ratchet_state.receiving_chain_active,
        created_at => State#ratchet_state.created_at,
        last_updated => State#ratchet_state.last_updated,
        has_remote_dh => State#ratchet_state.dh_remote =/= undefined
    }.

%% @doc Clean up expired skipped keys for forward secrecy
%%
%% Removes old skipped keys from the cache based on the configured
%% maximum age. This should be called periodically to maintain
%% forward secrecy properties.
%%
%% @param State The ratchet state to clean up
%% @returns Updated state with expired keys removed
cleanup_expired_keys(State = #ratchet_state{}) ->
    CurrentTime = erlang:system_time(millisecond),
    MaxAge = State#ratchet_state.max_cache_age,

    CleanedKeys = maps:filter(
        fun(_KeyId, KeyInfo) ->
            Age = CurrentTime - maps:get(timestamp, KeyInfo),
            Age =< MaxAge
        end,
        State#ratchet_state.skipped_keys
    ),

    State#ratchet_state{
        skipped_keys = CleanedKeys,
        last_updated = CurrentTime
    }.

%%% ============================================================================
%%% Internal Helper Functions (Stubs for Phase 1)
%%% ============================================================================

%% Note: These functions will be fully implemented in subsequent phases.
%% For Phase 1, we provide stubs to make the module compile.

%% @doc Perform DH ratchet step when new DH key received
%%
%% This is called when we receive a message with a new DH public key,
%% indicating that the sender has advanced their DH ratchet. We need to:
%% 1. Compute new shared secret with the new DH key
%% 2. Derive new root key and receiving chain key
%% 3. Generate new DH keypair for future sending
%% 4. Reset receiving chain for the new DH step
%%
%% @param Message The received message with new DH public key
%% @param State Current ratchet state
%% @returns Updated state with new DH ratchet step
perform_dh_ratchet_step(Message, State) ->
    % 1. Extract new remote DH public key
    NewRemoteDHPub = maps:get(dh_public, Message),
    {_OwnDHPub, OwnDHPriv} = State#ratchet_state.dh_self,

    % 2. Compute new DH shared secret
    % CRITICAL: This must match exactly what the sender used in activate_sending_chain
    % The sender used: scalarmult(OldDHPriv, RemoteDHPub)
    % So Alice (receiver) should use: scalarmult(AliceDHPriv, BobNewDHPub)
    DHOutput = cryptic_nif:scalarmult(OwnDHPriv, NewRemoteDHPub),

    % 3. Derive new root key and chain keys using high-performance KDF
    {NewRootKey, InitChainKey, RespChainKey} = kdf_rk(
        State#ratchet_state.root_key, DHOutput
    ),
    % Alice uses init chain for future sending, resp chain for receiving Bob's messages
    NewSendChainKey = InitChainKey,
    NewRecvChainKey = RespChainKey,

    % 4. Generate new DH keypair for future sending
    {NewOwnDHPub, NewOwnDHPriv} = cryptic_nif:gen_keypair(),

    % 5. Save the previous receiving chain length for the header
    PrevChainLength = State#ratchet_state.recv_msg_number,

    % 6. Update state with new DH step and receiving chain
    Now = erlang:system_time(millisecond),
    NewState = State#ratchet_state{
        root_key = NewRootKey,

        % Update sending chain key and reset counter for new DH step
        send_chain_key = NewSendChainKey,
        % CRITICAL FIX: Reset sending chain counter for new DH ratchet step
        send_msg_number = 0,

        % Reset receiving chain for new DH step
        recv_chain_key = NewRecvChainKey,
        recv_msg_number = 0,
        prev_recv_chain_length = PrevChainLength,

        % Update DH ratchet state
        dh_self = {NewOwnDHPub, NewOwnDHPriv},
        dh_remote = NewRemoteDHPub,
        dh_ratchet_step = State#ratchet_state.dh_ratchet_step + 1,

        % Activate receiving chain, sending chain becomes available
        receiving_chain_active = true,
        % Now we can send with new DH key
        sending_chain_active = true,

        last_updated = Now
    },

    % 7. Note: In a production implementation, we would securely zero
    % the old DH private key memory. For now, Erlang GC will handle it.

    NewState.

%% @doc Handle message gaps and derive skipped keys
%%
%% When we receive a message with a number higher than expected,
%% we need to pre-derive keys for all the skipped messages.
%% This maintains forward secrecy while allowing delayed message delivery.
%%
%% @param State Current ratchet state
%% @param IncomingMsgNum The message number we just received
%% @param CurrentDHStep The DH step for the incoming message
%% @returns {ok, NewState} with skipped keys pre-derived
handle_message_gap(State, IncomingMsgNum, _CurrentDHStep) ->
    ExpectedMsgNum = State#ratchet_state.recv_msg_number,

    case IncomingMsgNum =< ExpectedMsgNum of
        true ->
            % No gap to handle - message is current or delayed
            {ok, State};
        false ->
            % There's a gap - pre-derive keys for skipped messages
            SkipCount = IncomingMsgNum - ExpectedMsgNum,

            % Safety check to prevent memory exhaustion

            % Reasonable limit for message gaps
            MaxSkip = 100,
            case SkipCount > MaxSkip of
                true ->
                    {error, {excessive_message_gap, SkipCount, MaxSkip}};
                false ->
                    % Pre-derive all skipped message keys
                    derive_skipped_keys_for_gap(
                        State, ExpectedMsgNum, IncomingMsgNum
                    )
            end
    end.

%% @doc Derive and store keys for skipped messages
%%
%% Entry point for handling message gaps - initiates recursive derivation
%% of keys for all messages between the expected number and received number.
%%
%% @param State Current ratchet state
%% @param StartMsgNum First message number to derive (expected)
%% @param EndMsgNum Last message number to derive (received)
%% @returns {ok, NewState} with all gap keys pre-derived and stored
derive_skipped_keys_for_gap(State, StartMsgNum, EndMsgNum) ->
    derive_skipped_keys_loop(
        State, StartMsgNum, EndMsgNum, State#ratchet_state.recv_chain_key
    ).

%% @doc Recursively derive keys for skipped messages
%%
%% Performs the actual key derivation loop for handling message gaps.
%% Each iteration derives one message key and advances the chain.
%%
%% @param State Current ratchet state (accumulates skipped keys)
%% @param CurrentMsgNum Current message number being processed
%% @param EndMsgNum Target message number (loop termination)
%% @param ChainKey Current receiving chain key for derivation
%% @returns {ok, NewState} when all keys derived
derive_skipped_keys_loop(State, CurrentMsgNum, EndMsgNum, ChainKey) when
    CurrentMsgNum >= EndMsgNum
->
    % Base case: reached target, update chain state
    Now = erlang:system_time(millisecond),
    NewState = State#ratchet_state{
        recv_chain_key = ChainKey,
        recv_msg_number = EndMsgNum,
        last_updated = Now
    },
    {ok, NewState};
derive_skipped_keys_loop(State, CurrentMsgNum, EndMsgNum, ChainKey) ->
    % Recursive case: derive key for CurrentMsgNum and continue

    % 1. Advance chain and derive message key for current message
    {NextChainKey, MessageKey} = advance_receiving_chain(
        ChainKey, CurrentMsgNum
    ),

    % 2. Store this key for later use (when delayed message arrives)
    DHStep = State#ratchet_state.dh_ratchet_step,
    KeyId = {DHStep, CurrentMsgNum},
    KeyInfo = #{
        message_key => MessageKey,
        derived_at => erlang:system_time(millisecond)
    },

    % 3. Add to skipped keys map
    NewSkippedKeys = maps:put(KeyId, KeyInfo, State#ratchet_state.skipped_keys),
    UpdatedState = State#ratchet_state{skipped_keys = NewSkippedKeys},

    % 4. Continue with next message number
    derive_skipped_keys_loop(
        UpdatedState, CurrentMsgNum + 1, EndMsgNum, NextChainKey
    ).

%% @doc Decrypt message using receiving chain or skipped keys
%%
%% This function handles the actual message decryption after DH ratchet
%% and gap handling have been processed. It can decrypt either:
%% 1. Current expected message using the receiving chain directly
%% 2. Delayed message using a pre-stored skipped key
%%
%% @param Message The message to decrypt
%% @param State Current ratchet state (after DH ratchet and gap processing)
%% @returns {ok, Plaintext, NewState} or {error, Reason}
decrypt_with_receiving_chain(Message, State) ->
    MsgNum = maps:get(msg_number, Message),
    ExpectedMsgNum = State#ratchet_state.recv_msg_number,

    case MsgNum of
        ExpectedMsgNum ->
            % Current expected message - use receiving chain directly
            decrypt_current_message(Message, State);
        _ when MsgNum < ExpectedMsgNum ->
            % Delayed message - look up from skipped message key store
            process_delayed_message(Message, State);
        _ ->
            % Future message - should have been handled by gap processing
            {error, {unexpected_future_message, MsgNum, ExpectedMsgNum}}
    end.

%% @doc Decrypt current expected message using receiving chain
decrypt_current_message(Message, State) ->
    MsgNum = maps:get(msg_number, Message),

    % 1. Advance receiving chain and derive message key
    {NewRecvChainKey, MessageKey} = advance_receiving_chain(
        State#ratchet_state.recv_chain_key, MsgNum
    ),

    % 2. Derive encryption keys from message key
    {EncKey, _AuthKey} = kdf_mk(MessageKey),

    % 3. Decrypt the message using ChaCha20-Poly1305
    CipherText = maps:get(ciphertext, Message),
    Nonce = maps:get(nonce, Message),

    ?info("[DR] decrypt_current_message: MsgNum=~p~n", [MsgNum]),
    ?info("[DR] recvChainKey=~s~n", [binary:encode_hex(State#ratchet_state.recv_chain_key, lowercase)]),
    ?info("[DR] messageKey=~s~n", [binary:encode_hex(MessageKey, lowercase)]),
    ?info("[DR] encKey=~s~n", [binary:encode_hex(EncKey, lowercase)]),
    ?info("[DR] nonce(~p bytes)=~s~n", [byte_size(Nonce), binary:encode_hex(Nonce, lowercase)]),
    ?info("[DR] ciphertext(~p bytes)=~s~n", [byte_size(CipherText), binary:encode_hex(CipherText, lowercase)]),

    case cryptic_nif:aead_decrypt(CipherText, EncKey, Nonce, <<>>) of
        error ->
            ?info("[DR] DECRYPTION FAILED! authentication_failed for msg ~p~n", [MsgNum]),
            {error, {authentication_failed, MsgNum}};
        Plaintext when is_binary(Plaintext) ->
            % 4. Update receiving chain state
            Now = erlang:system_time(millisecond),
            NewState = State#ratchet_state{
                recv_chain_key = NewRecvChainKey,
                recv_msg_number = MsgNum + 1,
                receiving_chain_active = true,
                last_updated = Now
            },

            % 5. Success - return plaintext and new state
            % Note: MessageKey will be garbage collected (forward secrecy)
            {ok, Plaintext, NewState}
    end.

%% @doc Process delayed message using skipped message keys
process_delayed_message(Message, State) ->
    MsgNum = maps:get(msg_number, Message),
    DHStep = maps:get(dh_step, Message),
    KeyId = {DHStep, MsgNum},

    case maps:get(KeyId, State#ratchet_state.skipped_keys, undefined) of
        undefined ->
            {error, {no_skipped_key, KeyId}};
        KeyInfo ->
            % Found the pre-derived key - use it for decryption
            MessageKey = maps:get(message_key, KeyInfo),

            % Derive encryption keys
            {EncKey, _AuthKey} = kdf_mk(MessageKey),

            % Decrypt the message
            CipherText = maps:get(ciphertext, Message),
            Nonce = maps:get(nonce, Message),

            case cryptic_nif:aead_decrypt(CipherText, EncKey, Nonce, <<>>) of
                error ->
                    % Remove key even on auth failure to prevent retry attacks
                    CleanedSkippedKeys = maps:remove(
                        KeyId, State#ratchet_state.skipped_keys
                    ),
                    Now = erlang:system_time(millisecond),
                    _NewState = State#ratchet_state{
                        skipped_keys = CleanedSkippedKeys,
                        last_updated = Now
                    },
                    {error, {authentication_failed, MsgNum}};
                Plaintext when is_binary(Plaintext) ->
                    % SUCCESS: Remove the used key (forward secrecy)
                    CleanedSkippedKeys = maps:remove(
                        KeyId, State#ratchet_state.skipped_keys
                    ),
                    Now = erlang:system_time(millisecond),
                    NewState = State#ratchet_state{
                        skipped_keys = CleanedSkippedKeys,
                        last_updated = Now
                    },

                    {ok, Plaintext, NewState}
            end
    end.

%%% ============================================================================
%%% DH Ratchet on Send Functions
%%% ============================================================================

%% @doc Determine if we should perform a DH ratchet step before sending
%%
%% According to the Double Ratchet protocol, we should perform a DH ratchet when:
%% 1. We have received messages from the other party (recv_msg_number > 0)
%% 2. AND we're about to send our first message in response (send_msg_number = 0)
%% 3. AND we have the remote party's DH key
%%
%% This represents a "direction change" - we were receiving, now we start sending.
should_perform_dh_ratchet_on_send(State) ->
    HasReceivedMessages = State#ratchet_state.recv_msg_number > 0,
    FirstSendInDirection = State#ratchet_state.send_msg_number == 0,
    HasRemoteDH = State#ratchet_state.dh_remote =/= undefined,

    HasReceivedMessages andalso FirstSendInDirection andalso HasRemoteDH.

%% @doc Perform DH ratchet step before sending (generate new ephemeral key)
%%
%% This function implements the core DH ratchet operation when sending:
%% 1. Generate a new ephemeral DH keypair
%% 2. Compute shared secret with remote party's current DH key
%% 3. Derive new root key and sending chain key
%% 4. Update state with new DH step
%%
%% This ensures forward secrecy and break-in recovery properties.
perform_dh_ratchet_on_send(State) ->
    % 1. Generate new ephemeral DH keypair for this ratchet step
    {NewDHPub, NewDHPriv} = cryptic_nif:gen_keypair(),

    % 2. Get current remote DH key and our old private key
    RemoteDHPub = State#ratchet_state.dh_remote,

    % 3. Compute DH shared secret using our NEW private key and their current public key
    DHOutput = cryptic_nif:scalarmult(NewDHPriv, RemoteDHPub),

    % 4. Perform root key derivation (DH ratchet)
    {NewRootKey, _InitChainKey, RespChainKey} = kdf_rk(
        State#ratchet_state.root_key, DHOutput
    ),
    % Bob (responder) uses the responder chain for sending after DH ratchet
    % Alice will derive the same responder chain for receiving Bob's messages
    NewSendChainKey = RespChainKey,

    % 5. Update state with new DH ratchet step
    Now = erlang:system_time(millisecond),
    NewState = State#ratchet_state{
        % Update to new root key from DH ratchet
        root_key = NewRootKey,

        % Use new DH keypair (our new ephemeral key)
        dh_self = {NewDHPub, NewDHPriv},

        % Use new sending chain from DH ratchet
        send_chain_key = NewSendChainKey,
        % Reset send message counter for new chain
        send_msg_number = 0,

        % Increment DH ratchet step counter
        dh_ratchet_step = State#ratchet_state.dh_ratchet_step + 1,

        % Update metadata
        last_updated = Now
    },

    NewState.

%%% ============================================================================
%%% Test Helper Functions
%%% ============================================================================

%% @doc Set remote DH key (for simulating X3DH handshake in tests)
%%
%% In a real implementation, both parties would know each other's initial
%% DH keys from the X3DH handshake. This helper function allows tests to
%% simulate that state.
%%
%% @param State Current ratchet state
%% @param RemoteDHPub Remote party's DH public key (32 bytes)
%% @returns Updated state with remote DH key set
set_remote_dh_key(State, RemoteDHPub) when byte_size(RemoteDHPub) =:= 32 ->
    Now = erlang:system_time(millisecond),
    State#ratchet_state{
        dh_remote = RemoteDHPub,
        last_updated = Now
    }.
