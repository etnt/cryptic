-ifndef(_CRYPTIC_UI_HRL).
-define(_CRYPTIC_UI_HRL, true).
%%% @doc Cryptic UI State Header File
%%%
%%% This header file contains the state record definitions used throughout
%%% the Cryptic WebSocket mTLS terminal user interface modules.
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-21

%% Client state
-record(client_state, {
    ws_client_pid,
    username,
    keypair
}).

%% WebSocket chat state record containing connection and user information.
%%
%% This record maintains the core state for WebSocket mTLS operations including
%% certificate configuration, server connection details, and message monitoring.
-record(ws_chat_state, {
    server_host = "localhost" :: string(),
    server_port = 8443 :: pos_integer(),
    username :: string() | undefined,
    cert_config :: #{atom() => string()},
    ws_client_state :: term() | undefined,
    keypair :: {binary(), binary()} | undefined,
    % Full client key set
    client_keys :: #{} | undefined,
    connection_status = disconnected :: connected | disconnected | connecting,
    pending_operation :: map() | undefined,

    %% Double Ratchet fields

    % ConversationId -> RatchetState cache
    ratchet_sessions = #{} :: #{binary() => term()},
    ratchet_preferences = #{
        % Auto-initialize after X3DH
        auto_init => true,
        % Prefer ratchet over X3DH when available
        prefer_ratchet => true,
        % Show ratchet status in messages
        show_ratchet_status => true
    } :: #{atom() => boolean()}
}).

%% UI state record containing screen layout and interaction state.
%%
%% This record manages all UI-specific state including screen dimensions,
%% message display, input handling, and WebSocket communication.
-record(ui_state, {
    ws_chat_state :: #ws_chat_state{},
    screen_height :: integer(),
    screen_width :: integer(),
    % {From, Message, Timestamp}
    message_history = [] :: [{string(), string(), string()}],
    scroll_position = 0 :: integer(),
    command_history = [] :: [string()],
    current_input = "" :: string(),
    % Cursor position in current_input
    cursor_position = 0 :: integer(),
    % Position in command history (0 = not browsing)
    history_position = 0 :: integer(),
    input_pid :: pid(),
    status_pid :: pid(),

    %% Chat mode state

    % Whether in chat mode
    chat_mode = false :: boolean(),
    % Username being chatted with
    chat_target :: string() | undefined,

    %% Room cache for name-to-ID mapping
    room_cache = #{} :: #{string() => string()},

    %% Inbox for encrypted messages

    % {From, Message, Timestamp}
    inbox = [] :: [{string(), string(), integer()}],
    % Number of messages in inbox
    message_count = 0 :: integer(),

    %% Auto-display control

    % Whether to auto-display incoming messages
    auto_display = true :: boolean(),
    % Count of pending messages per user
    pending_messages = #{} :: #{string() => integer()},

    %% Passphrase input mode

    % Whether in passphrase input mode
    passphrase_mode = false :: boolean(),
    % Local directory for key loading, etc
    cryptic_dir :: string() | undefined,

    %% Emacs-style editing

    % Kill ring for cut/copy/paste operations
    kill_ring = [] :: [string()]
}).

%% Color pairs
-define(COLOR_STATUS_BAR, 1).
-define(COLOR_HELP_BAR, 2).
-define(COLOR_OWN_MESSAGE, 3).
-define(COLOR_OTHER_MESSAGE, 4).
-define(COLOR_SYSTEM_MESSAGE, 5).
-define(COLOR_TIMESTAMP, 6).
-define(COLOR_INPUT, 7).
-define(COLOR_SENT_MESSAGE, 8).

-endif.
