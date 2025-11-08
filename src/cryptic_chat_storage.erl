%% @doc Cryptic Chat Storage Module - SQLite Encrypted Message Storage
%%
%% This module provides persistent encrypted storage for chat message history using SQLite.
%% All messages are encrypted at rest using ChaCha20-Poly1305 AEAD with passphrase-derived keys.
%%
%% == Features ==
%% <ul>
%%   <li>SQLite-based persistent encrypted message storage</li>
%%   <li>Per-message encryption with unique salts and nonces</li>
%%   <li>PBKDF2-SHA256 key derivation (100K iterations)</li>
%%   <li>ChaCha20-Poly1305 AEAD encryption</li>
%%   <li>Time-based and user-based message queries</li>
%%   <li>Federation support (multi-server message storage)</li>
%% </ul>
%%
%% == Database Schema ==
%% ```
%% -- Encrypted messages table
%% CREATE TABLE encrypted_messages (
%%     id INTEGER PRIMARY KEY AUTOINCREMENT,
%%     from_user TEXT NOT NULL,
%%     to_user TEXT NOT NULL,
%%     server_host TEXT NOT NULL,
%%     server_port INTEGER NOT NULL,
%%     encrypted_message BLOB NOT NULL,
%%     salt BLOB NOT NULL,
%%     nonce BLOB NOT NULL,
%%     timestamp INTEGER NOT NULL,
%%     message_type TEXT DEFAULT 'text',
%%     read_status INTEGER DEFAULT 0,
%%     created_at INTEGER DEFAULT (strftime('%s', 'now'))
%% );
%%
%% -- Storage metadata
%% CREATE TABLE storage_metadata (
%%     key TEXT PRIMARY KEY,
%%     value TEXT NOT NULL
%% );
%% '''
%%
%% == Security ==
%% - Each message encrypted with unique 16-byte salt
%% - ChaCha20-Poly1305 AEAD provides authentication and encryption
%% - PBKDF2-SHA256 with 100,000 iterations for key derivation
%% - Database file permissions set to 600 (owner read/write only)
%% - No plaintext messages stored on disk
%%
%%% @author Cryptic Team
%%% @end
-module(cryptic_chat_storage).

-export([
    %% Database initialization
    init_storage/2,
    close_storage/0,

    %% Encrypted message storage

    % Now includes ServerHost and ServerPort
    save_encrypted_message/7,
    get_conversation/4,
    get_recent_encrypted_messages/3,
    get_messages_by_time_range/5,
    get_messages_from_yesterday/3,
    get_last_n_messages/3,

    %% Utility functions
    get_storage_path/0,

    %% Helper functions for testing and console use
    encrypt_message/2,
    decrypt_message/4,
    datetime_to_unix/1,
    unix_to_datetime/1
]).

-include("cryptic.hrl").

%% Default storage path
-define(DEFAULT_DB_PATH, "cryptic_db").

%%%===================================================================
%%% Database Initialization
%%%===================================================================

%% @doc Close the storage system and clean up resources.
-spec close_storage() -> ok.
close_storage() ->
    %% Close SQLite connection if open
    case get(cryptic_db_conn) of
        undefined ->
            ok;
        Conn ->
            esqlite3:close(Conn),
            erase(cryptic_db_conn)
    end,
    erase(cryptic_db_path),
    erase(cryptic_db_passphrase),
    ok.

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Get the current storage database path.
-spec get_storage_path() -> string() | undefined.
get_storage_path() ->
    get(cryptic_db_path).

%%%===================================================================
%%% Internal Helper Functions
%%%===================================================================

%%%===================================================================
%%% SQLite Encrypted Message Storage
%%%===================================================================

%% @doc Initialize storage with username and passphrase.
%%
%% Creates SQLite database at CrypticDir/Username/messages.db.
%% The database stores messages from all servers with server_host and server_port
%% columns for federation support. Server information is provided per-message when
%% saving, not at initialization, to support multiple simultaneous server connections.
%%
%% @param Username User's username
%% @param Passphrase User passphrase for message encryption
%% @returns `ok' on success, `{error, term()}' on failure
-spec init_storage(string(), binary() | string()) ->
    ok | {error, term()}.
init_storage(Username, Passphrase) when is_list(Passphrase) ->
    init_storage(Username, list_to_binary(Passphrase));
init_storage(Username, Passphrase) when is_binary(Passphrase) ->
    try
        %% Ensure esqlite application is started
        case application:ensure_all_started(esqlite) of
            {ok, _} -> ok;
            {error, {already_started, esqlite}} -> ok;
            {error, Reason} -> throw({esqlite_start_failed, Reason})
        end,

        %% Get the user's cryptic directory (not server-specific for federation)
        BaseDir = cryptic_lib:get_cryptic_dir(),
        UserDir = filename:join([BaseDir, Username]),

        %% Ensure directory exists
        ok = filelib:ensure_dir(UserDir),

        %% Database file path - single DB per user for all servers
        DbPath = filename:join(UserDir, "messages.db"),
        ?dbg("Initializing encrypted message storage at ~s~n", [DbPath]),

        %% Open SQLite connection
        {ok, Conn} = esqlite3:open(DbPath),

        %% Store connection, path, and passphrase in process dictionary
        put(cryptic_db_conn, Conn),
        put(cryptic_db_path, DbPath),
        put(cryptic_db_passphrase, Passphrase),

        %% Create schema
        ok = create_encrypted_messages_schema(Conn),

        %% Set file permissions to 600 (owner read/write only)
        ok = file:change_mode(DbPath, 8#00600),

        ok
    catch
        _:Error:StackTrace ->
            ?error(
                "Failed to initialize encrypted message storage: " ++
                    "~p~nStacktrace: ~p~n",
                [Error, StackTrace]
            ),
            {error, {init_storage_failed, Error}}
    end.

%% @private
%% @doc Create the encrypted messages database schema.
%% Schema now includes server_host and server_port for federation support.
-spec create_encrypted_messages_schema(term()) -> ok | {error, term()}.
create_encrypted_messages_schema(Conn) ->
    %% Enable WAL mode for better concurrency
    esqlite3:exec(Conn, "PRAGMA journal_mode=WAL;"),

    %% Create encrypted messages table with server columns for federation
    CreateTableSQL =
        "CREATE TABLE IF NOT EXISTS encrypted_messages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  from_user TEXT NOT NULL,"
        "  to_user TEXT NOT NULL,"
        "  server_host TEXT NOT NULL,"
        "  server_port INTEGER NOT NULL,"
        "  encrypted_message BLOB NOT NULL,"
        "  salt BLOB NOT NULL,"
        "  nonce BLOB NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  message_type TEXT DEFAULT 'text',"
        "  read_status INTEGER DEFAULT 0,"
        "  created_at INTEGER DEFAULT (strftime('%s', 'now'))"
        ");",
    esqlite3:exec(Conn, CreateTableSQL),

    %% Create indexes for common queries
    esqlite3:exec(
        Conn,
        "CREATE INDEX IF NOT EXISTS idx_to_user_timestamp "
        "ON encrypted_messages(to_user, timestamp);"
    ),
    esqlite3:exec(
        Conn,
        "CREATE INDEX IF NOT EXISTS idx_from_user_timestamp "
        "ON encrypted_messages(from_user, timestamp);"
    ),
    esqlite3:exec(
        Conn,
        "CREATE INDEX IF NOT EXISTS idx_conversation "
        "ON encrypted_messages(from_user, to_user, timestamp);"
    ),
    esqlite3:exec(
        Conn,
        "CREATE INDEX IF NOT EXISTS idx_server "
        "ON encrypted_messages(server_host, server_port, timestamp);"
    ),

    %% Create metadata table
    CreateMetadataSQL =
        "CREATE TABLE IF NOT EXISTS storage_metadata ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");",
    esqlite3:exec(Conn, CreateMetadataSQL),

    %% Insert metadata
    esqlite3:exec(
        Conn,
        "INSERT OR IGNORE INTO storage_metadata (key, value) VALUES "
        "('version', '1.1'), "
        "('encryption', 'chacha20-poly1305'), "
        "('kdf', 'pbkdf2-sha256'), "
        "('kdf_iterations', '100000');"
    ),

    ok.

%% @doc Encrypt a message using ChaCha20-Poly1305 with passphrase-derived key.
%%
%% Generates unique salt and nonce for each message encryption.
%%
%% @param PlainMessage The plaintext message to encrypt
%% @param Passphrase User passphrase for key derivation
%% @returns `{Salt, Nonce, Ciphertext}' tuple
-spec encrypt_message(binary(), binary()) -> {binary(), binary(), binary()}.
encrypt_message(PlainMessage, Passphrase) when
    is_binary(PlainMessage), is_binary(Passphrase)
->
    %% Generate unique salt for this message
    Salt = cryptic_nif:rand_bytes(16),

    %% Derive encryption key using PBKDF2 (same as key storage)
    EncKey = cryptic_lib:derive_key_from_passphrase(Passphrase, Salt),

    %% Encrypt with ChaCha20-Poly1305 AEAD
    %% IMPORTANT: Despite documentation saying {Nonce, Ciphertext},
    %% the actual NIF returns {CiphertextWithTag, Nonce}!
    {CiphertextWithTag, Nonce} = cryptic_nif:aead_encrypt(
        PlainMessage, EncKey, <<>>
    ),

    %% @doc Decrypt a message using ChaCha20-Poly1305 with passphrase-derived key.
    {Salt, Nonce, CiphertextWithTag}.
%%
%% @param Ciphertext The encrypted message
%% @param Salt The salt used for key derivation
%% @param Nonce The nonce used for encryption
%% @param Passphrase User passphrase for key derivation
%% @returns `{ok, PlainMessage}' on success, `{error, decryption_failed}' on failure
-spec decrypt_message(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, decryption_failed}.
decrypt_message(Ciphertext, Salt, Nonce, Passphrase) ->
    %% Derive the same encryption key
    EncKey = cryptic_lib:derive_key_from_passphrase(Passphrase, Salt),

    %% Decrypt with ChaCha20-Poly1305 AEAD
    case cryptic_nif:aead_decrypt(Ciphertext, EncKey, Nonce, <<>>) of
        error -> {error, decryption_failed};
        PlainMessage when is_binary(PlainMessage) -> {ok, PlainMessage}
    end.

%% @doc Convert Erlang datetime to Unix timestamp (seconds since epoch).
-spec datetime_to_unix(calendar:datetime()) -> integer().
datetime_to_unix(DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime) - 62167219200.

%% @doc Convert Unix timestamp to Erlang datetime.
-spec unix_to_datetime(integer()) -> calendar:datetime().
unix_to_datetime(Unix) ->
    calendar:gregorian_seconds_to_datetime(Unix + 62167219200).

%% @doc Save an encrypted message to the database.
%%
%% Stores messages with server host and port information for federation support.
%% Multiple servers' messages are stored in a single database per user.
%%
%% @param FromUser Sender's username
%% @param ToUser Recipient's username
%% @param ServerHost Server hostname for this message
%% @param ServerPort Server port for this message
%% @param PlainMessage The plaintext message to store
%% @param Timestamp Message timestamp
%% @param Passphrase User passphrase for encryption
%% @returns `ok' on success, `{error, term()}' on failure
-spec save_encrypted_message(
    string(),
    string(),
    string(),
    integer(),
    binary(),
    calendar:datetime(),
    binary()
) ->
    ok | {error, term()}.
save_encrypted_message(
    FromUser,
    ToUser,
    ServerHost,
    ServerPort,
    PlainMessage,
    Timestamp,
    Passphrase
) ->
    try
        %% Get database connection
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        %% Encrypt the message
        {Salt, Nonce, Ciphertext} = encrypt_message(PlainMessage, Passphrase),

        %% Convert timestamp to Unix time
        UnixTime = datetime_to_unix(Timestamp),

        %% Insert into database with server info
        InsertSQL =
            "INSERT INTO encrypted_messages "
            "(from_user, to_user, server_host, server_port, encrypted_message, salt, nonce, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",

        esqlite3:q(
            Conn,
            InsertSQL,
            [
                FromUser,
                ToUser,
                ServerHost,
                ServerPort,
                Ciphertext,
                Salt,
                Nonce,
                UnixTime
            ]
        ),

        ok
    catch
        throw:db_not_initialized ->
            {error, db_not_initialized};
        error:undef:Stacktrace ->
            io:format(
                "~n[ERROR] Undefined function in save_encrypted_message!~n"
            ),
            io:format("Stacktrace: ~p~n", [Stacktrace]),
            {error, {save_encrypted_message_failed, undef}};
        _:Error:Stacktrace ->
            ?dbg("save_encrypted_message failed: ~p~nStacktrace: ~p~n", [
                Error, Stacktrace
            ]),
            {error, {save_encrypted_message_failed, Error}}
    end.

%% @doc Get last N messages for a user (received or sent).
%%
%% @param Username User to get messages for
%% @param N Number of messages to retrieve
%% @param Passphrase Passphrase for decryption
%% @returns `{ok, Messages}' where Messages is list of `{FromUser, ToUser, Message, Timestamp}'
-spec get_last_n_messages(string(), pos_integer(), binary()) ->
    {ok, [{string(), string(), binary(), integer()}]} | {error, term()}.
get_last_n_messages(Username, N, Passphrase) ->
    try
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        QuerySQL =
            "SELECT from_user, to_user, encrypted_message, salt, nonce, timestamp, server_host, server_port "
            "FROM encrypted_messages "
            "WHERE from_user = ? OR to_user = ? "
            "ORDER BY timestamp DESC "
            "LIMIT ?",

        case esqlite3:q(Conn, QuerySQL, [Username, Username, N]) of
            Rows when is_list(Rows) ->
                Messages = lists:map(
                    fun(
                        [
                            FromUser,
                            ToUser,
                            Ciphertext,
                            Salt,
                            Nonce,
                            Timestamp,
                            ServerHost,
                            ServerPort
                        ]
                    ) ->
                        case
                            decrypt_message(Ciphertext, Salt, Nonce, Passphrase)
                        of
                            {ok, PlainMessage} ->
                                % Convert Unix timestamp back to datetime
                                DateTime = unix_to_datetime(Timestamp),
                                {FromUser, ToUser, PlainMessage, DateTime,
                                    ServerHost, ServerPort};
                            {error, Reason} ->
                                throw({decryption_failed, Reason})
                        end
                    end,
                    Rows
                ),
                % Reverse to get chronological order
                {ok, lists:reverse(Messages)};
            _Other ->
                {ok, []}
        end
    catch
        throw:db_not_initialized ->
            {error, db_not_initialized};
        _:Error:Stacktrace ->
            ?dbg("get_last_n_messages failed: ~p~nStacktrace: ~p~n", [
                Error, Stacktrace
            ]),
            {error, {get_last_n_messages_failed, Error}}
    end.

%% @doc Get messages from yesterday between current user and another user.
%%
%% @param CurrentUser Current user's username
%% @param FromUser Other user's username
%% @param Passphrase Passphrase for decryption
%% @returns `{ok, Messages}' on success
-spec get_messages_from_yesterday(string(), string(), binary()) ->
    {ok, [{string(), string(), binary(), integer()}]} | {error, term()}.
get_messages_from_yesterday(CurrentUser, FromUser, Passphrase) ->
    try
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        %% Calculate yesterday's start and end timestamps
        Now = calendar:universal_time(),
        {Date, _Time} = Now,
        YesterdayDate = calendar:gregorian_days_to_date(
            calendar:date_to_gregorian_days(Date) - 1
        ),

        StartTime = datetime_to_unix({YesterdayDate, {0, 0, 0}}),
        EndTime = datetime_to_unix({YesterdayDate, {23, 59, 59}}),

        QuerySQL =
            "SELECT from_user, to_user, encrypted_message, salt, nonce, timestamp, server_host, server_port "
            "FROM encrypted_messages "
            "WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)) "
            "  AND timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp ASC",

        case
            esqlite3:q(
                Conn,
                QuerySQL,
                [
                    FromUser,
                    CurrentUser,
                    CurrentUser,
                    FromUser,
                    StartTime,
                    EndTime
                ]
            )
        of
            Rows when is_list(Rows) ->
                Messages = lists:map(
                    fun(
                        [
                            From,
                            To,
                            Ciphertext,
                            Salt,
                            Nonce,
                            Timestamp,
                            ServerHost,
                            ServerPort
                        ]
                    ) ->
                        {ok, PlainMessage} = decrypt_message(
                            Ciphertext, Salt, Nonce, Passphrase
                        ),
                        DateTime = unix_to_datetime(Timestamp),
                        {From, To, PlainMessage, DateTime, ServerHost,
                            ServerPort}
                    end,
                    Rows
                ),
                {ok, Messages};
            _Other ->
                {ok, []}
        end
    catch
        throw:db_not_initialized ->
            {error, db_not_initialized};
        _:Error:Stacktrace ->
            ?dbg("get_messages_from_yesterday failed: ~p~nStacktrace: ~p~n", [
                Error, Stacktrace
            ]),
            {error, {get_messages_from_yesterday_failed, Error}}
    end.

%% @doc Get conversation history between two users with decryption.
%%
%% Retrieves encrypted messages from database and decrypts them.
%%
%% @param User1 First user in the conversation
%% @param User2 Second user in the conversation
%% @param Limit Maximum number of messages to retrieve
%% @param Passphrase Passphrase for decryption
%% @returns `{ok, Messages}' where Messages is list of `{FromUser, ToUser, Message, Timestamp}'
-spec get_conversation(string(), string(), pos_integer(), binary()) ->
    {ok, [{string(), string(), binary(), integer()}]} | {error, term()}.
get_conversation(User1, User2, Limit, Passphrase) ->
    try
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        QuerySQL =
            "SELECT from_user, to_user, encrypted_message, salt, nonce, timestamp, server_host, server_port "
            "FROM encrypted_messages "
            "WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) "
            "ORDER BY timestamp ASC "
            "LIMIT ?",

        case esqlite3:q(Conn, QuerySQL, [User1, User2, User2, User1, Limit]) of
            Rows when is_list(Rows) ->
                Messages = lists:map(
                    fun(
                        [
                            From,
                            To,
                            Ciphertext,
                            Salt,
                            Nonce,
                            Timestamp,
                            ServerHost,
                            ServerPort
                        ]
                    ) ->
                        {ok, PlainMessage} = decrypt_message(
                            Ciphertext, Salt, Nonce, Passphrase
                        ),
                        DateTime = unix_to_datetime(Timestamp),
                        {From, To, PlainMessage, DateTime, ServerHost,
                            ServerPort}
                    end,
                    Rows
                ),
                {ok, Messages};
            _Other ->
                {ok, []}
        end
    catch
        throw:db_not_initialized ->
            {error, db_not_initialized};
        _:Error:Stacktrace ->
            ?dbg("get_conversation failed: ~p~nStacktrace: ~p~n", [
                Error, Stacktrace
            ]),
            {error, {get_conversation_failed, Error}}
    end.

%% @doc Get recent encrypted messages across all conversations.
%%
%% Retrieves the most recent messages for a user from all conversations,
%% sorted by timestamp (newest first).
%%
%% @param Username User to get messages for
%% @param Limit Number of messages to retrieve
%% @param Passphrase Passphrase for decryption
%% @returns `{ok, Messages}' where Messages is list of `{FromUser, ToUser, Message, Timestamp}'
-spec get_recent_encrypted_messages(string(), pos_integer(), binary()) ->
    {ok, [{string(), string(), binary(), integer()}]} | {error, term()}.
get_recent_encrypted_messages(Username, Limit, Passphrase) ->
    try
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        %% Get messages where user is either sender or recipient
        QuerySQL =
            "SELECT from_user, to_user, encrypted_message, salt, nonce, timestamp, server_host, server_port "
            "FROM encrypted_messages "
            "WHERE from_user = ? OR to_user = ? "
            "ORDER BY timestamp DESC "
            "LIMIT ?",

        case esqlite3:q(QuerySQL, [Username, Username, Limit], Conn) of
            Rows when is_list(Rows) ->
                Messages = lists:map(
                    fun(
                        {From, To, Ciphertext, Salt, Nonce, Timestamp,
                            ServerHost, ServerPort}
                    ) ->
                        {ok, PlainMessage} = decrypt_message(
                            Ciphertext, Salt, Nonce, Passphrase
                        ),
                        {From, To, PlainMessage, Timestamp, ServerHost,
                            ServerPort}
                    end,
                    Rows
                ),
                {ok, Messages};
            _Other ->
                {ok, []}
        end
    catch
        throw:db_not_initialized -> {error, db_not_initialized};
        _:Error -> {error, {get_recent_encrypted_messages_failed, Error}}
    end.

%% @doc Get messages within a specific time range for a conversation.
%%
%% Retrieves messages between two users within the specified time window.
%%
%% @param User1 First user in the conversation
%% @param User2 Second user in the conversation
%% @param StartTime Start of time range (datetime)
%% @param EndTime End of time range (datetime)
%% @param Passphrase Passphrase for decryption
%% @returns `{ok, Messages}' on success
-spec get_messages_by_time_range(
    string(),
    string(),
    calendar:datetime(),
    calendar:datetime(),
    binary()
) ->
    {ok, [{string(), string(), binary(), integer()}]} | {error, term()}.
get_messages_by_time_range(User1, User2, StartTime, EndTime, Passphrase) ->
    try
        Conn =
            case get(cryptic_db_conn) of
                undefined -> throw(db_not_initialized);
                C -> C
            end,

        %% Convert datetimes to Unix timestamps
        StartUnix = datetime_to_unix(StartTime),
        EndUnix = datetime_to_unix(EndTime),

        QuerySQL =
            "SELECT from_user, to_user, encrypted_message, salt, nonce, timestamp, server_host, server_port "
            "FROM encrypted_messages "
            "WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)) "
            "  AND timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp ASC",

        case
            esqlite3:q(
                QuerySQL,
                [User1, User2, User2, User1, StartUnix, EndUnix],
                Conn
            )
        of
            Rows when is_list(Rows) ->
                Messages = lists:map(
                    fun(
                        {From, To, Ciphertext, Salt, Nonce, Timestamp,
                            ServerHost, ServerPort}
                    ) ->
                        {ok, PlainMessage} = decrypt_message(
                            Ciphertext, Salt, Nonce, Passphrase
                        ),
                        {From, To, PlainMessage, Timestamp, ServerHost,
                            ServerPort}
                    end,
                    Rows
                ),
                {ok, Messages};
            _Other ->
                {ok, []}
        end
    catch
        throw:db_not_initialized -> {error, db_not_initialized};
        _:Error -> {error, {get_messages_by_time_range_failed, Error}}
    end.
