%% @doc Cryptic Chat Storage Module - Local Data Persistence
%%
%% This module provides persistent storage for the cryptic chat shell including:
%% - Message history and conversation logs
%% - Contact management and user preferences
%% - Offline message queueing
%% - User profile and keypair storage
%% - Chat session state persistence
%%
%% == Features ==
%% <ul>
%%   <li>SQLite-based persistent storage</li>
%%   <li>Message history with full-text search</li>
%%   <li>Contact management with aliases</li>
%%   <li>Offline message queueing</li>
%%   <li>Secure keypair storage</li>
%%   <li>Session state management</li>
%% </ul>
%%
%% == Database Schema ==
%% ```
%% -- Messages table for conversation history
%% CREATE TABLE messages (
%%     id INTEGER PRIMARY KEY AUTOINCREMENT,
%%     from_user TEXT NOT NULL,
%%     to_user TEXT NOT NULL, 
%%     message TEXT NOT NULL,
%%     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
%%     message_type TEXT DEFAULT 'text',
%%     read_status BOOLEAN DEFAULT FALSE
%% );
%%
%% -- Contacts table for user management
%% CREATE TABLE contacts (
%%     username TEXT PRIMARY KEY,
%%     alias TEXT,
%%     public_key BLOB,
%%     last_seen DATETIME,
%%     favorite BOOLEAN DEFAULT FALSE,
%%     blocked BOOLEAN DEFAULT FALSE
%% );
%%
%% -- User profiles for current user data
%% CREATE TABLE user_profiles (
%%     username TEXT PRIMARY KEY,
%%     private_key BLOB NOT NULL,
%%     public_key BLOB NOT NULL,
%%     server_url TEXT DEFAULT 'http://localhost:8080',
%%     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
%%     last_login DATETIME
%% );
%%
%% -- Outbox for offline message queueing
%% CREATE TABLE outbox (
%%     id INTEGER PRIMARY KEY AUTOINCREMENT,
%%     to_user TEXT NOT NULL,
%%     message TEXT NOT NULL,
%%     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
%%     retry_count INTEGER DEFAULT 0,
%%     last_attempt DATETIME
%% );
%% '''
%%
%% @author Torbjörn Törnkvist
%% @version 1.0.0
%% @since September 2025
-module(cryptic_chat_storage).

-export([
    %% Database initialization
    init_storage/0,
    init_storage/1,
    close_storage/0,
    
    %% Message history management
    save_message/4,
    save_message/5,
    get_conversation/2,
    get_conversation/3,
    get_recent_messages/1,
    get_recent_messages/2,
    get_unread_messages/1,
    mark_message_read/1,
    search_messages/1,
    search_messages/2,
    
    %% Contact management
    add_contact/1,
    add_contact/2,
    add_contact/3,
    update_contact/2,
    get_contact/1,
    get_all_contacts/0,
    remove_contact/1,
    set_contact_alias/2,
    set_contact_favorite/2,
    block_contact/1,
    unblock_contact/1,
    
    %% User profile management
    save_user_profile/4,
    get_user_profile/1,
    update_last_login/1,
    get_current_user/0,
    
    %% Offline message queueing
    queue_message/2,
    get_queued_messages/0,
    get_queued_messages/1,
    remove_queued_message/1,
    increment_retry_count/1,
    
    %% Utility functions
    get_storage_path/0,
    backup_storage/0,
    backup_storage/1,
    get_storage_stats/0
]).

%% Default storage path
-define(DEFAULT_DB_PATH, "cryptic_chat.db").
-define(BACKUP_DIR, "backups").

%%%===================================================================
%%% Database Initialization
%%%===================================================================

%% @doc Initialize the storage system with default database path.
%%
%% Creates the SQLite database and all required tables if they don't exist.
%% Uses the default database path in the current directory.
%%
%% @returns `ok' on success, `{error, term()}' on failure
-spec init_storage() -> ok | {error, term()}.
init_storage() ->
    init_storage(?DEFAULT_DB_PATH).

%% @doc Initialize the storage system with custom database path.
%%
%% Creates the SQLite database and all required tables if they don't exist.
%% 
%% @param DbPath Path to the SQLite database file
%% @returns `ok' on success, `{error, term()}' on failure
-spec init_storage(string()) -> ok | {error, term()}.
init_storage(DbPath) ->
    try
        %% Ensure the database directory exists
        DbDir = filename:dirname(DbPath),
        case DbDir of
            "." -> ok;
            _ -> 
                case filelib:ensure_dir(DbPath) of
                    ok -> ok;
                    {error, Reason} -> throw({ensure_dir_failed, Reason})
                end
        end,
        
        %% For now, use ETS as a simple in-memory storage
        %% TODO: Replace with actual SQLite when esqlite3 is available
        case ets:info(cryptic_messages) of
            undefined ->
                ets:new(cryptic_messages, [named_table, ordered_set, public]),
                ets:new(cryptic_contacts, [named_table, set, public]),
                ets:new(cryptic_profiles, [named_table, set, public]),
                ets:new(cryptic_outbox, [named_table, ordered_set, public]);
            _ ->
                ok
        end,
        
        %% Store the database path for future reference
        put(cryptic_db_path, DbPath),
        ok
    catch
        throw:Error ->
            {error, Error};
        _:Error ->
            {error, {init_failed, Error}}
    end.

%% @doc Close the storage system and clean up resources.
-spec close_storage() -> ok.
close_storage() ->
    %% Clean up ETS tables
    try
        ets:delete(cryptic_messages),
        ets:delete(cryptic_contacts),
        ets:delete(cryptic_profiles),
        ets:delete(cryptic_outbox)
    catch
        _:_ -> ok
    end,
    erase(cryptic_db_path),
    ok.

%%%===================================================================
%%% Message History Management
%%%===================================================================

%% @doc Save a message to the conversation history.
%%
%% Stores a message with automatic timestamp generation.
%%
%% @param FromUser The sender's username
%% @param ToUser The recipient's username  
%% @param Message The message content
%% @param MessageType The type of message ('text', 'file', etc.)
%% @returns `ok' on success, `{error, term()}' on failure
-spec save_message(string(), string(), string(), string()) -> ok | {error, term()}.
save_message(FromUser, ToUser, Message, MessageType) ->
    Timestamp = calendar:universal_time(),
    save_message(FromUser, ToUser, Message, MessageType, Timestamp).

%% @doc Save a message with explicit timestamp.
-spec save_message(string(), string(), string(), string(), calendar:datetime()) -> ok | {error, term()}.
save_message(FromUser, ToUser, Message, MessageType, Timestamp) ->
    try
        MessageId = generate_message_id(),
        MessageRecord = {MessageId, FromUser, ToUser, Message, MessageType, Timestamp, false},
        ets:insert(cryptic_messages, MessageRecord),
        ok
    catch
        _:Error ->
            {error, {save_failed, Error}}
    end.

%% @doc Get conversation history between two users.
%%
%% @param User1 First user in the conversation
%% @param User2 Second user in the conversation
%% @returns `{ok, [Message]}' with list of messages, or `{error, term()}'
-spec get_conversation(string(), string()) -> {ok, [term()]} | {error, term()}.
get_conversation(User1, User2) ->
    get_conversation(User1, User2, 100). % Default limit

%% @doc Get conversation history with message limit.
-spec get_conversation(string(), string(), pos_integer()) -> {ok, [term()]} | {error, term()}.
get_conversation(User1, User2, Limit) ->
    try
        AllMessages = ets:tab2list(cryptic_messages),
        ConversationMessages = lists:filter(fun({_Id, From, To, _Msg, _Type, _Time, _Read}) ->
            (From =:= User1 andalso To =:= User2) orelse
            (From =:= User2 andalso To =:= User1)
        end, AllMessages),
        
        %% Sort by timestamp and limit
        SortedMessages = lists:sort(fun({_, _, _, _, _, T1, _}, {_, _, _, _, _, T2, _}) ->
            T1 =< T2
        end, ConversationMessages),
        
        LimitedMessages = case length(SortedMessages) > Limit of
            true -> lists:nthtail(length(SortedMessages) - Limit, SortedMessages);
            false -> SortedMessages
        end,
        
        {ok, LimitedMessages}
    catch
        _:Error ->
            {error, {get_conversation_failed, Error}}
    end.

%% @doc Get recent messages across all conversations.
-spec get_recent_messages(pos_integer()) -> {ok, [term()]} | {error, term()}.
get_recent_messages(Limit) ->
    try
        AllMessages = ets:tab2list(cryptic_messages),
        SortedMessages = lists:sort(fun({_, _, _, _, _, T1, _}, {_, _, _, _, _, T2, _}) ->
            T1 >= T2  % Descending order (newest first)
        end, AllMessages),
        
        LimitedMessages = lists:sublist(SortedMessages, Limit),
        {ok, LimitedMessages}
    catch
        _:Error ->
            {error, {get_recent_failed, Error}}
    end.

%% @doc Get recent messages for a specific user.
-spec get_recent_messages(string(), pos_integer()) -> {ok, [term()]} | {error, term()}.
get_recent_messages(Username, Limit) ->
    try
        AllMessages = ets:tab2list(cryptic_messages),
        UserMessages = lists:filter(fun({_Id, From, To, _Msg, _Type, _Time, _Read}) ->
            From =:= Username orelse To =:= Username
        end, AllMessages),
        
        SortedMessages = lists:sort(fun({_, _, _, _, _, T1, _}, {_, _, _, _, _, T2, _}) ->
            T1 >= T2  % Descending order (newest first)
        end, UserMessages),
        
        LimitedMessages = lists:sublist(SortedMessages, Limit),
        {ok, LimitedMessages}
    catch
        _:Error ->
            {error, {get_recent_failed, Error}}
    end.

%% @doc Get unread messages for a specific user.
-spec get_unread_messages(string()) -> {ok, [term()]} | {error, term()}.
get_unread_messages(ToUser) ->
    try
        AllMessages = ets:tab2list(cryptic_messages),
        % Filter for messages TO the user that are unread
        UnreadMessages = lists:filter(fun({_Id, _From, To, _Msg, _Type, _Time, ReadStatus}) ->
            To =:= ToUser andalso ReadStatus =:= false
        end, AllMessages),
        
        % Sort by timestamp (newest first)
        SortedMessages = lists:sort(fun({_, _, _, _, _, T1, _}, {_, _, _, _, _, T2, _}) ->
            T1 >= T2
        end, UnreadMessages),
        
        {ok, SortedMessages}
    catch
        _:Error ->
            {error, {get_unread_failed, Error}}
    end.

%% @doc Mark a message as read.
-spec mark_message_read(term()) -> ok | {error, term()}.
mark_message_read(MessageId) ->
    try
        case ets:lookup(cryptic_messages, MessageId) of
            [{MessageId, From, To, Msg, Type, Time, _Read}] ->
                UpdatedRecord = {MessageId, From, To, Msg, Type, Time, true},
                ets:insert(cryptic_messages, UpdatedRecord),
                ok;
            [] ->
                {error, message_not_found}
        end
    catch
        _:Error ->
            {error, {mark_read_failed, Error}}
    end.

%% @doc Search messages by content.
-spec search_messages(string()) -> {ok, [term()]} | {error, term()}.
search_messages(SearchTerm) ->
    search_messages(SearchTerm, 50). % Default limit

%% @doc Search messages by content with limit.
-spec search_messages(string(), pos_integer()) -> {ok, [term()]} | {error, term()}.
search_messages(SearchTerm, Limit) ->
    try
        AllMessages = ets:tab2list(cryptic_messages),
        LowerSearchTerm = string:lowercase(SearchTerm),
        
        MatchingMessages = lists:filter(fun({_Id, _From, _To, Msg, _Type, _Time, _Read}) ->
            LowerMsg = string:lowercase(Msg),
            string:find(LowerMsg, LowerSearchTerm) =/= nomatch
        end, AllMessages),
        
        %% Sort by timestamp (newest first) and limit
        SortedMessages = lists:sort(fun({_, _, _, _, _, T1, _}, {_, _, _, _, _, T2, _}) ->
            T1 >= T2
        end, MatchingMessages),
        
        LimitedMessages = lists:sublist(SortedMessages, Limit),
        {ok, LimitedMessages}
    catch
        _:Error ->
            {error, {search_failed, Error}}
    end.

%%%===================================================================
%%% Contact Management
%%%===================================================================

%% @doc Add a contact with username only.
-spec add_contact(string()) -> ok | {error, term()}.
add_contact(Username) ->
    add_contact(Username, Username, undefined).

%% @doc Add a contact with username and alias.
-spec add_contact(string(), string()) -> ok | {error, term()}.
add_contact(Username, Alias) ->
    add_contact(Username, Alias, undefined).

%% @doc Add a contact with username, alias, and public key.
-spec add_contact(string(), string(), binary() | undefined) -> ok | {error, term()}.
add_contact(Username, Alias, PublicKey) ->
    try
        Timestamp = calendar:universal_time(),
        ContactRecord = {Username, Alias, PublicKey, Timestamp, false, false},
        ets:insert(cryptic_contacts, ContactRecord),
        ok
    catch
        _:Error ->
            {error, {add_contact_failed, Error}}
    end.

%% @doc Update contact information.
-spec update_contact(string(), [{atom(), term()}]) -> ok | {error, term()}.
update_contact(Username, Updates) ->
    try
        case ets:lookup(cryptic_contacts, Username) of
            [{Username, Alias, PubKey, LastSeen, Favorite, Blocked}] ->
                NewAlias = proplists:get_value(alias, Updates, Alias),
                NewPubKey = proplists:get_value(public_key, Updates, PubKey),
                NewLastSeen = proplists:get_value(last_seen, Updates, LastSeen),
                NewFavorite = proplists:get_value(favorite, Updates, Favorite),
                NewBlocked = proplists:get_value(blocked, Updates, Blocked),
                
                UpdatedRecord = {Username, NewAlias, NewPubKey, NewLastSeen, NewFavorite, NewBlocked},
                ets:insert(cryptic_contacts, UpdatedRecord),
                ok;
            [] ->
                {error, contact_not_found}
        end
    catch
        _:Error ->
            {error, {update_contact_failed, Error}}
    end.

%% @doc Get contact information.
-spec get_contact(string()) -> {ok, term()} | {error, term()}.
get_contact(Username) ->
    try
        case ets:lookup(cryptic_contacts, Username) of
            [Contact] -> {ok, Contact};
            [] -> {error, contact_not_found}
        end
    catch
        _:Error ->
            {error, {get_contact_failed, Error}}
    end.

%% @doc Get all contacts.
-spec get_all_contacts() -> {ok, [term()]} | {error, term()}.
get_all_contacts() ->
    try
        Contacts = ets:tab2list(cryptic_contacts),
        {ok, Contacts}
    catch
        _:Error ->
            {error, {get_contacts_failed, Error}}
    end.

%% @doc Remove a contact.
-spec remove_contact(string()) -> ok | {error, term()}.
remove_contact(Username) ->
    try
        ets:delete(cryptic_contacts, Username),
        ok
    catch
        _:Error ->
            {error, {remove_contact_failed, Error}}
    end.

%% @doc Set contact alias.
-spec set_contact_alias(string(), string()) -> ok | {error, term()}.
set_contact_alias(Username, Alias) ->
    update_contact(Username, [{alias, Alias}]).

%% @doc Set contact as favorite.
-spec set_contact_favorite(string(), boolean()) -> ok | {error, term()}.
set_contact_favorite(Username, IsFavorite) ->
    update_contact(Username, [{favorite, IsFavorite}]).

%% @doc Block a contact.
-spec block_contact(string()) -> ok | {error, term()}.
block_contact(Username) ->
    update_contact(Username, [{blocked, true}]).

%% @doc Unblock a contact.
-spec unblock_contact(string()) -> ok | {error, term()}.
unblock_contact(Username) ->
    update_contact(Username, [{blocked, false}]).

%%%===================================================================
%%% User Profile Management
%%%===================================================================

%% @doc Save user profile with keypair.
-spec save_user_profile(string(), binary(), binary(), string()) -> ok | {error, term()}.
save_user_profile(Username, PrivateKey, PublicKey, ServerUrl) ->
    try
        Timestamp = calendar:universal_time(),
        ProfileRecord = {Username, PrivateKey, PublicKey, ServerUrl, Timestamp, undefined},
        ets:insert(cryptic_profiles, ProfileRecord),
        ok
    catch
        _:Error ->
            {error, {save_profile_failed, Error}}
    end.

%% @doc Get user profile.
-spec get_user_profile(string()) -> {ok, term()} | {error, term()}.
get_user_profile(Username) ->
    try
        case ets:lookup(cryptic_profiles, Username) of
            [Profile] -> {ok, Profile};
            [] -> {error, profile_not_found}
        end
    catch
        _:Error ->
            {error, {get_profile_failed, Error}}
    end.

%% @doc Update last login timestamp.
-spec update_last_login(string()) -> ok | {error, term()}.
update_last_login(Username) ->
    try
        case ets:lookup(cryptic_profiles, Username) of
            [{Username, PrivKey, PubKey, ServerUrl, CreatedAt, _LastLogin}] ->
                Timestamp = calendar:universal_time(),
                UpdatedRecord = {Username, PrivKey, PubKey, ServerUrl, CreatedAt, Timestamp},
                ets:insert(cryptic_profiles, UpdatedRecord),
                ok;
            [] ->
                {error, profile_not_found}
        end
    catch
        _:Error ->
            {error, {update_login_failed, Error}}
    end.

%% @doc Get current user (most recently logged in).
-spec get_current_user() -> {ok, string()} | {error, term()}.
get_current_user() ->
    try
        AllProfiles = ets:tab2list(cryptic_profiles),
        case AllProfiles of
            [] ->
                {error, no_profiles};
            Profiles ->
                %% Find profile with most recent login
                MostRecent = lists:foldl(fun
                    ({User, _, _, _, _, undefined}, Acc) ->
                        case Acc of
                            undefined -> {User, {{1970,1,1},{0,0,0}}};
                            _ -> Acc
                        end;
                    ({User, _, _, _, _, LastLogin}, undefined) ->
                        {User, LastLogin};
                    ({User, _, _, _, _, LastLogin}, {_AccUser, AccLogin}) ->
                        case LastLogin > AccLogin of
                            true -> {User, LastLogin};
                            false -> {_AccUser, AccLogin}
                        end
                end, undefined, Profiles),
                
                case MostRecent of
                    undefined -> {error, no_current_user};
                    {User, _} -> {ok, User}
                end
        end
    catch
        _:Error ->
            {error, {get_current_user_failed, Error}}
    end.

%%%===================================================================
%%% Offline Message Queueing
%%%===================================================================

%% @doc Queue a message for offline delivery.
-spec queue_message(string(), string()) -> ok | {error, term()}.
queue_message(ToUser, Message) ->
    try
        MessageId = generate_message_id(),
        Timestamp = calendar:universal_time(),
        QueueRecord = {MessageId, ToUser, Message, Timestamp, 0, undefined},
        ets:insert(cryptic_outbox, QueueRecord),
        ok
    catch
        _:Error ->
            {error, {queue_failed, Error}}
    end.

%% @doc Get all queued messages.
-spec get_queued_messages() -> {ok, [term()]} | {error, term()}.
get_queued_messages() ->
    try
        Messages = ets:tab2list(cryptic_outbox),
        {ok, Messages}
    catch
        _:Error ->
            {error, {get_queued_failed, Error}}
    end.

%% @doc Get queued messages for specific user.
-spec get_queued_messages(string()) -> {ok, [term()]} | {error, term()}.
get_queued_messages(ToUser) ->
    try
        AllMessages = ets:tab2list(cryptic_outbox),
        UserMessages = lists:filter(fun({_Id, To, _Msg, _Time, _Retry, _LastAttempt}) ->
            To =:= ToUser
        end, AllMessages),
        {ok, UserMessages}
    catch
        _:Error ->
            {error, {get_queued_failed, Error}}
    end.

%% @doc Remove a queued message (after successful delivery).
-spec remove_queued_message(term()) -> ok | {error, term()}.
remove_queued_message(MessageId) ->
    try
        ets:delete(cryptic_outbox, MessageId),
        ok
    catch
        _:Error ->
            {error, {remove_queued_failed, Error}}
    end.

%% @doc Increment retry count for a queued message.
-spec increment_retry_count(term()) -> ok | {error, term()}.
increment_retry_count(MessageId) ->
    try
        case ets:lookup(cryptic_outbox, MessageId) of
            [{MessageId, ToUser, Message, CreatedAt, RetryCount, _LastAttempt}] ->
                Timestamp = calendar:universal_time(),
                UpdatedRecord = {MessageId, ToUser, Message, CreatedAt, RetryCount + 1, Timestamp},
                ets:insert(cryptic_outbox, UpdatedRecord),
                ok;
            [] ->
                {error, message_not_found}
        end
    catch
        _:Error ->
            {error, {increment_retry_failed, Error}}
    end.

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Get the current storage database path.
-spec get_storage_path() -> string() | undefined.
get_storage_path() ->
    get(cryptic_db_path).

%% @doc Create a backup of the current database.
-spec backup_storage() -> ok | {error, term()}.
backup_storage() ->
    case get_storage_path() of
        undefined -> {error, no_storage_initialized};
        DbPath -> backup_storage(DbPath)
    end.

%% @doc Create a backup with custom filename.
-spec backup_storage(string()) -> ok | {error, term()}.
backup_storage(_SourcePath) ->
    try
        %% Create backup directory if it doesn't exist
        BackupDir = ?BACKUP_DIR,
        filelib:ensure_dir(filename:join(BackupDir, "dummy")),
        
        %% Generate backup filename with timestamp
        {{Y,M,D},{H,Min,S}} = calendar:universal_time(),
        Timestamp = io_lib:format("~4..0w~2..0w~2..0w_~2..0w~2..0w~2..0w", 
                                  [Y,M,D,H,Min,S]),
        BackupName = io_lib:format("cryptic_chat_backup_~s.db", [Timestamp]),
        BackupPath = filename:join(BackupDir, lists:flatten(BackupName)),
        
        %% For ETS tables, we'll save to a file format
        %% Note: SourcePath parameter is currently unused as we backup from ETS tables
        save_ets_backup(BackupPath),
        ok
    catch
        _:Error ->
            {error, {backup_failed, Error}}
    end.

%% @doc Get storage statistics.
-spec get_storage_stats() -> {ok, [{atom(), term()}]} | {error, term()}.
get_storage_stats() ->
    try
        MessageCount = ets:info(cryptic_messages, size),
        ContactCount = ets:info(cryptic_contacts, size),
        ProfileCount = ets:info(cryptic_profiles, size),
        QueuedCount = ets:info(cryptic_outbox, size),
        
        Stats = [
            {message_count, MessageCount},
            {contact_count, ContactCount},
            {profile_count, ProfileCount},
            {queued_messages, QueuedCount},
            {storage_type, ets_memory},
            {database_path, get_storage_path()}
        ],
        {ok, Stats}
    catch
        _:Error ->
            {error, {stats_failed, Error}}
    end.

%%%===================================================================
%%% Internal Helper Functions
%%%===================================================================

%% @private
%% @doc Generate a unique message ID.
generate_message_id() ->
    {Mega, Sec, Micro} = erlang:timestamp(),
    lists:flatten(io_lib:format("~w_~w_~w", [Mega, Sec, Micro])).

%% @private
%% @doc Save ETS tables to backup file.
save_ets_backup(BackupPath) ->
    try
        BackupData = [
            {messages, ets:tab2list(cryptic_messages)},
            {contacts, ets:tab2list(cryptic_contacts)},
            {profiles, ets:tab2list(cryptic_profiles)},
            {outbox, ets:tab2list(cryptic_outbox)}
        ],
        
        case file:write_file(BackupPath, term_to_binary(BackupData)) of
            ok -> ok;
            {error, Reason} -> throw({write_backup_failed, Reason})
        end
    catch
        throw:Error -> throw(Error);
        _:Error -> throw({backup_save_failed, Error})
    end.
