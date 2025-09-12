%% @doc Cryptic Chat Shell - Interactive End-to-End Encrypted Messaging
%%
%% This module provides an interactive command-line chat interface for the Cryptic
%% messaging system. Users can register, send encrypted messages, check their inbox,
%% and discover other users directly from the Erlang shell.
%%
%% == Basic Usage ==
%% ```
%% %% Start the chat shell
%% cryptic_chat:start().
%%
%% %% Example session:
%% > register alice
%% Successfully registered as alice
%% alice> list_users
%% Available users: [bob, charlie]
%% alice> send bob "Hello Bob, this is encrypted!"
%% Message sent to bob
%% alice> inbox
%% === New Messages ===
%% [2025-09-12T14:30:00Z] charlie: Hi Alice!
%% ====================
%% alice> quit
%% Goodbye!
%% '''
%%
%% @author Torbjörn Törnkvist
%% @version 1.0.0
%% @since September 2025
-module(cryptic_chat).

%% Public API
-export([
    start/0,              % Start interactive chat shell
    start/1,              % Start with server URL
    register/1,           % Register user with generated keypair
    list_users/0,         % List available users
    send/2,               % Send message: send(To, Message)
    inbox/0,              % Check messages for current user
    help/0,               % Display help
    quit/0,               % Exit chat shell

    %% Phase 2 enhancements
    history/1,            % View conversation history with user
    history/2,            % View conversation history with limit
    search/1,             % Search messages by content
    contacts/0,           % List contacts
    add_contact/1,        % Add contact
    add_contact/2,        % Add contact with alias
    remove_contact/1,     % Remove contact
    set_polling/1,        % Enable/disable automatic polling
    show_stats/0,         % Show storage statistics
    backup/0              % Create storage backup
]).

%% Internal state management
-export([
    shell_loop/1,         % Main shell loop
    parse_command/1,      % Command parser
    format_message/2      % Message formatting
]).

%% Polling interval in milliseconds
-define(POLL_INTERVAL, 2000).   % FIXME 

%% State record
-record(chat_state, {
    server_url = "http://localhost:8080" :: string(),
    current_user :: string() | undefined,
    keypair :: {binary(), binary()} | undefined,
    user_cache = #{} :: #{string() => binary()},  % Username -> PubKey cache

    %% Phase 2 enhancements
    polling_enabled = false :: boolean(),         % Auto-polling for messages
    polling_interval = ?POLL_INTERVAL :: pos_integer(), % Polling interval in milliseconds
    polling_timer :: timer:tref() | undefined,    % Timer reference for polling
    storage_initialized = false :: boolean(),     % Storage system status
    last_inbox_check :: calendar:datetime() | undefined,  % Last inbox check time
    unread_count = 0 :: non_neg_integer()        % Number of unread messages
}).

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Start the chat shell with default server URL.
%%
%% Initializes the Cryptic client library and starts an interactive
%% chat shell connected to the default server at localhost:8080.
%%
%% @returns `ok' when the shell exits normally.
-spec start() -> ok.
start() ->
    start("http://localhost:8080").

%% @doc Start the chat shell with a custom server URL.
%%
%% @param ServerUrl Base URL of the Cryptic server (e.g., "http://localhost:8080")
%% @returns `ok' when the shell exits normally.
-spec start(string()) -> ok.
start(ServerUrl) ->
    %% Initialize client library
    cryptic_client_lib:init_client(),

    %% Initialize storage system
    StorageInitialized = case cryptic_chat_storage:init_storage() of
        ok -> 
            io:format("Storage system initialized~n"),
            true;
        {error, Reason} ->
            io:format("Warning: Storage initialization failed: ~p~n", [Reason]),
            io:format("Continuing without persistent storage~n"),
            false
    end,

    %% Display welcome message
    io:format("~n=== Cryptic Chat Shell ===~n"),
    io:format("Server: ~s~n", [ServerUrl]),
    io:format("Type 'help' for available commands~n~n"),

    %% Initialize state with storage
    State = #chat_state{
        server_url = ServerUrl,
        storage_initialized = StorageInitialized
    },

    %% Start interactive shell loop
    shell_loop(State).

%% @doc Register a user with a new keypair.
%%
%% This is a convenience function for use outside the interactive shell.
%% It generates a new keypair and uploads the public key to the server.
%%
%% @param Username User identifier
%% @returns `ok' if successful, `{error, Reason}' if it fails.
-spec register(string()) -> ok | {error, term()}.
register(Username) ->
    cryptic_client_lib:init_client(),
    {PubKey, _PrivKey} = cryptic_lib:gen_keypair(),
    cryptic_client_lib:upload_prekey("http://localhost:8080", Username, PubKey).

%% @doc List all users with published prekeys.
%%
%% This is a convenience function for use outside the interactive shell.
%% Note: Currently returns a placeholder as the server doesn't implement
%% user listing yet.
%%
%% @returns `{ok, [Username]}' with list of available users.
-spec list_users() -> {ok, [string()]} | {error, term()}.
list_users() ->
    %% Use the client library to get the list of users from the server
    cryptic_client_lib:list_users("http://localhost:8080").

%% @doc Send an encrypted message to another user.
%%
%% This is a convenience function for use outside the interactive shell.
%% Note: Requires the user to be registered first or provide keypair.
%%
%% @param ToUser Recipient's username
%% @param Message Message content
%% @returns `ok' if successful, `{error, Reason}' if it fails.
-spec send(string(), string()) -> ok | {error, term()}.
send(_ToUser, _Message) ->
    {error, "Use interactive shell or provide full parameters"}.

%% @doc Check messages for the current user.
%%
%% This is a convenience function for use outside the interactive shell.
%% Note: Requires the user to be registered first or provide keypair.
%%
%% @returns `{ok, Messages}' or `{error, Reason}'.
-spec inbox() -> {ok, [term()]} | {error, term()}.
inbox() ->
    {error, "Use interactive shell or provide full parameters"}.

%% @doc Display help information.
%%
%% Shows available commands and their usage.
-spec help() -> ok.
help() ->
    display_help().

%% @doc Exit the chat shell.
%%
%% Convenience function to exit the interactive shell.
-spec quit() -> no_return().
quit() ->
    io:format("Goodbye!~n"),
    exit(normal).

%%%===================================================================
%%% Interactive Shell Implementation
%%%===================================================================

%% @doc Main interactive shell loop.
%%
%% Handles user input, command parsing, and state management for the
%% interactive chat session.
%%
%% @param State Current chat state record
%% @returns `ok' when the shell exits normally.
-spec shell_loop(#chat_state{}) -> ok.
shell_loop(State) ->
    %% Display prompt with current user
    Prompt = case State#chat_state.current_user of
        undefined -> "> ";
        User -> 
            UnreadStr = case State#chat_state.unread_count of
                0 -> "";
                N -> io_lib:format(" (~p unread)", [N])
            end,
            io_lib:format("~s~s> ", [User, UnreadStr])
    end,

    %% Check for messages or user input
    receive
        poll_messages ->
            %% Handle automatic polling
            NewState = handle_polling_check(State),
            shell_loop(NewState);

        {input_ready, Line} ->
            %% Handle user input
            Command = string:trim(Line),
            try
                NewState = handle_command(Command, State),
                shell_loop(NewState)
            catch
                exit:normal ->
                    cleanup_state(State),
                    ok;
                error:Reason ->
                    io:format("Error: ~p~n", [Reason]),
                    shell_loop(State)
            end
    after 100 ->
        %% Non-blocking input check
        case io:get_line(Prompt) of
            eof -> 
                io:format("Goodbye!~n"),
                cleanup_state(State),
                ok;
            Line ->
                Command = string:trim(Line),
                try
                    NewState = handle_command(Command, State),
                    shell_loop(NewState)
                catch
                    exit:normal ->
                        cleanup_state(State),
                        ok;
                    error:Reason ->
                        io:format("Error: ~p~n", [Reason]),
                        shell_loop(State)
                end
        end
    end.

%% @doc Parse and handle a user command.
%%
%% @param Command User input string
%% @param State Current chat state
%% @returns Updated chat state record.
-spec parse_command(string()) -> term().
parse_command(Command) ->
    %% This is a placeholder - actual parsing is done in handle_command/2
    Command.

%% @doc Format a message for display.
%%
%% @param From Sender's username
%% @param Message Message content
%% @returns Formatted message string.
-spec format_message(string(), string()) -> string().
format_message(From, Message) ->
    Timestamp = calendar:system_time_to_rfc3339(erlang:system_time(second)),
    io_lib:format("[~s] ~s: ~s", [Timestamp, From, Message]).

%%%===================================================================
%%% Internal Command Handlers
%%%===================================================================

%% @private
%% @doc Handle user commands and update state accordingly.
handle_command("help", State) ->
    display_help(),
    State;
handle_command("register " ++ Username, State) ->
    register_user(string:trim(Username), State);
handle_command("list_users", State) ->
    list_users_command(State);
handle_command("send " ++ Args, State) ->
    parse_send_command(Args, State);
handle_command("inbox", State) ->
    check_inbox(State);
handle_command("quit", _State) ->
    io:format("Goodbye!~n"),
    exit(normal);
handle_command("", State) ->
    %% Empty command, just continue
    State;

%% Phase 2 command handlers
handle_command("history " ++ Args, State) ->
    handle_history_command(Args),
    State;
handle_command("search " ++ SearchTerm, State) ->
    search(string:trim(SearchTerm)),
    State;
handle_command("contacts", State) ->
    contacts(),
    State;
handle_command("add_contact " ++ Args, State) ->
    handle_add_contact_command(Args),
    State;
handle_command("remove_contact " ++ Username, State) ->
    remove_contact(string:trim(Username)),
    State;
handle_command("polling " ++ Args, State) ->
    handle_polling_command(Args, State);
handle_command("stats", State) ->
    show_stats(),
    State;
handle_command("backup", State) ->
    backup(),
    State;

handle_command(Unknown, State) ->
    io:format("Unknown command: ~s~n", [Unknown]),
    io:format("Type 'help' for available commands~n"),
    State.

%% @private
%% @doc Register a user with the chat system.
register_user(Username, State) ->
    case State#chat_state.current_user of
        undefined ->
            %% TODO: Check for existing stored keys when storage module is implemented
            %% For now, always generate new keypair
            {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
            upload_and_set_user(Username, PubKey, PrivKey, State);
        CurrentUser ->
            io:format("Already registered as ~s. Use 'quit' to exit.~n", [CurrentUser]),
            State
    end.

%% @private
%% @doc Upload public key and set user in state.
upload_and_set_user(Username, PubKey, PrivKey, State) ->
    case cryptic_client_lib:upload_prekey(State#chat_state.server_url, Username, PubKey) of
        ok ->
            io:format("Successfully registered as ~s~n", [Username]),
            State#chat_state{
                current_user = Username,
                keypair = {PubKey, PrivKey}
            };
        {error, Reason} ->
            io:format("Failed to register: ~p~n", [Reason]),
            State
    end.

%% @private
%% @doc List available users command handler.
list_users_command(State) ->
    case cryptic_client_lib:list_users(State#chat_state.server_url) of
        {ok, []} ->
            io:format("No users found. Be the first to register!~n");
        {ok, Users} ->
            io:format("Users with published prekeys:~n"),
            lists:foreach(fun(User) ->
                CurrentMark = case State#chat_state.current_user of
                    User -> " (you)";
                    _ -> ""
                end,
                io:format("  - ~s~s~n", [User, CurrentMark])
            end, Users);
        {error, Reason} ->
            io:format("Failed to list users: ~p~n", [Reason])
    end,
    State.

%% @private
%% @doc Parse and handle send command.
parse_send_command(Args, State) ->
    case State#chat_state.current_user of
        undefined ->
            io:format("Please register first using 'register <username>'~n"),
            State;
        FromUser ->
            case parse_send_args(Args) of
                {ok, {ToUser, Message}} ->
                    send_message(FromUser, ToUser, Message, State);
                {error, Reason} ->
                    io:format("Invalid send command: ~s~n", [Reason]),
                    io:format("Usage: send <username> \"<message>\"~n"),
                    io:format("   or: send <username> <message_without_quotes>~n"),
                    State
            end
    end.

%% @private
%% @doc Parse arguments for send command.
parse_send_args(Args) ->
    %% Handle both quoted and unquoted messages
    %% Format: send username "message" or send username message
    case string:split(string:trim(Args), " ", leading) of
        [Username, MessagePart] ->
            %% Check if message is quoted
            case string:trim(MessagePart) of
                [$" | Rest] ->
                    %% Quoted message - remove trailing quote if present
                    Message = case lists:reverse(Rest) of
                        [$" | RevRest] -> lists:reverse(RevRest);
                        _ -> Rest
                    end,
                    {ok, {string:trim(Username), Message}};
                UnquotedMessage ->
                    %% Unquoted message
                    {ok, {string:trim(Username), UnquotedMessage}}
            end;
        [_] ->
            {error, "Missing message"};
        [] ->
            {error, "Missing username and message"}
    end.

%% @private
%% @doc Send an encrypted message to another user.
send_message(FromUser, ToUser, Message, State) ->
    {_PubKey, PrivKey} = State#chat_state.keypair,

    case cryptic_client_lib:send_encrypted_message(
        State#chat_state.server_url, FromUser, ToUser, Message, PrivKey) of
        ok ->
            io:format("Message sent to ~s~n", [ToUser]);
        {error, Reason} ->
            io:format("Failed to send message: ~p~n", [Reason])
    end,
    State.

%% @private
%% @doc Check inbox for new messages.
check_inbox(State) ->
    case State#chat_state.current_user of
        undefined ->
            io:format("Please register first~n"),
            State;
        Username ->
            % If polling is enabled and storage is initialized, check local storage first
            case State#chat_state.polling_enabled andalso State#chat_state.storage_initialized of
                true ->
                    % Check local storage for unread messages
                    case cryptic_chat_storage:get_unread_messages(Username) of
                        {ok, []} ->
                            io:format("No new messages~n"),
                            % Sync the unread count with actual storage state
                            State#chat_state{unread_count = 0};
                        {ok, Messages} ->
                            io:format("=== New Messages ===~n"),
                            display_stored_messages(Messages),
                            io:format("====================~n"),
                            % Mark messages as read
                            lists:foreach(fun({MessageId, _, _, _, _, _, _}) ->
                                cryptic_chat_storage:mark_message_read(MessageId)
                            end, Messages),
                            % Update unread count to 0 since we just read all messages
                            State#chat_state{unread_count = 0};
                        {error, Reason} ->
                            io:format("Failed to check local messages: ~p~n", [Reason]),
                            State
                    end;
                false ->
                    % Fall back to server check
                    {_PubKey, PrivKey} = State#chat_state.keypair,
                    case cryptic_client_lib:receive_and_decrypt_messages(
                        State#chat_state.server_url, Username, PrivKey) of
                        {ok, []} ->
                            io:format("No new messages~n"),
                            State;
                        {ok, Messages} ->
                            display_messages(Messages),
                            State;
                        {error, Reason} ->
                            io:format("Failed to check inbox: ~p~n", [Reason]),
                            State
                    end
            end
    end.

%% @private
%% @doc Display received messages in a formatted way.
display_messages(Messages) ->
    io:format("~n=== New Messages ===~n"),
    lists:foreach(fun({From, Message}) ->
        Timestamp = calendar:system_time_to_rfc3339(erlang:system_time(second)),
        io:format("[~s] ~s: ~s~n", [Timestamp, From, Message])
    end, Messages),
    io:format("====================~n~n").

%% @private
%% @doc Display messages from local storage.
display_stored_messages(Messages) ->
    lists:foreach(fun({_MessageId, From, _To, Message, _Type, Timestamp, _ReadStatus}) ->
        % Format timestamp for display
        FormattedTime = format_timestamp(Timestamp),
        io:format("[~s] ~s: ~s~n", [FormattedTime, From, Message])
    end, Messages).

%% @private
%% @doc Display help information.
display_help() ->
    io:format("~n=== Cryptic Chat Commands ===~n"),
    io:format("register <username>     - Register with a new keypair~n"),
    io:format("list_users              - Show all users with published prekeys~n"),
    io:format("send <user> \"<msg>\"     - Send encrypted message to user~n"),
    io:format("send <user> <msg>       - Send encrypted message (without quotes)~n"),
    io:format("inbox                   - Check for new messages~n"),
    io:format("~n=== Phase 2 Commands ===~n"),
    io:format("history <user>          - View conversation history with user~n"),
    io:format("history <user> <limit>  - View limited conversation history~n"),
    io:format("search <term>           - Search messages by content~n"),
    io:format("contacts                - List all contacts~n"),
    io:format("add_contact <user>      - Add user to contacts~n"),
    io:format("add_contact <user> <alias> - Add user with alias~n"),
    io:format("remove_contact <user>   - Remove user from contacts~n"),
    io:format("polling on/off          - Enable/disable auto message polling~n"),
    io:format("stats                   - Show storage statistics~n"),
    io:format("backup                  - Create storage backup~n"),
    io:format("~n=== General ===~n"),
    io:format("help                    - Show this help message~n"),
    io:format("quit                    - Exit chat shell~n"),
    io:format("=============================~n~n").

%%%===================================================================
%%% Phase 2 Enhanced Functions
%%%===================================================================

%% @doc View conversation history with a user.
%%
%% @param Username The user to view conversation history with
%% @returns `{ok, Messages}' or `{error, term()}'
-spec history(string()) -> {ok, [term()]} | {error, term()}.
history(Username) ->
    history(Username, 50).  % Default limit

%% @doc View conversation history with a user and message limit.
-spec history(string(), pos_integer()) -> {ok, [term()]} | {error, term()}.
history(Username, Limit) ->
    case get_current_user_from_storage() of
        {ok, CurrentUser} ->
            case cryptic_chat_storage:get_conversation(CurrentUser, Username, Limit) of
                {ok, Messages} ->
                    display_conversation_history(Messages),
                    {ok, Messages};
                {error, Reason} ->
                    io:format("Failed to retrieve conversation history: ~p~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("No current user found: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Search messages by content.
-spec search(string()) -> {ok, [term()]} | {error, term()}.
search(SearchTerm) ->
    case cryptic_chat_storage:search_messages(SearchTerm, 25) of
        {ok, Messages} ->
            display_search_results(SearchTerm, Messages),
            {ok, Messages};
        {error, Reason} ->
            io:format("Search failed: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc List all contacts.
-spec contacts() -> {ok, [term()]} | {error, term()}.
contacts() ->
    case cryptic_chat_storage:get_all_contacts() of
        {ok, Contacts} ->
            display_contacts(Contacts),
            {ok, Contacts};
        {error, Reason} ->
            io:format("Failed to retrieve contacts: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Add a contact.
-spec add_contact(string()) -> ok | {error, term()}.
add_contact(Username) ->
    add_contact(Username, Username).

%% @doc Add a contact with alias.
-spec add_contact(string(), string()) -> ok | {error, term()}.
add_contact(Username, Alias) ->
    case cryptic_chat_storage:add_contact(Username, Alias) of
        ok ->
            io:format("Added contact: ~s (alias: ~s)~n", [Username, Alias]),
            ok;
        {error, Reason} ->
            io:format("Failed to add contact: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Remove a contact.
-spec remove_contact(string()) -> ok | {error, term()}.
remove_contact(Username) ->
    case cryptic_chat_storage:remove_contact(Username) of
        ok ->
            io:format("Removed contact: ~s~n", [Username]),
            ok;
        {error, Reason} ->
            io:format("Failed to remove contact: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Enable or disable automatic message polling.
-spec set_polling(boolean()) -> ok | {error, term()}.
set_polling(Enabled) ->
    case Enabled of
        true ->
            io:format("Automatic message polling enabled (30s interval)~n"),
            io:format("Note: Polling requires interactive shell context~n");
        false ->
            io:format("Automatic message polling disabled~n")
    end,
    {error, "Use interactive shell for polling control"}.

%% @doc Show storage statistics.
-spec show_stats() -> ok | {error, term()}.
show_stats() ->
    case cryptic_chat_storage:get_storage_stats() of
        {ok, Stats} ->
            display_stats(Stats),
            ok;
        {error, Reason} ->
            io:format("Failed to retrieve statistics: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Create storage backup.
-spec backup() -> ok | {error, term()}.
backup() ->
    case cryptic_chat_storage:backup_storage() of
        ok ->
            io:format("Storage backup created successfully~n"),
            ok;
        {error, Reason} ->
            io:format("Backup failed: ~p~n", [Reason]),
            {error, Reason}
    end.

%%%===================================================================
%%% Phase 2 Helper Functions
%%%===================================================================

%% @private
%% @doc Get current user from storage system.
get_current_user_from_storage() ->
    cryptic_chat_storage:get_current_user().

%% @private
%% @doc Display conversation history.
display_conversation_history(Messages) ->
    io:format("~n=== Conversation History ===~n"),
    case Messages of
        [] ->
            io:format("No messages found~n");
        _ ->
            lists:foreach(fun({_Id, From, To, Msg, _Type, Timestamp, Read}) ->
                ReadStatus = case Read of
                    true -> " ";
                    false -> "*"
                end,
                TimeStr = format_timestamp(Timestamp),
                io:format("~s[~s] ~s -> ~s: ~s~n", [ReadStatus, TimeStr, From, To, Msg])
            end, Messages)
    end,
    io:format("========================~n~n").

%% @private
%% @doc Display search results.
display_search_results(SearchTerm, Messages) ->
    io:format("~n=== Search Results for '~s' ===~n", [SearchTerm]),
    case Messages of
        [] ->
            io:format("No messages found~n");
        _ ->
            lists:foreach(fun({_Id, From, To, Msg, _Type, Timestamp, _Read}) ->
                TimeStr = format_timestamp(Timestamp),
                io:format("[~s] ~s -> ~s: ~s~n", [TimeStr, From, To, Msg])
            end, Messages),
            io:format("Found ~p messages~n", [length(Messages)])
    end,
    io:format("=========================~n~n").

%% @private
%% @doc Display contacts list.
display_contacts(Contacts) ->
    io:format("~n=== Contacts ===~n"),
    case Contacts of
        [] ->
            io:format("No contacts found~n");
        _ ->
            lists:foreach(fun({Username, Alias, _PubKey, LastSeen, Favorite, Blocked}) ->
                FavStr = case Favorite of
                    true -> " ⭐";
                    false -> ""
                end,
                BlockedStr = case Blocked of
                    true -> " [BLOCKED]";
                    false -> ""
                end,
                LastSeenStr = case LastSeen of
                    undefined -> "Never";
                    _ -> format_timestamp(LastSeen)
                end,
                io:format("~s (~s)~s~s - Last seen: ~s~n", 
                         [Username, Alias, FavStr, BlockedStr, LastSeenStr])
            end, Contacts)
    end,
    io:format("===============~n~n").

%% @private
%% @doc Display storage statistics.
display_stats(Stats) ->
    io:format("~n=== Storage Statistics ===~n"),
    lists:foreach(fun({Key, Value}) ->
        io:format("~s: ~p~n", [format_stat_key(Key), Value])
    end, Stats),
    io:format("========================~n~n").

%% @private
%% @doc Format statistic key for display.
format_stat_key(message_count) -> "Messages";
format_stat_key(contact_count) -> "Contacts";
format_stat_key(profile_count) -> "Profiles";
format_stat_key(queued_messages) -> "Queued Messages";
format_stat_key(storage_type) -> "Storage Type";
format_stat_key(database_path) -> "Database Path";
format_stat_key(Key) -> atom_to_list(Key).

%% @private
%% @doc Format timestamp for display.
format_timestamp({{Y,M,D},{H,Min,S}}) ->
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w", [Y,M,D,H,Min,S]).

%%%===================================================================
%%% Phase 2 Command Handlers
%%%===================================================================

%% @private
%% @doc Handle history command with arguments.
handle_history_command(Args) ->
    case string:split(string:trim(Args), " ") of
        [Username] ->
            history(Username);
        [Username, LimitStr] ->
            try
                Limit = list_to_integer(LimitStr),
                history(Username, Limit)
            catch
                _:_ ->
                    io:format("Invalid limit: ~s~n", [LimitStr])
            end;
        _ ->
            io:format("Usage: history <username> [limit]~n")
    end.

%% @private
%% @doc Handle add_contact command with arguments.
handle_add_contact_command(Args) ->
    case string:split(string:trim(Args), " ") of
        [Username] ->
            add_contact(Username);
        [Username | AliasParts] ->
            Alias = string:join(AliasParts, " "),
            add_contact(Username, Alias);
        [] ->
            io:format("Usage: add_contact <username> [alias]~n")
    end.

%% @private
%% @doc Handle polling command.
handle_polling_command(Args, State) ->
    case string:trim(string:lowercase(Args)) of
        "on" ->
            case State#chat_state.polling_enabled of
                true ->
                    io:format("Polling is already enabled~n"),
                    State;
                false ->
                    start_polling(State)
            end;
        "off" ->
            case State#chat_state.polling_enabled of
                false ->
                    io:format("Polling is already disabled~n"),
                    State;
                true ->
                    stop_polling(State)
            end;
        _ ->
            io:format("Usage: polling on|off~n"),
            State
    end.

%% @private
%% @doc Start automatic message polling.
start_polling(State) ->
    case State#chat_state.current_user of
        undefined ->
            io:format("Please register first before enabling polling~n"),
            State;
        _User ->
            Interval = State#chat_state.polling_interval,
            case timer:send_interval(Interval, self(), poll_messages) of
                {ok, TimerRef} ->
                    io:format("Automatic message polling enabled (~p seconds interval)~n", [Interval div 1000]),
                    State#chat_state{
                        polling_enabled = true,
                        polling_timer = TimerRef
                    };
                {error, Reason} ->
                    io:format("Failed to start polling: ~p~n", [Reason]),
                    State
            end
    end.

%% @private  
%% @doc Stop automatic message polling.
stop_polling(State) ->
    case State#chat_state.polling_timer of
        undefined ->
            State#chat_state{polling_enabled = false};
        TimerRef ->
            timer:cancel(TimerRef),
            io:format("Automatic message polling disabled~n"),
            State#chat_state{
                polling_enabled = false,
                polling_timer = undefined
            }
    end.

%% @private
%% @doc Handle automatic polling check.
handle_polling_check(State) ->
    case State#chat_state.current_user of
        undefined ->
            State;
        User ->
            %% Check for new messages and update unread count
            case check_inbox_silent(State) of
                {ok, NewMessages} when length(NewMessages) > 0 ->
                    %% Save messages to storage first, then update state
                    case State#chat_state.storage_initialized of
                        true ->
                            save_new_messages(User, NewMessages, State),
                            %% Sync unread count with actual storage state
                            TempState = State#chat_state{last_inbox_check = calendar:universal_time()},
                            SyncedState = sync_unread_count(TempState),
                            io:format("~n[~p new messages] ", [SyncedState#chat_state.unread_count]),
                            SyncedState;
                        false ->
                            %% If storage not initialized, just display the count
                            io:format("~n[~p new messages] ", [length(NewMessages)]),
                            State#chat_state{
                                unread_count = State#chat_state.unread_count + length(NewMessages),
                                last_inbox_check = calendar:universal_time()
                            }
                    end;
                _ ->
                    State#chat_state{last_inbox_check = calendar:universal_time()}
            end
    end.

%% @private
%% @doc Check inbox without displaying messages (for polling).
check_inbox_silent(State) ->
    case State#chat_state.current_user of
        undefined ->
            {error, not_registered};
        User ->
            case cryptic_client_lib:receive_and_decrypt_messages(
                State#chat_state.server_url, User, 
                element(2, State#chat_state.keypair)) of
                {ok, Messages} ->
                    {ok, Messages};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @private
%% @doc Save new messages to storage.
save_new_messages(CurrentUser, Messages, State) ->
    case State#chat_state.storage_initialized of
        false -> ok;
        true ->
            lists:foreach(fun(Msg) ->
                case Msg of
                    {From, Message} ->
                        case cryptic_chat_storage:save_message(From, CurrentUser, Message, "text") of
                            ok -> ok;
                            {error, Reason} ->
                                io:format("Warning: Failed to save message from ~s: ~p~n", [From, Reason])
                        end;
                    _ -> ok
                end
            end, Messages)
    end.

%% @private
%% @doc Sync unread count with actual storage state.
sync_unread_count(State) ->
    case State#chat_state.storage_initialized andalso State#chat_state.current_user of
        false -> State;
        undefined -> State;
        Username ->
            case cryptic_chat_storage:get_unread_messages(Username) of
                {ok, UnreadMessages} ->
                    ActualCount = length(UnreadMessages),
                    State#chat_state{unread_count = ActualCount};
                {error, _} ->
                    State
            end
    end.

%% @private
%% @doc Clean up state when exiting.
cleanup_state(State) ->
    %% Stop polling timer if running
    case State#chat_state.polling_timer of
        undefined -> ok;
        TimerRef -> timer:cancel(TimerRef)
    end,
    
    %% Close storage if initialized
    case State#chat_state.storage_initialized of
        false -> ok;
        true -> cryptic_chat_storage:close_storage()
    end.
