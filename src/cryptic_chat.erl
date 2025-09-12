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
    quit/0                % Exit chat shell
]).

%% Internal state management
-export([
    shell_loop/1,         % Main shell loop
    parse_command/1,      % Command parser
    format_message/2      % Message formatting
]).

%% State record
-record(chat_state, {
    server_url = "http://localhost:8080" :: string(),
    current_user :: string() | undefined,
    keypair :: {binary(), binary()} | undefined,
    user_cache = #{} :: #{string() => binary()}  % Username -> PubKey cache
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
    
    %% Display welcome message
    io:format("~n=== Cryptic Chat Shell ===~n"),
    io:format("Server: ~s~n", [ServerUrl]),
    io:format("Type 'help' for available commands~n~n"),
    
    %% Initialize state
    State = #chat_state{server_url = ServerUrl},
    
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
        User -> io_lib:format("~s> ", [User])
    end,
    
    %% Read user input
    case io:get_line(Prompt) of
        eof -> 
            io:format("Goodbye!~n"),
            ok;
        Line ->
            Command = string:trim(Line),
            try
                NewState = handle_command(Command, State),
                shell_loop(NewState)
            catch
                exit:normal ->
                    ok;
                error:Reason ->
                    io:format("Error: ~p~n", [Reason]),
                    shell_loop(State)
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
            {_PubKey, PrivKey} = State#chat_state.keypair,
            case cryptic_client_lib:receive_and_decrypt_messages(
                State#chat_state.server_url, Username, PrivKey) of
                {ok, []} ->
                    io:format("No new messages~n");
                {ok, Messages} ->
                    display_messages(Messages);
                {error, Reason} ->
                    io:format("Failed to check inbox: ~p~n", [Reason])
            end,
            State
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
%% @doc Display help information.
display_help() ->
    io:format("~n=== Cryptic Chat Commands ===~n"),
    io:format("register <username>     - Register with a new keypair~n"),
    io:format("list_users              - Show all users with published prekeys~n"),
    io:format("send <user> \"<msg>\"     - Send encrypted message to user~n"),
    io:format("send <user> <msg>       - Send encrypted message (without quotes)~n"),
    io:format("inbox                   - Check for new messages~n"),
    io:format("help                    - Show this help message~n"),
    io:format("quit                    - Exit chat shell~n"),
    io:format("=============================~n~n").
