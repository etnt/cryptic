%%% @doc Cryptic WebSocket mTLS Handler
%%%
%%% This module implements a Cowboy WebSocket handler for the Cryptic chat
%%% application that provides secure real-time messaging using mutual TLS
%%% (mTLS) client certificate authentication. It handles WebSocket connections,
%%% user authentication, message routing, and connection management.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>mTLS client certificate authentication</li>
%%%   <li>Real-time bidirectional messaging over WebSocket</li>
%%%   <li>User connection tracking and presence management</li>
%%%   <li>Public key exchange for end-to-end encryption</li>
%%%   <li>Message storage and retrieval</li>
%%%   <li>User listing and status checking</li>
%%%   <li>JSON-based command protocol</li>
%%% </ul>
%%%
%%% == Authentication ==
%%%
%%% Users are authenticated using X.509 client certificates during the
%%% TLS handshake. The Common Name (CN) field in the certificate subject
%%% is used as the username for the authenticated session.
%%%
%%% == Command Protocol ==
%%%
%%% The handler processes JSON commands over WebSocket:
%%% <ul>
%%%   <li>`upload_prekey' - Upload user's public key for encryption</li>
%%%   <li>`get_prekey' - Request another user's public key</li>
%%%   <li>`send_message' - Send encrypted message to another user</li>
%%%   <li>`get_messages' - Retrieve stored messages</li>
%%%   <li>`list_users' - Get list of registered users</li>
%%% </ul>
%%%
%%% == Connection Management ==
%%%
%%% Active user connections are tracked in an ETS table for:
%%% <ul>
%%%   <li>Real-time message delivery to online users</li>
%%%   <li>User presence detection</li>
%%%   <li>Connection cleanup on disconnect</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_ws_handler).
-behaviour(cowboy_websocket).

-include("cryptic.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    init/2, websocket_init/1, websocket_handle/2, websocket_info/2, terminate/3
]).

%% @doc HTTP to WebSocket upgrade handler
%%
%% This function is called by Cowboy during the HTTP to WebSocket upgrade
%% process. It performs client certificate authentication by extracting
%% the client's X.509 certificate and validating it to determine the
%% user's identity.
%%
%% @param Req The Cowboy request object containing the HTTP request
%% @param State The initial handler state (unused in upgrade)
%% @returns {cowboy_websocket, Req, State} for successful authentication,
%%          or {ok, Response, State} with 401 error for authentication failure
init(Req, State) ->
    %% Extract client certificate information during handshake
    case get_client_identity(Req) of
        {ok, Username} ->
            ?info("Client ~s authenticated via certificate", [Username]),
            {cowboy_websocket, Req, #{username => Username}};
        {error, Reason} ->
            ?error("Client certificate authentication failed: ~p", [Reason]),
            {ok,
                cowboy_req:reply(
                    401, #{}, <<"Client certificate required">>, Req
                ),
                State}
    end.

%% @doc WebSocket connection initialization
%%
%% Called after successful WebSocket upgrade to initialize the connection.
%% Registers the authenticated user's connection for message routing and
%% sends a welcome message to confirm the connection is established.
%%
%% @param State The WebSocket state containing the authenticated username
%% @returns {Replies, State} where Replies contains the welcome message
websocket_init(State = #{username := Username}) ->
    %% Register this connection for the user
    register_user_connection(Username, self()),

    %% Send welcome message
    WelcomeMsg = #{
        type => <<"welcome">>,
        message => <<"Connected to Cryptic server">>,
        username => list_to_binary(Username)
    },
    {[{text, jsx:encode(WelcomeMsg)}], State}.

%% @doc Handle incoming WebSocket frames
%%
%% Processes various types of WebSocket frames including text messages
%% containing JSON commands, binary data, and control frames (ping/pong).
%% Text messages are parsed as JSON and dispatched to command handlers.
%%
%% @param Frame The WebSocket frame to process
%% @param State The current WebSocket state containing user information
%% @returns {Replies, State} or {Replies, NewState} with optional response frames
websocket_handle({text, Msg}, State = #{username := Username}) ->
    try
        Command = jsx:decode(Msg, [return_maps]),
        case handle_command(Command, Username, State) of
            {reply, Response} ->
                ResponseJson = jsx:encode(Response),
                {[{text, ResponseJson}], State};
            {reply, Response, NewState} ->
                {[{text, jsx:encode(Response)}], NewState};
            {noreply, NewState} ->
                {[], NewState};
            {error, ErrorMsg} ->
                ErrorResp = #{
                    type => <<"error">>,
                    message => list_to_binary(ErrorMsg)
                },
                {[{text, jsx:encode(ErrorResp)}], State}
        end
    catch
        _Error:_Reason ->
            ErrorResponse = #{
                type => <<"error">>,
                message => <<"Invalid JSON format">>
            },
            {[{text, jsx:encode(ErrorResponse)}], State}
    end;
websocket_handle({binary, _Data}, State) ->
    %% Handle binary data if needed
    {[], State};
%% Handle WebSocket ping frames
websocket_handle(ping, State) ->
    %% Respond with pong
    {[pong], State};
%% Handle WebSocket pong frames
websocket_handle(pong, State) ->
    %% Just acknowledge, no response needed
    {[], State};
websocket_handle(_Data, State) ->
    {[], State}.

%% @doc Handle Erlang messages sent to the WebSocket process
%%
%% Processes internal Erlang messages sent to the WebSocket handler process,
%% particularly messages from other users that need to be forwarded to the
%% connected client.
%%
%% @param Info The Erlang message received by the process
%% @param State The current WebSocket state
%% @returns {Replies, State} with optional response frames to send to client
websocket_info({message, FromUser, Message}, State = #{username := Username}) ->
    %% Incoming message from another user
    Response = #{
        type => <<"message">>,
        from => list_to_binary(FromUser),
        to => list_to_binary(Username),
        message => Message
    },
    {[{text, jsx:encode(Response)}], State};
websocket_info(_Info, State) ->
    {[], State}.

%% @doc Handle WebSocket commands from clients
%%
%% Dispatches JSON commands received from WebSocket clients to appropriate
%% handlers. Supports various command types including prekey management,
%% messaging, user listing, and message retrieval.
%%
%% @param Command The decoded JSON command map
%% @param Username The authenticated username of the sender
%% @param State The current WebSocket state (usually unused)
%% @returns {reply, Response} for single response,
%%          {reply, Response, NewState} for response with state change,
%%          {noreply, NewState} for state change without response,
%%          {error, ErrorMsg} for error responses
handle_command(
    #{<<"type">> := <<"upload_prekey">>, <<"prekey">> := PrekeyB64},
    Username,
    _State
) ->
    try
        Prekey = base64:decode(PrekeyB64),
        case cryptic_lib:store_prekey(Username, Prekey) of
            ok ->
                {reply, #{
                    type => <<"success">>, message => <<"Prekey uploaded">>
                }};
            {error, Reason} ->
                {error, io_lib:format("Failed to store prekey: ~p", [Reason])}
        end
    catch
        _:_ ->
            {error, "Invalid prekey format"}
    end;
handle_command(
    #{<<"type">> := <<"get_prekey">>, <<"user">> := UserB}, _Username, _State
) ->
    User = binary_to_list(UserB),
    %% First check if the user is currently connected
    case find_user_connection(User) of
        {ok, _Pid} ->
            %% User is online, get their prekey
            case cryptic_lib:get_prekey(User) of
                {ok, Prekey} ->
                    Response = #{
                        type => <<"prekey">>,
                        user => UserB,
                        prekey => base64:encode(Prekey)
                    },
                    {reply, Response};
                {error, not_found} ->
                    {error, "User not found"}
            end;
        not_found ->
            %% User is not currently connected - this is normal, not an error
            Response = #{
                type => <<"user_status">>,
                user => UserB,
                status => <<"offline">>,
                message => <<"User is not currently online">>
            },
            {reply, Response}
    end;
handle_command(
    #{
        <<"type">> := <<"send_message">>,
        <<"to">> := ToUserB,
        <<"ephemeral">> := EphB64,
        <<"nonce">> := NonceB64,
        <<"cipher">> := CipherB64
    },
    Username,
    _State
) ->
    ToUser = binary_to_list(ToUserB),

    %% Create message blob
    MessageBlob = #{
        from => Username,
        to => ToUser,
        ephemeral => EphB64,
        nonce => NonceB64,
        cipher => CipherB64,
        timestamp => erlang:system_time(second)
    },

    %% Store message
    cryptic_lib:store_message(ToUser, MessageBlob),

    %% Try to deliver immediately if user is online
    case find_user_connection(ToUser) of
        {ok, Pid} ->
            Pid ! {message, Username, MessageBlob};
        not_found ->
            % Message stored for later retrieval
            ok
    end,

    {reply, #{type => <<"success">>, message => <<"Message sent">>}};
handle_command(#{<<"type">> := <<"get_messages">>}, Username, _State) ->
    Messages = cryptic_lib:get_messages(Username),
    Response = #{
        type => <<"messages">>,
        messages => Messages
    },
    {reply, Response};
handle_command(#{<<"type">> := <<"list_users">>}, _Username, _State) ->
    Users = cryptic_lib:list_users(),
    Response = #{
        type => <<"users">>,
        users => [list_to_binary(U) || U <- Users]
    },
    {reply, Response};
%% Room management commands
handle_command(#{<<"type">> := <<"create_room">>} = Command, Username, _State) ->
    Response = cryptic_room_handlers:handle_room_command(
        create_room, Command, Username
    ),
    {reply, Response};
handle_command(#{<<"type">> := <<"join_room">>} = Command, Username, _State) ->
    Response = cryptic_room_handlers:handle_room_command(
        join_room, Command, Username
    ),
    {reply, Response};
handle_command(#{<<"type">> := <<"leave_room">>} = Command, Username, _State) ->
    Response = cryptic_room_handlers:handle_room_command(
        leave_room, Command, Username
    ),
    {reply, Response};
handle_command(#{<<"type">> := <<"list_rooms">>} = Command, Username, _State) ->
    Response = cryptic_room_handlers:handle_room_command(
        list_rooms, Command, Username
    ),
    {reply, Response};
handle_command(
    #{<<"type">> := <<"send_room_message">>} = Command, Username, _State
) ->
    io:format("DEBUG WS HANDLER: Calling room handler for send_room_message~n"),
    try
        Response = cryptic_room_handlers:handle_room_command(
            send_room_message, Command, Username
        ),
        io:format("DEBUG WS HANDLER: Room handler returned: ~p~n", [Response]),
        {reply, Response}
    catch
        Error:Reason:Stack ->
            io:format("DEBUG WS HANDLER: Room handler error: ~p:~p~n", [
                Error, Reason
            ]),
            io:format("DEBUG WS HANDLER: Stack trace: ~p~n", [Stack]),
            {error, "Room message failed"}
    end;
handle_command(
    #{<<"type">> := <<"get_room_messages">>} = Command, Username, _State
) ->
    Response = cryptic_room_handlers:handle_room_command(
        get_room_messages, Command, Username
    ),
    {reply, Response};
handle_command(
    #{<<"type">> := <<"get_room_members">>} = Command, Username, _State
) ->
    Response = cryptic_room_handlers:handle_room_command(
        get_room_members, Command, Username
    ),
    {reply, Response};
handle_command(Command, Username, _State) ->
    io:format("Unknown command from ~s: ~p~n", [Username, Command]),
    {error, "Unknown command"}.

%% @doc Extract client identity from SSL/TLS certificate
%%
%% Retrieves the client's X.509 certificate from the Cowboy request
%% and extracts the username from the certificate's Common Name field.
%% This provides the mTLS authentication mechanism for the application.
%%
%% @param Req The Cowboy request object containing the SSL context
%% @returns {ok, Username} for successful authentication,
%%          {error, Reason} for authentication failure
get_client_identity(Req) ->
    case cowboy_req:cert(Req) of
        undefined ->
            {error, no_client_cert};
        Cert ->
            case extract_username_from_cert(Cert) of
                {ok, Username} -> {ok, Username};
                {error, Reason} -> {error, Reason}
            end
    end.

%% @doc Extract username from X.509 certificate Common Name
%%
%% Decodes an X.509 certificate and extracts the Common Name (CN) field
%% from the subject distinguished name, which serves as the username
%% for authentication purposes.
%%
%% @param CertDER The DER-encoded X.509 certificate binary
%% @returns {ok, Username} if Common Name is found,
%%          {error, Reason} if certificate is invalid or CN is missing
extract_username_from_cert(CertDER) ->
    try
        Cert = public_key:pkix_decode_cert(CertDER, otp),
        TBSCert = Cert#'OTPCertificate'.tbsCertificate,
        Subject = TBSCert#'OTPTBSCertificate'.subject,
        case extract_common_name(Subject) of
            {ok, CN} -> {ok, CN};
            error -> {error, no_common_name}
        end
    catch
        _:Error ->
            {error, {cert_decode_error, Error}}
    end.

%% @doc Extract Common Name from certificate subject
%%
%% Processes the subject field of an X.509 certificate to locate
%% the Common Name attribute value.
%%
%% @param Subject The certificate subject as an RDN sequence
%% @returns {ok, CommonName} if found, error if not found
extract_common_name({rdnSequence, RDNSeq}) ->
    extract_cn_from_sequence(RDNSeq).

%% @doc Extract Common Name from RDN sequence
%%
%% Searches through a Relative Distinguished Name sequence to find
%% the Common Name attribute.
%%
%% @param RDNSeq List of RDN entries to search
%% @returns {ok, CommonName} if found, error if not found

extract_cn_from_sequence([]) ->
    error;
extract_cn_from_sequence([RDN | Rest]) ->
    case extract_cn_from_rdn(RDN) of
        {ok, CN} -> {ok, CN};
        error -> extract_cn_from_sequence(Rest)
    end.

%% @doc Extract Common Name from single RDN entry
%%
%% Searches within a single Relative Distinguished Name entry for
%% the Common Name attribute and handles various ASN.1 string types.
%%
%% @param RDN List of AttributeTypeAndValue entries
%% @returns {ok, CommonName} if found, error if not found

extract_cn_from_rdn([]) ->
    error;
extract_cn_from_rdn([
    #'AttributeTypeAndValue'{
        type = ?'id-at-commonName',
        value = Value
    }
    | _
]) ->
    case Value of
        {utf8String, CN} -> {ok, binary_to_list(CN)};
        {printableString, CN} -> {ok, CN};
        {teletexString, CN} -> {ok, binary_to_list(CN)};
        CN when is_list(CN) -> {ok, CN};
        CN when is_binary(CN) -> {ok, binary_to_list(CN)}
    end;
extract_cn_from_rdn([_ | Rest]) ->
    extract_cn_from_rdn(Rest).

%% @doc Register user connection in ETS table
%%
%% Stores the mapping between username and WebSocket process PID
%% in the user_connections ETS table for connection tracking and
%% message routing purposes.
%%
%% @param Username The authenticated username
%% @param Pid The WebSocket handler process PID
%% @returns ok (ETS insert always succeeds)
register_user_connection(Username, Pid) ->
    ets:insert(user_connections, {Username, Pid}).

%% @doc Find user connection by username
%%
%% Looks up a user's WebSocket connection PID in the user_connections
%% ETS table to determine if they are currently online and to route
%% messages to them.
%%
%% @param Username The username to look up
%% @returns {ok, Pid} if user is connected, not_found if offline

find_user_connection(Username) ->
    case ets:lookup(user_connections, Username) of
        [{Username, Pid}] -> {ok, Pid};
        [] -> not_found
    end.

%% @doc Clean up user connection when WebSocket terminates
%%
%% Removes the user's connection entry from the ETS table when their
%% WebSocket connection is terminated, ensuring proper cleanup and
%% accurate online status tracking.
%%
%% @param Reason The termination reason (ignored)
%% @param Req The Cowboy request object (ignored)
%% @param State The WebSocket state containing username information
%% @returns ok
terminate(_Reason, _Req, #{username := Username}) ->
    ets:delete(user_connections, Username),
    ?info("User ~s disconnected and removed from connection table", [Username]),
    ok;
terminate(_Reason, _Req, _State) ->
    ok.
