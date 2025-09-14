-module(cryptic_ws_handler).
-behaviour(cowboy_websocket).

-include("cryptic.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([init/2, websocket_init/1, websocket_handle/2, websocket_info/2, terminate/3]).

%% HTTP to WebSocket upgrade
init(Req, State) ->
    %% Extract client certificate information during handshake
    case get_client_identity(Req) of
        {ok, Username} ->
            ?info("Client ~s authenticated via certificate", [Username]),
            {cowboy_websocket, Req, #{username => Username}};
        {error, Reason} ->
            ?error("Client certificate authentication failed: ~p", [Reason]),
            {ok, cowboy_req:reply(401, #{}, <<"Client certificate required">>, Req), State}
    end.

%% WebSocket initialization
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

%% Handle incoming WebSocket messages
websocket_handle({text, Msg}, State = #{username := Username}) ->
    try
        Command = jsx:decode(Msg, [return_maps]),
        case handle_command(Command, Username, State) of
            {reply, Response} ->
                {[{text, jsx:encode(Response)}], State};
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
        _:_Error ->
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

%% Handle Erlang messages sent to this process
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

%% Handle WebSocket commands
handle_command(#{<<"type">> := <<"upload_prekey">>, <<"prekey">> := PrekeyB64}, Username, _State) ->
    try
        Prekey = base64:decode(PrekeyB64),
        case cryptic_lib:store_prekey(Username, Prekey) of
            ok ->
                {reply, #{type => <<"success">>, message => <<"Prekey uploaded">>}};
            {error, Reason} ->
                {error, io_lib:format("Failed to store prekey: ~p", [Reason])}
        end
    catch
        _:_ ->
            {error, "Invalid prekey format"}
    end;

handle_command(#{<<"type">> := <<"get_prekey">>, <<"user">> := UserB}, _Username, _State) ->
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

handle_command(#{<<"type">> := <<"send_message">>, <<"to">> := ToUserB, 
                 <<"ephemeral">> := EphB64, <<"nonce">> := NonceB64, 
                 <<"cipher">> := CipherB64}, Username, _State) ->
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
            ok  % Message stored for later retrieval
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

handle_command(Command, Username, _State) ->
    io:format("Unknown command from ~s: ~p~n", [Username, Command]),
    {error, "Unknown command"}.

%% Extract client identity from certificate
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

%% Extract username from X.509 certificate Common Name
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

%% Extract Common Name from certificate subject
extract_common_name({rdnSequence, RDNSeq}) ->
    extract_cn_from_sequence(RDNSeq).

extract_cn_from_sequence([]) ->
    error;
extract_cn_from_sequence([RDN | Rest]) ->
    case extract_cn_from_rdn(RDN) of
        {ok, CN} -> {ok, CN};
        error -> extract_cn_from_sequence(Rest)
    end.

extract_cn_from_rdn([]) ->
    error;
extract_cn_from_rdn([#'AttributeTypeAndValue'{type = ?'id-at-commonName', 
                                             value = Value} | _]) ->
    case Value of
        {utf8String, CN} -> {ok, binary_to_list(CN)};
        {printableString, CN} -> {ok, CN};
        {teletexString, CN} -> {ok, binary_to_list(CN)};
        CN when is_list(CN) -> {ok, CN};
        CN when is_binary(CN) -> {ok, binary_to_list(CN)}
    end;
extract_cn_from_rdn([_ | Rest]) ->
    extract_cn_from_rdn(Rest).

%% Connection management
register_user_connection(Username, Pid) ->
    ets:insert(user_connections, {Username, Pid}).

find_user_connection(Username) ->
    case ets:lookup(user_connections, Username) of
        [{Username, Pid}] -> {ok, Pid};
        [] -> not_found
    end.

%% Clean up user connection when WebSocket terminates
terminate(_Reason, _Req, #{username := Username}) ->
    ets:delete(user_connections, Username),
    ?info("User ~s disconnected and removed from connection table", [Username]),
    ok;
terminate(_Reason, _Req, _State) ->
    ok.
