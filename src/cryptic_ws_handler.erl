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

-include("cryptic_server.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    init/2,
    websocket_init/1,
    websocket_handle/2,
    websocket_info/2,
    terminate/3,
    % Double Ratchet integration functions
    create_conversation_id/2,
    store_ratchet_state/2,
    get_ratchet_state/1,
    update_ratchet_state/2
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
    WelcomeJson = jsx:encode(WelcomeMsg),
    ?msg_out("Sending welcome message to ~s: ~s", [Username, WelcomeJson]),
    {[{text, WelcomeJson}], State}.

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
        ?debug("Received message from ~s: ~s", [Username, Msg]),
        ?msg_in("Received WebSocket message from ~s: ~s", [Username, Msg]),

        %% 1. Decode JSON
        case jsx:decode(Msg, [return_maps]) of
            DecodedMessage when is_map(DecodedMessage) ->
                %% 2. Verify message follows cryptic_messages module definitions
                case cryptic_messages:validate_message(DecodedMessage) of
                    {ok, ValidatedMessage} ->
                        %% Log message type for debugging
                        MessageType = maps:get(
                            <<"type">>, ValidatedMessage, <<"unknown">>
                        ),
                        ?debug(
                            "Processing validated message from: ~s , type: ~s",
                            [
                                Username, MessageType
                            ]
                        ),

                        %% 3. Process valid message with command handler
                        case
                            handle_command(ValidatedMessage, Username, State)
                        of
                            {reply, Response} ->
                                ResponseJson = jsx:encode(Response),
                                ?msg_out(
                                    "Sending WebSocket response to ~s: ~s", [
                                        Username, ResponseJson
                                    ]
                                ),
                                {[{text, ResponseJson}], State};
                            {reply, Response, NewState} ->
                                ResponseJson = jsx:encode(Response),
                                ?msg_out(
                                    "Sending WebSocket response to ~s: ~s", [
                                        Username, ResponseJson
                                    ]
                                ),
                                {[{text, ResponseJson}], NewState};
                            {noreply, NewState} ->
                                {[], NewState};
                            {error, ErrorMsg} ->
                                ErrorResp = #{
                                    type => <<"error">>,
                                    message => list_to_binary(ErrorMsg)
                                },
                                ErrorJson = jsx:encode(ErrorResp),
                                ?debug("Sending WebSocket error to ~s: ~s", [
                                    Username, ErrorJson
                                ]),
                                ?msg_out("Sending WebSocket error to ~s: ~s", [
                                    Username, ErrorJson
                                ]),
                                {[{text, ErrorJson}], State}
                        end;
                    {error, ValidationError} ->
                        %% 4. Drop invalid message and log the fact
                        ?warning(
                            "Message validation failed from ~s: ~p, Original: ~s",
                            [Username, ValidationError, Msg]
                        ),
                        ValidationErrorResp = #{
                            type => <<"error">>,
                            message => <<"Invalid message format">>
                        },
                        ValidationErrorJson = jsx:encode(ValidationErrorResp),
                        ?msg_out("Sending validation error to ~s: ~s", [
                            Username, ValidationErrorJson
                        ]),
                        {[{text, ValidationErrorJson}], State}
                end;
            _ ->
                %% JSON decode failed
                ?warning("Invalid JSON format from ~s: ~s", [Username, Msg]),
                JsonErrorResp = #{
                    type => <<"error">>,
                    message => <<"Invalid JSON format">>
                },
                JsonErrorJson = jsx:encode(JsonErrorResp),
                ?msg_out("Sending JSON error to ~s: ~s", [
                    Username, JsonErrorJson
                ]),
                {[{text, JsonErrorJson}], State}
        end
    catch
        _Error:Reason ->
            ?error(
                "Failed to handle incoming text frame from ~s; Reason: ~p~n", [
                    Username, Reason
                ]
            ),
            CatchErrorResponse = #{
                type => <<"error">>,
                message => <<"Message processing failed">>
            },
            CatchErrorJson = jsx:encode(CatchErrorResponse),
            ?msg_out("Sending error response: ~s", [CatchErrorJson]),
            {[{text, CatchErrorJson}], State}
    end;
websocket_handle({binary, _Data}, State) ->
    %% Handle binary data if needed
    ?warning("Incoming binary frame, NYI!", []),
    {[], State};
%% Handle WebSocket ping frames
websocket_handle(ping, State) ->
    ?msg_in("Received WebSocket ping", []),
    %% Respond with pong
    ?msg_out("Sending WebSocket pong", []),
    {[pong], State};
%% Handle WebSocket pong frames
websocket_handle(pong, State) ->
    ?msg_in("Received WebSocket pong", []),
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
    %% Regular message or X3DH message - forward as-is
    Response = #{
        type => <<"message">>,
        from => FromUser,
        to => Username,
        message => Message
    },
    ResponseJson = jsx:encode(Response),
    ?msg_out("Forwarding message from ~s to ~s: ~s", [
        FromUser, Username, ResponseJson
    ]),
    {[{text, ResponseJson}], State};
websocket_info({send_message, RoomMessage}, State) ->
    %% Handle room message forwarding from broadcast_to_room_members
    ?debug("DEBUG WS: Received send_message: ~p", [RoomMessage]),
    JsonResponse = jsx:encode(RoomMessage),
    ?debug("DEBUG WS: Forwarding room message: ~p", [JsonResponse]),
    ?msg_out("Forwarding room message: ~s", [JsonResponse]),
    {[{text, JsonResponse}], State};
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
%% Handle key bundle upload (Step 1 implementation)
handle_command(
    #{
        <<"type">> := <<"upload_key_bundle">>,
        <<"identity_public">> := IdentityPubB64,
        <<"signed_prekey_public">> := SignedPrekeyPubB64,
        <<"signed_prekey_signature">> := SignatureB64,
        <<"one_time_prekeys">> := OtpkListB64,
        <<"key_id">> := KeyIdB64
    },
    Username,
    _State
) ->
    try
        %% Decode all the key components
        IdentityPub = base64:decode(IdentityPubB64),
        SignedPrekeyPub = base64:decode(SignedPrekeyPubB64),
        Signature = base64:decode(SignatureB64),
        KeyId = base64:decode(KeyIdB64),

        %% Decode one-time prekeys
        OtpkList = lists:map(
            fun(#{<<"id">> := IdB64, <<"public">> := PubB64}) ->
                #{
                    id => base64:decode(IdB64),
                    public => base64:decode(PubB64)
                }
            end,
            OtpkListB64
        ),

        %% Verify the signed prekey signature
        case
            cryptic_lib:verify_signature(
                SignedPrekeyPub, Signature, IdentityPub
            )
        of
            false ->
                {error, "Invalid signed prekey signature"};
            true ->
                %% Create the key bundle
                KeyBundle = #{
                    identity_sign_public => IdentityPub,
                    signed_prekey_public => SignedPrekeyPub,
                    signed_prekey_signature => Signature,
                    one_time_prekeys => OtpkList,
                    key_id => KeyId
                },

                %% Store the key bundle
                case cryptic_lib:store_key_bundle(Username, KeyBundle) of
                    ok ->
                        {reply, #{
                            type => <<"success">>,
                            message => <<"Key bundle uploaded successfully">>
                        }};
                    {error, Reason} ->
                        {error,
                            io_lib:format("Failed to store key bundle: ~p", [
                                Reason
                            ])}
                end
        end
    catch
        _:Error ->
            {error, io_lib:format("Invalid key bundle format: ~p", [Error])}
    end;
%% Handle identity keys upload (new 5-step authentication flow)
handle_command(
    #{
        <<"type">> := <<"upload_identity_keys">>,
        <<"identity_sign_public">> := IdentitySignPubB64,
        <<"identity_dh_public">> := IdentityDHPubB64,
        <<"signed_prekey_public">> := SignedPrekeyPubB64,
        <<"signed_prekey_signature">> := SignatureB64
    },
    Username,
    _State
) ->
    try
        %% Decode the identity key components
        IdentitySignPub = base64:decode(IdentitySignPubB64),
        IdentityDHPub = base64:decode(IdentityDHPubB64),
        SignedPrekeyPub = base64:decode(SignedPrekeyPubB64),
        Signature = base64:decode(SignatureB64),

        %% Create identity key record
        IdentityKeys = #{
            username => Username,
            identity_sign_public => IdentitySignPub,
            identity_dh_public => IdentityDHPub,
            signed_prekey_public => SignedPrekeyPub,
            signed_prekey_signature => Signature,
            timestamp => erlang:system_time(second)
        },

        %% Store the identity keys
        case cryptic_lib:store_identity_keys(Username, IdentityKeys) of
            ok ->
                {reply, #{
                    type => <<"success">>,
                    message => <<"Identity keys uploaded successfully">>
                }};
            {error, Reason} ->
                {error,
                    io_lib:format("Failed to store identity keys: ~p", [Reason])}
        end
    catch
        _:Error ->
            {error, io_lib:format("Invalid identity keys format: ~p", [Error])}
    end;
%% Handle prekey bundle upload (Step 5 of new authentication flow)
handle_command(
    #{
        <<"type">> := <<"upload_prekey_bundle">>,
        <<"one_time_prekeys">> := OtpkListJson
    },
    Username,
    _State
) ->
    try
        %% Decode one-time prekeys
        OtpkList = lists:map(
            fun(#{<<"id">> := IdB64, <<"public_key">> := PubB64}) ->
                #{
                    id => base64:decode(IdB64),
                    public => base64:decode(PubB64)
                }
            end,
            OtpkListJson
        ),

        %% Store the prekey bundle
        case cryptic_lib:store_prekey_bundle(Username, OtpkList) of
            ok ->
                {reply, #{
                    type => <<"success">>,
                    message => iolist_to_binary(
                        io_lib:format(
                            "Prekey bundle uploaded: ~p one-time keys", [
                                length(OtpkList)
                            ]
                        )
                    )
                }};
            {error, Reason} ->
                {error,
                    io_lib:format("Failed to store prekey bundle: ~p", [Reason])}
        end
    catch
        _:Error ->
            {error, io_lib:format("Invalid prekey bundle format: ~p", [Error])}
    end;
%% Get key bundle for X3DH (Step 1 implementation)
handle_command(
    #{<<"type">> := <<"get_key_bundle">>, <<"user">> := UserB},
    _Username,
    _State
) ->
    User = binary_to_list(UserB),
    ?debug("get_key_bundle request for user: ~p", [User]),
    case cryptic_lib:get_key_bundle(User) of
        {error, not_found} ->
            ?debug("Key bundle not found for user: ~p", [User]),
            {error, "key-bundle-not-found"};
        {ok, BundleData} ->
            ?debug(
                "Found key bundle for user: ~p, bundle keys: ~p", [
                    User, maps:keys(BundleData)
                ]
            ),
            #{
                identity_sign_public := IdentitySignPub,
                identity_dh_public := IdentityDHPub,
                signed_prekey := #{
                    public := SignedPrekeyPub,
                    signature := Signature
                },
                one_time_prekeys := OtpkList,
                key_id := KeyId
            } = BundleData,

            %% Select and mark one OTPK as consumed (if available)
            {SelectedOtpk, RemainingOtpks} =
                case OtpkList of
                    [] ->
                        {null, []};
                    [FirstOtpk | RestOtpks] ->
                        %% Mark this OTPK as consumed
                        #{id := FirstOtpkId} = FirstOtpk,
                        cryptic_lib:mark_otpk_consumed(User, FirstOtpkId),
                        {FirstOtpk, RestOtpks}
                end,

            %% Prepare response with both identity keys
            ?debug(
                "Sending both identity keys - Sign: ~p, DH: ~p", [
                    IdentitySignPub, IdentityDHPub
                ]
            ),
            Response = #{
                type => <<"key_bundle">>,
                user => UserB,
                key_id => base64:encode(KeyId),
                identity_sign_public => base64:encode(IdentitySignPub),
                identity_dh_public => base64:encode(IdentityDHPub),
                signed_prekey => base64:encode(SignedPrekeyPub),
                signed_prekey_signature => base64:encode(Signature),
                one_time_prekey =>
                    case SelectedOtpk of
                        null ->
                            null;
                        #{id := OtpkIdResp, public := OtpkPubResp} ->
                            #{
                                id => base64:encode(OtpkIdResp),
                                public => base64:encode(OtpkPubResp)
                            }
                    end,
                remaining_otpks => length(RemainingOtpks)
            },
            {reply, Response}
    end;
%% Handle unified encrypted messages (both X3DH and Double Ratchet)
handle_command(
    #{
        <<"type">> := <<"send_encrypted">>,
        <<"to">> := ToUserB,
        <<"message">> := MessagePayload
    },
    Username,
    _State
) ->
    ToUser = binary_to_list(ToUserB),

    %% Forward the encrypted message payload to recipient
    %% Server acts as pure relay without understanding the content
    MessageForward = #{
        type => <<"encrypted_message_received">>,
        from => list_to_binary(Username),
        message => MessagePayload,
        server_timestamp => erlang:system_time(second)
    },

    %% Try to deliver immediately if user is online
    case find_user_connection(ToUser) of
        {ok, Pid} ->
            %% User is online - deliver immediately without storing
            Pid ! {message, Username, MessageForward};
        not_found ->
            %% User is offline - store message for later retrieval
            cryptic_lib:store_message(ToUser, MessageForward)
    end,

    {reply, #{
        type => <<"message_sent">>,
        success => true,
        to => ToUserB,
        timestamp => erlang:system_time(second)
    }};
%% Handle X3DH protocol messages (SESSION-MESSAGE-FLOW.md implementation)
handle_command(
    #{
        <<"type">> := <<"x3dh">>,
        <<"from">> := FromUserB,
        <<"to">> := ToUserB,
        <<"message_id">> := MessageIdB64,
        <<"ephemeral_public">> := EphemeralPubB64,
        <<"otpk_id">> := OtpkIdB64,
        <<"ciphertext">> := CiphertextB64,
        <<"nonce">> := NonceB64,
        <<"signature">> := SignatureB64,
        <<"metadata">> := MetadataB64
    },
    Username,
    _State
) ->
    %% Validate that the 'from' field matches the authenticated user
    case binary_to_list(FromUserB) of
        Username ->
            ToUser = binary_to_list(ToUserB),

            %% Create X3DH message blob with complete metadata
            MessageBlob = #{
                from => Username,
                to => ToUser,
                message_type => <<"x3dh">>,
                message_id => MessageIdB64,
                ephemeral_public => EphemeralPubB64,
                otpk_id => OtpkIdB64,
                ciphertext => CiphertextB64,
                nonce => NonceB64,
                signature => SignatureB64,
                metadata => MetadataB64,
                server_timestamp => erlang:system_time(second)
            },

            %% Try to deliver immediately if user is online
            case find_user_connection(ToUser) of
                {ok, Pid} ->
                    %% User is online - deliver immediately without storing
                    Pid ! {message, Username, MessageBlob};
                not_found ->
                    %% User is offline - store message for later retrieval
                    cryptic_lib:store_message(ToUser, MessageBlob)
            end,

            {reply, #{
                type => <<"message_sent">>,
                success => true,
                message => <<"X3DH message sent">>
            }};
        _OtherUser ->
            %% The 'from' field doesn't match the authenticated user
            {reply, #{
                type => <<"error">>,
                success => false,
                message =>
                    <<"Authentication error: 'from' field doesn't match authenticated user">>
            }}
    end;
%% Handle Double Ratchet protocol messages (efficient ongoing messaging after X3DH)
handle_command(
    #{
        <<"type">> := <<"ratchet">>,
        <<"from">> := FromUserB,
        <<"to">> := ToUserB
    } = RatchetMessage,
    Username,
    _State
) ->
    %% Validate that the 'from' field matches the authenticated user
    case binary_to_list(FromUserB) of
        Username ->
            ToUser = binary_to_list(ToUserB),

            %% Add server metadata to the message
            MessageBlob = RatchetMessage#{
                <<"message_type">> => <<"ratchet">>,
                <<"server_timestamp">> => erlang:system_time(second)
            },

            %% Try to deliver immediately if user is online
            case find_user_connection(ToUser) of
                {ok, Pid} ->
                    %% User is online - deliver immediately without storing
                    Pid ! {message, Username, MessageBlob};
                not_found ->
                    %% User is offline - store message for later retrieval
                    cryptic_lib:store_message(ToUser, MessageBlob)
            end,

            {reply, #{
                type => <<"message_sent">>,
                success => true,
                message => <<"Double Ratchet message sent">>
            }};
        _OtherUser ->
            %% The 'from' field doesn't match the authenticated user
            {reply, #{
                type => <<"error">>,
                success => false,
                message =>
                    <<"Authentication error: 'from' field doesn't match authenticated user">>
            }}
    end;
handle_command(#{<<"type">> := <<"get_messages">>}, Username, _State) ->
    Messages = cryptic_lib:get_messages(Username),
    Response = #{
        type => <<"messages">>,
        messages => Messages
    },
    {reply, Response};
%% @doc Handle request for pending messages
%%
%% This command is sent by the client when the cryptic_engine is fully
%% initialized and ready to receive messages. It fetches all pending
%% messages and delivers them via the WebSocket connection.
%%
%% Unlike get_messages which returns a JSON response, this handler
%% directly sends message events to ensure they are processed the same
%% way as real-time messages.
handle_command(
    #{<<"type">> := <<"request_pending_messages">>}, Username, _State
) ->
    %% Fetch pending messages
    PendingMessages = cryptic_lib:get_messages(Username),
    case PendingMessages of
        [] ->
            %% No pending messages - just acknowledge
            ?msg_out("No pending messages for ~s", [Username]),
            Response = #{
                type => <<"pending_messages_delivered">>,
                count => 0
            },
            {reply, Response};
        Messages ->
            ?debug("Delivering pending messages: ~p~n", [Messages]),
            %% Deliver each pending message as a message event
            %% This ensures they go through the same processing as real-time messages
            lists:foreach(
                fun(MessageBlob) ->
                    %% Extract sender from message blob
                    From = maps:get(<<"from">>, MessageBlob),

                    %% Send to self - this will be processed by handle_info
                    self() ! {message, From, MessageBlob}
                end,
                Messages
            ),

            %% Log delivery
            ?msg_out("Queued ~p pending messages for delivery to ~s", [
                length(Messages), Username
            ]),

            %% Acknowledge that messages are being delivered
            Response = #{
                type => <<"pending_messages_delivered">>,
                count => length(Messages)
            },
            {reply, Response}
    end;
handle_command(#{<<"type">> := <<"list_users">>}, _Username, _State) ->
    Users = cryptic_lib:list_users(),
    Response = #{
        type => <<"users">>,
        users => [list_to_binary(U) || U <- Users]
    },
    {reply, Response};
handle_command(#{<<"type">> := <<"key_status">>}, Username, _State) ->
    case cryptic_lib:get_key_status(Username) of
        {ok, KeyStatus} ->
            Response = #{
                type => <<"key_status">>,
                status => KeyStatus
            },
            {reply, Response};
        {error, not_found} ->
            Response = #{
                type => <<"key_status">>,
                error => <<"No keys found for user">>,
                status => #{
                    username => list_to_binary(Username),
                    has_identity_keys => false,
                    has_signed_prekey => false,
                    otpk_count => 0
                }
            },
            {reply, Response}
    end;
handle_command(Command, Username, _State) ->
    ?debug("Unknown command from ~s: ~p", [Username, Command]),
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

%% @doc Create a unique conversation identifier for two users
%%
%% Creates a deterministic conversation ID that is the same regardless
%% of which user creates it (Alice-Bob = Bob-Alice).
%%
%% @param User1 First user in the conversation
%% @param User2 Second user in the conversation
%% @returns Unique conversation ID string
create_conversation_id(User1, User2) ->
    %% Sort users to ensure consistent ID regardless of order
    SortedUsers = lists:sort([User1, User2]),
    string:join(SortedUsers, "-").

%% @doc Store Double Ratchet state for a conversation
%%
%% Persists the ratchet state to storage for later retrieval.
%%
%% @param ConversationId Unique conversation identifier
%% @param RatchetState Double Ratchet state record
%% @returns ok | {error, Reason}
store_ratchet_state(ConversationId, RatchetState) ->
    %% Serialize the ratchet state
    SerializedState = cryptic_double_ratchet:serialize_state(RatchetState),

    %% Store in chat storage (extending existing storage system)
    cryptic_chat_storage:store_ratchet_state(ConversationId, SerializedState).

%% @doc Retrieve Double Ratchet state for a conversation
%%
%% Loads the ratchet state from storage.
%%
%% @param ConversationId Unique conversation identifier
%% @returns {ok, RatchetState} | {error, not_found}
get_ratchet_state(ConversationId) ->
    case cryptic_chat_storage:get_ratchet_state(ConversationId) of
        {ok, SerializedState} ->
            cryptic_double_ratchet:deserialize_state(SerializedState);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Update Double Ratchet state for a conversation
%%
%% Updates the stored ratchet state after message processing.
%%
%% @param ConversationId Unique conversation identifier
%% @param NewRatchetState Updated ratchet state
%% @returns ok | {error, Reason}
update_ratchet_state(ConversationId, NewRatchetState) ->
    store_ratchet_state(ConversationId, NewRatchetState).

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

%% @doc Register user connection
%%
%% Called when a user successfully establishes a WebSocket connection
%% to register their connection PID in the user_connections ETS table.
%%
%% Pending messages are NOT sent here - the client must explicitly
%% request them when ready via request_pending_messages command.
%% This avoids race conditions where messages are sent before the
%% client's cryptic_engine is fully initialized.
%%
%% @param Username The authenticated username
%% @param Pid The WebSocket handler process PID
%% @returns ok (ETS insert always succeeds)
register_user_connection(Username, Pid) ->
    %% Register the connection
    ets:insert(user_connections, {Username, Pid}),
    ?msg_out(
        "Registered connection for ~s (pending messages available on request)",
        [Username]
    ),
    ok.

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
