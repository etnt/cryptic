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
%%%   <li>`upload_identity_keys' - Upload user's identity and signed prekeys</li>
%%%   <li>`upload_prekey_bundle' - Upload one-time prekeys for forward secrecy</li>
%%%   <li>`get_key_bundle' - Request another user's key bundle for X3DH</li>
%%%   <li>`x3dh' - Send X3DH initial key exchange message</li>
%%%   <li>`ratchet' - Send Double Ratchet encrypted message</li>
%%%   <li>`get_messages' - Retrieve stored messages</li>
%%%   <li>`request_pending_messages' - Request delivery of pending messages</li>
%%%   <li>`list_users' - Get list of registered users</li>
%%% </ul>
%%%
%%% == Message Acknowledgment ==
%%%
%%% The server supports reliable message delivery through acknowledgments:
%%% <ul>
%%%   <li>Clients include a unique `message_id' in x3dh and ratchet messages</li>
%%%   <li>Server responds with `message_sent' containing the same `message_id'</li>
%%%   <li>This allows clients to track delivery and retry on network failures</li>
%%%   <li>Messages are delivered immediately to online users or stored for offline users</li>
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
%%% == Process Lifecycle ==
%%%
%%% This module implements the `cowboy_websocket' behavior. Each WebSocket
%%% connection runs in its own Erlang process, created and supervised by
%%% Cowboy/Ranch infrastructure.
%%%
%%% <h4>Connection Flow</h4>
%%%
%%% <ol>
%%%   <li>**HTTP Request** - Client connects and requests WebSocket upgrade
%%%       <ul>
%%%         <li>`init/2' is called in a new process created by Ranch</li>
%%%         <li>Extracts and validates client certificate (mTLS)</li>
%%%         <li>Returns `{cowboy_websocket, Req, State}' to approve upgrade</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>**WebSocket Initialization** - Same process continues
%%%       <ul>
%%%         <li>`websocket_init/1' is called after upgrade completes</li>
%%%         <li>Registers this process Pid in `user_connections' ETS table</li>
%%%         <li>Sends welcome message to client</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>**Active Connection** - Process enters message loop
%%%       <ul>
%%%         <li>`websocket_handle/2' - Handles incoming WebSocket frames (text, binary, ping/pong)</li>
%%%         <li>`websocket_info/2' - Handles Erlang messages from other processes</li>
%%%         <li>Process stays alive until connection closes</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>**Termination** - Connection closes
%%%       <ul>
%%%         <li>`terminate/3' is called</li>
%%%         <li>Removes entry from `user_connections' ETS table</li>
%%%         <li>Process exits</li>
%%%       </ul>
%%%   </li>
%%% </ol>
%%%
%%% <h4>Inter-Process Communication</h4>
%%%
%%% This handler process receives messages from two sources:
%%%
%%% <ul>
%%%   <li>**WebSocket client** - Handled by `websocket_handle/2'
%%%       <ul>
%%%         <li>Text frames containing JSON commands</li>
%%%         <li>Binary frames (currently not used)</li>
%%%         <li>Ping/pong control frames</li>
%%%       </ul>
%%%   </li>
%%%
%%%   <li>**Other Erlang processes** - Handled by `websocket_info/2'
%%%       <ul>
%%%         <li>`{message, FromUser, MessageData}' - Message from another user</li>
%%%         <li>`{send_message, RoomMessage}' - Room broadcast message</li>
%%%       </ul>
%%%   </li>
%%% </ul>
%%%
%%% Message routing example:
%%% <pre>
%%% % Alice sends message to Bob:
%%% 1. Alice's browser sends JSON via WebSocket
%%% 2. Alice's handler process receives in websocket_handle/2
%%% 3. Handler looks up Bob in user_connections ETS: {ok, BobPid}
%%% 4. Handler sends: BobPid ! {message, "Alice", MessageData}
%%% 5. Bob's handler receives in websocket_info/2
%%% 6. Bob's handler sends WebSocket frame to Bob's browser
%%% </pre>
%%%
%%% <h4>State Management</h4>
%%%
%%% The handler maintains minimal state:
%%% <ul>
%%%   <li>`#{username => "alice"}' - Authenticated username from certificate</li>
%%%   <li>All other data stored in ETS tables (cryptic_users, cryptic_messages, etc.)</li>
%%%   <li>No gen_server needed - Cowboy manages the process lifecycle</li>
%%% </ul>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0
%%% @since 2025-09-14

-module(cryptic_ws_handler).
-behaviour(cowboy_websocket).

-include("cryptic_server.hrl").
-include("../include/cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    init/2,
    websocket_init/1,
    websocket_handle/2,
    websocket_info/2,
    terminate/3
]).

%% WebSocket keepalive tuning.
%%
%% The server sends its own ping frames every ?WS_PING_INTERVAL so that
%% half-dead client sockets (e.g. a backgrounded phone) are detected and
%% reaped promptly instead of lingering in the connection table. The
%% idle_timeout must comfortably exceed the ping interval so a healthy
%% connection is never closed between pings.
-define(WS_PING_INTERVAL, 30000).   %% send a ping every 30s
-define(WS_IDLE_TIMEOUT, 75000).    %% close if no frames for 75s

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
    %%  Extract client certificate information during handshake
    %% Note: Certificate revocation/expiration is already checked by the TLS layer
    %% in cryptic_server:verify_peer/4, so by the time we reach this function,
    %% the certificate has already been validated as active and not revoked.
    case get_client_identity(Req) of
        {ok, Username} ->
            ?info("Client ~s authenticated via certificate", [Username]),

            %% Get database reference and peer certificate for admin operations
            {ok, DbRef} = application:get_env(cryptic, ca_db_ref),
            PeerCert = cowboy_req:cert(Req),

            %% Extract GPG fingerprint from certificate for admin permission checks
            {GpgFp, Authenticated} =
                case PeerCert of
                    undefined -> undefined;
                    _ ->
                        case extract_gpg_from_cert_der(PeerCert) of
                            {ok, Fp} ->
                                case cryptic_ca_store:get_gpg_identity(DbRef,Fp)
                                of
                                    {ok, _Identity} ->
                                        ?info("Authenticated with verified GPG"
                                              " fingerprint: ~s", [Fp]),
                                        {Fp, _Authenticated = true};
                                    {error, _} ->
                                        {Fp, _Authenticated=false}
                                end;
                            _ ->
                                {_Fp = undefined, _Authenticated = false}
                        end
                end,

            {cowboy_websocket, Req, #{
                username => Username,
                gpg_fp => GpgFp,
                db_ref => DbRef,
                authenticated => Authenticated,
                peer_cert => PeerCert
            }, #{idle_timeout => ?WS_IDLE_TIMEOUT}};
        {error, Reason} ->
            ?error("Client certificate authentication failed: ~p", [Reason]),
            Reply = cowboy_req:reply(
                401, #{}, <<"Authentication failed">>, Req
            ),
            {ok, Reply, State}
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
    register_user_connection(Username, self()),
    broadcast_user_status(Username, true),
    schedule_ping(),

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
                        MessageType =
                            maps:get(
                                <<"type">>, ValidatedMessage, <<"unknown">>
                            ),
                        ?debug(
                            "Processing validated message from: ~s , type: ~s",
                            [Username, MessageType]
                        ),

                        %% 3. Process valid message with command handler
                        case
                            handle_command(ValidatedMessage, Username, State)
                        of
                            {reply, Response} ->
                                ResponseJson = jsx:encode(Response),
                                ?msg_out(
                                    "Sending WebSocket response to ~s: ~s",
                                    [Username, ResponseJson]
                                ),
                                {[{text, ResponseJson}], State};
                            {reply, Response, NewState} ->
                                ResponseJson = jsx:encode(Response),
                                ?msg_out(
                                    "Sending WebSocket response to ~s: ~s",
                                    [Username, ResponseJson]
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
                                ?debug(
                                    "Sending WebSocket error to ~s: ~s",
                                    [Username, ErrorJson]
                                ),
                                ?msg_out(
                                    "Sending WebSocket error to ~s: ~s",
                                    [Username, ErrorJson]
                                ),
                                {[{text, ErrorJson}], State}
                        end;
                    {error, ValidationError} ->
                        %% 4. Drop invalid message and log the fact
                        ?warning(
                            "Message validation failed from ~s: ~p, "
                            "Original: ~s",
                            [Username, ValidationError, Msg]
                        ),
                        ValidationErrorResp = #{
                            type => <<"error">>,
                            message => <<"Invalid message format">>
                        },
                        ValidationErrorJson = jsx:encode(ValidationErrorResp),
                        ?msg_out(
                            "Sending validation error to ~s: ~s",
                            [Username, ValidationErrorJson]
                        ),
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
                "Failed to handle incoming text frame from ~s; "
                "Reason: ~p~n",
                [Username, Reason]
            ),
            CatchErrorResponse = #{
                type => <<"error">>,
                message => <<"Message processing failed">>
            },
            CatchErrorJson = jsx:encode(CatchErrorResponse),
            ?msg_out("Sending error response: ~s", [CatchErrorJson]),
            {[{text, CatchErrorJson}], State}
    end;
%% Handle binary data - not used!
websocket_handle({binary, _Data}, State) ->
    ?warning("Incoming binary frame, NYI!", []),
    {[], State};
%% Handle WebSocket ping frames
websocket_handle(ping, State) ->
    ?msg_in("Received WebSocket ping", []),
    ?msg_out("Sending WebSocket pong", []),
    {[pong], State};
%% Handle WebSocket pong frames
websocket_handle(pong, State) ->
    ?msg_in("Received WebSocket pong", []),
    %% Just acknowledge, no response needed
    {[], State};
%% Ignore anything else
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
websocket_info({send_text, Data}, State) ->
    %% Generic send - used for broadcasting user_status etc.
    {[{text, Data}], State};
websocket_info(send_ping, State) ->
    %% Server-initiated keepalive - probe the client and reschedule.
    %% A dead socket makes Cowboy fail the send and run terminate/3,
    %% pruning the stale connection instead of leaving it registered.
    schedule_ping(),
    {[ping], State};
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
        case store_identity_keys(Username, IdentityKeys) of
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
        case store_prekey_bundle(Username, OtpkList) of
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
    #{
        <<"type">> := <<"get_key_bundle">>,
        <<"user">> := UserB
    },
    _Username,
    _State
) ->
    User = binary_to_list(UserB),
    ?debug("get_key_bundle request for user: ~p", [User]),

    case get_key_bundle(User) of
        {error, not_found} ->
            ?debug("Key bundle not found for user: ~p", [User]),
            {error, "key-bundle-not-found"};
        {ok, BundleData} ->
            ?debug(
                "Found key bundle for user: ~p, bundle keys: ~p",
                [User, maps:keys(BundleData)]
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
                        mark_otpk_consumed(User, FirstOtpkId),
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
%% Handle X3DH protocol messages
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

            %% Store the message first so it survives until the recipient
            %% acknowledges it, then also push it live if they are online.
            %% Storing unconditionally makes online delivery reliable: a
            %% message pushed to a socket that is dying (backgrounded phone,
            %% network drop) is not lost, because the stored copy remains and
            %% is re-delivered via request_pending_messages until a
            %% message_ack removes it.
            store_message(ToUser, MessageBlob),
            case find_user_connection(ToUser) of
                {ok, Pid} ->
                    Pid ! {message, Username, MessageBlob};
                not_found ->
                    ok
            end,

            {reply, #{
                type => <<"message_sent">>,
                message_id => MessageIdB64,
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
%% Handle Double Ratchet protocol messages
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

            %% Store the message first so it survives until the recipient
            %% acknowledges it, then also push it live if they are online
            %% (see the X3DH handler above for the rationale).
            store_message(ToUser, MessageBlob),
            case find_user_connection(ToUser) of
                {ok, Pid} ->
                    Pid ! {message, Username, MessageBlob};
                not_found ->
                    ok
            end,

            %% Extract message_id if present for acknowledgment
            MessageId = maps:get(<<"message_id">>, RatchetMessage, undefined),
            Response =
                case MessageId of
                    undefined ->
                        #{
                            type => <<"message_sent">>,
                            success => true,
                            message => <<"Double Ratchet message sent">>
                        };
                    _ ->
                        #{
                            type => <<"message_sent">>,
                            message_id => MessageId,
                            success => true,
                            message => <<"Double Ratchet message sent">>
                        }
                end,
            {reply, Response};
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
%% @doc Acknowledge receipt of a delivered message.
%%
%% The recipient sends this after it has successfully decrypted and
%% persisted a message. The server removes the stored copy so it is not
%% re-delivered on reconnect. Until acknowledged, a message stays queued and
%% is re-delivered via request_pending_messages, which is what makes online
%% delivery loss-proof. The `message_id' is the same value the sender put in
%% the x3dh/ratchet blob.
handle_command(
    #{<<"type">> := <<"message_ack">>, <<"message_id">> := MessageId},
    Username,
    _State
) ->
    Removed = cryptic_lib:ack_message(Username, MessageId),
    ?debug(
        "message_ack from ~s for ~s (removed ~p queued cop~s)",
        [Username, MessageId, Removed, case Removed of 1 -> "y"; _ -> "ies" end]
    ),
    {reply, #{
        type => <<"message_ack_ok">>,
        message_id => MessageId,
        removed => Removed
    }};
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
    %% Fetch pending messages (non-draining: they stay queued until the
    %% client acknowledges each one with a message_ack, so a delivery that
    %% never reaches the recipient is retried on the next reconnect).
    PendingMessages = cryptic_lib:get_pending_messages(Username),
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
                    %% Extract sender from message blob. Stored blobs are not
                    %% key-consistent: ratchet blobs use the binary <<"from">>
                    %% key, while X3DH blobs use the atom `from` key. Accept
                    %% either so pending X3DH messages deliver instead of
                    %% crashing the frame with {badkey,<<"from">>}.
                    From =
                        case MessageBlob of
                            #{<<"from">> := F} -> F;
                            #{from := F} -> F
                        end,

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
%% @doc Handle request for online users list
%%
%% Returns a list of currently connected users (usernames only).
%% This command is available to all authenticated users, unlike list_users
%% which is admin-only and includes sensitive information.
handle_command(#{<<"type">> := <<"online_users">>}, _Username, _State) ->
    OnlineUsers = get_online_users(),
    Response = #{
        type => <<"online_users">>,
        users => [list_to_binary(U) || U <- OnlineUsers]
    },
    {reply, Response};
%% Admin commands - require admin privileges
handle_command(#{<<"type">> := <<"list_users">>} = Command, _Username, State) ->
    handle_admin_command(list_users, Command, State);
handle_command(#{<<"type">> := <<"register_user">>} = Command, _Username, State) ->
    handle_admin_command(register_user, Command, State);
handle_command(#{<<"type">> := <<"suspend_user">>} = Command, _Username, State) ->
    handle_admin_command(suspend_user, Command, State);
handle_command(#{<<"type">> := <<"revoke_user">>} = Command, _Username, State) ->
    handle_admin_command(revoke_user, Command, State);
handle_command(#{<<"type">> := <<"reactivate_user">>} = Command, _Username, State) ->
    handle_admin_command(reactivate_user, Command, State);
handle_command(#{<<"type">> := <<"get_user_info">>} = Command, _Username, State) ->
    handle_admin_command(get_user_info, Command, State);
handle_command(#{<<"type">> := <<"list_certificates">>} = Command, _Username, State) ->
    handle_admin_command(list_certificates, Command, State);
handle_command(#{<<"type">> := <<"revoke_certificate">>} = Command, _Username, State) ->
    handle_admin_command(revoke_certificate, Command, State);

handle_command(Command, Username, _State) ->
    ?debug("Unknown command from ~s: ~p", [Username, Command]),
    {error, "Unknown command"}.

%%%===================================================================
%%% Admin Command Handlers
%%%===================================================================

%% @doc Handle admin commands with permission checking
%% Checks if the user has admin privileges before executing the command
handle_admin_command(CommandType, Command, #{gpg_fp := GpgFp, db_ref := DbRef} = State) ->
    case is_admin(GpgFp, DbRef) of
        true ->
            execute_admin_command(CommandType, Command, State);
        false ->
            ?warning("Non-admin user attempted admin command: ~p", [GpgFp]),
            {reply,
             #{type => <<"error">>,
               message => <<"Admin privileges required for this command">>
            }}
    end;
handle_admin_command(_CommandType, _Command, _State) ->
    {reply,
     #{type => <<"error">>,
       message => <<"Valid GPG certificate required for admin commands">>
    }}.

%% @doc Execute admin commands after permission check
execute_admin_command(register_user, #{
    <<"gpg_fp">> := UserGpgFp,
    <<"gpg_pub">> := GpgPub
} = Command, #{gpg_fp := AdminFp, db_ref := DbRef}) ->
    Metadata = maps:get(<<"metadata">>, Command, null),
    
    case cryptic_ca_store:register_user(DbRef, UserGpgFp, GpgPub, AdminFp, Metadata) of
        ok ->
            {reply, #{
                type => <<"user_registered">>,
                gpg_fp => UserGpgFp,
                registered_by => AdminFp
            }};
        {error, Reason} ->
            {reply,
             #{type => <<"error">>,
               message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }}
    end;

%% List users information
execute_admin_command(list_users,
                      #{<<"type">> := <<"list_users">>} = Msg,
                      #{authenticated := true,
                        db_ref := DbRef} = _State) ->
    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            %% Optional filter by status
            FilteredIdentities =
                case maps:get(<<"filter">>, Msg, undefined) of
                    undefined -> Identities;
                    FilterStatus ->
                        lists:filter(
                          fun(#gpg_identity{status = S}) ->
                                  S =:= FilterStatus
                          end,
                          Identities
                         )
                end,

            %% Convert to JSON-friendly format
            Users =
                lists:map(
                  fun(#gpg_identity{
                         gpg_fp = Fp,
                         status = Status,
                         registered_by = RegBy,
                         registered_at = RegAt,
                         last_seen = LastSeen,
                         metadata = Meta
                        }) ->
                          %% Look up username from certificates
                          Username = case get_username_from_gpg_fp(DbRef, Fp) of
                              {ok, Name} -> list_to_binary(Name);
                              {error, not_found} -> <<"unknown">>
                          end,

                          UserMap = #{gpg_fp => Fp,
                                      username => Username,
                                      status => Status,
                                      registered_by => RegBy,
                                      registered_at => RegAt,
                                      last_seen => LastSeen,
                                      online => is_online(Username)
                                     },
                          case Meta of
                              undefined -> UserMap;
                              _ ->
                                  try
                                      MetaMap = jsx:decode(Meta, [return_maps]),
                                      UserMap#{metadata => MetaMap}
                                  catch
                                      _:_ -> UserMap
                                  end
                          end
                  end,
                  FilteredIdentities
                 ),

            SuccessResp = #{type => <<"list_users_response">>,
                            status => <<"success">>,
                            count => length(Users),
                            users => Users
                           },

            {reply, SuccessResp};

        {error, Reason} ->
            ?error("Failed to list users: ~p", [Reason]),

            ErrorResp =
                #{type => <<"list_users_response">>,
                  status => <<"error">>,
                  error => <<"list_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [Reason]))
                 },

            {reply, ErrorResp}
    end;
execute_admin_command(list_users,
                      #{<<"type">> := <<"list_users">>},
                       #{authenticated := false} = _State) ->
    ErrorResp =
        #{type => <<"error">>,
          message => <<"Not authenticated">>
         },
    {reply, ErrorResp};

%% Temporarily suspend a user's access.
execute_admin_command(suspend_user,
                      #{<<"gpg_fp">> := GpgFp} = Msg,
                      #{authenticated := true,
                        gpg_fp := AdminFp,
                        db_ref := DbRef} = _State) ->

    Reason = maps:get(<<"reason">>, Msg, <<"No reason provided">>),
    ?info("Admin ~s suspending user ~s: ~s", [AdminFp, GpgFp, Reason]),

    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"suspended">>) of
        ok ->
            Now = erlang:system_time(second),

            %% Log audit event
            AuditLog =
                #audit_log{
                   timestamp = Now,
                   event_type = <<"user_suspended">>,
                   gpg_fp = GpgFp,
                   invite_id = undefined,
                   details =
                       jsx:encode(
                         #{
                           suspended_by => AdminFp,
                           reason => Reason
                          }),
                   ip_address = undefined
                  },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            SuccessResp =
                #{type => <<"suspend_user_response">>,
                  status => <<"success">>,
                  gpg_fp => GpgFp,
                  new_status => <<"suspended">>,
                  suspended_by => AdminFp,
                  suspended_at => Now
                 },

            {reply, SuccessResp};

        {error, Reason2} ->
            ?error("Failed to suspend user ~s: ~p", [GpgFp, Reason2]),

            ErrorResp =
                #{type => <<"suspend_user_response">>,
                  status => <<"error">>,
                  error => <<"suspension_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [Reason2]))
                 },

            {reply, ErrorResp}
    end;
execute_admin_command(suspend_user,
                      _Msg,
                      #{authenticated := false} = _State) ->

    ErrorResp =
        #{type => <<"error">>,
          message => <<"Not authenticated">>
         },

    {reply, ErrorResp};

%% Permanently revoke a user's access (irreversible).
execute_admin_command(revoke_user,
                      #{<<"gpg_fp">> := GpgFp} = Msg,
                      #{authenticated := true,
                        gpg_fp := AdminFp,
                        db_ref := DbRef} = _State) ->

    Reason = maps:get(<<"reason">>, Msg, <<"No reason provided">>),
    ?info("Admin ~s revoking user ~s: ~s", [AdminFp, GpgFp, Reason]),

    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"revoked">>) of
        ok ->
            Now = erlang:system_time(second),

            %% Log audit event
            AuditLog =
                #audit_log{
                   timestamp = Now,
                   event_type = <<"user_revoked">>,
                   gpg_fp = GpgFp,
                   invite_id = undefined,
                   details =
                       jsx:encode(
                         #{
                           suspended_by => AdminFp,
                           reason => Reason
                          }),
                   ip_address = undefined
                  },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            SuccessResp =
                #{type => <<"revoke_user_response">>,
                  status => <<"success">>,
                  gpg_fp => GpgFp,
                  new_status => <<"revoked">>,
                  suspended_by => AdminFp,
                  suspended_at => Now
                 },

            {reply, SuccessResp};

        {error, Reason2} ->
            ?error("Failed to revoke user ~s: ~p", [GpgFp, Reason2]),

            ErrorResp =
                #{type => <<"revoke_user_response">>,
                  status => <<"error">>,
                  error => <<"refocation_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [Reason2]))
                 },

            {reply, ErrorResp}
    end;
execute_admin_command(revoke_user,
                      _Msg,
                      #{authenticated := false} = _State) ->

    ErrorResp =
        #{type => <<"error">>,
          message => <<"Not authenticated">>
         },

    {reply, ErrorResp};

%% Reactivate a suspended user (does not work for revoked users).
execute_admin_command(reactivate_user,
                      #{<<"gpg_fp">> := GpgFp} = _Msg,
                      #{authenticated := true,
                        gpg_fp := AdminFp,
                        db_ref := DbRef} = _State) ->
    ?info("Admin ~s reactivating user ~s", [AdminFp, GpgFp]),

    %% First check current status
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{status = <<"revoked">>}} ->
            ErrorResp =
                #{type => <<"reactivate_user_response">>,
                  status => <<"error">>,
                  error => <<"cannot_reactivate_revoked">>,
                  message => <<"Revoked users cannot be reactivated. Please register a new GPG key.">>
                 },
            {reply, ErrorResp};

        {ok, #gpg_identity{status = <<"active">>}} ->
            InfoResp =
                #{type => <<"reactivate_user_response">>,
                  status => <<"success">>,
                  gpg_fp => GpgFp,
                  message => <<"User already active">>
                 },
            {reply, InfoResp};

        {ok, _Identity} ->
            %% User is suspended, reactivate
            case cryptic_ca_store:update_user_status(DbRef,GpgFp,<<"active">>) of
                ok ->
                    Now = erlang:system_time(second),

                    %% Log audit event
                    AuditLog = #audit_log{
                        timestamp = Now,
                        event_type = <<"user_reactivated">>,
                        gpg_fp = GpgFp,
                        invite_id = undefined,
                        details = jsx:encode(#{
                            reactivated_by => AdminFp
                        }),
                        ip_address = undefined
                    },
                    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

                    SuccessResp =
                        #{type => <<"reactivate_user_response">>,
                          status => <<"success">>,
                          gpg_fp => GpgFp,
                          new_status => <<"active">>,
                          reactivated_by => AdminFp,
                          reactivated_at => Now
                         },
                    {reply, SuccessResp};

                {error, Reason} ->
                    ?error("Failed to reactivate user ~s: ~p", [GpgFp, Reason]),
                    ErrorResp =
                        #{type => <<"reactivate_user_response">>,
                          status => <<"error">>,
                          error => <<"reactivation_failed">>,
                          message => iolist_to_binary(io_lib:format("~p", [Reason]))
                         },
                    {reply, ErrorResp}
            end;

        {error, not_found} ->
            ErrorResp =
                #{type => <<"reactivate_user_response">>,
                  status => <<"error">>,
                  error => <<"user_not_found">>,
                  message => <<"GPG fingerprint not registered">>
                 },
            {reply, ErrorResp};

        {error, Reason} ->
            ?error("Failed to get user info for ~s: ~p", [GpgFp, Reason]),
            ErrorResp =
                #{type => <<"reactivate_user_response">>,
                  status => <<"error">>,
                  error => <<"query_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [Reason]))
                 },
            {reply, ErrorResp}
    end;
execute_admin_command(reactivate_user,
                      _Msg,
                      #{authenticated := false} = _State) ->

    ErrorResp =
        #{type => <<"error">>,
          message => <<"Not authenticated">>
         },

    {reply, ErrorResp};

execute_admin_command(get_user_info,
                      #{<<"gpg_fp">> := GpgFp},
                      #{authenticated := true,
                        db_ref := DbRef}) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{
                status = Status,
                registered_by = RegBy,
                registered_at = RegAt,
                last_seen = LastSeen,
                metadata = Meta
               }} ->
            UserInfo = #{gpg_fp => GpgFp,
                         status => Status,
                         registered_by => RegBy,
                         registered_at => RegAt,
                         last_seen => LastSeen
                        },

            UserInfoWithMeta =
                case Meta of
                    undefined -> UserInfo;
                    _ ->
                        try
                            MetaMap = jsx:decode(Meta, [return_maps]),
                            UserInfo#{metadata => MetaMap}
                        catch
                            _:_ -> UserInfo
                        end
                end,

            SuccessResp =
                #{type => <<"get_user_info_response">>,
                  status => <<"success">>,
                  user => UserInfoWithMeta
                 },

            {reply, SuccessResp};

        {error, not_found} ->
            ErrorResp =
                #{type => <<"get_user_info_response">>,
                  status => <<"error">>,
                  error => <<"user_not_found">>,
                  message => <<"GPG fingerprint not registered">>
                 },

            {reply, ErrorResp};

        {error, Reason} ->
            ?error("Failed to get user info for ~s: ~p", [GpgFp, Reason]),

            ErrorResp =
                #{type => <<"get_user_info_response">>,
                  status => <<"error">>,
                  error => <<"query_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [Reason]))
                 },

            {reply, ErrorResp}
    end;
execute_admin_command(get_user_info,
                      _Command,
                      #{authenticated := false}) ->
    ErrorResp =
        #{type => <<"error">>,
          message => <<"Not GPG authenticated">>
         },

    {reply, ErrorResp};

execute_admin_command(list_certificates,
                      #{<<"gpg_fp">> := GpgFp},
                      #{authenticated := true,
                        db_ref := DbRef}) ->
    %% List all certificates for the user
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, Certs} ->
            CertList =
                lists:map(
                  fun(Cert) ->
                          #{serial => Cert#certificate.serial,
                            issued_at => Cert#certificate.issued_at,
                            expires_at => Cert#certificate.expires_at,
                            status => Cert#certificate.status,
                            revoked_at => Cert#certificate.revoked_at,
                            revoked_by => Cert#certificate.revoked_by,
                            revoked_reason => Cert#certificate.revoked_reason
                           }
                  end, Certs),

            Resp = #{type => <<"list_certificates_response">>,
                     status => <<"success">>,
                     gpg_fp => GpgFp,
                     certificates => CertList,
                     count => length(Certs)
                    },

            {reply, Resp};

        {error, ErrorReason} ->
            ?error("Failed to list certificates for ~s: ~p", [GpgFp, ErrorReason]),

            ErrorResp =
                #{type => <<"list_certificates_response">>,
                  status => <<"error">>,
                  error => <<"list_failed">>,
                  message => iolist_to_binary(io_lib:format("~p", [ErrorReason]))
                 },

            {reply, ErrorResp}

    end;
execute_admin_command(list_certificates,
                      _Command,
                      #{authenticated := false}) ->
    ErrorResp =
        #{type => <<"error">>,
          message => <<"Admin authentication required">>
         },

    {reply, ErrorResp};

execute_admin_command(revoke_certificate,
                      #{<<"serial">> := Serial,
                        <<"reason">> := Reason},
                      #{authenticated := true,
                        gpg_fp := AdminFp,
                        db_ref := DbRef}) ->
    %% Revoke the certificate
    case cryptic_ca_store:revoke_certificate(DbRef, Serial, AdminFp, Reason) of
        ok ->
            ?info("Admin ~s revoked certificate ~s: ~s", [AdminFp, Serial, Reason]),

            Resp = #{
                type => <<"revoke_certificate_response">>,
                status => <<"success">>,
                message => <<"Certificate revoked successfully">>,
                serial => Serial,
                reason => Reason
            },
            {reply, Resp};

        {error, ErrorReason} ->
            ?error("Failed to revoke certificate ~s: ~p", [Serial, ErrorReason]),
            ErrorResp = #{
                type => <<"revoke_certificate_response">>,
                status => <<"error">>,
                error => <<"revoke_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [ErrorReason]))
            },
            {reply, ErrorResp}
    end;
execute_admin_command(revoke_certificate,
                      _Command,
                      #{authenticated := false}) ->
    ErrorResp =
        #{type => <<"error">>,
          message => <<"Admin authentication required">>
         },

    {reply, ErrorResp};

execute_admin_command(CommandType, _Command, _State) ->
    {reply, #{
        error => <<"not_implemented">>,
        message => iolist_to_binary(io_lib:format("Admin command ~p not yet implemented", [CommandType]))
    }}.

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

%% @doc Extract username from X.509 certificate
%%
%% Decodes an X.509 certificate and extracts the username for authentication.
%% Username extraction follows this priority order:
%%
%% 1. **Subject Alternative Name (SAN)** - Looks for `otherName' with OID 1.3.6.1.4.1.99999.1
%%    (Cryptic username extension). This is the recommended approach for production.
%%
%% 2. **Common Name (CN)** - Falls back to CN field from subject DN. This provides
%%    backward compatibility with simple lab certificates.
%%
%% == Production Certificate Generation ==
%%
%% To generate certificates with Cryptic username in SAN:
%%
%% <pre>
%% # In openssl.cnf, add:
%% [cryptic_client]
%% subjectAltName = otherName:1.3.6.1.4.1.99999.1;UTF8:alice
%%
%% # Or using command line:
%% openssl req -new -key client.key -out client.csr -subj "/CN=user123" \
%%   -addext "subjectAltName=otherName:1.3.6.1.4.1.99999.1;UTF8:alice"
%% </pre>
%%
%% This allows CN to be an employee ID, certificate serial, or any identifier,
%% while the actual Cryptic username is in the SAN extension.
%%
%% @param CertDER The DER-encoded X.509 certificate binary
%% @returns {ok, Username} if username is found (SAN or CN),
%%          {error, Reason} if certificate is invalid or no username found
extract_username_from_cert(CertDER) ->
    try
        Cert = public_key:pkix_decode_cert(CertDER, otp),
        TBSCert = Cert#'OTPCertificate'.tbsCertificate,

        %% Try to extract from SAN extension first (production)
        case extract_username_from_san(TBSCert) of
            {ok, Username} ->
                ?debug("Username from SAN extension: ~s", [Username]),
                {ok, Username};
            not_found ->
                %% Fall back to Common Name (lab/legacy)
                Subject = TBSCert#'OTPTBSCertificate'.subject,
                case extract_common_name(Subject) of
                    {ok, CN} ->
                        ?debug("Username from CN field: ~s", [CN]),
                        {ok, CN};
                    error ->
                        {error, no_username_in_cert}
                end
        end
    catch
        _:Error ->
            {error, {cert_decode_error, Error}}
    end.

%% @doc Extract Cryptic username from Subject Alternative Name extension
%%
%% Searches the certificate extensions for a Subject Alternative Name (SAN)
%% with a Cryptic-specific OID containing the username. This is the preferred
%% method for production environments where the CN might be used for other
%% purposes (employee ID, etc.).
%%
%% The Cryptic username OID is: 1.3.6.1.4.1.99999.1
%% (Private Enterprise Number space - replace 99999 with your organization's PEN)
%%
%% @param TBSCert The TBS (To Be Signed) certificate structure
%% @returns {ok, Username} if Cryptic username found in SAN,
%%          not_found if no SAN extension or no Cryptic username present
extract_username_from_san(TBSCert) ->
    case TBSCert#'OTPTBSCertificate'.extensions of
        asn1_NOVALUE ->
            not_found;
        Extensions ->
            %% Look for Subject Alternative Name extension
            case
                lists:keyfind(
                    ?'id-ce-subjectAltName', #'Extension'.extnID, Extensions
                )
            of
                false ->
                    not_found;
                #'Extension'{extnValue = SANValue} ->
                    %% When decoded with otp option, SANValue is already a list of GeneralNames
                    %% not DER-encoded binary
                    case SANValue of
                        GeneralNames when is_list(GeneralNames) ->
                            ?debug("SAN GeneralNames: ~p", [GeneralNames]),
                            extract_cryptic_username_from_san(GeneralNames);
                        _ ->
                            not_found
                    end
            end
    end.

%% @doc Extract Cryptic username from GeneralNames list
%%
%% Searches through the SAN GeneralNames for:
%% - otherName with Cryptic-specific OID (1.3.6.1.4.1.99999.1)
%% - rfc822Name (email address) - extracts the local part before @
%% - dNSName - if it looks like a username (no dots)
%%
%% @param GeneralNames List of GeneralName entries from SAN
%% @returns {ok, Username} if found, not_found otherwise
extract_cryptic_username_from_san([]) ->
    not_found;
extract_cryptic_username_from_san([{otherName, {OID, Value}} | Rest]) ->
    %% Check for Cryptic username OID: 1.3.6.1.4.1.99999.1
    %% You should replace 99999 with your organization's Private Enterprise Number
    case OID of
        {1, 3, 6, 1, 4, 1, 99999, 1} ->
            %% Found Cryptic username extension
            try
                %% Value should be UTF8String
                case Value of
                    {utf8String, Username} when is_binary(Username) ->
                        {ok, binary_to_list(Username)};
                    {utf8String, Username} when is_list(Username) ->
                        {ok, Username};
                    _ ->
                        extract_cryptic_username_from_san(Rest)
                end
            catch
                _:_ ->
                    extract_cryptic_username_from_san(Rest)
            end;
        _ ->
            extract_cryptic_username_from_san(Rest)
    end;
extract_cryptic_username_from_san([{rfc822Name, Email} | Rest]) ->
    %% Try email local part as username (user@domain -> user)
    try
        EmailStr =
            if
                is_binary(Email) -> binary_to_list(Email);
                is_list(Email) -> Email
            end,
        case string:split(EmailStr, "@") of
            [LocalPart, _Domain] ->
                {ok, LocalPart};
            _ ->
                extract_cryptic_username_from_san(Rest)
        end
    catch
        _:_ ->
            extract_cryptic_username_from_san(Rest)
    end;
extract_cryptic_username_from_san([{dNSName, Name} | Rest]) ->
    %% Try DNS name if it looks like a simple username (no dots)
    try
        NameStr =
            if
                is_binary(Name) -> binary_to_list(Name);
                is_list(Name) -> Name
            end,
        case string:find(NameStr, ".") of
            nomatch ->
                %% No dots, might be a username
                {ok, NameStr};
            _ ->
                %% Has dots, probably a real DNS name
                extract_cryptic_username_from_san(Rest)
        end
    catch
        _:_ ->
            extract_cryptic_username_from_san(Rest)
    end;
extract_cryptic_username_from_san([_ | Rest]) ->
    %% Skip other GeneralName types
    extract_cryptic_username_from_san(Rest).

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
    ets:insert(?CONNECTION_TABLE, {Username, Pid}),
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
    case ets:lookup(?CONNECTION_TABLE, Username) of
        [{Username, Pid}] ->
            case is_process_alive(Pid) of
                true -> {ok, Pid};
                false ->
                    %% Stale connection entry - clean it up
                    ets:delete(?CONNECTION_TABLE, Username),
                    ?warning("Cleaned up stale connection for ~s", [Username]),
                    not_found
            end;
        [] -> not_found
    end.

%% @doc Get list of currently online users
%%
%% Returns a list of usernames for all users who currently have
%% an active WebSocket connection. This is used by the online_users
%% command to show which users are available for messaging.
%%
%% @returns List of usernames (as strings)
get_online_users() ->
    AllConnections = ets:tab2list(?CONNECTION_TABLE),
    [Username || {Username, Pid} <- AllConnections, is_process_alive(Pid)].

%% @doc Broadcast user online/offline status to all other connected clients
%%
%% Sends a user_status message to every connected user except the one whose
%% status changed, so all clients can update their UI in real time.
broadcast_user_status(Username, IsOnline) ->
    StatusMsg = jsx:encode(#{
        type => <<"user_status">>,
        username => list_to_binary(Username),
        online => IsOnline
    }),
    AllConnections = ets:tab2list(?CONNECTION_TABLE),
    lists:foreach(
        fun({OtherUser, Pid}) when OtherUser =/= Username ->
                case is_process_alive(Pid) of
                    true -> Pid ! {send_text, StatusMsg};
                    false -> ok
                end;
           (_) ->
                ok
        end,
        AllConnections
    ),
    ok.

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
terminate(Reason, _Req, #{username := Username}) ->
    ets:delete(?CONNECTION_TABLE, Username),
    broadcast_user_status(Username, false),
    ?debug("User ~s disconnected (reason: ~p)~n", [Username, Reason]),
    ok;
terminate(_Reason, _Req, _State) ->
    ok.

%% -------------------------------------------------------------------
%% H E L P E R S
%% -------------------------------------------------------------------

%% @doc Schedule the next server-initiated keepalive ping.
%%
%% Sends a `send_ping' message to this handler process after
%% ?WS_PING_INTERVAL milliseconds, handled in websocket_info/2.
%%
%% @returns Timer reference (ignored)
schedule_ping() ->
    erlang:send_after(?WS_PING_INTERVAL, self(), send_ping).

%% @doc Get username from GPG fingerprint by looking up certificates.
%%
%% Retrieves the most recent certificate for a GPG fingerprint and 
%% extracts the username (CN) from it. This allows mapping from
%% GPG fingerprint to human-readable username.
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint (binary)
%% @returns {ok, Username} if found, {error, not_found} if no certificates
-spec get_username_from_gpg_fp(term(), binary()) -> {ok, string()} | {error, not_found}.
get_username_from_gpg_fp(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, [#certificate{cert_pem = CertPem} | _]} ->
            %% Got at least one certificate, decode PEM and extract username
            try
                %% Decode PEM to DER
                [{'Certificate', CertDER, not_encrypted}] = public_key:pem_decode(CertPem),
                %% Extract username from certificate
                case extract_username_from_cert(CertDER) of
                    {ok, Username} -> {ok, Username};
                    {error, _} -> {error, not_found}
                end
            catch
                _:_ -> {error, not_found}
            end;
        {ok, []} ->
            %% No certificates found
            {error, not_found};
        {error, _} ->
            {error, not_found}
    end.

%% @doc Store identity keys for a user (5-step authentication flow).
%%
%% Stores the user's identity keys including the public identity key,
%% signed prekey, and prekey signature. This is used in the new
%% 5-step authentication flow where identity keys are uploaded separately
%% from one-time prekey bundles.
%%
%% @param Username User ID
%% @param IdentityKeys Map containing identity key components
%% @returns ok or {error, Reason}
-spec store_identity_keys(string(), map()) -> ok | {error, term()}.
store_identity_keys(Username, IdentityKeys) ->
    try
        #{
            identity_sign_public := IdentitySignPub,
            identity_dh_public := IdentityDHPub,
            signed_prekey_public := SignedPrekeyPub,
            signed_prekey_signature := Signature,
            timestamp := Timestamp
        } = IdentityKeys,

        %% Store identity keys with structured tuple key
        IdentityData = #{
            username => Username,
            identity_sign_public => IdentitySignPub,
            identity_dh_public => IdentityDHPub,
            signed_prekey => #{
                public => SignedPrekeyPub,
                signature => Signature,
                timestamp => Timestamp
            },
            created_at => erlang:system_time(second)
        },

        %% Use structured tuple key: {username, identity}
        ets:insert(?PREKEY_TABLE, {{Username, identity}, IdentityData}),
        ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
        ok
    catch
        error:{badkey, Key} ->
            {error, {missing_key, Key}};
        _:Error ->
            {error, Error}
    end.

%% @doc Store prekey bundle (one-time prekeys) for a user.
%%
%% Stores a list of one-time prekeys for forward secrecy. This is used
%% in step 5 of the new authentication flow where prekey bundles are
%% uploaded separately from identity keys.
%%
%% @param Username User ID
%% @param PrekeyList List of prekey maps with id and public key
%% @returns ok or {error, Reason}
-spec store_prekey_bundle(string(), [map()]) -> ok | {error, term()}.
store_prekey_bundle(Username, PrekeyList) ->
    try
        %% Store each one-time prekey individually with structured tuple keys
        lists:foreach(
            fun(#{id := KeyId, public := PubKey}) ->
                %% Use structured tuple key: {username, otpk, key_id}
                KeyTuple = {Username, otpk, KeyId},
                PrekeyData = #{
                    username => Username,
                    key_id => KeyId,
                    public_key => PubKey,
                    consumed => false,
                    created_at => erlang:system_time(second)
                },
                ets:insert(?PREKEY_TABLE, {KeyTuple, PrekeyData})
            end,
            PrekeyList
        ),

        %% Update user record
        ets:insert(?USER_TABLE, {Username, erlang:system_time(second)}),
        ok
    catch
        _:Error ->
            {error, Error}
    end.

%% @doc Get complete key bundle for a user with fresh OTPK list.
%%
%% Retrieves the user's complete key bundle from PREKEY_TABLE structured format.
%% Reconstructs the bundle from identity data and available OTPKs.
%%
%% @param Username User ID
%% @returns {ok, KeyBundle} or {error, not_found}
-spec get_key_bundle(string()) -> {ok, map()} | {error, not_found}.
get_key_bundle(Username) ->
    ?debug("Looking up key bundle for username: ~p", [Username]),

    %% Look for identity entry in PREKEY_TABLE
    case ets:lookup(?PREKEY_TABLE, {Username, identity}) of
        [{{Username, identity}, IdentityData}] ->
            ?debug("Found identity data for ~p", [Username]),
            %% Extract identity data
            #{
                identity_sign_public := IdentitySignPub,
                identity_dh_public := IdentityDHPub,
                signed_prekey := #{
                    public := SignedPrekeyPub,
                    signature := SignedPrekeySignature,
                    timestamp := Timestamp
                }
            } = IdentityData,

            ?debug(
                "get_key_bundle: Retrieved IdentitySignPub: ~p",
                [IdentitySignPub]
            ),
            ?debug(
                "get_key_bundle: Retrieved IdentityDHPub: ~p",
                [IdentityDHPub]
            ),
            ?debug(
                "get_key_bundle: Retrieved SignedPrekeyPub: ~p",
                [SignedPrekeyPub]
            ),
            ?debug(
                "get_key_bundle: Retrieved SignedPrekeySignature: ~p",
                [SignedPrekeySignature]
            ),

            %% key_id might not exist for upload_identity_keys flow
            KeyId = maps:get(
                key_id, IdentityData, crypto:strong_rand_bytes(16)
            ),

            %% Get OTPKs for this user
            AvailableOtpks = get_available_otpks(Username),
            ?debug(
                "Available OTPKs for ~p: ~p",
                [Username, length(AvailableOtpks)]
            ),

            %% Reconstruct bundle in expected format
            ReconstructedBundle = #{
                username => Username,
                key_id => KeyId,
                identity_sign_public => IdentitySignPub,
                identity_dh_public => IdentityDHPub,
                signed_prekey => #{
                    public => SignedPrekeyPub,
                    signature => SignedPrekeySignature,
                    timestamp => Timestamp
                },
                one_time_prekeys => AvailableOtpks,
                created_at => maps:get(
                    created_at, IdentityData, erlang:system_time(second)
                )
            },

            ?debug("Successfully retrieved bundle for ~p", [Username]),
            {ok, ReconstructedBundle};
        [] ->
            ?debug("No key bundle found for username: ~p", [Username]),
            {error, not_found}
    end.

%% @doc Get available one-time prekeys for a user.
%%
%% Retrieves all unconsumed OTPKs for the specified user using
%% structured tuple key matching.
%%
%% @param Username User ID
%% @returns List of available OTPK data maps
-spec get_available_otpks(string()) -> [map()].
get_available_otpks(Username) ->
    %% Use ets:match to find all OTPKs for this user
    Pattern = {{Username, otpk, '_'}, '$1'},
    Matches = ets:match(?PREKEY_TABLE, Pattern),
    [
        #{
            id => maps:get(key_id, PrekeyData),
            public => maps:get(public_key, PrekeyData)
            %% Note: private key not stored on server for security
        }
     || [PrekeyData] <- Matches, not maps:get(consumed, PrekeyData, false)
    ].

%% @doc Mark one-time prekey as consumed to ensure one-time use.
%%
%% Removes the specified OTPK from the user's prekey storage to prevent reuse.
%% Uses the new structured tuple key format for efficient lookup.
%%
%% @param Username User ID
%% @param OtpkId One-time prekey ID to mark as consumed
%% @returns ok | {error, not_found}
-spec mark_otpk_consumed(string(), binary()) -> ok | {error, not_found}.
mark_otpk_consumed(Username, OtpkId) ->
    %% Use structured tuple key for direct lookup
    KeyTuple = {Username, otpk, OtpkId},
    case ets:lookup(?PREKEY_TABLE, KeyTuple) of
        [] ->
            {error, not_found};
        [{KeyTuple, _PrekeyData}] ->
            %% Delete the consumed OTPK
            ets:delete(?PREKEY_TABLE, KeyTuple),
            ok
    end.

%% @doc Store a message for a user.
%%
%% @param Username
%% @param Message (as a Map)
%% @returns ok
-spec store_message(string(), map()) -> ok.
store_message(ToUser, MessageBlob) ->
    MessageId = erlang:unique_integer([positive]),
    ets:insert(?MESSAGE_TABLE, {MessageId, ToUser, MessageBlob}),
    ok.

%%%===================================================================
%%% Admin Permission and GPG Extraction Functions
%%%===================================================================

%% OID constant for certificate extensions
-define(ID_CE_SUBJECT_ALT_NAME, {2, 5, 29, 17}).

%% @doc Extract GPG fingerprint from client certificate DER
-spec extract_gpg_from_cert_der(binary() | undefined) -> {ok, binary()} | {error, term()}.
extract_gpg_from_cert_der(undefined) ->
    {error, no_peer_cert};
extract_gpg_from_cert_der(CertDER) ->
    try
        %% Decode the certificate
        Cert = public_key:pkix_decode_cert(CertDER, otp),
        
        %% Extract extensions
        #'OTPCertificate'{
            tbsCertificate = #'OTPTBSCertificate'{
                extensions = Extensions
            }
        } = Cert,
        
        %% Find the Subject Alternative Name extension
        case find_san_extension(Extensions) of
            {ok, SANValue} ->
                extract_gpg_from_san(SANValue);
            {error, _} = Error ->
                Error
        end
    catch
        _:DecodeReason ->
            {error, {cert_decode_failed, DecodeReason}}
    end.

%% @private Find the SAN extension in the certificate extensions list
-spec find_san_extension([#'Extension'{}]) -> {ok, term()} | {error, not_found}.
find_san_extension([]) ->
    {error, san_not_found};
find_san_extension([#'Extension'{extnID = ?ID_CE_SUBJECT_ALT_NAME, extnValue = Value} | _]) ->
    {ok, Value};
find_san_extension([_ | Rest]) ->
    find_san_extension(Rest).

%% @private Extract GPG fingerprint from SAN value
%% Expected format: [{dNSName, "<fingerprint>.gpg.cryptic.local"}]
-spec extract_gpg_from_san(term()) -> {ok, binary()} | {error, term()}.
extract_gpg_from_san([{dNSName, DNSName} | _]) ->
    %% DNSName format: "<fingerprint>.gpg.cryptic.local"
    case string:split(DNSName, ".gpg.cryptic.local") of
        [Fingerprint, ""] ->
            {ok, list_to_binary(Fingerprint)};
        _ ->
            {error, invalid_san_format}
    end;
extract_gpg_from_san([_ | Rest]) ->
    extract_gpg_from_san(Rest);
extract_gpg_from_san([]) ->
    {error, no_gpg_in_san}.

%% @doc Check if a user has admin privileges
%% A user is considered an admin if they were not registered by another user
%% (i.e., registered_by is undefined), indicating they are a bootstrap/initial admin
-spec is_admin(binary(), term()) -> boolean().
is_admin(undefined, _DbRef) ->
    false;
is_admin(GpgFp, DbRef) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, Identity} ->
            %% Admin if they were not registered by someone else
            %% Need to include the record definition
            case Identity of
                #gpg_identity{registered_by = undefined} -> true;
                _ -> false
            end;
        {error, _} ->
            false
    end.

is_online(User) when is_binary(User) ->
    is_online(binary_to_list(User));
is_online(User) when is_list(User) ->
    case find_user_connection(User) of
        {ok, _Pid} -> true;
        not_found  -> false
    end.
