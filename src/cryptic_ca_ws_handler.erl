%% @doc WebSocket handler for CA invite operations from trusted clients (cryptic_console)
%%
%% This module handles WebSocket connections from authenticated clients
%% (cryptic_console) for invite management operations. Authentication is
%% provided by the existing mTLS connection.
%%
%% Supported Commands:
%% - invite_create: Create a new invite token
%% - invite_list: List invites created by the authenticated user
%% - invite_revoke: Revoke an unused invite
%% - gpg_register_bootstrap: Register GPG key for existing mTLS user
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_ws_handler).

-export([
    init/2,
    websocket_init/1,
    websocket_handle/2,
    websocket_info/2,
    terminate/3
]).

%% Export for testing
-export([handle_command/2]).

-include("cryptic_server.hrl").
-include("../include/cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

%% OID constants for certificate extensions
-define(ID_CE_SUBJECT_ALT_NAME, {2, 5, 29, 17}).

-record(state, {
    gpg_fp :: binary() | undefined,
    db_ref :: term(),
    authenticated = false :: boolean(),
    peer_cert :: binary() | undefined
}).

%%====================================================================
%% Cowboy WebSocket Callbacks
%%====================================================================

%% @doc Initialize the WebSocket handler.
%%
%% Upgrades the HTTP connection to WebSocket protocol. The client must
%% be authenticated via mTLS before this handler is invoked.
%%
%% @param Req Cowboy request object
%% @param _Opts Handler options (unused)
%% @returns {cowboy_websocket, Req, State} to upgrade to WebSocket
init(Req, _Opts) ->
    ?debug("Initializing CA WebSocket handler", []),

    %% Get database reference from application environment
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    %% Extract peer certificate from mTLS connection
    PeerCert = case cowboy_req:cert(Req) of
        undefined -> undefined;
        Cert -> Cert
    end,

    State = #state{
        db_ref = DbRef,
        authenticated = false,
        peer_cert = PeerCert
    },

    {cowboy_websocket, Req, State, #{
        % 10 minutes
        idle_timeout => 600000
    }}.

%% @doc WebSocket connection established.
%%
%% Extracts the GPG fingerprint from the mTLS certificate (if available)
%% or waits for bootstrap registration.
%%
%% @param State Handler state
%% @returns {ok, State} on successful initialization
websocket_init(#state{peer_cert = PeerCert} = State) ->
    ?info("CA WebSocket connection established", []),

    %% Extract GPG fingerprint from mTLS certificate's SAN extension
    %% The certificate embeds the GPG fingerprint as: <fingerprint>.gpg.cryptic.local
    case extract_gpg_from_cert_der(PeerCert) of
        {ok, GpgFp} ->
            ?info("Authenticated with GPG fingerprint from certificate: ~s", [GpgFp]),
            {ok, State#state{gpg_fp = GpgFp, authenticated = true}};
        {error, Reason} ->
            ?warning("Failed to extract GPG fingerprint from certificate: ~p", [Reason]),
            ?info("Client must use gpg_register_bootstrap to authenticate", []),
            {ok, State}
    end.

%% @doc Handle incoming WebSocket frames.
%%
%% Processes commands from the client and returns responses.
%%
%% @param Frame Incoming WebSocket frame
%% @param State Handler state
%% @returns {reply, Frame, State} | {ok, State}
websocket_handle({text, Msg}, State) ->
    ?debug("Received WebSocket message: ~p", [Msg]),

    try
        %% Decode JSON message
        MsgMap = jsx:decode(Msg, [return_maps]),
        handle_command(MsgMap, State)
    catch
        Error:Reason:Stack ->
            ?error(
                "Error handling WebSocket message: ~p:~p~nStack: ~p",
                [Error, Reason, Stack]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"invalid_request">>,
                message => <<"Failed to process request">>
            }),
            {reply, {text, ErrorResp}, State}
    end;
websocket_handle({binary, _}, State) ->
    %% We only support text frames for JSON messages
    ErrorResp = jsx:encode(#{
        error => <<"unsupported_frame_type">>,
        message => <<"Only text frames are supported">>
    }),
    {reply, {text, ErrorResp}, State};
websocket_handle(_Frame, State) ->
    {ok, State}.

%% @doc Handle Erlang messages sent to the WebSocket process.
%%
%% @param Info Erlang message
%% @param State Handler state
%% @returns {ok, State}
websocket_info(_Info, State) ->
    {ok, State}.

%% @doc Cleanup when WebSocket connection is closed.
%%
%% @param Reason Termination reason
%% @param _Req Cowboy request (unused)
%% @param _State Handler state (unused)
%% @returns ok
terminate(_Reason, _Req, _State) ->
    ?info("CA WebSocket connection terminated", []),
    ok.

%%====================================================================
%% Command Handlers
%%====================================================================

%% @doc Route commands to appropriate handlers.
%%
%% @param MsgMap Decoded JSON message map
%% @param State Handler state
%% @returns {reply, Frame, State} | {ok, State}
-spec handle_command(map(), #state{}) ->
    {reply, tuple(), #state{}} | {ok, #state{}}.

handle_command(#{<<"type">> := <<"invite_create">>} = Msg, State) ->
    handle_invite_create(Msg, State);
handle_command(#{<<"type">> := <<"invite_list">>} = Msg, State) ->
    handle_invite_list(Msg, State);
handle_command(#{<<"type">> := <<"invite_show">>} = Msg, State) ->
    handle_invite_show(Msg, State);
handle_command(#{<<"type">> := <<"invite_revoke">>} = Msg, State) ->
    handle_invite_revoke(Msg, State);
handle_command(#{<<"type">> := <<"cert_status_query">>} = Msg, State) ->
    handle_cert_status_query(Msg, State);
handle_command(#{<<"type">> := <<"cert_renew">>} = Msg, State) ->
    handle_cert_renew(Msg, State);
handle_command(#{<<"type">> := <<"gpg_register_bootstrap">>} = Msg, State) ->
    handle_gpg_register_bootstrap(Msg, State);
%% Legacy command format support (backward compatibility)
handle_command(#{<<"command">> := <<"invite_create">>} = Msg, State) ->
    handle_invite_create(Msg, State);
handle_command(#{<<"command">> := <<"invite_list">>} = Msg, State) ->
    handle_invite_list(Msg, State);
handle_command(#{<<"command">> := <<"invite_revoke">>} = Msg, State) ->
    handle_invite_revoke(Msg, State);
handle_command(#{<<"command">> := <<"gpg_register_bootstrap">>} = Msg, State) ->
    handle_gpg_register_bootstrap(Msg, State);
handle_command(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"unknown_command">>,
        message =>
            <<"Supported commands: invite_create, invite_list, invite_show, invite_revoke, cert_status_query, cert_renew, gpg_register_bootstrap">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle invite_create command.
%%
%% Creates a new invite token that can be used by another user to register.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_create",
%%   "expiry_hours": 24,
%%   "meta": {"note": "Inviting Bob"}
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "invite_id": "inv-8f3b12a4...",
%%   "expires_at": 1234567890
%% }
%% '''
-spec handle_invite_create(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_create(_Msg, #state{gpg_fp = undefined} = State) ->
    %% Not authenticated with GPG key
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message =>
            <<"Please register your GPG key first using gpg_register_bootstrap">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_create(Msg, #state{gpg_fp = InviterFp, db_ref = DbRef} = State) ->
    ExpiryHours = maps:get(<<"expiry_hours">>, Msg, 24),
    Meta = maps:get(<<"meta">>, Msg, #{}),

    ?info("Creating invite for inviter ~s, expiry: ~p hours", [
        InviterFp, ExpiryHours
    ]),

    %% Check rate limit for invite creation
    case cryptic_ca_rate_limiter:check_limit(InviterFp, invite_create, 1) of
        {ok, _Remaining} ->
            create_invite_impl(DbRef, InviterFp, ExpiryHours, Meta, State);
        {error, rate_limited, RetryAfter} ->
            ?warning(
                "Rate limit exceeded for inviter ~s, retry after ~p seconds",
                [InviterFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many invite creation requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @private Create invite after rate limit check
create_invite_impl(DbRef, InviterFp, ExpiryHours, Meta, State) ->
    case
        cryptic_invite_mgr:create_invite(DbRef, InviterFp, ExpiryHours, Meta)
    of
        {ok, InviteId} ->
            {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),

            Response = jsx:encode(#{
                status => <<"success">>,
                invite_id => InviteId,
                expires_at => Invite#invite.expires_at
            }),

            ?info("Invite created successfully: ~s", [InviteId]),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ?error("Failed to create invite: ~p", [Reason]),
            ErrorResp = jsx:encode(#{
                error => <<"invite_creation_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle invite_list command.
%%
%% Lists all invites created by the authenticated user.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_list"
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "invites": [
%%     {
%%       "invite_id": "inv-123",
%%       "expires_at": 1234567890,
%%       "consumed": false,
%%       "expired": false
%%     }
%%   ]
%% }
%% '''
-spec handle_invite_list(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_list(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_list(_Msg, #state{gpg_fp = InviterFp, db_ref = DbRef} = State) ->
    %% Check rate limit for invite listing
    case cryptic_ca_rate_limiter:check_limit(InviterFp, invite_list, 1) of
        {ok, _Remaining} ->
            list_invites_impl(DbRef, InviterFp, State);
        {error, rate_limited, RetryAfter} ->
            ?warning(
                "Rate limit exceeded for invite_list ~s, retry after ~p seconds",
                [InviterFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many list requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @private List invites after rate limit check
list_invites_impl(DbRef, InviterFp, State) ->
    case cryptic_invite_mgr:list_user_invites(DbRef, InviterFp) of
        {ok, Invites} ->
            Response = jsx:encode(#{
                status => <<"success">>,
                invites => Invites
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"list_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle invite_revoke command.
%%
%% Revokes an unused invite token.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_revoke",
%%   "invite_id": "inv-123"
%% }
%% '''
-spec handle_invite_revoke(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_revoke(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_revoke(
    #{<<"invite_id">> := InviteId},
    #state{gpg_fp = GpgFp, db_ref = DbRef} = State
) ->
    %% Check rate limit for invite revocation
    case cryptic_ca_rate_limiter:check_limit(GpgFp, invite_revoke, 1) of
        {ok, _Remaining} ->
            revoke_invite_impl(DbRef, InviteId, State);
        {error, rate_limited, RetryAfter} ->
            ?warning(
                "Rate limit exceeded for invite_revoke ~s, retry after ~p seconds",
                [GpgFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many revoke requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_invite_revoke(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_invite_id">>,
        message => <<"invite_id is required">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @private Revoke invite after rate limit check
revoke_invite_impl(DbRef, InviteId, State) ->
    case cryptic_invite_mgr:revoke_invite(DbRef, InviteId) of
        ok ->
            Response = jsx:encode(#{
                status => <<"success">>,
                invite_id => InviteId
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"revoke_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle invite_show command.
%%
%% Shows details for a specific invite.
%%
%% Request format:
%% ```
%% {
%%   "type": "invite_show",
%%   "invite_id": "inv-123"
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "invite": {
%%     "invite_id": "inv-123",
%%     "inviter_fp": "ABCD1234...",
%%     "expires_at": 1234567890,
%%     "consumed": false,
%%     "expired": false,
%%     "meta": {"note": "Welcome Bob"}
%%   }
%% }
%% '''
-spec handle_invite_show(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_show(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_show(
    #{<<"invite_id">> := InviteId},
    #state{gpg_fp = GpgFp, db_ref = DbRef} = State
) ->
    %% Check rate limit
    case cryptic_ca_rate_limiter:check_limit(GpgFp, invite_show, 1) of
        {ok, _Remaining} ->
            case cryptic_ca_store:get_invite(DbRef, InviteId) of
                {ok, Invite} ->
                    %% Check if this invite belongs to the requesting user
                    case Invite#invite.inviter_fp of
                        GpgFp ->
                            Now = erlang:system_time(second),
                            InviteMap = #{
                                invite_id => Invite#invite.invite_id,
                                inviter_fp => Invite#invite.inviter_fp,
                                expires_at => Invite#invite.expires_at,
                                consumed => Invite#invite.consumed,
                                expired => (Invite#invite.expires_at < Now),
                                meta => Invite#invite.meta
                            },
                            Response = jsx:encode(#{
                                status => <<"success">>,
                                invite => InviteMap
                            }),
                            {reply, {text, Response}, State};
                        _ ->
                            ErrorResp = jsx:encode(#{
                                error => <<"unauthorized">>,
                                message => <<"You can only view your own invites">>
                            }),
                            {reply, {text, ErrorResp}, State}
                    end;
                {error, not_found} ->
                    ErrorResp = jsx:encode(#{
                        error => <<"not_found">>,
                        message => <<"Invite not found">>
                    }),
                    {reply, {text, ErrorResp}, State};
                {error, Reason} ->
                    ErrorResp = jsx:encode(#{
                        error => <<"show_failed">>,
                        message => iolist_to_binary(io_lib:format("~p", [Reason]))
                    }),
                    {reply, {text, ErrorResp}, State}
            end;
        {error, rate_limited, RetryAfter} ->
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many show requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_invite_show(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_invite_id">>,
        message => <<"invite_id is required">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle cert_status_query command.
%%
%% Queries the server for GPG identity and certificate status.
%%
%% Request format:
%% ```
%% {
%%   "type": "cert_status_query"
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "gpg_fp": "ABCD1234...",
%%   "gpg_registered": true,
%%   "cert_issued": true
%% }
%% '''
-spec handle_cert_status_query(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_cert_status_query(_Msg, #state{gpg_fp = undefined} = State) ->
    %% Not authenticated with GPG, return basic status
    Response = jsx:encode(#{
        status => <<"success">>,
        gpg_registered => false,
        cert_issued => true  %% They have a cert if they're connected
    }),
    {reply, {text, Response}, State};
handle_cert_status_query(_Msg, #state{gpg_fp = GpgFp} = State) ->
    Response = jsx:encode(#{
        status => <<"success">>,
        gpg_fp => GpgFp,
        gpg_registered => true,
        cert_issued => true
    }),
    {reply, {text, Response}, State}.

%% @doc Handle cert_renew command.
%%
%% Requests certificate renewal with a GPG-signed CSR.
%%
%% Request format:
%% ```
%% {
%%   "type": "cert_renew",
%%   "csr": "base64-encoded-csr",
%%   "gpg_sig": "base64-encoded-signature",
%%   "force": false,
%%   "new_key": false
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "certificate": "-----BEGIN CERTIFICATE-----...",
%%   "serial": "1234567890ABCDEF",
%%   "expires_at": 1234567890
%% }
%% '''
-spec handle_cert_renew(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_cert_renew(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_cert_renew(
    #{<<"csr">> := CSRBase64, <<"gpg_sig">> := SigBase64} = Msg,
    #state{gpg_fp = GpgFp, db_ref = DbRef} = State
) ->
    _Force = maps:get(<<"force">>, Msg, false),
    _NewKey = maps:get(<<"new_key">>, Msg, false),

    ?info("Certificate renewal request for GPG FP: ~s", [GpgFp]),

    %% Check rate limit for cert renewal
    case cryptic_ca_rate_limiter:check_limit(GpgFp, csr, 1) of
        {ok, _Remaining} ->
            renew_certificate_impl(DbRef, GpgFp, CSRBase64, SigBase64, State);
        {error, rate_limited, RetryAfter} ->
            ?warning(
                "Rate limit exceeded for cert_renew ~s, retry after ~p seconds",
                [GpgFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many renewal requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_cert_renew(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_parameters">>,
        message => <<"csr and gpg_sig are required">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @private Renew certificate after rate limit check
renew_certificate_impl(DbRef, GpgFp, CSRBase64, SigBase64, State) ->
    try
        %% Decode CSR and signature
        CSR = base64:decode(CSRBase64),
        Signature = base64:decode(SigBase64),

        %% Verify GPG signature on CSR
        case cryptic_ca_gpg:verify_detached_signature(GpgFp, CSR, Signature) of
            {ok, verified} ->
                %% Issue new certificate
                case cryptic_ca_cert:issue_from_csr(DbRef, CSR, GpgFp) of
                    {ok, Certificate} ->
                        %% Extract certificate metadata
                        {ok, Serial} = cryptic_ca_cert:get_serial(Certificate),
                        {ok, ExpiresAt} = cryptic_ca_cert:get_expiry(Certificate),

                        Response = jsx:encode(#{
                            status => <<"success">>,
                            certificate => Certificate,
                            serial => Serial,
                            expires_at => ExpiresAt
                        }),

                        ?info("Certificate renewed successfully for ~s", [GpgFp]),
                        {reply, {text, Response}, State};
                    {error, Reason} ->
                        ?error("Certificate issuance failed: ~p", [Reason]),
                        ErrorResp = jsx:encode(#{
                            error => <<"issuance_failed">>,
                            message => iolist_to_binary(io_lib:format("~p", [Reason]))
                        }),
                        {reply, {text, ErrorResp}, State}
                end;
            {error, Reason} ->
                ?error("GPG signature verification failed: ~p", [Reason]),
                ErrorResp = jsx:encode(#{
                    error => <<"signature_verification_failed">>,
                    message => iolist_to_binary(io_lib:format("~p", [Reason]))
                }),
                {reply, {text, ErrorResp}, State}
        end
    catch
        Error:Reason2:Stack ->
            ?error(
                "Error processing cert renewal: ~p:~p~nStack: ~p",
                [Error, Reason2, Stack]
            ),
            ErrorResponse = jsx:encode(#{
                error => <<"processing_error">>,
                message => <<"Failed to process renewal request">>
            }),
            {reply, {text, ErrorResponse}, State}
    end.

%% @doc Handle gpg_register_bootstrap command.
%%
%% Registers a GPG key for a user who already has a valid mTLS certificate.
%% This is used for the initial admin setup or for users transitioning from
%% TLS-only to GPG-based authentication.
%%
%% Request format:
%% ```
%% {
%%   "command": "gpg_register_bootstrap",
%%   "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "gpg_fp": "ABCD1234...",
%%   "registered_at": 1234567890
%% }
%% '''
-spec handle_gpg_register_bootstrap(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_gpg_register_bootstrap(
    #{<<"gpg_pub">> := GpgPub}, #state{db_ref = DbRef} = State
) ->
    ?info("Bootstrap GPG registration request", []),

    %% Validate and extract GPG public key
    case cryptic_ca_gpg:extract_public_key(GpgPub) of
        {ok, ValidatedKey} ->
            %% Compute fingerprint
            case cryptic_ca_gpg:compute_fingerprint(ValidatedKey) of
                {ok, GpgFp} ->
                    %% Register as bootstrap identity
                    case
                        cryptic_gpg_registry:register_bootstrap_identity(
                            DbRef, GpgFp, ValidatedKey
                        )
                    of
                        ok ->
                            Now = erlang:system_time(second),
                            Response = jsx:encode(#{
                                status => <<"success">>,
                                gpg_fp => GpgFp,
                                registered_at => Now
                            }),

                            ?info(
                                "GPG bootstrap registration successful: ~s", [
                                    GpgFp
                                ]
                            ),

                            %% Update state to mark as authenticated
                            NewState = State#state{
                                gpg_fp = GpgFp,
                                authenticated = true
                            },
                            {reply, {text, Response}, NewState};
                        {error, Reason} ->
                            ?error("GPG registration failed: ~p", [Reason]),
                            ErrorResp = jsx:encode(#{
                                error => <<"registration_failed">>,
                                message => iolist_to_binary(
                                    io_lib:format("~p", [Reason])
                                )
                            }),
                            {reply, {text, ErrorResp}, State}
                    end;
                {error, Reason} ->
                    ErrorResp = jsx:encode(#{
                        error => <<"fingerprint_computation_failed">>,
                        message => iolist_to_binary(
                            io_lib:format("~p", [Reason])
                        )
                    }),
                    {reply, {text, ErrorResp}, State}
            end;
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"invalid_gpg_key">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_gpg_register_bootstrap(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_gpg_pub">>,
        message => <<"gpg_pub is required">>
    }),
    {reply, {text, ErrorResp}, State}.

%%====================================================================
%% Private Helper Functions
%%====================================================================

%% @private Extract GPG fingerprint from DER-encoded certificate
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
