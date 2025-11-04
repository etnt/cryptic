%% @doc WebSocket handler for CA operations from trusted clients (cryptic_console)
%%
%% This module handles WebSocket connections from authenticated clients
%% (cryptic_console) for CA management operations. Authentication is
%% provided by the existing mTLS connection.
%%
%% Admin User Management Commands:
%% - register_user: Register a new user's GPG public key
%% - list_users: List all registered users (with optional filter)
%% - get_user_info: Get detailed info about a specific user
%% - suspend_user: Temporarily suspend a user's access
%% - revoke_user: Permanently revoke a user's access
%% - reactivate_user: Reactivate a suspended user
%%
%% Legacy Invite Commands (deprecated):
%% - invite_create: Create a new invite token
%% - invite_list: List invites created by the authenticated user
%% - invite_revoke: Revoke an unused invite
%%
%% Other Commands:
%% - gpg_register_bootstrap: Register GPG key for existing mTLS user
%% - cert_status_query: Query certificate status
%% - cert_renew: Renew an expiring certificate
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
%% Extracts the GPG fingerprint from the mTLS certificate and verifies it
%% against the GPG registry. All client certificates must contain a valid
%% GPG fingerprint in the SAN extension.
%%
%% For bootstrap (admin only), clients without valid certificates can use
%% the gpg_register_bootstrap command.
%%
%% @param State Handler state
%% @returns {ok, State} on successful initialization, {stop, State} on auth failure
websocket_init(#state{peer_cert = PeerCert, db_ref = DbRef} = State) ->
    ?info("CA WebSocket connection established", []),

    %% Extract GPG fingerprint from mTLS certificate's SAN extension
    %% The certificate embeds the GPG fingerprint as: <fingerprint>.gpg.cryptic.local
    case extract_gpg_from_cert_der(PeerCert) of
        {ok, GpgFp} ->
            %% Verify the GPG fingerprint is registered in our database
            case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
                {ok, _Identity} ->
                    ?info("Authenticated with verified GPG fingerprint: ~s", [GpgFp]),
                    {ok, State#state{gpg_fp = GpgFp, authenticated = true}};
                {error, not_found} ->
                    ?warning("Certificate contains unregistered GPG fingerprint: ~s", [GpgFp]),
                    ?info("Closing connection - GPG fingerprint not in registry", []),
                    ErrorMsg = jsx:encode(#{
                        error => <<"authentication_failed">>,
                        message => <<"GPG fingerprint in certificate is not registered">>
                    }),
                    self() ! {send_and_close, ErrorMsg},
                    {ok, State};
                {error, Reason} ->
                    ?error("Database error verifying GPG fingerprint ~s: ~p", [GpgFp, Reason]),
                    ErrorMsg = jsx:encode(#{
                        error => <<"internal_error">>,
                        message => <<"Failed to verify credentials">>
                    }),
                    self() ! {send_and_close, ErrorMsg},
                    {ok, State}
            end;
        {error, no_peer_cert} ->
            ?warning("No client certificate provided - bootstrap mode only", []),
            ?info("Client must use gpg_register_bootstrap to authenticate", []),
            {ok, State};
        {error, Reason} ->
            ?warning("Failed to extract GPG fingerprint from certificate: ~p", [Reason]),
            ?info("Closing connection - invalid certificate format", []),
            ErrorMsg = jsx:encode(#{
                error => <<"authentication_failed">>,
                message => <<"Certificate does not contain valid GPG fingerprint">>
            }),
            self() ! {send_and_close, ErrorMsg},
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
%% @returns {ok, State} | {reply, Frame, State} | {stop, State}
websocket_info({send_and_close, ErrorMsg}, State) ->
    %% Send error message and then close the connection
    {[{text, ErrorMsg}, close], State};
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
%% Admin-mediated user management commands
handle_command(#{<<"type">> := <<"register_user">>} = Msg, State) ->
    handle_register_user(Msg, State);
handle_command(#{<<"type">> := <<"list_users">>} = Msg, State) ->
    handle_list_users(Msg, State);
handle_command(#{<<"type">> := <<"get_user_info">>} = Msg, State) ->
    handle_get_user_info(Msg, State);
handle_command(#{<<"type">> := <<"suspend_user">>} = Msg, State) ->
    handle_suspend_user(Msg, State);
handle_command(#{<<"type">> := <<"revoke_user">>} = Msg, State) ->
    handle_revoke_user(Msg, State);
handle_command(#{<<"type">> := <<"reactivate_user">>} = Msg, State) ->
    handle_reactivate_user(Msg, State);
handle_command(#{<<"type">> := <<"revoke_certificate">>} = Msg, State) ->
    handle_revoke_certificate(Msg, State);
handle_command(#{<<"type">> := <<"list_certificates">>} = Msg, State) ->
    handle_list_certificates(Msg, State);
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
            <<"Supported commands: register_user, list_users, get_user_info, suspend_user, revoke_user, reactivate_user, invite_create, invite_list, invite_show, invite_revoke, cert_status_query, cert_renew, gpg_register_bootstrap">>
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
                type => <<"invite_create_response">>,
                status => <<"success">>,
                invite_id => InviteId,
                expires_at => Invite#invite.expires_at
            }),

            ?info("Invite created successfully: ~s", [InviteId]),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ?error("Failed to create invite: ~p", [Reason]),
            ErrorResp = jsx:encode(#{
                type => <<"invite_create_response">>,
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
                type => <<"invite_list_response">>,
                status => <<"success">>,
                invites => Invites
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                type => <<"invite_list_response">>,
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
                type => <<"invite_revoke_response">>,
                status => <<"success">>,
                invite_id => InviteId
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                type => <<"invite_revoke_response">>,
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
                            %% Decode meta JSON if present
                            Meta = case Invite#invite.meta of
                                undefined -> #{};
                                MetaJson when is_binary(MetaJson) ->
                                    case jsx:decode(MetaJson, [return_maps]) of
                                        DecodedMeta when is_map(DecodedMeta) -> DecodedMeta;
                                        _ -> #{}
                                    end;
                                _ -> #{}
                            end,
                            InviteMap = #{
                                invite_id => Invite#invite.invite_id,
                                inviter_fp => Invite#invite.inviter_fp,
                                expires_at => Invite#invite.expires_at,
                                status => Invite#invite.status,
                                registered_at => Invite#invite.registered_at,
                                registered_by_fp => Invite#invite.registered_by_fp,
                                consumed_at => Invite#invite.consumed_at,
                                expired => (Invite#invite.expires_at < Now),
                                meta => Meta
                            },
                            Response = jsx:encode(#{
                                type => <<"invite_show_response">>,
                                status => <<"success">>,
                                invite => InviteMap
                            }),
                            {reply, {text, Response}, State};
                        _ ->
                            ErrorResp = jsx:encode(#{
                                type => <<"invite_show_response">>,
                                error => <<"unauthorized">>,
                                message => <<"You can only view your own invites">>
                            }),
                            {reply, {text, ErrorResp}, State}
                    end;
                {error, not_found} ->
                    ErrorResp = jsx:encode(#{
                        type => <<"invite_show_response">>,
                        error => <<"not_found">>,
                        message => <<"Invite not found">>
                    }),
                    {reply, {text, ErrorResp}, State};
                {error, Reason} ->
                    ErrorResp = jsx:encode(#{
                        type => <<"invite_show_response">>,
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
%% Admin User Management Commands
%%====================================================================

%% @doc Handle register_user command.
%%
%% Allows an admin to register a new user's GPG public key.
%% This is the primary onboarding method in the admin-mediated flow.
%%
%% Request format:
%% ```
%% {
%%   "type": "register_user",
%%   "gpg_fp": "ABCD1234...",
%%   "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
%%   "metadata": {
%%     "name": "Bob Smith",
%%     "team": "Engineering",
%%     "notes": "New team member"
%%   }
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "gpg_fp": "ABCD1234...",
%%   "registered_at": 1730000000,
%%   "registered_by": "ADMIN_FP"
%% }
%% '''
-spec handle_register_user(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_register_user(
    #{<<"gpg_fp">> := GpgFp, <<"gpg_pub">> := GpgPub} = Msg,
    #state{gpg_fp = AdminFp, db_ref = DbRef, authenticated = true} = State
) ->
    ?info("Admin ~s registering user ~s", [AdminFp, GpgFp]),

    %% Extract optional metadata
    Metadata = case maps:get(<<"metadata">>, Msg, undefined) of
        undefined -> undefined;
        Meta when is_map(Meta) -> jsx:encode(Meta);
        Meta when is_binary(Meta) -> Meta
    end,

    %% Register the user
    case cryptic_ca_store:register_user(DbRef, GpgFp, GpgPub, AdminFp, Metadata) of
        ok ->
            Now = erlang:system_time(second),
            
            %% Log audit event
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"user_registered">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    registered_by => AdminFp,
                    has_metadata => (Metadata =/= undefined)
                }),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            SuccessResp = jsx:encode(#{
                type => <<"register_user_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                registered_at => Now,
                registered_by => AdminFp
            }),
            {reply, {text, SuccessResp}, State};
        {error, Reason} ->
            ?error("Failed to register user ~s: ~p", [GpgFp, Reason]),
            ErrorResp = jsx:encode(#{
                type => <<"register_user_response">>,
                status => <<"error">>,
                error => <<"registration_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_register_user(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required fields: gpg_fp, gpg_pub">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle list_users command.
%%
%% Lists all registered users (admin only).
%%
%% Request format:
%% ```
%% {
%%   "type": "list_users",
%%   "filter": "active"  // optional: "active", "suspended", "revoked", or omit for all
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "users": [
%%     {
%%       "gpg_fp": "ABCD1234...",
%%       "status": "active",
%%       "registered_by": "ADMIN_FP",
%%       "registered_at": 1730000000,
%%       "last_seen": 1730000100,
%%       "metadata": {"name": "Bob Smith", "team": "Engineering"}
%%     }
%%   ]
%% }
%% '''
-spec handle_list_users(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_list_users(
    Msg,
    #state{db_ref = DbRef, authenticated = true} = State
) ->
    ?debug("Listing users", []),

    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            %% Optional filter by status
            FilteredIdentities = case maps:get(<<"filter">>, Msg, undefined) of
                undefined -> Identities;
                FilterStatus ->
                    lists:filter(
                        fun(#gpg_identity{status = S}) -> S =:= FilterStatus end,
                        Identities
                    )
            end,

            %% Convert to JSON-friendly format
            Users = lists:map(
                fun(#gpg_identity{
                    gpg_fp = Fp,
                    status = Status,
                    registered_by = RegBy,
                    registered_at = RegAt,
                    last_seen = LastSeen,
                    metadata = Meta
                }) ->
                    UserMap = #{
                        gpg_fp => Fp,
                        status => Status,
                        registered_by => RegBy,
                        registered_at => RegAt,
                        last_seen => LastSeen
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

            SuccessResp = jsx:encode(#{
                type => <<"list_users_response">>,
                status => <<"success">>,
                count => length(Users),
                users => Users
            }),
            {reply, {text, SuccessResp}, State};
        {error, Reason} ->
            ?error("Failed to list users: ~p", [Reason]),
            ErrorResp = jsx:encode(#{
                type => <<"list_users_response">>,
                status => <<"error">>,
                error => <<"list_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_list_users(_Msg, #state{authenticated = false} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"unauthorized">>,
        message => <<"Authentication required">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle get_user_info command.
%%
%% Get detailed information about a specific user.
%%
%% Request format:
%% ```
%% {
%%   "type": "get_user_info",
%%   "gpg_fp": "ABCD1234..."
%% }
%% '''
-spec handle_get_user_info(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_get_user_info(
    #{<<"gpg_fp">> := GpgFp},
    #state{db_ref = DbRef, authenticated = true} = State
) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{
            status = Status,
            registered_by = RegBy,
            registered_at = RegAt,
            last_seen = LastSeen,
            metadata = Meta
        }} ->
            UserInfo = #{
                gpg_fp => GpgFp,
                status => Status,
                registered_by => RegBy,
                registered_at => RegAt,
                last_seen => LastSeen
            },
            
            UserInfoWithMeta = case Meta of
                undefined -> UserInfo;
                _ ->
                    try
                        MetaMap = jsx:decode(Meta, [return_maps]),
                        UserInfo#{metadata => MetaMap}
                    catch
                        _:_ -> UserInfo
                    end
            end,

            SuccessResp = jsx:encode(#{
                type => <<"get_user_info_response">>,
                status => <<"success">>,
                user => UserInfoWithMeta
            }),
            {reply, {text, SuccessResp}, State};
        {error, not_found} ->
            ErrorResp = jsx:encode(#{
                type => <<"get_user_info_response">>,
                status => <<"error">>,
                error => <<"user_not_found">>,
                message => <<"GPG fingerprint not registered">>
            }),
            {reply, {text, ErrorResp}, State};
        {error, Reason} ->
            ?error("Failed to get user info for ~s: ~p", [GpgFp, Reason]),
            ErrorResp = jsx:encode(#{
                type => <<"get_user_info_response">>,
                status => <<"error">>,
                error => <<"query_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_get_user_info(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required field: gpg_fp">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle suspend_user command.
%%
%% Temporarily suspend a user's access.
%%
%% Request format:
%% ```
%% {
%%   "type": "suspend_user",
%%   "gpg_fp": "ABCD1234...",
%%   "reason": "Policy violation"
%% }
%% '''
-spec handle_suspend_user(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_suspend_user(
    #{<<"gpg_fp">> := GpgFp} = Msg,
    #state{gpg_fp = AdminFp, db_ref = DbRef, authenticated = true} = State
) ->
    Reason = maps:get(<<"reason">>, Msg, <<"No reason provided">>),
    ?info("Admin ~s suspending user ~s: ~s", [AdminFp, GpgFp, Reason]),

    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"suspended">>) of
        ok ->
            Now = erlang:system_time(second),
            
            %% Log audit event
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"user_suspended">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    suspended_by => AdminFp,
                    reason => Reason
                }),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            SuccessResp = jsx:encode(#{
                type => <<"suspend_user_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                new_status => <<"suspended">>,
                suspended_by => AdminFp,
                suspended_at => Now
            }),
            {reply, {text, SuccessResp}, State};
        {error, Reason2} ->
            ?error("Failed to suspend user ~s: ~p", [GpgFp, Reason2]),
            ErrorResp = jsx:encode(#{
                type => <<"suspend_user_response">>,
                status => <<"error">>,
                error => <<"suspension_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason2]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_suspend_user(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required field: gpg_fp">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle revoke_user command.
%%
%% Permanently revoke a user's access (irreversible).
%%
%% Request format:
%% ```
%% {
%%   "type": "revoke_user",
%%   "gpg_fp": "ABCD1234...",
%%   "reason": "Left company"
%% }
%% '''
-spec handle_revoke_user(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_revoke_user(
    #{<<"gpg_fp">> := GpgFp} = Msg,
    #state{gpg_fp = AdminFp, db_ref = DbRef, authenticated = true} = State
) ->
    Reason = maps:get(<<"reason">>, Msg, <<"No reason provided">>),
    ?info("Admin ~s revoking user ~s: ~s", [AdminFp, GpgFp, Reason]),

    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"revoked">>) of
        ok ->
            Now = erlang:system_time(second),
            
            %% Log audit event
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"user_revoked">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    revoked_by => AdminFp,
                    reason => Reason
                }),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            SuccessResp = jsx:encode(#{
                type => <<"revoke_user_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                new_status => <<"revoked">>,
                revoked_by => AdminFp,
                revoked_at => Now,
                message => <<"User permanently revoked (irreversible)">>
            }),
            {reply, {text, SuccessResp}, State};
        {error, Reason2} ->
            ?error("Failed to revoke user ~s: ~p", [GpgFp, Reason2]),
            ErrorResp = jsx:encode(#{
                type => <<"revoke_user_response">>,
                status => <<"error">>,
                error => <<"revocation_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason2]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_revoke_user(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required field: gpg_fp">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle reactivate_user command.
%%
%% Reactivate a suspended user (does not work for revoked users).
%%
%% Request format:
%% ```
%% {
%%   "type": "reactivate_user",
%%   "gpg_fp": "ABCD1234..."
%% }
%% '''
-spec handle_reactivate_user(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_reactivate_user(
    #{<<"gpg_fp">> := GpgFp},
    #state{gpg_fp = AdminFp, db_ref = DbRef, authenticated = true} = State
) ->
    ?info("Admin ~s reactivating user ~s", [AdminFp, GpgFp]),

    %% First check current status
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{status = <<"revoked">>}} ->
            ErrorResp = jsx:encode(#{
                type => <<"reactivate_user_response">>,
                status => <<"error">>,
                error => <<"cannot_reactivate_revoked">>,
                message => <<"Revoked users cannot be reactivated. Please register a new GPG key.">>
            }),
            {reply, {text, ErrorResp}, State};
        {ok, #gpg_identity{status = <<"active">>}} ->
            InfoResp = jsx:encode(#{
                type => <<"reactivate_user_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                message => <<"User already active">>
            }),
            {reply, {text, InfoResp}, State};
        {ok, _Identity} ->
            %% User is suspended, reactivate
            case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"active">>) of
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

                    SuccessResp = jsx:encode(#{
                        type => <<"reactivate_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        new_status => <<"active">>,
                        reactivated_by => AdminFp,
                        reactivated_at => Now
                    }),
                    {reply, {text, SuccessResp}, State};
                {error, Reason} ->
                    ?error("Failed to reactivate user ~s: ~p", [GpgFp, Reason]),
                    ErrorResp = jsx:encode(#{
                        type => <<"reactivate_user_response">>,
                        status => <<"error">>,
                        error => <<"reactivation_failed">>,
                        message => iolist_to_binary(io_lib:format("~p", [Reason]))
                    }),
                    {reply, {text, ErrorResp}, State}
            end;
        {error, not_found} ->
            ErrorResp = jsx:encode(#{
                type => <<"reactivate_user_response">>,
                status => <<"error">>,
                error => <<"user_not_found">>,
                message => <<"GPG fingerprint not registered">>
            }),
            {reply, {text, ErrorResp}, State};
        {error, Reason} ->
            ?error("Failed to get user info for ~s: ~p", [GpgFp, Reason]),
            ErrorResp = jsx:encode(#{
                type => <<"reactivate_user_response">>,
                status => <<"error">>,
                error => <<"query_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_reactivate_user(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required field: gpg_fp">>
    }),
    {reply, {text, ErrorResp}, State}.

%%--------------------------------------------------------------------
%% @doc Handle revoke_certificate command - Admin revokes a specific certificate
%% @end
%%--------------------------------------------------------------------
-spec handle_revoke_certificate(map(), #state{}) ->
    {reply, {text, binary()}, #state{}}.
handle_revoke_certificate(
    #{
        <<"serial">> := Serial,
        <<"reason">> := Reason
    } = _Msg,
    #state{db_ref = DbRef, gpg_fp = AdminFp, authenticated = true} = State
) ->
    %% Revoke the certificate
    case cryptic_ca_store:revoke_certificate(DbRef, Serial, AdminFp, Reason) of
        ok ->
            ?info("Admin ~s revoked certificate ~s: ~s", [AdminFp, Serial, Reason]),
            
            Resp = jsx:encode(#{
                type => <<"revoke_certificate_response">>,
                status => <<"success">>,
                message => <<"Certificate revoked successfully">>,
                serial => Serial,
                reason => Reason
            }),
            {reply, {text, Resp}, State};
        
        {error, ErrorReason} ->
            ?error("Failed to revoke certificate ~s: ~p", [Serial, ErrorReason]),
            ErrorResp = jsx:encode(#{
                type => <<"revoke_certificate_response">>,
                status => <<"error">>,
                error => <<"revoke_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [ErrorReason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_revoke_certificate(_Msg, #state{authenticated = false} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"unauthorized">>,
        message => <<"Admin authentication required">>
    }),
    {reply, {text, ErrorResp}, State};
handle_revoke_certificate(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required fields: serial, reason">>
    }),
    {reply, {text, ErrorResp}, State}.

%%--------------------------------------------------------------------
%% @doc Handle list_certificates command - List certificates for a user
%% @end
%%--------------------------------------------------------------------
-spec handle_list_certificates(map(), #state{}) ->
    {reply, {text, binary()}, #state{}}.
handle_list_certificates(
    #{<<"gpg_fp">> := GpgFp} = _Msg,
    #state{db_ref = DbRef, authenticated = true} = State
) ->
    %% List all certificates for the user
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, Certs} ->
            CertList = lists:map(fun(Cert) ->
                #{
                    serial => Cert#certificate.serial,
                    issued_at => Cert#certificate.issued_at,
                    expires_at => Cert#certificate.expires_at,
                    status => Cert#certificate.status,
                    revoked_at => Cert#certificate.revoked_at,
                    revoked_by => Cert#certificate.revoked_by,
                    revoked_reason => Cert#certificate.revoked_reason
                }
            end, Certs),
            
            Resp = jsx:encode(#{
                type => <<"list_certificates_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                certificates => CertList,
                count => length(Certs)
            }),
            {reply, {text, Resp}, State};
        
        {error, ErrorReason} ->
            ?error("Failed to list certificates for ~s: ~p", [GpgFp, ErrorReason]),
            ErrorResp = jsx:encode(#{
                type => <<"list_certificates_response">>,
                status => <<"error">>,
                error => <<"list_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [ErrorReason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_list_certificates(_Msg, #state{authenticated = false} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"unauthorized">>,
        message => <<"Admin authentication required">>
    }),
    {reply, {text, ErrorResp}, State};
handle_list_certificates(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"invalid_request">>,
        message => <<"Required field: gpg_fp">>
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
