%% @doc REST API handler for CA public operations
%%
%% This module handles HTTP REST endpoints for public certificate authority
%% operations including GPG registration and certificate signing requests.
%%
%% Public Endpoints:
%% - POST /ca/v1/register-gpg: Register a new user with invite token
%% - POST /ca/v1/csr: Request a certificate with GPG-signed CSR
%% - GET /ca/v1/status/:fingerprint: Check registration status
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_rest_handler).

-export([
    init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    handle_post/2,
    handle_get/2
]).

-include_lib("kernel/include/logger.hrl").
-include("../include/cryptic_ca.hrl").

%%====================================================================
%% Cowboy REST Callbacks
%%====================================================================

%% @doc Initialize the REST handler.
%%
%% Extracts the operation type from the state passed by Cowboy routing.
%%
%% @param Req Cowboy request object
%% @param State Initial state containing operation type
%% @returns {cowboy_rest, Req, State}
init(Req, State) ->
    %% State contains #{operation => register_gpg | csr | status}
    {cowboy_rest, Req, State}.

%% @doc Specify allowed HTTP methods.
%%
%% @param Req Cowboy request
%% @param State Handler state
%% @returns {Methods, Req, State}
allowed_methods(Req, State) ->
    {[<<"GET">>, <<"POST">>, <<"OPTIONS">>], Req, State}.

%% @doc Specify content types accepted for POST requests.
%%
%% @param Req Cowboy request
%% @param State Handler state
%% @returns {ContentTypes, Req, State}
content_types_accepted(Req, State) ->
    {
        [
            {{<<"application">>, <<"json">>, '*'}, handle_post}
        ],
        Req,
        State
    }.

%% @doc Specify content types provided for GET requests.
%%
%% @param Req Cowboy request
%% @param State Handler state
%% @returns {ContentTypes, Req, State}
content_types_provided(Req, State) ->
    {
        [
            {{<<"application">>, <<"json">>, []}, handle_get}
        ],
        Req,
        State
    }.

%%====================================================================
%% Request Handlers
%%====================================================================

%% @doc Handle POST requests.
%%
%% Routes to appropriate handler based on operation in state:
%% - register_gpg: GPG registration with invite
%% - csr: Certificate signing request
%%
%% @param Req Cowboy request
%% @param State Handler state with operation type
%% @returns {true|false, Req, State}
handle_post(Req, #{operation := Operation} = State) ->
    handle_post_operation(Operation, Req, State);
handle_post(Req, State) ->
    %% Fallback for unknown operation
    Path = cowboy_req:path(Req),
    handle_post_route(Path, Req, State).

%% @doc Handle GET requests.
%%
%% Routes to appropriate handler based on operation in state:
%% - status: Get registration status
%%
%% @param Req Cowboy request
%% @param State Handler state with operation type
%% @returns {Body, Req, State}
handle_get(Req, #{operation := status} = State) ->
    %% Extract fingerprint from binding
    Fingerprint = cowboy_req:binding(fingerprint, Req),
    handle_status(Fingerprint, Req, State);
handle_get(Req, State) ->
    %% Fallback for unknown operation
    Path = cowboy_req:path(Req),
    handle_get_route(Path, Req, State).

%%====================================================================
%% POST Route Handlers
%%====================================================================

%% @doc Route POST requests based on operation type.
-spec handle_post_operation(atom(), cowboy_req:req(), map()) ->
    {true | false, cowboy_req:req(), map()}.

handle_post_operation(register_gpg, Req, State) ->
    handle_register_gpg(Req, State);
handle_post_operation(csr, Req, State) ->
    handle_csr(Req, State);
handle_post_operation(_Operation, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => <<"not_found">>,
        message => <<"Unknown operation">>
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    {false, Req2, State}.

%% @doc Route POST requests to specific handlers (fallback for path-based routing).
-spec handle_post_route(binary(), cowboy_req:req(), map()) ->
    {true | false, cowboy_req:req(), map()}.

handle_post_route(<<"/ca/v1/register-gpg">>, Req, State) ->
    handle_register_gpg(Req, State);
handle_post_route(<<"/ca/v1/csr">>, Req, State) ->
    handle_csr(Req, State);
handle_post_route(_Path, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => <<"not_found">>,
        message => <<"Unknown endpoint">>
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    {false, Req2, State}.

%% @doc Handle GPG registration with invite token.
%%
%% Request body:
%% ```
%% {
%%   "invite_id": "inv-123...",
%%   "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
%% }
%% '''
%%
%% Response:
%% ```
%% {
%%   "status": "verified",
%%   "gpg_fp": "ABCD1234...",
%%   "issued_at": 1234567890
%% }
%% '''
-spec handle_register_gpg(cowboy_req:req(), map()) ->
    {true | false, cowboy_req:req(), map()}.
handle_register_gpg(Req, State) ->
    {ok, Body, Req2} = cowboy_req:read_body(Req),

    try
        ReqMap = jsx:decode(Body, [return_maps]),
        InviteId = maps:get(<<"invite_id">>, ReqMap),
        GpgPub = maps:get(<<"gpg_pub">>, ReqMap),

        ?LOG_INFO("GPG registration request for invite: ~s", [InviteId]),

        %% Extract IP address for rate limiting
        IpAddr = get_ip_address(Req2),

        %% Check rate limit per IP address
        case cryptic_ca_rate_limiter:check_limit(IpAddr, register_gpg, 1) of
            {ok, _Remaining} ->
                register_gpg_impl(Req2, State, InviteId, GpgPub);
            {error, rate_limited, RetryAfter} ->
                ?LOG_WARNING(
                    "Rate limit exceeded for registration from IP ~s, retry after ~p seconds",
                    [IpAddr, RetryAfter]
                ),
                rate_limit_response(RetryAfter, Req2, State)
        end
    catch
        Error:CatchReason:Stack ->
            ?LOG_ERROR(
                "Error processing registration: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            error_response(<<"invalid_request">>, CatchReason, Req2, State)
    end.

%% @private Perform GPG registration after rate limit check
register_gpg_impl(Req, State, InviteId, GpgPub) ->
    %% Get database reference
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    %% Validate invite
    case cryptic_invite_mgr:validate_invite(DbRef, InviteId) of
        {ok, InviterFp} ->
            %% Extract and validate GPG public key
            case cryptic_ca_gpg:extract_public_key(GpgPub) of
                {ok, ValidatedKey} ->
                    %% Compute fingerprint
                    case cryptic_ca_gpg:compute_fingerprint(ValidatedKey) of
                        {ok, GpgFp} ->
                            %% Register identity
                            case
                                cryptic_gpg_registry:register_gpg_identity(
                                    DbRef,
                                    GpgFp,
                                    ValidatedKey,
                                    InviterFp,
                                    InviteId
                                )
                            of
                                ok ->
                                    %% Consume the invite
                                    ok = cryptic_invite_mgr:consume_invite(
                                        DbRef, InviteId, GpgFp
                                    ),

                                    Now = erlang:system_time(second),
                                    RespBody = jsx:encode(#{
                                        status => <<"verified">>,
                                        gpg_fp => GpgFp,
                                        issued_at => Now
                                    }),

                                    ?LOG_INFO(
                                        "GPG registration successful: ~s", [
                                            GpgFp
                                        ]
                                    ),

                                    Req2 = cowboy_req:set_resp_body(
                                        RespBody, Req
                                    ),
                                    Req3 = cowboy_req:set_resp_header(
                                        <<"content-type">>,
                                        <<"application/json">>,
                                        Req2
                                    ),
                                    {true, Req3, State};
                                {error, Reason} ->
                                    ?LOG_ERROR("GPG registration failed: ~p", [
                                        Reason
                                    ]),
                                    error_response(
                                        <<"registration_failed">>,
                                        Reason,
                                        Req,
                                        State
                                    )
                            end;
                        {error, Reason} ->
                            error_response(
                                <<"fingerprint_computation_failed">>,
                                Reason,
                                Req,
                                State
                            )
                    end;
                {error, Reason} ->
                    error_response(<<"invalid_gpg_key">>, Reason, Req, State)
            end;
        {error, Reason} ->
            ?LOG_WARNING("Invalid invite: ~s, reason: ~p", [InviteId, Reason]),
            error_response(<<"verification_failed">>, Reason, Req, State)
    end.

%% @doc Handle certificate signing request.
%%
%% Request body:
%% ```
%% {
%%   "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
%%   "gpg_fp": "ABCD1234...",
%%   "gpg_sig_b64": "BASE64(...)"
%% }
%% '''
%%
%% The GPG signature is computed over the CSR PEM data to prove ownership
%% of the GPG key.
%%
%% Response:
%% ```
%% {
%%   "cert_pem": "-----BEGIN CERTIFICATE-----...",
%%   "expires_at": 1234567890,
%%   "issued_at": 1234567890
%% }
%% '''
-spec handle_csr(cowboy_req:req(), map()) ->
    {true | false, cowboy_req:req(), map()}.
handle_csr(Req, State) ->
    {ok, Body, Req2} = cowboy_req:read_body(Req),

    try
        ReqMap = jsx:decode(Body, [return_maps]),
        CsrPem = maps:get(<<"csr_pem">>, ReqMap),
        GpgFp = maps:get(<<"gpg_fp">>, ReqMap),
        GpgSigB64 = maps:get(<<"gpg_sig_b64">>, ReqMap),

        ?LOG_INFO("CSR request for fingerprint: ~s", [GpgFp]),

        %% Check rate limit per GPG fingerprint
        case cryptic_ca_rate_limiter:check_limit(GpgFp, csr, 1) of
            {ok, _Remaining} ->
                csr_impl(Req2, State, CsrPem, GpgFp, GpgSigB64);
            {error, rate_limited, RetryAfter} ->
                ?LOG_WARNING(
                    "Rate limit exceeded for CSR from ~s, retry after ~p seconds",
                    [GpgFp, RetryAfter]
                ),
                rate_limit_response(RetryAfter, Req2, State)
        end
    catch
        Error:CatchReason:Stack ->
            ?LOG_ERROR(
                "Error processing CSR: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            error_response(<<"invalid_request">>, CatchReason, Req2, State)
    end.

%% @private Perform CSR processing after rate limit check
csr_impl(Req, State, CsrPem, GpgFp, GpgSigB64) ->
    %% Get database reference
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    %% Verify GPG identity exists and is verified
    case cryptic_gpg_registry:verify_identity_status(DbRef, GpgFp) of
        {ok, Status} when
            Status =:= verified_via_invite; Status =:= verified_bootstrap
        ->
            %% Get the public key for signature verification
            {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
            GpgPub = Identity#gpg_identity.gpg_pub_armor,

            %% Decode signature
            GpgSig = base64:decode(GpgSigB64),

            %% Verify signature over CSR
            case cryptic_ca_gpg:verify_signature(GpgSig, GpgPub) of
                {ok, VerifiedCsr} when VerifiedCsr =:= CsrPem ->
                    %% Signature valid, proceed with certificate issuance
                    %% TODO: Implement certificate issuance (Phase 3)
                    %% For now, return a placeholder response

                    ?LOG_INFO("CSR signature verified for ~s", [GpgFp]),

                    %% Placeholder: Certificate would be issued here
                    Now = erlang:system_time(second),
                    % 7 days default
                    ExpiresAt = Now + (7 * 24 * 3600),

                    RespBody = jsx:encode(#{
                        status => <<"pending">>,
                        message =>
                            <<"Certificate issuance not yet implemented (Phase 3)">>,
                        expires_at => ExpiresAt,
                        issued_at => Now
                    }),

                    Req2 = cowboy_req:set_resp_body(RespBody, Req),
                    Req3 = cowboy_req:set_resp_header(
                        <<"content-type">>, <<"application/json">>, Req2
                    ),
                    {true, Req3, State};
                {ok, _Other} ->
                    error_response(
                        <<"signature_mismatch">>,
                        <<"GPG signature does not match CSR">>,
                        Req,
                        State
                    );
                {error, Reason} ->
                    error_response(
                        <<"signature_verification_failed">>, Reason, Req, State
                    )
            end;
        {ok, Status} ->
            error_response(
                <<"unverified_identity">>,
                iolist_to_binary(io_lib:format("Status: ~p", [Status])),
                Req,
                State
            );
        {error, not_found} ->
            error_response(
                <<"identity_not_found">>,
                <<"GPG fingerprint not registered">>,
                Req,
                State
            );
        {error, Reason} ->
            error_response(<<"verification_failed">>, Reason, Req, State)
    end.

%%====================================================================
%% GET Route Handlers
%%====================================================================

%% @doc Route GET requests to specific handlers.
-spec handle_get_route(binary(), cowboy_req:req(), map()) ->
    {binary(), cowboy_req:req(), map()}.

handle_get_route(Path, Req, State) ->
    %% Match /ca/v1/status/:fingerprint
    case binary:split(Path, <<"/">>, [global]) of
        [<<>>, <<"ca">>, <<"v1">>, <<"status">>, Fingerprint] ->
            handle_status(Fingerprint, Req, State);
        _ ->
            ErrorBody = jsx:encode(#{
                error => <<"not_found">>,
                message => <<"Unknown endpoint">>
            }),
            {ErrorBody, Req, State}
    end.

%% @doc Handle status check request.
%%
%% Returns the registration status of a GPG fingerprint.
%%
%% Response:
%% ```
%% {
%%   "gpg_fp": "ABCD1234...",
%%   "status": "verified_via_invite",
%%   "registered_at": 1234567890
%% }
%% '''
-spec handle_status(binary(), cowboy_req:req(), map()) ->
    {binary(), cowboy_req:req(), map()}.
handle_status(GpgFp, Req, State) ->
    ?LOG_INFO("Status check for fingerprint: ~s", [GpgFp]),

    %% Extract IP for rate limiting
    IpAddr = get_ip_address(Req),

    %% Check rate limit per IP address
    case cryptic_ca_rate_limiter:check_limit(IpAddr, status, 1) of
        {ok, _Remaining} ->
            status_impl(GpgFp, Req, State);
        {error, rate_limited, RetryAfter} ->
            ?LOG_WARNING(
                "Rate limit exceeded for status check from IP ~s, retry after ~p seconds",
                [IpAddr, RetryAfter]
            ),
            ErrorBody = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many status requests">>,
                retry_after => RetryAfter
            }),
            {ErrorBody, Req, State}
    end.

%% @private Perform status check after rate limit
status_impl(GpgFp, Req, State) ->
    try
        {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

        case cryptic_gpg_registry:get_identity(DbRef, GpgFp) of
            {ok, Identity} ->
                RespBody = jsx:encode(#{
                    gpg_fp => GpgFp,
                    status => Identity#gpg_identity.status,
                    registered_at => Identity#gpg_identity.registered_at,
                    last_seen => Identity#gpg_identity.last_seen
                }),
                {RespBody, Req, State};
            {error, not_found} ->
                ErrorBody = jsx:encode(#{
                    error => <<"not_found">>,
                    message => <<"GPG fingerprint not registered">>
                }),
                Req2 = cowboy_req:set_resp_status(404, Req),
                {ErrorBody, Req2, State};
            {error, Reason} ->
                ErrorBody = jsx:encode(#{
                    error => <<"query_failed">>,
                    message => iolist_to_binary(io_lib:format("~p", [Reason]))
                }),
                {ErrorBody, Req, State}
        end
    catch
        Error:CatchReason:Stack ->
            ?LOG_ERROR(
                "Error checking status: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            ErrBody = jsx:encode(#{
                error => <<"internal_error">>,
                message => <<"Failed to check status">>
            }),
            {ErrBody, Req, State}
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

%% @doc Generate error response.
-spec error_response(binary(), term(), cowboy_req:req(), map()) ->
    {false, cowboy_req:req(), map()}.
error_response(ErrorType, Reason, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => ErrorType,
        message => format_error(Reason)
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    Req3 = cowboy_req:set_resp_header(
        <<"content-type">>, <<"application/json">>, Req2
    ),
    {false, Req3, State}.

%% @doc Format error reason for user-friendly display.
-spec format_error(term()) -> binary().
format_error(Reason) when is_binary(Reason) ->
    Reason;
format_error(Reason) when is_atom(Reason) ->
    atom_to_binary(Reason, utf8);
format_error(Reason) ->
    iolist_to_binary(io_lib:format("~p", [Reason])).

%% @doc Generate rate limit error response with Retry-After header.
-spec rate_limit_response(integer(), cowboy_req:req(), map()) ->
    {false, cowboy_req:req(), map()}.
rate_limit_response(RetryAfter, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => <<"rate_limited">>,
        message => <<"Too many requests">>,
        retry_after => RetryAfter
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    Req3 = cowboy_req:set_resp_header(
        <<"content-type">>, <<"application/json">>, Req2
    ),
    Req4 = cowboy_req:set_resp_header(
        <<"retry-after">>, integer_to_binary(RetryAfter), Req3
    ),
    {false, Req4, State}.

%% @doc Extract IP address from Cowboy request for rate limiting.
-spec get_ip_address(cowboy_req:req()) -> binary().
get_ip_address(Req) ->
    {{A, B, C, D}, _Port} = cowboy_req:peer(Req),
    iolist_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).
