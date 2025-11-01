%% @doc REST API handler for CA public operations
%%
%% This module handles HTTP REST endpoints for public certificate authority
%% operations including GPG registration and certificate signing requests.
%%
%% Public Endpoints:
%% - POST /ca/v1/csr: Submit certificate signing request
%% - GET /ca/v1/status/:fingerprint: Check registration status
%% - GET /ca/v1/ca-cert: Download the CA certificate in PEM format
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

-include("cryptic_server.hrl").
-include("../include/cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

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
    case maps:get(operation, State, undefined) of
        ca_cert ->
            %% CA certificate endpoint returns PEM format
            {
                [
                    {{<<"application">>, <<"x-pem-file">>, []}, handle_get}
                ],
                Req,
                State
            };
        _ ->
            %% Default to JSON for other endpoints
            {
                [
                    {{<<"application">>, <<"json">>, []}, handle_get}
                ],
                Req,
                State
            }
    end.

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
%% - ca_cert: Get CA certificate in PEM format
%%
%% @param Req Cowboy request
%% @param State Handler state with operation type
%% @returns {Body, Req, State}
handle_get(Req, #{operation := status} = State) ->
    %% Extract fingerprint from binding
    Fingerprint = cowboy_req:binding(fingerprint, Req),
    handle_status(Fingerprint, Req, State);
handle_get(Req, #{operation := ca_cert} = State) ->
    %% Return the CA certificate in PEM format
    handle_ca_cert(Req, State);
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

        ?info("CSR request for fingerprint: ~s", [GpgFp]),

        %% Check rate limit per GPG fingerprint
        case cryptic_ca_rate_limiter:check_limit(GpgFp, csr, 1) of
            {ok, _Remaining} ->
                csr_impl(Req2, State, CsrPem, GpgFp, GpgSigB64);
            {error, rate_limited, RetryAfter} ->
                ?warning(
                    "Rate limit exceeded for CSR from ~s, retry after ~p seconds",
                    [GpgFp, RetryAfter]
                ),
                rate_limit_response(RetryAfter, Req2, State)
        end
    catch
        Error:CatchReason:Stack ->
            ?error(
                "Error processing CSR: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            error_response(<<"invalid_request">>, CatchReason, Req2, State)
    end.

%% @private Perform CSR processing after rate limit check
csr_impl(Req, State, CsrPem, GpgFp, GpgSigB64) ->
    %% Get database reference
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    %% Verify GPG identity exists and is active (admin-mediated flow)
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, Identity} ->
            %% Check if user is active
            case Identity#gpg_identity.status of
                <<"active">> ->
                    %% Get the public key for signature verification
                    GpgPub = Identity#gpg_identity.gpg_pub_armor,

                    %% Decode signature from base64
                    GpgSig = base64:decode(GpgSigB64),

                    %% Verify GPG signature on CSR
                    %% The signature proves the user possesses the GPG private key
                    case cryptic_ca_gpg:verify_detached_signature(CsrPem, GpgSig, GpgPub) of
                        ok ->
                            %% Signature valid, validate CSR contains matching GPG fingerprint
                            case validate_csr_fingerprint(CsrPem, GpgFp) of
                                ok ->
                                    %% Issue certificate
                                    ?info("CSR signature verified for ~s, issuing certificate", [GpgFp]),
                                    issue_certificate(Req, State, DbRef, CsrPem, GpgFp, Identity);
                                {error, Reason} ->
                                    ?warning("CSR validation failed for ~s: ~p", [GpgFp, Reason]),
                                    error_response(
                                        <<"csr_validation_failed">>,
                                        iolist_to_binary(io_lib:format("~p", [Reason])),
                                        Req,
                                        State
                                    )
                            end;
                        {error, Reason} ->
                            ?warning("GPG signature verification failed for ~s: ~p", [GpgFp, Reason]),
                            error_response(
                                <<"signature_verification_failed">>,
                                iolist_to_binary(io_lib:format("~p", [Reason])),
                                Req,
                                State
                            )
                    end;
                <<"suspended">> ->
                    ?warning("CSR request from suspended user: ~s", [GpgFp]),
                    error_response(
                        <<"user_suspended">>,
                        <<"Your account has been suspended. Please contact an administrator.">>,
                        Req,
                        State
                    );
                <<"revoked">> ->
                    ?warning("CSR request from revoked user: ~s", [GpgFp]),
                    error_response(
                        <<"user_revoked">>,
                        <<"Your account has been revoked. Please contact an administrator.">>,
                        Req,
                        State
                    );
                OtherStatus ->
                    ?warning("CSR request from user with invalid status ~s: ~s", [OtherStatus, GpgFp]),
                    error_response(
                        <<"invalid_user_status">>,
                        iolist_to_binary(io_lib:format("Status: ~p", [OtherStatus])),
                        Req,
                        State
                    )
            end;
        {error, not_found} ->
            ?warning("CSR request for unregistered GPG fingerprint: ~s", [GpgFp]),
            error_response(
                <<"identity_not_found">>,
                <<"GPG fingerprint not registered. Please contact an administrator to register your GPG key.">>,
                Req,
                State
            );
        {error, Reason} ->
            ?error("Database error looking up GPG identity ~s: ~p", [GpgFp, Reason]),
            error_response(
                <<"verification_failed">>,
                iolist_to_binary(io_lib:format("~p", [Reason])),
                Req,
                State
            )
    end.

%% @private Validate that CSR contains the correct GPG fingerprint in SAN extension
validate_csr_fingerprint(CsrPem, _ExpectedGpgFp) ->
    %% Basic validation: ensure CSR is valid PEM
    %% The cryptic_ca_cert:issue_from_csr/2 function will do deeper validation
    %% including checking that the CSR contains the correct GPG fingerprint in SAN
    try
        [_CsrEntry] = public_key:pem_decode(CsrPem),
        ok
    catch
        _:CatchReason ->
            ?error("Failed to decode CSR PEM: ~p", [CatchReason]),
            {error, {invalid_csr_pem, CatchReason}}
    end.

%% @private Issue certificate and update database
issue_certificate(Req, State, DbRef, CsrPem, GpgFp, Identity) ->
    %% Extract email from GPG public key
    GpgPubKey = Identity#gpg_identity.gpg_pub_armor,
    Email = case cryptic_ca_gpg:extract_email_from_key(GpgPubKey) of
        {ok, E} -> 
            ?info("Extracted email from GPG key: ~s", [E]),
            E;
        {error, EmailReason} -> 
            ?warning("Failed to extract email from GPG key: ~p", [EmailReason]),
            undefined
    end,
    
    ?info("Issuing certificate for ~s with email: ~p", [GpgFp, Email]),
    
    %% Issue certificate using cryptic_ca_cert module with email
    case cryptic_ca_cert:issue_from_csr(CsrPem, GpgFp, Email, 7) of
        {ok, CertPem} ->
            %% Extract validity from configuration
            ValidityDays = application:get_env(cryptic_ca, cert_default_lifetime_days, 7),
            
            Now = erlang:system_time(second),
            ExpiresAt = Now + (ValidityDays * 24 * 3600),

            %% Extract serial number from certificate
            Serial = extract_serial_from_cert(CertPem),

            ?info("Certificate ~s issued for ~s, expires in ~p days", 
                  [Serial, GpgFp, ValidityDays]),

            %% Store certificate in database
            CertRecord = #certificate{
                serial = Serial,
                gpg_fp = GpgFp,
                issued_at = Now,
                expires_at = ExpiresAt,
                status = <<"active">>,
                cert_pem = CertPem
            },
            case cryptic_ca_store:insert_certificate(DbRef, CertRecord) of
                ok -> 
                    ok;
                {error, 1555} ->
                    %% Duplicate serial number - this indicates the serial counter is out of sync
                    %% This can happen if the server crashed after issuing a cert but before 
                    %% persisting the serial counter. The solution is to restart the server
                    %% so it re-syncs from the database.
                    ?error("Certificate serial ~s already exists - serial counter out of sync. "
                           "Please restart the server to re-sync serial numbers.", [Serial]),
                    error({duplicate_serial, Serial, 
                           "Serial counter out of sync. Restart server to fix."});
                {error, Reason} ->
                    ?error("Failed to insert certificate ~s: ~p", [Serial, Reason]),
                    error({cert_insert_failed, Reason})
            end,

            %% Update last_seen timestamp for user
            ok = cryptic_ca_store:update_last_seen(DbRef, GpgFp),

            %% Log to audit
            RegisteredBy = case Identity#gpg_identity.registered_by of
                undefined -> <<"system">>;
                Rb -> Rb
            end,
            
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"certificate_issued">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    serial => Serial,
                    validity_days => ValidityDays,
                    expires_at => ExpiresAt,
                    registered_by => RegisteredBy
                }),
                ip_address = get_ip_address(Req)
            },
            ok = cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            %% Return certificate to client
            RespBody = jsx:encode(#{
                status => <<"issued">>,
                cert_pem => CertPem,
                serial => Serial,
                expires_at => ExpiresAt,
                issued_at => Now,
                validity_days => ValidityDays
            }),

            Req2 = cowboy_req:set_resp_body(RespBody, Req),
            Req3 = cowboy_req:set_resp_header(
                <<"content-type">>, <<"application/json">>, Req2
            ),
            {true, Req3, State};
        
        {error, Reason} ->
            ?error("Certificate issuance failed for ~s: ~p", [GpgFp, Reason]),
            error_response(
                <<"certificate_issuance_failed">>,
                iolist_to_binary(io_lib:format("~p", [Reason])),
                Req,
                State
            )
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

%% @doc Handle CA certificate download request.
%%
%% Returns the CA certificate in PEM format so clients can verify
%% the server's certificate during TLS handshake.
%%
%% Response: PEM-encoded CA certificate (application/x-pem-file)
-spec handle_ca_cert(cowboy_req:req(), map()) ->
    {binary(), cowboy_req:req(), map()}.
handle_ca_cert(Req, State) ->
    ?info("CA certificate download request from ~s", [get_ip_address(Req)]),

    %% Get CA certificate from application environment
    case application:get_env(cryptic, ca_cert) of
        {ok, CaCert} ->
            %% Encode to PEM format
            try
                %% Convert OTP certificate to plain format for encoding
                %% This unwraps ECPoint records and other OTP-specific structures
                PlainCert = public_key:pkix_encode('OTPCertificate', CaCert, otp),
                DecodedCert = public_key:pkix_decode_cert(PlainCert, plain),
                
                PemEntry = public_key:pem_entry_encode('Certificate', DecodedCert),
                CaPem = public_key:pem_encode([PemEntry]),
                
                ?info("Serving CA certificate (~p bytes)", [byte_size(CaPem)]),
                
                %% Return PEM-encoded certificate
                Req2 = cowboy_req:set_resp_header(
                    <<"content-type">>, <<"application/x-pem-file">>, Req
                ),
                Req3 = cowboy_req:set_resp_header(
                    <<"content-disposition">>, <<"attachment; filename=\"ca.crt\"">>, Req2
                ),
                {CaPem, Req3, State}
            catch
                Error:CatchReason:Stack ->
                    ?error(
                        "Failed to encode CA certificate: ~p:~p~nStack: ~p",
                        [Error, CatchReason, Stack]
                    ),
                    ErrorBody = jsx:encode(#{
                        error => <<"encoding_failed">>,
                        message => <<"Failed to encode CA certificate">>
                    }),
                    ReqErr = cowboy_req:set_resp_header(
                        <<"content-type">>, <<"application/json">>, Req
                    ),
                    {ErrorBody, ReqErr, State}
            end;
        undefined ->
            ?error("CA certificate not configured in application environment: ~p", [undefined]),
            ErrorBody = jsx:encode(#{
                error => <<"not_configured">>,
                message => <<"CA certificate not available">>
            }),
            ReqErr2 = cowboy_req:set_resp_header(
                <<"content-type">>, <<"application/json">>, Req
            ),
            {ErrorBody, ReqErr2, State}
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
    ?info("Status check for fingerprint: ~s", [GpgFp]),

    %% Extract IP for rate limiting
    IpAddr = get_ip_address(Req),

    %% Check rate limit per IP address
    case cryptic_ca_rate_limiter:check_limit(IpAddr, status, 1) of
        {ok, _Remaining} ->
            status_impl(GpgFp, Req, State);
        {error, rate_limited, RetryAfter} ->
            ?warning(
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
            ?error(
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

%% @doc Extract serial number from PEM-encoded certificate.
-spec extract_serial_from_cert(binary()) -> binary().
extract_serial_from_cert(CertPem) ->
    try
        %% Decode PEM to DER
        [{'Certificate', DerCert, not_encrypted}] = public_key:pem_decode(CertPem),
        
        %% Parse certificate
        OtpCert = public_key:pkix_decode_cert(DerCert, otp),
        
        %% Extract serial number
        TbsCert = OtpCert#'OTPCertificate'.tbsCertificate,
        Serial = TbsCert#'OTPTBSCertificate'.serialNumber,
        
        %% Convert to hex string (uppercase for consistency)
        list_to_binary(string:uppercase(integer_to_list(Serial, 16)))
    catch
        _:Error ->
            ?error("Failed to extract serial from certificate: ~p", [Error]),
            %% Fallback to random hex serial if extraction fails
            RandomBytes = crypto:strong_rand_bytes(16),
            %% Convert random bytes to hex string
            list_to_binary(string:uppercase(
                lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(RandomBytes)])
            ))
    end.
